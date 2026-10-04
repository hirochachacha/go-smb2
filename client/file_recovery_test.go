package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func writeFileRecoveryResponse(t *testing.T, conn net.Conn, request []byte, packet wire.Packet, status erref.NtStatus) {
	t.Helper()
	req := wire.PacketCodec(request)
	require.False(t, req.IsInvalid())
	data := make([]byte, packet.Size())
	packet.Encode(data)
	out := wire.PacketCodec(data)
	out.SetMessageId(req.MessageId())
	out.SetSessionId(req.SessionId())
	out.SetTreeId(req.TreeId())
	out.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	out.SetCreditResponse(req.CreditRequest())
	out.SetStatus(uint32(status))
	require.NoError(t, writeClientTestPacket(conn, data))
}

func TestStatfsFailureSessionRecovery(t *testing.T) {
	for _, layer := range []string{"file", "path"} {
		for _, failure := range []string{"status", "transport"} {
			t.Run(layer+"/"+failure, func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				var queries atomic.Int32
				var failed atomic.Bool
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := wire.PacketCodec(request)
					require.False(t, p.IsInvalid())
					if p.Command() != wire.SMB2_QUERY_INFO {
						return false
					}
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.False(t, query.IsInvalid())
					require.Equal(t, uint8(wire.SMB2_0_INFO_FILESYSTEM), query.InfoType())
					require.Equal(t, uint8(wire.FileFsFullSizeInformation), query.FileInfoClass())
					queries.Add(1)
					if failure == "transport" && !failed.Swap(true) {
						require.NoError(t, conn.Close())
					} else {
						writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_INFO}, erref.STATUS_IO_DEVICE_ERROR)
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.MaxCreditBalance = 1 // Reuse the fixture's single-request responses.
				d := New(dialer, WithSessionIdleTimeout(0))
				defer d.Close()
				ctx := context.Background()
				const name = `\\server\share\original`
				old, err := d.Open(ctx, name)
				require.NoError(t, err)
				defer old.Close(ctx)
				var info v2.FileFsInfo
				if layer == "file" {
					info, err = old.Statfs(ctx)
				} else {
					info, err = d.Statfs(ctx, name)
				}
				require.Nil(t, info)
				var pe *os.PathError
				require.ErrorAs(t, err, &pe)
				require.Equal(t, "statfs", pe.Op)
				require.Equal(t, name, pe.Path)
				require.IsNotType(t, &os.PathError{}, pe.Err)
				if failure == "transport" {
					require.ErrorIs(t, err, io.EOF)
					var transport *protocol.TransportError
					require.ErrorAs(t, err, &transport)
				} else {
					require.ErrorIs(t, err, erref.STATUS_IO_DEVICE_ERROR)
				}
				require.EqualValues(t, 1, queries.Load(), "failed I/O must not be replayed")
				next, err := d.Open(ctx, `\\SERVER\SHARE\healthy`)
				require.NoError(t, err)
				if failure == "transport" {
					require.NotSame(t, old.session, next.session)
				} else {
					require.Same(t, old.session, next.session)
				}
				require.NoError(t, next.Close(ctx))
				ep.mu.Lock()
				dials := ep.dials
				ep.mu.Unlock()
				wantDials := 1
				if failure == "transport" {
					wantDials = 2
				}
				require.Equal(t, wantDials, dials)
			})
		}
	}
}

func TestFileReadFailureRetiresSession(t *testing.T) {
	for _, mode := range []string{"transport", "transport Read", "expired", "partial expired"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				reads := 0
				var failedConn net.Conn
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := wire.PacketCodec(request)
					require.False(t, p.IsInvalid())
					command := p.Command()
					ep.mu.Lock()
					failed := failedConn == conn
					ep.mu.Unlock()
					if command == wire.SMB2_CREATE && failed {
						writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: command}, erref.STATUS_NETWORK_SESSION_EXPIRED)
						return true
					}
					if command != wire.SMB2_READ {
						return false
					}
					reads++
					if mode == "partial expired" && reads == 1 {
						writeFileRecoveryResponse(t, conn, request, &wire.ReadResponse{Data: clientTestBytes(bytes.Repeat([]byte("x"), 64<<10))}, 0)
					} else {
						ep.mu.Lock()
						failedConn = conn
						ep.mu.Unlock()
						writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_NETWORK_SESSION_EXPIRED)
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.IOPipelineDepth = 1
				d := New(dialer, WithSessionIdleTimeout(0))
				defer d.Close()
				ctx := context.Background()
				const name = `\\server\share\original`
				old, err := d.Open(ctx, name)
				require.NoError(t, err)
				transportFailure := mode == "transport" || mode == "transport Read"
				if transportFailure {
					ep.closeActivePeers()
				}
				size, wantN, wantReads := 1, 0, 1
				if mode == "partial expired" {
					size, wantN, wantReads = (64<<10)+1, 64<<10, 2
				} else if transportFailure {
					wantReads = 0
				}
				buf := make([]byte, size)
				var n int
				if mode == "transport Read" {
					n, err = old.Read(ctx, buf)
				} else {
					n, err = old.ReadAt(ctx, buf, 0)
				}
				require.Equal(t, wantN, n)
				if wantN > 0 {
					require.Equal(t, bytes.Repeat([]byte("x"), wantN), buf[:n])
				}
				var pathErr *os.PathError
				require.ErrorAs(t, err, &pathErr)
				require.Equal(t, "read", pathErr.Op)
				require.Equal(t, name, pathErr.Path)
				if transportFailure {
					var transport *protocol.TransportError
					require.ErrorAs(t, err, &transport)
				} else {
					require.ErrorIs(t, err, erref.STATUS_NETWORK_SESSION_EXPIRED)
				}
				require.Equal(t, wantReads, reads, "the failed I/O must not be replayed")
				next, err := d.Open(ctx, `\\SERVER\SHARE\healthy`)
				require.NoError(t, err, "the next independent Open must reconnect immediately")
				require.NotSame(t, old.session, next.session)
				require.False(t, old.closed, "I/O failure must not close the File")
				_, err = old.ReadAt(ctx, make([]byte, 1), 0)
				require.Error(t, err)
				synctest.Wait()
				d.mu.Lock()
				current, oldUsers, newUsers := d.sessions[canonicalKey("server")], old.session.users, next.session.users
				d.mu.Unlock()
				require.Same(t, next.session, current, "late old errors must not retire the replacement")
				require.Equal(t, 1, oldUsers, "retain the old File's base reference")
				require.Equal(t, 1, newUsers, "old temporary releases must not affect new users")
				require.NoError(t, next.Close(ctx))
			})
		})
	}
}

func TestFileReadErrorsPreserveHealthySession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status erref.NtStatus
		cause  error
	}{
		{"permission", erref.STATUS_ACCESS_DENIED, os.ErrPermission},
		{"EOF", erref.STATUS_END_OF_FILE, io.EOF},
		{"file closed", erref.STATUS_FILE_CLOSED, os.ErrClosed},
		{"canceled", erref.STATUS_CANCELLED, context.Canceled},
		{"deadline", erref.STATUS_CANCELLED, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				ep := newClientTestEndpoint("server")
				reads := 0
				var pending []byte
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := wire.PacketCodec(request)
					require.False(t, p.IsInvalid())
					status := erref.STATUS_END_OF_FILE
					if p.Command() == wire.SMB2_CANCEL {
						request = pending
						status = tc.status
					} else if p.Command() != wire.SMB2_READ {
						return false
					} else {
						reads++
						if reads == 1 {
							status = tc.status
							if tc.cause == context.Canceled || tc.cause == context.DeadlineExceeded {
								pending = append([]byte(nil), request...)
								if tc.cause == context.Canceled {
									cancel()
								}
								return true
							}
						}
					}
					writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, status)
					return true
				}
				d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(0))
				defer d.Close()
				file, err := d.Open(context.Background(), `\\server\share\original`)
				require.NoError(t, err)
				defer file.Close(context.Background())
				sibling, err := d.Open(context.Background(), `\\server\share\sibling`)
				require.NoError(t, err)
				defer sibling.Close(context.Background())
				n, err := file.WithContext(ctx).ReadAt(make([]byte, 1), 0)
				require.Zero(t, n)
				require.ErrorIs(t, err, tc.cause)
				if tc.cause == io.EOF {
					require.Equal(t, io.EOF, err)
				} else {
					var pathErr *os.PathError
					require.ErrorAs(t, err, &pathErr)
					require.Equal(t, file.Name(), pathErr.Path)
				}
				n, err = sibling.ReadAt(context.Background(), make([]byte, 1), 0)
				require.Zero(t, n)
				require.Equal(t, io.EOF, err, "the healthy sibling must remain usable")
				next, err := d.Open(context.Background(), `\\server\share\next`)
				require.NoError(t, err)
				require.Same(t, file.session, next.session)
				require.NoError(t, next.Close(context.Background()))
			})
		})
	}
}
