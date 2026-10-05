package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
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

func runClientCopy(method string, ctx context.Context, source, destination *File) (int64, error) {
	switch method {
	case "ReadFrom":
		return destination.ReadFrom(ctx, source.WithContext(ctx))
	case "WriteTo":
		return source.WriteTo(ctx, destination.WithContext(ctx))
	case "bound ReadFrom":
		return destination.WithContext(ctx).ReadFrom(source.WithContext(ctx))
	default:
		return source.WithContext(ctx).WriteTo(destination.WithContext(ctx))
	}
}

func TestClientCopyFailureRetiresAttributedSession(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, tc := range []struct {
			name, mode, op, abort              string
			separate                           bool
			n, sourceOffset, destinationOffset int64
			reads, writes, resumes, copies     int
		}{
			{name: "shared aborted", mode: "recovery", op: "copy", abort: "source"},
			{name: "source aborted", mode: "recovery", op: "read", abort: "source", separate: true},
			{name: "destination aborted", mode: "recovery", op: "write", abort: "destination", separate: true, sourceOffset: 3, reads: 1},
			{name: "partial shared copy", mode: "copy-partial-unavailable", op: "copy", n: 16 << 20, sourceOffset: 16 << 20, destinationOffset: 16 << 20, resumes: 1, copies: 2},
			{name: "partial source", mode: "fallback-read-unavailable", op: "read", separate: true, n: 3, sourceOffset: 3, destinationOffset: 3, reads: 2, writes: 1},
			{name: "partial destination", mode: "fallback-write-unavailable", op: "write", separate: true, n: 3, sourceOffset: 6, destinationOffset: 3, reads: 2, writes: 2},
			{name: "peer EOF", mode: "fallback-transport-error", op: "read", n: 3, sourceOffset: 3, destinationOffset: 4, reads: 2, writes: 1},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					source, destination, fixture := newClientCopyPairOnClients(t, tc.mode, tc.separate)
					ctx := context.Background()
					failed, healthy := source, destination
					if tc.op == "write" {
						failed, healthy = destination, source
					}
					if tc.abort != "" {
						require.NoError(t, failed.session.Abort())
					}
					if tc.mode == "fallback-transport-error" {
						_, err := destination.Seek(ctx, 1, io.SeekStart)
						require.NoError(t, err)
					}
					n, err := runClientCopy(method, ctx, source, destination)
					require.Equal(t, tc.n, n)
					if tc.abort != "" || tc.mode == "fallback-transport-error" {
						var transport *protocol.TransportError
						require.ErrorAs(t, err, &transport)
						cause := net.ErrClosed
						if tc.mode == "fallback-transport-error" {
							cause = io.EOF
						}
						require.ErrorIs(t, err, cause)
					} else {
						require.ErrorIs(t, err, erref.STATUS_NETWORK_SESSION_EXPIRED)
					}
					if tc.op == "copy" {
						var link *os.LinkError
						require.ErrorAs(t, err, &link)
						require.Equal(t, "copy", link.Op)
						require.Equal(t, source.name, link.Old)
						require.Equal(t, destination.name, link.New)
					} else {
						var path *os.PathError
						require.ErrorAs(t, err, &path)
						require.Equal(t, tc.op, path.Op)
						require.Equal(t, failed.name, path.Path)
					}
					require.Equal(t, tc.reads, fixture.reads)
					require.Equal(t, tc.writes, fixture.writes)
					require.Equal(t, tc.resumes, fixture.resumes)
					require.Equal(t, tc.copies, fixture.copies, "copy must not be replayed")
					for _, endpoint := range []struct {
						file   *File
						offset int64
					}{{source, tc.sourceOffset}, {destination, tc.destinationOffset}} {
						offset, seekErr := endpoint.file.Seek(ctx, 0, io.SeekCurrent)
						require.NoError(t, seekErr)
						require.Equal(t, endpoint.offset, offset)
						require.False(t, endpoint.file.closed)
					}
					d := failed.session.client
					d.mu.Lock()
					cached := d.sessions[failed.session.key]
					d.mu.Unlock()
					require.Nil(t, cached, "a failed copy must not reopen the session itself")
					next, openErr := d.Open(ctx, `\\SERVER\SHARE\fresh`)
					require.NoError(t, openErr, "the next independent Open must reconnect immediately")
					require.NotSame(t, failed.session, next.session)
					defer next.Close(ctx)
					// Repeat an old-generation copy failure after publishing a replacement.
					if tc.op == "write" {
						_, seekErr := source.Seek(ctx, 0, io.SeekStart)
						require.NoError(t, seekErr)
					}
					_, lateErr := runClientCopy(method, ctx, source, destination)
					require.Error(t, lateErr)
					synctest.Wait()
					d.mu.Lock()
					current, oldUsers, newUsers := d.sessions[failed.session.key], failed.session.users, next.session.users
					staleShares := 0
					for _, share := range d.shares {
						if share.session == failed.session {
							staleShares++
						}
					}
					d.mu.Unlock()
					require.Same(t, next.session, current, "late errors must preserve the replacement")
					require.Zero(t, staleShares)
					wantOldUsers := 2
					if tc.separate {
						wantOldUsers = 1
						hd := healthy.session.client
						hd.mu.Lock()
						healthyCurrent, healthyUsers := hd.sessions[healthy.session.key], healthy.session.users
						hd.mu.Unlock()
						require.Same(t, healthy.session, healthyCurrent)
						require.Equal(t, 1, healthyUsers)
						buf := make([]byte, 3)
						count, readErr := healthy.ReadAt(ctx, buf, 0)
						require.NoError(t, readErr)
						require.Equal(t, 3, count)
						require.Equal(t, "abc", string(buf))
					}
					require.Equal(t, wantOldUsers, oldUsers)
					require.Equal(t, 1, newUsers)
				})
			})
		}
	}
}

func TestClientCopyCancellationKeepsSessions(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, separate := range []bool{false, true} {
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
				t.Run(fmt.Sprintf("%s/%v/separate=%v", method, cause, separate), func(t *testing.T) {
					source, destination, fixture := newClientCopyPairOnClients(t, "recovery", separate)
					ctx, cancel := context.WithCancel(context.Background())
					if cause == context.DeadlineExceeded {
						cancel()
						ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
					}
					cancel()
					n, err := runClientCopy(method, ctx, source, destination)
					require.Zero(t, n)
					require.ErrorIs(t, err, cause)
					require.Zero(t, fixture.reads+fixture.writes+fixture.resumes+fixture.copies)
					for _, file := range []*File{source, destination} {
						d := file.session.client
						d.mu.Lock()
						current := d.sessions[file.session.key]
						d.mu.Unlock()
						require.Same(t, file.session, current)
					}
				})
			}
		}
	}
}

func TestClientCopyUnattributedErrorKeepsSessions(t *testing.T) {
	t.Parallel()
	source, destination, _ := newClientCopyPairOnClients(t, "recovery", true)
	cause := &protocol.TransportError{Err: net.ErrClosed}
	for _, err := range []error{
		&os.LinkError{Op: "copy", Old: "file", New: "file", Err: cause},
		&os.LinkError{Op: "rename", Old: "file", New: "file", Err: cause},
		&os.PathError{Op: "stat", Path: "file", Err: cause},
	} {
		require.ErrorIs(t, copyError(err, source, destination), cause)
		for _, file := range []*File{source, destination} {
			d := file.session.client
			d.mu.Lock()
			current := d.sessions[file.session.key]
			d.mu.Unlock()
			require.Same(t, file.session, current)
		}
	}
}

func TestClientCopyInFlightCancellationKeepsSession(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(method+"/"+cause.Error(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					source, destination, fixture := newClientCopyPair(t, "copy-cancel")
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					finished := make(chan error, 1)
					go func() {
						n, err := runClientCopy(method, ctx, source, destination)
						require.Zero(t, n)
						finished <- err
					}()
					synctest.Wait()
					require.Equal(t, 1, fixture.copies)
					require.NotEmpty(t, fixture.pendingCopy)
					if cause == context.Canceled {
						cancel()
					}
					require.ErrorIs(t, <-finished, cause)
					synctest.Wait()
					require.Empty(t, fixture.pendingCopy, "SMB CANCEL must complete the pending request")
					d := source.session.client
					next, err := d.Open(context.Background(), `\\server\share\healthy`)
					require.NoError(t, err)
					require.Same(t, source.session, next.session)
					require.NoError(t, next.Close(context.Background()))
					d.mu.Lock()
					users := source.session.users
					d.mu.Unlock()
					require.Equal(t, 2, users)
					require.False(t, source.closed)
					require.False(t, destination.closed)
				})
			})
		}
	}
}

type clientCopyFixture struct {
	mode                           string
	reads, writes, resumes, copies int
	pendingCopy                    []byte
}

func newClientCopyPair(t *testing.T, mode string) (source, destination *File, fixture *clientCopyFixture) {
	t.Helper()
	return newClientCopyPairOnClients(t, mode, false)
}

func newClientCopyPairOnClients(t *testing.T, mode string, separate bool) (source, destination *File, fixture *clientCopyFixture) {
	t.Helper()
	fixture = &clientCopyFixture{mode: mode}
	ep := newClientTestEndpoint("server")
	var failedConn net.Conn
	ep.handleRequest = func(conn net.Conn, request []byte) bool {
		p := wire.PacketCodec(request)
		require.False(t, p.IsInvalid())
		ep.mu.Lock()
		failed := failedConn == conn
		ep.mu.Unlock()
		if failed && p.Command() == wire.SMB2_CREATE {
			writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: p.Command()}, erref.STATUS_NETWORK_SESSION_EXPIRED)
			return true
		}
		var response wire.Packet
		status := erref.STATUS_SUCCESS
		switch p.Command() {
		case wire.SMB2_CANCEL:
			if mode != "copy-cancel" || fixture.pendingCopy == nil {
				return false
			}
			writeFileRecoveryResponse(t, conn, fixture.pendingCopy, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, erref.STATUS_CANCELLED)
			fixture.pendingCopy = nil
			return true
		case wire.SMB2_READ:
			fixture.reads++
			r := wire.ReadRequestDecoder(request[64:])
			require.False(t, r.IsInvalid())
			switch {
			case fixture.reads == 1 || (r.Offset() == 0 && (mode == "recovery" || strings.HasSuffix(mode, "unavailable"))):
				response = &wire.ReadResponse{Data: []byte("abc")}
			case mode == "fallback-transport-error":
				require.NoError(t, conn.Close())
				return true
			case mode == "fallback-read-error":
				status = erref.STATUS_ACCESS_DENIED
			case mode == "fallback-read-unavailable":
				status = erref.STATUS_NETWORK_SESSION_EXPIRED
			case (mode == "fallback-write-error" || mode == "fallback-write-unavailable") && fixture.reads == 2:
				response = &wire.ReadResponse{Data: []byte("def")}
			default:
				status = erref.STATUS_END_OF_FILE
			}
		case wire.SMB2_WRITE:
			fixture.writes++
			if mode == "fallback-write-error" && fixture.writes == 2 {
				status = erref.STATUS_ACCESS_DENIED
			} else if mode == "fallback-write-unavailable" && fixture.writes == 2 {
				status = erref.STATUS_NETWORK_SESSION_EXPIRED
			} else {
				r := wire.WriteRequestDecoder(request[64:])
				require.False(t, r.IsInvalid())
				response = &wire.WriteResponse{Count: r.Length()}
			}
		case wire.SMB2_IOCTL:
			r := wire.IoctlRequestDecoder(request[64:])
			require.False(t, r.IsInvalid())
			switch r.CtlCode() {
			case wire.FSCTL_SRV_REQUEST_RESUME_KEY:
				fixture.resumes++
				response = &wire.IoctlResponse{CtlCode: r.CtlCode(), Output: &wire.SrvRequestResumeKeyResponse{ResumeKey: [24]byte{1}}}
			case wire.FSCTL_SRV_COPYCHUNK, wire.FSCTL_SRV_COPYCHUNK_WRITE:
				fixture.copies++
				if mode == "copy-cancel" {
					fixture.pendingCopy = append([]byte(nil), request...)
					return true
				}
				if (mode == "copy-partial-error" || mode == "copy-partial-unavailable") && fixture.copies == 1 {
					response = &wire.IoctlResponse{CtlCode: r.CtlCode(), Output: &wire.SrvCopychunkResponse{ChunksWritten: 16, ChunksBytesWritten: 1 << 20, TotalBytesWritten: 16 << 20}}
				} else if mode == "copy-partial-unavailable" {
					status = erref.STATUS_NETWORK_SESSION_EXPIRED
				} else {
					status = erref.STATUS_ACCESS_DENIED
				}
			default:
				return false
			}
		case wire.SMB2_QUERY_INFO:
			r := wire.QueryInfoRequestDecoder(request[64:])
			require.False(t, r.IsInvalid())
			if r.FileInfoClass() != wire.FileStandardInformation {
				return false
			}
			data := make([]byte, 24)
			binary.LittleEndian.PutUint64(data[8:], 16<<20+3)
			response = &wire.QueryInfoResponse{Output: clientTestBytes(data)}
		default:
			return false
		}
		if status == erref.STATUS_NETWORK_SESSION_EXPIRED {
			ep.mu.Lock()
			failedConn = conn
			ep.mu.Unlock()
		}
		if response == nil {
			response = &wire.ErrorResponse{CommandCode: p.Command()}
		}
		data := make([]byte, response.Size())
		response.Encode(data)
		out := wire.PacketCodec(data)
		out.SetMessageId(p.MessageId())
		out.SetSessionId(p.SessionId())
		out.SetTreeId(p.TreeId())
		out.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		out.SetCreditResponse(1)
		out.SetStatus(uint32(status))
		require.NoError(t, writeClientTestPacket(conn, data))
		return true
	}
	dialer := newClientTestDialer(&clientTestCredentials{}, ep)
	dialer.DisableAAPLExtension = true
	d := New(dialer)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	destinationClient := d
	if separate {
		destinationClient = New(dialer)
		t.Cleanup(func() { require.NoError(t, destinationClient.Close()) })
	}
	ctx := context.Background()
	var err error
	source, err = d.Open(ctx, `\\SERVER\SHARE\file`)
	require.NoError(t, err)
	destination, err = destinationClient.OpenFile(ctx, `\\server\share\file`, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = source.Close(ctx); _ = destination.Close(ctx) })
	return
}

func TestClientCopyErrorsKeepEndpointUNC(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, mode := range []string{"source-closed", "destination-closed", "copy-error", "copy-partial-error", "fallback-read-error", "fallback-write-error", "fallback-transport-error", "fallback-eof"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				source, destination, fixture := newClientCopyPair(t, mode)
				ctx := context.Background()
				if mode == "source-closed" {
					require.NoError(t, source.Close(ctx))
				}
				if mode == "destination-closed" {
					require.NoError(t, destination.Close(ctx))
				}
				if strings.HasPrefix(mode, "fallback-") {
					_, err := destination.Seek(ctx, 1, io.SeekStart)
					require.NoError(t, err)
				}
				var n int64
				var err error
				switch method {
				case "ReadFrom":
					n, err = destination.ReadFrom(ctx, source.WithContext(ctx))
				case "WriteTo":
					n, err = source.WriteTo(ctx, destination.WithContext(ctx))
				case "bound ReadFrom":
					n, err = destination.WithContext(ctx).ReadFrom(source.WithContext(ctx))
				case "bound WriteTo":
					n, err = source.WithContext(ctx).WriteTo(destination.WithContext(ctx))
				}
				wantN, sourceOffset, destinationOffset := int64(0), int64(0), int64(0)
				switch mode {
				case "copy-partial-error":
					wantN, sourceOffset, destinationOffset = 16<<20, 16<<20, 16<<20
				case "fallback-read-error", "fallback-transport-error", "fallback-eof":
					wantN, sourceOffset, destinationOffset = 3, 3, 4
				case "fallback-write-error":
					wantN, sourceOffset, destinationOffset = 3, 6, 4
				}
				require.Equal(t, wantN, n)
				if mode == "fallback-eof" {
					require.NoError(t, err)
				} else {
					wantCause := os.ErrPermission
					if strings.HasSuffix(mode, "-closed") {
						wantCause = os.ErrClosed
					}
					if mode == "fallback-transport-error" {
						wantCause = io.EOF
						var transportErr *protocol.TransportError
						require.ErrorAs(t, err, &transportErr)
					}
					require.ErrorIs(t, err, wantCause)
					if strings.HasPrefix(mode, "copy-") {
						var linkErr *os.LinkError
						require.ErrorAs(t, err, &linkErr)
						require.Equal(t, "copy", linkErr.Op)
						require.Equal(t, source.Name(), linkErr.Old)
						require.Equal(t, destination.Name(), linkErr.New)
					} else {
						var pathErr *os.PathError
						require.ErrorAs(t, err, &pathErr)
						wantOp, wantPath := "read", source.Name()
						if mode == "destination-closed" || mode == "fallback-write-error" {
							wantOp, wantPath = "write", destination.Name()
						}
						require.Equal(t, wantOp, pathErr.Op)
						require.Equal(t, wantPath, pathErr.Path)
						_, nested := pathErr.Err.(*os.PathError)
						require.False(t, nested)
					}
					if wantCause == os.ErrPermission {
						var responseErr *protocol.ResponseError
						require.ErrorAs(t, err, &responseErr)
						require.EqualValues(t, erref.STATUS_ACCESS_DENIED, responseErr.Code)
					}
				}
				if !strings.HasSuffix(mode, "-closed") {
					off, err := source.Seek(ctx, 0, io.SeekCurrent)
					require.NoError(t, err)
					require.Equal(t, sourceOffset, off)
					off, err = destination.Seek(ctx, 0, io.SeekCurrent)
					require.NoError(t, err)
					require.Equal(t, destinationOffset, off)
				}
				if strings.HasPrefix(mode, "copy-") {
					require.Equal(t, 1, fixture.resumes)
					require.Positive(t, fixture.copies)
					require.Zero(t, fixture.reads)
					require.Zero(t, fixture.writes)
				}
				if strings.HasPrefix(mode, "fallback-") {
					require.Zero(t, fixture.resumes)
					require.Zero(t, fixture.copies)
					require.Positive(t, fixture.reads)
					require.Positive(t, fixture.writes)
				}
				if mode != "fallback-transport-error" {
					for _, file := range []*File{source, destination} {
						d := file.session.client
						d.mu.Lock()
						current := d.sessions[file.session.key]
						d.mu.Unlock()
						require.Same(t, file.session, current, "permission, EOF and closed errors must preserve sessions")
					}
				}
			})
		}
	}
}

type clientCopyErrorReader struct{ err error }

func (r clientCopyErrorReader) Read(p []byte) (int, error) { return copy(p, "abc"), r.err }

type clientCopyErrorWriter struct{ err error }

func (w clientCopyErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestClientCopyPreservesExternalErrorIdentity(t *testing.T) {
	t.Parallel()
	for _, externalErr := range []error{
		&os.PathError{Op: "read", Path: "file", Err: os.ErrPermission},
		&os.PathError{Op: "write", Path: "file", Err: os.ErrPermission},
		&os.LinkError{Op: "copy", Old: "file", New: "file", Err: os.ErrPermission},
		&protocol.TransportError{Err: net.ErrClosed},
		&protocol.TransportError{Err: io.EOF},
		&os.PathError{Op: "read", Path: "file", Err: io.EOF},
	} {
		for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
			t.Run(method+"/"+externalErr.Error(), func(t *testing.T) {
				source, destination, fixture := newClientCopyPair(t, "external")
				ctx := context.Background()
				var n int64
				var err error
				switch method {
				case "ReadFrom":
					n, err = destination.ReadFrom(ctx, clientCopyErrorReader{externalErr})
				case "bound ReadFrom":
					n, err = destination.WithContext(ctx).ReadFrom(clientCopyErrorReader{externalErr})
				case "WriteTo":
					n, err = source.WriteTo(ctx, clientCopyErrorWriter{externalErr})
				case "bound WriteTo":
					n, err = source.WithContext(ctx).WriteTo(clientCopyErrorWriter{externalErr})
				}
				require.Same(t, externalErr, err, "external errors must not be attributed by matching their operation or paths")
				if strings.Contains(method, "ReadFrom") {
					require.EqualValues(t, 3, n)
				} else {
					require.Zero(t, n)
				}
				require.Zero(t, fixture.resumes)
				require.Zero(t, fixture.copies)
				for _, file := range []*File{source, destination} {
					d := file.session.client
					d.mu.Lock()
					current := d.sessions[file.session.key]
					d.mu.Unlock()
					require.Same(t, file.session, current, "external errors must not retire either session")
				}
			})
		}
	}
}

func TestClientCopyAcceptsDirectEOF(t *testing.T) {
	t.Parallel()
	_, destination, fixture := newClientCopyPair(t, "external")
	n, err := destination.ReadFrom(context.Background(), clientCopyErrorReader{io.EOF})
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	require.Equal(t, 1, fixture.writes)
	client := destination.session.client
	client.mu.Lock()
	current := client.sessions[destination.session.key]
	client.mu.Unlock()
	require.Same(t, destination.session, current)
}

func TestClientCopyInvalidArgumentsAndSelfCopy(t *testing.T) {
	t.Parallel()
	source, destination, fixture := newClientCopyPair(t, "external")
	ctx := context.Background()
	for _, call := range []func() (int64, error){
		func() (int64, error) { return destination.ReadFrom(ctx, nil) },
		func() (int64, error) { return source.WriteTo(ctx, nil) },
		func() (int64, error) { return destination.WithContext(ctx).ReadFrom(nil) },
		func() (int64, error) { return source.WithContext(ctx).WriteTo(nil) },
		func() (int64, error) { return source.ReadFrom(ctx, source.WithContext(ctx)) },
		func() (int64, error) { return source.WriteTo(ctx, source.WithContext(ctx)) },
		func() (int64, error) { return source.WithContext(ctx).ReadFrom(source.WithContext(ctx)) },
		func() (int64, error) { return source.WithContext(ctx).WriteTo(source.WithContext(ctx)) },
		func() (int64, error) { return destination.ReadFrom(ctx, &fileContext{}) },
		func() (int64, error) { return source.WriteTo(ctx, &fileContext{}) },
	} {
		n, err := call()
		require.Zero(t, n)
		require.Equal(t, os.ErrInvalid, err)
	}
	require.Zero(t, fixture.reads)
	require.Zero(t, fixture.writes)
	require.Zero(t, fixture.resumes)
	require.Zero(t, fixture.copies)
}

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestClientLockErrorsRetireOnlyFailedGeneration(t *testing.T) {
	for _, unlock := range []bool{false, true} {
		for _, status := range []erref.NtStatus{erref.STATUS_LOCK_NOT_GRANTED, erref.STATUS_ACCESS_DENIED, erref.STATUS_FILE_CLOSED, erref.STATUS_NETWORK_SESSION_EXPIRED, erref.STATUS_USER_SESSION_DELETED, erref.STATUS_CONNECTION_DISCONNECTED} {
			t.Run(fmt.Sprintf("unlock=%v/status=%x", unlock, uint32(status)), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ep, healthyEP := newClientTestEndpoint("server"), newClientTestEndpoint("healthy")
					requests := 0
					ep.handleRequest = func(conn net.Conn, request []byte) bool {
						if wire.PacketCodec(request).Command() != wire.SMB2_LOCK {
							return false
						}
						requests++
						writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: wire.SMB2_LOCK}, status)
						return true
					}
					healthyEP.handleRequest = func(conn net.Conn, request []byte) bool {
						if wire.PacketCodec(request).Command() != wire.SMB2_FLUSH {
							return false
						}
						writeFileRecoveryResponse(t, conn, request, &wire.FlushResponse{}, 0)
						return true
					}
					d := New(newClientTestDialer(&clientTestCredentials{}, ep, healthyEP), WithSessionIdleTimeout(0))
					defer d.Close()
					ctx := context.Background()
					name := `\\SERVER\SHARE\original`
					old, err := d.Open(ctx, name)
					require.NoError(t, err)
					sibling, err := d.Open(ctx, `\\server\share\sibling`)
					require.NoError(t, err)
					healthy, err := d.Open(ctx, `\\healthy\share\independent`)
					require.NoError(t, err)
					defer healthy.Close(ctx)
					operation := func(f *File) error {
						if unlock {
							return f.Unlock(ctx, []v2.ByteRange{{Offset: 4, Length: 8}})
						}
						return f.Lock(ctx, []v2.LockRange{{Range: v2.ByteRange{Offset: 4, Length: 8}}}, true)
					}
					err = operation(old)
					require.ErrorIs(t, err, status)
					var pe *os.PathError
					require.ErrorAs(t, err, &pe)
					require.Equal(t, name, pe.Path)
					op := "lock"
					if unlock {
						op = "unlock"
					}
					require.Equal(t, op, pe.Op)
					require.IsNotType(t, &os.PathError{}, pe.Err)
					require.Equal(t, 1, requests)
					require.False(t, old.closed)
					retired := status == erref.STATUS_NETWORK_SESSION_EXPIRED || status == erref.STATUS_USER_SESSION_DELETED || status == erref.STATUS_CONNECTION_DISCONNECTED
					d.mu.Lock()
					current, oldUsers, healthyCurrent := d.sessions[old.session.key], old.session.users, d.sessions[healthy.session.key]
					d.mu.Unlock()
					require.Equal(t, 2, oldUsers)
					require.Same(t, healthy.session, healthyCurrent)
					if retired {
						require.Nil(t, current)
					} else {
						require.Same(t, old.session, current)
					}
					require.NoError(t, healthy.Sync(ctx))
					next, err := d.Open(ctx, `\\server\share\next`)
					require.NoError(t, err)
					defer next.Close(ctx)
					if retired {
						// A late failure on another old handle must preserve the replacement.
						require.NotSame(t, old.session, next.session)
						require.Error(t, operation(sibling))
						synctest.Wait()
						d.mu.Lock()
						current, newUsers := d.sessions[old.session.key], next.session.users
						d.mu.Unlock()
						require.Same(t, next.session, current)
						require.Equal(t, 1, newUsers)
					} else {
						require.Same(t, old.session, next.session)
					}
					// Retired handles may fail to CLOSE because their transport was aborted.
					_ = old.Close(ctx)
					_ = sibling.Close(ctx)
				})
			})
		}
	}
}

func TestClientStatfsRetainsSuccessfulValues(t *testing.T) {
	ep := newClientTestEndpoint("server")
	var queries atomic.Int32
	ep.handleRequest = func(conn net.Conn, request []byte) bool {
		p := wire.PacketCodec(request)
		if p.Command() != wire.SMB2_QUERY_INFO {
			return false
		}
		q := wire.QueryInfoRequestDecoder(p.Body())
		require.Equal(t, uint8(wire.SMB2_0_INFO_FILESYSTEM), q.InfoType())
		require.Equal(t, uint8(wire.FileFsFullSizeInformation), q.FileInfoClass())
		n := queries.Add(1)
		data := make([]byte, 32)
		total, available, free, sectors, bytes := uint64(1000), uint64(300), uint64(500), uint32(8), uint32(512)
		if n > 2 {
			total, available, free, sectors, bytes = 2000, 700, 800, 16, 4096
		}
		binary.LittleEndian.PutUint64(data, total)
		binary.LittleEndian.PutUint64(data[8:], available)
		binary.LittleEndian.PutUint64(data[16:], free)
		binary.LittleEndian.PutUint32(data[24:], sectors)
		binary.LittleEndian.PutUint32(data[28:], bytes)
		writeFileRecoveryResponse(t, conn, request, &wire.QueryInfoResponse{Output: clientTestBytes(data)}, erref.STATUS_SUCCESS)
		return true
	}
	dialer := newClientTestDialer(&clientTestCredentials{}, ep)
	dialer.MaxCreditBalance = 1
	c := New(dialer, WithSessionIdleTimeout(0))
	defer func() { require.NoError(t, c.Close()) }()
	ctx := context.Background()
	const name = `\\server\share\original`
	f, err := c.Open(ctx, name)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close(ctx)) }()
	pathInfo, err := c.Statfs(ctx, name)
	require.NoError(t, err)
	fileInfo, err := f.Statfs(ctx)
	require.NoError(t, err)
	require.NotNil(t, pathInfo)
	require.NotNil(t, fileInfo)
	values := func(info v2.FileFsInfo) [5]uint64 {
		return [5]uint64{info.BlockSize(), info.FragmentSize(), info.TotalBlockCount(), info.FreeBlockCount(), info.AvailableBlockCount()}
	}
	want := [5]uint64{4096, 8, 1000, 500, 300}
	require.Equal(t, want, values(pathInfo))
	require.Equal(t, want, values(fileInfo))
	for i := 0; i < 16; i++ {
		later, err := f.Statfs(ctx)
		require.NoError(t, err)
		require.Equal(t, [5]uint64{65536, 16, 2000, 800, 700}, values(later))
	}
	require.Equal(t, want, values(pathInfo))
	require.Equal(t, want, values(fileInfo))
	require.Equal(t, uint64(4096000), pathInfo.BlockSize()*pathInfo.TotalBlockCount())
	require.Equal(t, uint64(2048000), pathInfo.BlockSize()*pathInfo.FreeBlockCount())
	require.Equal(t, uint64(1228800), pathInfo.BlockSize()*pathInfo.AvailableBlockCount())
	require.Equal(t, int32(18), queries.Load())
}

func TestOpenTruncateFailureRetryPreservesOffset(t *testing.T) {
	for _, layer := range []string{"direct", "Client"} {
		t.Run(layer, func(t *testing.T) {
			const status = erref.STATUS_IO_DEVICE_ERROR
			ep := newClientTestEndpoint("server")
			var size atomic.Int64
			size.Store(8)
			var sets atomic.Int32
			ep.handleRequest = func(conn net.Conn, request []byte) bool {
				p := wire.PacketCodec(request)
				switch p.Command() {
				case wire.SMB2_SET_INFO:
					q := wire.SetInfoRequestDecoder(p.Body())
					require.Equal(t, uint8(wire.SMB2_0_INFO_FILE), q.InfoType())
					require.Equal(t, uint8(wire.FileEndOfFileInformation), q.FileInfoClass())
					desired := int64(binary.LittleEndian.Uint64(p[int(q.BufferOffset()):]))
					require.Equal(t, int64(4), desired)
					if sets.Add(1) == 1 {
						writeFileRecoveryResponse(t, conn, request, &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, status)
					} else {
						size.Store(desired)
						writeFileRecoveryResponse(t, conn, request, &wire.SetInfoResponse{}, erref.STATUS_SUCCESS)
					}
				case wire.SMB2_QUERY_INFO:
					q := wire.QueryInfoRequestDecoder(p.Body())
					require.Equal(t, uint8(wire.FileStandardInformation), q.FileInfoClass())
					data := make([]byte, 24)
					binary.LittleEndian.PutUint64(data[8:], uint64(size.Load()))
					writeFileRecoveryResponse(t, conn, request, &wire.QueryInfoResponse{Output: clientTestBytes(data)}, erref.STATUS_SUCCESS)
				case wire.SMB2_FLUSH:
					writeFileRecoveryResponse(t, conn, request, &wire.FlushResponse{}, erref.STATUS_SUCCESS)
				default:
					return false
				}
				return true
			}
			dialer := newClientTestDialer(&clientTestCredentials{}, ep)
			dialer.MaxCreditBalance = 1
			c := New(dialer, WithSessionIdleTimeout(0))
			defer func() { require.NoError(t, c.Close()) }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			const name = `\\server\share\original`
			f, err := c.Open(ctx, name)
			require.NoError(t, err)
			defer func() { require.NoError(t, f.Close(context.Background())) }()
			truncate, seek, syncFile := f.Truncate, f.Seek, f.Sync
			expectedPath := name
			if layer == "direct" {
				truncate, seek, syncFile = f.file.Truncate, f.file.Seek, f.file.Sync
				expectedPath = "original"
			}
			_, err = seek(ctx, 6, io.SeekStart)
			require.NoError(t, err)
			err = truncate(ctx, 4)
			require.ErrorIs(t, err, status)
			var pe *os.PathError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "truncate", pe.Op)
			require.Equal(t, expectedPath, pe.Path)
			require.IsNotType(t, &os.PathError{}, pe.Err)
			offset, err := seek(ctx, 0, io.SeekCurrent)
			require.NoError(t, err)
			require.Equal(t, int64(6), offset)
			require.Equal(t, int64(8), size.Load())
			require.Equal(t, int32(1), sets.Load(), "failed mutation must not be replayed")
			c.mu.Lock()
			cached := c.sessions[canonicalKey("server")]
			c.mu.Unlock()
			require.Same(t, f.session, cached)
			require.NoError(t, syncFile(ctx))
			next, err := c.Open(ctx, `\\server\share\healthy`)
			require.NoError(t, err)
			defer func() { require.NoError(t, next.Close(ctx)) }()
			require.NoError(t, next.Sync(ctx))
			require.Same(t, f.session, next.session)
			require.NoError(t, truncate(ctx, 4))
			offset, err = seek(ctx, 0, io.SeekCurrent)
			require.NoError(t, err)
			require.Equal(t, int64(6), offset)
			end, err := seek(ctx, 0, io.SeekEnd)
			require.NoError(t, err)
			require.Equal(t, int64(4), end)
			require.Equal(t, int32(2), sets.Load())
		})
	}
}

func TestCopyErrorNilEndpoints(t *testing.T) {
	t.Parallel()
	linkErr := &os.LinkError{Op: "copy", Old: "old", New: "new", Err: os.ErrInvalid}

	err := copyError(linkErr, nil, nil)
	require.Error(t, err)

	src := &File{name: "src"}
	err = copyError(linkErr, src, nil)
	require.Error(t, err)

	dst := &File{name: "dst"}
	err = copyError(linkErr, nil, dst)
	require.Error(t, err)
}
