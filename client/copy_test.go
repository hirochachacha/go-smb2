package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

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
