package smb2_test

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2"
	smbclient "github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestMkdirAllRecheckAfterMkdirFailure(t *testing.T) {
	for _, layer := range []string{"Share", "Client"} {
		for _, recheck := range []string{"directory", "file", "error"} {
			t.Run(layer+"/"+recheck, func(t *testing.T) {
				ep := newDFSExternalEndpoint("server")
				var lookups, mkdirs atomic.Int32
				ep.create = func(name string, p wire.PacketCodec) (erref.NtStatus, uint32) {
					require.False(t, p.IsInvalid())
					cr := wire.CreateRequestDecoder(p.Body())
					require.False(t, cr.IsInvalid())
					if name != "child" {
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
					}
					if cr.CreateDisposition() == wire.FILE_CREATE {
						mkdirs.Add(1)
						return erref.STATUS_OBJECT_NAME_COLLISION, 0
					}
					if lookups.Add(1) == 1 {
						return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
					}
					require.NotZero(t, cr.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT, "recheck must use Lstat")
					switch recheck {
					case "directory":
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
					case "file":
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_NORMAL
					default:
						return erref.STATUS_IO_DEVICE_ERROR, 0
					}
				}
				transport, result := newExternalServer(t, func(conn net.Conn, req []byte) error { return ep.serve(conn, req) })
				dialer := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: transport}
				ctx := context.Background()
				var name string
				var mkdirAll func(context.Context, string, os.FileMode) error
				var closeSession func() error
				if layer == "Client" {
					client := smbclient.New(dialer)
					mkdirAll, closeSession, name = client.MkdirAll, client.Close, `\\server\share\child`
				} else {
					session, err := dialer.Dial(ctx, "server")
					require.NoError(t, err)
					closeSession = session.Close
					share, err := session.Mount(ctx, "share")
					require.NoError(t, err)
					mkdirAll, name = share.MkdirAll, "child"
				}
				t.Cleanup(func() {
					require.NoError(t, closeSession())
					externalServerError(t, result)
				})
				err := mkdirAll(ctx, name, 0700)
				if recheck == "directory" {
					require.NoError(t, err)
				} else {
					var pe *os.PathError
					require.ErrorAs(t, err, &pe)
					require.Equal(t, "mkdir", pe.Op)
					require.Equal(t, name, pe.Path)
					require.ErrorIs(t, err, erref.STATUS_OBJECT_NAME_COLLISION)
					require.NotErrorIs(t, err, erref.STATUS_IO_DEVICE_ERROR, "preserve the first mkdir error")
					require.IsNotType(t, &os.PathError{}, pe.Err)
				}
				require.EqualValues(t, 1, mkdirs.Load())
				require.EqualValues(t, 2, lookups.Load())
			})
		}
	}
}
