package smb2_test

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestPathnameTruncateSetInfoFailure(t *testing.T) {
	for _, layer := range []string{"Share", "Client"} {
		t.Run(layer, func(t *testing.T) {
			ep := newDFSExternalEndpoint("server")
			var creates, closes atomic.Int32
			ep.custom = func(conn net.Conn, req []byte) error {
				p := wire.PacketCodec(req)
				require.False(t, p.IsInvalid())
				if p.Command() != wire.SMB2_CREATE || isAAPLServerQuery(req) {
					return ep.serve(conn, req)
				}
				var commands []wire.Command
				for offset := 0; ; {
					part := wire.PacketCodec(req[offset:])
					require.False(t, part.IsInvalid())
					commands = append(commands, part.Command())
					switch part.Command() {
					case wire.SMB2_CREATE:
						cr := wire.CreateRequestDecoder(part.Body())
						require.False(t, cr.IsInvalid())
						require.Equal(t, "file.txt", cr.Name())
						creates.Add(1)
					case wire.SMB2_SET_INFO:
						si := wire.SetInfoRequestDecoder(part.Body())
						require.False(t, si.IsInvalid())
						require.Equal(t, uint8(wire.SMB2_0_INFO_FILE), si.InfoType())
						require.Equal(t, uint8(wire.FileEndOfFileInformation), si.FileInfoClass())
						info := wire.FileEndOfFileInformationDecoder(si.Input())
						require.False(t, info.IsInvalid())
						require.EqualValues(t, 123, info.EndOfFile())
					case wire.SMB2_CLOSE:
						cr := wire.CloseRequestDecoder(part.Body())
						require.False(t, cr.IsInvalid())
						require.Equal(t, wire.RelatedFileId, cr.FileId().Decode())
						closes.Add(1)
					}
					if part.NextCommand() == 0 {
						break
					}
					next := int(part.NextCommand())
					require.GreaterOrEqual(t, next, 64)
					require.Less(t, next, len(req)-offset)
					offset += next
				}
				require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_SET_INFO, wire.SMB2_CLOSE}, commands)
				return dfsExternalWriteCompound(conn, req, []dfsExternalCompoundResponse{
					{packet: externalCreateSuccess()},
					{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, status: erref.STATUS_DISK_FULL},
					{packet: externalCloseSuccess()},
				})
			}
			ctx := context.Background()
			var name string
			var truncate func(context.Context, string, int64) error
			if layer == "Client" {
				client := newDFSExternalClient(t, ep)
				truncate = client.Truncate
				name = `\\server\share\file.txt`
			} else {
				dialer := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: &dfsExternalDialer{
					endpoints: map[string]*dfsExternalEndpoint{"server": ep},
				}}
				session, err := dialer.Dial(ctx, "server")
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, session.Close()) })
				share, err := session.Mount(ctx, "share")
				require.NoError(t, err)
				truncate = share.Truncate
				name = "file.txt"
			}
			err := truncate(ctx, name, 123)
			var pe *os.PathError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "truncate", pe.Op)
			require.Equal(t, name, pe.Path)
			require.ErrorIs(t, err, erref.STATUS_DISK_FULL)
			require.IsNotType(t, &os.PathError{}, pe.Err)
			require.EqualValues(t, 1, creates.Load())
			require.EqualValues(t, 1, closes.Load())
		})
	}
}
