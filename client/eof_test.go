package client

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestClientPreservesTransportEOF(t *testing.T) {
	for _, method := range []string{"ReadFile", "ReadDir", "FS.ReadFile", "FS.Open.ReadDir", "FS.Open.Read"} {
		for _, n := range []int{-1, 0, 1, 3} {
			if method != "FS.Open.ReadDir" && n != -1 {
				continue
			}
			t.Run(fmt.Sprintf("%s/n=%d", method, n), func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				queries := 0
				contents := strings.Repeat("x", 128<<10)
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := wire.PacketCodec(request)
					require.False(t, p.IsInvalid())
					switch p.Command() {
					case wire.SMB2_CREATE:
						writeFileRecoveryResponse(t, conn, request, &wire.CreateResponse{EndofFile: int64(len(contents)), FileId: wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}}, 0)
					case wire.SMB2_READ:
						r := wire.ReadRequestDecoder(request[64:])
						require.False(t, r.IsInvalid())
						if method != "FS.Open.Read" && r.Offset() == 0 {
							writeFileRecoveryResponse(t, conn, request, &wire.ReadResponse{Data: []byte(contents[:64<<10])}, 0)
						} else {
							require.NoError(t, conn.Close())
						}
					case wire.SMB2_QUERY_DIRECTORY:
						queries++
						if queries == 1 {
							writeFileRecoveryResponse(t, conn, request, &wire.QueryDirectoryResponse{Output: clientTestDirectoryPage("z", "a")}, 0)
						} else {
							require.NoError(t, conn.Close())
						}
					default:
						return false
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.MaxCreditBalance = 1
				dialer.DisableAAPLExtension = true
				d := New(dialer)
				defer d.Close()
				ctx := context.Background()
				name := `\\server\share\file`
				var err error
				switch method {
				case "ReadFile", "FS.ReadFile":
					var data []byte
					if method == "ReadFile" {
						data, err = d.ReadFile(ctx, name)
					} else {
						name = "server/share/file"
						data, err = d.WithContext(ctx).ReadFile(name)
					}
					require.Equal(t, contents[:64<<10], string(data))
				case "ReadDir":
					var entries []os.FileInfo
					entries, err = d.ReadDir(ctx, name)
					require.Len(t, entries, 2)
					require.Equal(t, "a", entries[0].Name())
					require.Equal(t, "z", entries[1].Name())
				case "FS.Open.ReadDir", "FS.Open.Read":
					name = "server/share/file"
					f, openErr := d.WithContext(ctx).Open(name)
					require.NoError(t, openErr)
					defer f.Close()
					if method == "FS.Open.Read" {
						count, readErr := f.Read(make([]byte, 1))
						require.Zero(t, count)
						err = readErr
					} else {
						var entries []fs.DirEntry
						entries, err = f.(fs.ReadDirFile).ReadDir(n)
						if n == 1 {
							require.NoError(t, err)
							require.Len(t, entries, 1)
							entries, err = f.(fs.ReadDirFile).ReadDir(n)
							require.NoError(t, err)
							require.Len(t, entries, 1)
							entries, err = f.(fs.ReadDirFile).ReadDir(n)
							require.Empty(t, entries)
						} else {
							require.Len(t, entries, 2)
						}
					}
				}
				var transportErr *protocol.TransportError
				require.ErrorAs(t, err, &transportErr)
				require.ErrorIs(t, transportErr, io.EOF)
				var pathErr *os.PathError
				require.ErrorAs(t, err, &pathErr)
				require.Equal(t, name, pathErr.Path)
				wantOp := "readdir"
				if method == "ReadFile" || method == "FS.ReadFile" {
					wantOp = "readfile"
				} else if method == "FS.Open.Read" {
					wantOp = "read"
				}
				require.Equal(t, wantOp, pathErr.Op)
				_, nested := pathErr.Err.(*os.PathError)
				require.False(t, nested)
				// Only a subsequent independent operation may establish a new session.
				fresh, openErr := d.Open(ctx, `\\server\share\fresh`)
				require.NoError(t, openErr)
				require.NoError(t, fresh.Close(ctx))
				ep.mu.Lock()
				dials := ep.dials
				ep.mu.Unlock()
				require.Equal(t, 2, dials)
			})
		}
	}
}
