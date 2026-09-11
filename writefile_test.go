package smb2

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestWriteFileResponseCount(t *testing.T) {
	for _, length := range []int{0, 2, 65536} {
		for _, count := range []uint32{0, 1, uint32(length), uint32(length) + 1} {
			t.Run(fmt.Sprintf("length=%d/count=%d", length, count), func(t *testing.T) {
				f, server := newTestFile(t)
				f.fs.conn.maxWriteSize = 65536
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				share := f.fs.WithContext(ctx)
				serverDone := make(chan error, 1)
				go func() {
					dt := direct(server)
					req, err := readMsg(dt)
					if err != nil {
						serverDone <- err
						return
					}
					for _, command := range []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_WRITE, smb2.SMB2_CLOSE} {
						p := smb2.PacketCodec(req)
						if p.Command() != command {
							serverDone <- fmt.Errorf("command = %v, want %v", p.Command(), command)
							return
						}
						var res smb2.Packet
						switch command {
						case smb2.SMB2_CREATE:
							res = &smb2.CreateResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}, FileId: &smb2.FileId{}}
						case smb2.SMB2_WRITE:
							if got := smb2.WriteRequestDecoder(p.Body()).Length(); got != uint32(length) {
								serverDone <- fmt.Errorf("write length = %d", got)
								return
							}
							res = &smb2.WriteResponse{Count: count}
						case smb2.SMB2_CLOSE:
							res = &smb2.CloseResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}}
						}
						sendTestResponse(dt, req, res, 0)
						if next := p.NextCommand(); next != 0 {
							req = req[next:]
						}
					}
					serverDone <- nil
				}()
				err := share.WriteFile("test.txt", make([]byte, length), 0600)
				switch {
				case count > uint32(length):
					var invalid *InvalidResponseError
					require.ErrorAs(t, err, &invalid)
				case count < uint32(length):
					require.ErrorIs(t, err, io.ErrShortWrite)
				default:
					require.NoError(t, err)
				}
				if err != nil {
					var pathErr *os.PathError
					require.ErrorAs(t, err, &pathErr)
					require.Equal(t, "writefile", pathErr.Op)
					require.Equal(t, "test.txt", pathErr.Path)
				}
				select {
				case err := <-serverDone:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("server did not complete")
				}
			})
		}
	}
}
