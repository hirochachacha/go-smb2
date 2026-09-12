package smb2

import (
	"context"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestCanceledCreateReclaimsHandle(t *testing.T) {
	for _, tc := range []struct {
		name         string
		compound     bool
		cancelAfter  int
		createStatus erref.NtStatus
		closeStatus  erref.NtStatus
		wantClose    int
	}{
		{name: "single success", wantClose: 1},
		{name: "single canceled", createStatus: erref.STATUS_CANCELLED},
		{name: "compound close succeeds", compound: true},
		{name: "compound close fails", compound: true, closeStatus: erref.STATUS_CANCELLED, wantClose: 1},
		{name: "create already received", compound: true, cancelAfter: 1, closeStatus: erref.STATUS_CANCELLED, wantClose: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs = fs.WithContext(ctx)
			fileID := &smb2.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
			cancelSeen := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			closed := make(chan int, 1)
			go func() {
				defer serverConn.Close()
				dt := direct(serverConn)
				req, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				for i := 0; ; i++ {
					p := smb2.PacketCodec(req)
					if i == tc.cancelAfter {
						cancel()
						pkt, err := readMsg(dt)
						if err != nil {
							t.Error(err)
							return
						}
						if smb2.PacketCodec(pkt).Command() != smb2.SMB2_CANCEL {
							t.Error("expected CANCEL")
							return
						}
						close(cancelSeen)
						<-release
					}
					switch p.Command() {
					case smb2.SMB2_CREATE:
						if tc.createStatus == erref.STATUS_SUCCESS {
							sendTestCreateAttributesResponse(dt, req, fileID, smb2.FILE_ATTRIBUTE_NORMAL)
						} else {
							sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(tc.createStatus))
						}
					case smb2.SMB2_QUERY_INFO:
						sendTestResponse(dt, req, &smb2.QueryInfoResponse{Output: rawEncoder(make([]byte, 24))}, uint32(erref.STATUS_SUCCESS))
					case smb2.SMB2_CLOSE:
						if tc.closeStatus == erref.STATUS_SUCCESS {
							sendTestCloseResponse(dt, req)
						} else {
							sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(tc.closeStatus))
						}
					}
					if p.NextCommand() == 0 {
						break
					}
					req = req[p.NextCommand():]
				}
				closeCount := 0
				for {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return
					}
					p := smb2.PacketCodec(req)
					switch p.Command() {
					case smb2.SMB2_CANCEL:
					case smb2.SMB2_CLOSE:
						closeCount++
						got := smb2.CloseRequestDecoder(p.Body()).FileId().Decode()
						if *got != *fileID {
							t.Errorf("closed wrong handle: %v", got)
						}
						sendTestCloseResponse(dt, req)
					case smb2.SMB2_FLUSH:
						sendTestResponse(dt, req, &smb2.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
						closed <- closeCount
						return
					default:
						t.Errorf("unexpected command %v", p.Command())
						return
					}
				}
			}()
			result := make(chan error, 1)
			go func() {
				if tc.compound {
					res, err := fs.request().create("file", smb2.GENERIC_READ, smb2.FILE_OPEN, 0, 0).
						queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 0, 24).close().sendRecv(ctx)
					res.close()
					result <- err
				} else {
					f, err := fs.Open("file")
					if f != nil {
						_ = f.Close()
					}
					result <- err
				}
			}()
			<-cancelSeen
			select {
			case err := <-result:
				t.Fatalf("returned before final CREATE response: %v", err)
			default:
			}
			close(release)
			require.ErrorIs(t, <-result, context.Canceled)
			// A separate request on the same connection must still succeed.
			res, err := fs.request().withFileId(fileID).flush().sendRecv(context.Background())
			require.NoError(t, err)
			res.close()
			require.Equal(t, tc.wantClose, <-closed)
		})
	}
}
