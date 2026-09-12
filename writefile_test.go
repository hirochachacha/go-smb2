package smb2

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// writeFileServerState records the CREATE arguments and the file content seen
// by the mock server so tests can verify what the client actually requested.
type writeFileServerState struct {
	mu       sync.Mutex
	content  []byte
	accesses []uint32
	attrs    []uint32
}

func (s *writeFileServerState) snapshot() (content []byte, accesses, attrs []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.content...), append([]uint32(nil), s.accesses...), append([]uint32(nil), s.attrs...)
}

// serveWriteFile answers CREATE/WRITE/CLOSE for both the compound fast path and
// the single-request large-data path. A CREATE that asks for DACL modification
// rights is denied, while GENERIC_WRITE and its constituent rights are allowed.
func serveWriteFile(t *testing.T, dt transport, state *writeFileServerState) {
	t.Helper()

	for {
		req, err := readMsg(dt)
		if err != nil {
			return
		}

		var offsets []int
		for off := 0; ; {
			if len(req)-off < 64 {
				t.Error("truncated compound header")
				return
			}
			offsets = append(offsets, off)
			next := smb2.PacketCodec(req[off:]).NextCommand()
			if next == 0 {
				break
			}
			if next < 64 || next%8 != 0 || uint64(next) > uint64(len(req)-off-64) {
				t.Error("invalid compound offset")
				return
			}
			off += int(next)
		}

		denied := false
		for i, off := range offsets {
			end := len(req)
			if i+1 < len(offsets) {
				end = offsets[i+1]
			}
			p := smb2.PacketCodec(req[off:end])

			if denied {
				// A related compound still receives a response for every
				// operation after a failure ([MS-SMB2] 3.3.5.2.7.2), so the
				// client never waits for a response that will not come.
				sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_INVALID_PARAMETER))
				continue
			}

			switch p.Command() {
			case smb2.SMB2_CREATE:
				cr := smb2.CreateRequestDecoder(p.Body())
				if cr.IsInvalid() {
					t.Error("invalid CREATE request")
					return
				}
				state.mu.Lock()
				state.accesses = append(state.accesses, cr.DesiredAccess())
				state.attrs = append(state.attrs, cr.FileAttributes())
				state.content = state.content[:0]
				state.mu.Unlock()

				// WRITE_DAC is the right to modify the DACL and is not part of
				// GENERIC_WRITE ([MS-SMB2] 2.2.13.1.1). A server that does not
				// grant it fails the open ([MS-SMB2] 3.3.5.9).
				if cr.DesiredAccess()&smb2.WRITE_DAC != 0 {
					sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
					denied = true
				} else {
					sendTestResponse(dt, req[off:], &smb2.CreateResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}, FileId: &smb2.FileId{}}, 0)
				}
			case smb2.SMB2_WRITE:
				wr := smb2.WriteRequestDecoder(p.Body())
				if wr.IsInvalid() {
					t.Error("invalid WRITE request")
					return
				}
				start, length := uint64(wr.DataOffset()), uint64(wr.Length())
				if start < 112 || start > uint64(len(p)) || length > uint64(len(p))-start ||
					wr.Offset() > uint64(int(^uint(0)>>1))-length {
					t.Error("invalid WRITE bounds")
					return
				}
				data := p[start : start+length]
				state.mu.Lock()
				if end := int(wr.Offset()) + len(data); end > len(state.content) {
					state.content = append(state.content, make([]byte, end-len(state.content))...)
				}
				copy(state.content[int(wr.Offset()):], data)
				state.mu.Unlock()
				sendTestResponse(dt, req[off:], &smb2.WriteResponse{Count: wr.Length()}, 0)
			case smb2.SMB2_CLOSE:
				sendTestResponse(dt, req[off:], &smb2.CloseResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}}, 0)
			default:
				t.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}
}

func TestWriteFileDesiredAccess(t *testing.T) {
	f, serverConn := newTestFile(t)
	f.fs.conn.maxWriteSize = 65536

	state := &writeFileServerState{}
	go serveWriteFile(t, direct(serverConn), state)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	share := f.fs.WithContext(ctx)

	limit := f.fs.maxWriteSizeReserving(maxCompoundCreditOverhead)

	fastPath := make([]byte, limit)
	for i := range fastPath {
		fastPath[i] = byte(i)
	}
	largePath := make([]byte, limit+1)
	for i := range largePath {
		largePath[i] = byte(i*7 + 1)
	}

	// Fast path: a single compound CREATE+WRITE+CLOSE.
	require.NoError(t, share.WriteFile("test.txt", fastPath, 0600))
	content, accesses, _ := state.snapshot()
	require.Equal(t, fastPath, content)
	require.Equal(t, []uint32{smb2.GENERIC_WRITE}, accesses)

	// Large-data path: OpenFile with GENERIC_WRITE followed by chunked writes.
	require.NoError(t, share.WriteFile("test.txt", largePath, 0600))
	content, accesses, _ = state.snapshot()
	require.Equal(t, largePath, content)
	require.Equal(t, []uint32{smb2.GENERIC_WRITE, smb2.GENERIC_WRITE}, accesses)
}

func TestWriteFileFastPathFileAttributes(t *testing.T) {
	for _, tc := range []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{"writable", 0600, smb2.FILE_ATTRIBUTE_NORMAL},
		{"readonly", 0400, smb2.FILE_ATTRIBUTE_NORMAL | smb2.FILE_ATTRIBUTE_READONLY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, serverConn := newTestFile(t)
			f.fs.conn.maxWriteSize = 65536

			state := &writeFileServerState{}
			go serveWriteFile(t, direct(serverConn), state)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			share := f.fs.WithContext(ctx)

			require.NoError(t, share.WriteFile("test.txt", []byte("data"), tc.perm))
			_, accesses, attrs := state.snapshot()
			require.Equal(t, []uint32{smb2.GENERIC_WRITE}, accesses)
			require.Equal(t, []uint32{tc.want}, attrs)
		})
	}
}

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
