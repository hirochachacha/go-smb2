package smb2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// candidatePeer owns all state in its responder. Directory cursors change only
// on QUERY_DIRECTORY (including an explicit RESTART_SCANS), never on local Seek.
func candidatePeer(t *testing.T, data string, names []string, morePages ...[]string) *Share {
	t.Helper()
	share, peer := newProtocolTestShare(t)
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var next byte
		cursors := map[wire.FileId]int{}
		content := []byte(data)
		pages := append([][]string{names}, morePages...)
		for {
			req, err := testReadPacket(peer)
			if err != nil {
				done <- err
				return
			}
			var replies []compoundResponse
			for off := 0; ; {
				p := wire.PacketCodec(req[off:])
				if p.IsInvalid() {
					done <- fmt.Errorf("invalid request header")
					return
				}
				status := erref.STATUS_SUCCESS
				var response wire.Packet
				switch p.Command() {
				case wire.SMB2_CREATE:
					q := wire.CreateRequestDecoder(p.Body())
					if q.IsInvalid() {
						done <- fmt.Errorf("invalid CREATE")
						return
					}
					next++
					id := wire.FileId{Persistent: [8]byte{next}}
					cursors[id] = 0
					attrs := uint32(wire.FILE_ATTRIBUTE_NORMAL)
					if names != nil {
						attrs = wire.FILE_ATTRIBUTE_DIRECTORY
					}
					response = &wire.CreateResponse{FileId: id, EndofFile: int64(len(content)), FileAttributes: attrs}
				case wire.SMB2_CLOSE:
					response = &wire.CloseResponse{}
				case wire.SMB2_READ:
					q := wire.ReadRequestDecoder(p.Body())
					if q.IsInvalid() {
						done <- fmt.Errorf("invalid READ")
						return
					}
					t.Logf("wire READ offset=%d length=%d", q.Offset(), q.Length())
					start := q.Offset()
					end := min(start+uint64(q.Length()), uint64(len(content)))
					if start >= uint64(len(content)) {
						status = erref.STATUS_END_OF_FILE
						response = &wire.ErrorResponse{CommandCode: p.Command()}
					} else {
						response = &wire.ReadResponse{Data: rawEncoder(content[start:end])}
					}
				case wire.SMB2_WRITE:
					q := wire.WriteRequestDecoder(p.Body())
					if q.IsInvalid() {
						done <- fmt.Errorf("invalid WRITE")
						return
					}
					t.Logf("wire WRITE offset=%d length=%d", q.Offset(), q.Length())
					start := int(q.Offset())
					payload := q.Data()
					end := start + len(payload)
					if start < 0 || end > 1<<20 {
						done <- fmt.Errorf("unbounded WRITE")
						return
					}
					if end > len(content) {
						content = append(content, make([]byte, end-len(content))...)
					}
					copy(content[start:], payload)
					response = &wire.WriteResponse{Count: uint32(len(payload))}
				case wire.SMB2_QUERY_INFO:
					q := wire.QueryInfoRequestDecoder(p.Body())
					if q.IsInvalid() {
						done <- fmt.Errorf("invalid QUERY_INFO")
						return
					}
					output := make([]byte, 104)
					attrs := uint32(wire.FILE_ATTRIBUTE_NORMAL)
					if names != nil {
						attrs = wire.FILE_ATTRIBUTE_DIRECTORY
					}
					le.PutUint32(output[32:], attrs)
					if q.FileInfoClass() == wire.FileStandardInformation {
						output = make([]byte, 24)
						le.PutUint64(output[8:], uint64(len(content)))
					}
					if q.FileInfoClass() == wire.FileAttributeTagInformation {
						output = make([]byte, 8)
						le.PutUint32(output, attrs)
					}
					response = &wire.QueryInfoResponse{Output: rawEncoder(output)}
				case wire.SMB2_QUERY_DIRECTORY:
					q := wire.QueryDirectoryRequestDecoder(p.Body())
					if q.IsInvalid() {
						done <- fmt.Errorf("invalid QUERY_DIRECTORY")
						return
					}
					id := q.FileId().Decode()
					t.Logf("wire QUERY_DIRECTORY handle=%v flags=%#x cursor=%d", id, q.Flags(), cursors[id])
					if q.Flags()&wire.RESTART_SCANS != 0 {
						cursors[id] = 0
					}
					if cursors[id] >= len(pages) {
						status = erref.STATUS_NO_MORE_FILES
						response = &wire.ErrorResponse{CommandCode: p.Command()}
					} else {
						page := pages[cursors[id]]
						cursors[id]++
						var matched []string
						for _, name := range page {
							if serverSearchMatch(q.FileName(), name) {
								matched = append(matched, name)
							}
						}
						if len(matched) == 0 {
							status = erref.STATUS_NO_SUCH_FILE
							response = &wire.ErrorResponse{CommandCode: p.Command()}
						} else {
							response = &wire.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformations(matched))}
						}
					}
				default:
					done <- fmt.Errorf("unexpected command %v", p.Command())
					return
				}
				replies = append(replies, compoundResponse{packet: response, status: status})
				if p.NextCommand() == 0 {
					break
				}
				off += int(p.NextCommand())
			}
			if err := sendCompoundResponse(peer, req, replies); err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = peer.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("responder: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("responder did not finish")
		}
	})
	return share
}

func TestSourceCandidateAppendInitialRead(t *testing.T) {
	for _, tc := range []struct {
		name, data               string
		flag                     int
		bound, copySource, write bool
	}{
		{name: "append-read", data: "abc", flag: os.O_RDWR | os.O_APPEND},
		{name: "no-append", data: "abc", flag: os.O_RDWR},
		{name: "empty", flag: os.O_RDWR | os.O_APPEND},
		{name: "WithContext", data: "abc", flag: os.O_RDWR | os.O_APPEND, bound: true},
		{name: "append-source-copy", data: "abc", flag: os.O_RDWR | os.O_APPEND, copySource: true},
		{name: "write-only-placement", data: "abc", flag: os.O_WRONLY | os.O_APPEND, write: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			share := candidatePeer(t, tc.data, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			f, err := share.OpenFile(ctx, "seed", tc.flag, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := f.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			if tc.write {
				n, err := f.Write(ctx, []byte("d"))
				if n != 1 || err != nil {
					t.Fatalf("Write=%d,%v", n, err)
				}
				check, err := share.Open(ctx, "seed")
				if err != nil {
					t.Fatal(err)
				}
				defer candidateClose(t, check)
				var b bytes.Buffer
				_, err = check.WriteTo(ctx, &b)
				if err != nil || b.String() != "abcd" {
					t.Errorf("content=%q,%v; want abcd", b.String(), err)
				}
				return
			}
			if tc.copySource {
				var b bytes.Buffer
				n, err := f.WithContext(ctx).WriteTo(&b)
				if n != 3 || err != nil || b.String() != "abc" {
					t.Errorf("append source copy=%d,%q,%v; want 3,abc,nil", n, b.String(), err)
				}
				return
			}
			b := make([]byte, 1)
			var n int
			if tc.bound {
				n, err = f.WithContext(ctx).Read(b)
			} else {
				n, err = f.Read(ctx, b)
			}
			if tc.data == "" {
				if n != 0 || err != io.EOF {
					t.Errorf("empty Read=%d,%v", n, err)
				}
				return
			}
			if n != 1 || err != nil || b[0] != 'a' {
				t.Errorf("immediate Read=%d,%q,%v; want 1,a,nil", n, b[:n], err)
			}
		})
	}
}

func candidateClose(t *testing.T, f *File) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.Close(ctx); err != nil {
		t.Error(err)
	}
}

func TestSourceCandidateAppendSourceToFile(t *testing.T) {
	srcShare := candidatePeer(t, "abc", nil)
	dstShare := candidatePeer(t, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	src, err := srcShare.OpenFile(ctx, "seed", os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer candidateClose(t, src)
	dst, err := dstShare.OpenFile(ctx, "destination", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer candidateClose(t, dst)
	n, err := src.WriteTo(ctx, dst.WithContext(ctx))
	if n != 3 || err != nil {
		t.Fatalf("append source -> nonappend File: %d,%v; want 3,nil", n, err)
	}
	got := make([]byte, 3)
	nr, err := dst.ReadAt(ctx, got, 0)
	if nr != 3 || err != nil || string(got) != "abc" {
		t.Errorf("destination=%d,%q,%v", nr, got, err)
	}
}

