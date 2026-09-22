package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/notify"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestFileAttributesFromPerm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{name: "writable", perm: 0o666, want: wire.FILE_ATTRIBUTE_NORMAL},
		{name: "readonly", perm: 0o444, want: wire.FILE_ATTRIBUTE_NORMAL | wire.FILE_ATTRIBUTE_READONLY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileAttributesFromPerm(tt.perm); got != tt.want {
				t.Errorf("fileAttributesFromPerm(%#o) = %#x, want %#x", tt.perm, got, tt.want)
			}
		})
	}
}

var le = binary.LittleEndian

// parseReaddir sends each raw fixture through the protocol response wrapper,
// so malformed entry chains exercise the same validation as live requests.
func parseReaddir(t testing.TB, output []byte) ([]os.FileInfo, error) {
	t.Helper()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{credits: 100, singleCredit: true})
	startFullFakeServer(serverConn, func(msgID uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		_, _ = testWritePacket(dt, encodeQueryDirResponse(msgID, p.SessionId(), p.TreeId(), output, uint32(erref.STATUS_SUCCESS), false))
		return true
	}, nil, nil)
	res, err := fs.Request().WithFileID(wire.FileId{}).
		QueryDir(wire.FileIdBothDirectoryInformation, "*", maxSingleCreditPayloadSize).
		Do(context.Background())
	if err != nil {
		return nil, err
	}
	defer res.Close()
	query, err := res.QueryDir(0)
	if err != nil {
		return nil, err
	}
	entries, err := query.FileIdBothDirectoryInformation()
	if err != nil {
		return nil, err
	}
	return parseDirectoryEntries(entries), nil
}

type partialReader struct {
	buf *bytes.Buffer
}

func (p *partialReader) Read(b []byte) (int, error) {
	if len(b) < 2 {
		return p.buf.Read(b)
	}
	// read partial of b
	return p.buf.Read(b[:len(b)/2])
}

func TestNilAndClosedFileMethods(t *testing.T) {
	t.Parallel()
	var nilFile *File
	closedFile := &File{}

	if err := nilFile.Close(context.Background()); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("nil.Close() should return os.ErrInvalid, got %v", err)
	}
	if err := closedFile.Close(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Errorf("closedFile.Close() should return os.ErrClosed, got %v", err)
	}

	testCases := []struct {
		name        string
		f           *File
		expectedErr error
	}{
		{"nil", nilFile, os.ErrInvalid},
		{"closed", closedFile, os.ErrClosed},
	}

	for _, tc := range testCases {
		f := tc.f
		expected := tc.expectedErr

		if err := f.Sync(context.Background()); !errors.Is(err, expected) {
			t.Errorf("[%s] Sync error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Stat(context.Background()); !errors.Is(err, expected) {
			t.Errorf("[%s] Stat error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Statfs(context.Background()); !errors.Is(err, expected) {
			t.Errorf("[%s] Statfs error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Truncate(context.Background(), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] Truncate error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Chmod(context.Background(), 0o644); !errors.Is(err, expected) {
			t.Errorf("[%s] Chmod error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Read(context.Background(), make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Read error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.ReadAt(context.Background(), make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] ReadAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Write(context.Background(), make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Write error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.WriteAt(context.Background(), make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] WriteAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Seek(context.Background(), 0, 0); !errors.Is(err, expected) {
			t.Errorf("[%s] Seek error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Readdir(context.Background(), -1); !errors.Is(err, expected) {
			t.Errorf("[%s] Readdir error expected %v, got %v", tc.name, expected, err)
		}
	}
}

func TestNegativeOffsetValidation(t *testing.T) {
	t.Parallel()
	f := &File{fs: &Share{}, fd: wire.FileId{}}

	if _, err := f.ReadAt(context.Background(), make([]byte, 1), -1); err == nil {
		t.Error("ReadAt with negative offset should return error")
	}

	if _, err := f.WriteAt(context.Background(), make([]byte, 1), -1); err == nil {
		t.Error("WriteAt with negative offset should return error")
	}

	if _, err := f.Seek(context.Background(), -1, 0); err == nil {
		t.Error("Seek to negative offset should return error")
	}
}

func startFullFakeServer(serverConn net.Conn, onQueryDir func(msgId uint64, reqBuf []byte, dt net.Conn) bool, onIoctl func(callId *uint32, msgId uint64, reqBuf []byte, dt net.Conn) bool, onQueryInfo func(msgId uint64, reqBuf []byte) []byte, onCreate ...func(req wire.CreateRequestDecoder, cres *wire.CreateResponse)) {
	go func() {
		dt := serverConn
		var callId uint32
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := wire.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				switch cmd {
				case wire.SMB2_TREE_CONNECT:
					tcres := &wire.TreeConnectResponse{
						ShareType: wire.SMB2_SHARE_TYPE_DISK,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case wire.SMB2_CREATE:
					attrs := uint32(0)
					if onQueryDir != nil {
						attrs = wire.FILE_ATTRIBUTE_DIRECTORY
					}
					cres := &wire.CreateResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
						FileAttributes: attrs,
						FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					if len(onCreate) > 0 && onCreate[0] != nil {
						onCreate[0](wire.CreateRequestDecoder(currBuf[64:]), cres)
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case wire.SMB2_CLOSE:
					clres := &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case wire.SMB2_TREE_DISCONNECT:
					tdres := &wire.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case wire.SMB2_QUERY_INFO:
					if onQueryInfo != nil {
						resBuf = onQueryInfo(msgId, currBuf)
					}

				case wire.SMB2_READ:
					reqData := currBuf[64:]
					readLen := int(le.Uint32(reqData[4:8]))
					rres := &wire.ReadResponse{Data: make([]byte, readLen)}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)

				case wire.SMB2_WRITE:
					wres := &wire.WriteResponse{
						Count: wire.WriteRequestDecoder(currBuf[64:]).Length(),
					}
					resBuf = make([]byte, wres.Size())
					wres.Encode(resBuf)

				case wire.SMB2_IOCTL:
					if onIoctl != nil && onIoctl(&callId, msgId, currBuf, dt) {
						resBuf = nil
					}

				case wire.SMB2_QUERY_DIRECTORY:
					if onQueryDir != nil && onQueryDir(msgId, currBuf, dt) {
						resBuf = nil
					}
				}

				if resBuf != nil {
					rp := wire.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						wire.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				testWritePacket(dt, finalBuf)
			}
		}
	}()
}

func encodeFileIdBothDirectoryInformation(name string) []byte {
	return encodeFileIdBothDirectoryInformationBytes(utf16le.EncodeStringToBytes(name))
}

func encodeFileIdBothDirectoryInformationBytes(nameBytes []byte) []byte {
	b := make([]byte, 104+len(nameBytes))
	le.PutUint32(b[0:4], 0)
	le.PutUint32(b[4:8], 1)
	le.PutUint64(b[40:48], 100)
	le.PutUint64(b[48:56], 4096)
	le.PutUint32(b[56:60], 0x20)
	le.PutUint32(b[60:64], uint32(len(nameBytes)))
	le.PutUint64(b[96:104], 1001)
	copy(b[104:], nameBytes)
	return b
}

func encodeFileIdBothDirectoryInformations(names []string) []byte {
	var buf []byte
	for i, name := range names {
		e := encodeFileIdBothDirectoryInformation(name)
		if i < len(names)-1 {
			next := wire.Roundup(len(e), 8)
			le.PutUint32(e[0:4], uint32(next))
			e = append(e, make([]byte, next-len(e))...)
		}
		buf = append(buf, e...)
	}
	return buf
}

func encodeFileIdBothDirectoryInformationAtOffset(firstName string, next uint32, secondName string) []byte {
	first := encodeFileIdBothDirectoryInformation(firstName)
	second := encodeFileIdBothDirectoryInformation(secondName)
	buf := make([]byte, int(next)+len(second))
	copy(buf, first)
	le.PutUint32(buf[0:4], next)
	copy(buf[int(next):], second)
	return buf
}

func TestFileWrite_NegativeBytesWrittenOnChunkError(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{
		maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
		credits: 100,
	})

	go func() {
		dt := serverConn
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := wire.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == wire.SMB2_WRITE {
				eres := &wire.ErrorResponse{CommandCode: wire.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			}
		}
	}()

	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.Write(context.Background(), []byte("test data"))
	require.Error(t, err)

	if n < 0 || f.offset < 0 {
		t.Fatalf("BUG CONFIRMED: File.Write returned negative bytes written n=%d or corrupted offset=%d!", n, f.offset)
	}
}

func TestFileWriteAt_NegativeBytesWrittenOnErr(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{
		maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
		credits: 100,
	})

	go func() {
		dt := serverConn
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := wire.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == wire.SMB2_WRITE {
				eres := &wire.ErrorResponse{CommandCode: wire.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			}
		}
	}()

	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.WriteAt(context.Background(), []byte("test data"), 0)
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.WriteAt returned negative bytes written n=%d!", n)
	}
}

func TestFileSeek_NegativeReturnOnErr(t *testing.T) {
	t.Parallel()
	fs := &Share{}
	f := &File{fs: fs}
	f.closed.Store(true)

	ret, err := f.Seek(context.Background(), 0, io.SeekStart)
	require.Error(t, err)
	if ret < 0 {
		t.Fatalf("BUG CONFIRMED: File.Seek returned negative offset ret=%d on closed file!", ret)
	}
}

func TestReadAtPropagatesChunkError(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{
		maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
		credits: 100,
	})
	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")
	go func() {
		dt := serverConn
		for range 2 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(req)
			readReq := wire.ReadRequestDecoder(req[64:])
			var res []byte
			if readReq.Offset() == 0 {
				rres := &wire.ReadResponse{Data: make([]byte, readReq.Length())}
				res = make([]byte, rres.Size())
				rres.Encode(res)
			} else {
				eres := &wire.ErrorResponse{CommandCode: wire.SMB2_READ}
				res = make([]byte, eres.Size())
				eres.Encode(res)
			}

			rp := wire.PacketCodec(res)
			rp.SetMessageId(p.MessageId())
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			if readReq.Offset() != 0 {
				rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			}
			_, _ = testWritePacket(dt, res)
		}
	}()

	_, err := f.ReadAt(context.Background(), make([]byte, fs.maxReadSize(0)+1), 0)
	require.Error(t, err)
}

func newTestFile(t testing.TB, options ...testServerOptions) (*File, net.Conn) {
	t.Helper()
	fs, serverConn := newProtocolTestShare(t, options...)
	return &File{fs: fs, fd: wire.FileId{}, name: "test.txt"}, serverConn
}

func sendTestResponse(dt net.Conn, req []byte, res wire.Packet, status uint32) {
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := wire.PacketCodec(req)
	rp := wire.PacketCodec(resBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(status)
	rp.SetCreditResponse(1)
	rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	_, _ = testWritePacket(dt, resBuf)
}

func TestReadAtCompletesShortSMBRead(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			readReq := wire.ReadRequestDecoder(req[64:])
			data := []byte{1}
			if readReq.Offset() != 0 {
				data = make([]byte, readReq.Length())
			}
			sendTestResponse(dt, req, &wire.ReadResponse{Data: data}, 0)
		}
	}()

	buf := make([]byte, f.fs.maxReadSize(0)+1)
	n, err := f.ReadAt(context.Background(), buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
}

func TestReadAtCompletesMultipleShortSMBReads(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{1}}, 0)
		}
	}()

	n, err := f.ReadAt(context.Background(), make([]byte, 4), 0)
	require.NoError(t, err)
	require.Equal(t, 4, n)
}

func TestReadAtReturnsEOFOnShortFile(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		for i := range 3 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if i < 2 {
				sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{1}}, 0)
			} else {
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, 0xC0000011) // STATUS_END_OF_FILE
			}
		}
	}()

	n, err := f.ReadAt(context.Background(), make([]byte, 8), 0)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, n)
}

func TestReadCompletesShortSMBRead(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{1}}, 0)
	}()

	n, err := f.Read(context.Background(), make([]byte, 8))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadReturnsErrorOnBufferOverflowWithNoData(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &wire.ReadResponse{}, 0x80000005) // STATUS_BUFFER_OVERFLOW
	}()

	n, err := f.Read(context.Background(), make([]byte, 8))
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestReadLargeBufferReadsSingleChunk(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		readReq := wire.ReadRequestDecoder(req[64:])
		data := []byte{1}
		if readReq.Offset() != 0 {
			data = make([]byte, readReq.Length())
		}
		sendTestResponse(dt, req, &wire.ReadResponse{Data: data}, 0)
	}()

	n, err := f.Read(context.Background(), make([]byte, f.fs.maxReadSize(0)+1))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadAtRejectsInvalidLength(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		readReq := wire.ReadRequestDecoder(req[64:])
		sendTestResponse(dt, req, &wire.ReadResponse{Data: make([]byte, readReq.Length()+1)}, 0)
	}()

	n, err := f.ReadAt(context.Background(), make([]byte, 8), 0)
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestWriteAtRejectsInvalidCount(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		writeReq := wire.WriteRequestDecoder(req[64:])
		sendTestResponse(dt, req, &wire.WriteResponse{Count: writeReq.Length() + 1}, 0)
	}()

	n, err := f.WriteAt(context.Background(), make([]byte, 8), 0)
	require.Error(t, err)
	require.LessOrEqual(t, n, 8)
}

func TestFileWriteAtShortWriteReturnsErrShortWrite(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		writeReq := wire.WriteRequestDecoder(req[64:])
		sendTestResponse(dt, req, &wire.WriteResponse{Count: writeReq.Length() - 1}, 0)
	}()

	n, err := f.WriteAt(context.Background(), make([]byte, 8), 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, io.ErrShortWrite), "expected io.ErrShortWrite, got %v", err)
	require.Equal(t, 7, n)
}

func TestReadAtRejectsOffsetOverflow(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	go func() {
		dt := serverConn
		for range 2 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			readReq := wire.ReadRequestDecoder(req[64:])
			sendTestResponse(dt, req, &wire.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
		}
	}()

	buf := make([]byte, f.fs.maxReadSize(0)+1)
	_, err := f.ReadAt(context.Background(), buf, math.MaxInt64-1)
	require.Error(t, err)
}

func TestFile_ConcurrentClose(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	dt := serverConn

	var closeRequests atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := wire.PacketCodec(reqBuf)
			if p.Command() == wire.SMB2_CLOSE {
				closeRequests.Add(1)
				res := &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}
				sendTestResponse(dt, reqBuf, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	start := make(chan struct{})
	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = f.Close(context.Background())
		}(i)
	}

	close(start)
	wg.Wait()

	var successCount, closedErrCount int
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, os.ErrClosed) {
			closedErrCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	require.Equal(t, 1, successCount, "exactly one Close() should succeed")
	require.Equal(t, concurrency-1, closedErrCount, "remaining Close() calls should return os.ErrClosed")
	require.Equal(t, int32(1), closeRequests.Load(), "server should receive exactly one SMB2_CLOSE request")
}

func TestFileCloseRetriesAfterFailure(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	f, serverConn := newTestFile(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := f.Close(ctx)
	require.Error(err)
	require.False(f.closed.Load())

	dt := serverConn
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &wire.CloseResponse{
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
		}, uint32(erref.STATUS_SUCCESS))
	}()

	require.NoError(f.Close(context.Background()))
	<-done
}

type testRawBytes []byte

func (b testRawBytes) Size() int { return len(b) }

func (b testRawBytes) Encode(p []byte) { copy(p, b) }

type queryDirectoryPage struct {
	output []byte
	status uint32
}

func startQueryDirectoryPages(t *testing.T, serverConn net.Conn, pages ...queryDirectoryPage) *int64 {
	t.Helper()
	var queryCount int64
	onQueryInfo := func(msgId uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
		if wire.QueryInfoRequestDecoder(reqBuf[64:]).FileInfoClass() == wire.FileAttributeTagInformation {
			info = make([]byte, 8)
			le.PutUint32(info, wire.FILE_ATTRIBUTE_DIRECTORY)
		}
		res := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		return resBuf
	}
	startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
		pageIndex := int(atomic.AddInt64(&queryCount, 1)) - 1
		page := queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)}
		if pageIndex < len(pages) {
			page = pages[pageIndex]
		}

		p := wire.PacketCodec(reqBuf)
		if page.status == uint32(erref.STATUS_SUCCESS) {
			_, _ = testWritePacket(dt, encodeQueryDirResponse(msgId, p.SessionId(), p.TreeId(), page.output, page.status, false))
			return true
		}

		errRes := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
		resBuf := make([]byte, errRes.Size())
		errRes.Encode(resBuf)
		rp := wire.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetStatus(page.status)
		rp.SetCreditResponse(1)
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		_, _ = testWritePacket(dt, resBuf)
		return true
	}, nil, onQueryInfo)
	return &queryCount
}

func TestFileChmodRejectsInvalidQueryInfo(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	dt := serverConn
	done := make(chan struct{})
	go func() {
		defer close(done)
		query, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, query, &wire.QueryInfoResponse{
			Output: testRawBytes([]byte{1, 2, 3}),
		}, uint32(erref.STATUS_SUCCESS))
	}()
	err := f.Chmod(context.Background(), 0o644)
	<-done
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func BenchmarkReadAt(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run("Plain/"+sz.name, func(b *testing.B) {
			fs, serverConn := newProtocolTestShare(b, testServerOptions{
				maxReadSize: 1 << 20, maxWriteSize: 1 << 20,
				maxTransactSize: 1 << 20,
			})
			startFullFakeServer(serverConn, nil, nil, nil)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "bench.txt")
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.readAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short read: %d != %d", n, sz.n)
				}
			}
		})
	}

}

func BenchmarkWriteAt(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run("Plain/"+sz.name, func(b *testing.B) {
			fs, serverConn := newProtocolTestShare(b, testServerOptions{
				maxReadSize: 1 << 20, maxWriteSize: 1 << 20,
				maxTransactSize: 1 << 20,
			})
			startFullFakeServer(serverConn, nil, nil, nil)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "bench.txt")
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.writeAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short write: %d != %d", n, sz.n)
				}
			}
		})
	}

}

// makeBenchDirEntries constructs synthetic FileIdBothDirectoryInformation entries for Readdir benchmarks.
func makeBenchDirEntries(count int) []byte {
	var buf []byte
	for i := range count {
		name := utf16le.EncodeStringToBytes(fmt.Sprintf("file_%04d.txt", i))
		entryLen := 104 + len(name)
		paddedLen := (entryLen + 7) &^ 7

		entry := make([]byte, paddedLen)
		if i < count-1 {
			binary.LittleEndian.PutUint32(entry[0:4], uint32(paddedLen)) // NextEntryOffset
		}
		binary.LittleEndian.PutUint32(entry[4:8], uint32(i+1)) // FileIndex
		binary.LittleEndian.PutUint64(entry[40:48], 1024)      // EndOfFile
		binary.LittleEndian.PutUint64(entry[48:56], 4096)      // AllocationSize
		binary.LittleEndian.PutUint32(entry[56:60], uint32(wire.FILE_ATTRIBUTE_NORMAL))
		binary.LittleEndian.PutUint32(entry[60:64], uint32(len(name))) // FileNameLength
		binary.LittleEndian.PutUint64(entry[96:104], uint64(i+1))      // FileId
		copy(entry[104:], name)

		buf = append(buf, entry...)
	}
	return buf
}

func BenchmarkReaddir(b *testing.B) {
	counts := []struct {
		name  string
		count int
	}{
		{"10Entries", 10},
		{"100Entries", 100},
		{"1000Entries", 1000},
	}

	for _, c := range counts {
		b.Run(c.name, func(b *testing.B) {
			fs, serverConn := newProtocolTestShare(b)
			dirData := makeBenchDirEntries(c.count)
			queryCount := 0
			startFullFakeServer(serverConn, func(_ uint64, reqBuf []byte, dt net.Conn) bool {
				queryCount++
				if queryCount%2 == 1 {
					sendTestResponse(dt, reqBuf, &wire.QueryDirectoryResponse{Output: rawEncoder(dirData)}, 0)
				} else {
					sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_NO_MORE_FILES))
				}
				return true
			}, nil, nil)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "benchdir")

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				f.noMoreFiles = false
				f.dirents = nil
				entries, err := f.Readdir(context.Background(), -1)
				if err != nil {
					b.Fatal(err)
				}
				if len(entries) != c.count {
					b.Fatalf("readdir entry count mismatch: %d != %d", len(entries), c.count)
				}
			}
		})
	}
}

func TestFileStatQueriesFileNetworkOpenInformation(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	var gotClass uint8
	var gotLen uint32
	var gotCharge uint16
	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		p := wire.PacketCodec(reqBuf)
		gotCharge = p.CreditCharge()
		qreq := wire.QueryInfoRequestDecoder(p.Body())
		gotClass = qreq.FileInfoClass()
		gotLen = qreq.OutputBufferLength()

		buf := make([]byte, 56)
		le.PutUint32(buf[0:4], 0x11223344)
		le.PutUint32(buf[4:8], 0x01234567)
		le.PutUint32(buf[8:12], 0x55667788)
		le.PutUint32(buf[12:16], 0x01234567)
		le.PutUint32(buf[16:20], 0x99aabbcc)
		le.PutUint32(buf[20:24], 0x01234567)
		le.PutUint32(buf[24:28], 0xddeeff00)
		le.PutUint32(buf[28:32], 0x01234567)
		le.PutUint64(buf[32:40], 16384)
		le.PutUint64(buf[40:48], 8192)
		le.PutUint32(buf[48:52], 0x20)

		res := &wire.QueryInfoResponse{Output: rawEncoder(buf)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		return resBuf
	})

	fi, err := f.Stat(context.Background())
	require.NoError(t, err)
	require.NotNil(t, fi)
	require.Equal(t, uint8(wire.FileNetworkOpenInformation), gotClass)
	require.Equal(t, uint32(56), gotLen)
	require.Equal(t, uint16(1), gotCharge)
	require.Equal(t, int64(8192), fi.Size())
	require.False(t, fi.IsDir())

	fst, ok := fi.(*FileStat)
	require.True(t, ok)
	require.Equal(t, uint32(0x20), fst.FileAttributes)
	require.Equal(t, int64(16384), fst.AllocationSize)
}

func TestFileStatRejectsNegativeFileNetworkOpenInformationTime(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		info := make([]byte, 56)
		le.PutUint64(info[0:8], ^uint64(0)) // CreationTime = -1
		qres := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	fi, err := f.Stat(context.Background())
	require.Nil(t, fi)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestFile_StatRejectsIncompleteFileNetworkOpenInformation(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		output []byte
	}{
		{name: "empty output", output: nil},
		{name: "truncated header", output: make([]byte, 32)},
		{name: "one byte short", output: make([]byte, 55)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "test.txt")

			startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
				res := &wire.QueryInfoResponse{Output: rawEncoder(tt.output)}
				resBuf := make([]byte, res.Size())
				res.Encode(resBuf)
				return resBuf
			})

			fi, err := f.Stat(context.Background())
			var invalidResponseErr *protocol.InvalidResponseError
			require.Nil(t, fi)
			require.ErrorAs(t, err, &invalidResponseErr)
		})
	}
}

func TestNewFileStatConstructors(t *testing.T) {
	t.Parallel()
	// 1. Test newFileStatFromCreateResponse
	createBuf := make([]byte, 88)
	// CreationTime @ 8:16
	le.PutUint32(createBuf[8:12], 0x11223344)
	le.PutUint32(createBuf[12:16], 0x01234567)
	// LastAccessTime @ 16:24
	le.PutUint32(createBuf[16:20], 0x55667788)
	le.PutUint32(createBuf[20:24], 0x01234567)
	// LastWriteTime @ 24:32
	le.PutUint32(createBuf[24:28], 0x99aabbcc)
	le.PutUint32(createBuf[28:32], 0x01234567)
	// ChangeTime @ 32:40
	le.PutUint32(createBuf[32:36], 0xddeeff00)
	le.PutUint32(createBuf[36:40], 0x01234567)
	// AllocationSize @ 40:48
	le.PutUint64(createBuf[40:48], 8192)
	// EndofFile @ 48:56
	le.PutUint64(createBuf[48:56], 4096)
	// FileAttributes @ 56:60
	le.PutUint32(createBuf[56:60], 0x20)

	fst1 := newFileStatFromCreateResponse(createBuf, `foo\bar\test.txt`)
	require.Equal(t, "test.txt", fst1.Name())
	require.Equal(t, int64(4096), fst1.Size())
	require.Equal(t, int64(8192), fst1.AllocationSize)
	require.Equal(t, uint32(0x20), fst1.FileAttributes)

	// 2. Test newFileStatFromFileNetworkOpenInformation
	netInfoBuf := make([]byte, 56)
	// CreationTime @ 0:8
	le.PutUint32(netInfoBuf[0:4], 0x11223344)
	le.PutUint32(netInfoBuf[4:8], 0x01234567)
	// LastAccessTime @ 8:16
	le.PutUint32(netInfoBuf[8:12], 0x55667788)
	le.PutUint32(netInfoBuf[12:16], 0x01234567)
	// LastWriteTime @ 16:24
	le.PutUint32(netInfoBuf[16:20], 0x99aabbcc)
	le.PutUint32(netInfoBuf[20:24], 0x01234567)
	// ChangeTime @ 24:32
	le.PutUint32(netInfoBuf[24:28], 0xddeeff00)
	le.PutUint32(netInfoBuf[28:32], 0x01234567)
	// AllocationSize @ 32:40
	le.PutUint64(netInfoBuf[32:40], 16384)
	// EndOfFile @ 40:48
	le.PutUint64(netInfoBuf[40:48], 8192)
	// FileAttributes @ 48:52
	le.PutUint32(netInfoBuf[48:52], 0x10) // Directory

	fst2 := newFileStatFromFileNetworkOpenInformation(netInfoBuf, `dir\subdir`)
	require.Equal(t, "subdir", fst2.Name())
	require.Equal(t, int64(8192), fst2.Size())
	require.Equal(t, int64(16384), fst2.AllocationSize)
	require.Equal(t, uint32(0x10), fst2.FileAttributes)
	require.True(t, fst2.IsDir())

	// 3. Test newFileStatFromFileIdBothDirectoryInformation
	bothDirBuf := make([]byte, 104)
	// EndOfFile @ 40:48
	le.PutUint64(bothDirBuf[40:48], 100)
	// AllocationSize @ 48:56
	le.PutUint64(bothDirBuf[48:56], 512)
	// FileAttributes @ 56:60
	le.PutUint32(bothDirBuf[56:60], 0x20)

	fst3 := newFileStatFromFileIdBothDirectoryInformation(bothDirBuf, "entry.txt")
	require.Equal(t, "entry.txt", fst3.Name())
	require.Equal(t, int64(100), fst3.Size())
	require.Equal(t, int64(512), fst3.AllocationSize)
	require.Equal(t, uint32(0x20), fst3.FileAttributes)
	require.False(t, fst3.IsDir())
}

func TestLstatDoesNotRegisterFinalizer(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 65536, maxWriteSize: 65536, credits: 100, singleCredit: true})
	var createCount, closeCount int64

	const (
		creationLow    = uint32(0x11223344)
		creationHigh   = uint32(0x01234567)
		accessLow      = uint32(0x55667788)
		accessHigh     = uint32(0x01234567)
		writeLow       = uint32(0x99aabbcc)
		writeHigh      = uint32(0x01234567)
		changeLow      = uint32(0xddeeff00)
		changeHigh     = uint32(0x01234567)
		allocationSize = int64(8192)
		endOfFile      = int64(4096)
		fileAttributes = uint32(0x20)
	)

	filetime := func(low, high uint32) time.Time {
		raw := make([]byte, 8)
		le.PutUint32(raw[0:4], low)
		le.PutUint32(raw[4:8], high)
		return wire.FiletimeDecoder(raw).Time()
	}

	// Fake server that counts CREATE and CLOSE requests so we can detect
	// a spurious CLOSE triggered by a runtime finalizer after GC.
	go func() {
		dt := serverConn
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := wire.PacketCodec(currBuf)
				msgId := p.MessageId()

				var resBuf []byte
				switch p.Command() {
				case wire.SMB2_CREATE:
					atomic.AddInt64(&createCount, 1)
					cres := &wire.CreateResponse{
						CreationTime:   wire.Filetime{LowDateTime: creationLow, HighDateTime: creationHigh},
						LastAccessTime: wire.Filetime{LowDateTime: accessLow, HighDateTime: accessHigh},
						LastWriteTime:  wire.Filetime{LowDateTime: writeLow, HighDateTime: writeHigh},
						ChangeTime:     wire.Filetime{LowDateTime: changeLow, HighDateTime: changeHigh},
						AllocationSize: allocationSize,
						EndofFile:      endOfFile,
						FileAttributes: fileAttributes,
						FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case wire.SMB2_QUERY_INFO:
					output := make([]byte, 8)
					le.PutUint32(output[:4], fileAttributes)
					qres := &wire.QueryInfoResponse{Output: rawEncoder(output)}
					resBuf = make([]byte, qres.Size())
					qres.Encode(resBuf)

				case wire.SMB2_CLOSE:
					atomic.AddInt64(&closeCount, 1)
					clres := &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := wire.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if p.NextCommand() == 0 {
					break
				}
				currBuf = currBuf[p.NextCommand():]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						wire.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				_, _ = testWritePacket(dt, finalBuf)
			}
		}
	}()

	fi, err := fs.Lstat(context.Background(), "test.txt")
	require.NoError(t, err)

	require.Equal(t, "test.txt", fi.Name())
	require.Equal(t, os.FileMode(0o666), fi.Mode())
	require.Equal(t, endOfFile, fi.Size())
	require.True(t, fi.ModTime().Equal(filetime(writeLow, writeHigh)))

	fst, ok := fi.(*FileStat)
	require.True(t, ok, "Lstat must return *FileStat")
	require.True(t, fst.CreationTime.Equal(filetime(creationLow, creationHigh)))
	require.True(t, fst.LastAccessTime.Equal(filetime(accessLow, accessHigh)))
	require.True(t, fst.LastWriteTime.Equal(filetime(writeLow, writeHigh)))
	require.True(t, fst.ChangeTime.Equal(filetime(changeLow, changeHigh)))
	require.Equal(t, endOfFile, fst.EndOfFile)
	require.Equal(t, allocationSize, fst.AllocationSize)
	require.Equal(t, fileAttributes, fst.FileAttributes)

	require.Equal(t, int64(1), atomic.LoadInt64(&createCount))
	require.Equal(t, int64(1), atomic.LoadInt64(&closeCount), "Lstat must send exactly one CLOSE (the compound close)")

	// The *File created by the old implementation becomes unreachable right
	// after Lstat returns, so its finalizer fires on GC and issues a spurious
	// CLOSE request. Force GC and make sure no extra CLOSE ever arrives.
	runtime.GC()
	runtime.GC()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := atomic.LoadInt64(&closeCount); n != 1 {
			t.Fatalf("Lstat registered a finalizer: %d CLOSE requests observed (want 1)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestParseFsFullSizeInfoRejectsNegativeAllocationUnits(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		offset int
	}{
		{name: "TotalAllocationUnits", offset: 0},
		{name: "CallerAvailableAllocationUnits", offset: 8},
		{name: "ActualAvailableAllocationUnits", offset: 16},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			info := make([]byte, 32)
			le.PutUint64(info[0:8], 1000)
			le.PutUint64(info[8:16], 600)
			le.PutUint64(info[16:24], 500)
			le.PutUint32(info[24:28], 8)
			le.PutUint32(info[28:32], 512)
			le.PutUint64(info[testCase.offset:testCase.offset+8], ^uint64(0))

			fs, serverConn := newProtocolTestShare(t, testServerOptions{credits: 100, singleCredit: true})
			startFullFakeServer(serverConn, nil, nil, func(msgID uint64, reqBuf []byte) []byte {
				qres := &wire.QueryInfoResponse{Output: rawEncoder(info)}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)
				return resBuf
			})
			got, err := fs.statfs(context.Background(), nil, "test")
			require.Nil(t, got)
			var invalid *protocol.InvalidResponseError
			require.ErrorAs(t, err, &invalid)
		})
	}
}

func TestStatfs_RegularFilePath(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, path string, sectorsPerAllocationUnit uint32, expectedBlockSize uint64) {
		fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

		done := make(chan struct{})
		go func() {
			defer close(done)
			dt := serverConn
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			// The fake server accepts the CREATE only when it does not force
			// FILE_DIRECTORY_FILE, mirroring how a real server rejects
			// opening a regular file as a directory with
			// STATUS_NOT_A_DIRECTORY.
			notADirectory := false
			curr := reqBuf
			for {
				p := wire.PacketCodec(curr)
				if p.Command() == wire.SMB2_CREATE &&
					wire.CreateRequestDecoder(curr[64:]).CreateOptions()&wire.FILE_DIRECTORY_FILE != 0 {
					notADirectory = true
					break
				}
				if p.NextCommand() == 0 {
					break
				}
				curr = curr[p.NextCommand():]
			}

			curr = reqBuf
			for {
				p := wire.PacketCodec(curr)
				msgId := p.MessageId()
				cmd := p.Command()

				var resBuf []byte
				switch {
				case notADirectory:
					resBuf = make([]byte, 64+8)
					le.PutUint16(resBuf[64:66], 9) // ErrorResponse StructureSize
					rp := wire.PacketCodec(resBuf)
					rp.SetProtocolId()
					rp.SetStructureSize()
					rp.SetCommand(cmd)
					rp.SetStatus(uint32(erref.STATUS_NOT_A_DIRECTORY))
				case cmd == wire.SMB2_CREATE:
					cres := &wire.CreateResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
						FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)
				case cmd == wire.SMB2_QUERY_INFO:
					// FileFsFullSizeInformation (32 bytes)
					info := make([]byte, 32)
					le.PutUint64(info[0:8], 1000)                       // TotalAllocationUnits
					le.PutUint64(info[8:16], 600)                       // CallerAvailableAllocationUnits
					le.PutUint64(info[16:24], 500)                      // ActualAvailableAllocationUnits
					le.PutUint32(info[24:28], sectorsPerAllocationUnit) // SectorsPerAllocationUnit
					le.PutUint32(info[28:32], 512)                      // BytesPerSector
					qres := &wire.QueryInfoResponse{Output: rawEncoder(info)}
					resBuf = make([]byte, qres.Size())
					qres.Encode(resBuf)
				default: // SMB2_CLOSE
					clres := &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(0x100)
				rp.SetTreeId(0x200)
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				if _, err := testWritePacket(dt, resBuf); err != nil {
					return
				}

				if p.NextCommand() == 0 {
					return
				}
				curr = curr[p.NextCommand():]
			}
		}()

		info, err := fs.Statfs(context.Background(), path)
		require.NoError(t, err)
		require.Equal(t, expectedBlockSize, info.BlockSize())
		require.Equal(t, uint64(sectorsPerAllocationUnit), info.FragmentSize())
		require.Equal(t, uint64(1000), info.TotalBlockCount())
		require.Equal(t, uint64(500), info.FreeBlockCount())
		require.Equal(t, uint64(600), info.AvailableBlockCount())
		require.Equal(t, uint64(1000)*expectedBlockSize, info.TotalBlockCount()*info.BlockSize())
		require.Equal(t, uint64(500)*expectedBlockSize, info.FreeBlockCount()*info.BlockSize())
		require.Equal(t, uint64(600)*expectedBlockSize, info.AvailableBlockCount()*info.BlockSize())
	}

	t.Run("regular file", func(t *testing.T) {
		run(t, "file.txt", 8, 4096)
	})

	t.Run("directory", func(t *testing.T) {
		run(t, "dir", 8, 4096)
	})

	t.Run("single-sector allocation unit", func(t *testing.T) {
		run(t, "file.txt", 1, 512)
	})

	t.Run("allocation unit exceeds 32 bits", func(t *testing.T) {
		run(t, "file.txt", 1<<23, 1<<32)
	})
}

func TestParseReaddir_MultipleEntries(t *testing.T) {
	t.Parallel()
	names := []string{".", "..", "alpha", "beta.txt"}
	buf := encodeFileIdBothDirectoryInformations(names)

	fis, err := parseReaddir(t, buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != 2 {
		t.Fatalf("expected 2 entries after excluding dot entries, got %d", len(fis))
	}
	for i, name := range names[2:] {
		if fis[i].Name() != name {
			t.Errorf("entry %d: expected name %q, got %q", i, name, fis[i].Name())
		}
		if got := fis[i].(*FileStat).FileAttributes; got != 0x20 {
			t.Errorf("entry %d: expected attributes %#x, got %#x", i, uint32(0x20), got)
		}
	}
}

func TestParseReaddir_RejectsOddNameLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		buf  func() []byte
	}{
		{
			name: "single entry",
			buf: func() []byte {
				return encodeFileIdBothDirectoryInformationBytes([]byte{'A'})
			},
		},
		{
			name: "odd first entry",
			buf: func() []byte {
				first := encodeFileIdBothDirectoryInformationBytes([]byte{'A'})
				second := encodeFileIdBothDirectoryInformation("second")
				next := wire.Roundup(len(first), 8)
				buf := make([]byte, next+len(second))
				copy(buf, first)
				le.PutUint32(buf[0:4], uint32(next))
				copy(buf[next:], second)
				return buf
			},
		},
		{
			name: "odd final entry after a valid entry",
			buf: func() []byte {
				first := encodeFileIdBothDirectoryInformation("first")
				second := encodeFileIdBothDirectoryInformationBytes([]byte{'A'})
				next := wire.Roundup(len(first), 8)
				buf := make([]byte, next+len(second))
				copy(buf, first)
				le.PutUint32(buf[0:4], uint32(next))
				copy(buf[next:], second)
				return buf
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fis, err := parseReaddir(t, test.buf())
			if fis != nil {
				t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
			}
			if _, ok := err.(*protocol.InvalidResponseError); !ok {
				t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
			}
		})
	}
}

func TestParseReaddir_RejectsPathSeparators(t *testing.T) {
	t.Parallel()
	for _, name := range []string{`..\outside.txt`, `a\b`, `../outside.txt`, `a/b`} {
		t.Run(name, func(t *testing.T) {
			for _, names := range [][]string{{name}, {"valid.txt", name}} {
				fis, err := parseReaddir(t, encodeFileIdBothDirectoryInformations(names))
				if fis != nil {
					t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
				}
				if _, ok := err.(*protocol.InvalidResponseError); !ok {
					t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
				}
			}
		})
	}
}

func TestParseReaddir_UnicodeNames(t *testing.T) {
	t.Parallel()
	names := []string{"ascii.txt", "日本語.txt", "😀.txt", "a..b"}
	fis, err := parseReaddir(t, encodeFileIdBothDirectoryInformations(names))
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != len(names) {
		t.Fatalf("expected %d entries, got %d", len(names), len(fis))
	}
	for i, name := range names {
		if fis[i].Name() != name {
			t.Errorf("entry %d: expected name %q, got %q", i, name, fis[i].Name())
		}
	}
}

func TestParseReaddir_UnpaddedFinalUnicodeName(t *testing.T) {
	t.Parallel()
	const name = "終😀"
	fis, err := parseReaddir(t, encodeFileIdBothDirectoryInformation(name))
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != 1 || fis[0].Name() != name {
		t.Fatalf("expected unpadded final entry %q, got %#v", name, fis)
	}
}

func TestParseReaddir_UnpaddedFinalEntry(t *testing.T) {
	t.Parallel()
	buf := encodeFileIdBothDirectoryInformations([]string{"final"})

	fis, err := parseReaddir(t, buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != 1 || fis[0].Name() != "final" {
		t.Fatalf("expected unpadded final entry, got %#v", fis)
	}
}

func TestParseReaddir_Filetimes(t *testing.T) {
	t.Parallel()
	const futureFiletime = uint64(283696992000000000)
	buf := encodeFileIdBothDirectoryInformation("timestamps.txt")
	for _, offset := range []int{8, 16} {
		le.PutUint64(buf[offset:offset+8], 0)
	}
	for _, offset := range []int{24, 32} {
		le.PutUint64(buf[offset:offset+8], futureFiletime)
	}

	fis, err := parseReaddir(t, buf)
	require.NoError(t, err)
	require.Len(t, fis, 1)

	fst := fis[0].(*FileStat)
	zero := time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC)
	require.True(t, fst.CreationTime.Equal(zero))
	require.True(t, fst.LastAccessTime.Equal(zero))
	require.True(t, fst.LastWriteTime.Equal(future))
	require.True(t, fst.ChangeTime.Equal(future))
}

func TestParseReaddir_NextEntryOffsetEqualsBufferLength(t *testing.T) {
	t.Parallel()
	names := []string{"file1.txt", "file2.txt"}
	buf := encodeFileIdBothDirectoryInformations(names)

	// Some servers terminate the entry list with
	// NextEntryOffset == len(output) instead of 0 on the last entry.
	lastEntrySize := 104 + len(utf16le.EncodeStringToBytes(names[len(names)-1]))
	lastEntryOffset := len(buf) - lastEntrySize
	le.PutUint32(buf[lastEntryOffset:lastEntryOffset+4], uint32(lastEntrySize))

	fis, err := parseReaddir(t, buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != len(names) {
		t.Fatalf("expected %d entries, got %d", len(names), len(fis))
	}
	for i, fi := range fis {
		if fi.Name() != names[i] {
			t.Errorf("entry %d: expected name %q, got %q", i, names[i], fi.Name())
		}
	}
}

func TestParseReaddir_InvalidSmallNextEntryOffset(t *testing.T) {
	t.Parallel()
	for _, next := range []uint32{8, 50} {
		buf := encodeFileIdBothDirectoryInformation("file1.txt")
		// A non-zero NextEntryOffset smaller than the fixed part of
		// FILE_ID_BOTH_DIRECTORY_INFORMATION (104 bytes) is malformed.
		le.PutUint32(buf[0:4], next)

		_, err := parseReaddir(t, buf)
		if err == nil {
			t.Fatalf("parseReaddir(t, next=%d): expected error, got nil", next)
		}
		if _, ok := err.(*protocol.InvalidResponseError); !ok {
			t.Fatalf("parseReaddir(t, next=%d): expected *protocol.InvalidResponseError, got %T", next, err)
		}
	}
}

func TestParseReaddir_InvalidNextEntryOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		buf       []byte
		wantError string
	}{
		{
			name:      "not eight byte aligned",
			buf:       encodeFileIdBothDirectoryInformationAtOffset("", 105, "next"),
			wantError: "non-aligned continuation",
		},
		{
			name:      "overlaps file name",
			buf:       encodeFileIdBothDirectoryInformationAtOffset("a", 104, "next"),
			wantError: "continuation overlaps current entry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseReaddir(t, tc.buf)
			if err == nil {
				t.Fatalf("parseReaddir: expected %s error, got nil", tc.wantError)
			}
			if _, ok := err.(*protocol.InvalidResponseError); !ok {
				t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
			}
		})
	}

	t.Run("outside buffer", func(t *testing.T) {
		buf := encodeFileIdBothDirectoryInformation("")
		le.PutUint32(buf[0:4], uint32(len(buf)+1))

		_, err := parseReaddir(t, buf)
		if err == nil {
			t.Fatal("parseReaddir: expected out-of-range error, got nil")
		}
		if _, ok := err.(*protocol.InvalidResponseError); !ok {
			t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
		}
	})
}

func TestParseReaddir_RejectsNegativeEndOfFile(t *testing.T) {
	t.Parallel()
	for _, eof := range []int64{-1, -1 << 63, 0, 42, 1<<63 - 1} {
		buf := encodeFileIdBothDirectoryInformation("file1.txt")
		le.PutUint64(buf[40:48], uint64(eof))

		fis, err := parseReaddir(t, buf)
		if eof >= 0 {
			require.NoError(t, err)
			require.Len(t, fis, 1)
			require.Equal(t, eof, fis[0].Size())
			continue
		}
		if fis != nil {
			t.Fatalf("parseReaddir(t, EndOfFile=%d): expected no FileInfo, got %d entries", eof, len(fis))
		}
		if _, ok := err.(*protocol.InvalidResponseError); !ok {
			t.Fatalf("parseReaddir(t, EndOfFile=%d): expected *protocol.InvalidResponseError, got %T", eof, err)
		}
	}
}

func TestParseReaddir_RejectsNegativeDirectoryTimes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		offset int
	}{
		{"CreationTime", 8},
		{"LastAccessTime", 16},
		{"LastWriteTime", 24},
		{"ChangeTime", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeFileIdBothDirectoryInformation("file1.txt")
			le.PutUint64(buf[tt.offset:tt.offset+8], 0x8000000000000000)

			fis, err := parseReaddir(t, buf)
			if fis != nil {
				t.Fatalf("parseReaddir(t, %s): expected no FileInfo, got %d entries", tt.name, len(fis))
			}
			if _, ok := err.(*protocol.InvalidResponseError); !ok {
				t.Fatalf("parseReaddir(t, %s): expected *protocol.InvalidResponseError, got %T", tt.name, err)
			}
		})
	}

	t.Run("later entry is invalid", func(t *testing.T) {
		buf := encodeFileIdBothDirectoryInformations([]string{"first", "second"})
		firstSize := wire.Roundup(104+len(utf16le.EncodeStringToBytes("first")), 8)
		le.PutUint64(buf[firstSize+32:firstSize+40], 0xffffffffffffffff)

		fis, err := parseReaddir(t, buf)
		if fis != nil {
			t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
		}
		if _, ok := err.(*protocol.InvalidResponseError); !ok {
			t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
		}
	})
}

func TestReaddirAll_RequestedBufferSize(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{
		maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
		maxTransactSize: 128 * 1024,
		credits:         100,
	})

	const numFiles = 700
	names := make([]string, numFiles)
	for i := range names {
		names[i] = fmt.Sprintf("f%03d", i)
	}
	dirData := encodeFileIdBothDirectoryInformations(names)
	// 700 entries * 112 bytes = 78400 bytes: more than a single-credit payload
	// (64KB) but less than the negotiated max transact size (128KB).
	if len(dirData) <= 64*1024 || len(dirData) > 128*1024 {
		t.Fatalf("test setup: dirData size %d does not match scenario", len(dirData))
	}

	go func() {
		dt := serverConn
		off := 0
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(reqBuf)
			switch p.Command() {
			case wire.SMB2_CREATE:
				// compound CREATE + QUERY_DIRECTORY: locate the query part
				qdir := reqBuf
				for {
					if wire.PacketCodec(qdir).Command() == wire.SMB2_QUERY_DIRECTORY {
						break
					}
					qdir = qdir[wire.PacketCodec(qdir).NextCommand():]
				}
				requested := wire.QueryDirectoryRequestDecoder(qdir[64:]).OutputBufferLength()
				require.EqualValues(t, maxSingleCreditPayloadSize, requested)

				// The server returns as many complete entries as fit in the
				// requested output buffer. The last returned entry terminates
				// the chain (NextEntryOffset = 0), like a real server.
				output := make([]byte, 0, min(int(requested), len(dirData)-off))
				lastEntryLen := 0
				for off < len(dirData) {
					entryLen := int(le.Uint32(dirData[off : off+4]))
					if entryLen == 0 {
						entryLen = len(dirData) - off
					}
					if len(output)+entryLen > int(requested) {
						break
					}
					output = append(output, dirData[off:off+entryLen]...)
					lastEntryLen = entryLen
					off += entryLen
				}
				if len(output) > 0 {
					le.PutUint32(output[len(output)-lastEntryLen:], 0)
				}

				cres := &wire.CreateResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				cresBuf := make([]byte, cres.Size())
				cres.Encode(cresBuf)

				qres := &wire.QueryDirectoryResponse{
					Output: rawEncoder(output),
				}
				qresBuf := make([]byte, qres.Size())
				qres.Encode(qresBuf)

				pad := (8 - (len(cresBuf) % 8)) % 8
				nextCmd := uint32(len(cresBuf) + pad)
				padded := make([]byte, nextCmd)
				copy(padded, cresBuf)
				wire.PacketCodec(padded).SetNextCommand(nextCmd)

				compound := append(append([]byte{}, padded...), qresBuf...)

				head0 := wire.PacketCodec(compound[:len(padded)])
				head0.SetMessageId(p.MessageId())
				head0.SetSessionId(p.SessionId())
				head0.SetTreeId(p.TreeId())
				head0.SetCreditResponse(1)
				head0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				head1 := wire.PacketCodec(compound[len(padded):])
				head1.SetMessageId(p.MessageId() + 1)
				head1.SetSessionId(p.SessionId())
				head1.SetTreeId(p.TreeId())
				head1.SetCreditResponse(3)
				head1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)

				testWritePacket(dt, compound)

			case wire.SMB2_QUERY_DIRECTORY:
				if off >= len(dirData) {
					eres := &wire.ErrorResponse{
						CommandCode: wire.SMB2_QUERY_DIRECTORY,
					}
					resBuf := make([]byte, eres.Size())
					eres.Encode(resBuf)

					erp := wire.PacketCodec(resBuf)
					erp.SetMessageId(p.MessageId())
					erp.SetSessionId(p.SessionId())
					erp.SetTreeId(p.TreeId())
					erp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
					erp.SetCreditResponse(1)
					erp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					testWritePacket(dt, resBuf)
					break
				}

				requested := wire.QueryDirectoryRequestDecoder(p.Body()).OutputBufferLength()
				require.EqualValues(t, maxSingleCreditPayloadSize, requested)

				output := make([]byte, 0, min(int(requested), len(dirData)-off))
				lastEntryLen := 0
				for off < len(dirData) {
					entryLen := int(le.Uint32(dirData[off : off+4]))
					if entryLen == 0 {
						entryLen = len(dirData) - off
					}
					if len(output)+entryLen > int(requested) {
						break
					}
					output = append(output, dirData[off:off+entryLen]...)
					lastEntryLen = entryLen
					off += entryLen
				}
				if len(output) > 0 {
					le.PutUint32(output[len(output)-lastEntryLen:], 0)
				}

				qres := &wire.QueryDirectoryResponse{
					Output: rawEncoder(output),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)

			case wire.SMB2_CLOSE:
				clres := &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}
				resBuf := make([]byte, clres.Size())
				clres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			}
		}
	}()

	fis, err := fs.ReadDir(context.Background(), "testdir")
	require.NoError(t, err)
	require.Len(t, fis, numFiles)
	for i, fi := range fis {
		require.Equal(t, names[i], fi.Name())
	}
}

func TestReaddir_NormalVsBugBehavior(t *testing.T) {
	t.Parallel()
	t.Run("NormalServer_ReturnsFilesThenNoMoreFiles", func(t *testing.T) {
		fs, serverConn := newProtocolTestShare(t, testServerOptions{
			maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
			maxTransactSize: 128 * 1024,
			credits:         100,
		})
		f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

		var reqCount atomic.Int64

		// Normal fakeServer: 1st call returns "file1.txt", 2nd call returns STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
			count := reqCount.Add(1)
			p := wire.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &wire.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			} else {
				// 2nd call: STATUS_NO_MORE_FILES (0x80000606) using standard ErrorResponse
				eres := &wire.ErrorResponse{
					CommandCode: wire.SMB2_QUERY_DIRECTORY,
				}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(context.Background(), -1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Normal Readdir completed cleanly after %d requests, got %d files", reqCount.Load(), len(fis))
	})

	t.Run("BugBehavior_ServerReturnsEmptySuccessInsteadOfNoMoreFiles", func(t *testing.T) {
		fs, serverConn := newProtocolTestShare(t, testServerOptions{
			maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
			maxTransactSize: 128 * 1024,
			credits:         100,
		})
		f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

		var reqCount atomic.Int64

		// Parameter change: 1st call returns "file1.txt", 2nd call returns STATUS_SUCCESS (0) with empty output instead of STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
			count := reqCount.Add(1)
			p := wire.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &wire.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0)
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			} else {
				// 2nd call: PARAMETER CHANGED to STATUS_SUCCESS (0) with 0 bytes output
				qres := &wire.QueryDirectoryResponse{
					Output: rawEncoder([]byte{}),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(context.Background(), -1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Readdir completed cleanly after fix even with empty STATUS_SUCCESS response (%d requests)", reqCount.Load())
	})

	t.Run("EmptyDir_ServerReturnsNoSuchFile", func(t *testing.T) {
		fs, serverConn := newProtocolTestShare(t, testServerOptions{
			maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
			maxTransactSize: 128 * 1024,
			credits:         100,
		})
		f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "emptydir")

		var reqCount atomic.Int64

		// Some servers report STATUS_NO_SUCH_FILE on the first QUERY_DIRECTORY
		// of an empty directory instead of STATUS_NO_MORE_FILES. Readdir must
		// treat it as a normal end-of-directory, not an error.
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
			reqCount.Add(1)
			p := wire.PacketCodec(reqBuf)

			eres := &wire.ErrorResponse{
				CommandCode: wire.SMB2_QUERY_DIRECTORY,
			}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)

			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(uint32(erref.STATUS_NO_SUCH_FILE))
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		}, nil, nil)

		fis, err := f.Readdir(context.Background(), -1)
		require.NoError(t, err)
		require.Empty(t, fis)

		// End of directory is reached: a subsequent read reports io.EOF.
		_, err = f.Readdir(context.Background(), 1)
		require.ErrorIs(t, err, io.EOF)
		t.Logf("PASS: Readdir treated STATUS_NO_SUCH_FILE as empty directory after %d requests", reqCount.Load())
	})
}

func TestReaddirContinuesPastDotOnlyPages(t *testing.T) {
	t.Parallel()
	for _, n := range []int{-1, 1} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

			queryCount := startQueryDirectoryPages(t, serverConn,
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformations([]string{"."}),
				},
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformations([]string{".."}),
				},
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformation("visible.txt"),
				},
				queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)},
			)

			fis, err := f.Readdir(context.Background(), n)
			require.NoError(t, err)
			require.Len(t, fis, 1)
			require.Equal(t, "visible.txt", fis[0].Name())
			if n == 1 {
				require.EqualValues(t, 3, atomic.LoadInt64(queryCount))
			} else {
				require.EqualValues(t, 4, atomic.LoadInt64(queryCount))
			}
		})
	}
}

func TestReaddirReleasesDotOnlyPagesBeforeNextQuery(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t)
	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

	// The public file API does not expose receive buffers. Advancing through
	// multiple dot-only pages before returning the visible entry exercises the
	// same response-release boundary through the supported API.
	queryCount := startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{".", ".."})},
		queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{".", ".."})},
		queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("visible.txt")},
	)

	entries, err := f.Readdir(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "visible.txt", entries[0].Name())
	require.EqualValues(t, 3, atomic.LoadInt64(queryCount))
}

func TestReaddirReturnsParseErrorAfterDotOnlyPage(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

	queryCount := startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{output: []byte{0}},
	)

	_, err := f.Readdir(context.Background(), -1)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.EqualValues(t, 2, atomic.LoadInt64(queryCount))
}

func TestReaddirDotPagesBeforeEnd(t *testing.T) {
	t.Parallel()
	for _, dotPages := range []int{1, 2} {
		for _, status := range []uint32{0, uint32(erref.STATUS_NO_MORE_FILES)} {
			t.Run(fmt.Sprintf("pages=%d/status=%x", dotPages, status), func(t *testing.T) {
				fs, serverConn := newTestShare(t)
				f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")
				pages := []queryDirectoryPage{{output: encodeFileIdBothDirectoryInformation(".")}}
				if dotPages == 2 {
					pages = append(pages, queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("..")})
				}
				pages = append(pages, queryDirectoryPage{status: status})
				queryCount := startQueryDirectoryPages(t, serverConn, pages...)
				fis, err := f.Readdir(context.Background(), -1)
				require.NoError(t, err)
				require.Empty(t, fis)
				require.EqualValues(t, dotPages+1, atomic.LoadInt64(queryCount))
			})
		}
	}
}

func TestReaddirStopsAfterThreeDotOnlyPages(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")

	var queryCount int64
	startFullFakeServer(serverConn, func(_ uint64, reqBuf []byte, dt net.Conn) bool {
		count := atomic.AddInt64(&queryCount, 1)
		if count <= 3 {
			sendTestResponse(dt, reqBuf, &wire.QueryDirectoryResponse{
				Output: rawEncoder(encodeFileIdBothDirectoryInformations([]string{".", ".."})),
			}, uint32(erref.STATUS_SUCCESS))
		} else {
			errRes := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
			sendTestResponse(dt, reqBuf, errRes, uint32(erref.STATUS_NO_MORE_FILES))
		}
		return true
	}, nil, func(_ uint64, _ []byte) []byte {
		output := make([]byte, 8)
		le.PutUint32(output[:4], wire.FILE_ATTRIBUTE_DIRECTORY)
		response := &wire.QueryInfoResponse{Output: rawEncoder(output)}
		buf := make([]byte, response.Size())
		response.Encode(buf)
		return buf
	})

	_, err := f.Readdir(context.Background(), -1)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "readdir", pathErr.Op)
	require.Equal(t, "query directory returned only dot entries", pathErr.Err.Error())
	require.EqualValues(t, 3, atomic.LoadInt64(&queryCount))

	// A malformed enumeration must not poison the shared connection.
	_, err = fs.Stat(context.Background(), "other")
	require.NoError(t, err)
}

func TestFile_Readdir_NoSliceAliasing(t *testing.T) {
	t.Parallel()
	entry1 := &FileStat{FileName: "file1.txt"}
	entry2 := &FileStat{FileName: "file2.txt"}
	entry3 := &FileStat{FileName: "file3.txt"}

	f := &File{
		fs:          &Share{},
		fd:          wire.FileId{},
		noMoreFiles: true,
		dirents:     []os.FileInfo{entry1, entry2, entry3},
	}

	first, err := f.Readdir(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "file1.txt", first[0].Name())

	// If capacity is not restricted with 3-index slicing, append would overwrite entry2 in f.dirents
	bogus := &FileStat{FileName: "corrupted.txt"}
	_ = append(first, bogus)

	second, err := f.Readdir(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "file2.txt", second[0].Name())
}

func TestQueryDirectoryResponseBufferBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		offset  uint16
		length  uint32
		size    int
		invalid bool
	}{
		{"header", 64, 1, 8, true}, {"fixed fields", 71, 1, 8, true},
		{"valid", 72, 106, 114, false}, {"empty zero offset", 0, 0, 8, false},
		{"empty end", 72, 0, 8, false}, {"empty beyond end", 73, 0, 8, true},
		{"overflow", 72, 0xffffffff, 8, true}, {"truncated", 72, 2, 9, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := make([]byte, 64+tc.size)
			(&wire.QueryDirectoryResponse{}).Encode(pkt)
			le.PutUint16(pkt[66:68], tc.offset)
			le.PutUint32(pkt[68:72], tc.length)
			if tc.name == "valid" {
				copy(pkt[72:], encodeFileIdBothDirectoryInformation("x"))
			}
			r := wire.QueryDirectoryResponseDecoder(pkt[64:])
			if tc.invalid {
				require.True(t, r.IsInvalid())
				return
			}
			require.False(t, r.IsInvalid())
			if tc.name == "valid" {
				entries, err := parseReaddir(t, r.Output())
				require.NoError(t, err)
				require.Len(t, entries, 1)
				require.Equal(t, "x", entries[0].Name())
			}
		})
	}
}

func TestParseReaddir_RejectsNULNames(t *testing.T) {
	t.Parallel()
	nulName := func(name string, count int) []byte {
		nameBytes := utf16le.EncodeStringToBytes(name)
		return append(nameBytes, make([]byte, 2*count)...)
	}

	tests := []struct {
		name      string
		nameBytes []byte
	}{
		{name: "dot plus NUL", nameBytes: nulName(".", 1)},
		{name: "dotdot plus NUL", nameBytes: nulName("..", 1)},
		{name: "dotdot plus multiple NULs", nameBytes: nulName("..", 2)},
		{name: "trailing NUL", nameBytes: nulName("name", 1)},
		{name: "embedded NUL", nameBytes: nulName("na", 1)},
	}
	tests[4].nameBytes = append(tests[4].nameBytes, utf16le.EncodeStringToBytes("me")...)

	for _, test := range tests {
		for _, withValidEntry := range []bool{false, true} {
			caseName := "single entry"
			if withValidEntry {
				caseName = "after valid entry"
			}
			t.Run(test.name+"/"+caseName, func(t *testing.T) {
				invalid := encodeFileIdBothDirectoryInformationBytes(test.nameBytes)
				buf := invalid
				if withValidEntry {
					valid := encodeFileIdBothDirectoryInformation("valid.txt")
					next := wire.Roundup(len(valid), 8)
					buf = make([]byte, next+len(invalid))
					copy(buf, valid)
					le.PutUint32(buf[0:4], uint32(next))
					copy(buf[next:], invalid)
				}

				fis, err := parseReaddir(t, buf)
				if fis != nil {
					t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
				}
				if _, ok := err.(*protocol.InvalidResponseError); !ok {
					t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
				}
			})
		}
	}
}

func TestParseReaddir_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		names []string
	}{
		{name: "single empty entry", names: []string{""}},
		{name: "empty final entry after valid entry", names: []string{"valid.txt", ""}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fis, err := parseReaddir(t, encodeFileIdBothDirectoryInformations(test.names))
			if fis != nil {
				t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
			}
			if _, ok := err.(*protocol.InvalidResponseError); !ok {
				t.Fatalf("parseReaddir: expected *protocol.InvalidResponseError, got %T", err)
			}
		})
	}
}

func TestReadDirCompoundFailureClosesServerHandle(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

	expectedFileId := wire.FileId{
		Persistent: [8]byte{2, 3, 4, 5, 6, 7, 8, 9},
		Volatile:   [8]byte{10, 11, 12, 13, 14, 15, 16, 17},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectory ErrorResponse
		errPkt1 := &wire.ErrorResponse{
			CommandCode: wire.SMB2_QUERY_DIRECTORY,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		wire.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
		wire.PacketCodec(resBuf1).SetSessionId(p.SessionId())
		wire.PacketCodec(resBuf1).SetTreeId(p.TreeId())
		wire.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(resBuf1).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = testWritePacket(dt, compound)

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeReq := wire.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if fd == expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = testWritePacket(dt, closeBuf)
		}
	}()

	_, err := fs.ReadDir(context.Background(), "some_dir")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle when ReadDir fails mid-flight")
}

func TestReadDir_EmptyDirectory(t *testing.T) {
	t.Parallel()
	// Some servers (e.g. Samba) report STATUS_NO_MORE_FILES or even
	// STATUS_NO_SUCH_FILE on the first QUERY_DIRECTORY of a compound
	// CREATE+QUERY_DIRECTORY when the directory has no entries.
	for _, status := range []erref.NtStatus{erref.STATUS_NO_MORE_FILES, erref.STATUS_NO_SUCH_FILE} {
		t.Run(status.Error(), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := serverConn

			expectedFileId := wire.FileId{
				Persistent: [8]byte{4, 5, 6, 7, 8, 9, 10, 11},
				Volatile:   [8]byte{12, 13, 14, 15, 16, 17, 18, 19},
			}

			var closeReceived atomic.Bool

			done := make(chan struct{})
			go func() {
				defer close(done)
				// Request 1: compound create + queryDir (ReadDir)
				reqBuf1, err := readMsg(dt)
				if err != nil {
					return
				}

				p := wire.PacketCodec(reqBuf1)

				// Op 0: CreateResponse SUCCESS
				createRes := &wire.CreateResponse{
					FileId:         expectedFileId,
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}
				resBuf0 := make([]byte, createRes.Size())
				createRes.Encode(resBuf0)
				pad0 := (8 - (len(resBuf0) % 8)) % 8
				next0 := uint32(len(resBuf0) + pad0)
				padded0 := make([]byte, next0)
				copy(padded0, resBuf0)
				wire.PacketCodec(padded0).SetMessageId(p.MessageId())
				wire.PacketCodec(padded0).SetSessionId(p.SessionId())
				wire.PacketCodec(padded0).SetTreeId(p.TreeId())
				wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
				wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				wire.PacketCodec(padded0).SetNextCommand(next0)

				// Op 1: QueryDirectory ErrorResponse
				errPkt1 := &wire.ErrorResponse{
					CommandCode: wire.SMB2_QUERY_DIRECTORY,
				}
				resBuf1 := make([]byte, errPkt1.Size())
				errPkt1.Encode(resBuf1)
				wire.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
				wire.PacketCodec(resBuf1).SetSessionId(p.SessionId())
				wire.PacketCodec(resBuf1).SetTreeId(p.TreeId())
				wire.PacketCodec(resBuf1).SetStatus(uint32(status))
				wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
				wire.PacketCodec(resBuf1).SetCreditResponse(1)

				var compound []byte
				compound = append(compound, padded0...)
				compound = append(compound, resBuf1...)
				_, _ = testWritePacket(dt, compound)

				// Request 2: automatic fallback close request
				reqBuf2, err := readMsg(dt)
				if err != nil {
					return
				}
				p2 := wire.PacketCodec(reqBuf2)
				if p2.Command() == wire.SMB2_CLOSE {
					closeReq := wire.CloseRequestDecoder(p2.Body())
					if !closeReq.IsInvalid() {
						fd := closeReq.FileId().Decode()
						if fd == expectedFileId {
							closeReceived.Store(true)
						}
					}
					closeRes := &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}
					closeBuf := make([]byte, closeRes.Size())
					closeRes.Encode(closeBuf)
					rp := wire.PacketCodec(closeBuf)
					rp.SetMessageId(p2.MessageId())
					rp.SetSessionId(p2.SessionId())
					rp.SetTreeId(p2.TreeId())
					rp.SetStatus(uint32(erref.STATUS_SUCCESS))
					rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					rp.SetCreditResponse(1)
					_, _ = testWritePacket(dt, closeBuf)
				}
			}()

			fis, err := fs.ReadDir(context.Background(), "some_dir")
			require.NoError(t, err, "an empty directory must not fail")
			require.NotNil(t, fis, "an empty directory must return a non-nil slice")
			require.Len(t, fis, 0)

			<-done
			require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle")
		})
	}
}

func TestReadDirContinuesEnumerationWhenFirstResponseIsSmallerThanRequested(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

	expectedFileId := wire.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (Share.ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectoryResponse with a single entry. The response is
		// far smaller than the requested OutputBufferLength (maxTransactSize),
		// but the server still has more entries to return.
		resBuf1 := encodeQueryDirResponse(p.MessageId()+1, p.SessionId(), p.TreeId(), encodeFileIdBothDirEntry("alpha.txt"), uint32(erref.STATUS_SUCCESS), true)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = testWritePacket(dt, compound)

		// Request 2: follow-up queryDir issued by Readdir(-1); one more entry
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		resBuf2 := encodeQueryDirResponse(p2.MessageId(), p2.SessionId(), p2.TreeId(), encodeFileIdBothDirEntry("beta.txt"), uint32(erref.STATUS_SUCCESS), false)
		_, _ = testWritePacket(dt, resBuf2)

		// Request 3: follow-up queryDir; no more entries
		reqBuf3, err := readMsg(dt)
		if err != nil {
			return
		}
		p3 := wire.PacketCodec(reqBuf3)
		errPkt := &wire.ErrorResponse{
			CommandCode: wire.SMB2_QUERY_DIRECTORY,
		}
		errBuf := make([]byte, errPkt.Size())
		errPkt.Encode(errBuf)
		ep := wire.PacketCodec(errBuf)
		ep.SetMessageId(p3.MessageId())
		ep.SetSessionId(p3.SessionId())
		ep.SetTreeId(p3.TreeId())
		ep.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		ep.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		ep.SetCreditResponse(1)
		_, _ = testWritePacket(dt, errBuf)

		// Request 4: automatic close issued by ReadDir's deferred Close
		reqBuf4, err := readMsg(dt)
		if err != nil {
			return
		}
		p4 := wire.PacketCodec(reqBuf4)
		if p4.Command() == wire.SMB2_CLOSE {
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p4.MessageId())
			rp.SetSessionId(p4.SessionId())
			rp.SetTreeId(p4.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = testWritePacket(dt, closeBuf)
		}
	}()

	fis, err := fs.ReadDir(context.Background(), "some_dir")
	require.NoError(t, err)

	names := make([]string, len(fis))
	for i, fi := range fis {
		names[i] = fi.Name()
	}
	require.Equal(t, []string{"alpha.txt", "beta.txt"}, names, "entries from subsequent query batches must not be dropped")

	<-done
}

func TestReadDirStopsAfterThreeDotOnlyPages(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
	var queryCount int64 = 1 // The initial QUERY_DIRECTORY is compound with CREATE.
	done := make(chan struct{})
	go func() {
		defer close(done)

		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)

		createRes := &wire.CreateResponse{
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
			FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
		}
		createBuf := make([]byte, createRes.Size())
		createRes.Encode(createBuf)
		pad := (8 - (len(createBuf) % 8)) % 8
		paddedCreate := make([]byte, len(createBuf)+pad)
		copy(paddedCreate, createBuf)
		createPacket := wire.PacketCodec(paddedCreate)
		createPacket.SetMessageId(p.MessageId())
		createPacket.SetSessionId(p.SessionId())
		createPacket.SetTreeId(p.TreeId())
		createPacket.SetStatus(uint32(erref.STATUS_SUCCESS))
		createPacket.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		createPacket.SetNextCommand(uint32(len(paddedCreate)))

		queryBuf := encodeQueryDirResponse(
			p.MessageId()+1,
			p.SessionId(),
			p.TreeId(),
			encodeFileIdBothDirectoryInformations([]string{".", ".."}),
			uint32(erref.STATUS_SUCCESS),
			true,
		)
		_, _ = testWritePacket(dt, append(paddedCreate, queryBuf...))

		for {
			reqBuf, err = readMsg(dt)
			if err != nil {
				return
			}
			if wire.PacketCodec(reqBuf).Command() == wire.SMB2_CLOSE {
				sendTestResponse(dt, reqBuf, &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
				return
			}

			count := atomic.AddInt64(&queryCount, 1)
			if count <= 4 {
				sendTestResponse(dt, reqBuf, &wire.QueryDirectoryResponse{
					Output: rawEncoder(encodeFileIdBothDirectoryInformations([]string{".", ".."})),
				}, uint32(erref.STATUS_SUCCESS))
			} else {
				sendTestResponse(dt, reqBuf, &wire.ErrorResponse{
					CommandCode: wire.SMB2_QUERY_DIRECTORY,
				}, uint32(erref.STATUS_NO_MORE_FILES))
			}
		}
	}()

	_, err := fs.ReadDir(context.Background(), "testdir")
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "readdir", pathErr.Op)
	require.Equal(t, "testdir", pathErr.Path)
	var fileErr *os.PathError
	require.ErrorAs(t, pathErr.Err, &fileErr)
	require.Equal(t, "readdir", fileErr.Op)
	require.EqualError(t, fileErr.Err, "query directory returned only dot entries")
	require.EqualValues(t, 4, atomic.LoadInt64(&queryCount))
	<-done
}

func TestReaddirContinuesPastSplitDotEntries(t *testing.T) {
	t.Parallel()
	dot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{"."})}
	dotdot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{".."})}
	visible := queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("visible.txt")}
	end := queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)}

	cases := []struct {
		name  string
		pages []queryDirectoryPage
		want  []string
	}{
		{
			name:  "single dot page then entry",
			pages: []queryDirectoryPage{dot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then entry",
			pages: []queryDirectoryPage{dot, dotdot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then end of enumeration",
			pages: []queryDirectoryPage{dot, dotdot, end},
			want:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")
			queryCount := startQueryDirectoryPages(t, serverConn, tc.pages...)

			fis, err := f.Readdir(context.Background(), -1)
			require.NoError(t, err)
			names := make([]string, len(fis))
			for i, fi := range fis {
				names[i] = fi.Name()
			}
			require.Equal(t, tc.want, names)
			require.EqualValues(t, len(tc.pages), atomic.LoadInt64(queryCount))
		})
	}
}

func TestCopyBufferPartialRead(t *testing.T) {
	t.Parallel()
	bufIn := []byte("this is a partial read test data")
	bufR := make([]byte, len(bufIn))
	copy(bufR, bufIn)
	p := &partialReader{
		buf: bytes.NewBuffer(bufR),
	}
	var bufW bytes.Buffer
	n, err := copyBuffer(p, &bufW, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(bufIn)) {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(bufIn, bufW.Bytes()) {
		t.Fatal("data not equal")
	}
}

func TestReadFrom_NegativeBytesWrittenOnCopyFileErr(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{
		maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024,
		credits: 100,
	})

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			eres := &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		}
		return false
	}, nil)

	srcFile := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "src.txt")
	dstFile := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

	n, err := dstFile.ReadFrom(context.Background(), srcFile.WithContext(context.Background()))
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.ReadFrom returned negative bytes read n=%d on copyFile error!", n)
	}
}

func TestFileCopyToSelf(t *testing.T) {
	t.Parallel()
	f := &File{}

	if _, err := f.ReadFrom(context.Background(), &boundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("ReadFrom self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
	if _, err := f.WriteTo(context.Background(), &boundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("WriteTo self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
}

func TestFileCopyAcrossSharesSharingTreeConn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		op   func(src, dst *File)
	}{
		{"ReadFrom", func(src, dst *File) { _, _ = dst.ReadFrom(context.Background(), src.WithContext(context.Background())) }},
		{"WriteTo", func(src, dst *File) {
			_, _ = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs1, serverConn := newProtocolTestShare(t)
			fs2 := fs1

			var resumeKeyRequests atomic.Int32
			go func() {
				dt := serverConn
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					switch wire.PacketCodec(req).Command() {
					case wire.SMB2_IOCTL:
						reqData := req[64:]
						if wire.IoctlRequestDecoder(reqData).CtlCode() == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
							resumeKeyRequests.Add(1)
						}
						sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, 0xC0000001)
					case wire.SMB2_READ:
						readReq := wire.ReadRequestDecoder(req[64:])
						sendTestResponse(dt, req, &wire.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
					case wire.SMB2_WRITE:
						sendTestResponse(dt, req, &wire.WriteResponse{}, 0)
					}
				}
			}()

			srcFile := fs1.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "src.txt")
			dstFile := fs2.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

			tc.op(srcFile, dstFile)

			require.Equal(t, int32(1), resumeKeyRequests.Load(),
				"copyFile (FSCTL_SRV_REQUEST_RESUME_KEY) must be attempted between files opened from different Share instances sharing the same treeConn")
		})
	}
}

func TestLargeMockFileCopy(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	const fileSize = 10 * 1024 * 1024 // 10MB
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go func() {
		dt := serverConn
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case wire.SMB2_WRITE:
				wreq := wire.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &wire.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				testWritePacket(dt, resBuf)

			case wire.SMB2_READ:
				rreq := wire.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				end := min(int(off)+int(length), len(mockStorage))
				var chunkData []byte
				if int(off) < len(mockStorage) {
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &wire.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				testWritePacket(dt, resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	for i := range testPayload {
		testPayload[i] = byte((i*17 + 13) % 251)
	}

	dummyFd := wire.FileId{}
	wn, err := fs.writeAt(context.Background(), dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(context.Background(), dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestCopyFile_ZeroBytes(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	var sentCopyChunkReq bool

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			qres := &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, qres.Size())
			qres.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		} else if ctlCode == wire.FSCTL_SRV_COPYCHUNK || ctlCode == wire.FSCTL_SRV_COPYCHUNK_WRITE {
			sentCopyChunkReq = true
			eres := &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC000000D) // STATUS_INVALID_PARAMETER
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[0:8], 0)  // AllocationSize = 0
		le.PutUint64(stdInfoBuf[8:16], 0) // EndOfFile = 0
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := wire.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(context.Background(), srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.NoError(t, err)
	require.True(t, supported)
	require.Equal(t, int64(0), n)
	if sentCopyChunkReq {
		t.Fatal("BUG CONFIRMED: copyFile sent FSCTL_SRV_COPYCHUNK request with 0 chunks for 0-byte copy!")
	}
}

func TestCopyFileRejectsInvalidOffsets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		readFrom  bool
		srcOffset int64
		dstOffset int64
	}{
		{name: "ReadFrom source", readFrom: true, srcOffset: -1},
		{name: "ReadFrom destination", readFrom: true, dstOffset: -1},
		{name: "WriteTo source", srcOffset: -1},
		{name: "WriteTo destination", dstOffset: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &Share{}
			src := &File{fs: fs, fd: wire.FileId{}, name: "src.txt", offset: tt.srcOffset}
			dst := &File{fs: fs, fd: wire.FileId{}, name: "dst.txt", offset: tt.dstOffset}

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
			} else {
				n, err = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
			}

			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, os.ErrInvalid)
			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "copy", linkErr.Op)
			require.Equal(t, int64(tt.srcOffset), src.offset)
			require.Equal(t, int64(tt.dstOffset), dst.offset)
		})
	}
}

func TestCopyFileEqualOffsetsNearLimit(t *testing.T) {
	t.Parallel()
	const size = int64(2 * 1024 * 1024)
	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, recorder := newCopyFileTestShare(t, math.MaxInt64)
			offset := int64(math.MaxInt64) - size
			src := &File{fs: fs, fd: wire.FileId{Persistent: [8]byte{1}}, name: "src", offset: offset}
			dst := &File{fs: fs, fd: wire.FileId{Persistent: [8]byte{2}}, name: "dst", offset: offset, readAccess: true}
			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, size, n)
			require.Equal(t, int64(math.MaxInt64), src.offset)
			require.Equal(t, src.offset, dst.offset)
			chunks := recorder.snapshot()
			require.Len(t, chunks, 2)
			for _, chunk := range chunks {
				require.Equal(t, offset, chunk.SourceOffset)
				require.Equal(t, offset, chunk.TargetOffset)
				require.LessOrEqual(t, offset, math.MaxInt64-int64(chunk.Length))
				offset += int64(chunk.Length)
			}
			require.Equal(t, int64(math.MaxInt64), offset)
		})
	}
}

func TestCopyFileUnsupportedFallsBackToNormalCopy(t *testing.T) {
	t.Parallel()
	const sourceByte = byte(0x5a)

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					src, serverConn := newTestFile(t)
					dst := &File{fs: src.fs, fd: wire.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

					var mu sync.Mutex
					var ioctlCtlCodes []uint32
					var resumeKeyStatus uint32
					var readCount, writeCount int
					var written []byte
					done := make(chan struct{})
					t.Cleanup(func() {
						_ = serverConn.Close()
						<-done
					})

					go func() {
						defer close(done)
						defer serverConn.Close()
						dt := serverConn
						for {
							req, err := readMsg(dt)
							if err != nil {
								return
							}
							if len(req) < 64 {
								return
							}
							switch wire.PacketCodec(req).Command() {
							case wire.SMB2_IOCTL:
								ioctlReq := wire.IoctlRequestDecoder(req[64:])
								if ioctlReq.IsInvalid() {
									return
								}
								ctlCode := ioctlReq.CtlCode()
								mu.Lock()
								ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
								if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
									resumeKeyStatus = uint32(status.status)
								}
								mu.Unlock()
								if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(status.status))
								} else {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_INVALID_PARAMETER))
								}
							case wire.SMB2_READ:
								mu.Lock()
								readCount++
								first := readCount == 1
								mu.Unlock()
								if first {
									sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{sourceByte}}, 0)
								} else {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
								}
							case wire.SMB2_WRITE:
								writeReq := wire.WriteRequestDecoder(req[64:])
								if writeReq.IsInvalid() {
									return
								}
								dataOffset, dataLength := uint64(writeReq.DataOffset()), uint64(writeReq.Length())
								if dataOffset > uint64(len(req)) || dataLength > uint64(len(req))-dataOffset {
									return
								}
								data := append([]byte(nil), req[dataOffset:dataOffset+dataLength]...)
								mu.Lock()
								writeCount++
								written = append(written, data...)
								mu.Unlock()
								sendTestResponse(dt, req, &wire.WriteResponse{Count: writeReq.Length()}, 0)
							}
						}
					}()

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(1), n)
					require.Equal(t, int64(1), src.offset)
					require.Equal(t, int64(1), dst.offset)

					_ = serverConn.Close()
					<-done

					mu.Lock()
					defer mu.Unlock()
					require.Equal(t, []uint32{wire.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
					require.Equal(t, uint32(status.status), resumeKeyStatus)
					require.Greater(t, readCount, 0)
					require.Greater(t, writeCount, 0)
					require.Equal(t, []byte{sourceByte}, written)
				})
			}
		})
	}
}

func TestCopyFileResumeKeyAccessDeniedDoesNotFallBack(t *testing.T) {
	t.Parallel()
	src, serverConn := newTestFile(t)
	dst := &File{fs: src.fs, fd: wire.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

	var mu sync.Mutex
	var ioctlCtlCodes []uint32
	var readCount, writeCount int
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = serverConn.Close()
		<-done
	})

	go func() {
		defer close(done)
		defer serverConn.Close()
		dt := serverConn
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if len(req) < 64 {
				return
			}
			switch wire.PacketCodec(req).Command() {
			case wire.SMB2_IOCTL:
				ioctlReq := wire.IoctlRequestDecoder(req[64:])
				if ioctlReq.IsInvalid() {
					return
				}
				ctlCode := ioctlReq.CtlCode()
				mu.Lock()
				ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
				mu.Unlock()
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_ACCESS_DENIED))
			case wire.SMB2_READ:
				mu.Lock()
				readCount++
				mu.Unlock()
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
			case wire.SMB2_WRITE:
				mu.Lock()
				writeCount++
				mu.Unlock()
				sendTestResponse(dt, req, &wire.WriteResponse{}, 0)
			}
		}
	}()

	n, err := dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
	require.Equal(t, int64(0), n)
	require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
	require.Equal(t, int64(0), src.offset)
	require.Equal(t, int64(0), dst.offset)

	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []uint32{wire.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
	require.Equal(t, 0, readCount)
	require.Equal(t, 0, writeCount)
}

func TestCopyFileFailurePreservesStatusAndProgress(t *testing.T) {
	t.Parallel()
	const firstBatch = int64(16 * 1024 * 1024)

	tests := []struct {
		name      string
		readFrom  bool
		endOfFile int64
		failAfter int
		status    erref.NtStatus
		wantN     int64
	}{
		{name: "ReadFrom first disk full", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "WriteTo first disk full", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "ReadFrom after success disk full", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "WriteTo after success disk full", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "ReadFrom first invalid parameter", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "WriteTo first invalid parameter", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "ReadFrom after success invalid parameter", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
		{name: "WriteTo after success invalid parameter", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := newCopyFailureTestFiles(t, tt.endOfFile, tt.failAfter, tt.status)

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
			} else {
				n, err = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
			}

			require.Equal(t, tt.wantN, n)
			require.ErrorIs(t, err, tt.status)
			var responseErr *protocol.ResponseError
			require.ErrorAs(t, err, &responseErr)
			require.Equal(t, uint32(tt.status), responseErr.Code)
			// Copy failures must not be exposed as partial READ/IOCTL output.
			_, partial := protocol.BufferOverflowData(responseErr)
			require.False(t, partial)
			require.Equal(t, tt.wantN, src.offset)
			require.Equal(t, tt.wantN, dst.offset)
		})
	}
}

func TestCopyFileWriteOnlyDestinationUsesWriteVariant(t *testing.T) {
	t.Parallel()
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{sourceSize: sourceSize})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileReadWriteDestinationUsesCopyChunk(t *testing.T) {
	t.Parallel()
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			// The server rejects FSCTL_SRV_COPYCHUNK_WRITE, proving a read/write
			// destination never relies on it.
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:           sourceSize,
				rejectWriteCtlStatus: erref.STATUS_NOT_SUPPORTED,
			})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileWriteVariantUnsupportedFallsBackToNormalCopy(t *testing.T) {
	t.Parallel()
	const sourceSize = 150 * 1024

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
						sourceSize:           sourceSize,
						rejectWriteCtlStatus: status.status,
					})

					src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
					require.NoError(t, err)
					defer src.Close(context.Background())

					dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
					require.NoError(t, err)
					defer dst.Close(context.Background())

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(sourceSize), n)
					require.Equal(t, int64(sourceSize), src.offset)
					require.Equal(t, int64(sourceSize), dst.offset)
					require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

					codes, reads, writes, copies := srv.snapshot()
					require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
					require.Equal(t, 1, copies)
					require.Greater(t, reads, 0)
					require.Greater(t, writes, 0)
				})
			}
		})
	}
}

func TestCopyFileAccessDeniedDoesNotFallBack(t *testing.T) {
	t.Parallel()
	const sourceSize = 150 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:       sourceSize,
				rejectCopyStatus: erref.STATUS_ACCESS_DENIED,
			})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
			require.Equal(t, int64(0), src.offset)
			require.Equal(t, int64(0), dst.offset)

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
			require.Empty(t, srv.content(dst.fd))
		})
	}
}

func TestCopyFileWriteVariantFailureAfterFirstBatchPreservesProgress(t *testing.T) {
	t.Parallel()
	const firstBatch = int64(16 * 1024 * 1024)
	const sourceSize = firstBatch + 1024*1024

	fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
		sourceSize:      sourceSize,
		failCopyRequest: 2,
		failCopyStatus:  erref.STATUS_NOT_SUPPORTED,
	})

	src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer src.Close(context.Background())

	dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	require.NoError(t, err)
	defer dst.Close(context.Background())

	n, err := dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
	require.Equal(t, firstBatch, n)
	require.ErrorIs(t, err, erref.STATUS_NOT_SUPPORTED)
	require.Equal(t, firstBatch, src.offset)
	require.Equal(t, firstBatch, dst.offset)

	codes, reads, writes, copies := srv.snapshot()
	require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE, wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
	require.Equal(t, 2, copies)
	require.Equal(t, 0, reads)
	require.Equal(t, 0, writes)
	require.Equal(t, srv.sourceContent()[:firstBatch], srv.content(dst.fd))
}

func TestCopyFile_RejectsShortTotalBytesWritten(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	const totalFileSize = 100

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			ires := &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		} else if ctlCode == wire.FSCTL_SRV_COPYCHUNK {
			// Sum up the chunk lengths requested by the client.
			reqData := reqBuf[64:]
			inputCount := int(le.Uint32(reqData[28:32]))
			input := reqData[56 : 56+inputCount] // SrvCopychunkCopy
			reqTotal := uint64(0)
			chunks := le.Uint32(input[24:28])
			for i := range chunks {
				off := 32 + i*24
				reqTotal += uint64(le.Uint32(input[off+16 : off+20]))
			}

			// Respond with a SrvCopychunkResponse reporting one byte less than requested.
			respBuf := make([]byte, 12)
			le.PutUint32(respBuf[0:4], chunks)
			le.PutUint32(respBuf[4:8], uint32(reqTotal-1))  // ChunksBytesWritten
			le.PutUint32(respBuf[8:12], uint32(reqTotal-1)) // TotalBytesWritten
			ires := &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(respBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], totalFileSize) // EndOfFile = 100
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := wire.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(context.Background(), srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.True(t, supported)
	require.Error(t, err, "copyFile must fail when TotalBytesWritten is less than the requested bytes")

	var linkErr *os.LinkError
	require.True(t, errors.As(err, &linkErr))
	require.Equal(t, "copy", linkErr.Op)
	require.Equal(t, "src.txt", linkErr.Old)
	require.Equal(t, "dst.txt", linkErr.New)

	var invalidResp *protocol.InvalidResponseError
	require.True(t, errors.As(linkErr.Err, &invalidResp))
	require.Equal(t, "srv copy chunk total bytes written does not match requested total", invalidResp.Message)

	require.Equal(t, int64(0), n)
}

func TestFileLockValidatesRangesAndEncodesRequest(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	for _, test := range []struct {
		name   string
		lock   []LockRange
		unlock []ByteRange
	}{
		{name: "empty lock"},
		{name: "negative offset", lock: []LockRange{{Range: ByteRange{Offset: -1, Length: 1}}}},
		{name: "negative length", lock: []LockRange{{Range: ByteRange{Length: -1}}}},
		{name: "range overflow", lock: []LockRange{{Range: ByteRange{Offset: math.MaxInt64, Length: 2}}}},
		{name: "request too large", lock: make([]LockRange, (maxLockRequestSize-64-24)/24+1)},
		{name: "waiting multiple ranges", lock: []LockRange{{}, {}}},
		{name: "empty unlock", unlock: []ByteRange{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.unlock != nil {
				err = f.Unlock(context.Background(), test.unlock)
			} else {
				err = f.Lock(context.Background(), test.lock, false)
			}
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("error = %v, want os.ErrInvalid", err)
			}
		})
	}

	server := serverConn
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(server)
		if err != nil {
			t.Errorf("read lock request: %v", err)
			return
		}
		d := wire.LockRequestDecoder(req[64:])
		if d.IsInvalid() || d.LockCount() != 1 {
			t.Errorf("invalid lock request: count=%d invalid=%v", d.LockCount(), d.IsInvalid())
			return
		}
		lock := wire.LockElementDecoder(d.Locks())
		if lock.Offset() != 7 || lock.Length() != 0 || lock.Flags() != wire.SMB2_LOCKFLAG_EXCLUSIVE_LOCK {
			t.Errorf("unexpected lock element: offset=%d length=%d flags=%#x", lock.Offset(), lock.Length(), lock.Flags())
		}
		sendTestResponse(server, req, &wire.LockResponse{}, 0)
	}()

	if err := f.Lock(context.Background(), []LockRange{{Range: ByteRange{Offset: 7}, Exclusive: true}}, false); err != nil {
		t.Fatalf("Lock returned error: %v", err)
	}
	<-done
}

func TestFileLockReturnsRangeStatus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		status erref.NtStatus
		unlock bool
		wantOp string
	}{
		{name: "lock conflict", status: erref.STATUS_LOCK_NOT_GRANTED, wantOp: "lock"},
		{name: "unlock conflict", status: erref.STATUS_RANGE_NOT_LOCKED, unlock: true, wantOp: "unlock"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, serverConn := newTestFile(t)
			server := serverConn
			done := make(chan struct{})
			go func() {
				defer close(done)
				req, err := readMsg(server)
				if err != nil {
					t.Errorf("read %s request: %v", test.wantOp, err)
					return
				}
				if got := wire.PacketCodec(req).Command(); got != wire.SMB2_LOCK {
					t.Errorf("command = %v, want LOCK", got)
					return
				}
				sendTestResponse(server, req, &wire.ErrorResponse{CommandCode: wire.SMB2_LOCK}, uint32(test.status))
			}()

			var err error
			if test.unlock {
				err = f.Unlock(context.Background(), []ByteRange{{Offset: 7, Length: 1}})
			} else {
				err = f.Lock(context.Background(), []LockRange{{Range: ByteRange{Offset: 7, Length: 1}}}, true)
			}
			var responseErr *protocol.ResponseError
			if !errors.As(err, &responseErr) {
				t.Fatalf("error = %v, want protocol.ResponseError", err)
			}
			if responseErr.Code != uint32(test.status) {
				t.Fatalf("protocol.ResponseError.Code = %#x, want %#x", responseErr.Code, test.status)
			}
			<-done
		})
	}
}

func TestFileLockCancelSendsAsyncCancelAndKeepsConnectionUsable(t *testing.T) {
	t.Parallel()
	for _, status := range []erref.NtStatus{erref.STATUS_SUCCESS, erref.STATUS_CANCELLED, erref.STATUS_LOCK_NOT_GRANTED} {
		t.Run(fmt.Sprintf("status_%x", uint32(status)), func(t *testing.T) {

			f, serverConn := newTestFile(t)
			other := &File{fs: f.fs, fd: wire.FileId{Volatile: [8]byte{2}}, name: "other.txt"}
			server := serverConn

			ctx, cancel := context.WithCancel(context.Background())
			lockDone := make(chan error, 1)
			go func() {
				lockDone <- f.Lock(ctx, []LockRange{{Range: ByteRange{Offset: 4, Length: 8}}}, false)
			}()

			lockReq, err := readMsg(server)
			if err != nil {
				t.Fatalf("read LOCK request: %v", err)
			}
			lockPkt := wire.PacketCodec(lockReq)
			if lockPkt.Command() != wire.SMB2_LOCK {
				t.Fatalf("command = %v, want LOCK", lockPkt.Command())
			}

			pending := &wire.ErrorResponse{CommandCode: wire.SMB2_LOCK}
			pendingBuf := make([]byte, pending.Size())
			pending.Encode(pendingBuf)
			pendingPkt := wire.PacketCodec(pendingBuf)
			pendingPkt.SetMessageId(lockPkt.MessageId())
			pendingPkt.SetSessionId(lockPkt.SessionId())
			pendingPkt.SetTreeId(lockPkt.TreeId())
			pendingPkt.SetStatus(uint32(erref.STATUS_PENDING))
			pendingPkt.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND)
			pendingPkt.SetAsyncId(0xA55A)
			pendingPkt.SetCreditResponse(1)
			if _, err := testWritePacket(server, pendingBuf); err != nil {
				t.Fatalf("send pending LOCK response: %v", err)
			}

			cancel()
			cancelReq, err := readMsg(server)
			if err != nil {
				t.Fatalf("read CANCEL request: %v", err)
			}
			cancelPkt := wire.PacketCodec(cancelReq)
			if cancelPkt.Command() != wire.SMB2_CANCEL || cancelPkt.MessageId() != lockPkt.MessageId() {
				t.Fatalf("CANCEL = command %v, message id %d; want LOCK id %d", cancelPkt.Command(), cancelPkt.MessageId(), lockPkt.MessageId())
			}
			if cancelPkt.Flags()&wire.SMB2_FLAGS_ASYNC_COMMAND == 0 || cancelPkt.AsyncId() != 0xA55A {
				t.Fatalf("CANCEL async fields = flags %#x, id %#x", cancelPkt.Flags(), cancelPkt.AsyncId())
			}

			otherDone := make(chan error, 2)
			go func() { otherDone <- other.Sync(context.Background()) }()
			go func() { otherDone <- sendProtocolEcho(f.fs) }()
			for range 2 {
				req, err := readMsg(server)
				if err != nil {
					t.Fatalf("read concurrent request: %v", err)
				}
				switch wire.PacketCodec(req).Command() {
				case wire.SMB2_FLUSH:
					sendTestResponse(server, req, &wire.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_ECHO:
					sendTestResponse(server, req, &wire.EchoResponse{}, uint32(erref.STATUS_SUCCESS))
				default:
					t.Fatalf("unexpected concurrent command: %v", wire.PacketCodec(req).Command())
				}
			}
			for range 2 {
				select {
				case err := <-otherDone:
					if err != nil {
						t.Fatalf("concurrent operation failed: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("concurrent operation did not complete while LOCK was canceled")
				}
			}

			select {
			case err := <-lockDone:
				t.Fatalf("LOCK completed before delayed final response: %v", err)
			default:
			}

			var final wire.Packet = &wire.LockResponse{}
			if status != erref.STATUS_SUCCESS {
				final = &wire.ErrorResponse{CommandCode: wire.SMB2_LOCK}
			}
			finalBuf := make([]byte, final.Size())
			final.Encode(finalBuf)
			finalPkt := wire.PacketCodec(finalBuf)
			finalPkt.SetMessageId(lockPkt.MessageId())
			finalPkt.SetSessionId(lockPkt.SessionId())
			finalPkt.SetTreeId(lockPkt.TreeId())
			finalPkt.SetStatus(uint32(status))
			finalPkt.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND)
			finalPkt.SetAsyncId(0xA55A)
			finalPkt.SetCreditResponse(1)
			if _, err := testWritePacket(server, finalBuf); err != nil {
				t.Fatalf("send final LOCK response: %v", err)
			}
			select {
			case err := <-lockDone:
				switch status {
				case erref.STATUS_SUCCESS:
					require.NoError(t, err)
				case erref.STATUS_CANCELLED:
					require.ErrorIs(t, err, context.Canceled)
				default:
					var responseErr *protocol.ResponseError
					require.ErrorAs(t, err, &responseErr)
					require.Equal(t, uint32(status), responseErr.Code)
				}
			case <-time.After(time.Second):
				t.Fatal("LOCK did not complete after final response")
			}

			// A new request after the final asynchronous response verifies that
			// cancellation released the LOCK request's connection state.
			echoDone := make(chan error, 1)
			go func() { echoDone <- sendProtocolEcho(f.fs) }()
			echoReq, err := readMsg(server)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echoReq).Command())
			sendTestResponse(server, echoReq, &wire.EchoResponse{}, uint32(erref.STATUS_SUCCESS))
			require.NoError(t, <-echoDone)
		})
	}
}

func sendProtocolEcho(fs *Share) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := fs.Request().Append(&wire.EchoRequest{}).Do(ctx)
	if res != nil {
		res.Close()
	}
	return err
}

func TestFileLockMultipleRangesAndUnlock(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	server := serverConn
	ranges := []ByteRange{{Offset: 7}, {Offset: math.MaxInt64, Length: 1}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, unlock := range []bool{false, true} {
			req, err := readMsg(server)
			if err != nil {
				t.Error(err)
				return
			}
			d := wire.LockRequestDecoder(req[64:])
			if d.IsInvalid() || d.LockCount() != 2 {
				t.Error("invalid multi-range request")
				return
			}
			require.Equal(t, f.fd, d.FileId().Decode())
			for i, r := range ranges {
				element := wire.LockElementDecoder(d.Locks()[24*i:])
				require.Equal(t, uint64(r.Offset), element.Offset())
				require.Equal(t, uint64(r.Length), element.Length())
				flags := uint32(wire.SMB2_LOCKFLAG_SHARED_LOCK | wire.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
				if i == 1 {
					flags = wire.SMB2_LOCKFLAG_EXCLUSIVE_LOCK | wire.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
				}
				if unlock {
					flags = wire.SMB2_LOCKFLAG_UNLOCK
				}
				require.Equal(t, flags, element.Flags())
			}
			sendTestResponse(server, req, &wire.LockResponse{}, 0)
		}
	}()
	require.NoError(t, f.Lock(context.Background(), []LockRange{{Range: ranges[0]}, {Range: ranges[1], Exclusive: true}}, true))
	require.NoError(t, f.Unlock(context.Background(), ranges))
	<-done
}

func TestFileLockCancellationWaitsForTransportFailure(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.Lock(ctx, []LockRange{{}}, false) }()
	server := serverConn
	_, err := readMsg(server)
	require.NoError(t, err)
	cancel()
	req, err := readMsg(server)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(req).Command())
	require.NoError(t, serverConn.Close())
	select {
	case err := <-done:
		var transportErr *protocol.TransportError
		require.ErrorAs(t, err, &transportErr)
	case <-time.After(time.Second):
		t.Fatal("LOCK did not finish after transport failure")
	}
}

func notifyEventBytes(action notify.Action, name string) []byte {
	encoded := utf16le.EncodeStringToBytes(name)
	record := make([]byte, (12+len(encoded)+3)&^3)
	le.PutUint32(record[4:8], uint32(action))
	le.PutUint32(record[8:12], uint32(len(encoded)))
	copy(record[12:], encoded)
	return record
}

type notifyOutcome struct {
	result notify.Result
	err    error
}

func startNotify(f *File, ctx context.Context, filter notify.Filter, recursive bool) <-chan notifyOutcome {
	done := make(chan notifyOutcome, 1)
	go func() {
		result, err := f.WaitForChange(ctx, filter, recursive)
		done <- notifyOutcome{result, err}
	}()
	return done
}

func finishNotify(t *testing.T, done <-chan notifyOutcome) (notify.Result, error) {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome.result, outcome.err
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForChange did not complete")
		return notify.Result{}, nil
	}
}

func TestFileWaitForChangeRequiresDirectoryAndValidFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilFile *File
	if _, err := nilFile.WaitForChange(ctx, notify.FileName, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil File error = %v, want os.ErrInvalid", err)
	}

	f := &File{fs: &Share{}, fd: wire.FileId{}}
	if _, err := f.WaitForChange(ctx, notify.FileName, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("regular File error = %v, want os.ErrInvalid", err)
	}
	f.isDir = true
	if _, err := f.WaitForChange(ctx, 0, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zero filter error = %v, want os.ErrInvalid", err)
	}
	if _, err := f.WaitForChange(ctx, notify.Filter(1<<31), false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("unknown filter error = %v, want os.ErrInvalid", err)
	}
}

func TestFileWaitForChangeEmptyResponseRequiresRescan(t *testing.T) {
	t.Parallel()
	for _, status := range []uint32{uint32(erref.STATUS_SUCCESS), uint32(erref.STATUS_NOTIFY_ENUM_DIR)} {
		t.Run(fmt.Sprintf("status-%08x", status), func(t *testing.T) {
			require := require.New(t)
			f, serverConn := newTestFile(t)
			f.isDir = true
			go func() {
				dt := serverConn
				req, err := readMsg(dt)
				if err != nil {
					return
				}
				require.Equal(wire.SMB2_CHANGE_NOTIFY, wire.PacketCodec(req).Command())
				sendTestResponse(dt, req, &wire.ChangeNotifyResponse{}, status)
			}()

			result, err := f.WaitForChange(context.Background(), notify.FileName, false)
			require.NoError(err)
			require.Empty(result.Events)
			require.True(result.RescanRequired)
		})
	}
}

func TestFileWaitForChangePreservesEventOrderAndNames(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	f, serverConn := newTestFile(t)
	f.isDir = true

	makeEvent := func(action uint32, name string) []byte {
		nameBytes := utf16le.EncodeStringToBytes(name)
		size := (12 + len(nameBytes) + 3) &^ 3
		b := make([]byte, size)
		le.PutUint32(b[4:8], action)
		le.PutUint32(b[8:12], uint32(len(nameBytes)))
		copy(b[12:], nameBytes)
		return b
	}
	oldName := makeEvent(wire.FILE_ACTION_RENAMED_OLD_NAME, "old.txt")
	newName := makeEvent(wire.FILE_ACTION_RENAMED_NEW_NAME, "new.txt")
	le.PutUint32(oldName[:4], uint32(len(oldName)))
	output := append(oldName, newName...)

	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		request := wire.ChangeNotifyRequestDecoder(wire.PacketCodec(req).Body())
		if request.IsInvalid() {
			return
		}
		sendTestResponse(dt, req, &wire.ChangeNotifyResponse{Output: rawEncoder(output)}, uint32(erref.STATUS_SUCCESS))
	}()

	result, err := f.WaitForChange(context.Background(), notify.FileName, false)
	require.NoError(err)
	require.False(result.RescanRequired)
	require.Equal([]notify.Event{
		{Action: notify.RenamedOldName, Name: "old.txt"},
		{Action: notify.RenamedNewName, Name: "new.txt"},
	}, result.Events)
}

func TestFileWaitForChangeResponseValidation(t *testing.T) {
	t.Parallel()
	validThenEmpty := notifyEventBytes(notify.Added, "valid")
	le.PutUint32(validThenEmpty[:4], uint32(len(validThenEmpty)))
	validThenEmpty = append(validThenEmpty, notifyEventBytes(notify.Added, "")...)

	for _, test := range []struct {
		name       string
		output     []byte
		recursive  bool
		status     erref.NtStatus
		wantStatus bool
	}{
		{name: "empty name", output: notifyEventBytes(notify.Added, "")},
		{name: "embedded NUL", output: notifyEventBytes(notify.Added, "a\x00b")},
		{name: "trailing NUL", output: notifyEventBytes(notify.Added, "a\x00")},
		{name: "control character", output: notifyEventBytes(notify.Added, "a\x1fb")},
		{name: "invalid name after valid event", output: validThenEmpty},
		{name: "root slash", output: notifyEventBytes(notify.Added, "/root")},
		{name: "root backslash", output: notifyEventBytes(notify.Added, `\root`)},
		{name: "quote", output: notifyEventBytes(notify.Added, `a"b`)},
		{name: "stream name quote", output: notifyEventBytes(notify.Added, `file:st"ream`)},
		{name: "stream type quote", output: notifyEventBytes(notify.Added, `file:str:ty"pe`)},
		{name: "child slash", output: notifyEventBytes(notify.Added, "a/b")},
		{name: "child backslash", output: notifyEventBytes(notify.Added, `a\b`)},
		{name: "dotdot", output: notifyEventBytes(notify.Added, "..")},
		{name: "dotdot escape", output: notifyEventBytes(notify.Added, `..\target`)},
		{name: "recursive quote", output: notifyEventBytes(notify.Added, `a"b`), recursive: true},
		{name: "recursive dotdot", output: notifyEventBytes(notify.Added, ".."), recursive: true},
		{name: "recursive dotdot escape", output: notifyEventBytes(notify.Added, `..\target`), recursive: true},
		{name: "recursive stream name quote", output: notifyEventBytes(notify.Added, `file:st"ream`), recursive: true},
		{name: "recursive stream type quote", output: notifyEventBytes(notify.Added, `file:str:ty"pe`), recursive: true},
		{name: "truncated record", output: make([]byte, 11)},
		{name: "unknown action", output: notifyEventBytes(12, "a")},
		{name: "request limit", output: make([]byte, maxSingleCreditPayloadSize+1)},
		{name: "enum with events", status: erref.STATUS_NOTIFY_ENUM_DIR, output: notifyEventBytes(notify.Added, "a")},
		{name: "cleanup", status: erref.STATUS_NOTIFY_CLEANUP, wantStatus: true},
		{name: "access denied", status: erref.STATUS_ACCESS_DENIED, wantStatus: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
			f.isDir = true
			done := startNotify(f, context.Background(), notify.FileName, test.recursive)
			dt := peer
			request, err := readMsg(dt)
			require.NoError(t, err)
			var response wire.Packet = &wire.ChangeNotifyResponse{Output: rawEncoder(test.output)}
			if test.wantStatus {
				response = &wire.ErrorResponse{CommandCode: wire.SMB2_CHANGE_NOTIFY}
			}
			sendTestResponse(dt, request, response, uint32(test.status))
			result, err := finishNotify(t, done)
			require.Empty(t, result.Events)
			require.False(t, result.RescanRequired)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			if test.wantStatus {
				var responseErr *protocol.ResponseError
				require.ErrorAs(t, err, &responseErr)
				require.Equal(t, uint32(test.status), responseErr.Code)
			} else {
				var invalid *protocol.InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			}
		})
	}
}

func TestFileWaitForChangeContract(t *testing.T) {
	t.Parallel()
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.isDir = true
	f.fd = wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{7}}
	filter := notify.FileName | notify.DirName
	want := []notify.Event{{Action: notify.Added, Name: `child\same`}, {Action: notify.Added, Name: `child\same`}, {Action: notify.RenamedNewName, Name: `child\new`}}
	var output []byte
	for i, event := range want {
		record := notifyEventBytes(event.Action, event.Name)
		if i < len(want)-1 {
			le.PutUint32(record[:4], uint32(len(record)))
		}
		output = append(output, record...)
	}
	dt := peer
	var first notify.Result
	for i := range 2 {
		done := startNotify(f, context.Background(), filter, true)
		request, err := readMsg(dt)
		require.NoError(t, err)
		p := wire.PacketCodec(request)
		r := wire.ChangeNotifyRequestDecoder(p.Body())
		require.False(t, r.IsInvalid())
		require.Equal(t, f.fd, r.FileId().Decode())
		require.EqualValues(t, filter, r.CompletionFilter())
		require.EqualValues(t, wire.SMB2_WATCH_TREE, r.Flags())
		require.EqualValues(t, maxSingleCreditPayloadSize, r.OutputBufferLength())
		require.EqualValues(t, 1, p.CreditCharge())
		require.Zero(t, p.NextCommand())
		var response wire.Packet = &wire.ChangeNotifyResponse{}
		if i == 0 {
			response = &wire.ChangeNotifyResponse{Output: rawEncoder(output)}
		}
		sendTestResponse(dt, request, response, 0)
		result, err := finishNotify(t, done)
		require.NoError(t, err)
		if i == 0 {
			first = result
		}
	}
	require.Equal(t, want, first.Events) // Survives subsequent buffer reuse.
	f.closed.Store(true)
	_, err := f.WaitForChange(context.Background(), filter, true)
	require.ErrorIs(t, err, os.ErrClosed)
	var nilCtx context.Context
	require.Panics(t, func() { _, _ = f.WaitForChange(nilCtx, filter, true) })
}

func TestChangeNotifyCancellationPreservesSharedConnection(t *testing.T) {
	t.Parallel()
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprintf("async=%v", async), func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			f.isDir = true
			other := &File{fs: f.fs, fd: wire.FileId{Volatile: [8]byte{2}}, name: "other", isDir: true}
			dt := peer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := startNotify(f, ctx, notify.FileName, false)
			request, err := readMsg(dt)
			require.NoError(t, err)
			p := wire.PacketCodec(request)
			require.EqualValues(t, 65536, wire.ChangeNotifyRequestDecoder(p.Body()).OutputBufferLength())
			const asyncID = 0x12345678
			if async {
				pending := &wire.ErrorResponse{CommandCode: wire.SMB2_CHANGE_NOTIFY}
				buf := make([]byte, pending.Size())
				pending.Encode(buf)
				r := wire.PacketCodec(buf)
				r.SetMessageId(p.MessageId())
				r.SetSessionId(p.SessionId())
				r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND)
				r.SetAsyncId(asyncID)
				r.SetStatus(uint32(erref.STATUS_PENDING))
				r.SetCreditResponse(0)
				_, err := testWritePacket(dt, buf)
				require.NoError(t, err)
			}
			otherDone := startNotify(other, context.Background(), notify.DirName, true)
			otherRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, other.fd, wire.ChangeNotifyRequestDecoder(wire.PacketCodec(otherRequest).Body()).FileId().Decode())
			cancel()
			cancelRequest, err := readMsg(dt)
			require.NoError(t, err)
			cp := wire.PacketCodec(cancelRequest)
			require.Equal(t, wire.SMB2_CANCEL, cp.Command())
			require.Equal(t, p.MessageId(), cp.MessageId())
			require.Zero(t, cp.CreditCharge())
			require.Zero(t, cp.CreditRequest())
			if async {
				require.NotZero(t, cp.Flags()&wire.SMB2_FLAGS_ASYNC_COMMAND)
				require.EqualValues(t, asyncID, cp.AsyncId())
			} else {
				require.Zero(t, cp.Flags()&wire.SMB2_FLAGS_ASYNC_COMMAND)
			}
			_, err = finishNotify(t, done)
			require.ErrorIs(t, err, context.Canceled)
			require.False(t, f.closed.Load())
			// ECHO completes while both notification responses are still pending.
			echoDone := make(chan error, 1)
			go func() { echoDone <- sendProtocolEcho(f.fs) }()
			echoRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echoRequest).Command())
			sendTestResponse(dt, echoRequest, &wire.EchoResponse{}, 0)
			select {
			case err := <-echoDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked ECHO")
			}
			final := &wire.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(notify.Added, "late"))}
			buf := make([]byte, final.Size())
			final.Encode(buf)
			fp := wire.PacketCodec(buf)
			fp.SetMessageId(p.MessageId())
			fp.SetSessionId(p.SessionId())
			fp.SetTreeId(p.TreeId())
			fp.SetCreditResponse(1)
			fp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			if async {
				fp.SetFlags(fp.Flags() | wire.SMB2_FLAGS_ASYNC_COMMAND)
				fp.SetAsyncId(asyncID)
			}
			_, err = testWritePacket(dt, buf)
			require.NoError(t, err)
			sendTestResponse(dt, otherRequest, &wire.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(notify.Added, "other"))}, 0)
			result, err := finishNotify(t, otherDone)
			require.NoError(t, err)
			require.Equal(t, []notify.Event{{Action: notify.Added, Name: "other"}}, result.Events)
			// A request after both final notifications confirms that canceled
			// notification state and its credits were fully released.
			echoDone = make(chan error, 1)
			go func() { echoDone <- sendProtocolEcho(f.fs) }()
			echoRequest, err = readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echoRequest).Command())
			sendTestResponse(dt, echoRequest, &wire.EchoResponse{}, 0)
			require.NoError(t, <-echoDone)
		})
	}
}

func TestChangeNotifyResponseRejectsMalformedEnum(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{nil, make([]byte, 7), {8, 0, 0, 0, 0, 0, 0, 0}, {9, 0, 72, 0, 1, 0, 0, 0}} {
		if !wire.ChangeNotifyResponseDecoder(body).IsInvalid() {
			t.Fatalf("malformed CHANGE_NOTIFY response %v was accepted", body)
		}
	}
}

func TestChangeNotifyCannotReadNextCompoundResponse(t *testing.T) {
	t.Parallel()
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.isDir = true
	dt := peer
	done := startNotify(f, context.Background(), notify.FileName, false)
	notifyRequest, err := readMsg(dt)
	require.NoError(t, err)
	echoDone := make(chan error, 1)
	go func() { echoDone <- sendProtocolEcho(f.fs) }()
	echoRequest, err := readMsg(dt)
	require.NoError(t, err)
	makeResponse := func(request []byte, response wire.Packet) []byte {
		buf := make([]byte, response.Size())
		response.Encode(buf)
		p, r := wire.PacketCodec(request), wire.PacketCodec(buf)
		r.SetMessageId(p.MessageId())
		r.SetSessionId(p.SessionId())
		r.SetTreeId(p.TreeId())
		r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		r.SetCreditResponse(1)
		return buf
	}
	first := makeResponse(notifyRequest, &wire.ChangeNotifyResponse{})
	wire.PacketCodec(first).SetNextCommand(uint32(len(first)))
	le.PutUint16(first[66:68], 80) // Points into the next SMB2 command.
	le.PutUint32(first[68:72], 16)
	second := makeResponse(echoRequest, &wire.EchoResponse{})
	_, err = testWritePacket(dt, append(first, second...))
	require.NoError(t, err)
	_, err = finishNotify(t, done)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	select {
	case err := <-echoDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ECHO response following malformed CHANGE_NOTIFY was lost")
	}
}

func TestFileStatReparseModes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		attrs, tag uint32
		mode       os.FileMode
	}{
		{"file", 0, 0, 0666},
		{"directory", wire.FILE_ATTRIBUTE_DIRECTORY, 0, os.ModeDir | 0777},
		{"symlink", wire.FILE_ATTRIBUTE_REPARSE_POINT, wire.IO_REPARSE_TAG_SYMLINK, os.ModeSymlink | 0666},
		{"directory symlink", wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_DIRECTORY, wire.IO_REPARSE_TAG_SYMLINK, os.ModeSymlink | 0666},
		{"junction", wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_DIRECTORY, wire.IO_REPARSE_TAG_MOUNT_POINT, os.ModeIrregular | 0666},
		{"socket", wire.FILE_ATTRIBUTE_REPARSE_POINT, wire.IO_REPARSE_TAG_AF_UNIX, os.ModeSocket | 0666},
		{"deduplicated file", wire.FILE_ATTRIBUTE_REPARSE_POINT, wire.IO_REPARSE_TAG_DEDUP, 0666},
		{"unknown file", wire.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000042, os.ModeIrregular | 0666},
		{"unknown directory", wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_DIRECTORY, 0x80000042, os.ModeDir | os.ModeIrregular | 0777},
		{"unknown name surrogate", wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_DIRECTORY, 0xa0000042, os.ModeIrregular | 0666},
		{"tag without reparse attribute", wire.FILE_ATTRIBUTE_DIRECTORY, wire.IO_REPARSE_TAG_SYMLINK, os.ModeDir | 0777},
		{"readonly link", wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_READONLY, wire.IO_REPARSE_TAG_SYMLINK, os.ModeSymlink | 0444},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stat := &FileStat{FileAttributes: tc.attrs, ReparseTag: tc.tag}
			require.Equal(t, tc.mode, stat.Mode())
			require.Equal(t, tc.mode.IsDir(), stat.IsDir())
		})
	}
}

func TestStatReparseTag(t *testing.T) {
	for _, operation := range []string{"Stat", "Lstat", "File.Stat"} {
		for _, tag := range []uint32{wire.IO_REPARSE_TAG_SYMLINK, wire.IO_REPARSE_TAG_MOUNT_POINT, wire.IO_REPARSE_TAG_DEDUP, wire.IO_REPARSE_TAG_AF_UNIX, 0x80000042} {
			t.Run(fmt.Sprintf("%s/%x", operation, tag), func(t *testing.T) {
				fs, peer := newTestShare(t)
				attrs := uint32(wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_DIRECTORY)
				startFullFakeServer(peer, nil, nil, func(_ uint64, request []byte) []byte {
					q := wire.QueryInfoRequestDecoder(wire.PacketCodec(request).Body())
					if q.IsInvalid() {
						return nil
					}
					var output []byte
					switch q.FileInfoClass() {
					case wire.FileNetworkOpenInformation:
						output = make([]byte, 56)
						le.PutUint32(output[48:], attrs)
					case wire.FileAttributeTagInformation:
						output = make([]byte, 8)
						le.PutUint32(output, attrs)
						le.PutUint32(output[4:], tag)
					default:
						return nil
					}
					response := &wire.QueryInfoResponse{Output: rawEncoder(output)}
					buf := make([]byte, response.Size())
					response.Encode(buf)
					return buf
				}, func(_ wire.CreateRequestDecoder, response *wire.CreateResponse) { response.FileAttributes = attrs })
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var info os.FileInfo
				var err error
				switch operation {
				case "Stat":
					info, err = fs.Stat(ctx, "entry")
				case "Lstat":
					info, err = fs.Lstat(ctx, "entry")
				case "File.Stat":
					f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "entry")
					info, err = f.Stat(ctx)
				}
				require.NoError(t, err)
				require.Equal(t, tag, info.Sys().(*FileStat).ReparseTag)
				require.Equal(t, (&FileStat{FileAttributes: attrs, ReparseTag: tag}).Mode(), info.Mode())
			})
		}
	}
}

func TestDirectoryEntryPreservesReparseTag(t *testing.T) {
	buf := make([]byte, 106)
	le.PutUint32(buf[56:], wire.FILE_ATTRIBUTE_DIRECTORY|wire.FILE_ATTRIBUTE_REPARSE_POINT)
	le.PutUint32(buf[60:], 2)
	le.PutUint32(buf[64:], wire.IO_REPARSE_TAG_MOUNT_POINT)
	buf[104] = 'x'
	entry := wire.FileIdBothDirectoryInformationDecoder(buf)
	require.False(t, entry.IsInvalid())
	info := newFileStatFromFileIdBothDirectoryInformation(entry, entry.FileName())
	require.Equal(t, uint32(wire.IO_REPARSE_TAG_MOUNT_POINT), info.ReparseTag)
	require.Equal(t, os.ModeIrregular|0666, info.Mode())
	require.False(t, info.IsDir(), "directory traversal must not follow junctions")
	// EaSize is an EA length, not a tag, on ordinary files.
	le.PutUint32(buf[56:], 0)
	info = newFileStatFromFileIdBothDirectoryInformation(entry, entry.FileName())
	require.Zero(t, info.ReparseTag)
	require.Equal(t, os.FileMode(0666), info.Mode())
}

func TestFileStatRejectsTruncatedReparseTag(t *testing.T) {
	fs, peer := newTestShare(t)
	f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "link")
	startFullFakeServer(peer, nil, nil, func(_ uint64, request []byte) []byte {
		q := wire.QueryInfoRequestDecoder(wire.PacketCodec(request).Body())
		if q.IsInvalid() {
			return nil
		}
		output := make([]byte, 7)
		if q.FileInfoClass() == wire.FileNetworkOpenInformation {
			output = make([]byte, 56)
			le.PutUint32(output[48:], wire.FILE_ATTRIBUTE_REPARSE_POINT)
		}
		response := &wire.QueryInfoResponse{Output: rawEncoder(output)}
		buf := make([]byte, response.Size())
		response.Encode(buf)
		return buf
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := f.Stat(ctx)
	require.Nil(t, info)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestAppendFileRejectsWriteAt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fs, server := newProtocolTestShare(t)
	go func() {
		for {
			req, err := readMsg(server)
			if err != nil {
				return
			}
			switch wire.PacketCodec(req).Command() {
			case wire.SMB2_CREATE:
				sendTestResponse(server, req, &wire.CreateResponse{}, 0)
			case wire.SMB2_CLOSE:
				sendTestResponse(server, req, &wire.CloseResponse{}, 0)
			default:
				t.Errorf("unexpected request: %d", wire.PacketCodec(req).Command())
				return
			}
		}
	}()
	for _, flag := range []int{os.O_WRONLY | os.O_APPEND, os.O_RDWR | os.O_APPEND | os.O_TRUNC} {
		f, err := fs.OpenFile(ctx, "file", flag, 0600)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range [][]byte{nil, []byte("x")} {
			for _, write := range []func([]byte, int64) (int, error){
				func(p []byte, off int64) (int, error) { return f.WriteAt(ctx, p, off) },
				f.WithContext(ctx).WriteAt,
			} {
				if n, err := write(b, 0); n != 0 || err == nil || !strings.Contains(err.Error(), "O_APPEND") {
					t.Fatalf("WriteAt = %d, %v", n, err)
				}
			}
		}
		if err := f.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendTruncateIgnoresStaleCreateSize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fs, server := newProtocolTestShare(t)
	offsets := make(chan uint64, 1)
	go func() {
		for {
			req, err := readMsg(server)
			if err != nil {
				return
			}
			switch wire.PacketCodec(req).Command() {
			case wire.SMB2_CREATE:
				sendTestResponse(server, req, &wire.CreateResponse{EndofFile: 3}, 0)
			case wire.SMB2_WRITE:
				w := wire.WriteRequestDecoder(req[64:])
				if w.IsInvalid() {
					return
				}
				offsets <- w.Offset()
				sendTestResponse(server, req, &wire.WriteResponse{Count: w.Length()}, 0)
			case wire.SMB2_CLOSE:
				sendTestResponse(server, req, &wire.CloseResponse{}, 0)
			}
		}
	}()
	f, err := fs.OpenFile(ctx, "file", os.O_RDWR|os.O_APPEND|os.O_TRUNC, 0600)
	require.NoError(t, err)
	n, err := f.Write(ctx, []byte("ABC"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, uint64(0), <-offsets)
	require.NoError(t, f.Close(ctx))
}

func TestAppendCopyUsesWrite(t *testing.T) {
	for _, readFrom := range []bool{false, true} {
		t.Run(fmt.Sprintf("readFrom_%t", readFrom), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			src, server := newTestFile(t)
			dst := &File{fs: src.fs, fd: wire.FileId{Persistent: [8]byte{1}}, name: "dest", offset: 6, appendMode: true, readAccess: true}
			written := make(chan uint64, 1)
			go func() {
				for {
					req, err := readMsg(server)
					if err != nil {
						return
					}
					switch wire.PacketCodec(req).Command() {
					case wire.SMB2_READ:
						r := wire.ReadRequestDecoder(req[64:])
						if r.IsInvalid() {
							return
						}
						if r.Offset() == 0 {
							sendTestResponse(server, req, &wire.ReadResponse{Data: []byte("copy")}, 0)
						} else {
							sendTestResponse(server, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
						}
					case wire.SMB2_WRITE:
						w := wire.WriteRequestDecoder(req[64:])
						if w.IsInvalid() {
							return
						}
						written <- w.Offset()
						sendTestResponse(server, req, &wire.WriteResponse{Count: w.Length()}, 0)
					default:
						t.Errorf("append copy sent unexpected command %v", wire.PacketCodec(req).Command())
						sendTestResponse(server, req, &wire.ErrorResponse{CommandCode: wire.PacketCodec(req).Command()}, uint32(erref.STATUS_NOT_SUPPORTED))
					}
				}
			}()
			var n int64
			var err error
			if readFrom {
				n, err = dst.ReadFrom(ctx, src.WithContext(ctx))
			} else {
				n, err = src.WriteTo(ctx, dst.WithContext(ctx))
			}
			require.NoError(t, err)
			require.Equal(t, int64(4), n)
			require.Equal(t, uint64(6), <-written)
			require.Equal(t, int64(10), dst.offset)
			require.Equal(t, int64(4), src.offset)
		})
	}
}

func TestCopySelectsPathByOffsets(t *testing.T) {
	t.Parallel()
	const size = int64(4096)
	for _, appendMode := range []bool{false, true} {
		for _, offsets := range []struct{ source, target int64 }{{0, 0}, {4, 4}, {4, 0}} {
			for _, tc := range copyPaths() {
				t.Run(fmt.Sprintf("append_%t_%d_%d_%s", appendMode, offsets.source, offsets.target, tc.name), func(t *testing.T) {
					fs, srv := newCopyPermissionShare(t, copyPermissionConfig{sourceSize: size})
					src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
					require.NoError(t, err)
					defer src.Close(context.Background())
					flags := os.O_RDWR | os.O_CREATE
					if appendMode {
						flags |= os.O_APPEND
					}
					dst, err := fs.OpenFile(context.Background(), "dst.txt", flags, 0)
					require.NoError(t, err)
					defer dst.Close(context.Background())
					src.offset, dst.offset = offsets.source, offsets.target
					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, size-offsets.source, n)
					expected := make([]byte, offsets.target)
					expected = append(expected, srv.sourceContent()[offsets.source:]...)
					require.Equal(t, expected, srv.content(dst.fd))
					require.Equal(t, size, src.offset)
					require.Equal(t, offsets.target+n, dst.offset)
					codes, reads, writes, copies := srv.snapshot()
					if offsets.source == offsets.target {
						require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK}, codes)
						require.Equal(t, 1, copies)
						require.Zero(t, reads)
						require.Zero(t, writes)
					} else {
						require.Empty(t, codes)
						require.Zero(t, copies)
						require.Positive(t, reads)
						require.Positive(t, writes)
					}
				})
			}
		}
	}
}
