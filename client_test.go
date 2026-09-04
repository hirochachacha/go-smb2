package smb2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

var le = binary.LittleEndian

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

func TestCopyBufferPartialRead(t *testing.T) {
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

func TestNilAndClosedFileMethods(t *testing.T) {
	var nilFile *File
	closedFile := &File{}

	if err := nilFile.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("nil.Close() should return os.ErrInvalid, got %v", err)
	}
	if err := closedFile.Close(); !errors.Is(err, os.ErrClosed) {
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

		if err := f.Sync(); !errors.Is(err, expected) {
			t.Errorf("[%s] Sync error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Stat(); !errors.Is(err, expected) {
			t.Errorf("[%s] Stat error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Statfs(); !errors.Is(err, expected) {
			t.Errorf("[%s] Statfs error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Truncate(0); !errors.Is(err, expected) {
			t.Errorf("[%s] Truncate error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Chmod(0o644); !errors.Is(err, expected) {
			t.Errorf("[%s] Chmod error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Read(make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Read error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] ReadAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Write(make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Write error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.WriteAt(make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] WriteAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Seek(0, 0); !errors.Is(err, expected) {
			t.Errorf("[%s] Seek error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Readdir(-1); !errors.Is(err, expected) {
			t.Errorf("[%s] Readdir error expected %v, got %v", tc.name, expected, err)
		}
	}
}

func TestNegativeOffsetValidation(t *testing.T) {
	f := &File{fd: &smb2.FileId{}}

	if _, err := f.ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("ReadAt with negative offset should return error")
	}

	if _, err := f.WriteAt(make([]byte, 1), -1); err == nil {
		t.Error("WriteAt with negative offset should return error")
	}

	if _, err := f.Seek(-1, 0); err == nil {
		t.Error("Seek to negative offset should return error")
	}
}

func TestSymlinkRejectsEmptyTarget(t *testing.T) {
	fs := &Share{}
	var err error

	require.NotPanics(t, func() {
		err = fs.Symlink("", "link")
	})
	require.Error(t, err)
}

func TestFileCopyToSelf(t *testing.T) {
	f := &File{}

	if _, err := f.ReadFrom(f); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("ReadFrom self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
	if _, err := f.WriteTo(f); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("WriteTo self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
}

func TestResponseErrorIs(t *testing.T) {
	tests := []struct {
		code     uint32
		target   error
		expected bool
	}{
		{0xC0000034, os.ErrNotExist, true},   // STATUS_OBJECT_NAME_NOT_FOUND
		{0xC000003A, os.ErrNotExist, true},   // STATUS_OBJECT_PATH_NOT_FOUND
		{0xC0000035, os.ErrExist, true},      // STATUS_OBJECT_NAME_COLLISION
		{0xC0000022, os.ErrPermission, true}, // STATUS_ACCESS_DENIED
		{0xC0000121, os.ErrPermission, true}, // STATUS_CANNOT_DELETE
		{0xC0000128, os.ErrClosed, true},     // STATUS_FILE_CLOSED
		{0xC0000034, os.ErrPermission, false},
		{0xC0000034, os.ErrExist, false},
	}

	for _, tc := range tests {
		err := &ResponseError{Code: tc.code}
		pathErr := &os.PathError{Op: "open", Path: "test", Err: err}

		if errors.Is(err, tc.target) != tc.expected {
			t.Errorf("ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
		if errors.Is(pathErr, tc.target) != tc.expected {
			t.Errorf("PathError wrapping ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
	}
}

func TestParallelChunkedReadWrite(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	const fileSize = 512 * 1024
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case smb2.SMB2_WRITE:
				wreq := smb2.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &smb2.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Write(resBuf)

			case smb2.SMB2_READ:
				rreq := smb2.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				var chunkData []byte
				if int(off) < len(mockStorage) {
					end := int(off) + int(length)
					if end > len(mockStorage) {
						end = len(mockStorage)
					}
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &smb2.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Write(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	_, err := rand.Read(testPayload)
	req.NoError(err)

	dummyFd := &smb2.FileId{}
	wn, err := fs.writeAt(dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestLargeMockFileCopy(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	const fileSize = 10 * 1024 * 1024 // 10MB
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case smb2.SMB2_WRITE:
				wreq := smb2.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &smb2.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Write(resBuf)

			case smb2.SMB2_READ:
				rreq := smb2.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				end := int(off) + int(length)
				if end > len(mockStorage) {
					end = len(mockStorage)
				}
				var chunkData []byte
				if int(off) < len(mockStorage) {
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &smb2.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Write(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	for i := range testPayload {
		testPayload[i] = byte((i*17 + 13) % 251)
	}

	dummyFd := &smb2.FileId{}
	wn, err := fs.writeAt(dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestEvalSymlinkErrorRelativePath(t *testing.T) {
	symErr := &smb2.SymbolicLinkErrorResponse{
		UnparsedPathLength: 0,
		Flags:              smb2.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     "target.txt",
		PrintName:          "target.txt",
	}
	buf := make([]byte, symErr.Size())
	symErr.Encode(buf)

	resolved, err := evalSymlinkError(`sub1\sub2\symlink`, buf)
	require.NoError(t, err)

	expected := `sub1\sub2\target.txt`
	if resolved != expected {
		t.Errorf("evalSymlinkError failed: expected %q, got %q", expected, resolved)
	}
}

type rawEncoder []byte

func (r rawEncoder) Size() int       { return len(r) }
func (r rawEncoder) Encode(b []byte) { copy(b, r) }

func startFullFakeServer(serverConn net.Conn, onQueryDir func(msgId uint64, reqBuf []byte, dt transport) bool, onIoctl func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool, onQueryInfo func(msgId uint64, reqBuf []byte) []byte) {
	go func() {
		dt := direct(serverConn)
		var callId uint32
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_DISK,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_QUERY_INFO:
					if onQueryInfo != nil {
						resBuf = onQueryInfo(msgId, currBuf)
					}

				case smb2.SMB2_READ:
					reqData := currBuf[64:]
					readLen := int(le.Uint32(reqData[4:8]))
					rres := &smb2.ReadResponse{Data: make([]byte, readLen)}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					if onIoctl != nil && onIoctl(&callId, msgId, currBuf, dt) {
						resBuf = nil
					}

				case smb2.SMB2_QUERY_DIRECTORY:
					if onQueryDir != nil && onQueryDir(msgId, currBuf, dt) {
						resBuf = nil
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()
}

func encodeFileIdBothDirectoryInformation(name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
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

func TestReaddir_NormalVsBugBehavior(t *testing.T) {
	t.Run("NormalServer_ReturnsFilesThenNoMoreFiles", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()

		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}
		f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

		go c.runReceiver()

		var reqCount int64

		// Normal fakeServer: 1st call returns "file1.txt", 2nd call returns STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
			count := atomic.AddInt64(&reqCount, 1)
			p := smb2.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			} else {
				// 2nd call: STATUS_NO_MORE_FILES (0x80000606) using standard ErrorResponse
				eres := &smb2.ErrorResponse{
					CommandCode: smb2.SMB2_QUERY_DIRECTORY,
				}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Normal Readdir completed cleanly after %d requests, got %d files", atomic.LoadInt64(&reqCount), len(fis))
	})

	t.Run("BugBehavior_ServerReturnsEmptySuccessInsteadOfNoMoreFiles", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()

		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}
		f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

		go c.runReceiver()

		var reqCount int64

		// Parameter change: 1st call returns "file1.txt", 2nd call returns STATUS_SUCCESS (0) with empty output instead of STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
			count := atomic.AddInt64(&reqCount, 1)
			p := smb2.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0)
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			} else {
				// 2nd call: PARAMETER CHANGED to STATUS_SUCCESS (0) with 0 bytes output
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder([]byte{}),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Readdir completed cleanly after fix even with empty STATUS_SUCCESS response (%d requests)", atomic.LoadInt64(&reqCount))
	})
}

func TestReadFile_LargeFile(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	const totalFileSize = 200 * 1024 // 200KB (> 2 * maxReadSize = 128KB)

	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], totalFileSize) // EndOfFile = 200KB
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	done := make(chan struct{})
	var data []byte
	var err error
	go func() {
		defer close(done)
		data, err = fs.ReadFile("largefile.dat")
	}()

	select {
	case <-done:
		require.NoError(t, err)
		if len(data) != totalFileSize {
			t.Fatalf("BUG CONFIRMED: ReadFile truncated data! Expected %d bytes, got %d bytes", totalFileSize, len(data))
		}
		t.Logf("PASS: ReadFile read complete %d bytes", len(data))
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadFile timed out")
	}
}

func TestCopyFile_ZeroBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	var sentCopyChunkReq bool

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			qres := &smb2.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, qres.Size())
			qres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Write(resBuf)
			return true
		} else if ctlCode == smb2.FSCTL_SRV_COPYCHUNK {
			sentCopyChunkReq = true
			eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC000000D) // STATUS_INVALID_PARAMETER
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Write(resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[0:8], 0)  // AllocationSize = 0
		le.PutUint64(stdInfoBuf[8:16], 0) // EndOfFile = 0
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := &smb2.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(srcFd, dstFd, "src.txt", "dst.txt", 0, 0)
	require.NoError(t, err)
	require.True(t, supported)
	require.Equal(t, int64(0), n)
	if sentCopyChunkReq {
		t.Fatal("BUG CONFIRMED: copyFile sent FSCTL_SRV_COPYCHUNK request with 0 chunks for 0-byte copy!")
	}
}

func TestFileWrite_NegativeBytesWrittenOnChunkError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == smb2.SMB2_WRITE {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			}
		}
	}()

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.Write([]byte("test data"))
	require.Error(t, err)

	if n < 0 || f.offset < 0 {
		t.Fatalf("BUG CONFIRMED: File.Write returned negative bytes written n=%d or corrupted offset=%d!", n, f.offset)
	}
}

func TestFileWriteAt_NegativeBytesWrittenOnErr(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == smb2.SMB2_WRITE {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Write(resBuf)
			}
		}
	}()

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.WriteAt([]byte("test data"), 0)
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.WriteAt returned negative bytes written n=%d!", n)
	}
}

func TestFileSeek_NegativeReturnOnErr(t *testing.T) {
	fs := &Share{ctx: context.Background()}
	f := &File{fs: fs}

	ret, err := f.Seek(0, io.SeekStart)
	require.Error(t, err)
	if ret < 0 {
		t.Fatalf("BUG CONFIRMED: File.Seek returned negative offset ret=%d on closed file!", ret)
	}
}

func TestReadFile_BrokenQueryInfoResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		// Return broken query info response (< 24 bytes)
		qres := &smb2.QueryInfoResponse{Output: rawEncoder([]byte{1, 2, 3, 4})}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	_, err := fs.ReadFile("test.txt")
	require.Error(t, err)
	var invErr *InvalidResponseError
	if !errors.As(err, &invErr) {
		t.Fatalf("BUG CONFIRMED: ReadFile failed to validate broken query info response, got err: %v", err)
	}
}

func TestReadFileRejectsUnreasonableEndOfFile(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()
	queryInfoReady := make(chan struct{})
	go func() {
		<-queryInfoReady
		time.Sleep(10 * time.Millisecond)
		serverConn.Close()
	}()
	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		close(queryInfoReady)
		output := make([]byte, 24)
		le.PutUint64(output[8:16], uint64(^uint64(0)>>1))
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(output)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	var err error
	require.NotPanics(t, func() {
		_, err = fs.ReadFile("test.txt")
	})
	require.Error(t, err)
}

func TestReadAtPropagatesChunkError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	go c.runReceiver()
	go func() {
		dt := direct(serverConn)
		for i := 0; i < 2; i++ {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}

			p := smb2.PacketCodec(req)
			readReq := smb2.ReadRequestDecoder(req[64:])
			var res []byte
			if readReq.Offset() == 0 {
				rres := &smb2.ReadResponse{Data: make([]byte, readReq.Length())}
				res = make([]byte, rres.Size())
				rres.Encode(res)
			} else {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}
				res = make([]byte, eres.Size())
				eres.Encode(res)
			}

			rp := smb2.PacketCodec(res)
			rp.SetMessageId(p.MessageId())
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			if readReq.Offset() != 0 {
				rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			}
			_, _ = dt.Write(res)
		}
	}()

	_, err := f.ReadAt(make([]byte, fs.maxReadSize()+1), 0)
	require.Error(t, err)
}

func newTestFile(t *testing.T) (*File, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	return fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt"), serverConn
}

func sendTestResponse(dt transport, req []byte, res smb2.Packet, status uint32) {
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := smb2.PacketCodec(req)
	rp := smb2.PacketCodec(resBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(status)
	rp.SetCreditResponse(1)
	rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	_, _ = dt.Write(resBuf)
}

func TestReadAtCompletesShortSMBRead(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}
			readReq := smb2.ReadRequestDecoder(req[64:])
			data := []byte{1}
			if readReq.Offset() != 0 {
				data = make([]byte, readReq.Length())
			}
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: data}, 0)
		}
	}()

	buf := make([]byte, f.fs.maxReadSize()+1)
	n, err := f.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
}

func TestReadAtCompletesMultipleShortSMBReads(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
		}
	}()

	n, err := f.ReadAt(make([]byte, 4), 0)
	require.NoError(t, err)
	require.Equal(t, 4, n)
}

func TestReadAtReturnsEOFOnShortFile(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for i := 0; i < 3; i++ {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}
			if i < 2 {
				sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
			} else {
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, 0xC0000011) // STATUS_END_OF_FILE
			}
		}
	}()

	n, err := f.ReadAt(make([]byte, 8), 0)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, n)
}

func TestReadCompletesShortSMBRead(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
			return
		}
	}()

	n, err := f.Read(make([]byte, 8))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadLargeBufferReadsSingleChunk(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		size, err := dt.ReadSize()
		if err != nil {
			return
		}
		req := make([]byte, size)
		if _, err := dt.Read(req); err != nil {
			return
		}
		readReq := smb2.ReadRequestDecoder(req[64:])
		data := []byte{1}
		if readReq.Offset() != 0 {
			data = make([]byte, readReq.Length())
		}
		sendTestResponse(dt, req, &smb2.ReadResponse{Data: data}, 0)
	}()

	n, err := f.Read(make([]byte, f.fs.maxReadSize()+1))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadAtRejectsInvalidLength(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		size, err := dt.ReadSize()
		if err != nil {
			return
		}
		req := make([]byte, size)
		if _, err := dt.Read(req); err != nil {
			return
		}
		readReq := smb2.ReadRequestDecoder(req[64:])
		sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length()+1)}, 0)
	}()

	n, err := f.ReadAt(make([]byte, 8), 0)
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestWriteAtRejectsInvalidCount(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		size, err := dt.ReadSize()
		if err != nil {
			return
		}
		req := make([]byte, size)
		if _, err := dt.Read(req); err != nil {
			return
		}
		writeReq := smb2.WriteRequestDecoder(req[64:])
		sendTestResponse(dt, req, &smb2.WriteResponse{Count: writeReq.Length() + 1}, 0)
	}()

	n, err := f.WriteAt(make([]byte, 8), 0)
	require.Error(t, err)
	require.LessOrEqual(t, n, 8)
}

func TestReadAtRejectsOffsetOverflow(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for i := 0; i < 2; i++ {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			req := make([]byte, size)
			if _, err := dt.Read(req); err != nil {
				return
			}
			readReq := smb2.ReadRequestDecoder(req[64:])
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
		}
	}()

	maxInt64 := int64(^uint64(0) >> 1)
	buf := make([]byte, f.fs.maxReadSize()+1)
	_, err := f.ReadAt(buf, maxInt64-1)
	require.Error(t, err)
}

func TestReadFrom_NegativeBytesWrittenOnCopyFileErr(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Write(resBuf)
			return true
		}
		return false
	}, nil)

	srcFile := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "src.txt")
	dstFile := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

	n, err := dstFile.ReadFrom(srcFile)
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.ReadFrom returned negative bytes read n=%d on copyFile error!", n)
	}
}

func TestListSharenames_RejectsExcessiveResponseSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:        c.session,
		ctx:      ctx,
		addr:     "testserver",
		hostname: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 300 // 300 * ~4KB > 1MB

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := make([]byte, 24)
							bindAck[0] = 5  // RPC_VERSION
							bindAck[1] = 0  // RPC_VERSION_MINOR
							bindAck[2] = 12 // RPC_TYPE_BIND_ACK
							le.PutUint32(bindAck[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment read: level 1, large count (incomplete)
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Subsequent incomplete fragments
						frag = make([]byte, 4000)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4000)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()

	_, err := s.ListSharenames()
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Less(t, readCount, maxReads)
}

func TestListSharenames_RejectsEmptyFragment(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:        c.session,
		ctx:      ctx,
		addr:     "testserver",
		hostname: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 10

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := make([]byte, 24)
							bindAck[0] = 5  // RPC_VERSION
							bindAck[1] = 0  // RPC_VERSION_MINOR
							bindAck[2] = 12 // RPC_TYPE_BIND_ACK
							le.PutUint32(bindAck[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Return empty fragment (header only: 24 bytes, Buffer() is 0 bytes)
						frag = make([]byte, 24)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 24)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()

	_, err := s.ListSharenames()
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Equal(t, 2, readCount)
}

func TestListSharenames_TerminatesOnLastFrag(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:        c.session,
		ctx:      ctx,
		addr:     "testserver",
		hostname: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := make([]byte, 24)
							bindAck[0] = 5  // RPC_VERSION
							bindAck[1] = 0  // RPC_VERSION_MINOR
							bindAck[2] = 12 // RPC_TYPE_BIND_ACK
							le.PutUint32(bindAck[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment: PFC_FIRST_FRAG (0x01)
						frag = make([]byte, 60)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 1 // PFC_FIRST_FRAG
						le.PutUint16(frag[8:10], 60)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)       // level 1
						le.PutUint32(frag[28:32], 1)       // CTR pointer
						le.PutUint32(frag[32:36], 0x20004) // Referent ID
						le.PutUint32(frag[36:40], 1)       // Count = 1
						le.PutUint32(frag[40:44], 0x20008) // Array pointer
						le.PutUint32(frag[44:48], 1)       // Array MaxCount = 1
						le.PutUint32(frag[48:52], 0x2000c) // Name pointer
						le.PutUint32(frag[52:56], 0)        // Type
						le.PutUint32(frag[56:60], 0x20010) // Comment pointer
					} else if readCount == 2 {
						// Second fragment: PFC_LAST_FRAG (0x02) containing deferred name
						nameBytes := utf16le.EncodeStringToBytes("SHARE1")
						nameCount := uint32(len(nameBytes)/2 + 1)
						commentBytes := utf16le.EncodeStringToBytes("")
						commentCount := uint32(1)

						frag = make([]byte, 128)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 2 // PFC_LAST_FRAG
						le.PutUint32(frag[12:16], rpcCallId)

						off := 24
						// Name deferred
						le.PutUint32(frag[off:off+4], nameCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], nameCount)
						copy(frag[off+12:], nameBytes)
						off = (off + 12 + int(nameCount*2) + 3) &^ 3

						// Comment deferred
						le.PutUint32(frag[off:off+4], commentCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], commentCount)
						copy(frag[off+12:], commentBytes)
						off = (off + 12 + int(commentCount*2) + 3) &^ 3

						frag = frag[:off]
						le.PutUint16(frag[8:10], uint16(off))
					} else {
						// Should not reach here if PFC_LAST_FRAG terminates
						serverConn.Close()
						return
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestListSharenames_HandlesShortRead(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:        c.session,
		ctx:      ctx,
		addr:     "testserver",
		hostname: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := make([]byte, 24)
							bindAck[0] = 5  // RPC_VERSION
							bindAck[1] = 0  // RPC_VERSION_MINOR
							bindAck[2] = 12 // RPC_TYPE_BIND_ACK
							le.PutUint32(bindAck[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					// Build PDU 1 (60 bytes)
					pdu1 := make([]byte, 60)
					pdu1[0] = 5 // RPC_VERSION
					pdu1[1] = 0 // RPC_VERSION_MINOR
					pdu1[2] = 2 // RPC_TYPE_RESPONSE
					pdu1[3] = 1 // PFC_FIRST_FRAG
					le.PutUint16(pdu1[8:10], 60) // FragLength = 60
					le.PutUint32(pdu1[12:16], rpcCallId)
					le.PutUint32(pdu1[24:28], 1)       // level 1
					le.PutUint32(pdu1[28:32], 1)       // CTR pointer
					le.PutUint32(pdu1[32:36], 0x20004) // Referent ID
					le.PutUint32(pdu1[36:40], 1)       // Count = 1
					le.PutUint32(pdu1[40:44], 0x20008) // Array pointer
					le.PutUint32(pdu1[44:48], 1)       // Array MaxCount = 1
					le.PutUint32(pdu1[48:52], 0x2000c) // Name pointer
					le.PutUint32(pdu1[52:56], 0)        // Type
					le.PutUint32(pdu1[56:60], 0x20010) // Comment pointer

					// Build PDU 2 (72 bytes)
					nameBytes := utf16le.EncodeStringToBytes("SHARE1")
					nameCount := uint32(len(nameBytes)/2 + 1)
					commentBytes := utf16le.EncodeStringToBytes("")
					commentCount := uint32(1)

					pdu2 := make([]byte, 128)
					pdu2[0] = 5 // RPC_VERSION
					pdu2[1] = 0 // RPC_VERSION_MINOR
					pdu2[2] = 2 // RPC_TYPE_RESPONSE
					pdu2[3] = 2 // PFC_LAST_FRAG
					le.PutUint32(pdu2[12:16], rpcCallId)

					off := 24
					le.PutUint32(pdu2[off:off+4], nameCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], nameCount)
					copy(pdu2[off+12:], nameBytes)
					off = (off + 12 + int(nameCount*2) + 3) &^ 3

					le.PutUint32(pdu2[off:off+4], commentCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], commentCount)
					copy(pdu2[off+12:], commentBytes)
					off = (off + 12 + int(commentCount*2) + 3) &^ 3
					pdu2 = pdu2[:off]
					le.PutUint16(pdu2[8:10], uint16(len(pdu2))) // FragLength

					stream := append(pdu1, pdu2...)
					// Chunks to serve: 20, 4 (completes pdu1 header), 36 (completes pdu1 stub), 24 (pdu2 header), 48 (pdu2 stub)
					chunkSizes := []int{20, 4, 36, 24, len(pdu2) - 24}
					if readCount > len(chunkSizes) {
						serverConn.Close()
						return
					}

					chunkOffset := 0
					for i := 0; i < readCount-1; i++ {
						chunkOffset += chunkSizes[i]
					}
					fragData := stream[chunkOffset : chunkOffset+chunkSizes[readCount-1]]

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 5, readCount)
}

func TestListSharenames_HandlesResidualData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:        c.session,
		ctx:      ctx,
		addr:     "testserver",
		hostname: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		var frag1, frag2 []byte

		for {
			size, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, size)
			_, err = dt.Read(reqBuf)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := make([]byte, 24)
							bindAck[0] = 5  // RPC_VERSION
							bindAck[1] = 0  // RPC_VERSION_MINOR
							bindAck[2] = 12 // RPC_TYPE_BIND_ACK
							le.PutUint32(bindAck[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)

							// Prepare frag1 and frag2
							frag1 = make([]byte, 60)
							frag1[0] = 5 // RPC_VERSION
							frag1[1] = 0 // RPC_VERSION_MINOR
							frag1[2] = 2 // RPC_TYPE_RESPONSE
							frag1[3] = 1 // PFC_FIRST_FRAG
							le.PutUint16(frag1[8:10], 60)
							le.PutUint32(frag1[12:16], rpcCallId)
							le.PutUint32(frag1[24:28], 1)       // level 1
							le.PutUint32(frag1[28:32], 1)       // CTR pointer
							le.PutUint32(frag1[32:36], 0x20004) // Referent ID
							le.PutUint32(frag1[36:40], 1)       // Count = 1
							le.PutUint32(frag1[40:44], 0x20008) // Array pointer
							le.PutUint32(frag1[44:48], 1)       // Array MaxCount = 1
							le.PutUint32(frag1[48:52], 0x2000c) // Name pointer
							le.PutUint32(frag1[52:56], 0)        // Type
							le.PutUint32(frag1[56:60], 0x20010) // Comment pointer

							nameBytes := utf16le.EncodeStringToBytes("SHARE1")
							nameCount := uint32(len(nameBytes)/2 + 1)
							commentBytes := utf16le.EncodeStringToBytes("")
							commentCount := uint32(1)

							frag2 = make([]byte, 128)
							frag2[0] = 5 // RPC_VERSION
							frag2[1] = 0 // RPC_VERSION_MINOR
							frag2[2] = 2 // RPC_TYPE_RESPONSE
							frag2[3] = 2 // PFC_LAST_FRAG
							le.PutUint32(frag2[12:16], rpcCallId)

							off := 24
							le.PutUint32(frag2[off:off+4], nameCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], nameCount)
							copy(frag2[off+12:], nameBytes)
							off = (off + 12 + int(nameCount*2) + 3) &^ 3

							le.PutUint32(frag2[off:off+4], commentCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], commentCount)
							copy(frag2[off+12:], commentBytes)
							off = (off + 12 + int(commentCount*2) + 3) &^ 3

							frag2 = frag2[:off]
							le.PutUint16(frag2[8:10], uint16(off))
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var fragData []byte
					if readCount == 1 {
						// Return frag1 + first 30 bytes of frag2 (overflowing frag1)
						fragData = append(append([]byte(nil), frag1...), frag2[:30]...)
					} else if readCount == 2 {
						// Return remainder of frag2
						fragData = frag2[30:]
					}

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Write(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestFile_ConcurrentClose(t *testing.T) {
	f, serverConn := newTestFile(t)
	dt := direct(serverConn)

	var closeRequests atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			if _, err := dt.Read(reqBuf); err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			if p.Command() == smb2.SMB2_CLOSE {
				closeRequests.Add(1)
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				sendTestResponse(dt, reqBuf, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	start := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = f.Close()
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

func TestFile_Readdir_NoSliceAliasing(t *testing.T) {
	entry1 := &FileStat{FileName: "file1.txt"}
	entry2 := &FileStat{FileName: "file2.txt"}
	entry3 := &FileStat{FileName: "file3.txt"}

	f := &File{
		fd:          &smb2.FileId{},
		noMoreFiles: true,
		dirents:     []os.FileInfo{entry1, entry2, entry3},
	}

	first, err := f.Readdir(1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "file1.txt", first[0].Name())

	// If capacity is not restricted with 3-index slicing, append would overwrite entry2 in f.dirents
	bogus := &FileStat{FileName: "corrupted.txt"}
	_ = append(first, bogus)

	second, err := f.Readdir(1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "file2.txt", second[0].Name())
}

func newTestShare(t *testing.T) (*Share, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	return fs, serverConn
}

func sendTestCompoundErrorResponse(dt transport, req []byte, status uint32) {
	p := smb2.PacketCodec(req)
	baseMsgId := p.MessageId()

	var parts [][]byte
	for i := 0; i < 3; i++ {
		errPkt := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_CREATE,
		}
		resBuf := make([]byte, errPkt.Size())
		errPkt.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(baseMsgId + uint64(i))
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		if i == 0 {
			rp.SetStatus(status)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		} else {
			rp.SetStatus(uint32(erref.STATUS_INVALID_PARAMETER))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		}
		parts = append(parts, resBuf)
	}

	var compound []byte
	for i, part := range parts {
		if i < len(parts)-1 {
			pad := (8 - (len(part) % 8)) % 8
			next := uint32(len(part) + pad)
			padded := make([]byte, next)
			copy(padded, part)
			smb2.PacketCodec(padded).SetNextCommand(next)
			compound = append(compound, padded...)
		} else {
			smb2.PacketCodec(part).SetCreditResponse(1)
			compound = append(compound, part...)
		}
	}
	_, _ = dt.Write(compound)
}

func TestShare_Remove_NoFallbackOnNonAccessError(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			if _, err := dt.Read(reqBuf); err != nil {
				return
			}
			requestCount.Add(1)
			// Return STATUS_OBJECT_NAME_NOT_FOUND on the first request
			sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		}
	}()

	err := fs.Remove("nonexistent.txt")
	require.Error(t, err)

	// Must NOT attempt fallback chmod; requestCount must be exactly 1
	require.Equal(t, int32(1), requestCount.Load(), "should not trigger chmod fallback on STATUS_OBJECT_NAME_NOT_FOUND")
}

func sendTestCompoundSuccessResponse(dt transport, req []byte) {
	createRes := &smb2.CreateResponse{
		FileId:         &smb2.FileId{},
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	setInfoRes := &smb2.SetInfoResponse{}
	closeRes := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)
	resBuf2 := make([]byte, setInfoRes.Size())
	setInfoRes.Encode(resBuf2)
	resBuf3 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf3)

	p := smb2.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	smb2.PacketCodec(padded1).SetMessageId(p.MessageId())
	smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	smb2.PacketCodec(padded1).SetNextCommand(next1)

	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	smb2.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	smb2.PacketCodec(padded2).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded2).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded2).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(padded2).SetNextCommand(next2)

	smb2.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	smb2.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	smb2.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	smb2.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(resBuf3).SetCreditResponse(1)

	compound := append(padded1, padded2...)
	compound = append(compound, resBuf3...)
	_, _ = dt.Write(compound)
}

func TestShare_Remove_FallbackOnCannotDelete(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			if _, err := dt.Read(reqBuf); err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod fallback (CREATE + SET_INFO + CLOSE compound)
				sendTestCompoundSuccessResponse(dt, reqBuf)
			case 3:
				// Third request is retry remove (CREATE + SET_INFO + CLOSE compound)
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove("readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(3), requestCount.Load(), "should perform remove, chmod, then retry remove")
}

func TestShare_Remove_FallbackOnAccessDenied(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			sz, err := dt.ReadSize()
			if err != nil {
				return
			}
			reqBuf := make([]byte, sz)
			if _, err := dt.Read(reqBuf); err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_ACCESS_DENIED
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_ACCESS_DENIED))
			case 2:
				// Second request is chmod fallback
				sendTestCompoundSuccessResponse(dt, reqBuf)
			case 3:
				// Third request is retry remove
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove("readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(3), requestCount.Load(), "should perform remove, chmod, then retry remove")
}

func TestDialClosesConnectionOnSessionSetupError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Round 1: server replies to Negotiate request with success
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		buf := make([]byte, sz)
		if _, err := st.Read(buf); err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB210,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		if _, err := st.Write(respBuf); err != nil {
			return
		}

		// Round 2: read SessionSetup request then close serverConn to simulate network/auth failure
		sz2, err := st.ReadSize()
		if err != nil {
			return
		}
		buf2 := make([]byte, sz2)
		_, _ = st.Read(buf2)
		_ = serverConn.Close()
	}()

	d := &Dialer{
		Initiator: &NTLMInitiator{
			User:     "user",
			Password: "password",
		},
	}

	_, err := d.DialContextWithHostname(context.Background(), clientConn, "test-server")
	require.Error(t, err)

	// clientConn must be closed on sessionSetup failure
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(t, readErr, "clientConn should be closed after failed sessionSetup")
}

func TestShare_MaxPayloadSizeCappedByCredits(t *testing.T) {
	c := &conn{
		account:         openAccount(4),
		capabilities:    smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	// Initially, maxCredits = 1 -> capped to 1 * 64KB = 64KB
	require.Equal(t, 64*1024, fs.maxReadSize())
	require.Equal(t, 64*1024, fs.maxWriteSize())
	require.Equal(t, 64*1024, fs.maxTransactSize())

	// Replenish to 4 credits (targetCreditBalance) -> capped to 4 * 64KB = 256KB
	c.account.charge(3)
	require.Equal(t, 256*1024, fs.maxReadSize())
	require.Equal(t, 256*1024, fs.maxWriteSize())
	require.Equal(t, 256*1024, fs.maxTransactSize())

	// If targetCreditBalance is large and credits are granted, scales up to winMaxPayloadSize (1MB)
	c.account.targetCreditBalance = 128
	c.account.charge(30)
	require.Equal(t, 1024*1024, fs.maxReadSize())
	require.Equal(t, 1024*1024, fs.maxWriteSize())
	require.Equal(t, 1024*1024, fs.maxTransactSize())
}

func sendTestCompoundMidFailureResponse(dt transport, req []byte, fileId *smb2.FileId, status uint32) {
	createRes := &smb2.CreateResponse{
		FileId:         fileId,
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)

	p := smb2.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	smb2.PacketCodec(padded1).SetMessageId(p.MessageId())
	smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	smb2.PacketCodec(padded1).SetNextCommand(next1)

	errPkt := &smb2.ErrorResponse{
		CommandCode: smb2.SMB2_SET_INFO,
	}
	resBuf2 := make([]byte, errPkt.Size())
	errPkt.Encode(resBuf2)
	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	smb2.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	smb2.PacketCodec(padded2).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded2).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded2).SetStatus(status)
	smb2.PacketCodec(padded2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(padded2).SetNextCommand(next2)

	closeErrPkt := &smb2.ErrorResponse{
		CommandCode: smb2.SMB2_CLOSE,
	}
	resBuf3 := make([]byte, closeErrPkt.Size())
	closeErrPkt.Encode(resBuf3)
	smb2.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	smb2.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	smb2.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	smb2.PacketCodec(resBuf3).SetStatus(status)
	smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(resBuf3).SetCreditResponse(1)

	var compound []byte
	compound = append(compound, padded1...)
	compound = append(compound, padded2...)
	compound = append(compound, resBuf3...)

	_, _ = dt.Write(compound)
}

func TestCompoundMidFailureClosesServerHandle(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + setInfo + close (Rename)
		sz1, err := dt.ReadSize()
		if err != nil {
			return
		}
		reqBuf1 := make([]byte, sz1)
		if _, err := dt.Read(reqBuf1); err != nil {
			return
		}
		sendTestCompoundMidFailureResponse(dt, reqBuf1, expectedFileId, uint32(erref.STATUS_ACCESS_DENIED))

		// Request 2: automatic fallback close request
		sz2, err := dt.ReadSize()
		if err != nil {
			return
		}
		reqBuf2 := make([]byte, sz2)
		if _, err := dt.Read(reqBuf2); err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeReq := smb2.CloseRequestDecoder(p2.Data())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Write(closeBuf)
		}
	}()

	err := fs.Rename("old.txt", "new.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when compound fails mid-flight")
}



