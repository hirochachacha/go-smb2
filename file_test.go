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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

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
	res, err := fs.Request().WithFileID(&wire.FileId{}).
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
	f := &File{fd: &wire.FileId{}}

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
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
						FileAttributes: attrs,
						FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					if len(onCreate) > 0 && onCreate[0] != nil {
						onCreate[0](wire.CreateRequestDecoder(currBuf[64:]), cres)
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case wire.SMB2_CLOSE:
					clres := &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
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
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
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
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
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
	}, nil, nil)

	_, err := f.Readdir(context.Background(), -1)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "invalid response error: query directory returned only dot entries", invalid.Error())
	require.EqualValues(t, 3, atomic.LoadInt64(&queryCount))

	// A malformed enumeration must not poison the shared connection.
	_, err = fs.Stat(context.Background(), "other")
	require.NoError(t, err)
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

	ret, err := f.Seek(context.Background(), 0, io.SeekStart)
	require.Error(t, err)
	if ret < 0 {
		t.Fatalf("BUG CONFIRMED: File.Seek returned negative offset ret=%d on closed file!", ret)
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
	return &File{fs: fs, fd: &wire.FileId{}, name: "test.txt"}, serverConn
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
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
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
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}, uint32(erref.STATUS_SUCCESS))
	}()

	require.NoError(f.Close(context.Background()))
	<-done
}

func TestFile_Readdir_NoSliceAliasing(t *testing.T) {
	t.Parallel()
	entry1 := &FileStat{FileName: "file1.txt"}
	entry2 := &FileStat{FileName: "file2.txt"}
	entry3 := &FileStat{FileName: "file3.txt"}

	f := &File{
		fd:          &wire.FileId{},
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
