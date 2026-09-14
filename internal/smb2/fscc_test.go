package smb2

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

func TestSymlinkReparseLengthExcludesCompoundPadding(t *testing.T) {
	for _, target := range []string{"target.txt", "リンク先.txt"} {
		t.Run(target, func(t *testing.T) {
			req := &IoctlRequest{
				CtlCode: FSCTL_SET_REPARSE_POINT,
				FileId:  &FileId{},
				Input: &SymbolicLinkReparseDataBuffer{
					Flags:          SYMLINK_FLAG_RELATIVE,
					SubstituteName: target,
					PrintName:      target,
				},
			}
			pkt := make([]byte, Roundup(req.Size(), 8))
			require.Greater(t, len(pkt), req.Size())
			req.Encode(pkt)
			ioctl := IoctlRequestDecoder(pkt[64:])
			input := pkt[ioctl.InputOffset() : ioctl.InputOffset()+ioctl.InputCount()]
			reparse := SymbolicLinkReparseDataBufferDecoder(input)
			require.Equal(t, len(input)-8, int(reparse.ReparseDataLength()))
			require.False(t, reparse.IsInvalid())
			require.Equal(t, target, reparse.SubstituteName())
			require.Equal(t, target, reparse.PrintName())
		})
	}
}

func TestSymbolicLinkReparseDataBufferDecoderRejectsOddLengths(t *testing.T) {
	response := &SymbolicLinkReparseDataBuffer{
		SubstituteName: "target",
		PrintName:      "target",
	}
	buf := make([]byte, response.Size())
	response.Encode(buf)
	if SymbolicLinkReparseDataBufferDecoder(buf).IsInvalid() {
		t.Fatal("well-formed symbolic link reparse data was rejected")
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"SubstituteNameLength", func(b []byte) { le.PutUint16(b[10:12], 1) }},
		{"PrintNameLength", func(b []byte) { le.PutUint16(b[14:16], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), buf...)
			tc.mutate(bad)
			if !SymbolicLinkReparseDataBufferDecoder(bad).IsInvalid() {
				t.Fatal("odd symbolic link length was accepted")
			}
		})
	}
}

func TestSymbolicLinkReparseDataBufferDecoderAcceptsValidUnicodeLengths(t *testing.T) {
	for _, tc := range []struct {
		name           string
		substituteName string
		printName      string
	}{
		{name: "zero lengths"},
		{name: "names end at buffer", substituteName: "target", printName: "display"},
		{name: "surrogate pair", substituteName: "😀", printName: "😀"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &SymbolicLinkReparseDataBuffer{
				SubstituteName: tc.substituteName,
				PrintName:      tc.printName,
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			d := SymbolicLinkReparseDataBufferDecoder(buf)
			if d.IsInvalid() {
				t.Fatal("valid symbolic link reparse data was rejected")
			}
			if got := d.SubstituteName(); got != tc.substituteName {
				t.Errorf("SubstituteName() = %q, want %q", got, tc.substituteName)
			}
			if got := d.PrintName(); got != tc.printName {
				t.Errorf("PrintName() = %q, want %q", got, tc.printName)
			}
		})
	}
}

func buildFileNotifyInformation(action uint32, name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
	size := Roundup(12+len(nameBytes), 4)
	b := make([]byte, size)
	le.PutUint32(b[4:8], action)
	le.PutUint32(b[8:12], uint32(len(nameBytes)))
	copy(b[12:], nameBytes)
	return b
}

func TestFileNotifyInformationDecoder(t *testing.T) {
	first := buildFileNotifyInformation(FILE_ACTION_RENAMED_OLD_NAME, "old")
	second := buildFileNotifyInformation(FILE_ACTION_RENAMED_NEW_NAME, "new")
	le.PutUint32(first[0:4], uint32(len(first)))
	output := append(first, second...)

	one := FileNotifyInformationDecoder(output)
	if one.IsInvalid() || one.Action() != FILE_ACTION_RENAMED_OLD_NAME || one.FileName() != "old" {
		t.Fatalf("first notification was decoded incorrectly: invalid=%v action=%d name=%q", one.IsInvalid(), one.Action(), one.FileName())
	}
	two := FileNotifyInformationDecoder(output[one.NextEntryOffset():])
	if two.IsInvalid() || two.Action() != FILE_ACTION_RENAMED_NEW_NAME || two.FileName() != "new" {
		t.Fatalf("second notification was decoded incorrectly: invalid=%v action=%d name=%q", two.IsInvalid(), two.Action(), two.FileName())
	}
}

func TestFileNotifyInformationDecoderRejectsBrokenLengths(t *testing.T) {
	valid := buildFileNotifyInformation(FILE_ACTION_MODIFIED, "x")
	cases := []struct {
		name string
		edit func([]byte)
	}{
		{"odd name length", func(b []byte) { le.PutUint32(b[8:12], 1) }},
		{"name outside record", func(b []byte) { le.PutUint32(b[8:12], 100) }},
		{"unaligned next offset", func(b []byte) { le.PutUint32(b[0:4], 13) }},
		{"next offset without fixed record", func(b []byte) { le.PutUint32(b[0:4], 16) }},
		{"trailing bytes after final record", nil},
		{"overflowing name length", func(b []byte) { le.PutUint32(b[8:12], 0xfffffffe) }},
		{"overflowing next offset", func(b []byte) { le.PutUint32(b[:4], 0xfffffffc) }},
		{"non-forward next offset", func(b []byte) { le.PutUint32(b[:4], 4) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), valid...)
			if tc.name == "trailing bytes after final record" {
				b = append(b, 0)
			} else {
				tc.edit(b)
			}
			if !FileNotifyInformationDecoder(b).IsInvalid() {
				t.Fatal("broken FILE_NOTIFY_INFORMATION was accepted")
			}
		})
	}
}

// buildIdBothDirInfo encodes a FILE_ID_BOTH_DIR_INFORMATION entry (MS-FSCC
// 2.4.22) with the given file id and name, so the decoder's offsets can be
// checked against an independently laid-out buffer.
func buildIdBothDirInfo(fileID uint64, name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)

	b := make([]byte, 104+len(nameBytes))
	le.PutUint32(b[0:4], 0)      // NextEntryOffset
	le.PutUint32(b[4:8], 7)      // FileIndex (resume cookie, not the file id)
	le.PutUint64(b[40:48], 1234) // EndOfFile
	le.PutUint64(b[48:56], 4096) // AllocationSize
	le.PutUint32(b[56:60], 0x20) // FileAttributes
	le.PutUint32(b[60:64], uint32(len(nameBytes)))
	le.PutUint64(b[96:104], fileID)
	copy(b[104:], nameBytes)

	return b
}

func TestFileIdBothDirectoryInformationDecoder(t *testing.T) {
	const (
		fileID = uint64(0x0004000000047FD3)
		name   = "hello.txt"
	)

	require := require.New(t)

	c := FileIdBothDirectoryInformationDecoder(buildIdBothDirInfo(fileID, name))

	require.False(c.IsInvalid())
	require.Equal(fileID, c.FileId())
	require.Equal(name, c.FileName())
	require.EqualValues(7, c.FileIndex())
	require.EqualValues(1234, c.EndOfFile())
	require.EqualValues(4096, c.AllocationSize())
	require.EqualValues(0x20, c.FileAttributes())
}

// A truncated entry must be rejected rather than panicking, since the buffer
// comes straight off the wire.
func TestFileIdBothDirectoryInformationDecoderIsInvalid(t *testing.T) {
	require := require.New(t)

	full := buildIdBothDirInfo(1, "hello.txt")

	for _, n := range []int{0, 63, 64, 103, len(full) - 1} {
		require.True(FileIdBothDirectoryInformationDecoder(full[:n]).IsInvalid(),
			"truncation to %d bytes not reported invalid", n)
	}
}

func TestFileIdBothDirectoryInformationDecoderNextEntryOffset(t *testing.T) {
	for _, tt := range []struct {
		name       string
		next       uint32
		bufferSize int
		invalid    bool
	}{
		{"unpadded final entry", 0, 106, false},
		{"buffer length termination", 106, 106, false},
		{"aligned continuation", 112, 216, false},
		{"extra padding", 120, 224, false},
		{"overlapping header", 96, 216, true},
		{"overlapping file name", 104, 216, true},
		{"unaligned continuation", 110, 216, true},
		{"outside buffer", 224, 216, true},
		{"maximum offset", ^uint32(0), 216, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufferSize)
			copy(buf, buildIdBothDirInfo(1, "a"))
			le.PutUint32(buf[:4], tt.next)
			require.Equal(t, tt.invalid, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
		})
	}
}

func TestFileIdBothDirectoryInformationDecoderFileNameBytes(t *testing.T) {
	require := require.New(t)

	c := FileIdBothDirectoryInformationDecoder(buildIdBothDirInfo(1, "test.txt"))
	require.Equal(utf16le.EncodeStringToBytes("test.txt"), c.FileNameBytes())
}

func TestFileIdBothDirectoryInformationDecoderEndOfFile(t *testing.T) {
	for _, eof := range []int64{-1, -1 << 63, 0, 42, 1<<63 - 1} {
		buf := buildIdBothDirInfo(1, "x")
		le.PutUint64(buf[40:48], uint64(eof))

		require.Equal(t, eof < 0,
			FileIdBothDirectoryInformationDecoder(buf).IsInvalid(),
			"EndOfFile=%d", eof)
	}
}

func TestFileIdBothDirectoryInformationDecoderTimes(t *testing.T) {
	tests := []struct {
		name   string
		offset int
	}{
		{"CreationTime", 8},
		{"LastAccessTime", 16},
		{"LastWriteTime", 24},
		{"ChangeTime", 32},
	}
	values := []struct {
		name  string
		value uint64
		valid bool
	}{
		{"zero", 0, true},
		{"normal", 42, true},
		{"maximum nonnegative", 0x7fffffffffffffff, true},
		{"minimum negative", 0x8000000000000000, false},
		{"maximum uint64", 0xffffffffffffffff, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					buf := buildIdBothDirInfo(1, "x")
					le.PutUint64(buf[tt.offset:tt.offset+8], value.value)

					require.Equal(t, !value.valid,
						FileIdBothDirectoryInformationDecoder(buf).IsInvalid(),
						"%s=%#x", tt.name, value.value)
				})
			}
		})
	}
}

func TestFileInformationRejectsNegativeEndOfFile(t *testing.T) {
	for _, eof := range []int64{-1, -1 << 63, 0, 42, 1<<63 - 1} {
		standard := make([]byte, 24)
		le.PutUint64(standard[8:16], uint64(eof))
		all := make([]byte, 100)
		copy(all[40:64], standard)
		require.Equal(t, eof < 0, FileStandardInformationDecoder(standard).IsInvalid())
		require.Equal(t, eof < 0, FileAllInformationDecoder(all).IsInvalid())
		for n := range 24 {
			require.True(t, FileStandardInformationDecoder(standard[:n]).IsInvalid())
		}
		for n := range 100 {
			require.True(t, FileAllInformationDecoder(all[:n]).IsInvalid())
		}
	}
}

func TestFileAllInformationDecoderNameInformation(t *testing.T) {
	require := require.New(t)

	for n := range 100 {
		require.True(FileAllInformationDecoder(make([]byte, n)).IsInvalid(),
			"truncation to %d bytes not reported invalid", n)
	}

	nameBytes := utf16le.EncodeStringToBytes("hello.txt")
	matching := make([]byte, 100+len(nameBytes))
	le.PutUint32(matching[96:100], uint32(len(nameBytes)))
	copy(matching[100:], nameBytes)

	oddMatching := make([]byte, 100+4)
	le.PutUint32(oddMatching[96:100], 3)

	nameLengthCases := []struct {
		name  string
		buf   []byte
		valid bool
	}{
		{"empty name", make([]byte, 100), true},
		{"name data matches length", matching, true},
		{"name length exceeds data", matching[:len(matching)-1], false},
		{"odd name length", oddMatching, false},
		{"maximum name length exceeds data", make([]byte, 100), false},
	}
	le.PutUint32(nameLengthCases[4].buf[96:100], ^uint32(0))

	for _, tt := range nameLengthCases {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(tt.valid, !FileAllInformationDecoder(tt.buf).IsInvalid())
		})
	}
}

func TestFileAllInformationDecoderTimes(t *testing.T) {
	tests := []struct {
		name   string
		offset int
	}{
		{"CreationTime", 0},
		{"LastAccessTime", 8},
		{"LastWriteTime", 16},
		{"ChangeTime", 24},
	}
	values := []struct {
		name  string
		value uint64
		valid bool
	}{
		{"zero", 0, true},
		{"normal", 42, true},
		{"maximum nonnegative", 0x7fffffffffffffff, true},
		{"minus one", ^uint64(0), false},
		{"minus two", ^uint64(0) - 1, false},
		{"minimum negative", 0x8000000000000000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					buf := make([]byte, 100)
					le.PutUint64(buf[tt.offset:tt.offset+8], value.value)

					require.Equal(t, !value.valid,
						FileAllInformationDecoder(buf).IsInvalid(),
						"%s=%#x", tt.name, value.value)
				})
			}
		})
	}
}

func TestFileNotifyInformationActionAndRecordBoundaries(t *testing.T) {
	for action := uint32(0); action <= 12; action++ {
		record := buildFileNotifyInformation(action, "a")
		require.Equal(t, action < 1 || action > 11, FileNotifyInformationDecoder(record).IsInvalid())
	}
	record := buildFileNotifyInformation(FILE_ACTION_ADDED, "a")
	for size := range record {
		require.True(t, FileNotifyInformationDecoder(record[:size]).IsInvalid())
	}
	le.PutUint32(record[:4], uint32(len(record)))
	next := buildFileNotifyInformation(FILE_ACTION_ADDED, "b")
	chain := append(record, next...)
	// The name fits the complete output, but overlaps the next record.
	le.PutUint32(chain[8:12], 8)
	require.True(t, FileNotifyInformationDecoder(chain).IsInvalid())
}

func TestFileNetworkOpenInformationDecoder(t *testing.T) {
	buf := make([]byte, 56)
	le.PutUint32(buf[0:4], 0x11223344)
	le.PutUint32(buf[4:8], 0x01234567)
	le.PutUint32(buf[8:12], 0x55667788)
	le.PutUint32(buf[12:16], 0x01234567)
	le.PutUint32(buf[16:20], 0x99aabbcc)
	le.PutUint32(buf[20:24], 0x01234567)
	le.PutUint32(buf[24:28], 0xddeeff00)
	le.PutUint32(buf[28:32], 0x01234567)
	le.PutUint64(buf[32:40], 8192)
	le.PutUint64(buf[40:48], 4096)
	le.PutUint32(buf[48:52], 0x20)

	dec := FileNetworkOpenInformationDecoder(buf)
	require.False(t, dec.IsInvalid())
	require.Equal(t, int64(8192), dec.AllocationSize())
	require.Equal(t, int64(4096), dec.EndOfFile())
	require.Equal(t, uint32(0x20), dec.FileAttributes())

	for n := range 56 {
		require.True(t, FileNetworkOpenInformationDecoder(buf[:n]).IsInvalid())
	}

	// Negative timestamps
	for off := 0; off < 32; off += 8 {
		bad := make([]byte, 56)
		copy(bad, buf)
		bad[off+7] |= 0x80
		require.True(t, FileNetworkOpenInformationDecoder(bad).IsInvalid())
	}

	// Negative EOF
	badEOF := make([]byte, 56)
	copy(badEOF, buf)
	le.PutUint64(badEOF[40:48], uint64(^uint64(0)>>1+1))
	require.True(t, FileNetworkOpenInformationDecoder(badEOF).IsInvalid())
}

// The QUERY_DIRECTORY decoders validate a server-supplied length before
// slicing by it. That validation overflows.
//
// IsInvalid computed 64+FileNameLength in uint32, so a FileNameLength
// near the top of the range wrapped the sum to a small number, the
// comparison passed, and the decoder went on to slice a buffer by a
// length it had just failed to reject.
//
// A directory listing against a hostile or man-in-the-middle SMB server
// crashes the process on it. GO-2026-5051.
func TestFileDirectoryInformationDecoderRejectsOverflowingNameLength(t *testing.T) {
	for _, nameLen := range []uint32{
		0xFFFFFFFF, // 64 + this wraps to 63
		0xFFFFFFC0, // wraps to exactly 0
		0xFFFFFFC1, // wraps to 1
		1 << 31,
		0x7FFFFFFF,
	} {
		// A minimal entry: the 64-byte fixed part and no name, claiming
		// a name far larger than the buffer.
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint32(buf[60:64], nameLen)

		d := FileDirectoryInformationDecoder(buf)
		if !d.IsInvalid() {
			t.Errorf("FileNameLength %#x in a %d-byte buffer was accepted as valid",
				nameLen, len(buf))
		}
	}
}

// A well-formed entry must still be accepted — the bound must reject
// what does not fit, not everything.
func TestFileDirectoryInformationDecoderAcceptsAWellFormedEntry(t *testing.T) {
	nameBytes := utf16le.EncodeStringToBytes("test")
	buf := make([]byte, 64+len(nameBytes))
	binary.LittleEndian.PutUint32(buf[60:64], uint32(len(nameBytes)))
	copy(buf[64:], nameBytes)

	if d := FileDirectoryInformationDecoder(buf); d.IsInvalid() {
		t.Errorf("a %d-byte buffer with a %d-byte name was rejected", len(buf), len(nameBytes))
	}

	// One byte short of what it claims must still be rejected.
	short := make([]byte, 64+len(nameBytes)-1)
	binary.LittleEndian.PutUint32(short[60:64], uint32(len(nameBytes)))
	copy(short[64:], nameBytes[:len(nameBytes)-1])
	if d := FileDirectoryInformationDecoder(short); !d.IsInvalid() {
		t.Errorf("a buffer one byte short of its declared name was accepted")
	}
}

func TestFileIdBothDirectoryInformationDecoderRejectsOddNameLength(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		nameLength uint32
		next       uint32
		bufferSize int
	}{
		{name: "final one-byte name", nameLength: 1, bufferSize: 105},
		{name: "final three-byte name", nameLength: 3, bufferSize: 107},
		{name: "continued one-byte name", nameLength: 1, next: 112, bufferSize: 216},
		{name: "continued three-byte name", nameLength: 3, next: 112, bufferSize: 216},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			buf := make([]byte, testCase.bufferSize)
			binary.LittleEndian.PutUint32(buf[0:4], testCase.next)
			binary.LittleEndian.PutUint32(buf[60:64], testCase.nameLength)

			if !FileIdBothDirectoryInformationDecoder(buf).IsInvalid() {
				t.Fatalf("a %d-byte name in a %d-byte buffer was accepted",
					testCase.nameLength, len(buf))
			}
		})
	}
}

func TestFileIdBothDirectoryInformationDecoderRejectsPathSeparators(t *testing.T) {
	for _, name := range []string{`..\outside.txt`, `a\b`, `../outside.txt`, `a/b`} {
		t.Run(name, func(t *testing.T) {
			buf := buildIdBothDirInfo(1, name)
			require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
		})
	}
}

func TestFileIdBothDirectoryInformationDecoderRejectsEmptyAndNULNames(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, "")
		require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
	})

	t.Run("NUL in name", func(t *testing.T) {
		nameBytes := append(utf16le.EncodeStringToBytes("a"), 0, 0)
		b := make([]byte, 104+len(nameBytes))
		le.PutUint32(b[60:64], uint32(len(nameBytes)))
		copy(b[104:], nameBytes)
		require.True(t, FileIdBothDirectoryInformationDecoder(b).IsInvalid())
	})
}

func buildFileDirInfo(name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
	b := make([]byte, 64+len(nameBytes))
	le.PutUint32(b[0:4], 0)      // NextEntryOffset
	le.PutUint32(b[4:8], 7)      // FileIndex
	le.PutUint64(b[40:48], 1234) // EndOfFile
	le.PutUint64(b[48:56], 4096) // AllocationSize
	le.PutUint32(b[56:60], 0x20) // FileAttributes
	le.PutUint32(b[60:64], uint32(len(nameBytes)))
	copy(b[64:], nameBytes)
	return b
}

func TestFileDirectoryInformationDecoderRejectsPathSeparators(t *testing.T) {
	for _, name := range []string{`..\outside.txt`, `a\b`, `../outside.txt`, `a/b`} {
		t.Run(name, func(t *testing.T) {
			buf := buildFileDirInfo(name)
			require.True(t, FileDirectoryInformationDecoder(buf).IsInvalid())
		})
	}
}

func TestFileDirectoryInformationDecoderRejectsEmptyAndNULNames(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		buf := buildFileDirInfo("")
		require.True(t, FileDirectoryInformationDecoder(buf).IsInvalid())
	})

	t.Run("NUL in name", func(t *testing.T) {
		nameBytes := append(utf16le.EncodeStringToBytes("a"), 0, 0)
		b := make([]byte, 64+len(nameBytes))
		le.PutUint32(b[60:64], uint32(len(nameBytes)))
		copy(b[64:], nameBytes)
		require.True(t, FileDirectoryInformationDecoder(b).IsInvalid())
	})
}

func TestFileDirectoryInformationDecoderRejectsOddNameLength(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		nameLength uint32
		next       uint32
		bufferSize int
	}{
		{name: "final one-byte name", nameLength: 1, bufferSize: 65},
		{name: "final three-byte name", nameLength: 3, bufferSize: 67},
		{name: "continued one-byte name", nameLength: 1, next: 72, bufferSize: 144},
		{name: "continued three-byte name", nameLength: 3, next: 72, bufferSize: 144},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			buf := make([]byte, testCase.bufferSize)
			binary.LittleEndian.PutUint32(buf[0:4], testCase.next)
			binary.LittleEndian.PutUint32(buf[60:64], testCase.nameLength)

			if !FileDirectoryInformationDecoder(buf).IsInvalid() {
				t.Fatalf("a %d-byte name in a %d-byte buffer was accepted",
					testCase.nameLength, len(buf))
			}
		})
	}
}


func TestFileDirectoryInformationDecoderRejectsTruncatedFixedPart(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{name: "nil"},
	}
	for length := range 64 {
		testCases = append(testCases, struct {
			name  string
			input []byte
		}{name: strconv.Itoa(length), input: make([]byte, length)})
	}
	backing := make([]byte, 64)
	testCases = append(testCases, struct {
		name  string
		input []byte
	}{name: "spare-capacity", input: backing[:63]})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated directory information caused panic: %v", r)
				}
			}()

			if d := FileDirectoryInformationDecoder(testCase.input); !d.IsInvalid() {
				t.Fatalf("%d-byte directory information was accepted", len(testCase.input))
			}
		})
	}
}

// The same arithmetic appears in three other decoders, all reachable
// from a server response.
func TestOtherDecodersRejectOverflowingLengths(t *testing.T) {
	t.Run("SrvRequestResumeKeyResponse", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint32(buf[24:28], 0xFFFFFFFF)
		if d := SrvRequestResumeKeyResponseDecoder(buf); !d.IsInvalid() {
			t.Error("an overflowing ContextLength was accepted")
		}
	})

	t.Run("FileQuotaInformation", func(t *testing.T) {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint32(buf[4:8], 0xFFFFFFFF)
		if d := FileQuotaInformationDecoder(buf); !d.IsInvalid() {
			t.Error("an overflowing SidLength was accepted")
		}
	})
}

func TestFileQuotaInformationDecoderRejectsTruncatedFixedPart(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{name: "nil"},
	}
	for length := range 40 {
		testCases = append(testCases, struct {
			name  string
			input []byte
		}{name: strconv.Itoa(length), input: make([]byte, length)})
	}
	backing := make([]byte, 40)
	testCases = append(testCases, struct {
		name  string
		input []byte
	}{name: "spare-capacity", input: backing[:39]})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated quota information caused panic: %v", r)
				}
			}()

			if d := FileQuotaInformationDecoder(testCase.input); !d.IsInvalid() {
				t.Fatalf("%d-byte quota information was accepted", len(testCase.input))
			}
		})
	}
}

func TestSrvRequestResumeKeyResponseRejectsTruncatedResponse(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("truncated response caused panic: %v", r)
		}
	}()

	if !SrvRequestResumeKeyResponseDecoder(nil).IsInvalid() {
		t.Fatal("truncated response was accepted")
	}
}

func TestFileFsFullSizeInformationDecoderValidatesAllocationUnits(t *testing.T) {
	testCases := []struct {
		name   string
		offset int
	}{
		{name: "TotalAllocationUnits", offset: 0},
		{name: "CallerAvailableAllocationUnits", offset: 8},
		{name: "ActualAvailableAllocationUnits", offset: 16},
	}
	values := []struct {
		name    string
		value   int64
		invalid bool
	}{
		{name: "negative one", value: -1, invalid: true},
		{name: "minimum int64", value: -1 << 63, invalid: true},
		{name: "zero", value: 0},
		{name: "one", value: 1},
		{name: "maximum int64", value: 1<<63 - 1},
	}

	for _, testCase := range testCases {
		for _, value := range values {
			t.Run(testCase.name+"/"+value.name, func(t *testing.T) {
				buf := make([]byte, 32)
				binary.LittleEndian.PutUint64(buf[testCase.offset:testCase.offset+8], uint64(value.value))

				if got := FileFsFullSizeInformationDecoder(buf).IsInvalid(); got != value.invalid {
					t.Errorf("IsInvalid() = %v for %d in %s, want %v", got, value.value, testCase.name, value.invalid)
				}
			})
		}
	}
}

func TestFileFsFullSizeInformationDecoderRejectsTruncatedBody(t *testing.T) {
	for length := range 32 {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated full size information caused panic: %v", r)
				}
			}()

			if !FileFsFullSizeInformationDecoder(make([]byte, length)).IsInvalid() {
				t.Fatalf("%d-byte full size information was accepted", length)
			}
		})
	}
}
