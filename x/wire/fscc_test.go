package wire

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
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
		Flags:          SYMLINK_FLAG_RELATIVE,
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
		flags          uint32
		substituteName string
		printName      string
	}{
		{name: "zero print name", flags: SYMLINK_FLAG_RELATIVE, substituteName: "target", printName: ""},
		{name: "names end at buffer", flags: SYMLINK_FLAG_RELATIVE, substituteName: "target", printName: "display"},
		{name: "surrogate pair", flags: SYMLINK_FLAG_RELATIVE, substituteName: "😀", printName: "😀"},
		{name: "absolute drive path", flags: 0, substituteName: `\??\C:\dir`, printName: `C:\dir`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &SymbolicLinkReparseDataBuffer{
				Flags:          tc.flags,
				SubstituteName: tc.substituteName,
				PrintName:      tc.printName,
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			d := SymbolicLinkReparseDataBufferDecoder(buf)
			if d.IsInvalid() {
				t.Fatal("valid symbolic link reparse data was rejected")
			}
			wantSub := normalizeSymlinkTarget(tc.substituteName)
			if got := d.SubstituteName(); got != wantSub {
				t.Errorf("SubstituteName() = %q, want %q", got, wantSub)
			}
			if got := d.PrintName(); got != tc.printName {
				t.Errorf("PrintName() = %q, want %q", got, tc.printName)
			}
		})
	}
}

func TestSymbolicLinkReparseDataBufferDecoderRejectsInvalidTargets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		flags      uint32
		substitute string
	}{
		{name: "empty target", flags: SYMLINK_FLAG_RELATIVE, substitute: ""},
		{name: "relative leading backslash", flags: SYMLINK_FLAG_RELATIVE, substitute: `\target`},
		{name: "relative leading slash", flags: SYMLINK_FLAG_RELATIVE, substitute: `/target`},
		{name: "relative LongNamePrefix NT", flags: SYMLINK_FLAG_RELATIVE, substitute: `\??\C:\dir`},
		{name: "relative LongNamePrefix Win32", flags: SYMLINK_FLAG_RELATIVE, substitute: `\\?\C:\dir`},
		{name: "relative UNC", flags: SYMLINK_FLAG_RELATIVE, substitute: `\\server\share\dir`},
		{name: "relative drive path", flags: SYMLINK_FLAG_RELATIVE, substitute: `C:\dir`},
		{name: "absolute relative path", flags: 0, substitute: `dir\target`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &SymbolicLinkReparseDataBuffer{
				Flags:          tc.flags,
				SubstituteName: tc.substitute,
				PrintName:      "display",
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			if !SymbolicLinkReparseDataBufferDecoder(buf).IsInvalid() {
				t.Fatalf("invalid target %q with flags %#x was accepted", tc.substitute, tc.flags)
			}
		})
	}
}

func TestSymbolicLinkReparseDataBufferDecoderRejectsMalformedUTF16(t *testing.T) {
	response := &SymbolicLinkReparseDataBuffer{
		Flags:          SYMLINK_FLAG_RELATIVE,
		SubstituteName: "target",
		PrintName:      "display",
	}
	buf := make([]byte, response.Size())
	response.Encode(buf)
	printOffset := 20 + utf16le.EncodedStringLen(response.SubstituteName)
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "lone high substitute",
			mutate: func(b []byte) {
				le.PutUint16(b[20:22], 0xd800)
			},
		},
		{
			name: "lone low substitute",
			mutate: func(b []byte) {
				le.PutUint16(b[20:22], 0xdc00)
			},
		},
		{
			name: "malformed print pair",
			mutate: func(b []byte) {
				le.PutUint16(b[printOffset:printOffset+2], 0xd800)
				le.PutUint16(b[printOffset+2:printOffset+4], 'x')
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), buf...)
			tc.mutate(bad)
			if !SymbolicLinkReparseDataBufferDecoder(bad).IsInvalid() {
				t.Fatal("malformed UTF-16 was accepted")
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

func TestFileNotifyInformationDecoderUnpadded(t *testing.T) {
	nameBytes := utf16le.EncodeStringToBytes("created.txt")
	b := make([]byte, 12+len(nameBytes))
	le.PutUint32(b[4:8], FILE_ACTION_ADDED)
	le.PutUint32(b[8:12], uint32(len(nameBytes)))
	copy(b[12:], nameBytes)

	dec := FileNotifyInformationDecoder(b)
	require.False(t, dec.IsInvalid())
	require.Equal(t, uint32(FILE_ACTION_ADDED), dec.Action())
	require.Equal(t, "created.txt", dec.FileName())
}

func TestFileNotifyInformationDecoderValidatesName(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		invalid bool
	}{
		{name: "empty", value: "", invalid: true},
		{name: "embedded NUL", value: "a\x00b", invalid: true},
		{name: "trailing NUL", value: "a\x00", invalid: true},
		{name: "dot", value: ".", invalid: true},
		{name: "dotdot", value: "..", invalid: true},
		{name: "leading dot", value: `.\x`, invalid: true},
		{name: "middle dotdot", value: `a\..\b`, invalid: true},
		{name: "trailing dot", value: `a\.`, invalid: true},
		{name: "dotdot escape", value: `..\target`, invalid: true},
		{name: "ASCII", value: "abc"},
		{name: "filename with interior dots", value: "a.b.txt"},
		{name: "dot prefix filename", value: ".gitignore"},
		{name: "BMP", value: "é"},
		{name: "surrogate pair", value: "😀"},
		{name: "U+0020", value: "a b"},
		{name: "zero padding", value: "a"},
		{name: "relative subpath", value: `dir\file.txt`},
		{name: "relative stream", value: `file.txt:stream:$DATA`},
		{name: "relative stream name", value: "file:stream"},
		{name: "relative stream type", value: "file:stream:$DATA"},
		{name: "root slash", value: "/root", invalid: true},
		{name: "root backslash", value: `\root`, invalid: true},
		{name: "quote", value: `a"b`, invalid: true},
		{name: "stream name quote", value: `file:st"ream`, invalid: true},
		{name: "stream type quote", value: `file:str:ty"pe`, invalid: true},
		{name: "U+0122", value: "a\u0122b"},
		{name: "child slash", value: "a/b", invalid: true},
		{name: "trailing backslash", value: `a\`, invalid: true},
		{name: "consecutive backslashes", value: `a\\b`, invalid: true},
	}
	for value := rune(0); value <= 0x001f; value++ {
		cases = append(cases, struct {
			name    string
			value   string
			invalid bool
		}{name: "control U+" + strconv.FormatInt(int64(value), 16), value: "a" + string(value) + "b", invalid: true})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := buildFileNotifyInformation(FILE_ACTION_MODIFIED, tc.value)
			require.Equal(t, tc.invalid, FileNotifyInformationDecoder(record).IsInvalid())
		})
	}
}

// The double quote check covers only the declared FileName; the zero padding
// before the next 4-byte boundary is not part of the name ([MS-SMB2] 3.2.5.16).
// It also checks both UTF-16LE bytes, so a code unit such as U+0122,
// whose little-endian low byte is 0x22, is not mistaken for a quote.
func TestFileNotifyInformationDecoderQuoteCheckScope(t *testing.T) {
	record := buildFileNotifyInformation(FILE_ACTION_MODIFIED, "a")
	record[len(record)-2] = '"'
	require.False(t, FileNotifyInformationDecoder(record).IsInvalid())

	record = buildFileNotifyInformation(FILE_ACTION_MODIFIED, "a\u0122b")
	require.False(t, FileNotifyInformationDecoder(record).IsInvalid())
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
		{"truncated next entry", 112, 112 + 50, true},
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

func TestFileInformationRejectsNegativeOffsets(t *testing.T) {
	for _, val := range []int64{-1, -1 << 63, 0, 42, 1<<63 - 1} {
		pos := make([]byte, 8)
		le.PutUint64(pos[:8], uint64(val))
		require.Equal(t, val < 0, FilePositionInformationDecoder(pos).IsInvalid())

		eof := make([]byte, 8)
		le.PutUint64(eof[:8], uint64(val))
		require.Equal(t, val < 0, FileEndOfFileInformationDecoder(eof).IsInvalid())

		alloc := make([]byte, 24)
		le.PutUint64(alloc[:8], uint64(val))
		require.Equal(t, val < 0, FileStandardInformationDecoder(alloc).IsInvalid())

		all := make([]byte, 100)
		copy(all[80:88], pos)
		require.Equal(t, val < 0, FileAllInformationDecoder(all).IsInvalid())
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
		if size == 14 {
			require.False(t, FileNotifyInformationDecoder(record[:size]).IsInvalid())
			continue
		}
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

func TestFileDirectoryInformationDecoderNextEntryOffset(t *testing.T) {
	for _, tt := range []struct {
		name       string
		next       uint32
		bufferSize int
		invalid    bool
	}{
		{"unpadded final entry", 0, 72, false},
		{"buffer length termination", 72, 72, false},
		{"aligned continuation", 72, 72 + 64, false},
		{"truncated next entry", 72, 72 + 30, true},
		{"unaligned continuation", 70, 72 + 64, true},
		{"outside buffer", 150, 72 + 64, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufferSize)
			nameBytes := utf16le.EncodeStringToBytes("test")
			binary.LittleEndian.PutUint32(buf[60:64], uint32(len(nameBytes)))
			copy(buf[64:], nameBytes)
			binary.LittleEndian.PutUint32(buf[:4], tt.next)
			require.Equal(t, tt.invalid, FileDirectoryInformationDecoder(buf).IsInvalid())
		})
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

func TestFileBasicInformationDecoderTimestamps(t *testing.T) {
	for _, offset := range []int{0, 8, 16, 24} {
		buf := make([]byte, 40)
		le.PutUint32(buf[offset+4:offset+8], 0x80000000)
		require.True(t, FileBasicInformationDecoder(buf).IsInvalid())

		le.PutUint32(buf[offset+4:offset+8], 0)
		require.False(t, FileBasicInformationDecoder(buf).IsInvalid())
	}
	require.True(t, FileBasicInformationDecoder(make([]byte, 39)).IsInvalid())
}

func TestFileQuotaInformationDecoderValidation(t *testing.T) {
	buildValidQuota := func() []byte {
		sid := &Sid{
			Revision:            1,
			IdentifierAuthority: 5,
			SubAuthority:        []uint32{500},
		}
		sidBytes := make([]byte, sid.Size())
		sid.Encode(sidBytes)

		buf := make([]byte, 40+len(sidBytes))
		le.PutUint32(buf[4:8], uint32(len(sidBytes))) // SidLength
		le.PutUint64(buf[8:16], 0)                    // ChangeTime
		le.PutUint64(buf[16:24], 100)                 // QuotaUsed
		le.PutUint64(buf[24:32], ^uint64(0))          // QuotaThreshold (-1 = no threshold)
		le.PutUint64(buf[32:40], ^uint64(0))          // QuotaLimit (-1 = no limit)
		copy(buf[40:], sidBytes)
		return buf
	}

	t.Run("valid entry", func(t *testing.T) {
		buf := buildValidQuota()
		require.False(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("negative ChangeTime", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint32(buf[12:16], 0x80000000)
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("negative QuotaUsed", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint64(buf[16:24], ^uint64(0))
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid QuotaThreshold", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint64(buf[24:32], ^uint64(1)) // -2
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid QuotaLimit", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint64(buf[32:40], ^uint64(2)) // -3
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid SidLength", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint32(buf[4:8], 8) // mismatch: actual SID has 1 subauthority (12 bytes)
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid SID revision", func(t *testing.T) {
		buf := buildValidQuota()
		buf[40] = 2
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("valid NextEntryOffset", func(t *testing.T) {
		buf1 := buildValidQuota()
		paddedLen := Roundup(len(buf1), 8)
		buf := make([]byte, paddedLen+len(buf1))
		copy(buf, buf1)
		le.PutUint32(buf[:4], uint32(paddedLen))
		copy(buf[paddedLen:], buf1)
		require.False(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("unaligned NextEntryOffset", func(t *testing.T) {
		buf := buildValidQuota()
		buf = append(buf, make([]byte, 16)...)
		le.PutUint32(buf[:4], 53) // not multiple of 8
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("NextEntryOffset less than entrySize", func(t *testing.T) {
		buf := buildValidQuota()
		le.PutUint32(buf[:4], 40) // less than 40+12=52
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})

	t.Run("truncated next entry", func(t *testing.T) {
		buf1 := buildValidQuota()
		paddedLen := Roundup(len(buf1), 8)
		buf := make([]byte, paddedLen+20) // 20 < 40 minimum entry size
		copy(buf, buf1)
		le.PutUint32(buf[:4], uint32(paddedLen))
		require.True(t, FileQuotaInformationDecoder(buf).IsInvalid())
	})
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

func TestIsDotDirectoryName(t *testing.T) {
	for _, tt := range []struct {
		name  string
		bytes []byte
		want  bool
	}{
		{".", utf16le.EncodeStringToBytes("."), true},
		{"..", utf16le.EncodeStringToBytes(".."), true},
		{"...", utf16le.EncodeStringToBytes("..."), false},
		{"empty", nil, false},
		{"a", utf16le.EncodeStringToBytes("a"), false},
		{".a", utf16le.EncodeStringToBytes(".a"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, IsDotDirectoryName(tt.bytes))
			require.Equal(t, !tt.want, IsInvalidDotDirectoryName(tt.bytes))
		})
	}
}

func TestIsInvalidFilename(t *testing.T) {
	for _, tt := range []struct {
		name string
		val  string
		want bool
	}{
		{"valid", "hello.txt", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 256), true},
		{"max length", strings.Repeat("a", 255), false},
		{"slash", "a/b", true},
		{"backslash", `a\b`, true},
		{"colon", "a:b", true},
		{"pipe", "a|b", true},
		{"less than", "a<b", true},
		{"greater than", "a>b", true},
		{"quote", "a\"b", true},
		{"asterisk", "a*b", true},
		{"question mark", "a?b", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.val)
			require.Equal(t, tt.want, IsInvalidFilename(b))
		})
	}

	t.Run("control character", func(t *testing.T) {
		b := []byte{'a', 0, 1, 0}
		require.True(t, IsInvalidFilename(b))
	})
	t.Run("odd length", func(t *testing.T) {
		require.True(t, IsInvalidFilename([]byte{'a'}))
	})
}

func TestIsInvalidShortName(t *testing.T) {
	for _, tt := range []struct {
		name string
		val  string
		want bool
	}{
		{"valid 8.3", "TEST.TXT", false},
		{"valid lowercase 8.3", "test.txt", false},
		{"valid base only", "README", false},
		{"max base", "12345678", false},
		{"max base and ext", "12345678.123", false},
		{"empty", "", true},
		{"space", "TE ST.TXT", true},
		{"two dots", "TE..TXT", true},
		{"no base", ".TXT", true},
		{"trailing dot without ext", "FILE.", true},
		{"base too long", "123456789.TXT", true},
		{"ext too long", "FILE.TEXT", true},
		{"DBCS short name", "日本語~1", false},
		{"DBCS extension", "テスト.TXT", false},
		{"extended OEM character", "ÉCOLE.TXT", false},
		{"non-OEM supplementary character", "😀.TXT", true},
		{"colon", "TEST:1.TXT", true},
		{"slash", "TEST/1.TXT", true},
		{"backslash", `TEST\1.TXT`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.val)
			require.Equal(t, tt.want, IsInvalidShortName(b))
		})
	}
}

func TestIsInvalidStreamNameAndType(t *testing.T) {
	t.Run("StreamName", func(t *testing.T) {
		require.False(t, IsInvalidStreamName(utf16le.EncodeStringToBytes("stream")))
		require.False(t, IsInvalidStreamName(nil))
		require.True(t, IsInvalidStreamName(utf16le.EncodeStringToBytes("a/b")))
		require.True(t, IsInvalidStreamName(utf16le.EncodeStringToBytes("a\\b")))
		require.True(t, IsInvalidStreamName(utf16le.EncodeStringToBytes("a:b")))
		require.True(t, IsInvalidStreamName(append(utf16le.EncodeStringToBytes("a"), 0, 0)))
		require.True(t, IsInvalidStreamName(utf16le.EncodeStringToBytes(strings.Repeat("a", 256))))
	})

	t.Run("StreamType", func(t *testing.T) {
		require.False(t, IsInvalidStreamType(utf16le.EncodeStringToBytes("$DATA")))
		require.True(t, IsInvalidStreamType(nil))
		require.True(t, IsInvalidStreamType(utf16le.EncodeStringToBytes("a/b")))
		require.True(t, IsInvalidStreamType(utf16le.EncodeStringToBytes("a\\b")))
		require.True(t, IsInvalidStreamType(utf16le.EncodeStringToBytes("a:b")))
		require.True(t, IsInvalidStreamType(append(utf16le.EncodeStringToBytes("a"), 0, 0)))
	})
}

func TestIsInvalidDirectoryEntryName(t *testing.T) {
	require.False(t, IsInvalidDirectoryEntryName(utf16le.EncodeStringToBytes(".")))
	require.False(t, IsInvalidDirectoryEntryName(utf16le.EncodeStringToBytes("..")))
	require.False(t, IsInvalidDirectoryEntryName(utf16le.EncodeStringToBytes("valid.txt")))
	require.True(t, IsInvalidDirectoryEntryName(nil))
	require.True(t, IsInvalidDirectoryEntryName(utf16le.EncodeStringToBytes("a/b")))
}

func TestIsInvalidPathnameComponent(t *testing.T) {
	for _, tt := range []struct {
		name string
		val  string
		want bool
	}{
		{"dot", ".", true},
		{"dotdot", "..", true},
		{"filename", "file.txt", false},
		{"stream only", "file.txt:stream", false},
		{"stream and type", "file.txt:stream:$DATA", false},
		{"type without stream", "file.txt::$DATA", false},
		{"empty", "", true},
		{"slash", "a/b", true},
		{"backslash", `a\b`, true},
		{"colon without stream", "file.txt:", true},
		{"three colons", "file.txt:s:t:u", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.val)
			require.Equal(t, tt.want, IsInvalidPathnameComponent(b))
		})
	}
}

func TestIsInvalidPathname(t *testing.T) {
	for _, tt := range []struct {
		name string
		val  string
		want bool
	}{
		{"single file", "file.txt", false},
		{"filename with dots", ".gitignore", false},
		{"relative subpath", `dir\file.txt`, false},
		{"absolute subpath", `\dir\file.txt`, false},
		{"stream at end", `dir\file.txt:stream`, false},
		{"stream in intermediate", `dir:stream\file.txt`, true},
		{"trailing backslash", `dir\file.txt\`, true},
		{"consecutive backslashes", `dir\\file.txt`, true},
		{"slash", "dir/file.txt", true},
		{"empty", "", true},
		{"just backslash", `\`, false},
		{"dot only", ".", true},
		{"dotdot only", "..", true},
		{"leading dot", `.\x`, true},
		{"leading dotdot", `..\x`, true},
		{"middle dot", `a\.\b`, true},
		{"middle dotdot", `a\..\b`, true},
		{"trailing dot", `a\.`, true},
		{"trailing dotdot", `a\..`, true},
		{"absolute dot only", `\.`, true},
		{"absolute dotdot only", `\..`, true},
		{"absolute leading dot", `\.\x`, true},
		{"absolute leading dotdot", `\..\x`, true},
		{"absolute middle dotdot", `\a\..\b`, true},
		{"absolute trailing dot", `\a\.`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.val)
			require.Equal(t, tt.want, IsInvalidPathname(b))
		})
	}
}

func TestIsInvalidRelativePathname(t *testing.T) {
	for _, tt := range []struct {
		name string
		val  string
		want bool
	}{
		{"single file", "file.txt", false},
		{"relative subpath", `dir\file.txt`, false},
		{"stream", `file.txt:stream:$DATA`, false},
		{"absolute backslash", `\dir\file.txt`, true},
		{"absolute slash", "/dir/file.txt", true},
		{"empty", "", true},
		{"dot only", ".", true},
		{"dotdot only", "..", true},
		{"leading dot", `.\x`, true},
		{"leading dotdot", `..\x`, true},
		{"middle dotdot", `a\..\b`, true},
		{"trailing dot", `a\.`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.val)
			require.Equal(t, tt.want, IsInvalidRelativePathname(b))
		})
	}
}

func TestFileIdBothDirectoryInformationDecoderShortName(t *testing.T) {
	t.Run("Windows Japanese directory response", func(t *testing.T) {
		// Captured while enumerating a directory containing 日本語フォルダ.
		buf, err := hex.DecodeString("0000000000000000efbe8f8e8449dd01efbe8f8e8449dd01efbe8f8e8449dd01efbe8f8e8449dd0100000000000000000000000000000000100000000e000000000000000a00e5652c679e8a7e0031000000000000000000000000000000000083d0020000000900e5652c679e8ad530a930eb30c030")
		require.NoError(t, err)
		d := FileIdBothDirectoryInformationDecoder(buf)
		require.False(t, d.IsInvalid())
		require.Equal(t, "日本語フォルダ", d.FileName())
		require.Equal(t, "日本語~1", d.ShortName())
	})

	t.Run("valid short name", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, "longfilename.txt")
		shortBytes := utf16le.EncodeStringToBytes("LONGFI~1.TXT")
		buf[68] = uint8(len(shortBytes))
		copy(buf[70:70+len(shortBytes)], shortBytes)
		d := FileIdBothDirectoryInformationDecoder(buf)
		require.False(t, d.IsInvalid())
		require.Equal(t, "LONGFI~1.TXT", d.ShortName())
	})

	t.Run("invalid short name length odd", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, "longfilename.txt")
		buf[68] = 3
		require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid short name length exceeds 24", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, "longfilename.txt")
		buf[68] = 26
		require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
	})

	t.Run("invalid short name content", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, "longfilename.txt")
		badShort := utf16le.EncodeStringToBytes("BAD NAME.TXT")
		buf[68] = uint8(len(badShort))
		copy(buf[70:70+len(badShort)], badShort)
		require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
	})
}

func TestFileIdBothDirectoryInformationDecoderForbiddenCharacters(t *testing.T) {
	for _, char := range []string{`"`, `:`, `|`, `<`, `>`, `*`, `?`} {
		t.Run(char, func(t *testing.T) {
			buf := buildIdBothDirInfo(1, "file"+char+".txt")
			require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
		})
	}

	// [MS-FSCC] 2.4.10 and 2.4.22 explicitly permit dot directory names in
	// the FileName field of directory enumeration entries.
	t.Run("dot directory names", func(t *testing.T) {
		for _, name := range []string{".", ".."} {
			buf := buildIdBothDirInfo(1, name)
			d := FileIdBothDirectoryInformationDecoder(buf)
			require.False(t, d.IsInvalid())
			require.Equal(t, name, d.FileName())
		}
	})

	t.Run("too long filename", func(t *testing.T) {
		buf := buildIdBothDirInfo(1, strings.Repeat("a", 256))
		require.True(t, FileIdBothDirectoryInformationDecoder(buf).IsInvalid())
	})
}

func TestFileNameInformationDecoder(t *testing.T) {
	for _, tt := range []struct {
		name    string
		path    string
		invalid bool
	}{
		{"root backslash", `\`, false},
		{"absolute file", `\hello.txt`, false},
		{"relative file", "hello.txt", false},
		{"absolute subpath", `\dir\file.txt`, false},
		{"relative subpath", `dir\file.txt`, false},
		{"stream", `\file.txt:stream:$DATA`, false},
		{"empty name", "", false},
		{"quote", `\a"b`, true},
		{"slash", "/a/b", true},
		{"trailing backslash", `\dir\file.txt\`, true},
		{"consecutive backslashes", `\dir\\file.txt`, true},
		{"control char", "a\x1fb", true},
		{"embedded NUL", "a\x00b", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.path)
			buf := make([]byte, 4+len(b))
			le.PutUint32(buf[:4], uint32(len(b)))
			copy(buf[4:], b)
			d := FileNameInformationDecoder(buf)
			require.Equal(t, tt.invalid, d.IsInvalid())
			if !tt.invalid {
				require.Equal(t, tt.path, d.FileName())
				require.Equal(t, tt.path, utf16le.DecodeToString(d.FileNameBytes()))
			}
		})
	}

	t.Run("truncated buffer", func(t *testing.T) {
		require.True(t, FileNameInformationDecoder(make([]byte, 3)).IsInvalid())
	})

	t.Run("odd length", func(t *testing.T) {
		buf := make([]byte, 8)
		le.PutUint32(buf[:4], 3)
		require.True(t, FileNameInformationDecoder(buf).IsInvalid())
	})

	t.Run("length exceeds buffer", func(t *testing.T) {
		buf := make([]byte, 6)
		le.PutUint32(buf[:4], 4)
		require.True(t, FileNameInformationDecoder(buf).IsInvalid())
	})
}
