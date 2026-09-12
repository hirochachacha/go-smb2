package smb2

import (
	"testing"

	"github.com/hirochachacha/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

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
		for n := 0; n < 24; n++ {
			require.True(t, FileStandardInformationDecoder(standard[:n]).IsInvalid())
		}
		for n := 0; n < 100; n++ {
			require.True(t, FileAllInformationDecoder(all[:n]).IsInvalid())
		}
	}
}

func TestFileAllInformationDecoderNameInformation(t *testing.T) {
	require := require.New(t)

	for n := 0; n < 100; n++ {
		require.True(FileAllInformationDecoder(make([]byte, n)).IsInvalid(),
			"truncation to %d bytes not reported invalid", n)
	}

	nameBytes := utf16le.EncodeStringToBytes("hello.txt")
	matching := make([]byte, 100+len(nameBytes))
	le.PutUint32(matching[96:100], uint32(len(nameBytes)))
	copy(matching[100:], nameBytes)

	nameLengthCases := []struct {
		name  string
		buf   []byte
		valid bool
	}{
		{"empty name", make([]byte, 100), true},
		{"name data matches length", matching, true},
		{"name length exceeds data", matching[:len(matching)-1], false},
		{"maximum name length exceeds data", make([]byte, 100), false},
	}
	le.PutUint32(nameLengthCases[3].buf[96:100], ^uint32(0))

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
	for size := 0; size < len(record); size++ {
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

	for n := 0; n < 56; n++ {
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
