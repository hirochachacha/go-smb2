package smb2

import (
	"testing"

	"github.com/hirochachacha/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

// buildIdBothDirInfo encodes a FILE_ID_BOTH_DIR_INFORMATION entry (MS-FSCC
// 2.4.17) with the given file id and name, so the decoder's offsets can be
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
		for n := 0; n < 96; n++ {
			require.True(t, FileAllInformationDecoder(all[:n]).IsInvalid())
		}
	}
}
