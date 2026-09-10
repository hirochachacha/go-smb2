package smb2

import (
	"bytes"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func TestCompressPacketUsesRawLZ4AndFallsBack(t *testing.T) {
	small := bytes.Repeat([]byte{'a'}, 20)
	smallCompressed, err := compressPacket(small)
	if err != nil {
		t.Fatal(err)
	}
	if len(smallCompressed) <= len(small) {
		t.Fatalf("the 16-byte header boundary was not preserved: compressed=%d original=%d", len(smallCompressed), len(small))
	}

	original := bytes.Repeat([]byte("compressible payload "), 32)
	original = append(make([]byte, 64), original...)
	p := smb2.PacketCodec(original)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_WRITE)
	compressed, err := compressPacket(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(original) {
		t.Fatalf("compressed packet length = %d, original = %d", len(compressed), len(original))
	}
	c := smb2.CompressionCodec(compressed)
	if c.IsInvalid() || c.CompressionAlgorithm() != smb2.SMB2_COMPRESSION_ALGORITHM_LZ4 {
		t.Fatal("compressed packet does not contain an LZ4 compression header")
	}
	if got, err := decompressPacket(&conn{
		dialect:         smb2.SMB311,
		compressionIds:  []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:     65536,
		maxWriteSize:    65536,
		maxTransactSize: 65536,
	}, compressed); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("raw LZ4 round trip failed: len=%d err=%v", len(got), err)
	}

	incompressible := make([]byte, 97)
	for i := range incompressible {
		incompressible[i] = byte(i)
	}
	got, err := compressPacket(incompressible)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &incompressible[0] {
		t.Fatal("incompressible data was copied instead of returned unchanged")
	}
}

func TestDecompressPacketPreservesOffsetPrefix(t *testing.T) {
	prefix := make([]byte, 64)
	p := smb2.PacketCodec(prefix)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_READ)
	p.SetSessionId(0x1234)

	compressed := []byte{0x50, 'h', 'e', 'l', 'l', 'o'}
	pkt := make([]byte, 16+len(prefix)+len(compressed))
	c := smb2.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(compressed) - 1))
	c.SetCompressionAlgorithm(smb2.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(smb2.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(len(prefix)))
	copy(pkt[16:], prefix)
	copy(pkt[16+len(prefix):], compressed)

	got, err := decompressPacket(&conn{
		dialect:         smb2.SMB311,
		compressionIds:  []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:     65536,
		maxWriteSize:    65536,
		maxTransactSize: 65536,
	}, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:len(prefix)], prefix) || string(got[len(prefix):]) != "hello" {
		t.Fatalf("offset prefix or decompressed payload was changed: %x", got)
	}
}

func TestDecompressPacketRejectsUnsafeSizesBeforeAllocation(t *testing.T) {
	pkt := make([]byte, 16+1)
	c := smb2.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetCompressionAlgorithm(smb2.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(smb2.SMB2_COMPRESSION_FLAG_NONE)

	tests := []struct {
		name   string
		orig   uint32
		offset uint32
	}{
		{"declared size over limit", 1000, 0},
		{"offset outside input", 1, 2},
		{"offset addition overflow", ^uint32(0), ^uint32(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.SetOriginalCompressedSegmentSize(tt.orig)
			c.SetOffset(tt.offset)
			if _, err := decompressPacket(&conn{
				dialect:         smb2.SMB311,
				compressionIds:  []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
				maxReadSize:     128,
				maxWriteSize:    128,
				maxTransactSize: 128,
			}, pkt); err == nil {
				t.Fatal("unsafe compressed packet accepted")
			}
		})
	}
}
