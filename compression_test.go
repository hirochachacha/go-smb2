package smb2

import (
	"bytes"
	"context"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/pierrec/lz4/v4"
)

func TestWriteCompressedWhenNegotiated(t *testing.T) {
	c := &conn{
		account:             openAccount(1),
		outstandingRequests: newOutstandingRequests(),
		dialect:             smb2.SMB311,
		compressionIds:      []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:         1 << 20,
		maxWriteSize:        1 << 20,
		maxTransactSize:     1 << 20,
	}
	c.enableSession()
	c.session = &session{conn: c, sessionId: 1}

	data := bytes.Repeat([]byte("compressible payload "), 4096)
	_, parts, err := c.makeOutstandingRequest(context.Background(), false, []uint64{1}, &smb2.WriteRequest{Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("got %d transport parts, want 1", len(parts))
	}

	pkt := parts[0]
	if len(pkt) < compressionHeaderSize || pkt[0] != 0xfc || string(pkt[1:4]) != "SMB" {
		t.Fatalf("negotiated write was not compressed: prefix=% x", pkt[:min(8, len(pkt))])
	}

	got, err := decompressPacket(c, pkt)
	if err != nil {
		t.Fatalf("decompressPacket: %v", err)
	}
	if smb2.PacketCodec(got).Command() != smb2.SMB2_WRITE {
		t.Fatalf("decompressed command = %v, want SMB2_WRITE", smb2.PacketCodec(got).Command())
	}
	if !bytes.Contains(got, data) {
		t.Fatal("decompressed write request does not contain the original payload")
	}
}

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
	dst := make([]byte, maxCompressedPacketSize(len(original)))
	direct, err := compressPacketInto(original, dst)
	if err != nil {
		t.Fatal(err)
	}
	if &direct[0] != &dst[0] || !bytes.Equal(direct, compressed) {
		t.Fatal("compressed packet was not written directly into the destination buffer")
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

func TestDecompressPacketUsesDirectReadBuffer(t *testing.T) {
	const messageID = 7
	want := bytes.Repeat([]byte("direct compressed read "), 64)
	res := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR},
		Data:         want,
	}
	plain := make([]byte, res.Size())
	res.Encode(plain)
	smb2.PacketCodec(plain).SetMessageId(messageID)
	frontSize := int(smb2.ReadResponseDecoder(plain[64:]).DataOffset())

	compressed := make([]byte, lz4.CompressBlockBound(len(want)))
	var compressor lz4.Compressor
	n, err := compressor.CompressBlock(want, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("test payload was not compressible")
	}

	pkt := make([]byte, compressionHeaderSize+frontSize+n)
	c := smb2.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(want)))
	c.SetCompressionAlgorithm(smb2.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(smb2.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(frontSize))
	copy(pkt[compressionHeaderSize:], plain[:frontSize])
	copy(pkt[compressionHeaderSize+frontSize:], compressed[:n])

	readBuf := make([]byte, len(want))
	conn := &conn{
		dialect:             smb2.SMB311,
		compressionIds:      []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:         uint32(len(want)),
		maxWriteSize:        uint32(len(want)),
		maxTransactSize:     uint32(len(want)),
		outstandingRequests: newOutstandingRequests(),
	}
	rr := &outstandingRequest{msgId: messageID, readBuf: readBuf}
	conn.outstandingRequests.set(messageID, rr)

	decoded, encrypted, err := conn.tryDecrypt(&recvPacket{pkt: pkt})
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		t.Fatal("compressed-only READ was reported as encrypted")
	}
	if !bytes.Equal(decoded.pkt, plain[:frontSize]) {
		t.Fatal("decompressed READ prefix changed")
	}
	if len(decoded.ext) != len(want) || &decoded.ext[0] != &readBuf[0] || !bytes.Equal(decoded.ext, want) {
		t.Fatal("compressed READ payload was not expanded directly into the caller buffer")
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
