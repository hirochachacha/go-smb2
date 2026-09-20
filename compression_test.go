package smb2

import (
	"bytes"
	"context"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/pierrec/lz4/v4"
	"github.com/stretchr/testify/require"
)

func TestWriteCompressedWhenNegotiated(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:             openAccount(1),
		outstandingRequests: newOutstandingRequests(),
		dialect:             wire.SMB311,
		compressionIds:      []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:         1 << 20,
		maxWriteSize:        1 << 20,
		maxTransactSize:     1 << 20,
	}
	c.enableSession()
	c.session = &session{conn: c, sessionId: 1}

	data := bytes.Repeat([]byte("compressible payload "), 4096)
	_, parts, err := c.makeOutstandingRequest(context.Background(), false, []uint64{1}, &wire.WriteRequest{Data: data})
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
	if wire.PacketCodec(got).Command() != wire.SMB2_WRITE {
		t.Fatalf("decompressed command = %v, want SMB2_WRITE", wire.PacketCodec(got).Command())
	}
	if !bytes.Contains(got, data) {
		t.Fatal("decompressed write request does not contain the original payload")
	}
}

func TestCompressPacketUsesRawLZ4AndFallsBack(t *testing.T) {
	t.Parallel()
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
	p := wire.PacketCodec(original)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(wire.SMB2_WRITE)
	compressed, err := compressPacket(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(original) {
		t.Fatalf("compressed packet length = %d, original = %d", len(compressed), len(original))
	}
	c := wire.CompressionCodec(compressed)
	if c.IsInvalid() || c.CompressionAlgorithm() != wire.SMB2_COMPRESSION_ALGORITHM_LZ4 {
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
		dialect:         wire.SMB311,
		compressionIds:  []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
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
	t.Parallel()
	const messageID = 7
	want := bytes.Repeat([]byte("direct compressed read "), 64)
	res := &wire.ReadResponse{
		PacketHeader: wire.PacketHeader{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR},
		Data:         want,
	}
	plain := make([]byte, res.Size())
	res.Encode(plain)
	wire.PacketCodec(plain).SetMessageId(messageID)
	frontSize := int(wire.ReadResponseDecoder(plain[64:]).DataOffset())

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
	c := wire.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(want)))
	c.SetCompressionAlgorithm(wire.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(wire.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(frontSize))
	copy(pkt[compressionHeaderSize:], plain[:frontSize])
	copy(pkt[compressionHeaderSize+frontSize:], compressed[:n])

	readBuf := make([]byte, len(want))
	conn := &conn{
		dialect:             wire.SMB311,
		compressionIds:      []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
		maxReadSize:         uint32(len(want)),
		maxWriteSize:        uint32(len(want)),
		maxTransactSize:     uint32(len(want)),
		outstandingRequests: newOutstandingRequests(),
	}
	conn.session = &session{conn: conn}
	conn.enableSession()
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
	t.Parallel()
	prefix := make([]byte, 64)
	p := wire.PacketCodec(prefix)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(wire.SMB2_READ)
	p.SetSessionId(0x1234)

	compressed := []byte{0x50, 'h', 'e', 'l', 'l', 'o'}
	pkt := make([]byte, 16+len(prefix)+len(compressed))
	c := wire.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(compressed) - 1))
	c.SetCompressionAlgorithm(wire.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(wire.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(len(prefix)))
	copy(pkt[16:], prefix)
	copy(pkt[16+len(prefix):], compressed)

	got, err := decompressPacket(&conn{
		dialect:         wire.SMB311,
		compressionIds:  []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
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
	t.Parallel()
	pkt := make([]byte, 16+1)
	c := wire.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetCompressionAlgorithm(wire.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(wire.SMB2_COMPRESSION_FLAG_NONE)

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
				dialect:         wire.SMB311,
				compressionIds:  []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
				maxReadSize:     128,
				maxWriteSize:    128,
				maxTransactSize: 128,
			}, pkt); err == nil {
				t.Fatal("unsafe compressed packet accepted")
			}
		})
	}
}

func TestTryDecryptCompressedDirectReadValidatesBeforeCopy(t *testing.T) {
	t.Parallel()
	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			const (
				sessionID = uint64(0xCAFE)
				messageID = uint64(7)
			)
			want := bytes.Repeat([]byte("compressed encrypted payload "), 32)
			makePlain := func(innerSessionID uint64) []byte {
				res := &wire.ReadResponse{
					PacketHeader: wire.PacketHeader{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, SessionId: innerSessionID},
					Data:         want,
				}
				plain := make([]byte, res.Size())
				res.Encode(plain)
				wire.PacketCodec(plain).SetMessageId(messageID)
				return plain
			}

			c := &conn{
				dialect:             wire.SMB311,
				compressionIds:      []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4},
				maxReadSize:         uint32(len(want)),
				maxWriteSize:        uint32(len(want)),
				maxTransactSize:     uint32(len(want)),
				outstandingRequests: newOutstandingRequests(),
			}
			c.session = &session{
				conn:      c,
				sessionId: sessionID,
				decrypter: aead,
				encrypter: aead,
			}

			makeEncrypted := func(compressed []byte) *recvPacket {
				pkt, err := c.session.encrypt(compressed, make([]byte, 52+len(compressed)+aead.Overhead()))
				require.NoError(err)
				return &recvPacket{pkt: pkt}
			}

			badBuf := bytes.Repeat([]byte{0xa5}, len(want)+16)
			c.outstandingRequests.set(messageID, &outstandingRequest{
				msgId:      messageID,
				readBuf:    badBuf,
				directDone: make(chan struct{}),
			})
			bad := makeEncrypted(compressReadResponseForTest(t, makePlain(sessionID+1)))
			decoded, encrypted, err := c.tryDecrypt(bad)
			require.ErrorContains(err, "unknown session id")
			require.True(encrypted)
			require.Same(bad, decoded)
			require.Equal(bytes.Repeat([]byte{0xa5}, len(badBuf)), badBuf)

			goodBuf := bytes.Repeat([]byte{0xa5}, len(want)+16)
			goodRR := &outstandingRequest{
				msgId:      messageID,
				readBuf:    goodBuf,
				directDone: make(chan struct{}),
			}
			c.outstandingRequests.set(messageID, goodRR)
			good := makeEncrypted(compressReadResponseForTest(t, makePlain(sessionID)))
			decoded, encrypted, err = c.tryDecrypt(good)
			require.NoError(err)
			require.True(encrypted)
			require.Same(&goodBuf[0], &decoded.ext[0])
			require.Equal(want, goodBuf[:len(want)])
			require.NotEqual(directStateReading, goodRR.directState.Load())
		})
	}
}

func compressReadResponseForTest(t *testing.T, plain []byte) []byte {
	t.Helper()
	require := require.New(t)
	frontSize := int(wire.ReadResponseDecoder(plain[64:]).DataOffset())
	payload := plain[frontSize:]
	compressed := make([]byte, lz4.CompressBlockBound(len(payload)))
	var compressor lz4.Compressor
	n, err := compressor.CompressBlock(payload, compressed)
	require.NoError(err)
	require.NotZero(n)

	pkt := make([]byte, compressionHeaderSize+frontSize+n)
	c := wire.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(payload)))
	c.SetCompressionAlgorithm(wire.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(wire.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(frontSize))
	copy(pkt[compressionHeaderSize:], plain[:frontSize])
	copy(pkt[compressionHeaderSize+frontSize:], compressed[:n])
	return pkt
}
