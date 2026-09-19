package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCompressionCodec(t *testing.T) {
	pkt := make([]byte, 24)
	copy(pkt[:4], []byte{0xfc, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint32(pkt[4:8], 0x11223344)
	binary.LittleEndian.PutUint16(pkt[8:10], SMB2_COMPRESSION_ALGORITHM_LZ4)
	binary.LittleEndian.PutUint16(pkt[10:12], SMB2_COMPRESSION_FLAG_NONE)
	binary.LittleEndian.PutUint32(pkt[12:16], 0x00000008)

	c := CompressionCodec(pkt)
	if c.IsInvalid() {
		t.Fatal("known compression header rejected")
	}
	if got := c.OriginalCompressedSegmentSize(); got != 0x11223344 {
		t.Fatalf("OriginalCompressedSegmentSize = %#x", got)
	}
	if got := c.CompressionAlgorithm(); got != SMB2_COMPRESSION_ALGORITHM_LZ4 {
		t.Fatalf("CompressionAlgorithm = %#x", got)
	}
	if got := c.Flags(); got != SMB2_COMPRESSION_FLAG_NONE {
		t.Fatalf("Flags = %#x", got)
	}
	if got := c.Offset(); got != 0x00000008 {
		t.Fatalf("Offset = %#x", got)
	}

	for n := range pkt {
		if !CompressionCodec(pkt[:n]).IsInvalid() {
			t.Fatalf("truncated compression header of length %d accepted", n)
		}
	}
}

func TestCompressionContextDataDecoder(t *testing.T) {
	encoded := make([]byte, (&CompressionContext{
		CompressionAlgorithms: []uint16{SMB2_COMPRESSION_ALGORITHM_LZ4},
		Flags:                 SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE,
	}).Size())
	(&CompressionContext{
		CompressionAlgorithms: []uint16{SMB2_COMPRESSION_ALGORITHM_LZ4},
		Flags:                 SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE,
	}).Encode(encoded)
	want := []byte{
		0x03, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
	}
	// The context is padded to an 8-byte boundary by the enclosing request,
	// not by the context encoder itself.
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded compression context = %x, want %x", encoded, want)
	}

	data := make([]byte, 12)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.LittleEndian.PutUint32(data[4:8], SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE)
	binary.LittleEndian.PutUint16(data[8:10], SMB2_COMPRESSION_ALGORITHM_LZ4)
	binary.LittleEndian.PutUint16(data[10:12], SMB2_COMPRESSION_ALGORITHM_NONE)

	d := CompressionContextDataDecoder(data)
	if d.IsInvalid() {
		t.Fatal("known compression context rejected")
	}
	if got := d.CompressionAlgorithms(); len(got) != 2 || got[0] != SMB2_COMPRESSION_ALGORITHM_LZ4 || got[1] != SMB2_COMPRESSION_ALGORITHM_NONE {
		t.Fatalf("CompressionAlgorithms = %#v", got)
	}

	for n := range data {
		if !CompressionContextDataDecoder(data[:n]).IsInvalid() {
			t.Fatalf("truncated compression context of length %d accepted", n)
		}
	}
}

func TestTransformCodec(t *testing.T) {
	// 52 bytes header + 64 bytes encrypted payload = 116 bytes
	pkt := make([]byte, 116)
	copy(pkt[:4], []byte{0xfd, 'S', 'M', 'B'})

	// SMB 3.0/3.0.2: OriginalMessageSize is 0 (Reserved)
	binary.LittleEndian.PutUint32(pkt[36:40], 0)
	tc := TransformCodec(pkt)
	if tc.IsInvalid() {
		t.Fatal("TransformCodec with OriginalMessageSize=0 rejected")
	}

	// SMB 3.1.1: OriginalMessageSize matches payload size (116 - 52 = 64)
	binary.LittleEndian.PutUint32(pkt[36:40], 64)
	if tc.IsInvalid() {
		t.Fatal("TransformCodec with matching OriginalMessageSize rejected")
	}

	// Mismatched size
	binary.LittleEndian.PutUint32(pkt[36:40], 65)
	if !tc.IsInvalid() {
		t.Fatal("TransformCodec with mismatched OriginalMessageSize accepted")
	}
}

func TestCompressionCodecValidation(t *testing.T) {
	pkt := make([]byte, 24)
	copy(pkt[:4], []byte{0xfc, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], SMB2_COMPRESSION_ALGORITHM_LZ4)
	binary.LittleEndian.PutUint16(pkt[10:12], SMB2_COMPRESSION_FLAG_NONE)
	binary.LittleEndian.PutUint32(pkt[12:16], 8) // 8-byte aligned

	c := CompressionCodec(pkt)
	if c.IsInvalid() {
		t.Fatal("valid compression header rejected")
	}

	// Misaligned offset
	binary.LittleEndian.PutUint32(pkt[12:16], 4)
	if !c.IsInvalid() {
		t.Fatal("misaligned compression offset accepted")
	}
	binary.LittleEndian.PutUint32(pkt[12:16], 8)

	// Non-zero flags
	binary.LittleEndian.PutUint16(pkt[10:12], 1)
	if !c.IsInvalid() {
		t.Fatal("non-zero flags accepted")
	}
	binary.LittleEndian.PutUint16(pkt[10:12], 0)

	// Invalid algorithm
	binary.LittleEndian.PutUint16(pkt[8:10], 6)
	if !c.IsInvalid() {
		t.Fatal("invalid compression algorithm accepted")
	}
}
