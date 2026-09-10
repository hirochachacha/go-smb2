package smb2

import (
	"fmt"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/pierrec/lz4/v4"
)

const compressionHeaderSize = 16

func compressPacket(pkt []byte) ([]byte, error) {
	if len(pkt) == 0 {
		return pkt, nil
	}

	compressed := make([]byte, lz4.CompressBlockBound(len(pkt)))
	var compressor lz4.Compressor
	n, err := compressor.CompressBlock(pkt, compressed)
	if err != nil {
		return nil, err
	}
	// CompressBlock returns zero for data which is not compressible.
	// SMB2 requires the original packet in that case.
	if n == 0 || n >= len(pkt) {
		return pkt, nil
	}

	result := make([]byte, compressionHeaderSize+n)
	c := smb2.CompressionCodec(result)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(pkt)))
	c.SetCompressionAlgorithm(smb2.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(smb2.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(0)
	copy(result[compressionHeaderSize:], compressed[:n])
	return result, nil
}

func (conn *conn) compressionEnabled() bool {
	if conn == nil || conn.dialect != smb2.SMB311 {
		return false
	}
	for _, algorithm := range conn.compressionIds {
		if algorithm == smb2.SMB2_COMPRESSION_ALGORITHM_LZ4 {
			return true
		}
	}
	return false
}

func decompressPacket(conn *conn, pkt []byte) ([]byte, error) {
	if conn == nil || !conn.compressionEnabled() {
		return nil, &InvalidResponseError{"compression was not negotiated"}
	}

	c := smb2.CompressionCodec(pkt)
	if c.IsInvalid() {
		return nil, &InvalidResponseError{"broken compression header format"}
	}
	if c.CompressionAlgorithm() != smb2.SMB2_COMPRESSION_ALGORITHM_LZ4 {
		return nil, &InvalidResponseError{"unsupported compression algorithm"}
	}
	if c.Flags() != smb2.SMB2_COMPRESSION_FLAG_NONE {
		return nil, &InvalidResponseError{"chained compression is not supported"}
	}

	originalSize := uint64(c.OriginalCompressedSegmentSize())
	offset := uint64(c.Offset())
	largestMessage := uint64(max(conn.maxReadSize, max(conn.maxWriteSize, conn.maxTransactSize)))
	if originalSize > 256+compressionHeaderSize+largestMessage {
		return nil, &InvalidResponseError{"compressed segment is too large"}
	}
	if offset > uint64(len(pkt)-compressionHeaderSize) {
		return nil, &InvalidResponseError{"compression offset exceeds packet"}
	}

	fullSize := offset + originalSize
	if fullSize < offset || fullSize > maxDirectTCPSize || fullSize > uint64(int(^uint(0)>>1)) {
		return nil, &InvalidResponseError{"decompressed packet is too large"}
	}

	output := make([]byte, int(fullSize))
	prefixEnd := compressionHeaderSize + int(offset)
	copy(output[:int(offset)], pkt[compressionHeaderSize:prefixEnd])
	n, err := lz4.UncompressBlock(pkt[prefixEnd:], output[int(offset):])
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("LZ4 decompression failed: %v", err)}
	}
	if uint64(n) != originalSize {
		return nil, &InvalidResponseError{"decompressed segment size mismatch"}
	}
	if smb2.PacketCodec(output).IsInvalid() {
		return nil, &InvalidResponseError{"broken decompressed packet format"}
	}
	return output, nil
}
