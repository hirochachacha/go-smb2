package smb2

import (
	"encoding/binary"
	"testing"
)

// The request decoders validate a variable-length buffer by comparing the
// packet length against int(offset+length)-64. The offset and length come
// straight off the wire in narrow unsigned types (uint16 or uint32), so the
// addition itself can wrap around before the comparison happens.
//
// A crafted packet whose offset+length wraps to a small value passes
// IsInvalid, and the later accessors slice the buffer with the unwrapped
// values, panicking on a hostile peer's packet.
//
// Widening both sides of the comparison to uint64 makes it wrap-free:
//
//	uint64(len(r))+64 < uint64(offset)+uint64(length)

// Each case feeds a minimal request whose declared offset+length wraps
// around to a small value in the field's own type. Current code accepts
// these as valid; a fixed decoder must reject every one of them.
func TestRequestDecodersRejectOverflowingBufferBounds(t *testing.T) {
	t.Run("SessionSetupRequest", func(t *testing.T) {
		buf := make([]byte, 24)
		binary.LittleEndian.PutUint16(buf[0:2], 25) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16.
		binary.LittleEndian.PutUint16(buf[12:14], 0xFF00) // SecurityBufferOffset
		binary.LittleEndian.PutUint16(buf[14:16], 0x0100) // SecurityBufferLength

		if d := (SessionSetupRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing SecurityBufferOffset+Length was accepted as valid")
		}
	})

	t.Run("TreeConnectRequest", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], 9) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16.
		binary.LittleEndian.PutUint16(buf[4:6], 0xFF00) // PathOffset
		binary.LittleEndian.PutUint16(buf[6:8], 0x0100) // PathLength

		if d := (TreeConnectRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing PathOffset+PathLength was accepted as valid")
		}
	})

	t.Run("CreateRequest/name", func(t *testing.T) {
		buf := make([]byte, 56)
		binary.LittleEndian.PutUint16(buf[0:2], 57) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16; 0xFF00 is 8-byte aligned.
		binary.LittleEndian.PutUint16(buf[44:46], 0xFF00) // NameOffset
		binary.LittleEndian.PutUint16(buf[46:48], 0x0100) // NameLength

		if d := (CreateRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing NameOffset+NameLength was accepted as valid")
		}
	})

	t.Run("CreateRequest/create-contexts", func(t *testing.T) {
		buf := make([]byte, 56)
		binary.LittleEndian.PutUint16(buf[0:2], 57) // StructureSize
		// 0xFFFFFFF8 + 0x0008 wraps to 0 in uint32; 0xFFFFFFF8 is 8-byte aligned.
		binary.LittleEndian.PutUint32(buf[48:52], 0xFFFFFFF8) // CreateContextsOffset
		binary.LittleEndian.PutUint32(buf[52:56], 0x0008)     // CreateContextsLength

		if d := (CreateRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing CreateContextsOffset+Length was accepted as valid")
		}
	})

	t.Run("ReadRequest", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16.
		binary.LittleEndian.PutUint16(buf[44:46], 0xFF00) // ReadChannelInfoOffset
		binary.LittleEndian.PutUint16(buf[46:48], 0x0100) // ReadChannelInfoLength

		if d := (ReadRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing ReadChannelInfoOffset+Length was accepted as valid")
		}
	})

	t.Run("WriteRequest/data", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// 0x0041 + 0xFFFFFFFF wraps to 0x0040 in uint32.
		binary.LittleEndian.PutUint16(buf[2:4], 0x0041)     // DataOffset
		binary.LittleEndian.PutUint32(buf[4:8], 0xFFFFFFFF) // Length

		if d := (WriteRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing DataOffset+Length was accepted as valid")
		}
	})

	t.Run("WriteRequest/write-channel-info", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16.
		binary.LittleEndian.PutUint16(buf[40:42], 0xFF00) // WriteChannelInfoOffset
		binary.LittleEndian.PutUint16(buf[42:44], 0x0100) // WriteChannelInfoLength

		if d := (WriteRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing WriteChannelInfoOffset+Length was accepted as valid")
		}
	})

	t.Run("IoctlRequest", func(t *testing.T) {
		buf := make([]byte, 56)
		binary.LittleEndian.PutUint16(buf[0:2], 57) // StructureSize
		// 0x0041 + 0xFFFFFFFF wraps to 0x0040 in uint32.
		binary.LittleEndian.PutUint32(buf[24:28], 0x0041)     // InputOffset
		binary.LittleEndian.PutUint32(buf[28:32], 0xFFFFFFFF) // InputCount

		if d := (IoctlRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing InputOffset+InputCount was accepted as valid")
		}
	})

	t.Run("QueryDirectoryRequest", func(t *testing.T) {
		buf := make([]byte, 32)
		binary.LittleEndian.PutUint16(buf[0:2], 33) // StructureSize
		// 0xFF00 + 0x0100 wraps to 0 in uint16.
		binary.LittleEndian.PutUint16(buf[24:26], 0xFF00) // FileNameOffset
		binary.LittleEndian.PutUint16(buf[26:28], 0x0100) // FileNameLength

		if d := (QueryDirectoryRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing FileNameOffset+FileNameLength was accepted as valid")
		}
	})

	t.Run("QueryInfoRequest", func(t *testing.T) {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint16(buf[0:2], 41) // StructureSize
		// 0x0041 + 0xFFFFFFFF wraps to 0x0040 in uint32.
		binary.LittleEndian.PutUint16(buf[8:10], 0x0041)      // InputBufferOffset
		binary.LittleEndian.PutUint32(buf[12:16], 0xFFFFFFFF) // InputBufferLength

		if d := (QueryInfoRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing InputBufferOffset+Length was accepted as valid")
		}
	})

	t.Run("SetInfoRequest", func(t *testing.T) {
		buf := make([]byte, 32)
		binary.LittleEndian.PutUint16(buf[0:2], 33) // StructureSize
		// 0x0041 + 0xFFFFFFFF wraps to 0x0040 in uint32.
		binary.LittleEndian.PutUint16(buf[8:10], 0x0041)    // BufferOffset
		binary.LittleEndian.PutUint32(buf[4:8], 0xFFFFFFFF) // BufferLength

		if d := (SetInfoRequestDecoder)(buf); !d.IsInvalid() {
			t.Error("an overflowing BufferOffset+BufferLength was accepted as valid")
		}
	})
}

// The request accessors slice variable-length buffers with the offset and
// length read straight off the wire in narrow unsigned types (uint16), so the
// addition off+len can wrap around, and off itself can point past the end of
// the packet. Either way the slice expression panics on a hostile peer's
// packet.
//
// The accessors must therefore convert both values to int and bounds-check
// them before slicing, returning nil (or "") instead of panicking.
func TestRequestDecodersSafeAccessorsOnWrappingBuffers(t *testing.T) {
	t.Run("SessionSetupRequest", func(t *testing.T) {
		buf := make([]byte, 24)
		binary.LittleEndian.PutUint16(buf[0:2], 25) // StructureSize
		// 65216 + 768 = 65984 wraps to 448 in uint16.
		binary.LittleEndian.PutUint16(buf[12:14], 0xFF00) // SecurityBufferOffset
		binary.LittleEndian.PutUint16(buf[14:16], 0x0300) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (SessionSetupRequestDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("TreeConnectRequest", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], 9) // StructureSize
		// 65216 + 768 = 65984 wraps to 448 in uint16.
		binary.LittleEndian.PutUint16(buf[4:6], 0xFF00) // PathOffset
		binary.LittleEndian.PutUint16(buf[6:8], 0x0300) // PathLength

		call(t, "Path", func() {
			if got := (TreeConnectRequestDecoder)(buf).Path(); got != "" {
				t.Errorf("Path() = %q, want \"\"", got)
			}
		})
	})

	t.Run("QueryDirectoryRequest", func(t *testing.T) {
		buf := make([]byte, 32)
		binary.LittleEndian.PutUint16(buf[0:2], 33) // StructureSize
		// 65216 + 768 = 65984 wraps to 448 in uint16.
		binary.LittleEndian.PutUint16(buf[24:26], 0xFF00) // FileNameOffset
		binary.LittleEndian.PutUint16(buf[26:28], 0x0300) // FileNameLength

		call(t, "FileName", func() {
			if got := (QueryDirectoryRequestDecoder)(buf).FileName(); got != "" {
				t.Errorf("FileName() = %q, want \"\"", got)
			}
		})
	})
}

// The offset need not wrap to panic: a plain offset+length beyond the end of
// the packet must also be rejected safely.
func TestRequestDecodersSafeAccessorsOnOutOfRangeBuffers(t *testing.T) {
	t.Run("SessionSetupRequest", func(t *testing.T) {
		buf := make([]byte, 24)
		binary.LittleEndian.PutUint16(buf[0:2], 25)       // StructureSize
		binary.LittleEndian.PutUint16(buf[12:14], 88)     // SecurityBufferOffset (64+24)
		binary.LittleEndian.PutUint16(buf[14:16], 0xFFFF) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (SessionSetupRequestDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("TreeConnectRequest", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], 9)      // StructureSize
		binary.LittleEndian.PutUint16(buf[4:6], 72)     // PathOffset (64+8)
		binary.LittleEndian.PutUint16(buf[6:8], 0xFFFF) // PathLength

		call(t, "Path", func() {
			if got := (TreeConnectRequestDecoder)(buf).Path(); got != "" {
				t.Errorf("Path() = %q, want \"\"", got)
			}
		})
	})

	t.Run("QueryDirectoryRequest", func(t *testing.T) {
		buf := make([]byte, 32)
		binary.LittleEndian.PutUint16(buf[0:2], 33)       // StructureSize
		binary.LittleEndian.PutUint16(buf[24:26], 96)     // FileNameOffset (64+32)
		binary.LittleEndian.PutUint16(buf[26:28], 0xFFFF) // FileNameLength

		call(t, "FileName", func() {
			if got := (QueryDirectoryRequestDecoder)(buf).FileName(); got != "" {
				t.Errorf("FileName() = %q, want \"\"", got)
			}
		})
	})
}

// A well-formed request must still yield the declared buffer.
func TestRequestDecodersAccessorsOnWellFormedBuffers(t *testing.T) {
	t.Run("SessionSetupRequest", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint16(buf[0:2], 25)   // StructureSize
		binary.LittleEndian.PutUint16(buf[12:14], 88) // SecurityBufferOffset (64+24)
		binary.LittleEndian.PutUint16(buf[14:16], 4)  // SecurityBufferLength
		copy(buf[24:], []byte{0xde, 0xad, 0xbe, 0xef})

		if got := (SessionSetupRequestDecoder)(buf).SecurityBuffer(); string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("SecurityBuffer() = %v, want the declared 4-byte buffer", got)
		}
	})

	t.Run("TreeConnectRequest", func(t *testing.T) {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], 9)  // StructureSize
		binary.LittleEndian.PutUint16(buf[4:6], 72) // PathOffset (64+8)
		binary.LittleEndian.PutUint16(buf[6:8], 8)  // PathLength
		copy(buf[8:], []byte{0x2f, 0x00, 0x61, 0x00, 0x2f, 0x00, 0x62, 0x00})

		if got := (TreeConnectRequestDecoder)(buf).Path(); got != "/a/b" {
			t.Errorf("Path() = %q, want \"/a/b\"", got)
		}
	})

	t.Run("QueryDirectoryRequest", func(t *testing.T) {
		buf := make([]byte, 42)
		binary.LittleEndian.PutUint16(buf[0:2], 33)   // StructureSize
		binary.LittleEndian.PutUint16(buf[24:26], 96) // FileNameOffset (64+32)
		binary.LittleEndian.PutUint16(buf[26:28], 10) // FileNameLength
		copy(buf[32:], []byte{0x2a, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00})

		if got := (QueryDirectoryRequestDecoder)(buf).FileName(); got != "*.txt" {
			t.Errorf("FileName() = %q, want \"*.txt\"", got)
		}
	})
}

// A well-formed request must still be accepted — the widened bounds must
// reject what does not fit, not everything.
func TestRequestDecodersAcceptWellFormedRequests(t *testing.T) {
	t.Run("SessionSetupRequest", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint16(buf[0:2], 25)   // StructureSize
		binary.LittleEndian.PutUint16(buf[12:14], 88) // SecurityBufferOffset (64+24)
		binary.LittleEndian.PutUint16(buf[14:16], 4)  // SecurityBufferLength

		if d := (SessionSetupRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed session setup request was rejected")
		}

		// One byte short of the declared buffer must still be rejected.
		short := buf[:27]
		if d := (SessionSetupRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated session setup request was accepted")
		}
	})

	t.Run("TreeConnectRequest", func(t *testing.T) {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], 9)  // StructureSize
		binary.LittleEndian.PutUint16(buf[4:6], 72) // PathOffset (64+8)
		binary.LittleEndian.PutUint16(buf[6:8], 8)  // PathLength

		if d := (TreeConnectRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed tree connect request was rejected")
		}

		short := buf[:15]
		if d := (TreeConnectRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated tree connect request was accepted")
		}
	})

	t.Run("CreateRequest", func(t *testing.T) {
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint16(buf[0:2], 57)    // StructureSize
		binary.LittleEndian.PutUint16(buf[44:46], 120) // NameOffset (64+56)
		binary.LittleEndian.PutUint16(buf[46:48], 8)   // NameLength

		if d := (CreateRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed create request was rejected")
		}

		short := buf[:63]
		if d := (CreateRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated create request was accepted")
		}
	})

	t.Run("ReadRequest", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// No read channel info: offset and length are both zero.

		if d := (ReadRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed read request was rejected")
		}
	})

	t.Run("WriteRequest", func(t *testing.T) {
		buf := make([]byte, 56)
		binary.LittleEndian.PutUint16(buf[0:2], 49)  // StructureSize
		binary.LittleEndian.PutUint16(buf[2:4], 112) // DataOffset (64+48)
		binary.LittleEndian.PutUint32(buf[4:8], 8)   // Length

		if d := (WriteRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed write request was rejected")
		}

		short := buf[:55]
		if d := (WriteRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated write request was accepted")
		}
	})

	t.Run("IoctlRequest", func(t *testing.T) {
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint16(buf[0:2], 57)    // StructureSize
		binary.LittleEndian.PutUint32(buf[24:28], 120) // InputOffset (64+56)
		binary.LittleEndian.PutUint32(buf[28:32], 8)   // InputCount

		if d := (IoctlRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed ioctl request was rejected")
		}

		short := buf[:63]
		if d := (IoctlRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated ioctl request was accepted")
		}
	})

	t.Run("QueryDirectoryRequest", func(t *testing.T) {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint16(buf[0:2], 33)   // StructureSize
		binary.LittleEndian.PutUint16(buf[24:26], 96) // FileNameOffset (64+32)
		binary.LittleEndian.PutUint16(buf[26:28], 8)  // FileNameLength

		if d := (QueryDirectoryRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed query directory request was rejected")
		}

		short := buf[:39]
		if d := (QueryDirectoryRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated query directory request was accepted")
		}
	})

	t.Run("QueryInfoRequest", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 41)   // StructureSize
		binary.LittleEndian.PutUint16(buf[8:10], 104) // InputBufferOffset (64+40)
		binary.LittleEndian.PutUint32(buf[12:16], 8)  // InputBufferLength

		if d := (QueryInfoRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed query info request was rejected")
		}

		short := buf[:47]
		if d := (QueryInfoRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated query info request was accepted")
		}
	})

	t.Run("SetInfoRequest", func(t *testing.T) {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint16(buf[0:2], 33)  // StructureSize
		binary.LittleEndian.PutUint32(buf[4:8], 8)   // BufferLength
		binary.LittleEndian.PutUint16(buf[8:10], 96) // BufferOffset (64+32)

		if d := (SetInfoRequestDecoder)(buf); d.IsInvalid() {
			t.Error("a well-formed set info request was rejected")
		}

		short := buf[:39]
		if d := (SetInfoRequestDecoder)(short); !d.IsInvalid() {
			t.Error("a truncated set info request was accepted")
		}
	})
}
