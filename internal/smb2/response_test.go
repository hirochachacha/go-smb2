package smb2

import (
	"encoding/binary"
	"testing"
)

// The response decoders slice variable-length buffers with the offset and
// length read straight off the wire in narrow unsigned types (uint16 or
// uint32). The addition off+len is computed in that same narrow type, so it
// can wrap around, and off itself can point past the end of the packet.
// Either way the slice expression panics on a hostile peer's packet.
//
// The accessors must therefore convert both values to int and bounds-check
// them before slicing, returning nil (or "") instead of panicking.

// call recovers a panic from fn and reports it as a test failure.
func call(t *testing.T, name string, fn func()) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()

	fn()
}

func TestResponseDecodersSafeAccessorsOnWrappingBuffers(t *testing.T) {
	t.Run("SessionSetupResponse", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], 9) // StructureSize
		// 65216 + 768 = 65984 wraps to 448 in uint16.
		binary.LittleEndian.PutUint16(buf[4:6], 0xFF00) // SecurityBufferOffset
		binary.LittleEndian.PutUint16(buf[6:8], 0x0300) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (SessionSetupResponseDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("NegotiateResponse", func(t *testing.T) {
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint16(buf[0:2], 65) // StructureSize
		// 65216 + 768 = 65984 wraps to 448 in uint16.
		binary.LittleEndian.PutUint16(buf[56:58], 0xFF00) // SecurityBufferOffset
		binary.LittleEndian.PutUint16(buf[58:60], 0x0300) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (NegotiateResponseDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("CreateResponse", func(t *testing.T) {
		buf := make([]byte, 88)
		binary.LittleEndian.PutUint16(buf[0:2], 89) // StructureSize
		// 136 + 0xFFFFFFFF wraps to 135 in uint32, below the slice start.
		binary.LittleEndian.PutUint32(buf[80:84], 200)        // CreateContextsOffset
		binary.LittleEndian.PutUint32(buf[84:88], 0xFFFFFFFF) // CreateContextsLength

		call(t, "CreateContexts", func() {
			if got := (CreateResponseDecoder)(buf).CreateContexts(); got != nil {
				t.Errorf("CreateContexts() = %v, want nil", got)
			}
		})
	})

	t.Run("IoctlResponse/input", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// 64 + 0xFFFFFFF0 wraps to 48 in uint32, below the slice start.
		binary.LittleEndian.PutUint32(buf[24:28], 0x80)       // InputOffset
		binary.LittleEndian.PutUint32(buf[28:32], 0xFFFFFFF0) // InputCount

		call(t, "Input", func() {
			if got := (IoctlResponseDecoder)(buf).Input(); got != nil {
				t.Errorf("Input() = %v, want nil", got)
			}
		})
	})

	t.Run("IoctlResponse/output", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
		// 64 + 0xFFFFFFF0 wraps to 48 in uint32, below the slice start.
		binary.LittleEndian.PutUint32(buf[32:36], 0x80)       // OutputOffset
		binary.LittleEndian.PutUint32(buf[36:40], 0xFFFFFFF0) // OutputCount

		call(t, "Output", func() {
			if got := (IoctlResponseDecoder)(buf).Output(); got != nil {
				t.Errorf("Output() = %v, want nil", got)
			}
		})
	})
}

// The offset need not wrap to panic: a plain offset+length beyond the end of
// the packet must also be rejected safely.
func TestResponseDecodersSafeAccessorsOnOutOfRangeBuffers(t *testing.T) {
	t.Run("SessionSetupResponse", func(t *testing.T) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], 9)      // StructureSize
		binary.LittleEndian.PutUint16(buf[4:6], 72)     // SecurityBufferOffset (64+8)
		binary.LittleEndian.PutUint16(buf[6:8], 0xFFFF) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (SessionSetupResponseDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("NegotiateResponse", func(t *testing.T) {
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint16(buf[0:2], 65)       // StructureSize
		binary.LittleEndian.PutUint16(buf[56:58], 128)    // SecurityBufferOffset (64+64)
		binary.LittleEndian.PutUint16(buf[58:60], 0xFFFF) // SecurityBufferLength

		call(t, "SecurityBuffer", func() {
			if got := (NegotiateResponseDecoder)(buf).SecurityBuffer(); got != nil {
				t.Errorf("SecurityBuffer() = %v, want nil", got)
			}
		})
	})

	t.Run("CreateResponse", func(t *testing.T) {
		buf := make([]byte, 88)
		binary.LittleEndian.PutUint16(buf[0:2], 89)       // StructureSize
		binary.LittleEndian.PutUint32(buf[80:84], 152)    // CreateContextsOffset (64+88)
		binary.LittleEndian.PutUint32(buf[84:88], 0xFFFF) // CreateContextsLength

		call(t, "CreateContexts", func() {
			if got := (CreateResponseDecoder)(buf).CreateContexts(); got != nil {
				t.Errorf("CreateContexts() = %v, want nil", got)
			}
		})
	})

	t.Run("IoctlResponse/input", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49)       // StructureSize
		binary.LittleEndian.PutUint32(buf[24:28], 112)    // InputOffset (64+48)
		binary.LittleEndian.PutUint32(buf[28:32], 0xFFFF) // InputCount

		call(t, "Input", func() {
			if got := (IoctlResponseDecoder)(buf).Input(); got != nil {
				t.Errorf("Input() = %v, want nil", got)
			}
		})
	})

	t.Run("IoctlResponse/output", func(t *testing.T) {
		buf := make([]byte, 48)
		binary.LittleEndian.PutUint16(buf[0:2], 49)       // StructureSize
		binary.LittleEndian.PutUint32(buf[32:36], 112)    // OutputOffset (64+48)
		binary.LittleEndian.PutUint32(buf[36:40], 0xFFFF) // OutputCount

		call(t, "Output", func() {
			if got := (IoctlResponseDecoder)(buf).Output(); got != nil {
				t.Errorf("Output() = %v, want nil", got)
			}
		})
	})
}

// ErrorResponse.Encode must write the ErrorData size as a uint32 into
// ByteCount (offset 4), not as a uint16 into the ErrorContextCount area
// (offset 2), so that a round trip through ErrorResponseDecoder restores
// the original payload.
func TestErrorResponse_EncodeDecode(t *testing.T) {
	t.Run("SmallBufferErrorResponse", func(t *testing.T) {
		c := &ErrorResponse{
			ErrorData: &SmallBufferErrorResponse{
				RequiredBufferLength: 0x01020304,
			},
		}

		pkt := make([]byte, c.Size())
		c.Encode(pkt)

		r := ErrorResponseDecoder(pkt[64:])
		if r.IsInvalid() {
			t.Fatal("ErrorResponseDecoder.IsInvalid() = true, want false")
		}

		want := uint32(c.ErrorData.Size())
		if got := r.ByteCount(); got != want {
			t.Errorf("ByteCount() = %d, want %d", got, want)
		}

		data := r.ErrorData()
		if len(data) != int(want) {
			t.Fatalf("len(ErrorData()) = %d, want %d", len(data), want)
		}

		d := SmallBufferErrorResponseDecoder(data)
		if d.IsInvalid() {
			t.Fatal("SmallBufferErrorResponseDecoder.IsInvalid() = true, want false")
		}
		if got := d.RequiredBufferLength(); got != 0x01020304 {
			t.Errorf("RequiredBufferLength() = %#x, want %#x", got, 0x01020304)
		}
	})

	t.Run("SymbolicLinkErrorResponse", func(t *testing.T) {
		c := &ErrorResponse{
			ErrorData: &SymbolicLinkErrorResponse{
				UnparsedPathLength: 8,
				Flags:              0x1,
				SubstituteName:     "\\??\\UNC\\host\\share",
				PrintName:          "\\\\host\\share",
			},
		}

		pkt := make([]byte, c.Size())
		c.Encode(pkt)

		r := ErrorResponseDecoder(pkt[64:])
		if r.IsInvalid() {
			t.Fatal("ErrorResponseDecoder.IsInvalid() = true, want false")
		}

		want := uint32(c.ErrorData.Size())
		if got := r.ByteCount(); got != want {
			t.Errorf("ByteCount() = %d, want %d", got, want)
		}

		data := r.ErrorData()
		if len(data) != int(want) {
			t.Fatalf("len(ErrorData()) = %d, want %d", len(data), want)
		}

		d := SymbolicLinkErrorResponseDecoder(data)
		if d.IsInvalid() {
			t.Fatal("SymbolicLinkErrorResponseDecoder.IsInvalid() = true, want false")
		}
		if got := d.SubstituteName(); got != "\\??\\UNC\\host\\share" {
			t.Errorf("SubstituteName() = %q, want %q", got, "\\??\\UNC\\host\\share")
		}
		if got := d.PrintName(); got != "\\\\host\\share" {
			t.Errorf("PrintName() = %q, want %q", got, "\\\\host\\share")
		}
	})
}

// A well-formed response must still yield the declared buffer.
func TestResponseDecodersAccessorsOnWellFormedBuffers(t *testing.T) {
	t.Run("SessionSetupResponse", func(t *testing.T) {
		buf := make([]byte, 12)
		binary.LittleEndian.PutUint16(buf[0:2], 9)  // StructureSize
		binary.LittleEndian.PutUint16(buf[4:6], 72) // SecurityBufferOffset (64+8)
		binary.LittleEndian.PutUint16(buf[6:8], 4)  // SecurityBufferLength
		copy(buf[8:], []byte{0xde, 0xad, 0xbe, 0xef})

		if got := (SessionSetupResponseDecoder)(buf).SecurityBuffer(); string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("SecurityBuffer() = %v, want the declared 4-byte buffer", got)
		}
	})

	t.Run("NegotiateResponse", func(t *testing.T) {
		buf := make([]byte, 68)
		binary.LittleEndian.PutUint16(buf[0:2], 65)    // StructureSize
		binary.LittleEndian.PutUint16(buf[56:58], 128) // SecurityBufferOffset (64+64)
		binary.LittleEndian.PutUint16(buf[58:60], 4)   // SecurityBufferLength
		copy(buf[64:], []byte{0xde, 0xad, 0xbe, 0xef})

		if got := (NegotiateResponseDecoder)(buf).SecurityBuffer(); string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("SecurityBuffer() = %v, want the declared 4-byte buffer", got)
		}
	})

	t.Run("CreateResponse", func(t *testing.T) {
		buf := make([]byte, 96)
		binary.LittleEndian.PutUint16(buf[0:2], 89)    // StructureSize
		binary.LittleEndian.PutUint32(buf[80:84], 152) // CreateContextsOffset (64+88)
		binary.LittleEndian.PutUint32(buf[84:88], 8)   // CreateContextsLength
		copy(buf[88:], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00})

		if got := (CreateResponseDecoder)(buf).CreateContexts(); len(got) != 8 {
			t.Errorf("CreateContexts() = %v, want the declared 8-byte buffer", got)
		}
	})

	t.Run("IoctlResponse", func(t *testing.T) {
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint16(buf[0:2], 49)    // StructureSize
		binary.LittleEndian.PutUint32(buf[24:28], 112) // InputOffset (64+48)
		binary.LittleEndian.PutUint32(buf[28:32], 4)   // InputCount
		binary.LittleEndian.PutUint32(buf[32:36], 116) // OutputOffset (64+48+4)
		binary.LittleEndian.PutUint32(buf[36:40], 4)   // OutputCount
		copy(buf[48:], []byte{0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce})

		d := (IoctlResponseDecoder)(buf)
		if got := d.Input(); string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("Input() = %v, want the declared 4-byte buffer", got)
		}
		if got := d.Output(); string(got) != string([]byte{0xfe, 0xed, 0xfa, 0xce}) {
			t.Errorf("Output() = %v, want the declared 4-byte buffer", got)
		}
	})
}
