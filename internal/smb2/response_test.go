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
		binary.LittleEndian.PutUint32(buf[32:36], 120) // OutputOffset (64+48+4, rounded up)
		binary.LittleEndian.PutUint32(buf[36:40], 4)   // OutputCount
		copy(buf[48:52], []byte{0xde, 0xad, 0xbe, 0xef})
		copy(buf[56:60], []byte{0xfe, 0xed, 0xfa, 0xce})

		d := (IoctlResponseDecoder)(buf)
		if d.IsInvalid() {
			t.Fatal("IoctlResponseDecoder.IsInvalid() = true, want false")
		}
		if got := d.Input(); string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("Input() = %v, want the declared 4-byte buffer", got)
		}
		if got := d.Output(); string(got) != string([]byte{0xfe, 0xed, 0xfa, 0xce}) {
			t.Errorf("Output() = %v, want the declared 4-byte buffer", got)
		}
	})
}

func TestIoctlResponseDecoderPayloadValidation(t *testing.T) {
	tests := []struct {
		name         string
		inputOffset  uint32
		inputCount   uint32
		outputOffset uint32
		outputCount  uint32
		length       int
		invalid      bool
	}{
		{
			name:         "non-empty input in fixed part",
			inputOffset:  111,
			inputCount:   1,
			outputOffset: 0,
			length:       49,
			invalid:      true,
		},
		{
			name:        "non-empty input past packet end",
			inputOffset: 112,
			inputCount:  2,
			length:      49,
			invalid:     true,
		},
		{
			name:         "non-empty output in fixed part",
			outputOffset: 1,
			outputCount:  1,
			length:       49,
			invalid:      true,
		},
		{
			name:         "non-empty output past packet end",
			outputOffset: 112,
			outputCount:  2,
			length:       49,
			invalid:      true,
		},
		{
			name:         "output overlaps input",
			inputOffset:  112,
			inputCount:   4,
			outputOffset: 112,
			outputCount:  1,
			length:       53,
			invalid:      true,
		},
		{
			name:         "output is not aligned after input",
			inputOffset:  112,
			inputCount:   4,
			outputOffset: 116,
			outputCount:  1,
			length:       57,
			invalid:      true,
		},
		{
			name:         "non-empty output",
			inputOffset:  112,
			outputOffset: 112,
			outputCount:  1,
			length:       49,
		},
		{
			name:         "input and output with alignment padding",
			inputOffset:  112,
			inputCount:   4,
			outputOffset: 120,
			outputCount:  4,
			length:       60,
		},
		{
			name:         "empty output offset is advisory",
			inputOffset:  112,
			inputCount:   4,
			outputOffset: 1,
			outputCount:  0,
			length:       52,
		},
		{name: "unaligned input is legal", inputOffset: 113, inputCount: 2, outputOffset: 120, outputCount: 1, length: 57},
		{name: "empty input still determines output position", inputOffset: 120, outputOffset: 120, outputCount: 1, length: 57},
		{name: "incorrect output position with empty input", inputOffset: 120, outputOffset: 112, outputCount: 1, length: 57, invalid: true},
		{name: "empty offsets are advisory", inputOffset: ^uint32(0), outputOffset: ^uint32(0), length: 49},
		{name: "input range overflow", inputOffset: ^uint32(0), inputCount: 2, length: 49, invalid: true},
		{name: "output rounding overflow", inputOffset: ^uint32(0), outputOffset: 112, outputCount: 1, length: 49, invalid: true},
		{
			name:   "empty response",
			length: 49,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := make([]byte, test.length)
			binary.LittleEndian.PutUint16(buf[0:2], 49) // StructureSize
			binary.LittleEndian.PutUint32(buf[24:28], test.inputOffset)
			binary.LittleEndian.PutUint32(buf[28:32], test.inputCount)
			binary.LittleEndian.PutUint32(buf[32:36], test.outputOffset)
			binary.LittleEndian.PutUint32(buf[36:40], test.outputCount)

			if got := (IoctlResponseDecoder)(buf).IsInvalid(); got != test.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, test.invalid)
			}
		})
	}
}

type ioctlResponseTestEncoder []byte

func (e ioctlResponseTestEncoder) Size() int { return len(e) }

func (e ioctlResponseTestEncoder) Encode(dst []byte) { copy(dst, e) }

func TestIoctlResponseEncodeAlignsOutput(t *testing.T) {
	res := &IoctlResponse{
		Input:  ioctlResponseTestEncoder{0xde, 0xad, 0xbe, 0xef},
		Output: ioctlResponseTestEncoder{0xfe, 0xed, 0xfa, 0xce},
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)

	d := IoctlResponseDecoder(pkt[64:])
	if d.IsInvalid() {
		t.Fatal("IoctlResponseDecoder.IsInvalid() = true, want false")
	}
	if d.InputOffset() != 112 || d.OutputOffset() != 120 {
		t.Errorf("InputOffset() = %d, OutputOffset() = %d, want 112 and 120", d.InputOffset(), d.OutputOffset())
	}
}

func TestReadResponseDecoder(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		buf := make([]byte, 16+10)
		binary.LittleEndian.PutUint16(buf[0:2], 17) // StructureSize
		buf[2] = 80                                 // DataOffset (64+16)
		binary.LittleEndian.PutUint32(buf[4:8], 10) // DataLength

		d := ReadResponseDecoder(buf)
		if d.IsInvalidHeader() {
			t.Error("IsInvalidHeader() = true, want false")
		}
		if d.IsInvalidPayload() {
			t.Error("IsInvalidPayload() = true, want false")
		}
		if d.IsInvalid() {
			t.Error("IsInvalid() = true, want false")
		}
	})

	t.Run("invalid header structure size", func(t *testing.T) {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], 18) // wrong StructureSize
		buf[2] = 80

		d := ReadResponseDecoder(buf)
		if !d.IsInvalidHeader() {
			t.Error("IsInvalidHeader() = false, want true")
		}
		if !d.IsInvalid() {
			t.Error("IsInvalid() = false, want true")
		}
	})

	t.Run("invalid header data offset", func(t *testing.T) {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], 17)
		buf[2] = 79 // DataOffset < 80

		d := ReadResponseDecoder(buf)
		if !d.IsInvalidHeader() {
			t.Error("IsInvalidHeader() = false, want true")
		}
		if !d.IsInvalid() {
			t.Error("IsInvalid() = false, want true")
		}
	})

	t.Run("valid header but incomplete data", func(t *testing.T) {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:2], 17)
		buf[2] = 80
		binary.LittleEndian.PutUint32(buf[4:8], 10) // 10 bytes declared, 0 present

		d := ReadResponseDecoder(buf)
		if d.IsInvalidHeader() {
			t.Error("IsInvalidHeader() = true, want false")
		}
		if !d.IsInvalidPayload() {
			t.Error("IsInvalidPayload() = false, want true")
		}
		if !d.IsInvalid() {
			t.Error("IsInvalid() = false, want true")
		}
	})
}
