package smb2

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestLockResponseDecoder(t *testing.T) {
	res := &LockResponse{}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	if d := LockResponseDecoder(pkt[64:]); d.IsInvalid() {
		t.Fatal("a well-formed lock response was rejected")
	}

	bad := pkt[64:]
	binary.LittleEndian.PutUint16(bad[:2], 5)
	if d := LockResponseDecoder(bad); !d.IsInvalid() {
		t.Fatal("invalid lock response structure size was accepted")
	}
}

func TestChangeNotifyResponseDecoderBounds(t *testing.T) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint16(buf[0:2], 9)
	binary.LittleEndian.PutUint16(buf[2:4], 72)
	binary.LittleEndian.PutUint32(buf[4:8], 4)
	copy(buf[8:], []byte("test"))

	r := ChangeNotifyResponseDecoder(buf)
	if r.IsInvalid() || string(r.OutputBuffer()) != "test" {
		t.Fatalf("valid CHANGE_NOTIFY response was rejected: invalid=%v output=%q", r.IsInvalid(), r.OutputBuffer())
	}

	cases := []struct {
		name   string
		offset uint16
		length uint32
		valid  bool
	}{
		{"empty response", 0, 0, true},
		{"offset before fixed fields", 71, 1, false},
		{"length beyond command", 72, 5, false},
		{"offset beyond command", 80, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 12)
			binary.LittleEndian.PutUint16(b[0:2], 9)
			binary.LittleEndian.PutUint16(b[2:4], tc.offset)
			binary.LittleEndian.PutUint32(b[4:8], tc.length)
			if got := !ChangeNotifyResponseDecoder(b).IsInvalid(); got != tc.valid {
				t.Fatalf("valid=%v, want %v", got, tc.valid)
			}
		})
	}
}

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

	t.Run("SymbolicLinkErrorResponse", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint32(buf[0:4], 24)        // SymLinkLength
		binary.LittleEndian.PutUint32(buf[4:8], 0x4c4d5953) // SymLinkErrorTag
		binary.LittleEndian.PutUint32(buf[8:12], IO_REPARSE_TAG_SYMLINK)
		binary.LittleEndian.PutUint16(buf[12:14], 12)      // ReparseDataLength
		binary.LittleEndian.PutUint16(buf[16:18], 0)       // SubstituteNameOffset
		binary.LittleEndian.PutUint16(buf[18:20], 100)     // SubstituteNameLength (out of range)
		binary.LittleEndian.PutUint16(buf[20:22], 0)       // PrintNameOffset
		binary.LittleEndian.PutUint16(buf[22:24], 100)     // PrintNameLength (out of range)

		d := SymbolicLinkErrorResponseDecoder(buf)
		call(t, "SubstituteName", func() {
			if got := d.SubstituteName(); got != "" {
				t.Errorf("SubstituteName() = %q, want empty", got)
			}
		})
		call(t, "PrintName", func() {
			if got := d.PrintName(); got != "" {
				t.Errorf("PrintName() = %q, want empty", got)
			}
		})
	})
}

func TestSymbolicLinkErrorResponseDecoder_Overflow32Bit(t *testing.T) {
	// Craft a payload with a large SymLinkLength (e.g. 0x7ffffff0 or 0xfffffffe)
	// that would wrap 4 + tlen on 32-bit systems if evaluated as int.
	for _, symLinkLen := range []uint32{0x7ffffff0, 0x7ffffffe, 0xfffffffe} {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint32(buf[0:4], symLinkLen)
		binary.LittleEndian.PutUint32(buf[4:8], 0x4c4d5953) // SymLinkErrorTag
		binary.LittleEndian.PutUint32(buf[8:12], IO_REPARSE_TAG_SYMLINK)
		binary.LittleEndian.PutUint16(buf[12:14], 20)      // ReparseDataLength
		binary.LittleEndian.PutUint16(buf[16:18], 0)       // SubstituteNameOffset
		binary.LittleEndian.PutUint16(buf[18:20], 4)        // SubstituteNameLength
		binary.LittleEndian.PutUint16(buf[20:22], 4)        // PrintNameOffset
		binary.LittleEndian.PutUint16(buf[22:24], 4)        // PrintNameLength

		d := SymbolicLinkErrorResponseDecoder(buf)
		if !d.IsInvalid() {
			t.Errorf("IsInvalid() for SymLinkLength 0x%x = false, want true", symLinkLen)
		}
		// Slicing must not panic even on invalid/short buffer.
		_ = d.SubstituteName()
		_ = d.PrintName()
	}
}

func TestSymbolicLinkErrorResponseDecoderRejectsOddLengths(t *testing.T) {
	response := &SymbolicLinkErrorResponse{
		SubstituteName: "target",
		PrintName:      "target",
	}
	buf := make([]byte, response.Size())
	response.Encode(buf)
	if d := SymbolicLinkErrorResponseDecoder(buf); d.IsInvalid() {
		t.Fatal("well-formed symbolic link error response was rejected")
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"UnparsedPathLength", func(b []byte) { binary.LittleEndian.PutUint16(b[14:16], 1) }},
		{"SubstituteNameLength", func(b []byte) { binary.LittleEndian.PutUint16(b[18:20], 1) }},
		{"PrintNameLength", func(b []byte) { binary.LittleEndian.PutUint16(b[22:24], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), buf...)
			tc.mutate(bad)
			if !SymbolicLinkErrorResponseDecoder(bad).IsInvalid() {
				t.Fatal("odd symbolic link length was accepted")
			}
		})
	}
}

func TestSymbolicLinkErrorResponseDecoderAcceptsValidUnicodeLengths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unparsed   uint16
		substitute string
		printName  string
	}{
		{name: "zero lengths"},
		{name: "names end at buffer", unparsed: 2, substitute: "target", printName: "display"},
		{name: "surrogate pair", substitute: "😀", printName: "😀"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &SymbolicLinkErrorResponse{
				UnparsedPathLength: tc.unparsed,
				SubstituteName:     tc.substitute,
				PrintName:          tc.printName,
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			d := SymbolicLinkErrorResponseDecoder(buf)
			if d.IsInvalid() {
				t.Fatal("valid symbolic link error response was rejected")
			}
			if got := d.SubstituteName(); got != tc.substitute {
				t.Errorf("SubstituteName() = %q, want %q", got, tc.substitute)
			}
			if got := d.PrintName(); got != tc.printName {
				t.Errorf("PrintName() = %q, want %q", got, tc.printName)
			}
		})
	}
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

func TestSymbolicLinkErrorResponseLengthsExcludeTrailingBytes(t *testing.T) {
	for _, target := range []string{"target.txt", "リンク先.txt"} {
		for _, withContexts := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/contexts=%t", target, withContexts), func(t *testing.T) {
				link := &SymbolicLinkErrorResponse{
					Flags:          SYMLINK_FLAG_RELATIVE,
					SubstituteName: target,
					PrintName:      target,
				}
				res := &ErrorResponse{ErrorData: link}
				if withContexts {
					res.ErrorData = ErrorContextListResponse{
						{ErrorData: link},
						{ErrorData: &SmallBufferErrorResponse{RequiredBufferLength: 4096}},
					}
				}
				pkt := make([]byte, Roundup(res.Size(), 8))
				if len(pkt) == res.Size() {
					t.Fatal("test requires compound padding")
				}
				res.Encode(pkt)
				payload := ErrorResponseDecoder(pkt[64:]).ErrorData()
				if withContexts {
					payload = ErrorContextResponseDecoder(payload).ErrorContextData()
				}
				linkResponse := SymbolicLinkErrorResponseDecoder(payload)
				if got, want := int(linkResponse.SymLinkLength()), len(payload)-4; got != want {
					t.Errorf("SymLinkLength() = %d, want %d", got, want)
				}
				if got, want := int(linkResponse.ReparseDataLength()), len(payload)-16; got != want {
					t.Errorf("ReparseDataLength() = %d, want %d", got, want)
				}
				if linkResponse.IsInvalid() {
					t.Fatal("symbolic link response is invalid")
				}
				if linkResponse.SubstituteName() != target || linkResponse.PrintName() != target {
					t.Fatal("symbolic link names did not round trip")
				}
			})
		}
	}
}

func TestNegotiateResponseDecoderSMB311Layout(t *testing.T) {
	makePayload := func(packetLength int, securityOffset, securityLength uint16, contextOffset uint32) []byte {
		payload := make([]byte, packetLength-64)
		binary.LittleEndian.PutUint16(payload[0:2], 65) // StructureSize
		binary.LittleEndian.PutUint16(payload[4:6], SMB311)
		binary.LittleEndian.PutUint16(payload[56:58], securityOffset)
		binary.LittleEndian.PutUint16(payload[58:60], securityLength)
		binary.LittleEndian.PutUint32(payload[60:64], contextOffset)
		return payload
	}

	tests := []struct {
		name                   string
		packetLength           int
		securityBufferOffset   uint16
		securityBufferLength   uint16
		negotiateContextOffset uint32
		invalid                bool
	}{
		{
			name:                   "context offset in fixed response",
			packetLength:           128,
			negotiateContextOffset: 72,
			invalid:                true,
		},
		{
			name:                   "security buffer starts inside fixed response",
			packetLength:           136,
			securityBufferOffset:   120,
			securityBufferLength:   8,
			negotiateContextOffset: 128,
			invalid:                true,
		},
		{
			name:                   "context overlaps non-empty security buffer",
			packetLength:           152,
			securityBufferOffset:   128,
			securityBufferLength:   16,
			negotiateContextOffset: 136,
			invalid:                true,
		},
		{
			name:                   "security buffer extends past packet",
			packetLength:           136,
			securityBufferOffset:   128,
			securityBufferLength:   9,
			negotiateContextOffset: 136,
			invalid:                true,
		},
		{
			name:                   "context offset extends past packet",
			packetLength:           128,
			negotiateContextOffset: 136,
			invalid:                true,
		},
		{
			name:                   "context offset is not aligned",
			packetLength:           136,
			negotiateContextOffset: 130,
			invalid:                true,
		},
		{
			name:                   "empty security buffer",
			packetLength:           128,
			negotiateContextOffset: 128,
		},
		{
			name:                   "empty security buffer ignores its offset",
			packetLength:           128,
			securityBufferOffset:   0xffff,
			negotiateContextOffset: 128,
		},
		{
			name:                   "non-empty security buffer",
			packetLength:           136,
			securityBufferOffset:   128,
			securityBufferLength:   4,
			negotiateContextOffset: 136,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := makePayload(test.packetLength, test.securityBufferOffset, test.securityBufferLength, test.negotiateContextOffset)
			if got := (NegotiateResponseDecoder)(payload).IsInvalid(); got != test.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, test.invalid)
			}
		})
	}
}

func TestNegotiateResponseDecoderAcceptsContextWithoutTrailingPadding(t *testing.T) {
	response := &NegotiateResponse{
		DialectRevision: SMB311,
		SystemTime:      &Filetime{},
		ServerStartTime: &Filetime{},
		Contexts: []Encoder{
			&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: make([]byte, 32)},
		},
	}
	pkt := make([]byte, response.Size())
	response.Encode(pkt)

	if len(pkt)%8 == 0 {
		t.Fatal("test response unexpectedly includes trailing context padding")
	}
	if d := NegotiateResponseDecoder(pkt[64:]); d.IsInvalid() {
		t.Fatal("NegotiateResponseDecoder.IsInvalid() = true, want false")
	}
}

func TestNegotiateContextDecoderDataLengthBounds(t *testing.T) {
	for _, dataLength := range []uint16{0, 65527, 65528, 65535} {
		t.Run(fmt.Sprintf("DataLength-%d", dataLength), func(t *testing.T) {
			const trailing = 8
			buf := make([]byte, 8+int(dataLength)+trailing)
			binary.LittleEndian.PutUint16(buf[0:2], SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
			binary.LittleEndian.PutUint16(buf[2:4], dataLength)
			for i := 0; i < int(dataLength); i++ {
				buf[8+i] = byte(i)
			}
			for i := 8 + int(dataLength); i < len(buf); i++ {
				buf[i] = 0xff
			}

			ctx := NegotiateContextDecoder(buf)
			if ctx.IsInvalid() {
				t.Fatal("IsInvalid() = true, want false")
			}
			data := ctx.Data()
			if len(data) != int(dataLength) {
				t.Fatalf("len(Data()) = %d, want %d", len(data), dataLength)
			}
			if dataLength > 0 {
				if got, want := data[0], byte(0); got != want {
					t.Errorf("Data()[0] = %#x, want %#x", got, want)
				}
				if got, want := data[len(data)-1], byte(int(dataLength)-1); got != want {
					t.Errorf("Data()[last] = %#x, want %#x", got, want)
				}
			}
		})
	}
}

func TestNegotiateContextDecoderRejectsTruncatedData(t *testing.T) {
	tests := []struct {
		name string
		ctx  NegotiateContextDecoder
	}{
		{
			name: "header shorter than 8 bytes",
			ctx:  NegotiateContextDecoder(make([]byte, 7)),
		},
		{
			name: "buffer one byte shorter than declared data",
			ctx: func() NegotiateContextDecoder {
				buf := make([]byte, 8+4)
				binary.LittleEndian.PutUint16(buf[2:4], 5)
				return NegotiateContextDecoder(buf)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.ctx.IsInvalid() {
				t.Fatal("IsInvalid() = false, want true")
			}
		})
	}
}

func TestNegotiateResponseDecoderNegotiateContextListBounds(t *testing.T) {
	makeBody := func(packetLength int, dialect uint16, contextOffset uint32) []byte {
		body := make([]byte, packetLength-64)
		binary.LittleEndian.PutUint16(body[0:2], 65) // StructureSize
		binary.LittleEndian.PutUint16(body[4:6], dialect)
		binary.LittleEndian.PutUint32(body[60:64], contextOffset)
		return body
	}

	tests := []struct {
		name       string
		body       []byte
		wantNil    bool
		wantLength int
	}{
		{
			name:    "body shorter than fixed structure",
			body:    make([]byte, 63),
			wantNil: true,
		},
		{
			name:    "offset inside fixed response",
			body:    makeBody(128, SMB311, 63),
			wantNil: true,
		},
		{
			name:       "offset exactly at end",
			body:       makeBody(128, SMB311, 128),
			wantLength: 0,
		},
		{
			name:    "offset one byte past end",
			body:    makeBody(128, SMB311, 129),
			wantNil: true,
		},
		{
			name:    "maximum offset",
			body:    makeBody(128, SMB311, 0xffffffff),
			wantNil: true,
		},
		{
			name:    "non-SMB311 response with out-of-range offset",
			body:    makeBody(128, SMB210, 0x30303030),
			wantNil: true,
		},
		{
			name:       "SMB311 context list",
			body:       makeBody(136, SMB311, 128),
			wantLength: 8,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NegotiateResponseDecoder(test.body).NegotiateContextList()
			if test.wantNil {
				if got != nil {
					t.Fatalf("NegotiateContextList() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("NegotiateContextList() = nil, want non-nil")
			}
			if len(got) != test.wantLength {
				t.Fatalf("len(NegotiateContextList()) = %d, want %d", len(got), test.wantLength)
			}
		})
	}
}

// A non-SMB311 response is not required to carry a meaningful
// NegotiateContextOffset, so IsInvalid must keep accepting it while the
// accessor refuses to slice out of bounds.
func TestNegotiateResponseDecoderNonSMB311OutOfRangeContextOffset(t *testing.T) {
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)           // StructureSize
	binary.LittleEndian.PutUint16(body[4:6], SMB210)       // DialectRevision
	binary.LittleEndian.PutUint32(body[60:64], 0x30303030) // NegotiateContextOffset

	d := NegotiateResponseDecoder(body)
	if d.IsInvalid() {
		t.Fatal("IsInvalid() = true, want false")
	}
	if got := d.NegotiateContextList(); got != nil {
		t.Fatalf("NegotiateContextList() = %v, want nil", got)
	}
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

func TestQueryInfoResponseDecoderPayloadValidation(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		length  uint32
		size    int
		want    []byte
		invalid bool
	}{
		{name: "non-empty offset 0", offset: 0, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 63", offset: 63, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 64", offset: 64, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 65", offset: 65, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 66", offset: 66, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 67", offset: 67, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 68", offset: 68, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 69", offset: 69, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 70", offset: 70, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 71", offset: 71, length: 1, size: 8, invalid: true},
		{name: "non-empty offset 72", offset: 72, length: 4, size: 12, want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "non-empty after padding", offset: 80, length: 4, size: 20, want: []byte{0xfe, 0xed, 0xfa, 0xce}},
		{name: "non-empty past packet", offset: 72, length: 5, size: 12, invalid: true},
		{name: "large length", offset: 72, length: 0xffffffff, size: 8, invalid: true},
		{name: "empty offset 0", offset: 0, length: 0, size: 8},
		{name: "empty offset 72", offset: 72, length: 0, size: 8},
		{name: "empty past packet", offset: 73, length: 0, size: 8, invalid: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := make([]byte, test.size)
			binary.LittleEndian.PutUint16(buf[0:2], 9) // StructureSize
			binary.LittleEndian.PutUint16(buf[2:4], test.offset)
			binary.LittleEndian.PutUint32(buf[4:8], test.length)
			if test.want != nil {
				copy(buf[int(test.offset)-64:], test.want)
			}

			d := QueryInfoResponseDecoder(buf)
			if got := d.IsInvalid(); got != test.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, test.invalid)
			}
			if test.want != nil && !test.invalid {
				if got := d.OutputBuffer(); string(got) != string(test.want) {
					t.Errorf("OutputBuffer() = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestCreateResponseDecoderContextValidation(t *testing.T) {
	tests := []struct {
		name     string
		packet   func() []byte
		invalid  bool
		wantQFid bool
	}{
		{
			name: "empty context list",
			packet: func() []byte {
				buf := make([]byte, 64+88)
				binary.LittleEndian.PutUint16(buf[64:66], 89)
				return buf
			},
		},
		{
			name: "encoded single context",
			packet: func() []byte {
				res := &CreateResponse{
					CreationTime:   &Filetime{},
					LastAccessTime: &Filetime{},
					LastWriteTime:  &Filetime{},
					ChangeTime:     &Filetime{},
					FileId:         &FileId{},
					Contexts:       []Encoder{qfidCreateContext{size: 56, response: true}},
				}
				buf := make([]byte, res.Size())
				res.Encode(buf)
				return buf
			},
			wantQFid: true,
		},
		{
			name: "non-empty offset zero",
			packet: func() []byte {
				return createResponseContextPacket(0, 8)
			},
			invalid: true,
		},
		{
			name: "non-empty offset 64",
			packet: func() []byte {
				return createResponseContextPacket(64, 8)
			},
			invalid: true,
		},
		{
			name: "non-empty offset 144",
			packet: func() []byte {
				return createResponseContextPacket(144, 8)
			},
			invalid: true,
		},
		{
			name: "non-aligned offset",
			packet: func() []byte {
				return append(createResponseContextPacket(153, 1), 0, 0)
			},
			invalid: true,
		},
		{
			name: "context extends past packet end",
			packet: func() []byte {
				return createResponseContextPacket(152, 1)
			},
			invalid: true,
		},
		{
			name: "empty context list with non-zero offset",
			packet: func() []byte {
				return createResponseContextPacket(152, 0)
			},
			invalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := tt.packet()
			d := CreateResponseDecoder(buf[64:])
			if got := d.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
			if tt.wantQFid {
				contexts := d.CreateContexts()
				if len(contexts) != 56 || string(contexts[16:20]) != "QFid" {
					t.Errorf("CreateContexts() = %v, want the encoded QFid context", contexts)
				}
			}
		})
	}
}

func TestCreateResponseDecoderSizeValidation(t *testing.T) {
	for _, offset := range []int{40, 48} {
		for _, size := range []uint64{0, 1, 1<<63 - 1, 1 << 63, ^uint64(0)} {
			buf := make([]byte, 88)
			binary.LittleEndian.PutUint16(buf[0:2], 89)
			binary.LittleEndian.PutUint64(buf[offset:offset+8], size)
			wantInvalid := size > 1<<63-1
			if got := (CreateResponseDecoder)(buf).IsInvalid(); got != wantInvalid {
				t.Errorf("size at offset %d = %d: IsInvalid() = %v, want %v", offset, size, got, wantInvalid)
			}
		}
	}
}

func createResponseContextPacket(offset, length uint32) []byte {
	buf := make([]byte, 64+88)
	binary.LittleEndian.PutUint16(buf[64:66], 89)
	binary.LittleEndian.PutUint32(buf[64+80:64+84], offset)
	binary.LittleEndian.PutUint32(buf[64+84:64+88], length)
	return buf
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
	tests := []struct {
		name           string
		dataLength     uint32
		payloadSize    int
		invalidHeader  bool
		invalidPayload bool
	}{
		{
			name:        "valid response",
			dataLength:  10,
			payloadSize: 10,
		},
		{
			name:           "zero-length response",
			dataLength:     0,
			payloadSize:    0,
			invalidPayload: true,
		},
		{
			name:           "zero-length response with trailing byte",
			dataLength:     0,
			payloadSize:    1,
			invalidPayload: true,
		},
		{
			name:        "valid one-byte response",
			dataLength:  1,
			payloadSize: 1,
		},
		{
			name:           "declared data exceeds payload",
			dataLength:     10,
			payloadSize:    0,
			invalidPayload: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := make([]byte, 16+test.payloadSize)
			binary.LittleEndian.PutUint16(buf[0:2], 17) // StructureSize
			buf[2] = 80                                 // DataOffset (64+16)
			binary.LittleEndian.PutUint32(buf[4:8], test.dataLength)

			d := ReadResponseDecoder(buf)
			if got := d.IsInvalidHeader(); got != test.invalidHeader {
				t.Errorf("IsInvalidHeader() = %v, want %v", got, test.invalidHeader)
			}
			if got := d.IsInvalidPayload(); got != test.invalidPayload {
				t.Errorf("IsInvalidPayload() = %v, want %v", got, test.invalidPayload)
			}
			if got, want := d.IsInvalid(), test.invalidHeader || test.invalidPayload; got != want {
				t.Errorf("IsInvalid() = %v, want %v", got, want)
			}
		})
	}

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

}
