package smb2

import (
	"encoding/binary"
	"testing"
)

func TestChangeNotifyRequestEncoding(t *testing.T) {
	req := &ChangeNotifyRequest{
		Flags:              SMB2_WATCH_TREE,
		OutputBufferLength: 65536,
		FileId:             &FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
		CompletionFilter:   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
	}
	pkt := make([]byte, req.Size())
	for i := range pkt {
		pkt[i] = 0xff
	}
	req.Encode(pkt)

	d := ChangeNotifyRequestDecoder(pkt[64:])
	if d.IsInvalid() {
		t.Fatal("well-formed CHANGE_NOTIFY request was rejected")
	}
	if d.StructureSize() != 32 || d.Flags() != SMB2_WATCH_TREE || d.OutputBufferLength() != 65536 || d.CompletionFilter() != req.CompletionFilter {
		t.Fatalf("unexpected CHANGE_NOTIFY request fields: %#v", d)
	}
	if got := d.FileId().Decode(); got.Persistent != req.FileId.Persistent || got.Volatile != req.FileId.Volatile {
		t.Fatalf("unexpected FileId: %#v", got)
	}
}

func TestChangeNotifyRequestDecoderRejectsInvalidFlagsAndReserved(t *testing.T) {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint16(buf[0:2], 32)
	binary.LittleEndian.PutUint16(buf[2:4], 2)
	if !ChangeNotifyRequestDecoder(buf).IsInvalid() {
		t.Fatal("invalid CHANGE_NOTIFY flags were accepted")
	}
	binary.LittleEndian.PutUint16(buf[2:4], 0)
	binary.LittleEndian.PutUint32(buf[28:32], 1)
	if !ChangeNotifyRequestDecoder(buf).IsInvalid() {
		t.Fatal("non-zero CHANGE_NOTIFY Reserved was accepted")
	}
}

// NegotiateContextOffset is measured from the start of the SMB2 header, so a
// request decoder (which sits right after the 64-byte header) must subtract
// the full header size, and must reject offsets that do not fit in the packet.
//
// The old decoder subtracted only the 36-byte request structure, returning a
// slice shifted by 28 bytes, and its bounds check accepted offsets smaller
// than 64 or offsets extending beyond the packet.
func TestNegotiateRequestDecoderNegotiateContext(t *testing.T) {
	req := &NegotiateRequest{
		SecurityMode: SMB2_NEGOTIATE_SIGNING_ENABLED,
		Capabilities: SMB2_GLOBAL_CAP_ENCRYPTION,
		Dialects:     []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311},
		Contexts: []Encoder{
			&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: []byte{0x01, 0x02, 0x03, 0x04}},
			&CipherContext{Ciphers: []uint16{AES128CCM}},
		},
	}

	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	d := NegotiateRequestDecoder(pkt[64:])

	if d.IsInvalid() {
		t.Fatal("a well-formed negotiate request with contexts was rejected")
	}

	if d.NegotiateContextCount() != 2 {
		t.Fatalf("unexpected NegotiateContextCount: got %d, want 2", d.NegotiateContextCount())
	}

	list := d.NegotiateContextList()
	if len(list) == 0 {
		t.Fatal("NegotiateContextList returned an empty list")
	}

	want := []uint16{SMB2_PREAUTH_INTEGRITY_CAPABILITIES, SMB2_ENCRYPTION_CAPABILITIES}
	for i := 0; i < int(d.NegotiateContextCount()); i++ {
		ctx := NegotiateContextDecoder(list)
		if ctx.IsInvalid() {
			t.Fatalf("context %d is out of the packet bounds", i)
		}
		if got := ctx.ContextType(); got != want[i] {
			t.Errorf("context %d: got ContextType %d, want %d", i, got, want[i])
		}
		if next := ctx.Next(); next < len(list) {
			list = list[next:]
		}
	}
}

// A hostile peer can declare a DialectCount far larger than the packet can
// hold. IsInvalid must reject such a request before Dialects() slices past
// the end of the buffer and panics on the peer's packet.
func TestNegotiateRequestDecoderRejectsOutOfBoundsDialectCount(t *testing.T) {
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint16(buf[0:2], 36)     // StructureSize
	binary.LittleEndian.PutUint16(buf[2:4], 0xFFFF) // DialectCount

	if d := (NegotiateRequestDecoder)(buf); !d.IsInvalid() {
		t.Error("a negotiate request declaring 0xFFFF dialects in a 36-byte packet was accepted as valid")
	}
}

func TestNegotiateRequestDecoderMaxDialectCount(t *testing.T) {
	const dialectCount = 0xFFFF

	buf := make([]byte, 36+2*dialectCount)
	binary.LittleEndian.PutUint16(buf[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(buf[2:4], dialectCount)
	binary.LittleEndian.PutUint16(buf[36:38], 0x0202)
	binary.LittleEndian.PutUint16(buf[len(buf)-2:], 0x0311)

	d := NegotiateRequestDecoder(buf)
	if d.IsInvalid() {
		t.Fatal("a well-formed negotiate request with the maximum dialect count was rejected")
	}
	dialects := d.Dialects()
	if len(dialects) != dialectCount {
		t.Fatalf("unexpected dialect count: got %d, want %d", len(dialects), dialectCount)
	}
	if dialects[0] != 0x0202 || dialects[len(dialects)-1] != 0x0311 {
		t.Fatalf("unexpected dialect endpoints: got %#x and %#x", dialects[0], dialects[len(dialects)-1])
	}

	if d = NegotiateRequestDecoder(buf[:len(buf)-1]); !d.IsInvalid() {
		t.Fatal("a negotiate request truncated by one byte was accepted")
	}
}

func TestHashContextDataDecoderSaltBounds(t *testing.T) {
	tests := []struct {
		name           string
		hashCount      uint16
		saltLength     uint16
		salt           []byte
		wantSaltOffset int
	}{
		{
			name:           "maximum count and salt length",
			hashCount:      0xFFFF,
			saltLength:     0xFFFF,
			salt:           []byte{0x11, 0x22, 0x33, 0x44},
			wantSaltOffset: 4 + 2*0xFFFF,
		},
		{
			name:           "salt end addition wraps",
			hashCount:      32765,
			saltLength:     4,
			salt:           []byte{0x55, 0x66, 0x77, 0x88},
			wantSaltOffset: 4 + 2*32765,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 4+2*int(tt.hashCount)+int(tt.saltLength))
			binary.LittleEndian.PutUint16(buf[0:2], tt.hashCount)
			binary.LittleEndian.PutUint16(buf[2:4], tt.saltLength)
			for i := 0; i < int(tt.saltLength); i++ {
				buf[tt.wantSaltOffset+i] = tt.salt[i%len(tt.salt)]
			}

			d := HashContextDataDecoder(buf)
			if d.IsInvalid() {
				t.Fatal("a well-formed hash context was rejected")
			}
			salt := d.Salt()
			if len(salt) != int(tt.saltLength) {
				t.Fatalf("unexpected salt length: got %d, want %d", len(salt), tt.saltLength)
			}
			for i, got := range salt {
				if want := tt.salt[i%len(tt.salt)]; got != want {
					t.Fatalf("unexpected salt byte at index %d: got %#x, want %#x", i, got, want)
				}
			}

			if d = HashContextDataDecoder(buf[:len(buf)-1]); !d.IsInvalid() {
				t.Fatal("a hash context truncated by one byte was accepted")
			}
		})
	}
}

// IsInvalid must reject negotiate requests whose NegotiateContextOffset does
// not fit in the packet. An offset smaller than 64 points before the request
// structure; an offset larger than len(r)+64 points beyond the packet.
func TestNegotiateRequestDecoderRejectsOutOfBoundsNegotiateContextOffset(t *testing.T) {
	tests := []struct {
		name string
		noff uint32
		size int
	}{
		// 0xFF00 + 0x0100 wraps to 0 in uint16, but 36 bytes are enough.
		{"offset below the request structure", 32, 40},
		{"offset beyond the packet", 0x100, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			binary.LittleEndian.PutUint16(buf[0:2], 36)        // StructureSize
			binary.LittleEndian.PutUint32(buf[28:32], tt.noff) // NegotiateContextOffset

			if d := (NegotiateRequestDecoder)(buf); !d.IsInvalid() {
				t.Errorf("an out-of-bounds NegotiateContextOffset (0x%x) was accepted as valid", tt.noff)
			}
		})
	}
}

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

// ReadChannelInfoOffset is measured from the start of the SMB2 header, so a
// request decoder (which sits right after the 64-byte header) must add the
// header size back before comparing against the buffer length.
func TestReadRequestDecoderReadChannelInfo(t *testing.T) {
	req := &ReadRequest{
		Length:  4096,
		FileId:  &FileId{Persistent: [8]byte{0x01}, Volatile: [8]byte{0x02}},
		Channel: SMB2_CHANNEL_RDMA_V1,
		ReadChannelInfo: []Encoder{
			rawChannelInfo{
				0x00, 0x00, 0x00, 0x00, // Channel
				0x04, 0x00, 0x00, 0x00, // Length
				0xAA, 0xBB, 0xCC, 0xDD, // data
			},
		},
	}

	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	d := ReadRequestDecoder(pkt[64:])

	if d.IsInvalid() {
		t.Error("a well-formed read request with read channel info was rejected")
	}
}

func TestLockRequestEncodeAndDecode(t *testing.T) {
	req := &LockRequest{
		FileId: &FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
		Locks: []LockElement{
			{Offset: 7, Length: 0, Flags: SMB2_LOCKFLAG_SHARED_LOCK},
			{Offset: 11, Length: 13, Flags: SMB2_LOCKFLAG_EXCLUSIVE_LOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY},
		},
	}

	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	d := LockRequestDecoder(pkt[64:])
	if d.IsInvalid() {
		t.Fatal("a well-formed lock request was rejected")
	}
	if d.StructureSize() != 48 || d.LockCount() != 2 || d.LockSequence() != 0 {
		t.Fatalf("unexpected lock fixed fields: size=%d count=%d sequence=%d", d.StructureSize(), d.LockCount(), d.LockSequence())
	}
	if got := d.FileId().Decode(); *got != *req.FileId {
		t.Fatalf("FileId = %#v, want %#v", got, req.FileId)
	}
	locks := d.Locks()
	for i, want := range req.Locks {
		got := LockElementDecoder(locks[i*24:])
		if got.Offset() != want.Offset || got.Length() != want.Length || got.Flags() != want.Flags || got.Reserved() != 0 {
			t.Errorf("lock %d does not match: offset=%d length=%d flags=%#x reserved=%d", i, got.Offset(), got.Length(), got.Flags(), got.Reserved())
		}
	}
}

func TestLockRequestDecoderRejectsInvalidElements(t *testing.T) {
	base := make([]byte, 48)
	binary.LittleEndian.PutUint16(base[0:2], 48)
	binary.LittleEndian.PutUint16(base[2:4], 1)
	for _, flags := range []uint32{0, SMB2_LOCKFLAG_UNLOCK | SMB2_LOCKFLAG_SHARED_LOCK, SMB2_LOCKFLAG_FAIL_IMMEDIATELY} {
		buf := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(buf[40:44], flags)
		if !LockRequestDecoder(buf).IsInvalid() {
			t.Errorf("flags %#x were accepted", flags)
		}
	}
	reserved := append([]byte(nil), base...)
	binary.LittleEndian.PutUint32(reserved[44:48], 1)
	if !LockRequestDecoder(reserved).IsInvalid() {
		t.Fatal("nonzero lock element reserved field was accepted")
	}

	truncated := base[:47]
	if !LockRequestDecoder(truncated).IsInvalid() {
		t.Fatal("truncated lock request was accepted")
	}
}

// rawChannelInfo is a fixed-size read channel info blob for tests.
type rawChannelInfo []byte

func (b rawChannelInfo) Size() int { return len(b) }

func (b rawChannelInfo) Encode(pkt []byte) { copy(pkt, b) }

func assertCreateContextChain(t *testing.T, pkt []byte, offset, length uint32, sizes []int) {
	t.Helper()

	if offset%8 != 0 {
		t.Fatalf("CreateContextsOffset = %d, want an 8-byte-aligned offset", offset)
	}

	pos := int(offset)
	start := pos
	for i, size := range sizes {
		if pos%8 != 0 {
			t.Fatalf("context %d starts at %d, want an 8-byte boundary", i, pos)
		}
		if got := string(pkt[pos+16 : pos+20]); got != "QFid" {
			t.Errorf("context %d name = %q, want QFid", i, got)
		}

		if size >= 56 {
			if le.Uint16(pkt[pos+10:pos+12]) != 24 || le.Uint32(pkt[pos+12:pos+16]) != 32 {
				t.Fatal("response context payload bounds changed")
			}
			for j := 24; j < 56; j++ {
				if pkt[pos+j] != byte(j) {
					t.Fatal("response context payload changed")
				}
			}
		}
		end := pos + size
		wantNext := 0
		if i+1 < len(sizes) {
			wantNext = Roundup(end, 8) - pos
		}
		if got := int(le.Uint32(pkt[pos : pos+4])); got != wantNext {
			t.Errorf("context %d Next = %d, want %d", i, got, wantNext)
		}

		if i+1 < len(sizes) {
			pos = Roundup(end, 8)
		} else {
			pos = end
		}
	}

	if got := int(length); got != pos-start {
		t.Errorf("CreateContextsLength = %d, want %d", got, pos-start)
	}
}

func TestCreateRequestContextNext(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantOffset uint32
		sizes      []int
	}{
		{name: "single non-aligned", sizes: []int{20}},
		{name: "non-aligned followed by non-aligned", sizes: []int{20, 20}},
		{name: "aligned followed by non-aligned", sizes: []int{24, 20}},
		{name: "name length 2", path: "a", wantOffset: 128, sizes: []int{20}},
		{name: "name length 4", path: "ab", wantOffset: 128, sizes: []int{20}},
		{name: "name length 6", path: "abc", wantOffset: 128, sizes: []int{20}},
		{name: "name length 8", path: "abcd", wantOffset: 128, sizes: []int{20}},
		{name: "name followed by multiple contexts", path: "a", wantOffset: 128, sizes: []int{20, 20}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := make([]Encoder, len(tt.sizes))
			for i, size := range tt.sizes {
				contexts[i] = qfidCreateContext{size: size}
			}

			req := &CreateRequest{Name: tt.path, Contexts: contexts}
			pkt := make([]byte, req.Size())
			req.Encode(pkt)

			d := CreateRequestDecoder(pkt[64:])
			if d.IsInvalid() {
				t.Fatal("encoded create request was rejected")
			}
			if tt.wantOffset != 0 && d.CreateContextsOffset() != tt.wantOffset {
				t.Errorf("CreateContextsOffset = %d, want %d", d.CreateContextsOffset(), tt.wantOffset)
			}
			assertCreateContextChain(t, pkt, d.CreateContextsOffset(), d.CreateContextsLength(), tt.sizes)
		})
	}
}

func TestCreateRequestWithoutContexts(t *testing.T) {
	req := &CreateRequest{Name: "a"}
	pkt := make([]byte, req.Size())
	req.Encode(pkt)

	d := CreateRequestDecoder(pkt[64:])
	if d.IsInvalid() {
		t.Fatal("encoded create request was rejected")
	}
	if got := d.CreateContextsOffset(); got != 0 {
		t.Errorf("CreateContextsOffset = %d, want 0", got)
	}
	if got := d.CreateContextsLength(); got != 0 {
		t.Errorf("CreateContextsLength = %d, want 0", got)
	}
}
