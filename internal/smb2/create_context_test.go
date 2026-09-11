package smb2

import "testing"

// qfidCreateContext encodes a QFid context with a 20-byte request or a
// 32-byte response payload. Extra bytes represent trailing context padding.
type qfidCreateContext struct {
	size     int
	response bool
}

func (c qfidCreateContext) Size() int {
	return c.size
}

func (c qfidCreateContext) Encode(p []byte) {
	clear(p[:c.size])
	le.PutUint32(p[:4], 0xdeadbeef) // overwritten by the CREATE encoder
	le.PutUint16(p[4:6], 16)        // NameOffset
	le.PutUint16(p[6:8], 4)         // NameLength
	copy(p[16:20], "QFid")
	if c.response {
		le.PutUint16(p[10:12], 24)
		le.PutUint32(p[12:16], 32)
		for i := 24; i < 56; i++ {
			p[i] = byte(i)
		}
	}
}

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
		name  string
		sizes []int
	}{
		{name: "single non-aligned", sizes: []int{20}},
		{name: "non-aligned followed by non-aligned", sizes: []int{20, 20}},
		{name: "aligned followed by non-aligned", sizes: []int{24, 20}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := make([]Encoder, len(tt.sizes))
			for i, size := range tt.sizes {
				contexts[i] = qfidCreateContext{size: size}
			}

			req := &CreateRequest{Contexts: contexts}
			pkt := make([]byte, req.Size())
			req.Encode(pkt)

			d := CreateRequestDecoder(pkt[64:])
			if d.IsInvalid() {
				t.Fatal("encoded create request was rejected")
			}
			assertCreateContextChain(t, pkt, d.CreateContextsOffset(), d.CreateContextsLength(), tt.sizes)
		})
	}
}

func TestCreateResponseContextNext(t *testing.T) {
	tests := []struct {
		name  string
		sizes []int
	}{
		{name: "single non-aligned", sizes: []int{60}},
		{name: "non-aligned followed by non-aligned", sizes: []int{60, 60}},
		{name: "aligned followed by non-aligned", sizes: []int{56, 60}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := make([]Encoder, len(tt.sizes))
			for i, size := range tt.sizes {
				contexts[i] = qfidCreateContext{size: size, response: true}
			}

			res := &CreateResponse{
				CreationTime:   &Filetime{},
				LastAccessTime: &Filetime{},
				LastWriteTime:  &Filetime{},
				ChangeTime:     &Filetime{},
				FileId:         &FileId{},
				Contexts:       contexts,
			}
			pkt := make([]byte, res.Size())
			res.Encode(pkt)

			d := CreateResponseDecoder(pkt[64:])
			if d.IsInvalid() {
				t.Fatal("encoded create response was rejected")
			}
			assertCreateContextChain(t, pkt, d.CreateContextsOffset(), d.CreateContextsLength(), tt.sizes)
		})
	}
}
