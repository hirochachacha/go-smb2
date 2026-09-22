package security

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func descriptorWithRawACE(t *testing.T, raw []byte) []byte {
	t.Helper()
	acl := &ACL{Revision: 4, ACEs: []ACE{{Type: ACEType(raw[0]), Flags: ACEFlags(raw[1]), Raw: raw}}}
	d := &Descriptor{DACL: acl}
	if aceIsSACLOnly(ACEType(raw[0])) {
		d = &Descriptor{SACL: acl}
	}
	encoded, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeRawACEBodies(t *testing.T) {
	for _, typ := range []byte{0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f} {
		t.Run(fmt.Sprintf("type_%02x", typ), func(t *testing.T) {
			object := typ == 5 || typ == 6 || typ == 7 || typ == 0x0b || typ == 0x0c || typ == 0x0f
			for flags := range uint32(4) {
				if !object && flags != 0 {
					continue
				}
				sidOffset := 8
				if object {
					sidOffset = 12
					if flags&1 != 0 {
						sidOffset += 16
					}
					if flags&2 != 0 {
						sidOffset += 16
					}
				}
				for _, trailing := range []int{0, 4} {
					raw := make([]byte, sidOffset+12+trailing)
					raw[0] = typ
					binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw)))
					if object {
						binary.LittleEndian.PutUint32(raw[8:12], flags)
					}
					MustSID("S-1-1-0").Encode(raw[sidOffset:])
					encoded := descriptorWithRawACE(t, raw)
					d, err := DecodeDescriptor(encoded)
					if err != nil {
						t.Fatalf("flags=%d trailing=%d: %v", flags, trailing, err)
					}
					acl := d.DACL
					if aceIsSACLOnly(ACEType(typ)) {
						acl = d.SACL
					}
					if !bytes.Equal(acl.ACEs[0].Raw, raw) {
						t.Fatal("raw bytes changed")
					}
					for _, length := range []int{4, sidOffset, sidOffset + 8} {
						bad := append([]byte(nil), raw[:length]...)
						binary.LittleEndian.PutUint16(bad[2:4], uint16(len(bad)))
						if _, err := DecodeDescriptor(descriptorWithRawACE(t, bad)); err == nil {
							t.Fatalf("accepted truncated ACE length=%d", length)
						}
					}
					for _, mutate := range []func([]byte){
						func(b []byte) { b[sidOffset] = 2 },
						func(b []byte) { b[sidOffset+1] = 16 },
					} {
						bad := append([]byte(nil), raw...)
						mutate(bad)
						if _, err := DecodeDescriptor(descriptorWithRawACE(t, bad)); err == nil {
							t.Fatal("accepted invalid SID")
						}
					}
					if object {
						raw[8] |= 4
						if _, err := DecodeDescriptor(descriptorWithRawACE(t, raw)); err == nil {
							t.Fatal("accepted invalid object flags")
						}
					}
				}
			}
		})
	}
	unknown := []byte{0x42, 0, 4, 0}
	if _, err := DecodeDescriptor(descriptorWithRawACE(t, unknown)); err != nil {
		t.Fatalf("unknown ACE: %v", err)
	}
}

func TestDecodeResourceACE(t *testing.T) {
	makeACE := func(typ uint16, value []byte) []byte {
		// The name occupies four UTF-16 bytes after one value offset.
		claim := make([]byte, 24+len(value))
		binary.LittleEndian.PutUint32(claim, 20)
		binary.LittleEndian.PutUint16(claim[4:], typ)
		binary.LittleEndian.PutUint32(claim[12:], 1)
		binary.LittleEndian.PutUint32(claim[16:], 24)
		claim[20] = 'x'
		copy(claim[24:], value)
		raw := make([]byte, roundup4(20+len(claim)))
		raw[0] = 0x12
		binary.LittleEndian.PutUint16(raw[2:], uint16(len(raw)))
		MustSID("S-1-1-0").Encode(raw[8:])
		copy(raw[20:], claim)
		return raw
	}
	octets := func(value []byte) []byte {
		b := make([]byte, 4+len(value))
		binary.LittleEndian.PutUint32(b, uint32(len(value)))
		copy(b[4:], value)
		return b
	}
	for _, tc := range []struct {
		typ   uint16
		value []byte
	}{
		{1, make([]byte, 8)}, {2, bytes.Repeat([]byte{0xff}, 8)},
		{3, []byte{'v', 0, 0, 0}}, {3, []byte{0x00, 0xd8, 0x00, 0xdc, 0, 0}},
		{5, octets([]byte("S-1-1-0"))}, {5, octets([]byte("S-1-1-0\x00"))},
		{6, []byte{1, 0, 0, 0, 0, 0, 0, 0}}, {0x10, octets([]byte{1, 2, 3})},
	} {
		raw := makeACE(tc.typ, tc.value)
		raw[26] = 0xff // Reserved is ignored on receipt.
		if tc.typ == 3 || tc.typ == 5 {
			raw[28] = 2 // Case sensitivity is valid for string values.
		}
		if _, err := DecodeDescriptor(descriptorWithRawACE(t, raw)); err != nil {
			t.Fatalf("type %d: %v", tc.typ, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"mask", func(b []byte) { b[4] = 1 }},
		{"trustee", func(b []byte) { b[15] = 5 }},
		{"type", func(b []byte) { b[24] = 4 }},
		{"flags", func(b []byte) { b[28] = 0x40 }},
		{"case sensitivity on boolean", func(b []byte) { b[28] = 2 }},
		{"provenance", func(b []byte) { b[30] = 3 }},
		{"count", func(b []byte) { binary.LittleEndian.PutUint32(b[32:], ^uint32(0)) }},
		{"name offset", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], ^uint32(0)) }},
		{"name in header", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 4) }},
		{"empty name", func(b []byte) { b[40] = 0 }},
		{"value offset", func(b []byte) { binary.LittleEndian.PutUint32(b[36:], ^uint32(0)) }},
		{"value in header", func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 8) }},
		{"bool", func(b []byte) { b[44] = 2 }},
		{"octet length", func(b []byte) { b[24] = 0x10; binary.LittleEndian.PutUint32(b[44:], ^uint32(0)) }},
		{"string surrogate", func(b []byte) { b[24] = 3; b[44] = 0; b[45] = 0xd8 }},
		{"unterminated string", func(b []byte) {
			b[24] = 3
			for i := 44; i < len(b); i++ {
				b[i] = 1
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := makeACE(6, []byte{1, 0, 0, 0, 0, 0, 0, 0})
			tc.mutate(raw)
			if _, err := DecodeDescriptor(descriptorWithRawACE(t, raw)); err == nil {
				t.Fatal("accepted malformed resource attribute")
			}
		})
	}
	for _, value := range []string{"bad", "S-2-1-0", "S-1-1-0\x00junk"} {
		if _, err := DecodeDescriptor(descriptorWithRawACE(t, makeACE(5, octets([]byte(value))))); err == nil {
			t.Fatal("accepted malformed SID claim")
		}
	}
	for _, size := range []int{4, 8, 16, 20, 32} {
		raw := makeACE(6, make([]byte, 8))[:size]
		binary.LittleEndian.PutUint16(raw[2:], uint16(size))
		if _, err := DecodeDescriptor(descriptorWithRawACE(t, raw)); err == nil {
			t.Fatalf("accepted truncated resource ACE size=%d", size)
		}
	}
}
