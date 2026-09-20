package wire

import (
	"bytes"
	"testing"
	"uuid"
)

// TestGUIDWireFormat pins the on-wire byte order to [MS-DTYP] 2.3.4.2 using
// the example GUID from [MS-DTYP] 2.3.4.3:
//
//	{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}
func TestGUIDWireFormat(t *testing.T) {
	u := uuid.MustParse("{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}")

	// Data1, Data2 and Data3 are little-endian; Data4 is stored in order.
	want := []byte{
		0xae, 0x4f, 0x1d, 0xf8,
		0xec, 0x7d,
		0xd0, 0x11,
		0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b, 0xf6,
	}

	got := make([]byte, 16)
	encodeGUID(u, got)
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeGUID = % x, want % x", got, want)
	}
	if back := decodeGUID(want); back != u {
		t.Fatalf("decodeGUID = %v, want %v", back, u)
	}
}
