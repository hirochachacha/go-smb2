package security

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestACLNullAndEmptyRepresentationsAreDistinct(t *testing.T) {
	if NullACL == nil {
		t.Fatal("NullACL is nil")
	}
	descriptor := &Descriptor{
		DACL: NullACL,
		SACL: &ACL{ACEs: []ACE{}},
	}

	if descriptor.DACL != NullACL {
		t.Fatal("DACL does not represent a NULL ACL")
	}
	if descriptor.SACL == nil || descriptor.SACL == NullACL || len(descriptor.SACL.ACEs) != 0 {
		t.Fatal("SACL does not represent an empty ACL")
	}
	if (&Descriptor{}).DACL != nil {
		t.Fatal("an unselected ACL does not have the nil representation")
	}
}

func TestACESizeAndEncode(t *testing.T) {
	var nilACE *ACE
	if nilACE.Size() != 0 {
		t.Fatalf("nilACE.Size() = %d, want 0", nilACE.Size())
	}
	nilACE.Encode(make([]byte, 10)) // should not panic

	// Raw ACE
	rawBytes := []byte{0x42, 0x01, 0x04, 0x00}
	rawACE := &ACE{Raw: rawBytes}
	if rawACE.Size() != len(rawBytes) {
		t.Fatalf("rawACE.Size() = %d, want %d", rawACE.Size(), len(rawBytes))
	}
	rawBuf := make([]byte, rawACE.Size())
	rawACE.Encode(rawBuf)
	if !bytes.Equal(rawBuf, rawBytes) {
		t.Fatalf("rawACE.Encode() = %x, want %x", rawBuf, rawBytes)
	}

	// Structured ACE
	sid := MustSID("S-1-5-32-544")
	ace := &ACE{
		Type:  AccessAllowed,
		Flags: 0x03,
		Mask:  0x001f01ff,
		SID:   sid,
	}
	wantSize := 8 + sid.Size() // 8 + 16 = 24
	if ace.Size() != wantSize {
		t.Fatalf("ace.Size() = %d, want %d", ace.Size(), wantSize)
	}

	// Short buffer
	shortBuf := make([]byte, wantSize-1)
	ace.Encode(shortBuf) // should not panic or write

	buf := make([]byte, wantSize)
	ace.Encode(buf)

	if buf[0] != byte(AccessAllowed) {
		t.Fatalf("Type = %x, want %x", buf[0], AccessAllowed)
	}
	if buf[1] != 0x03 {
		t.Fatalf("Flags = %x, want 0x03", buf[1])
	}
	if gotSize := binary.LittleEndian.Uint16(buf[2:4]); gotSize != uint16(wantSize) {
		t.Fatalf("AceSize = %d, want %d", gotSize, wantSize)
	}
	if gotMask := binary.LittleEndian.Uint32(buf[4:8]); gotMask != 0x001f01ff {
		t.Fatalf("Mask = %x, want 0x001f01ff", gotMask)
	}
	expectedSID := make([]byte, sid.Size())
	sid.Encode(expectedSID)
	if !bytes.Equal(buf[8:], expectedSID) {
		t.Fatalf("SID = %x, want %x", buf[8:], expectedSID)
	}
}

func TestACLSizeAndEncode(t *testing.T) {
	var nilACL *ACL
	if nilACL.Size() != 0 {
		t.Fatalf("nilACL.Size() = %d, want 0", nilACL.Size())
	}
	nilACL.Encode(make([]byte, 10)) // should not panic

	if NullACL.Size() != 0 {
		t.Fatalf("NullACL.Size() = %d, want 0", NullACL.Size())
	}
	NullACL.Encode(make([]byte, 10)) // should not panic

	// Empty ACL
	emptyACL := &ACL{Revision: 2}
	if emptyACL.Size() != 8 {
		t.Fatalf("emptyACL.Size() = %d, want 8", emptyACL.Size())
	}
	emptyBuf := make([]byte, 8)
	emptyACL.Encode(emptyBuf)
	if emptyBuf[0] != 2 || binary.LittleEndian.Uint16(emptyBuf[2:4]) != 8 || binary.LittleEndian.Uint16(emptyBuf[4:6]) != 0 {
		t.Fatalf("emptyACL.Encode() = %x", emptyBuf)
	}

	// ACL with ACEs
	ace1 := ACE{
		Type:  AccessAllowed,
		Flags: 0,
		Mask:  0x001f01ff,
		SID:   MustSID("S-1-5-18"),
	}
	ace2 := ACE{
		Type:  AccessDenied,
		Flags: 0,
		Mask:  0x001f01ff,
		SID:   MustSID("S-1-5-19"),
	}
	acl := &ACL{
		Revision: 2,
		ACEs:     []ACE{ace1, ace2},
	}
	wantSize := 8 + ace1.Size() + ace2.Size()
	if acl.Size() != wantSize {
		t.Fatalf("acl.Size() = %d, want %d", acl.Size(), wantSize)
	}

	// Short buffer
	shortBuf := make([]byte, wantSize-1)
	acl.Encode(shortBuf) // should not panic or write

	buf := make([]byte, wantSize)
	acl.Encode(buf)
	if buf[0] != 2 {
		t.Fatalf("Revision = %d, want 2", buf[0])
	}
	if gotSize := binary.LittleEndian.Uint16(buf[2:4]); gotSize != uint16(wantSize) {
		t.Fatalf("AclSize = %d, want %d", gotSize, wantSize)
	}
	if count := binary.LittleEndian.Uint16(buf[4:6]); count != 2 {
		t.Fatalf("AceCount = %d, want 2", count)
	}
}


func TestSecurityDescriptorDecoderRejectsCorruptInputWithoutPanic(t *testing.T) {
	for length := range 64 {
		input := make([]byte, length)
		if length >= 20 {
			input[0] = 1
			input[2] = 0x00
			input[3] = 0x80 // securityDescriptorSelfRelative
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("security descriptor decoder panicked for %d-byte input: %v", length, recovered)
				}
			}()
			_, _ = DecodeDescriptor(input)
		}()
	}
}

