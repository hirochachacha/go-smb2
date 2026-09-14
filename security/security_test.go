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

func TestDecodeStructuredMandatoryAndScopedPolicyACEs(t *testing.T) {
	// SECURITY_DESCRIPTOR with a hand-built SACL containing ML and SP ACEs.
	wire := []byte{
		0x01, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x11, 0x40, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x00, 0x20, 0x00, 0x00,
		0x13, 0x08, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
		0x01, 0x00, 0x00, 0x00,
	}

	descriptor, err := DecodeDescriptor(wire)
	if err != nil {
		t.Fatalf("DecodeDescriptor() error = %v", err)
	}
	if descriptor.SACL == nil || len(descriptor.SACL.ACEs) != 2 {
		t.Fatalf("decoded SACL = %#v, want two ACEs", descriptor.SACL)
	}
	mandatory, scoped := descriptor.SACL.ACEs[0], descriptor.SACL.ACEs[1]
	if mandatory.Raw != nil || mandatory.Type != 0x11 || mandatory.Flags != SuccessfulAccess || mandatory.Mask != 1 || mandatory.SID.String() != "S-1-16-8192" {
		t.Fatalf("decoded ML ACE = %#v", mandatory)
	}
	if scoped.Raw != nil || scoped.Type != 0x13 || scoped.Flags != InheritOnly || scoped.Mask != 0 || scoped.SID.String() != "S-1-17-1" {
		t.Fatalf("decoded SP ACE = %#v", scoped)
	}
}

func TestMandatoryAndScopedPolicySDDLRoundTrip(t *testing.T) {
	input := "O:UDS:(ML;CI;0x1;;;S-1-16-8192)(SP;IO;0x0;;;S-1-17-1)"
	descriptor, err := ParseDescriptor(input)
	if err != nil {
		t.Fatalf("ParseDescriptor() error = %v", err)
	}
	encoded, err := descriptor.Encode()
	if err != nil {
		t.Fatalf("Descriptor.Encode() error = %v", err)
	}
	decoded, err := DecodeDescriptor(encoded)
	if err != nil {
		t.Fatalf("DecodeDescriptor() error = %v", err)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 2 {
		t.Fatalf("decoded SACL = %#v, want two ACEs", decoded.SACL)
	}
	if decoded.DACL != nil {
		t.Fatalf("decoded unexpected DACL: %#v", decoded.DACL)
	}
	for i, ace := range decoded.SACL.ACEs {
		want := descriptor.SACL.ACEs[i]
		if ace.Raw != nil || ace.Type != want.Type || ace.Flags != want.Flags || ace.Mask != want.Mask || ace.SID.String() != want.SID.String() {
			t.Fatalf("decoded ACE %d = %#v, want %#v", i, ace, want)
		}
	}

	canonical := decoded.String()
	reparsed, err := ParseDescriptor(canonical)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error = %v", canonical, err)
	}
	reencoded, err := reparsed.Encode()
	if err != nil {
		t.Fatalf("reparsed Descriptor.Encode() error = %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encoded descriptor differs:\n got %x\nwant %x", reencoded, encoded)
	}
}

func TestStructuredACEValidation(t *testing.T) {
	tests := []struct {
		name string
		ace  ACE
	}{
		{
			name: "non-zero scoped policy mask",
			ace:  ACE{Type: 0x13, Mask: 1, SID: MustSID("S-1-17-1")},
		},
		{
			name: "invalid mandatory label authority",
			ace:  ACE{Type: 0x11, Mask: 1, SID: MustSID("S-1-5-18")},
		},
		{
			name: "invalid mandatory label RID",
			ace:  ACE{Type: 0x11, Mask: 1, SID: MustSID("S-1-16-1")},
		},
		{
			name: "missing mandatory label RID",
			ace:  ACE{Type: 0x11, Mask: 1, SID: &SID{Revision: 1, IdentifierAuthority: 16}},
		},
		{
			name: "multiple mandatory label RIDs",
			ace:  ACE{Type: 0x11, Mask: 1, SID: MustSID("S-1-16-8192-8192")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&Descriptor{SACL: &ACL{ACEs: []ACE{tc.ace}}}).Encode()
			if err == nil {
				t.Fatal("Descriptor.Encode() succeeded for invalid structured ACE")
			}
		})
	}
}

func TestStructuredACEDecoderRejectsTruncatedSIDAndExtraData(t *testing.T) {
	valid := []byte{
		0x01, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x11, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x00, 0x20, 0x00, 0x00,
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"invalid ML authority", func(b []byte) { b[43] = 5 }},
		{"invalid ML RID", func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], 1) }},
		{"non-zero SP mask", func(b []byte) { b[28], b[43] = 0x13, 17 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			tc.mutate(wire)
			if _, err := DecodeDescriptor(wire); err == nil {
				t.Fatal("DecodeDescriptor() accepted invalid type-specific fields")
			}
		})
	}

	truncatedSID := append([]byte(nil), valid...)
	truncatedSID[37] = 2 // SID declares two subauthorities but has one.
	if _, err := DecodeDescriptor(truncatedSID); err == nil {
		t.Fatal("DecodeDescriptor() accepted a truncated SID")
	}

	extraData := append([]byte(nil), valid...)
	extraData = append(extraData, 0xde, 0xad, 0xbe, 0xef)
	binary.LittleEndian.PutUint16(extraData[22:24], 0x20)
	binary.LittleEndian.PutUint16(extraData[30:32], 0x18)
	if _, err := DecodeDescriptor(extraData); err == nil {
		t.Fatal("DecodeDescriptor() accepted extra data in a structured ACE")
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
