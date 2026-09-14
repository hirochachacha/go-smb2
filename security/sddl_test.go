package security

import (
	"strings"
	"testing"
)

func TestSDDLMSDTYPExample(t *testing.T) {
	// Example from [MS-DTYP] section 2.5.1.4:
	// "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)"
	want := "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)"

	descriptor := &Descriptor{
		Owner: MustSID("S-1-5-32-544"),
		Group: MustSID("S-1-5-32-544"),
		DACL: &ACL{
			Protected: true,
			ACEs: []ACE{
				{
					Type:  AccessAllowed,
					Flags: ContainerInherit | ObjectInherit,
					Mask:  GenericRead | GenericExecute,
					SID:   MustSID("S-1-5-32-545"),
				},
				{
					Type:  AccessAllowed,
					Flags: ContainerInherit | ObjectInherit,
					Mask:  GenericAll,
					SID:   MustSID("S-1-5-32-544"),
				},
				{
					Type:  AccessAllowed,
					Flags: ContainerInherit | ObjectInherit,
					Mask:  GenericAll,
					SID:   MustSID("S-1-5-18"),
				},
				{
					Type:  AccessAllowed,
					Flags: ContainerInherit | ObjectInherit,
					Mask:  GenericAll,
					SID:   MustSID("S-1-3-0"),
				},
			},
		},
		SACL: &ACL{
			Protected: true,
			ACEs: []ACE{
				{
					Type:  SystemAudit,
					Flags: FailedAccess,
					Mask:  GenericRead,
					SID:   MustSID("S-1-1-0"),
				},
			},
		},
	}

	if got := descriptor.String(); got != want {
		t.Fatalf("descriptor.String() = %q, want %q", got, want)
	}
}

func TestSDDLNilAndEmpty(t *testing.T) {
	var nilDesc *Descriptor
	if got := nilDesc.String(); got != "" {
		t.Fatalf("nilDesc.String() = %q, want %q", got, "")
	}

	emptyDesc := &Descriptor{}
	if got := emptyDesc.String(); got != "" {
		t.Fatalf("emptyDesc.String() = %q, want %q", got, "")
	}

	nullACLDESC := &Descriptor{
		Owner: MustSID("S-1-5-18"),
		DACL:  NullACL,
	}
	if got, want := nullACLDESC.String(), "O:SY"; got != want {
		t.Fatalf("nullACLDESC.String() = %q, want %q", got, want)
	}

	emptyDACLDesc := &Descriptor{
		Owner: MustSID("S-1-5-18"),
		DACL:  &ACL{},
	}
	if got, want := emptyDACLDesc.String(), "O:SYD:"; got != want {
		t.Fatalf("emptyDACLDesc.String() = %q, want %q", got, want)
	}

	var nilACL *ACL
	if got := nilACL.String(); got != "" {
		t.Fatalf("nilACL.String() = %q, want %q", got, "")
	}
	if got := NullACL.String(); got != "" {
		t.Fatalf("NullACL.String() = %q, want %q", got, "")
	}

	var nilACE *ACE
	if got := nilACE.String(); got != "" {
		t.Fatalf("nilACE.String() = %q, want %q", got, "")
	}
	rawACE := &ACE{Raw: []byte{1, 2, 3}}
	if got := rawACE.String(); got != "" {
		t.Fatalf("rawACE.String() = %q, want %q", got, "")
	}
}

func TestSDDLACEFormat(t *testing.T) {
	tests := []struct {
		name string
		ace  *ACE
		want string
	}{
		{
			name: "AccessDenied with FileAllAccess",
			ace: &ACE{
				Type: AccessDenied,
				Mask: FileAllAccess,
				SID:  MustSID("S-1-5-32-544"),
			},
			want: "(D;;FA;;;BA)",
		},
		{
			name: "AccessAllowed with FileGenericRead and NoPropagateInherit",
			ace: &ACE{
				Type:  AccessAllowed,
				Flags: NoPropagateInherit,
				Mask:  FileGenericRead,
				SID:   MustSID("S-1-5-19"),
			},
			want: "(A;NP;FR;;;LS)",
		},
		{
			name: "AccessAllowed with FileGenericWrite and InheritOnly",
			ace: &ACE{
				Type:  AccessAllowed,
				Flags: InheritOnly,
				Mask:  FileGenericWrite,
				SID:   MustSID("S-1-5-20"),
			},
			want: "(A;IO;FW;;;NS)",
		},
		{
			name: "AccessAllowed with FileGenericExecute and Inherited",
			ace: &ACE{
				Type:  AccessAllowed,
				Flags: Inherited,
				Mask:  FileGenericExecute,
				SID:   MustSID("S-1-5-11"),
			},
			want: "(A;ID;FX;;;AU)",
		},
		{
			name: "SystemAudit with SuccessfulAccess",
			ace: &ACE{
				Type:  SystemAudit,
				Flags: SuccessfulAccess,
				Mask:  Delete | ReadControl,
				SID:   MustSID("S-1-1-0"),
			},
			want: "(AU;SA;RCSD;;;WD)",
		},
		{
			name: "Hexadecimal mask and custom domain SID",
			ace: &ACE{
				Type: AccessAllowed,
				Mask: 0x1200a9,
				SID:  MustSID("S-1-5-21-1-2-3-513"),
			},
			want: "(A;;0x1200a9;;;S-1-5-21-1-2-3-513)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ace.String(); got != tc.want {
				t.Fatalf("ace.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSDDLACLFormat(t *testing.T) {
	acl := &ACL{
		Protected: true,
		ACEs: []ACE{
			{
				Type: AccessAllowed,
				Mask: FileAllAccess,
				SID:  MustSID("S-1-5-32-544"),
			},
		},
	}
	if got, want := acl.String(), "P(A;;FA;;;BA)"; got != want {
		t.Fatalf("acl.String() = %q, want %q", got, want)
	}
}

func TestParseDescriptorRoundTrip(t *testing.T) {
	sddl := "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)"
	d, err := ParseDescriptor(sddl)
	if err != nil {
		t.Fatalf("ParseDescriptor() error = %v", err)
	}
	if got := d.String(); got != sddl {
		t.Fatalf("d.String() = %q, want %q", got, sddl)
	}
}

func TestParseDescriptorComponents(t *testing.T) {
	// Empty string
	d, err := ParseDescriptor("")
	if err != nil {
		t.Fatalf("ParseDescriptor(\"\") error = %v", err)
	}
	if d.Owner != nil || d.Group != nil || d.DACL != nil || d.SACL != nil {
		t.Fatalf("expected empty descriptor, got %#v", d)
	}

	// Owner only
	d, err = ParseDescriptor("O:BA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := d.Owner.String(), "S-1-5-32-544"; got != want {
		t.Fatalf("Owner = %q, want %q", got, want)
	}
	if d.Group != nil || d.DACL != nil || d.SACL != nil {
		t.Fatalf("unexpected components: %#v", d)
	}

	// Empty DACL
	d, err = ParseDescriptor("D:")
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 0 || d.DACL.Protected {
		t.Fatalf("expected empty unprotected DACL, got %#v", d.DACL)
	}

	// Protected empty DACL
	d, err = ParseDescriptor("D:P")
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 0 || !d.DACL.Protected {
		t.Fatalf("expected protected empty DACL, got %#v", d.DACL)
	}

	// Custom domain SID with hex rights
	customSDDL := "O:S-1-5-21-1-2-3-513D:(A;;0x1200a9;;;S-1-5-21-1-2-3-513)"
	d, err = ParseDescriptor(customSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.String(); got != customSDDL {
		t.Fatalf("roundtrip = %q, want %q", got, customSDDL)
	}

	// USER_MODE_DRIVERS (UD) and extended ACE types & registry rights
	extendedSDDL := "O:UDD:(ML;;0x1;;;WD)(SP;;0x0;;;UD)"
	d, err = ParseDescriptor(extendedSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := d.Owner.String(), "S-1-5-84-0-0-0-0-0"; got != want {
		t.Fatalf("Owner UD = %q, want %q", got, want)
	}
	if got, want := d.String(), "O:UDD:(ML;;0x1;;;WD)(SP;;0x0;;;UD)"; got != want {
		t.Fatalf("roundtrip = %q, want %q", got, want)
	}


	// Decimal numeric rights
	d, err = ParseDescriptor("D:(A;;12345;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.DACL.ACEs) != 1 || d.DACL.ACEs[0].Mask != 12345 {
		t.Fatalf("decimal rights parse failed: %#v", d.DACL)
	}
}


func TestParseDescriptorErrors(t *testing.T) {
	tests := []struct {
		name string
		sddl string
	}{
		{"unmatched paren open", "D:(A;;FA;;;WD"},
		{"unmatched paren close", "D:A;;FA;;;WD)"},
		{"invalid tag", "X:BA"},
		{"unexpected prefix", "garbageO:BA"},
		{"duplicate owner", "O:BAO:SY"},
		{"duplicate DACL", "D:D:"},
		{"invalid owner SID", "O:invalid-sid"},
		{"invalid ACE fields", "D:(A;FA;WD)"},
		{"missing SID in ACE", "D:(A;;FA;;;)"},
		{"unknown ACE type", "D:(UNKNOWN;;FA;;;WD)"},
		{"odd length ACE flags", "D:(A;C;FA;;;WD)"},
		{"unknown ACE flag", "D:(A;ZZ;FA;;;WD)"},
		{"odd length rights", "D:(A;;F;;;WD)"},
		{"unknown rights token", "D:(A;;ZZ;;;WD)"},
		{"unrecognized ACL flag", "D:Z(A;;FA;;;WD)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDescriptor(tc.sddl); err == nil {
				t.Fatalf("ParseDescriptor(%q) should have failed", tc.sddl)
			}
		})
	}
}

func TestParseDescriptorRejectsObjectACETypes(t *testing.T) {
	types := []string{
		"OA", "OD", "OU",
		"0x05", "0x06", "0x07", "0x08", "0x0b", "0x0c", "0x0f", "0x10",
	}
	for _, aceType := range types {
		t.Run(aceType, func(t *testing.T) {
			sddl := "D:(" + aceType + ";;FA;;;WD)"
			_, err := ParseDescriptor(sddl)
			if err == nil || !strings.Contains(err.Error(), "unsupported ACE type") {
				t.Fatalf("ParseDescriptor(%q) error = %v, want unsupported ACE type error", sddl, err)
			}

			withGUID := "D:(" + aceType + ";;FA;11111111-2222-3333-4444-555555555555;;WD)"
			if _, err := ParseDescriptor(withGUID); err == nil || !strings.Contains(err.Error(), "unsupported object GUID fields") {
				t.Fatalf("ParseDescriptor(%q) error = %v, want unsupported object GUID error", withGUID, err)
			}
		})
	}
}

func TestParseDescriptorRejectsACEGUIDFields(t *testing.T) {
	guid := "11111111-2222-3333-4444-555555555555"
	invalidGUID := "not-a-guid"
	fields := []struct {
		name              string
		objectGUID        string
		inheritObjectGUID string
	}{
		{"object GUID only, valid", guid, ""},
		{"object GUID only, invalid", invalidGUID, ""},
		{"inherited object GUID only, valid", "", guid},
		{"inherited object GUID only, invalid", "", invalidGUID},
		{"both GUIDs, valid", guid, guid},
		{"both GUIDs, invalid", invalidGUID, invalidGUID},
	}
	for _, aceType := range []string{"A", "D", "AU"} {
		for _, tc := range fields {
			t.Run(aceType+"/"+tc.name, func(t *testing.T) {
				sddl := "D:(" + aceType + ";;FA;" + tc.objectGUID + ";" + tc.inheritObjectGUID + ";WD)"
				_, err := ParseDescriptor(sddl)
				if err == nil || !strings.Contains(err.Error(), "unsupported object GUID fields") {
					t.Fatalf("ParseDescriptor(%q) error = %v, want unsupported object GUID error", sddl, err)
				}
			})
		}
	}
}

func TestParseDescriptorEncodeWithoutACEGUIDs(t *testing.T) {
	sddl := "D:(A;;FA;;;BA)(D;;FR;;;WD)S:(AU;FA;GR;;;WD)"
	d, err := ParseDescriptor(sddl)
	if err != nil {
		t.Fatalf("ParseDescriptor() error = %v", err)
	}
	if got := d.String(); got != sddl {
		t.Fatalf("d.String() = %q, want %q", got, sddl)
	}

	encoded, err := d.Encode()
	if err != nil {
		t.Fatalf("Descriptor.Encode() error = %v", err)
	}
	decoded, err := DecodeDescriptor(encoded)
	if err != nil {
		t.Fatalf("DecodeDescriptor() error = %v", err)
	}
	if got := decoded.String(); got != sddl {
		t.Fatalf("decoded.String() = %q, want %q", got, sddl)
	}
}

func TestMustDescriptor(t *testing.T) {
	d := MustDescriptor("O:BA")
	if d.Owner == nil || d.Owner.String() != "S-1-5-32-544" {
		t.Fatalf("MustDescriptor() got %#v", d)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("MustDescriptor should panic on invalid SDDL")
		}
	}()
	MustDescriptor("invalid SDDL")
}

