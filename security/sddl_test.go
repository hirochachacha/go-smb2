package security

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkSDDLString(b *testing.B) {
	d := MustDescriptor("O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)")
	b.ReportAllocs()
	for b.Loop() {
		d.String()
	}
}

func TestSDDLAutoInheritanceFlagsRoundTrip(t *testing.T) {
	t.Parallel()
	d, err := ParseDescriptor("D:ARAI")
	if err != nil {
		t.Fatal(err)
	}
	if got := d.String(); got != "D:ARAI" {
		t.Fatalf("rendered SDDL = %q, want D:ARAI", got)
	}
	encoded, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.LittleEndian.Uint16(encoded[2:4]); flags&0x0500 != 0x0500 {
		t.Fatalf("encoded control flags = %#x, want DACL AR and AI", flags)
	}
	decoded, err := DecodeDescriptor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.String(); got != "D:ARAI" {
		t.Fatalf("decoded SDDL = %q, want D:ARAI", got)
	}
}

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
					Type:  systemAudit,
					Flags: failedAccess,
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
			name: "All standard rights",
			ace:  &ACE{Type: AccessAllowed, Mask: WriteOwner | WriteDACL | ReadControl | Delete, SID: MustSID("S-1-1-0")},
			want: "(A;;WOWDRCSD;;;WD)",
		},
		{
			name: "File specific rights",
			ace:  &ACE{Type: AccessAllowed, Mask: FileReadData | FileWriteData, SID: MustSID("S-1-1-0")},
			want: "(A;;0x3;;;WD)",
		},
		{
			name: "All access mask bits",
			ace:  &ACE{Type: AccessAllowed, Mask: 0xffffffff, SID: MustSID("S-1-1-0")},
			want: "(A;;0xffffffff;;;WD)",
		},
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
			name: "systemAudit with successfulAccess",
			ace: &ACE{
				Type:  systemAudit,
				Flags: successfulAccess,
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

func TestSDDLTypeConversion(t *testing.T) {
	parseTests := []struct {
		name  string
		input string
		want  ACEType
	}{
		{name: "SP", input: "SP", want: 0x13},
		{name: "audit callback", input: "XU", want: 0x0d},
		{name: "object allow callback", input: "ZA", want: 0x0b},
		{name: "resource attribute numeric type", input: "0x12", want: 0x12},
		{name: "alarm", input: "AL", want: 0x03},
		{name: "object alarm", input: "OL", want: 0x08},
		{name: "resource attribute", input: "RA", want: 0x12},
		{name: "process trust label", input: "TL", want: 0x14},
		{name: "access filter", input: "FL", want: 0x15},
	}
	for _, tc := range parseTests {
		t.Run("parse/"+tc.name, func(t *testing.T) {
			got, err := parseSDDLType(tc.input)
			if err != nil {
				t.Fatalf("parseSDDLType(%q) error = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("parseSDDLType(%q) = 0x%x, want 0x%x", tc.input, got, tc.want)
			}
		})
	}

	writeTests := []struct {
		name  string
		input ACEType
		want  string
	}{
		{name: "scoped policy ID", input: 0x13, want: "SP"},
		{name: "resource attribute", input: 0x12, want: "RA"},
		{name: "alarm", input: 0x03, want: "AL"},
		{name: "object alarm", input: 0x08, want: "OL"},
		{name: "audit callback", input: 0x0d, want: "XU"},
		{name: "object allow callback", input: 0x0b, want: "ZA"},
		{name: "process trust label", input: 0x14, want: "TL"},
		{name: "access filter", input: 0x15, want: "FL"},
		{name: "unknown type", input: 0xff, want: "0xff"},
	}
	for _, tc := range writeTests {
		t.Run("write/"+tc.name, func(t *testing.T) {
			var b strings.Builder
			tc.input.writeSDDL(&b)
			if got := b.String(); got != tc.want {
				t.Fatalf("ACE type %#x rendered as %q, want %q", byte(tc.input), got, tc.want)
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

func TestSDDLRightsAndCriticalFlagRoundTrip(t *testing.T) {
	tests := []struct {
		sddl  string
		mask  AccessMask
		flags ACEFlags
	}{
		{"D:(A;CR;FRFW;;;WD)", 0x0012019f, 0x20},
		{"D:(A;;FAFRFWFXGR;;;WD)", 0x801f01ff, 0},
		{"D:(A;;KRKWKX;;;WD)", 0x0002001f, 0},
		{"D:(A;;KAGR;;;WD)", 0x800f003f, 0},
		{"S:(ML;;NW;;;ME)", 1, 0},
		{"S:(ML;;NR;;;ME)", 2, 0},
		{"S:(ML;;NX;;;ME)", 4, 0},
		{"S:(ML;;NWNRNX;;;ME)", 7, 0},
	}
	for _, tc := range tests {
		t.Run(tc.sddl, func(t *testing.T) {
			d, err := ParseDescriptor(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			check := func(d *Descriptor) {
				t.Helper()
				acl := d.DACL
				if acl == nil {
					acl = d.SACL
				}
				ace := acl.ACEs[0]
				if ace.Mask != tc.mask || ace.Flags != tc.flags {
					t.Fatalf("mask/flags = %#x/%#x, want %#x/%#x", uint32(ace.Mask), byte(ace.Flags), uint32(tc.mask), byte(tc.flags))
				}
			}
			check(d)
			encoded, err := d.Encode()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeDescriptor(encoded)
			if err != nil {
				t.Fatal(err)
			}
			check(decoded)
			reparsed, err := ParseDescriptor(decoded.String())
			if err != nil {
				t.Fatal(err)
			}
			check(reparsed)
		})
	}
}

func TestSDDLFlagContext(t *testing.T) {
	for _, tc := range []struct {
		typ  ACEType
		flag string
		want string
	}{
		{systemAudit, "SA", "(AU;CISA;GR;;;WD)"},
		{systemAccessFilter, "TP", "(FL;CITP;GR;;;WD)"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			flags, err := parseSDDLFlags("CI"+tc.flag, tc.typ)
			if err != nil {
				t.Fatal(err)
			}
			if flags != 0x42 {
				t.Fatalf("flags = %#x, want 0x42", byte(flags))
			}
			ace := ACE{Type: tc.typ, Flags: flags, Mask: GenericRead, SID: MustSID("S-1-1-0")}
			if got := ace.String(); got != tc.want {
				t.Fatalf("ACE.String() = %q, want %q", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		typ   ACEType
		flags string
	}{
		{AccessAllowed, "TP"},
		{systemAudit, "TP"},
		{systemAccessFilter, "SA"},
		{systemAccessFilter, "SATP"},
		{AccessDenied, "CR"},
		{systemAudit, "CR"},
	} {
		if _, err := parseSDDLFlags(tc.flags, tc.typ); err == nil {
			t.Errorf("accepted flags %q for type %#x", tc.flags, tc.typ)
		}
	}
}

func TestSDDLAuditFlagsRequireAuditOrAlarm(t *testing.T) {
	// winnt.h limits SA and FA to audit and alarm ACE types, including
	// their object and callback variants. TP shares SA's bit but not its meaning.
	for typ := ACEType(0); typ <= systemAccessFilter; typ++ {
		valid := false
		switch typ {
		case systemAudit, systemAlarm, systemAuditObject, systemAlarmObject,
			systemAuditCallback, systemAlarmCallback, systemAuditCallbackObject, systemAlarmCallbackObject:
			valid = true
		}
		for _, token := range []string{"SA", "FA", "SAFA"} {
			t.Run(fmt.Sprintf("%02x/%s", byte(typ), token), func(t *testing.T) {
				flags, err := parseSDDLFlags("CIOI"+token, typ)
				if !valid {
					if err == nil {
						t.Fatalf("accepted %s for ACE type %#x", token, byte(typ))
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := ACEFlags(0x03)
				if strings.Contains(token, "SA") {
					want |= 0x40
				}
				if strings.Contains(token, "FA") {
					want |= 0x80
				}
				if flags != want {
					t.Fatalf("flags = %#x, want %#x", byte(flags), byte(want))
				}
			})
		}
	}
	for _, token := range []string{"SA", "FA", "SAFA"} {
		for _, sddl := range []string{
			"D:(A;" + token + ";FR;;;WD)",
			"D:(D;" + token + ";FR;;;WD)",
			"S:(ML;" + token + ";NW;;;ME)",
			"S:(SP;" + token + ";;;;S-1-17-1)",
		} {
			if d, err := ParseDescriptor(sddl); err == nil || d != nil {
				t.Errorf("ParseDescriptor(%q) = (%v, %v), want (nil, error)", sddl, d, err)
			}
		}
		if _, err := ParseDescriptor("S:(AU;" + token + ";GR;;;WD)"); err != nil {
			t.Fatalf("audit ACE with %s: %v", token, err)
		}
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
	if _, err := d.Encode(); err != nil {
		t.Fatalf("owner-only descriptor Encode() error = %v", err)
	}

	// Group only
	d, err = ParseDescriptor("G:BA")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := d.Group.String(), "S-1-5-32-544"; got != want {
		t.Fatalf("Group = %q, want %q", got, want)
	}
	if _, err := d.Encode(); err != nil {
		t.Fatalf("group-only descriptor Encode() error = %v", err)
	}

	// Empty DACL
	d, err = ParseDescriptor("D:")
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 0 || d.DACL.Protected {
		t.Fatalf("expected empty unprotected DACL, got %#v", d.DACL)
	}
	if _, err := d.Encode(); err != nil {
		t.Fatalf("empty DACL descriptor Encode() error = %v", err)
	}

	// Protected empty DACL
	d, err = ParseDescriptor("D:P")
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL == nil || len(d.DACL.ACEs) != 0 || !d.DACL.Protected {
		t.Fatalf("expected protected empty DACL, got %#v", d.DACL)
	}
	if _, err := d.Encode(); err != nil {
		t.Fatalf("protected empty DACL descriptor Encode() error = %v", err)
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
	if _, err := d.Encode(); err != nil {
		t.Fatalf("custom descriptor Encode() error = %v", err)
	}

	// USER_MODE_DRIVERS (UD) owner token
	d, err = ParseDescriptor("O:UD")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := d.Owner.String(), "S-1-5-84-0-0-0-0-0"; got != want {
		t.Fatalf("Owner UD = %q, want %q", got, want)
	}

	// ML and SP use the structured layouts specified by [MS-DTYP]
	// sections 2.4.4.13 and 2.4.4.16.
	extendedSDDL := "O:UDS:(ML;;0x1;;;S-1-16-8192)(SP;;0x0;;;S-1-17-1)"
	d, err = ParseDescriptor(extendedSDDL)
	if err != nil {
		t.Fatalf("ParseDescriptor(%q) error = %v", extendedSDDL, err)
	}
	if len(d.SACL.ACEs) != 2 || d.SACL.ACEs[0].Type != 0x11 || d.SACL.ACEs[1].Type != 0x13 {
		t.Fatalf("ML/SP ACEs were not structured: %#v", d.SACL)
	}

	// Numeric scoped policy ACE types are accepted as the same structured type.
	numericSP, err := ParseDescriptor("S:(0x13;;0x0;;;S-1-17-1)")
	if err != nil {
		t.Fatalf("numeric SP ParseDescriptor() error = %v", err)
	}
	if len(numericSP.SACL.ACEs) != 1 || numericSP.SACL.ACEs[0].Type != 0x13 {
		t.Fatalf("numeric SP ACE was not structured: %#v", numericSP.SACL)
	}

	// Decimal numeric rights
	d, err = ParseDescriptor("D:(A;;12345;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.DACL.ACEs) != 1 || d.DACL.ACEs[0].Mask != 12345 {
		t.Fatalf("decimal rights parse failed: %#v", d.DACL)
	}
	if _, err := d.Encode(); err != nil {
		t.Fatalf("decimal rights descriptor Encode() error = %v", err)
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
		{"trailing partial rights token", "D:(A;;FRF;;;WD)"},
		{"unknown concatenated rights token", "D:(A;;FRZZ;;;WD)"},
		{"numeric rights mixed with tokens", "D:(A;;FR0x1;;;WD)"},
		{"trust filter flag on allow ACE", "D:(A;TP;FR;;;WD)"},
		{"critical flag on deny ACE", "D:(D;CR;FR;;;WD)"},
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

func TestParseDescriptorRejectsUnencodableACEs(t *testing.T) {
	tests := []struct {
		name string
		sddl string
	}{
		{"conditional allow", "D:(XA;;;;;WD)"},
		{"conditional deny", "D:(XD;;;;;WD)"},
		{"conditional audit", "S:(XU;;;;;WD)"},
		{"unsupported numeric type", "S:(0x12;;;;;WD)"},
		{"alarm", "S:(AL;;;;;WD)"},
		{"object alarm", "S:(OL;;;;;WD)"},
		{"resource attribute", "S:(RA;;;;;WD)"},
		{"process trust label", "S:(TL;;;;;WD)"},
		{"access filter", "S:(FL;TP;;;;WD)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseDescriptor(tc.sddl)
			if err == nil || d != nil {
				t.Fatalf("ParseDescriptor(%q) = (%#v, %v), want (nil, error)", tc.sddl, d, err)
			}
			if !strings.Contains(err.Error(), "unsupported ACE type") {
				t.Fatalf("ParseDescriptor(%q) error = %v, want unsupported ACE type", tc.sddl, err)
			}
		})
	}
}

func TestParseDescriptorRejectsInvalidACEPlacement(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		want string
	}{
		{"access ACE in SACL", "S:(A;;FA;;;WD)", "DACL ACE type is invalid for SACL"},
		{"audit ACE in DACL", "D:(AU;FA;GR;;;WD)", "SACL ACE type is invalid for DACL"},
		{"mandatory label ACE in DACL", "D:(ML;;0x1;;;ME)", "SACL ACE type is invalid for DACL"},
		{"scoped policy ACE in DACL", "D:(SP;;0x0;;;S-1-17-1)", "SACL ACE type is invalid for DACL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseDescriptor(tc.sddl)
			if err == nil || d != nil {
				t.Fatalf("ParseDescriptor(%q) = (%#v, %v), want (nil, error)", tc.sddl, d, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseDescriptor(%q) error = %v, want %q", tc.sddl, err, tc.want)
			}
		})
	}
}

func TestParseDescriptorRejectsObjectACETypes(t *testing.T) {
	types := []string{
		"OA", "OD", "OU", "ZA",
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
