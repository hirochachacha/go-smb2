package security

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSID(t *testing.T) {
	tests := []struct {
		text string
		want *SID
	}{
		{
			text: "S-1-5-32-544",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 5,
				SubAuthority:        []uint32{32, 544},
			},
		},
		{
			text: "S-1-0xffffffff0000-0-4294967295",
			want: &SID{
				Revision:            1,
				IdentifierAuthority: 0xffffffff0000,
				SubAuthority:        []uint32{0, 1<<32 - 1},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.text, func(t *testing.T) {
			got, err := ParseSID(test.text)
			if err != nil {
				t.Fatalf("ParseSID() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParseSID() = %#v, want %#v", got, test.want)
			}
			if got.String() != test.text {
				t.Fatalf("SID.String() = %q, want %q", got.String(), test.text)
			}
		})
	}
}

func TestParseSIDCanonicalizesHexadecimalAuthority(t *testing.T) {
	sid, err := ParseSID("S-1-0X000100000000-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sid.String(), "S-1-0x000100000000-1"; got != want {
		t.Fatalf("SID.String() = %q, want %q", got, want)
	}
}

func TestParseSIDRejectsInvalidString(t *testing.T) {
	tooManySubAuthorities := "S-1-5" + strings.Repeat("-1", 16)
	for _, text := range []string{
		"",
		"s-1-5-18",
		"S-2-5-18",
		"S-1-5",
		"S-1-05-18",
		"S-1-4294967296-18",
		"S-1-0x000000000005-18",
		"S-1-0x1000000000000-18",
		"S-1-5-01",
		"S-1-5-4294967296",
		"S-1-5-",
		tooManySubAuthorities,
	} {
		t.Run(text, func(t *testing.T) {
			if _, err := ParseSID(text); err == nil {
				t.Fatal("ParseSID() accepted an invalid SID")
			}
		})
	}
}

func TestMustSID(t *testing.T) {
	if got := MustSID("S-1-5-18").String(); got != "S-1-5-18" {
		t.Fatalf("MustSID().String() = %q", got)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("MustSID() did not panic")
		}
	}()
	MustSID("not a SID")
}

func TestNilSIDString(t *testing.T) {
	var sid *SID
	if got := sid.String(); got != "<nil>" {
		t.Fatalf("SID.String() = %q, want %q", got, "<nil>")
	}
}

func TestSIDSizeAndEncode(t *testing.T) {
	var nilSID *SID
	if nilSID.Size() != 0 {
		t.Fatalf("nilSID.Size() = %d, want 0", nilSID.Size())
	}
	buf := make([]byte, 10)
	nilSID.Encode(buf) // should not panic

	sid := MustSID("S-1-5-32-544")
	wantSize := 8 + 4*2 // 16 bytes
	if sid.Size() != wantSize {
		t.Fatalf("sid.Size() = %d, want %d", sid.Size(), wantSize)
	}

	shortBuf := make([]byte, wantSize-1)
	sid.Encode(shortBuf) // should not panic or write

	encoded := make([]byte, wantSize)
	sid.Encode(encoded)
	expected := []byte{
		1,                // revision
		2,                // sub authority count
		0, 0, 0, 0, 0, 5, // authority
		32, 0, 0, 0, // sub authority 1
		32, 2, 0, 0, // sub authority 2 (544 = 0x0220)
	}
	if !reflect.DeepEqual(encoded, expected) {
		t.Fatalf("sid.Encode() = %x, want %x", encoded, expected)
	}
}
