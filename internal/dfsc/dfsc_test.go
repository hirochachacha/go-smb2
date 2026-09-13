package dfsc

import (
	"bytes"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

func TestDFSReferralRequestEncoding(t *testing.T) {
	r := &ReferralRequest{MaxReferralLevel: 4, RequestFileName: `\\domain\root\link`}
	b := make([]byte, r.Size())
	r.Encode(b)
	if got := le.Uint16(b[:2]); got != 4 {
		t.Fatalf("level = %d", got)
	}
	if !bytes.Equal(b[2:8], []byte{'\\', 0, 'd', 0, 'o', 0}) {
		t.Fatalf("path does not have one leading slash: %x", b[2:8])
	}
	if !bytes.Equal(b[len(b)-2:], []byte{0, 0}) {
		t.Fatal("request is not NUL terminated")
	}
	r.RequestFileName = `\domain\root\link`
	b2 := make([]byte, r.Size())
	r.Encode(b2)
	if !bytes.Equal(b, b2) {
		t.Fatal("leading slash normalization changed encoding")
	}
}

func makeDFSResponse(version uint16, names ...string) []byte {
	entrySize := 8
	if version == 2 {
		entrySize = 22
	}
	if version >= 3 {
		entrySize = 34
	}
	entries := make([]byte, entrySize*len(names))
	strings := make([]byte, 0)
	if version == 1 {
		entries = nil
		for _, name := range names {
			entry := make([]byte, 8)
			le.PutUint16(entry[:2], 1)
			le.PutUint16(entry[4:6], 0)
			le.PutUint16(entry[6:8], 0)
			entry = append(entry, utf16le.EncodeStringToBytes(name)...)
			entry = append(entry, 0, 0)
			le.PutUint16(entry[2:4], uint16(len(entry)))
			entries = append(entries, entry...)
		}
	}
	for i, name := range names {
		if version == 1 {
			continue
		}
		off := i * entrySize
		le.PutUint16(entries[off:off+2], version)
		le.PutUint16(entries[off+2:off+4], uint16(entrySize))
		if version == 1 {
			le.PutUint16(entries[off+4:off+6], 0)
			le.PutUint16(entries[off+6:off+8], 0)
			value := append(utf16le.EncodeStringToBytes(name), 0, 0)
			entries = append(entries, value...)
			le.PutUint16(entries[off+2:off+4], uint16(len(entries)-off))
			continue
		}
		le.PutUint32(entries[off+8:off+12], 300)
		path := utf16le.EncodeStringToBytes(`\domain\root`)
		path = append(path, 0, 0)
		net := append(utf16le.EncodeStringToBytes(name), 0, 0)
		pathOff := uint16(entrySize*(len(names)-i) + len(strings))
		netOff := pathOff + uint16(len(path))
		le.PutUint16(entries[off+12:off+14], pathOff)
		le.PutUint16(entries[off+14:off+16], pathOff)
		le.PutUint16(entries[off+16:off+18], netOff)
		strings = append(strings, path...)
		strings = append(strings, net...)
	}
	b := make([]byte, 8+len(entries)+len(strings))
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(`\domain\root`)))
	le.PutUint16(b[2:4], uint16(len(names)))
	copy(b[8:], entries)
	copy(b[8+len(entries):], strings)
	return b
}

func TestDFSReferralResponseVersions(t *testing.T) {
	for _, version := range []uint16{1, 2, 3, 4} {
		b := makeDFSResponse(version, `\\server\share`, `\\server2\share`)
		if version == 4 {
			// V4 is V3 plus the target-set flag in ReferralEntryFlags.
			le.PutUint16(b[8+6:8+8], ReferralTargetBoundary)
		}
		r, err := ParseReferralResponse(b, `\domain\root`)
		if err != nil {
			t.Fatalf("V%d: %v", version, err)
		}
		if len(r.Entries) != 2 || r.Entries[1].NetworkAddress != `\\server2\share` {
			t.Fatalf("V%d entries = %#v", version, r.Entries)
		}
		if version == 4 && !r.Entries[0].TargetSetBoundary {
			t.Fatal("V4 target boundary not parsed")
		}
	}
}

func TestDFSReferralV3NameList(t *testing.T) {
	entrySize := 18
	special := append(utf16le.EncodeStringToBytes(`\special`), 0, 0)
	expanded := append(utf16le.EncodeStringToBytes(`\expanded`), 0, 0)
	b := make([]byte, 8+entrySize+len(special)+len(expanded))
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], uint16(entrySize))
	le.PutUint16(b[14:16], ReferralNameList)
	le.PutUint16(b[20:22], uint16(entrySize))
	le.PutUint16(b[22:24], 1)
	le.PutUint16(b[24:26], uint16(entrySize+len(special)))
	copy(b[8+entrySize:], special)
	copy(b[8+entrySize+len(special):], expanded)

	r, err := ParseReferralResponse(b, `\domain\root`)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsNameList() || r.Entries[0].SpecialName != `\special` || len(r.Entries[0].ExpandedNames) != 1 || r.Entries[0].ExpandedNames[0] != `\expanded` {
		t.Fatalf("name-list referral = %#v", r)
	}
}

func TestDFSReferralRejectsMalformedInput(t *testing.T) {
	valid := makeDFSResponse(3, `\\server\share`)
	cases := [][]byte{
		valid[:7], valid[:8+3], append([]byte(nil), valid...), append([]byte(nil), valid...), append([]byte(nil), valid...),
	}
	// Count that does not fit and an entry with zero Size.
	le.PutUint16(cases[1][2:4], 2)
	le.PutUint16(cases[2][8+2:8+4], 0)
	// Odd and out-of-range string offsets.
	le.PutUint16(cases[3][8+12:8+14], 39)
	le.PutUint16(cases[4][8+16:8+18], 0xffff)
	for i, b := range cases {
		if _, err := ParseReferralResponse(b, `\domain\root`); err == nil {
			t.Errorf("case %d accepted malformed referral", i)
		}
	}
}

func TestDFSReferralAllowsEmptyResponse(t *testing.T) {
	b := make([]byte, 8)
	le.PutUint16(b[:2], 0)
	r, err := ParseReferralResponse(b, `\domain\root\missing`)
	if err != nil || r.NumberOfReferrals != 0 || len(r.Entries) != 0 {
		t.Fatalf("empty response = %#v, %v", r, err)
	}
}

func TestDFSReferralRejectsInconsistentStoragePaths(t *testing.T) {
	b := makeDFSResponse(3, `\\server\share`, `\\server2\share`)
	second := 8 + 34
	// Point the second entry's DFSPath at a distinct, valid UTF-16 string.
	// Its offset remains in the shared string area, so this exercises the
	// semantic invariant rather than the generic offset bounds checks.
	pathOff := le.Uint16(b[second+12 : second+14])
	absolute := second + int(pathOff)
	if absolute < 0 || absolute+2 > len(b) {
		t.Fatal("test referral string offset is invalid")
	}
	le.PutUint16(b[absolute:absolute+2], 'x')
	if _, err := ParseReferralResponse(b, `\domain\root`); err == nil {
		t.Fatal("accepted inconsistent DFS paths")
	}
}
