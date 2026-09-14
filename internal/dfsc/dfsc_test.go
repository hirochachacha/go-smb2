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
		ttlOffset := 8
		pathOffset := 12
		if version == 2 {
			// [MS-DFSC] 2.2.5.2 places Proximity before TimeToLive and
			// the three string offsets at bytes 16, 18, and 20.
			ttlOffset = 12
			pathOffset = 16
		}
		le.PutUint32(entries[off+ttlOffset:off+ttlOffset+4], 300)
		path := utf16le.EncodeStringToBytes(`\domain\root`)
		path = append(path, 0, 0)
		net := append(utf16le.EncodeStringToBytes(name), 0, 0)
		pathOff := uint16(entrySize*(len(names)-i) + len(strings))
		netOff := pathOff + uint16(len(path))
		le.PutUint16(entries[off+pathOffset:off+pathOffset+2], pathOff)
		le.PutUint16(entries[off+pathOffset+2:off+pathOffset+4], pathOff)
		le.PutUint16(entries[off+pathOffset+4:off+pathOffset+6], netOff)
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
		if version == 2 {
			expectedNetworks := []string{`\\server\share`, `\\server2\share`}
			for i, entry := range r.Entries {
				if entry.TimeToLive != 300 || entry.DFSPath != `\domain\root` || entry.DFSAlternatePath != `\domain\root` || entry.NetworkAddress != expectedNetworks[i] {
					t.Fatalf("V2 entry %d = %#v", i, entry)
				}
			}
		}
		if version == 4 && !r.Entries[0].TargetSetBoundary {
			t.Fatal("V4 target boundary not parsed")
		}
	}
}

func TestDFSReferralV2FixedLayout(t *testing.T) {
	path := append(utf16le.EncodeStringToBytes(`\domain\root`), 0, 0)
	alternate := append(utf16le.EncodeStringToBytes(`\domain\root-alt`), 0, 0)
	network := append(utf16le.EncodeStringToBytes(`\\server\share`), 0, 0)
	entrySize := 22
	entry := make([]byte, entrySize)
	flags := uint16(0xffff)
	le.PutUint16(entry[0:2], 2)
	le.PutUint16(entry[2:4], uint16(entrySize))
	le.PutUint16(entry[6:8], flags)
	// Proximity is reserved in V2 and must not displace TimeToLive.
	le.PutUint32(entry[8:12], 0x01020304)
	le.PutUint32(entry[12:16], 0x11223344)
	pathOffset := uint16(entrySize)
	alternateOffset := pathOffset + uint16(len(path))
	networkOffset := alternateOffset + uint16(len(alternate))
	le.PutUint16(entry[16:18], pathOffset)
	le.PutUint16(entry[18:20], alternateOffset)
	le.PutUint16(entry[20:22], networkOffset)

	b := make([]byte, 8+len(entry)+len(path)+len(alternate)+len(network))
	le.PutUint16(b[2:4], 1)
	copy(b[8:], entry)
	strings := append(append(path, alternate...), network...)
	copy(b[8+len(entry):], strings)

	response, err := ParseReferralResponse(b, `\domain\root`)
	if err != nil {
		t.Fatal(err)
	}
	got := response.Entries[0]
	if got.TimeToLive != 0x11223344 || got.DFSPath != `\domain\root` || got.DFSAlternatePath != `\domain\root-alt` || got.NetworkAddress != `\\server\share` {
		t.Fatalf("V2 entry = %#v", got)
	}
	if got.EntryFlags != flags || got.NameListReferral {
		t.Fatalf("V2 flags were interpreted: %#v", got)
	}
}

func TestDFSReferralV2RejectsTruncatedAndInvalidOffsets(t *testing.T) {
	valid := makeDFSResponse(2, `\\server\share`)
	truncated := append([]byte(nil), valid[:8+21]...)
	le.PutUint16(truncated[8+2:8+4], 21)
	oddOffset := append([]byte(nil), valid...)
	le.PutUint16(oddOffset[8+16:8+18], 23)
	outsideOffset := append([]byte(nil), valid...)
	le.PutUint16(outsideOffset[8+20:8+22], 0xfffe)

	for name, b := range map[string][]byte{
		"truncated":      truncated,
		"odd offset":     oddOffset,
		"outside offset": outsideOffset,
	} {
		if _, err := ParseReferralResponse(b, `\domain\root`); err == nil {
			t.Errorf("%s V2 referral was accepted", name)
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

func TestDFSReferralResponseOversized(t *testing.T) {
	oversized := make([]byte, maxReferralResponseSize+1)
	le.PutUint16(oversized[:2], 0)
	le.PutUint16(oversized[2:4], 0)
	if _, err := ParseReferralResponse(oversized, `\domain\root`); err == nil {
		t.Fatal("expected error for response exceeding maxReferralResponseSize")
	}
}

func TestDFSReferralSharedStringMemoization(t *testing.T) {
	// Create multiple entries pointing to the identical offsets for DFSPath and NetworkAddress.
	entryCount := 50
	entrySize := 34
	path := append(utf16le.EncodeStringToBytes(`\domain\root`), 0, 0)
	net := append(utf16le.EncodeStringToBytes(`\\server\share`), 0, 0)
	strings := append(append([]byte(nil), path...), net...)

	totalEntriesSize := entryCount * entrySize
	b := make([]byte, 8+totalEntriesSize+len(strings))
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(`\domain\root`)))
	le.PutUint16(b[2:4], uint16(entryCount))

	for i := 0; i < entryCount; i++ {
		off := 8 + i*entrySize
		le.PutUint16(b[off:off+2], 3)
		le.PutUint16(b[off+2:off+4], uint16(entrySize))
		le.PutUint32(b[off+8:off+12], 300)

		pathOff := uint16(entrySize*(entryCount-i))
		netOff := pathOff + uint16(len(path))
		le.PutUint16(b[off+12:off+14], pathOff)
		le.PutUint16(b[off+14:off+16], pathOff)
		le.PutUint16(b[off+16:off+18], netOff)
	}
	copy(b[8+totalEntriesSize:], strings)

	resp, err := ParseReferralResponse(b, `\domain\root`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Entries) != entryCount {
		t.Fatalf("expected %d entries, got %d", entryCount, len(resp.Entries))
	}
	for i, e := range resp.Entries {
		if e.DFSPath != `\domain\root` || e.NetworkAddress != `\\server\share` {
			t.Fatalf("entry %d corrupted: %#v", i, e)
		}
	}
}

func TestDFSReferralDecodedBudgetExceeded(t *testing.T) {
	// Generate an entry where the string exceeds maxDFSStringLength
	longStr := make([]byte, (maxDFSStringLength+10)*2+2)
	for i := 0; i < len(longStr)-2; i += 2 {
		longStr[i] = 'a'
	}
	// NUL terminate
	longStr[len(longStr)-2] = 0
	longStr[len(longStr)-1] = 0

	entrySize := 34
	b := make([]byte, 8+entrySize+len(longStr))
	le.PutUint16(b[:2], 0)
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], uint16(entrySize))
	le.PutUint32(b[16:20], 300)
	le.PutUint16(b[20:22], uint16(entrySize))
	le.PutUint16(b[22:24], uint16(entrySize))
	le.PutUint16(b[24:26], uint16(entrySize))
	copy(b[8+entrySize:], longStr)

	if _, err := ParseReferralResponse(b, `\domain\root`); err == nil {
		t.Fatal("expected error for string exceeding maxDFSStringLength")
	}
}
