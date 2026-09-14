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

func makeDFSInternalStorageResponse(version uint16, networks ...string) []byte {
	fixedSize := 34
	if version == 2 {
		fixedSize = 22
	}
	path := append(utf16le.EncodeStringToBytes(`\domain\root`), 0, 0)
	entries := make([]byte, 0)
	for _, networkName := range networks {
		network := append(utf16le.EncodeStringToBytes(networkName), 0, 0)
		alternate := append(utf16le.EncodeStringToBytes(`\domain\root-alt`), 0, 0)
		entrySize := fixedSize + len(path) + len(alternate) + len(network)
		entry := make([]byte, entrySize)
		le.PutUint16(entry[:2], version)
		le.PutUint16(entry[2:4], uint16(entrySize))
		if version == 2 {
			le.PutUint32(entry[12:16], 300)
			le.PutUint16(entry[16:18], uint16(fixedSize))
			le.PutUint16(entry[18:20], uint16(fixedSize+len(path)))
			le.PutUint16(entry[20:22], uint16(fixedSize+len(path)+len(alternate)))
		} else {
			le.PutUint32(entry[8:12], 300)
			le.PutUint16(entry[12:14], uint16(fixedSize))
			le.PutUint16(entry[14:16], uint16(fixedSize+len(path)))
			le.PutUint16(entry[16:18], uint16(fixedSize+len(path)+len(alternate)))
		}
		if version == 4 && len(entries) == 0 {
			le.PutUint16(entry[6:8], ReferralTargetBoundary)
		}
		copy(entry[fixedSize:], path)
		copy(entry[fixedSize+len(path):], alternate)
		copy(entry[fixedSize+len(path)+len(alternate):], network)
		entries = append(entries, entry...)
	}
	b := make([]byte, 8+len(entries))
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(`\domain\root`)))
	le.PutUint16(b[2:4], uint16(len(networks)))
	copy(b[8:], entries)
	return b
}

func makeDFSInternalNameListResponse(version uint16) []byte {
	special := append(utf16le.EncodeStringToBytes(`\special`), 0, 0)
	expandedOne := append(utf16le.EncodeStringToBytes(`\expanded-one`), 0, 0)
	expandedTwo := append(utf16le.EncodeStringToBytes(`\expanded-two`), 0, 0)
	entrySize := 18 + len(special) + len(expandedOne) + len(expandedTwo)
	b := make([]byte, 8+entrySize)
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], version)
	le.PutUint16(b[10:12], uint16(entrySize))
	le.PutUint32(b[16:20], 300)
	le.PutUint16(b[14:16], ReferralNameList)
	if version == 4 {
		le.PutUint16(b[14:16], ReferralNameList|ReferralTargetBoundary)
	}
	le.PutUint16(b[20:22], 18)
	le.PutUint16(b[22:24], 2)
	le.PutUint16(b[24:26], uint16(18+len(special)))
	copy(b[8+18:], special)
	copy(b[8+18+len(special):], expandedOne)
	copy(b[8+18+len(special)+len(expandedOne):], expandedTwo)
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

func TestDFSReferralStringsInsideEntries(t *testing.T) {
	for _, version := range []uint16{2, 3, 4} {
		b := makeDFSInternalStorageResponse(version, `\\server\\share`, `\\server2\\share`)
		response, err := ParseReferralResponse(b, `\domain\root`)
		if err != nil {
			t.Fatalf("V%d: %v", version, err)
		}
		for i, entry := range response.Entries {
			expectedNetwork := []string{`\\server\\share`, `\\server2\\share`}[i]
			if entry.DFSPath != `\domain\root` || entry.DFSAlternatePath != `\domain\root-alt` || entry.NetworkAddress != expectedNetwork {
				t.Fatalf("V%d entry %d = %#v", version, i, entry)
			}
		}
	}
}

func TestDFSReferralNameListStringsInsideEntries(t *testing.T) {
	for _, version := range []uint16{3, 4} {
		response, err := ParseReferralResponse(makeDFSInternalNameListResponse(version), `\domain\root`)
		if err != nil {
			t.Fatalf("V%d: %v", version, err)
		}
		entry := response.Entries[0]
		if entry.SpecialName != `\special` || entry.ExpandedNames[0] != `\expanded-one` || entry.ExpandedNames[1] != `\expanded-two` {
			t.Fatalf("V%d name-list entry = %#v", version, entry)
		}
	}
}

func makeDFSMixedStorageResponse(version uint16) []byte {
	fixedSize := 34
	if version == 2 {
		fixedSize = 22
	}
	path := append(utf16le.EncodeStringToBytes(`\domain\root`), 0, 0)
	alternate := append(utf16le.EncodeStringToBytes(`\domain\root-alt`), 0, 0)
	network := append(utf16le.EncodeStringToBytes(`\\server\\share`), 0, 0)
	firstSize := fixedSize + len(path) + len(alternate) + len(network)
	secondOff := 8 + firstSize
	entriesEnd := secondOff + fixedSize
	b := make([]byte, entriesEnd+len(path)+len(alternate)+len(network))
	le.PutUint16(b[2:4], 2)
	for i, off := range []int{8, secondOff} {
		le.PutUint16(b[off:off+2], version)
		le.PutUint16(b[off+2:off+4], uint16(firstSize))
		if i == 1 {
			le.PutUint16(b[off+2:off+4], uint16(fixedSize))
		}
		if version == 2 {
			le.PutUint32(b[off+12:off+16], 300)
		} else {
			le.PutUint32(b[off+8:off+12], 300)
		}
		if version == 4 && i == 0 {
			le.PutUint16(b[off+6:off+8], ReferralTargetBoundary)
		}
	}
	firstPathField := 8 + 12
	if version == 2 {
		firstPathField = 8 + 16
	}
	le.PutUint16(b[firstPathField:firstPathField+2], uint16(fixedSize))
	le.PutUint16(b[firstPathField+2:firstPathField+4], uint16(fixedSize+len(path)))
	le.PutUint16(b[firstPathField+4:firstPathField+6], uint16(fixedSize+len(path)+len(alternate)))
	secondStringOff := entriesEnd - secondOff
	pathField := secondOff + 12
	if version == 2 {
		pathField = secondOff + 16
	}
	le.PutUint16(b[pathField:pathField+2], uint16(secondStringOff))
	le.PutUint16(b[pathField+2:pathField+4], uint16(secondStringOff+len(path)))
	le.PutUint16(b[pathField+4:pathField+6], uint16(secondStringOff+len(path)+len(alternate)))
	copy(b[8+fixedSize:], path)
	copy(b[8+fixedSize+len(path):], alternate)
	copy(b[8+fixedSize+len(path)+len(alternate):], network)
	shared := entriesEnd
	copy(b[shared:], path)
	copy(b[shared+len(path):], alternate)
	copy(b[shared+len(path)+len(alternate):], network)
	return b
}

func TestDFSReferralAllowsInternalAndSharedStrings(t *testing.T) {
	for _, version := range []uint16{2, 3, 4} {
		response, err := ParseReferralResponse(makeDFSMixedStorageResponse(version), `\domain\root`)
		if err != nil {
			t.Fatalf("V%d: %v", version, err)
		}
		for i, entry := range response.Entries {
			if entry.DFSPath != `\domain\root` || entry.DFSAlternatePath != `\domain\root-alt` || entry.NetworkAddress != `\\server\\share` {
				t.Fatalf("V%d entry %d = %#v", version, i, entry)
			}
		}
	}
}

func makeDFSSharedNameListResponse(version uint16, count int) []byte {
	entrySize := 18
	special := append(utf16le.EncodeStringToBytes(`\special`), 0, 0)
	expanded := append(utf16le.EncodeStringToBytes(`\expanded`), 0, 0)
	entriesEnd := 8 + entrySize*count
	b := make([]byte, entriesEnd+len(special)+2*len(expanded))
	le.PutUint16(b[2:4], uint16(count))
	for i := 0; i < count; i++ {
		off := 8 + entrySize*i
		le.PutUint16(b[off:off+2], version)
		le.PutUint16(b[off+2:off+4], uint16(entrySize))
		flags := uint16(ReferralNameList)
		if version == 4 && i == 0 {
			flags |= ReferralTargetBoundary
		}
		le.PutUint16(b[off+6:off+8], flags)
		le.PutUint16(b[off+12:off+14], uint16(entriesEnd-off))
		le.PutUint16(b[off+14:off+16], 2)
		expandedOffset := entriesEnd - off + len(special)
		le.PutUint16(b[off+16:off+18], uint16(expandedOffset))
	}
	copy(b[entriesEnd:], special)
	copy(b[entriesEnd+len(special):], expanded)
	copy(b[entriesEnd+len(special)+len(expanded):], expanded)
	return b
}

func TestDFSReferralNameListSharedStringsMultipleEntries(t *testing.T) {
	for _, version := range []uint16{3, 4} {
		response, err := ParseReferralResponse(makeDFSSharedNameListResponse(version, 2), `\domain\root`)
		if err != nil {
			t.Fatalf("V%d: %v", version, err)
		}
		if len(response.Entries) != 2 {
			t.Fatalf("V%d entries = %#v", version, response.Entries)
		}
		for i, entry := range response.Entries {
			if entry.SpecialName != `\special` || len(entry.ExpandedNames) != 2 || entry.ExpandedNames[1] != `\expanded` {
				t.Fatalf("V%d entry %d = %#v", version, i, entry)
			}
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

func TestDFSReferralRejectsCrossingStringRegions(t *testing.T) {
	fixedReference := makeDFSInternalStorageResponse(3, `\\server\\share`)
	le.PutUint16(fixedReference[8+12:8+14], 8)

	otherEntryReference := makeDFSInternalStorageResponse(3, `\\server\\share`, `\\server2\\share`)
	second := 8 + int(le.Uint16(otherEntryReference[8+2:8+4]))
	le.PutUint16(otherEntryReference[8+12:8+14], uint16(second+34-8))

	crossingString := makeDFSInternalStorageResponse(3, `\\server\\share`)
	le.PutUint16(crossingString[8+2:8+4], 36)

	nameList := makeDFSInternalNameListResponse(3)
	specialLen := len(append(utf16le.EncodeStringToBytes(`\special`), 0, 0))
	firstExpandedLen := len(append(utf16le.EncodeStringToBytes(`\expanded-one`), 0, 0))
	le.PutUint16(nameList[8+2:8+4], uint16(18+specialLen+firstExpandedLen))

	outOfRange := makeDFSInternalStorageResponse(3, `\\server\\share`)
	le.PutUint16(outOfRange[8+12:8+14], 0xfffe)
	odd := makeDFSInternalStorageResponse(3, `\\server\\share`)
	le.PutUint16(odd[8+12:8+14], 35)

	for name, b := range map[string][]byte{
		"fixed reference":       fixedReference,
		"other entry reference": otherEntryReference,
		"internal string":       crossingString,
		"expanded name region":  nameList,
		"out of range":          outOfRange,
		"odd offset":            odd,
	} {
		if response, err := ParseReferralResponse(b, `\domain\root`); err == nil || response != nil {
			t.Errorf("accepted %s: response=%#v error=%v", name, response, err)
		}
	}
}

func TestDFSReferralCachedStringHonorsLimit(t *testing.T) {
	buf := append(utf16le.EncodeStringToBytes(`\long-string`), 0, 0)
	ctx := &dfsDecoderContext{cache: make(map[int]string)}
	if _, _, err := ctx.decodeDFSStringAt(buf, 0, len(buf), "cached"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ctx.decodeDFSStringAt(buf, 0, 4, "cached"); err == nil {
		t.Fatal("cached string escaped its region limit")
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

		pathOff := uint16(entrySize * (entryCount - i))
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
