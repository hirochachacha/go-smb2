package dfsc

// The structures in this file are from [MS-DFSC] 2.2.2, 2.2.4 and
// 2.2.5.  They deliberately live below the SMB2 IOCTL layer: an IOCTL
// response contains an opaque DFS buffer and must not be interpreted by the
// generic SMB2 response decoder.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

var le = binary.LittleEndian

const (
	ReferralLevel4 = 4

	ReferralHeaderServers  = 0x00000001
	ReferralHeaderStorage  = 0x00000002
	ReferralHeaderFailback = 0x00000004

	ReferralNameList       = 0x0002
	ReferralTargetBoundary = 0x0004
)

// ReferralRequest is REQ_GET_DFS_REFERRAL. RequestFileName is a DFS path,
// not a user-visible UNC path; Encode normalizes it to exactly one leading
// backslash as required by [MS-DFSC] 2.2.1.
type ReferralRequest struct {
	MaxReferralLevel uint16
	RequestFileName  string
}

func (r *ReferralRequest) normalizedPath() string {
	p := r.RequestFileName
	for len(p) > 0 && p[0] == '\\' {
		p = p[1:]
	}
	return "\\" + p
}

func (r *ReferralRequest) Size() int {
	return 2 + utf16le.EncodedStringLen(r.normalizedPath()) + 2
}

func (r *ReferralRequest) Encode(p []byte) {
	path := r.normalizedPath()
	need := r.Size()
	if len(p) < need {
		return
	}
	le.PutUint16(p[:2], r.MaxReferralLevel)
	n := utf16le.EncodeString(p[2:], path)
	le.PutUint16(p[2+n:2+n+2], 0)
}

// ReferralEntry is one target from a V2/V3/V4 referral. V1 referrals use
// the same target representation, but do not have a DFS path prefix or TTL.
type ReferralEntry struct {
	Version           uint16
	Size              uint16
	ServerType        uint16
	EntryFlags        uint16
	TimeToLive        uint32
	DFSPath           string
	DFSAlternatePath  string
	NetworkAddress    string
	TargetSetBoundary bool
	NameListReferral  bool
	SpecialName       string
	ExpandedNames     []string
}

// ReferralResponse is the validated representation of RESP_GET_DFS_REFERRAL.
type ReferralResponse struct {
	PathConsumed        uint16
	NumberOfReferrals   uint16
	ReferralHeaderFlags uint32
	Entries             []ReferralEntry
}

func (r *ReferralResponse) IsNameList() bool {
	return len(r.Entries) > 0 && r.Entries[0].NameListReferral
}

const (
	maxReferralResponseSize = 64 * 1024
	maxDFSStringLength      = 4096
	maxDFSTotalDecodedBytes = 256 * 1024
)

// ParseReferralResponse validates and decodes a DFS referral buffer. The
// requestPath argument is used to validate PathConsumed in bytes. A malformed
// buffer returns an error and never exposes a partially parsed entry.
func ParseReferralResponse(buf []byte, requestPath string) (*ReferralResponse, error) {
	if len(buf) < 8 {
		return nil, fmt.Errorf("DFS referral header is truncated")
	}
	if len(buf) > maxReferralResponseSize {
		return nil, fmt.Errorf("DFS referral response exceeds maximum size")
	}
	path := normalizeDFSPath(requestPath)
	pathLen := utf16le.EncodedStringLen(path)
	pathConsumed := le.Uint16(buf[:2])
	if pathConsumed&1 != 0 || uint64(pathConsumed) > uint64(pathLen) || !dfsUTF16Boundary(path, int(pathConsumed)) {
		return nil, fmt.Errorf("invalid DFS referral PathConsumed")
	}
	count := le.Uint16(buf[2:4])
	flags := le.Uint32(buf[4:8])
	if count == 0 {
		return &ReferralResponse{PathConsumed: pathConsumed, NumberOfReferrals: 0, ReferralHeaderFlags: flags}, nil
	}

	entriesEnd := 8
	if uint64(count)*4 > uint64(len(buf)-entriesEnd) {
		return nil, fmt.Errorf("DFS referral entry count is truncated")
	}
	type referralSpan struct {
		off, size int
		version   uint16
	}
	spans := make([]referralSpan, 0, int(count))
	for i := 0; i < int(count); i++ {
		if len(buf)-entriesEnd < 4 {
			return nil, fmt.Errorf("DFS referral entry header is truncated")
		}
		entryVersion := le.Uint16(buf[entriesEnd : entriesEnd+2])
		size := le.Uint16(buf[entriesEnd+2 : entriesEnd+4])
		if size == 0 || int(size) < 4 || uint64(size) > uint64(len(buf)-entriesEnd) {
			return nil, fmt.Errorf("invalid DFS referral entry size")
		}
		if entryVersion < 1 || entryVersion > ReferralLevel4 {
			return nil, fmt.Errorf("unsupported DFS referral version %d", entryVersion)
		}
		spans = append(spans, referralSpan{off: entriesEnd, size: int(size), version: entryVersion})
		entriesEnd += int(size)
	}
	version := spans[0].version
	ctx := &dfsDecoderContext{
		cache: make(map[int]string),
	}
	entries := make([]ReferralEntry, 0, int(count))
	for _, span := range spans {
		if span.version != version {
			return nil, fmt.Errorf("mixed DFS referral versions")
		}
		entry, err := parseDFSReferralEntry(ctx, buf, span.off, span.size, span.version, entriesEnd)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	for _, entry := range entries {
		if !entry.NameListReferral && entry.NetworkAddress == "" {
			return nil, fmt.Errorf("DFS referral has no target network address")
		}
	}
	nameList := entries[0].NameListReferral
	pathPrefix := entries[0].DFSPath
	for _, entry := range entries {
		if entry.NameListReferral != nameList {
			return nil, fmt.Errorf("mixed DFS name-list and storage referrals")
		}
		if !nameList && !equalDFSPath(pathPrefix, entry.DFSPath) {
			return nil, fmt.Errorf("inconsistent DFS path prefixes")
		}
	}
	if version == 4 && entries[0].EntryFlags&ReferralTargetBoundary == 0 {
		return nil, fmt.Errorf("DFS V4 first target lacks target-set boundary")
	}
	return &ReferralResponse{PathConsumed: pathConsumed, NumberOfReferrals: count,
		ReferralHeaderFlags: flags, Entries: entries}, nil
}

func equalDFSPath(a, b string) bool { return strings.EqualFold(a, b) }

func normalizeDFSPath(path string) string {
	for len(path) > 0 && path[0] == '\\' {
		path = path[1:]
	}
	return "\\" + path
}

type dfsDecoderContext struct {
	cache        map[int]string
	totalDecoded int
}

func (ctx *dfsDecoderContext) decodeDFSStringAt(buf []byte, off, limit int, what string) (string, int, error) {
	if s, ok := ctx.cache[off]; ok {
		n := utf16le.EncodedStringLen(s) + 2
		if n > limit {
			return "", 0, fmt.Errorf("invalid DFS %s bounds", what)
		}
		return s, n, nil
	}
	s, n, err := decodeDFSStringAt(buf, off, limit, what)
	if err != nil {
		return "", 0, err
	}
	ctx.totalDecoded += len(s)
	if ctx.totalDecoded > maxDFSTotalDecodedBytes {
		return "", 0, fmt.Errorf("DFS referral decoded string budget exceeded")
	}
	ctx.cache[off] = s
	return s, n, nil
}

func (ctx *dfsDecoderContext) decodeDFSOffsetString(buf []byte, entryOff, entrySize, entriesEnd int, offset uint16, what string) (string, error) {
	if offset == 0 || int(offset)&1 != 0 {
		return "", fmt.Errorf("invalid DFS %s offset", what)
	}
	absolute := uint64(entryOff) + uint64(offset)
	if absolute < uint64(entriesEnd) || absolute >= uint64(len(buf)) || absolute&1 != 0 {
		return "", fmt.Errorf("DFS %s offset is outside string buffer", what)
	}
	s, _, err := ctx.decodeDFSStringAt(buf, int(absolute), len(buf)-int(absolute), what)
	return s, err
}

func (ctx *dfsDecoderContext) decodeDFSString(p []byte, off, limit int, what string) (string, error) {
	if off < 0 || limit < 0 || off > len(p) || limit > len(p)-off {
		return "", fmt.Errorf("invalid DFS %s bounds", what)
	}
	s, _, err := ctx.decodeDFSStringAt(p, off, limit, what)
	return s, err
}

func parseDFSReferralEntry(ctx *dfsDecoderContext, buf []byte, off, size int, version uint16, entriesEnd int) (ReferralEntry, error) {
	entry := ReferralEntry{Version: version, Size: uint16(size)}
	p := buf[off : off+size]
	if version == 1 {
		if size < 8 {
			return entry, fmt.Errorf("DFS V1 entry is truncated")
		}
		entry.ServerType = le.Uint16(p[4:6])
		entry.EntryFlags = le.Uint16(p[6:8])
		name, err := ctx.decodeDFSString(buf, off+8, size-8, "V1 target")
		if err != nil {
			return entry, err
		}
		entry.NetworkAddress = name
		return entry, nil
	}
	if version == 2 && size < 22 {
		return entry, fmt.Errorf("DFS V%d entry is truncated", version)
	}
	if version >= 3 && size < 18 {
		return entry, fmt.Errorf("DFS V%d entry is truncated", version)
	}
	entry.ServerType = le.Uint16(p[4:6])
	entry.EntryFlags = le.Uint16(p[6:8])
	entry.TimeToLive = le.Uint32(p[8:12])
	entry.NameListReferral = entry.EntryFlags&ReferralNameList != 0
	entry.TargetSetBoundary = version == 4 && entry.EntryFlags&ReferralTargetBoundary != 0
	if entry.NameListReferral {
		if version == 2 {
			return entry, fmt.Errorf("DFS V2 cannot contain a name-list referral")
		}
		if size < 18 {
			return entry, fmt.Errorf("DFS name-list entry is truncated")
		}
		special := le.Uint16(p[12:14])
		names := le.Uint16(p[14:16])
		expanded := le.Uint16(p[16:18])
		var specialErr error
		entry.SpecialName, specialErr = ctx.decodeDFSOffsetString(buf, off, size, entriesEnd, special, "special name")
		if specialErr != nil {
			return entry, specialErr
		}
		if names > 0 {
			if expanded == 0 {
				return entry, fmt.Errorf("DFS expanded names offset is zero")
			}
			cur := int(expanded)
			for i := uint16(0); i < names; i++ {
				if cur < size || cur > len(buf)-off || off+cur < entriesEnd {
					return entry, fmt.Errorf("invalid DFS expanded name offset")
				}
				absolute := off + cur
				name, n, err := ctx.decodeDFSStringAt(buf, absolute, len(buf)-absolute, "expanded name")
				if err != nil {
					return entry, err
				}
				entry.ExpandedNames = append(entry.ExpandedNames, name)
				if n > len(buf)-absolute || cur > len(buf)-off-n {
					return entry, fmt.Errorf("DFS expanded name offset overflows")
				}
				cur += n
			}
		}
		return entry, nil
	}
	if version >= 3 && size < 34 {
		return entry, fmt.Errorf("DFS V%d entry is truncated", version)
	}
	dfsOff := le.Uint16(p[12:14])
	altOff := le.Uint16(p[14:16])
	netOff := le.Uint16(p[16:18])
	var err error
	if entry.DFSPath, err = ctx.decodeDFSOffsetString(buf, off, size, entriesEnd, dfsOff, "DFS path"); err != nil {
		return entry, err
	}
	if entry.DFSAlternatePath, err = ctx.decodeDFSOffsetString(buf, off, size, entriesEnd, altOff, "DFS alternate path"); err != nil {
		return entry, err
	}
	if entry.NetworkAddress, err = ctx.decodeDFSOffsetString(buf, off, size, entriesEnd, netOff, "network address"); err != nil {
		return entry, err
	}
	return entry, nil
}

func dfsUTF16Boundary(path string, consumed int) bool {
	if consumed < 0 {
		return false
	}
	encoded := utf16le.EncodeStringToBytes(path)
	if consumed == 0 || consumed == len(encoded) {
		return true
	}
	if consumed > len(encoded) {
		return false
	}
	// A boundary between a surrogate pair is not a complete UTF-16 scalar.
	if consumed >= 2 {
		prev := le.Uint16(encoded[consumed-2:])
		if prev >= 0xd800 && prev <= 0xdbff {
			return false
		}
	}
	return consumed&1 == 0
}

func decodeDFSStringAt(p []byte, off, limit int, what string) (string, int, error) {
	if off&1 != 0 || limit < 2 || off < 0 || off > len(p) || limit > len(p)-off {
		return "", 0, fmt.Errorf("invalid DFS %s bounds", what)
	}
	for n := 0; n+1 < limit; n += 2 {
		if n/2 > maxDFSStringLength {
			return "", 0, fmt.Errorf("DFS %s exceeds maximum length %d", what, maxDFSStringLength)
		}
		if p[off+n] == 0 && p[off+n+1] == 0 {
			data := p[off : off+n]
			if !validUTF16LE(data) {
				return "", 0, fmt.Errorf("invalid DFS %s UTF-16", what)
			}
			return string(utf16.Decode(func() []uint16 {
				u := make([]uint16, len(data)/2)
				for i := range u {
					u[i] = le.Uint16(data[2*i:])
				}
				return u
			}())), n + 2, nil
		}
	}
	return "", 0, fmt.Errorf("DFS %s is not NUL terminated", what)
}

func validUTF16LE(data []byte) bool {
	if len(data)&1 != 0 {
		return false
	}
	for i := 0; i < len(data); i += 2 {
		u := le.Uint16(data[i:])
		if u >= 0xd800 && u <= 0xdbff {
			if i+2 >= len(data) {
				return false
			}
			u2 := le.Uint16(data[i+2:])
			if u2 < 0xdc00 || u2 > 0xdfff {
				return false
			}
			i += 2
		} else if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
	}
	return true
}
