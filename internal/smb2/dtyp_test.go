package smb2

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

func TestFiletimeTime(t *testing.T) {
	const (
		unixEpochFiletime = uint64(116444736000000000)
		modernFiletime    = uint64(133444736001234567)
		boundaryFiletime  = uint64(208678456368547758)
		futureFiletime    = uint64(283696992000000000)
	)

	tests := []struct {
		name  string
		ticks uint64
		want  time.Time
	}{
		{
			name:  "zero",
			ticks: 0,
			want:  time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "unix epoch minus 100ns",
			ticks: unixEpochFiletime - 1,
			want:  time.Date(1969, time.December, 31, 23, 59, 59, 999999900, time.UTC),
		},
		{
			name:  "unix epoch",
			ticks: unixEpochFiletime,
			want:  time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "modern date",
			ticks: modernFiletime,
			want:  time.Date(2023, time.November, 14, 22, 13, 20, 123456700, time.UTC),
		},
		{
			name:  "2262 boundary",
			ticks: boundaryFiletime,
			want:  time.Date(2262, time.April, 11, 23, 47, 16, 854775800, time.UTC),
		},
		{
			name:  "2262 boundary plus 100ns",
			ticks: boundaryFiletime + 1,
			want:  time.Date(2262, time.April, 11, 23, 47, 16, 854775900, time.UTC),
		},
		{
			name:  "2500",
			ticks: futureFiletime,
			want:  time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "high bit",
			ticks: uint64(1 << 63),
			want:  time.Date(30828, time.September, 14, 2, 48, 5, 477580800, time.UTC),
		},
		{
			name:  "maximum uint64",
			ticks: ^uint64(0),
			want:  time.Date(60056, time.May, 28, 5, 36, 10, 955161500, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &Filetime{
				LowDateTime:  uint32(tt.ticks),
				HighDateTime: uint32(tt.ticks >> 32),
			}
			require.True(t, ft.Time().Equal(tt.want), "Filetime.Time() = %v, want %v", ft.Time(), tt.want)

			buf := make([]byte, ft.Size())
			ft.Encode(buf)
			dec := FiletimeDecoder(buf)
			require.True(t, dec.Time().Equal(tt.want), "FiletimeDecoder.Time() = %v, want %v", dec.Time(), tt.want)

			encoded := TimeToFiletime(dec.Time())
			require.NotNil(t, encoded)
			require.Equal(t, tt.ticks, uint64(encoded.HighDateTime)<<32|uint64(encoded.LowDateTime))
		})
	}

	var nilFt *Filetime
	require.True(t, nilFt.Time().IsZero())
}

func TestSIDPacketRepresentation(t *testing.T) {
	sid := &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 544}}
	want := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0}
	got := make([]byte, sid.Size())
	sid.Encode(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("SID bytes = %x, want %x", got, want)
	}
	decoded := SidDecoder(want)
	if decoded.IsInvalid() || decoded.Decode().IdentifierAuthority != 5 {
		t.Fatalf("known SID did not decode: %#v", decoded.Decode())
	}
}

func TestSidDecoderRejectsCorruptInputWithoutPanic(t *testing.T) {
	for length := range 24 {
		input := make([]byte, length)
		if length > 1 {
			input[0] = 1
			input[1] = 15
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("SID decoder panicked for %d-byte input: %v", length, recovered)
				}
			}()
			if !SidDecoder(input).IsInvalid() {
				t.Errorf("corrupt %d-byte SID was accepted", length)
			}
			_ = SidDecoder(input).Decode()
		}()
	}
}

func TestTrimUNCPrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantRem string
		wantOk  bool
	}{
		{name: "standard UNC", input: `\\server\share`, wantRem: `server\share`, wantOk: true},
		{name: "NT prefix UNC", input: `\??\UNC\server\share`, wantRem: `server\share`, wantOk: true},
		{name: "Win32 prefix UNC", input: `\\?\UNC\server\share`, wantRem: `server\share`, wantOk: true},
		{name: "case-insensitive UNC prefix", input: `\??\unc\server\share`, wantRem: `server\share`, wantOk: true},
		{name: "Win32 drive path is not UNC", input: `\\?\C:\dir\file.txt`, wantRem: `\\?\C:\dir\file.txt`, wantOk: false},
		{name: "NT drive path is not UNC", input: `\??\C:\dir\file.txt`, wantRem: `\??\C:\dir\file.txt`, wantOk: false},
		{name: "no prefix", input: `server\share`, wantRem: `server\share`, wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.input)
			rem, ok := TrimUNCPrefix(b)
			require.Equal(t, tt.wantOk, ok, "TrimUNCPrefix ok for %s", tt.input)
			require.Equal(t, tt.wantRem, utf16le.DecodeToString(rem), "TrimUNCPrefix rem for %s", tt.input)
			require.Equal(t, tt.wantOk, HasUNCPrefix(b), "HasUNCPrefix for %s", tt.input)
		})
	}
}

func TestIsInvalidUNC(t *testing.T) {
	tests := []struct {
		name    string
		unc     string
		invalid bool
	}{
		{name: "simple host and share", unc: `\\server\share`, invalid: false},
		{name: "with file", unc: `\\server\share\file.txt`, invalid: false},
		{name: "with subdirs", unc: `\\server\share\sub\dir\file.txt`, invalid: false},
		{name: "IPv4 host", unc: `\\192.168.1.1\share\file.txt`, invalid: false},
		{name: "IPv6 bracket host", unc: `\\[0:0:0:0:0:0:0:1]\share\file.txt`, invalid: false},
		{name: "NT prefix UNC", unc: `\??\UNC\server\share\file.txt`, invalid: false},
		{name: "Win32 prefix UNC", unc: `\\?\UNC\server\share\file.txt`, invalid: false},
		{name: "empty", unc: "", invalid: true},
		{name: "no prefix", unc: `server\share`, invalid: true},
		{name: "missing share", unc: `\\server`, invalid: true},
		{name: "missing share with slash", unc: `\\server\`, invalid: true},
		{name: "trailing slash after share", unc: `\\server\share\`, invalid: true},
		{name: "host with space", unc: `\\server name\share`, invalid: true},
		{name: "dot host", unc: `\\.\share`, invalid: true},
		{name: "dotdot host", unc: `\\..\share`, invalid: true},
		{name: "dot share", unc: `\\server\.`, invalid: true},
		{name: "dotdot share", unc: `\\server\..`, invalid: true},
		{name: "empty component in object", unc: `\\server\share\dir\\file.txt`, invalid: true},
		{name: "invalid share char", unc: `\\server\share*`, invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.unc)
			require.Equal(t, tt.invalid, IsInvalidUNC(b), "UNC: %s", tt.unc)
		})
	}
}

func TestIsInvalidSharePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		invalid bool
	}{
		{name: "simple", path: `\\server\share`, invalid: false},
		{name: "IPv4", path: `\\127.0.0.1\share`, invalid: false},
		{name: "IPv6 bracket", path: `\\[0:0:0:0:0:0:0:1]\share`, invalid: false},
		{name: "share max len 80", path: `\\server\` + strings.Repeat("s", 80), invalid: false},
		{name: "host max len 255", path: `\\` + strings.Repeat("h", 255) + `\share`, invalid: false},
		{name: "trailing slash", path: `\\server\share\`, invalid: true},
		{name: "with file", path: `\\server\share\file`, invalid: true},
		{name: "no prefix", path: `server\share`, invalid: true},
		{name: "missing share", path: `\\server`, invalid: true},
		{name: "missing share with slash", path: `\\server\`, invalid: true},
		{name: "dot host", path: `\\.\share`, invalid: true},
		{name: "dotdot host", path: `\\..\share`, invalid: true},
		{name: "dot share", path: `\\server\.`, invalid: true},
		{name: "dotdot share", path: `\\server\..`, invalid: true},
		{name: "host with space", path: `\\server name\share`, invalid: true},
		{name: "invalid share char", path: `\\server\share*`, invalid: true},
		{name: "share over limit 81", path: `\\server\` + strings.Repeat("s", 81), invalid: true},
		{name: "host over limit 256", path: `\\` + strings.Repeat("h", 256) + `\share`, invalid: true},
		{name: "NT prefix rejected for SharePath", path: `\??\UNC\server\share`, invalid: true},
		{name: "Win32 prefix rejected for SharePath", path: `\\?\UNC\server\share`, invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.path)
			require.Equal(t, tt.invalid, IsInvalidSharePath(b), "path: %s", tt.path)
		})
	}
}

func TestIsInvalidShareName(t *testing.T) {
	tests := []struct {
		name    string
		share   string
		invalid bool
	}{
		{name: "simple", share: "share", invalid: false},
		{name: "IPC$", share: "IPC$", invalid: false},
		{name: "with spaces", share: "my share", invalid: false},
		{name: "with punctuation", share: "share-1_test#2", invalid: false},
		{name: "at limit 80 chars", share: strings.Repeat("s", 80), invalid: false},
		{name: "empty", share: "", invalid: true},
		{name: "over limit 81 chars", share: strings.Repeat("s", 81), invalid: true},
		{name: "dot directory .", share: ".", invalid: true},
		{name: "dot directory ..", share: "..", invalid: true},
		{name: "contains quote", share: `sh"are`, invalid: true},
		{name: "contains backslash", share: `sh\are`, invalid: true},
		{name: "contains slash", share: `sh/are`, invalid: true},
		{name: "contains left bracket", share: `sh[are`, invalid: true},
		{name: "contains right bracket", share: `sh]are`, invalid: true},
		{name: "contains colon", share: `sh:are`, invalid: true},
		{name: "contains pipe", share: `sh|are`, invalid: true},
		{name: "contains less than", share: `sh<are`, invalid: true},
		{name: "contains greater than", share: `sh>are`, invalid: true},
		{name: "contains plus", share: `sh+are`, invalid: true},
		{name: "contains equals", share: `sh=are`, invalid: true},
		{name: "contains semicolon", share: `sh;are`, invalid: true},
		{name: "contains comma", share: `sh,are`, invalid: true},
		{name: "contains asterisk", share: `sh*are`, invalid: true},
		{name: "contains question mark", share: `sh?are`, invalid: true},
		{name: "contains null", share: "sh\x00are", invalid: true},
		{name: "contains newline", share: "sh\nare", invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.share)
			require.Equal(t, tt.invalid, IsInvalidShareName(b), "share: %s", tt.share)
		})
	}
}

func TestIsInvalidSubstituteName(t *testing.T) {
	tests := []struct {
		name    string
		sub     string
		flags   uint32
		invalid bool
	}{
		{name: "empty", sub: "", invalid: true},
		{name: "relative file", sub: "target.txt", flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative subpath", sub: `dir\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative dotdot", sub: `..\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative multiple dotdot", sub: `..\..\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative dot", sub: `.\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative just dotdot", sub: `..`, flags: SYMLINK_FLAG_RELATIVE, invalid: false},
		{name: "relative leading backslash", sub: `\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative LongNamePrefix NT", sub: `\??\C:\dir\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative LongNamePrefix Win32", sub: `\\?\C:\dir\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative UNC standard", sub: `\\server\share\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative UNC NT prefix", sub: `\??\UNC\server\share\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative UNC Win32 prefix", sub: `\\?\UNC\server\share\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "relative drive path", sub: `C:\dir\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "UNC standard", sub: `\\server\share\target.txt`, invalid: false},
		{name: "UNC NT prefix", sub: `\??\UNC\server\share\target.txt`, invalid: false},
		{name: "UNC Win32 prefix", sub: `\\?\UNC\server\share\target.txt`, invalid: false},
		{name: "UNC with dotdot", sub: `\??\UNC\server\share\..\target.txt`, invalid: false},
		{name: "NT device drive path", sub: `\??\C:\dir\target.txt`, invalid: false},
		{name: "Win32 device drive path", sub: `\\?\C:\dir\target.txt`, invalid: false},
		{name: "drive path", sub: `C:\dir\target.txt`, invalid: false},
		{name: "drive root", sub: `C:\`, invalid: false},
		{name: "NT device root", sub: `\??\C:\`, invalid: false},
		{name: "absolute relative path", sub: `dir\target.txt`, flags: 0, invalid: true},
		{name: "invalid char", sub: `dir\tar*get.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "trailing slash", sub: `dir\target\`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "consecutive slashes", sub: `dir\\target.txt`, flags: SYMLINK_FLAG_RELATIVE, invalid: true},
		{name: "invalid device non-drive", sub: `\??\invalid`, invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := utf16le.EncodeStringToBytes(tt.sub)
			require.Equal(t, tt.invalid, isInvalidSubstituteName(b, tt.flags), "sub: %s", tt.sub)
		})
	}
}

func TestNormalizeSymlinkTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expected string
	}{
		{
			name:     "NT UNC prefix",
			target:   `\??\UNC\server\share`,
			expected: `\\server\share`,
		},
		{
			name:     "Win32 UNC prefix",
			target:   `\\?\UNC\server\share`,
			expected: `\\server\share`,
		},
		{
			name:     "NT drive prefix",
			target:   `\??\C:\path`,
			expected: `C:\path`,
		},
		{
			name:     "Win32 drive prefix",
			target:   `\\?\C:\path`,
			expected: `C:\path`,
		},
		{
			name:     "plain path",
			target:   `dir\target.txt`,
			expected: `dir\target.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSymlinkTarget(tt.target)
			if got != tt.expected {
				t.Errorf("normalizeSymlinkTarget(%q) = %q, want %q", tt.target, got, tt.expected)
			}
		})
	}
}

func TestFiletimeDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		invalid bool
	}{
		{
			name:    "nil",
			buf:     nil,
			invalid: true,
		},
		{
			name:    "too short",
			buf:     make([]byte, 7),
			invalid: true,
		},
		{
			name:    "zero timestamp",
			buf:     make([]byte, 8),
			invalid: false,
		},
		{
			name: "positive timestamp",
			buf: func() []byte {
				b := make([]byte, 8)
				le.PutUint32(b[:4], 100)
				le.PutUint32(b[4:8], 200)
				return b
			}(),
			invalid: false,
		},
		{
			name: "max positive timestamp",
			buf: func() []byte {
				b := make([]byte, 8)
				le.PutUint32(b[:4], 0xffffffff)
				le.PutUint32(b[4:8], 0x7fffffff)
				return b
			}(),
			invalid: false,
		},
		{
			name: "negative timestamp high bit set",
			buf: func() []byte {
				b := make([]byte, 8)
				le.PutUint32(b[4:8], 0x80000000)
				return b
			}(),
			invalid: true,
		},
		{
			name: "all ones (-1)",
			buf: func() []byte {
				b := make([]byte, 8)
				le.PutUint32(b[:4], 0xffffffff)
				le.PutUint32(b[4:8], 0xffffffff)
				return b
			}(),
			invalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.invalid, FiletimeDecoder(tt.buf).IsInvalid())
		})
	}
}
