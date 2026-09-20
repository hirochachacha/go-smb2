package protocol

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestEvalSymlinkErrorRejectsOddLengths(t *testing.T) {
	t.Parallel()
	valid := encodeSymlinkErrorResponse(0, true, "target", "target")
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{name: "UnparsedPathLength", offset: 14},
		{name: "SubstituteNameLength", offset: 18},
		{name: "PrintNameLength", offset: 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(buf[tc.offset:tc.offset+2], 1)

			resolved, err := resolveTestSymlink(`dir\link\file`, buf)
			var invalid *InvalidResponseError
			require.ErrorAs(t, err, &invalid)
			require.Empty(t, resolved)
		})
	}
}

func TestResolveSymlinkExtendedRemoteUNC(t *testing.T) {
	t.Parallel()
	data := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\?\UNC\SERVER\share\dir`, `\\?\UNC\SERVER\share\dir`)
	resolved, err := resolveTestSymlink(`link\file`, data)
	require.NoError(t, err)
	require.Equal(t, `dir\file`, resolved)

	data = encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\?\UNC\other\share\dir`, `\\?\UNC\other\share\dir`)
	resolved, err = resolveTestSymlink(`link\file`, data)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\server\share\link\file`, linkErr.Path)
	require.Equal(t, `\\other\share\dir`, linkErr.Target)
	require.Equal(t, `\\other\share\dir\file`, linkErr.ResolvedPath)
}

func TestResolveSymlinkNormalizesAbsoluteDotsAndSuffixBoundary(t *testing.T) {
	t.Parallel()
	data := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\server\share\dir\.\sub\..\base`, `\\server\share\dir\.\sub\..\base`)
	resolved, err := resolveTestSymlink(`link\file`, data)
	require.NoError(t, err)
	require.Equal(t, `dir\base\file`, resolved)

	data = encodeSymlinkErrorResponse(0, false,
		`\\server\share\..\..\file`, `\\server\share\..\..\file`)
	resolved, err = resolveTestSymlink(`link`, data)
	require.NoError(t, err)
	require.Equal(t, `file`, resolved)

	data = encodeSymlinkErrorResponse(0, false,
		`\\other\share\..\..\file`, `\\other\share\..\..\file`)
	resolved, err = resolveTestSymlink(`link`, data)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\other\share\file`, linkErr.ResolvedPath)
}

func TestResolveSymlinkRejectsInvalidAbsoluteTargets(t *testing.T) {
	t.Parallel()
	for _, target := range []string{`C:\dir`, `D:\dir`, `\\?\C:\dir`, `other\share\file`} {
		t.Run(target, func(t *testing.T) {
			buf := encodeSymlinkErrorResponse(0, false, target, target)
			resolved, err := resolveTestSymlink(`link`, buf)
			var invalid *InvalidResponseError
			require.ErrorAs(t, err, &invalid)
			require.Empty(t, resolved)
		})
	}
}

func TestResolveSymlinkRelativePath(t *testing.T) {
	t.Parallel()
	unparsed := func(s string) uint16 { return uint16(utf16le.EncodedStringLen(s)) }

	tests := []struct {
		name               string
		path               string
		substituteName     string
		unparsedPathLength uint16
		want               string
		wantErr            bool
	}{
		{
			name:           "replace link name",
			path:           `sub1\sub2\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\sub2\target.txt`,
		},
		{
			name:           "parent reference in substitute name",
			path:           `sub1\sub2\symlink`,
			substituteName: `..\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "current directory reference in substitute name",
			path:           `sub1\symlink`,
			substituteName: `.\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "multiple parent references",
			path:           `a\b\link`,
			substituteName: `..\..\x`,
			want:           `x`,
		},
		{
			name:           "root level symlink",
			path:           `symlink`,
			substituteName: `target.txt`,
			want:           `target.txt`,
		},
		{
			name:           "parent beyond root stays at root",
			path:           `symlink`,
			substituteName: `..\target.txt`,
			wantErr:        true,
		},
		{
			name:           "result is share root",
			path:           `a\link`,
			substituteName: `..`,
			want:           ``,
		},
		{
			name:           "leading backslash is removed",
			path:           `symlink`,
			substituteName: `\target.txt`,
			wantErr:        true,
		},
		{
			name:               "unparsed suffix is preserved",
			path:               `sub1\symlink\dir2\file.txt`,
			substituteName:     `..\target.txt`,
			unparsedPathLength: unparsed(`\dir2\file.txt`),
			want:               `target.txt\dir2\file.txt`,
		},
		{
			name:               "unparsed suffix with dot components is normalized",
			path:               `sub1\symlink\dir2\..\file.txt`,
			substituteName:     `target.txt`,
			unparsedPathLength: unparsed(`\dir2\..\file.txt`),
			want:               `sub1\target.txt\file.txt`,
		},
		{
			name:           "non-ASCII components are preserved",
			path:           `sub1\リンク\symlink`,
			substituteName: `..\ターゲット.txt`,
			want:           `sub1\ターゲット.txt`,
		},
		{
			name:           "names containing dots are preserved",
			path:           `sub1\file..txt\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\file..txt\target.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symErr := &wire.SymbolicLinkErrorResponse{
				UnparsedPathLength: tt.unparsedPathLength,
				Flags:              wire.SYMLINK_FLAG_RELATIVE,
				SubstituteName:     tt.substituteName,
				PrintName:          tt.substituteName,
			}
			buf := make([]byte, symErr.Size())
			symErr.Encode(buf)

			resolved, err := resolveTestSymlink(tt.path, buf)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
		})
	}
}

func TestResolveSymlinkResolvedNameLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		path        string
		unparsed    uint16
		substitute  string
		relative    bool
		want        string
		wantNameLen int
		wantErr     bool
	}{
		{
			name:        "relative resolved name at limit",
			path:        "d" + strings.Repeat("a", 32765),
			unparsed:    65530,
			substitute:  "t",
			relative:    true,
			want:        "t\\" + strings.Repeat("a", 32765),
			wantNameLen: 65534,
		},
		{
			name:       "relative resolved name over limit",
			path:       "d" + strings.Repeat("a", 32766),
			unparsed:   65532,
			substitute: strings.Repeat("t", 100),
			relative:   true,
			wantErr:    true,
		},
		{
			name:        "supplementary plane resolved name at limit",
			path:        "d" + strings.Repeat("\U0001F600", 16382) + "a",
			unparsed:    65530,
			substitute:  "t",
			relative:    true,
			want:        "t\\" + strings.Repeat("\U0001F600", 16382) + "a",
			wantNameLen: 65534,
		},
		{
			name:       "supplementary plane resolved name over limit",
			path:       "d" + strings.Repeat("\U0001F600", 16383) + "a",
			unparsed:   65534,
			substitute: "t",
			relative:   true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeSymlinkErrorResponse(tt.unparsed, tt.relative, tt.substitute, tt.substitute)
			resolved, err := resolveTestSymlink(tt.path, buf)
			if tt.wantErr {
				require.ErrorContains(t, err, "protocol: resolved symbolic link path exceeds uint16")
				require.Equal(t, "", resolved)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
			require.Equal(t, tt.wantNameLen, utf16le.EncodedStringLen(resolved))
		})
	}
}

func TestResolveSymlinkResolvedNameNormalizedWithinLimit(t *testing.T) {
	t.Parallel()
	// The raw substitution overflows the uint16 name bound, but eliminating the
	// "." and ".." components brings it back within the limit. [MS-SMB2]
	// 2.2.2.2.1.1 requires those components to be removed during symlink
	// processing, so the retry must succeed.
	comp := strings.Repeat("t", 250)
	target := strings.Repeat(comp+`\`, 129) + comp // 32629 chars, 65258 bytes
	suffix := strings.Repeat(`\..`, 130)           // 390 chars, 780 bytes; raw total > 65535 bytes
	path := "d" + suffix
	unparsed := uint16(utf16le.EncodedStringLen(suffix))

	buf := encodeSymlinkErrorResponse(unparsed, true, target, "")
	resolved, err := resolveTestSymlink(path, buf)
	require.NoError(t, err)
	require.Equal(t, "", resolved)
}

func TestResolveSymlinkReturnsCrossShareContinuation(t *testing.T) {
	t.Parallel()
	buf := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false, `\\other\share\dir`, `\\other\share\dir`)
	resolved, err := resolveTestSymlink(`link\file`, buf)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\server\share\link\file`, linkErr.Path)
	require.Equal(t, `\\other\share\dir\file`, linkErr.ResolvedPath)
}

func TestShare_MaxPayloadSizeCappedByCredits(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// Initially, maxCredits = 1 -> capped to 1 * 64KB = 64KB
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))

	// Replenish to 4 credits (maxCreditBalance) -> capped to 4 * 64KB = 256KB
	c.account.charge(3)
	require.Equal(t, 256*1024, fs.MaxReadSize(0))
	require.Equal(t, 256*1024, fs.MaxWriteSize(0))
	require.Equal(t, 256*1024, fs.MaxTransactSize(0))

	// If maxCreditBalance is large and credits are granted, scales up to winMaxPayloadSize (1MB)
	c.account.maxCreditBalance = 128
	c.account.charge(30)
	require.Equal(t, 1024*1024, fs.MaxReadSize(0))
	require.Equal(t, 1024*1024, fs.MaxWriteSize(0))
	require.Equal(t, 1024*1024, fs.MaxTransactSize(0))
}

func TestShare_MaxPayloadSizeReservesCompoundCredits(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// Replenish to maxCreditBalance so the cap is 4 * 64KB.
	c.account.charge(3)

	// A standalone request may use the whole credit cap.
	require.Equal(t, 256*1024, fs.MaxReadSize(0))
	require.Equal(t, 256*1024, fs.MaxWriteSize(0))
	require.Equal(t, 256*1024, fs.MaxTransactSize(0))

	// A compound leaves room for its single-credit companions.
	require.Equal(t, 128*1024, fs.MaxWriteSize(2))
	require.Equal(t, 128*1024, fs.MaxTransactSize(2))
	require.Equal(t, 192*1024, fs.MaxTransactSize(1))

	// Sizing never drops below a single credit.
	require.Equal(t, 64*1024, fs.MaxTransactSize(8))
}

func TestShare_MaxPayloadSizeRespectsServerAdvertisedValues(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// server advertises 32KB (< singleCreditMaxPayloadSize) -> respect it
	require.Equal(t, 32*1024, fs.MaxReadSize(0))
	require.Equal(t, 32*1024, fs.MaxWriteSize(0))
	require.Equal(t, 32*1024, fs.MaxTransactSize(0))

	// non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))

	// without LARGE_MTU, server-advertised sizes are still respected
	c = &conn{
		account:         openAccount(4),
		capabilities:    0,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s = &session{conn: c}
	tc = &Tree{session: s}
	fs = tc
	require.Equal(t, 32*1024, fs.MaxReadSize(0))
	require.Equal(t, 32*1024, fs.MaxWriteSize(0))
	require.Equal(t, 32*1024, fs.MaxTransactSize(0))

	// without LARGE_MTU, non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))
}

func resolveTestSymlink(name string, data []byte) (string, error) {
	req := &Request{tc: &Tree{serverName: "server", shareName: "share"}}
	return req.resolveSymlink(context.Background(), name,
		&ResponseError{Code: uint32(erref.STATUS_STOPPED_ON_SYMLINK)}, data)
}

func encodeSymlinkErrorResponse(unparsedPathLength uint16, relative bool, substituteName, printName string) []byte {
	flags := uint32(0)
	if relative {
		flags = wire.SYMLINK_FLAG_RELATIVE
	}
	symErr := &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: unparsedPathLength,
		Flags:              flags,
		SubstituteName:     substituteName,
		PrintName:          printName,
	}
	buf := make([]byte, symErr.Size())
	symErr.Encode(buf)
	return buf
}
