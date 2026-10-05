package protocol

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"testing/synctest"
	"time"

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

func TestSymlinkWithoutErrorData(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, target       string
		malformed, denied, cycle bool
	}{
		{name: "final link", path: `dir\link`, target: "target"},
		{name: "ancestor link", path: `dir\link\child`, target: "target"},
		{name: "malformed reparse data", path: `dir\link`, target: "target", malformed: true},
		{name: "probe denied", path: `dir\link`, target: "target", denied: true},
		{name: "cycle", path: `dir\link`, target: "link", cycle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				tree, peer := newTestTree(t)
				transport := NewTransport(peer)
				done := make(chan struct{})
				var names []string
				var queries, updates int
				go func() {
					defer close(done)
					for {
						packet, err := readMsg(transport)
						if err != nil {
							return
						}
						create := wire.CreateRequestDecoder(wire.PacketCodec(packet).Body())
						if create.IsInvalid() {
							t.Error("invalid CREATE")
							return
						}
						name := create.Name()
						names = append(names, name)
						probe := create.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT != 0
						var responses []compoundResponse
						if probe && name == `dir\link` && !tc.denied {
							queries++
							var output wire.Encoder = &wire.SymbolicLinkReparseDataBuffer{Flags: wire.SYMLINK_FLAG_RELATIVE, SubstituteName: tc.target, PrintName: tc.target}
							if tc.malformed {
								output = rawEncoder{1}
							}
							responses = []compoundResponse{
								{packet: testTreeCreateResponse(wire.FileId{}), status: erref.STATUS_SUCCESS},
								{packet: &wire.IoctlResponse{CtlCode: wire.FSCTL_GET_REPARSE_POINT, FileId: wire.FileId{}, Output: output}, status: erref.STATUS_SUCCESS},
								{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
							}
						} else if !probe && strings.HasPrefix(name, `dir\target`) {
							updates++
							responses = []compoundResponse{
								{packet: testTreeCreateResponse(wire.FileId{}), status: erref.STATUS_SUCCESS},
								{packet: &wire.SetInfoResponse{}, status: erref.STATUS_SUCCESS},
								{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
							}
						} else {
							first := erref.STATUS_STOPPED_ON_SYMLINK
							command := wire.SMB2_SET_INFO
							if probe {
								command = wire.SMB2_IOCTL
								if tc.denied {
									first = erref.STATUS_ACCESS_DENIED
								}
							}
							responses = []compoundResponse{
								{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, status: first},
								{packet: &wire.ErrorResponse{CommandCode: command}, status: erref.STATUS_FILE_CLOSED},
								{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}, status: erref.STATUS_FILE_CLOSED},
							}
						}
						if err := sendCompoundResponse(transport, packet, responses); err != nil {
							return
						}
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				request := tree.Request().WithFollowSymlinks(true).
					Create(tc.path, wire.DELETE, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL).
					SetInfo(wire.SMB2_0_INFO_FILE, wire.FileDispositionInformation, 0, &wire.FileDispositionInformationEncoder{DeletePending: 1}).Close()
				res, err := request.Do(ctx)
				if res != nil {
					res.Close()
				}
				peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				<-done
				switch {
				case tc.malformed:
					var invalid *InvalidResponseError
					require.ErrorAs(t, err, &invalid)
					require.Equal(t, 1, queries)
					require.Zero(t, updates)
				case tc.denied:
					require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
					require.Zero(t, queries)
					require.Zero(t, updates)
				case tc.cycle:
					require.ErrorContains(t, err, "Too many levels of symbolic links")
					require.LessOrEqual(t, queries, clientMaxSymlinkDepth)
					require.Zero(t, updates)
				default:
					require.NoError(t, err)
					require.Equal(t, 1, queries)
					require.Equal(t, 1, updates)
					if tc.path == `dir\link\child` {
						require.Equal(t, []string{tc.path, tc.path, `dir\link`, `dir\target\child`}, names)
					} else {
						require.Equal(t, []string{tc.path, tc.path, `dir\target`}, names)
					}
				}
			})
		})
	}
}
