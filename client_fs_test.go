package smb2

import (
	"errors"
	iofs "io/fs"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func TestDirFS(t *testing.T) {
	share := &Share{}

	fs := share.DirFS(`dir/`).(*wfs)
	if got, want := fs.root, `dir`; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
	if got, want := fs.path(`file.txt`), `dir\file.txt`; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	fs = share.DirFS(`dir\`).(*wfs)
	if got, want := fs.root, `dir`; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
	if got, want := fs.path(`file.txt`), `dir\file.txt`; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	fs = share.DirFS(`/`).(*wfs)
	if got, want := fs.root, ``; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
}

func TestDirFSRejectsBackslashPath(t *testing.T) {
	share := &Share{}

	for _, root := range []string{`dir/`, ``} {
		fs := share.DirFS(root)

		for _, name := range []string{`sub\..\secret`, `sub\secret`} {
			if _, err := fs.Open(name); !errors.Is(err, iofs.ErrInvalid) {
				t.Errorf("Open(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
			}
			if sfs, ok := fs.(iofs.StatFS); ok {
				if _, err := sfs.Stat(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("Stat(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.StatFS")
			}
			if rfs, ok := fs.(iofs.ReadFileFS); ok {
				if _, err := rfs.ReadFile(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadFile(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.ReadFileFS")
			}
			if gfs, ok := fs.(iofs.GlobFS); ok {
				if _, err := gfs.Glob(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("Glob(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.GlobFS")
			}
		}
	}
}

func TestDirFSPatternMetaCharacters(t *testing.T) {
	share := &Share{}

	tests := []struct {
		root     string
		pattern  string
		expected string
	}{
		{`dir[1]`, `*.txt`, `dir[[]1]\*.txt`},
		{`dir*`, `*.txt`, `dir[*]\*.txt`},
		{`dir?`, `*.txt`, `dir[?]\*.txt`},
		{`a[b*c?d]`, `file.txt`, `a[[]b[*]c[?]d]\file.txt`},
		{`normal`, `*.txt`, `normal\*.txt`},
		{``, `*.txt`, `*.txt`},
	}

	for _, tc := range tests {
		fs := share.DirFS(tc.root).(*wfs)
		got := fs.pattern(tc.pattern)
		if got != tc.expected {
			t.Errorf("root=%q pattern=%q: got %q, want %q", tc.root, tc.pattern, got, tc.expected)
		}
	}

	// Verify that escaped root matches literal directory and does not match wildcard expansion
	fsBracket := share.DirFS(`dir[1]`).(*wfs)
	patBracket := fsBracket.pattern(`*.txt`)
	if matched, err := Match(patBracket, `dir[1]\test.txt`); err != nil || !matched {
		t.Errorf("Match(%q, %q) = %v, %v; want true, nil", patBracket, `dir[1]\test.txt`, matched, err)
	}
	if matched, err := Match(patBracket, `dir1\test.txt`); err != nil || matched {
		t.Errorf("Match(%q, %q) = %v, %v; want false, nil", patBracket, `dir1\test.txt`, matched, err)
	}
}

func TestDirFSGlobPrefixValidation(t *testing.T) {
	// Test prefix validation and trimming helper
	matches := []string{
		`dir\file1.txt`,
		`other\file2.txt`,
		`dir\sub\file3.txt`,
		`d`,
		`dir`,
	}

	got := cleanMatches(matches, `dir`)
	want := []string{
		`file1.txt`,
		`sub/file3.txt`,
	}

	if len(got) != len(want) {
		t.Fatalf("cleanMatches len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cleanMatches[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Empty root converts SMB separators to io/fs separators.
	orig := []string{`a.txt`, `sub\b.txt`}
	if gotEmpty := cleanMatches(orig, ``); gotEmpty[1] != `sub/b.txt` {
		t.Errorf("cleanMatches with empty root returned %v, want slash separators", gotEmpty)
	}
}

func TestDirFSGlobResultsOpen(t *testing.T) {
	share, serverConn := newTestShare(t)
	queryCount := 0

	onQueryDir := func(msgID uint64, reqBuf []byte, dt transport) bool {
		queryCount++
		p := smb2.PacketCodec(reqBuf)
		if queryCount%2 == 1 {
			query := &smb2.QueryDirectoryResponse{
				Output: rawEncoder(encodeFileIdBothDirectoryInformation("file.txt")),
			}
			buf := make([]byte, query.Size())
			query.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			_, _ = dt.Writev(buf)
			return true
		}

		errRes := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
		buf := make([]byte, errRes.Size())
		errRes.Encode(buf)
		rp := smb2.PacketCodec(buf)
		rp.SetMessageId(msgID)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		_, _ = dt.Writev(buf)
		return true
	}

	onQueryInfo := func(msgID uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], smb2.FILE_ATTRIBUTE_DIRECTORY)
		query := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, query.Size())
		query.Encode(buf)
		return buf
	}
	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	for _, root := range []string{"", "root"} {
		dirFS := share.DirFS(root)
		for _, pattern := range []string{"sub/file.txt", "sub/*"} {
			matches, err := iofs.Glob(dirFS, pattern)
			if err != nil {
				t.Fatalf("DirFS(%q).Glob(%q): %v", root, pattern, err)
			}
			want := []string{"sub/file.txt"}
			if len(matches) != 1 || matches[0] != want[0] {
				t.Fatalf("DirFS(%q).Glob(%q) = %v, want %v", root, pattern, matches, want)
			}
			file, err := dirFS.Open(matches[0])
			if err != nil {
				t.Fatalf("DirFS(%q).Open(%q): %v", root, matches[0], err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("DirFS(%q).Open(%q).Close(): %v", root, matches[0], err)
			}
		}
	}
}
