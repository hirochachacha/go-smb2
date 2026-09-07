package smb2

import (
	"errors"
	iofs "io/fs"
	"testing"
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
		`sub\file3.txt`,
	}

	if len(got) != len(want) {
		t.Fatalf("cleanMatches len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cleanMatches[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Empty root returns matches as-is
	orig := []string{`a.txt`, `b.txt`}
	if gotEmpty := cleanMatches(orig, ``); len(gotEmpty) != len(orig) {
		t.Errorf("cleanMatches with empty root returned %v, want %v", gotEmpty, orig)
	}
}
