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
