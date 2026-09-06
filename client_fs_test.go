package smb2

import "testing"

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
