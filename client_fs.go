// +build go1.6

package smb2

import (
	"io/fs"
)

type wfs struct {
	root  string
	share *Share
}

func (s *Share) DirFS(dirname string) fs.FS {
	return &wfs{
		root:  normPath(dirname),
		share: s,
	}
}

func (fs *wfs) path(name string) string {
	name = normPath(name)

	if fs.root != "" {
		if name != "" {
			name = fs.root + "\\" + name
		} else {
			name = fs.root
		}
	}

	return name
}

func (fs *wfs) Open(name string) (fs.File, error) {
	file, err := fs.share.Open(fs.path(name))
	if err != nil {
		return nil, err
	}
	return &wfile{file}, nil
}

func (fs *wfs) Stat(name string) (fs.FileInfo, error) {
	return fs.share.Stat(fs.path(name))
}

func (fs *wfs) ReadFile(name string) ([]byte, error) {
	return fs.share.ReadFile(fs.path(name))
}

type wfile struct {
	*File
}

func (f *wfile) ReadDir(n int) (dirents []fs.DirEntry, err error) {
	infos, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}
	dirents = make([]fs.DirEntry, len(infos))
	for i, info := range infos {
		dirents[i] = fs.FileInfoToDirEntry(info)
	}
	return dirents, nil
}
