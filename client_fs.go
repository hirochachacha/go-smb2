//go:build go1.16

package smb2

import (
	iofs "io/fs"
	"strings"
)

type wfs struct {
	root  string
	share *Share
}

func (s *Share) DirFS(dirname string) iofs.FS {
	return &wfs{
		root:  strings.TrimRight(normPath(dirname), `\`),
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

func (fs *wfs) pattern(pattern string) string {
	pattern = normPattern(pattern)

	if fs.root != "" {
		pattern = fs.root + "\\" + pattern
	}

	return pattern
}

func (fs *wfs) Open(name string) (iofs.File, error) {
	if !iofs.ValidPath(name) {
		return nil, &iofs.PathError{Op: "open", Path: name, Err: iofs.ErrInvalid}
	}
	file, err := fs.share.Open(fs.path(name))
	if err != nil {
		return nil, err
	}
	return &wfile{file}, nil
}

func (fs *wfs) Stat(name string) (iofs.FileInfo, error) {
	if !iofs.ValidPath(name) {
		return nil, &iofs.PathError{Op: "stat", Path: name, Err: iofs.ErrInvalid}
	}
	return fs.share.Stat(fs.path(name))
}

func (fs *wfs) ReadFile(name string) ([]byte, error) {
	if !iofs.ValidPath(name) {
		return nil, &iofs.PathError{Op: "readfile", Path: name, Err: iofs.ErrInvalid}
	}
	return fs.share.ReadFile(fs.path(name))
}

func (fs *wfs) Glob(pattern string) (matches []string, err error) {
	matches, err = fs.share.Glob(fs.pattern(pattern))
	if err != nil {
		return nil, err
	}

	if fs.root == "" {
		return matches, nil
	}

	for i, match := range matches {
		matches[i] = match[len(fs.root)+1:]
	}

	return matches, nil
}

// dirInfo is a DirEntry based on a FileInfo.
type dirInfo struct {
	fileInfo iofs.FileInfo
}

func (di dirInfo) IsDir() bool {
	return di.fileInfo.IsDir()
}

func (di dirInfo) Type() iofs.FileMode {
	return di.fileInfo.Mode().Type()
}

func (di dirInfo) Info() (iofs.FileInfo, error) {
	return di.fileInfo, nil
}

func (di dirInfo) Name() string {
	return di.fileInfo.Name()
}

func fileInfoToDirEntry(info iofs.FileInfo) iofs.DirEntry {
	if info == nil {
		return nil
	}
	return dirInfo{fileInfo: info}
}

type wfile struct {
	*File
}

func (f *wfile) ReadDir(n int) (dirents []iofs.DirEntry, err error) {
	infos, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}
	dirents = make([]iofs.DirEntry, len(infos))
	for i, info := range infos {
		dirents[i] = fileInfoToDirEntry(info)
	}
	return dirents, nil
}
