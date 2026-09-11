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

func escapeGlob(s string) string {
	if !strings.ContainsAny(s, `*?[`) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*', '?', '[':
			b.WriteByte('[')
			b.WriteRune(r)
			b.WriteByte(']')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (fs *wfs) pattern(pattern string) string {
	pattern = normPattern(pattern)

	if fs.root != "" {
		pattern = escapeGlob(fs.root) + "\\" + pattern
	}

	return pattern
}

func validFSName(name string) bool {
	return iofs.ValidPath(name) && !strings.ContainsRune(name, '\\')
}

func (fs *wfs) Open(name string) (iofs.File, error) {
	if !validFSName(name) {
		return nil, &iofs.PathError{Op: "open", Path: name, Err: iofs.ErrInvalid}
	}
	file, err := fs.share.Open(fs.path(name))
	if err != nil {
		return nil, err
	}
	return &wfile{file}, nil
}

func (fs *wfs) Stat(name string) (iofs.FileInfo, error) {
	if !validFSName(name) {
		return nil, &iofs.PathError{Op: "stat", Path: name, Err: iofs.ErrInvalid}
	}
	return fs.share.Stat(fs.path(name))
}

func (fs *wfs) ReadFile(name string) ([]byte, error) {
	if !validFSName(name) {
		return nil, &iofs.PathError{Op: "readfile", Path: name, Err: iofs.ErrInvalid}
	}
	return fs.share.ReadFile(fs.path(name))
}

// io/fs Path Names requires slash-separated paths, even on SMB. Check the
// SMB root before conversion so results outside that root remain excluded.
// https://pkg.go.dev/io/fs#hdr-Path_Names
func cleanMatches(matches []string, root string) []string {
	if root != "" {
		prefix := root + "\\"
		validMatches := matches[:0]
		for _, match := range matches {
			if strings.HasPrefix(match, prefix) {
				validMatches = append(validMatches, strings.ReplaceAll(match[len(prefix):], `\`, "/"))
			}
		}
		return validMatches
	}

	for i, match := range matches {
		matches[i] = strings.ReplaceAll(match, `\`, "/")
	}
	return matches
}

func (fs *wfs) Glob(pattern string) (matches []string, err error) {
	if !validFSName(pattern) {
		return nil, &iofs.PathError{Op: "glob", Path: pattern, Err: iofs.ErrInvalid}
	}
	matches, err = fs.share.Glob(fs.pattern(pattern))
	if err != nil {
		return nil, err
	}

	return cleanMatches(matches, fs.root), nil
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
