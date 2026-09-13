package smb2

import (
	"context"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"strings"
)

// ContextShare binds a context to a Share for use with io/fs. It does not
// duplicate the Share's connection or mutable state.
type ContextShare struct {
	share *Share
	ctx   context.Context
	root  string
}

func (s *ContextShare) path(name string) string {
	name = strings.ReplaceAll(name, "/", `\`)
	name = normPath(name)
	if s.root == "" {
		return name
	}
	if name == "" {
		return s.root
	}
	return s.root + `\` + name
}

func (s *ContextShare) pattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, "/", `\`)
	if s.root == "" {
		return pattern
	}
	return escapeGlob(s.root) + `\` + pattern
}

func validContextPath(name string) bool {
	return iofs.ValidPath(name) && !strings.ContainsRune(name, '\\')
}

func invalidContextPath(op, name string) error {
	return &iofs.PathError{Op: op, Path: name, Err: iofs.ErrInvalid}
}

func contextPathError(op, name string, err error) error {
	if err == nil {
		return nil
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return &iofs.PathError{Op: op, Path: name, Err: pe.Err}
	}
	return err
}

func (s *ContextShare) Open(name string) (iofs.File, error) {
	if !validContextPath(name) {
		return nil, invalidContextPath("open", name)
	}
	f, err := s.share.Open(s.ctx, s.path(name))
	if err != nil {
		return nil, contextPathError("open", name, err)
	}
	return &ContextFile{file: f, ctx: s.ctx}, nil
}

func (s *ContextShare) Stat(name string) (iofs.FileInfo, error) {
	if !validContextPath(name) {
		return nil, invalidContextPath("stat", name)
	}
	fi, err := s.share.Stat(s.ctx, s.path(name))
	return fi, contextPathError("stat", name, err)
}

func (s *ContextShare) Lstat(name string) (iofs.FileInfo, error) {
	if !validContextPath(name) {
		return nil, invalidContextPath("lstat", name)
	}
	fi, err := s.share.Lstat(s.ctx, s.path(name))
	return fi, contextPathError("lstat", name, err)
}

func (s *ContextShare) ReadFile(name string) ([]byte, error) {
	if !validContextPath(name) {
		return nil, invalidContextPath("readfile", name)
	}
	b, err := s.share.ReadFile(s.ctx, s.path(name))
	return b, contextPathError("readfile", name, err)
}

func (s *ContextShare) ReadDir(name string) ([]iofs.DirEntry, error) {
	if !validContextPath(name) {
		return nil, invalidContextPath("readdir", name)
	}
	fis, err := s.share.ReadDir(s.ctx, s.path(name))
	if err != nil {
		return nil, contextPathError("readdir", name, err)
	}
	entries := make([]iofs.DirEntry, len(fis))
	for i, fi := range fis {
		entries[i] = iofs.FileInfoToDirEntry(fi)
	}
	return entries, nil
}

func (s *ContextShare) ReadLink(name string) (string, error) {
	if !validContextPath(name) {
		return "", invalidContextPath("readlink", name)
	}
	target, err := s.share.Readlink(s.ctx, s.path(name))
	if err != nil {
		return "", contextPathError("readlink", name, err)
	}
	return strings.ReplaceAll(target, `\`, "/"), nil
}

func (s *ContextShare) Glob(pattern string) ([]string, error) {
	if !validContextPath(pattern) {
		return nil, invalidContextPath("glob", pattern)
	}
	matches, err := s.share.Glob(s.ctx, s.pattern(pattern))
	if err != nil {
		return nil, contextPathError("glob", pattern, err)
	}
	return cleanMatches(matches, s.root), nil
}

func (s *ContextShare) Sub(dir string) (iofs.FS, error) {
	if !validContextPath(dir) {
		return nil, invalidContextPath("sub", dir)
	}
	root := s.path(dir)
	return &ContextShare{share: s.share, ctx: s.ctx, root: root}, nil
}

// ContextFile binds a context to a core File. All wrappers share the core
// file's offset, directory cursor, and closed state.
type ContextFile struct {
	file *File
	ctx  context.Context
}

func (f *ContextFile) Close() error                             { return f.file.Close(f.ctx) }
func (f *ContextFile) Name() string                             { return f.file.Name() }
func (f *ContextFile) Stat() (iofs.FileInfo, error)             { return f.file.Stat(f.ctx) }
func (f *ContextFile) Read(p []byte) (int, error)               { return f.file.Read(f.ctx, p) }
func (f *ContextFile) ReadAt(p []byte, off int64) (int, error)  { return f.file.ReadAt(f.ctx, p, off) }
func (f *ContextFile) Write(p []byte) (int, error)              { return f.file.Write(f.ctx, p) }
func (f *ContextFile) WriteAt(p []byte, off int64) (int, error) { return f.file.WriteAt(f.ctx, p, off) }
func (f *ContextFile) Seek(off int64, whence int) (int64, error) {
	return f.file.Seek(f.ctx, off, whence)
}
func (f *ContextFile) ReadDir(n int) ([]iofs.DirEntry, error) { return f.file.ReadDir(f.ctx, n) }
func (f *ContextFile) ReadFrom(r io.Reader) (int64, error)    { return f.file.ReadFrom(f.ctx, r) }
func (f *ContextFile) WriteTo(w io.Writer) (int64, error)     { return f.file.WriteTo(f.ctx, w) }

type contextReader struct {
	ctx  context.Context
	file *File
}

func (r *contextReader) Read(p []byte) (int, error) { return r.file.Read(r.ctx, p) }

type contextWriter struct {
	ctx  context.Context
	file *File
}

func (w *contextWriter) Write(p []byte) (int, error) { return w.file.Write(w.ctx, p) }

var (
	_ iofs.FS          = (*ContextShare)(nil)
	_ iofs.StatFS      = (*ContextShare)(nil)
	_ iofs.ReadFileFS  = (*ContextShare)(nil)
	_ iofs.ReadDirFS   = (*ContextShare)(nil)
	_ iofs.GlobFS      = (*ContextShare)(nil)
	_ iofs.ReadLinkFS  = (*ContextShare)(nil)
	_ iofs.SubFS       = (*ContextShare)(nil)
	_ iofs.File        = (*ContextFile)(nil)
	_ iofs.ReadDirFile = (*ContextFile)(nil)
	_ io.Reader        = (*ContextFile)(nil)
	_ io.ReaderAt      = (*ContextFile)(nil)
	_ io.Writer        = (*ContextFile)(nil)
	_ io.WriterAt      = (*ContextFile)(nil)
	_ io.Seeker        = (*ContextFile)(nil)
	_ io.ReaderFrom    = (*ContextFile)(nil)
	_ io.WriterTo      = (*ContextFile)(nil)
)
