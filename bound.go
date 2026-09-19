package smb2

import (
	"context"
	"errors"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"io"
	iofs "io/fs"
	"os"
	"strings"
)

// BoundShare binds a context to a Share for use with io/fs. It does not
// duplicate the Share's connection or mutable state.
type BoundShare struct {
	share *Share
	ctx   context.Context
	root  string
}

func (s *BoundShare) path(name string) string {
	return pathpkg.Join(s.root, pathpkg.Normalize(name))
}

func (s *BoundShare) pattern(pattern string) string {
	pattern = pathpkg.NormalizePattern(pattern)
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

func (s *BoundShare) checkValid() error {
	if s == nil || s.share == nil {
		return os.ErrInvalid
	}
	return nil
}

func (s *BoundShare) Open(name string) (iofs.File, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(name) {
		return nil, invalidContextPath("open", name)
	}
	f, err := s.share.Open(s.ctx, s.path(name))
	if err != nil {
		return nil, contextPathError("open", name, err)
	}
	return &BoundFile{file: f, ctx: s.ctx}, nil
}

func (s *BoundShare) Stat(name string) (iofs.FileInfo, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(name) {
		return nil, invalidContextPath("stat", name)
	}
	fi, err := s.share.Stat(s.ctx, s.path(name))
	return fi, contextPathError("stat", name, err)
}

func (s *BoundShare) Lstat(name string) (iofs.FileInfo, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(name) {
		return nil, invalidContextPath("lstat", name)
	}
	fi, err := s.share.Lstat(s.ctx, s.path(name))
	return fi, contextPathError("lstat", name, err)
}

func (s *BoundShare) ReadFile(name string) ([]byte, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(name) {
		return nil, invalidContextPath("readfile", name)
	}
	b, err := s.share.ReadFile(s.ctx, s.path(name))
	return b, contextPathError("readfile", name, err)
}

func (s *BoundShare) ReadDir(name string) ([]iofs.DirEntry, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
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

func (s *BoundShare) ReadLink(name string) (string, error) {
	if err := s.checkValid(); err != nil {
		return "", err
	}
	if !validContextPath(name) {
		return "", invalidContextPath("readlink", name)
	}
	target, err := s.share.Readlink(s.ctx, s.path(name))
	if err != nil {
		return "", contextPathError("readlink", name, err)
	}
	return strings.ReplaceAll(target, `\`, "/"), nil
}

func (s *BoundShare) Glob(pattern string) ([]string, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(pattern) {
		return nil, invalidContextPath("glob", pattern)
	}
	matches, err := s.share.Glob(s.ctx, s.pattern(pattern))
	if err != nil {
		return nil, contextPathError("glob", pattern, err)
	}
	return cleanMatches(matches, s.root), nil
}

func (s *BoundShare) Sub(dir string) (iofs.FS, error) {
	if err := s.checkValid(); err != nil {
		return nil, err
	}
	if !validContextPath(dir) {
		return nil, invalidContextPath("sub", dir)
	}
	root := s.path(dir)
	return &BoundShare{share: s.share, ctx: s.ctx, root: root}, nil
}

// BoundFile binds a context to a core File. All wrappers share the core
// file's offset, directory cursor, and closed state.
type BoundFile struct {
	file *File
	ctx  context.Context
}

func (f *BoundFile) checkValid() error {
	if f == nil || f.file == nil {
		return os.ErrInvalid
	}
	return nil
}

func (f *BoundFile) Close() error {
	if err := f.checkValid(); err != nil {
		return err
	}
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return f.file.Close(ctx)
}

func (f *BoundFile) Name() string {
	if f == nil || f.file == nil {
		return ""
	}
	return f.file.Name()
}

func (f *BoundFile) Stat() (iofs.FileInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	return f.file.Stat(f.ctx)
}

func (f *BoundFile) Read(p []byte) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Read(f.ctx, p)
}

func (f *BoundFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.ReadAt(f.ctx, p, off)
}

func (f *BoundFile) Write(p []byte) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Write(f.ctx, p)
}

func (f *BoundFile) WriteAt(p []byte, off int64) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.WriteAt(f.ctx, p, off)
}

func (f *BoundFile) Seek(off int64, whence int) (int64, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Seek(f.ctx, off, whence)
}

func (f *BoundFile) ReadDir(n int) ([]iofs.DirEntry, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	return f.file.ReadDir(f.ctx, n)
}

func (f *BoundFile) ReadFrom(r io.Reader) (int64, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.ReadFrom(f.ctx, r)
}

func (f *BoundFile) WriteTo(w io.Writer) (int64, error)     {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.WriteTo(f.ctx, w)
}

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
	_ iofs.FS          = (*BoundShare)(nil)
	_ iofs.StatFS      = (*BoundShare)(nil)
	_ iofs.ReadFileFS  = (*BoundShare)(nil)
	_ iofs.ReadDirFS   = (*BoundShare)(nil)
	_ iofs.GlobFS      = (*BoundShare)(nil)
	_ iofs.ReadLinkFS  = (*BoundShare)(nil)
	_ iofs.SubFS       = (*BoundShare)(nil)
	_ iofs.File        = (*BoundFile)(nil)
	_ iofs.ReadDirFile = (*BoundFile)(nil)
	_ io.Reader        = (*BoundFile)(nil)
	_ io.ReaderAt      = (*BoundFile)(nil)
	_ io.Writer        = (*BoundFile)(nil)
	_ io.WriterAt      = (*BoundFile)(nil)
	_ io.Seeker        = (*BoundFile)(nil)
	_ io.Closer        = (*BoundFile)(nil)
	_ io.ReaderFrom    = (*BoundFile)(nil)
	_ io.WriterTo      = (*BoundFile)(nil)
)
