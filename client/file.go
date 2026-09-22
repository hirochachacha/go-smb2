package client

import (
	"context"
	"io"
	"io/fs"
	"os"
	"sync"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/notify"
)

// File is an open file on a resolved target. It keeps its session in use until
// Close succeeds. Name returns the original UNC supplied by the caller.
// A File must not be copied.
type File struct {
	file    *v2.File
	name    string
	session *sessionEntry
	closeMu sync.Mutex
	closed  bool
}

// Name returns the original UNC the file was opened with.
func (f *File) Name() string {
	if f == nil {
		return ""
	}
	return f.name
}

// Fd returns a copy of the server's descriptor for the open file. It returns
// the zero value for a nil File. Closing the file does not clear the descriptor.
func (f *File) Fd() v2.FileDescriptor {
	return f.underlying().Fd()
}

func (f *File) underlying() *v2.File {
	if f == nil {
		return nil
	}
	return f.file
}

// holdSession keeps in-flight I/O alive even if Close runs concurrently.
func (f *File) holdSession() func() {
	if f == nil || f.session == nil {
		return func() {}
	}
	s := f.session
	s.client.mu.Lock()
	s.retain()
	s.client.mu.Unlock()
	return s.release
}

// Close closes the file and releases its use of the session. A failed close
// keeps the session in use so the caller can retry.
func (f *File) Close(ctx context.Context) error {
	if f == nil {
		return os.ErrInvalid
	}
	if ctx == nil {
		panic("nil context")
	}
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	if err := f.file.Close(ctx); err != nil {
		return err
	}
	f.closed = true
	if f.session != nil {
		f.session.release()
	}
	return nil
}

func (f *File) Sync(ctx context.Context) error {
	defer f.holdSession()()
	return f.underlying().Sync(ctx)
}

func (f *File) Truncate(ctx context.Context, size int64) error {
	defer f.holdSession()()
	return f.underlying().Truncate(ctx, size)
}

func (f *File) Chmod(ctx context.Context, mode os.FileMode) error {
	defer f.holdSession()()
	return f.underlying().Chmod(ctx, mode)
}

func (f *File) Read(ctx context.Context, b []byte) (int, error) {
	defer f.holdSession()()
	return f.underlying().Read(ctx, b)
}

func (f *File) ReadAt(ctx context.Context, b []byte, off int64) (int, error) {
	defer f.holdSession()()
	return f.underlying().ReadAt(ctx, b, off)
}

func (f *File) Write(ctx context.Context, b []byte) (int, error) {
	defer f.holdSession()()
	return f.underlying().Write(ctx, b)
}

func (f *File) WriteAt(ctx context.Context, b []byte, off int64) (int, error) {
	defer f.holdSession()()
	return f.underlying().WriteAt(ctx, b, off)
}

func (f *File) Seek(ctx context.Context, offset int64, whence int) (int64, error) {
	defer f.holdSession()()
	return f.underlying().Seek(ctx, offset, whence)
}

func (f *File) Stat(ctx context.Context) (os.FileInfo, error) {
	defer f.holdSession()()
	return f.underlying().Stat(ctx)
}

func (f *File) Statfs(ctx context.Context) (v2.FileFsInfo, error) {
	defer f.holdSession()()
	return f.underlying().Statfs(ctx)
}

func (f *File) Readdir(ctx context.Context, n int) ([]os.FileInfo, error) {
	defer f.holdSession()()
	return f.underlying().Readdir(ctx, n)
}

func (f *File) ReadDir(ctx context.Context, n int) ([]fs.DirEntry, error) {
	defer f.holdSession()()
	return f.underlying().ReadDir(ctx, n)
}

func (f *File) Readdirnames(ctx context.Context, n int) ([]string, error) {
	defer f.holdSession()()
	return f.underlying().Readdirnames(ctx, n)
}

func (f *File) ReadFrom(ctx context.Context, r io.Reader) (int64, error) {
	defer f.holdSession()()
	if source, ok := r.(*fileContext); ok && source != nil {
		defer source.file.holdSession()()
		r = source.file.underlying().WithContext(source.ctx)
	}
	return f.underlying().ReadFrom(ctx, r)
}

func (f *File) WriteTo(ctx context.Context, w io.Writer) (int64, error) {
	defer f.holdSession()()
	if target, ok := w.(*fileContext); ok && target != nil {
		defer target.file.holdSession()()
		w = target.file.underlying().WithContext(target.ctx)
	}
	return f.underlying().WriteTo(ctx, w)
}

func (f *File) Lock(ctx context.Context, ranges []v2.LockRange, failImmediately bool) error {
	defer f.holdSession()()
	return f.underlying().Lock(ctx, ranges, failImmediately)
}

func (f *File) Unlock(ctx context.Context, ranges []v2.ByteRange) error {
	defer f.holdSession()()
	return f.underlying().Unlock(ctx, ranges)
}

func (f *File) WaitForChange(ctx context.Context, filter notify.Filter, recursive bool) (notify.Result, error) {
	defer f.holdSession()()
	return f.underlying().WaitForChange(ctx, filter, recursive)
}

// WithContext returns an adapter using ctx and sharing this File's state.
func (f *File) WithContext(ctx context.Context) interface {
	fs.File
	fs.ReadDirFile
	io.Writer
	io.Seeker
	io.ReaderAt
	io.WriterAt
	io.ReaderFrom
	io.WriterTo
} {
	if ctx == nil {
		panic("nil context")
	}
	if f == nil {
		return nil
	}
	return &fileContext{file: f, ctx: ctx}
}

type fileContext struct {
	file *File
	ctx  context.Context
}

func (f *fileContext) Close() error { return f.file.Close(f.ctx) }

func (f *fileContext) Read(b []byte) (int, error) { return f.file.Read(f.ctx, b) }

func (f *fileContext) ReadAt(b []byte, off int64) (int, error) { return f.file.ReadAt(f.ctx, b, off) }

func (f *fileContext) Write(b []byte) (int, error) { return f.file.Write(f.ctx, b) }

func (f *fileContext) WriteAt(b []byte, off int64) (int, error) { return f.file.WriteAt(f.ctx, b, off) }

func (f *fileContext) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(f.ctx, offset, whence)
}

func (f *fileContext) Stat() (os.FileInfo, error) { return f.file.Stat(f.ctx) }

func (f *fileContext) ReadDir(n int) ([]fs.DirEntry, error) { return f.file.ReadDir(f.ctx, n) }

func (f *fileContext) ReadFrom(r io.Reader) (int64, error) { return f.file.ReadFrom(f.ctx, r) }

func (f *fileContext) WriteTo(w io.Writer) (int64, error) { return f.file.WriteTo(f.ctx, w) }
