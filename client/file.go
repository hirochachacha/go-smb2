package client

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/notify"
)

// File is an open file on a resolved target. It keeps its session in use until
// Close succeeds or confirms it is already closed. Name returns the original
// UNC supplied by the caller.
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

// pathError preserves the operation and cause while displaying the caller's
// UNC instead of the resolved share-relative path. Do not mutate shared errors.
func (f *File) pathError(err error) error {
	if pathErr, ok := err.(*os.PathError); ok && f != nil {
		copy := *pathErr
		copy.Path = f.name
		return &copy
	}
	return err
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
// keeps the session in use so the caller can retry, unless the server confirms
// that the handle is already closed.
func (f *File) Close(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	if f == nil {
		return os.ErrInvalid
	}
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return &os.PathError{Op: "close", Path: f.name, Err: os.ErrClosed}
	}
	if f.file == nil {
		return os.ErrInvalid
	}
	err := f.file.Close(ctx)
	if err != nil && !errors.Is(err, os.ErrClosed) {
		return f.pathError(err)
	}
	f.closed = true
	if f.session != nil {
		f.session.release()
	}
	return f.pathError(err)
}

func (f *File) Sync(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	return f.pathError(f.underlying().Sync(ctx))
}

func (f *File) Truncate(ctx context.Context, size int64) error {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	return f.pathError(f.underlying().Truncate(ctx, size))
}

func (f *File) Chmod(ctx context.Context, mode os.FileMode) error {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	return f.pathError(f.underlying().Chmod(ctx, mode))
}

func (f *File) Read(ctx context.Context, b []byte) (int, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	n, err := f.underlying().Read(ctx, b)
	return n, f.pathError(err)
}

func (f *File) ReadAt(ctx context.Context, b []byte, off int64) (int, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	n, err := f.underlying().ReadAt(ctx, b, off)
	return n, f.pathError(err)
}

func (f *File) Write(ctx context.Context, b []byte) (int, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	n, err := f.underlying().Write(ctx, b)
	return n, f.pathError(err)
}

func (f *File) WriteAt(ctx context.Context, b []byte, off int64) (int, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	n, err := f.underlying().WriteAt(ctx, b, off)
	return n, f.pathError(err)
}

func (f *File) Seek(ctx context.Context, offset int64, whence int) (int64, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	offset, err := f.underlying().Seek(ctx, offset, whence)
	return offset, f.pathError(err)
}

func (f *File) Stat(ctx context.Context) (os.FileInfo, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	info, err := f.underlying().Stat(ctx)
	if err != nil {
		return info, f.pathError(err)
	}
	return namedUNCInfo(info, f.name), nil
}

func (f *File) Statfs(ctx context.Context) (v2.FileFsInfo, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	info, err := f.underlying().Statfs(ctx)
	return info, f.pathError(err)
}

func (f *File) Readdir(ctx context.Context, n int) ([]os.FileInfo, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	infos, err := f.underlying().Readdir(ctx, n)
	return infos, f.pathError(err)
}

func (f *File) ReadDir(ctx context.Context, n int) ([]fs.DirEntry, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	entries, err := f.underlying().ReadDir(ctx, n)
	return entries, f.pathError(err)
}

func (f *File) Readdirnames(ctx context.Context, n int) ([]string, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	names, err := f.underlying().Readdirnames(ctx, n)
	return names, f.pathError(err)
}

func (f *File) ReadFrom(ctx context.Context, r io.Reader) (int64, error) {
	if ctx == nil {
		panic("nil context")
	}
	if f == nil || r == nil {
		return 0, os.ErrInvalid
	}
	defer f.holdSession()()
	if source, ok := r.(*fileContext); ok && source != nil {
		if source.file == nil {
			return 0, os.ErrInvalid
		}
		defer source.file.holdSession()()
		r = source.file.underlying().WithContext(source.ctx)
		n, err := f.underlying().ReadFrom(ctx, r)
		return n, copyError(err, source.file, f)
	}
	return f.underlying().ReadFrom(ctx, r)
}

func (f *File) WriteTo(ctx context.Context, w io.Writer) (int64, error) {
	if ctx == nil {
		panic("nil context")
	}
	if f == nil || w == nil {
		return 0, os.ErrInvalid
	}
	defer f.holdSession()()
	if target, ok := w.(*fileContext); ok && target != nil {
		if target.file == nil {
			return 0, os.ErrInvalid
		}
		defer target.file.holdSession()()
		w = target.file.underlying().WithContext(target.ctx)
		n, err := f.underlying().WriteTo(ctx, w)
		return n, copyError(err, f, target.file)
	}
	return f.underlying().WriteTo(ctx, w)
}

// copyError is used only when both endpoints are known client files. The lower
// copy implementation attributes reads to source and writes to destination.
// External readers and writers may return indistinguishable wrappers themselves.
func copyError(err error, source, destination *File) error {
	switch wrapped := err.(type) {
	case *os.PathError:
		switch wrapped.Op {
		case "read":
			return source.pathError(err)
		case "write":
			return destination.pathError(err)
		}
	case *os.LinkError:
		if wrapped.Op == "copy" {
			copy := *wrapped
			copy.Old, copy.New = source.name, destination.name
			return &copy
		}
	}
	return err
}

func (f *File) Lock(ctx context.Context, ranges []v2.LockRange, failImmediately bool) error {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	return f.pathError(f.underlying().Lock(ctx, ranges, failImmediately))
}

func (f *File) Unlock(ctx context.Context, ranges []v2.ByteRange) error {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	return f.pathError(f.underlying().Unlock(ctx, ranges))
}

func (f *File) WaitForChange(ctx context.Context, filter notify.Filter, recursive bool) (notify.Result, error) {
	if ctx == nil {
		panic("nil context")
	}
	defer f.holdSession()()
	result, err := f.underlying().WaitForChange(ctx, filter, recursive)
	return result, f.pathError(err)
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

func (f *fileContext) checkValid() error {
	if f == nil || f.file == nil {
		return os.ErrInvalid
	}
	return nil
}

func (f *fileContext) Close() error {
	if err := f.checkValid(); err != nil {
		return err
	}
	return f.file.Close(f.ctx)
}

func (f *fileContext) Read(b []byte) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Read(f.ctx, b)
}

func (f *fileContext) ReadAt(b []byte, off int64) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.ReadAt(f.ctx, b, off)
}

func (f *fileContext) Write(b []byte) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Write(f.ctx, b)
}

func (f *fileContext) WriteAt(b []byte, off int64) (int, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.WriteAt(f.ctx, b, off)
}

func (f *fileContext) Seek(offset int64, whence int) (int64, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.Seek(f.ctx, offset, whence)
}

func (f *fileContext) Stat() (os.FileInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	return f.file.Stat(f.ctx)
}

func (f *fileContext) ReadDir(n int) ([]fs.DirEntry, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	return f.file.ReadDir(f.ctx, n)
}

func (f *fileContext) ReadFrom(r io.Reader) (int64, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.ReadFrom(f.ctx, r)
}

func (f *fileContext) WriteTo(w io.Writer) (int64, error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	return f.file.WriteTo(f.ctx, w)
}
