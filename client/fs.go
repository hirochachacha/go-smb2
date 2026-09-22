package client

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
)

// WithContext exposes the client as an io/fs filesystem with paths of the
// form server/share/path. The virtual root lists currently cached servers;
// it is not network discovery. Uncached servers can be accessed directly.
// Server directories list shares. Virtual directories have mode 0555 and
// zero modification times. Closing files does not close the client.
func (d *Client) WithContext(ctx context.Context) interface {
	fs.FS
	fs.StatFS
	fs.ReadFileFS
	fs.ReadDirFS
	fs.ReadLinkFS
	fs.GlobFS
	fs.SubFS
} {
	if ctx == nil {
		panic("nil context")
	}
	return &boundClient{client: d, ctx: ctx}
}

type boundClient struct {
	client *Client
	ctx    context.Context
	root   string
}

func fsError(op, name string, err error) error {
	if err == nil {
		return nil
	}
	return &fs.PathError{Op: op, Path: name, Err: unwrapFilesystemError(err)}
}

func validFSPath(name string) bool { return pathpkg.ValidPosixPath(name) }

func (s *boundClient) resolve(name string) (string, error) {
	if !validFSPath(name) || s == nil || s.client == nil {
		return "", fs.ErrInvalid
	}
	if err := s.ctx.Err(); err != nil {
		return "", err
	}
	s.client.mu.Lock()
	closed := s.client.closing
	s.client.mu.Unlock()
	if closed {
		return "", net.ErrClosed
	}
	return path.Join(s.root, name), nil
}

func uncPath(name string) string { return pathpkg.PosixPathToUNC(name) }

func (s *boundClient) Open(name string) (fs.File, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, fsError("open", name, err)
	}
	if !strings.Contains(full, "/") {
		entries, err := s.ReadDir(name)
		if err != nil {
			return nil, fsError("open", name, err)
		}
		return &virtualDirectory{name: name, info: virtualInfo(path.Base(full)), entries: entries}, nil
	}
	f, err := s.client.Open(s.ctx, uncPath(full))
	if err != nil {
		return nil, fsError("open", name, err)
	}
	return &boundClientFile{file: f.WithContext(s.ctx), name: name, base: path.Base(full)}, nil
}

func (s *boundClient) stat(name string, follow bool) (fs.FileInfo, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(full, "/") {
		if full != "." {
			session, err := s.client.acquireSession(s.ctx, full)
			if err != nil {
				return nil, err
			}
			session.release()
		}
		return virtualInfo(full), nil
	}
	var info fs.FileInfo
	if follow {
		info, err = s.client.Stat(s.ctx, uncPath(full))
	} else {
		info, err = s.client.Lstat(s.ctx, uncPath(full))
	}
	if err != nil {
		return nil, err
	}
	return namedInfo{FileInfo: info, name: path.Base(full)}, nil
}

func (s *boundClient) Stat(name string) (fs.FileInfo, error) {
	info, err := s.stat(name, true)
	return info, fsError("stat", name, err)
}

func (s *boundClient) Lstat(name string) (fs.FileInfo, error) {
	info, err := s.stat(name, false)
	return info, fsError("lstat", name, err)
}

func (s *boundClient) ReadDir(name string) ([]fs.DirEntry, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, fsError("readdir", name, err)
	}
	entries := make([]fs.DirEntry, 0)
	switch {
	case full == ".":
		s.client.mu.Lock()
		for server := range s.client.sessions {
			entries = append(entries, fs.FileInfoToDirEntry(virtualInfo(server)))
		}
		s.client.mu.Unlock()
	case !strings.Contains(full, "/"):
		session, err := s.client.acquireSession(s.ctx, full)
		if err != nil {
			return nil, fsError("readdir", name, err)
		}
		defer session.release()
		shares, err := session.ListShareNames(s.ctx)
		if err != nil {
			return nil, fsError("readdir", name, err)
		}
		for _, share := range shares {
			if share == "." || !validFSPath(share) || strings.Contains(share, "/") {
				return nil, fsError("readdir", name, fs.ErrInvalid)
			}
			entries = append(entries, fs.FileInfoToDirEntry(virtualInfo(share)))
		}
	default:
		infos, err := s.client.ReadDir(s.ctx, uncPath(full))
		if err != nil {
			return nil, fsError("readdir", name, err)
		}
		for _, info := range infos {
			entries = append(entries, fs.FileInfoToDirEntry(info))
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (s *boundClient) ReadFile(name string) ([]byte, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, fsError("readfile", name, err)
	}
	if !strings.Contains(full, "/") {
		return nil, fsError("readfile", name, syscall.EISDIR)
	}
	data, err := s.client.ReadFile(s.ctx, uncPath(full))
	return data, fsError("readfile", name, err)
}

func (s *boundClient) ReadLink(name string) (string, error) {
	full, err := s.resolve(name)
	if err != nil {
		return "", fsError("readlink", name, err)
	}
	if !strings.Contains(full, "/") {
		return "", fsError("readlink", name, fs.ErrInvalid)
	}
	target, err := s.client.Readlink(s.ctx, uncPath(full))
	return pathpkg.ToPOSIXPath(target), fsError("readlink", name, err)
}

func (s *boundClient) Sub(dir string) (fs.FS, error) {
	full, err := s.resolve(dir)
	if err != nil {
		return nil, fsError("sub", dir, err)
	}
	return &boundClient{client: s.client, ctx: s.ctx, root: full}, nil
}

func (s *boundClient) Glob(pattern string) ([]string, error) {
	if _, err := s.resolve("."); err != nil {
		return nil, fsError("glob", pattern, err)
	}
	return pathpkg.GlobFS(pattern, s.Lstat, func(dir, pattern string) ([]string, error) {
		full, err := s.resolve(dir)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, fsError("glob", dir, err)
			}
			return nil, nil
		}
		if !strings.Contains(full, "/") {
			entries, err := s.ReadDir(dir)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, fsError("glob", dir, err)
				}
				return nil, nil
			}
			names := make([]string, len(entries))
			for i, entry := range entries {
				names[i] = entry.Name()
			}
			return names, nil
		}
		matches, err := s.client.globNames(s.ctx, uncPath(full), pathpkg.SMBSearchPattern(pattern))
		if err != nil {
			return nil, fsError("glob", dir, err)
		}
		return matches, nil
	})
}

type namedInfo struct {
	fs.FileInfo
	name string
}

func (i namedInfo) Name() string { return i.name }

type virtualInfo string

func (i virtualInfo) Name() string     { return string(i) }
func (virtualInfo) Size() int64        { return 0 }
func (virtualInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (virtualInfo) ModTime() time.Time { return time.Time{} }
func (virtualInfo) IsDir() bool        { return true }
func (virtualInfo) Sys() any           { return nil }

type virtualDirectory struct {
	mu      sync.Mutex
	name    string
	info    virtualInfo
	entries []fs.DirEntry
	offset  int
	closed  bool
}

func (d *virtualDirectory) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fsError("close", d.name, fs.ErrClosed)
	}
	d.closed = true
	return nil
}

func (d *virtualDirectory) Stat() (fs.FileInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fsError("stat", d.name, fs.ErrClosed)
	}
	return d.info, nil
}

func (d *virtualDirectory) Read([]byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, fsError("read", d.name, fs.ErrClosed)
	}
	return 0, fsError("read", d.name, syscall.EISDIR)
}

func (d *virtualDirectory) ReadDir(n int) ([]fs.DirEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fsError("readdir", d.name, fs.ErrClosed)
	}
	if n > 0 && d.offset == len(d.entries) {
		return nil, io.EOF
	}
	end := len(d.entries)
	if n > 0 && n < end-d.offset {
		end = d.offset + n
	}
	entries := append([]fs.DirEntry{}, d.entries[d.offset:end]...)
	d.offset = end
	return entries, nil
}

type boundClientFile struct {
	file interface {
		fs.File
		fs.ReadDirFile
	}
	name, base string
}

func (f *boundClientFile) Close() error { return fsError("close", f.name, f.file.Close()) }
func (f *boundClientFile) Stat() (fs.FileInfo, error) {
	info, err := f.file.Stat()
	if err != nil {
		return nil, fsError("stat", f.name, err)
	}
	return namedInfo{FileInfo: info, name: f.base}, nil
}

func (f *boundClientFile) Read(p []byte) (int, error) {
	n, err := f.file.Read(p)
	if err == io.EOF {
		return n, err
	}
	return n, fsError("read", f.name, err)
}

func (f *boundClientFile) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := f.file.ReadDir(n)
	if err == io.EOF {
		return entries, err
	}
	return entries, fsError("readdir", f.name, err)
}
