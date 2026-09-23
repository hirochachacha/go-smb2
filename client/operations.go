package client

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/directory"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/security"
)

// Open opens an absolute UNC path and returns a file bound to its selected
// target tree.
func (d *Client) Open(ctx context.Context, name string) (*File, error) {
	return d.OpenFile(ctx, name, os.O_RDONLY, 0)
}

func (d *Client) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*File, error) {
	value, err := d.executeValue(ctx, name, "open", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if flag&os.O_EXCL != 0 && route.isExactLink() {
			return nil, os.ErrPermission
		}
		opened, err := route.share.OpenFile(ctx, route.path.RelPath, flag, perm)
		if err != nil {
			return nil, err
		}
		d.mu.Lock()
		route.session.retain()
		d.mu.Unlock()
		return &File{file: opened, name: name, session: route.session}, nil
	})
	if err != nil {
		return nil, err
	}
	opened, ok := value.(*File)
	if !ok || opened == nil {
		return nil, errors.New("client: unexpected file handle")
	}
	return opened, nil
}

func (d *Client) Create(ctx context.Context, name string) (*File, error) {
	return d.OpenFile(ctx, name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (d *Client) ReadFile(ctx context.Context, name string) ([]byte, error) {
	value, err := d.executeValue(ctx, name, "readfile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadFile(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (d *Client) WriteFile(ctx context.Context, name string, data []byte, perm os.FileMode) error {
	// WriteFile is a compound mutation. Its lower typed continuation errors
	// certify that a stopped CREATE did not execute the later write.
	return d.executeError(ctx, name, "writefile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.WriteFile(ctx, route.path.RelPath, data, perm)
	})
}

func (d *Client) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return d.executeError(ctx, name, "mkdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Mkdir(ctx, route.path.RelPath, perm)
	})
}

// MkdirAll creates name and any missing parents with perm. It succeeds if
// name already names a directory. Servers and shares must already exist.
func (d *Client) MkdirAll(ctx context.Context, name string, perm os.FileMode) error {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(pathpkg.ToSMBPath(name))
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	info, err := d.Stat(ctx, path)
	if err == nil {
		if info.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: name, Err: syscall.ENOTDIR}
	}
	unc, _ := pathpkg.ParseUNC(path)
	if unc.RelPath == "" || !errors.Is(err, os.ErrNotExist) {
		return &os.PathError{Op: "mkdir", Path: name, Err: unwrapFilesystemError(err)}
	}
	// Resolve each parent independently: a referral for a missing parent
	// must not replace the original path of the directory being created.
	if err := d.MkdirAll(ctx, pathpkg.Dir(path), perm); err != nil {
		return err
	}
	if err := d.Mkdir(ctx, path, perm); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		info, statErr := d.Lstat(ctx, path)
		if errors.Is(statErr, context.Canceled) || errors.Is(statErr, context.DeadlineExceeded) {
			return statErr
		}
		if statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func (d *Client) Remove(ctx context.Context, name string) error {
	return d.executeError(ctx, name, "remove", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.isExactLink() {
			return nil, os.ErrPermission
		}
		return nil, route.share.Remove(ctx, route.path.RelPath)
	})
}

// RemoveAll removes name and its children without following final symbolic
// links. An empty name or a nonexistent path succeeds. Share roots and DFS
// links themselves cannot be removed. Once the target share is resolved,
// recursive deletion does not follow referrals to other shares.
func (d *Client) RemoveAll(ctx context.Context, name string) error {
	if ctx == nil {
		panic("nil context")
	}
	if name == "" {
		return nil
	}
	path, err := pathpkg.ParseUNC(pathpkg.Normalize(pathpkg.ToSMBPath(name)))
	if err == nil && path.RelPath == "" {
		err = os.ErrInvalid
	}
	if err != nil {
		return &os.PathError{Op: "removeall", Path: name, Err: err}
	}
	route, err := d.resolveRoute(ctx, name, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		defer route.session.release()
		switch {
		case route.isExactLink():
			err = os.ErrPermission
		case route.path.RelPath == "":
			err = os.ErrInvalid
		default:
			// Do not run deletion inside execute: a referral encountered in
			// a child must not restart deletion at the referral target.
			err = route.share.RemoveAll(ctx, route.path.RelPath)
		}
	}
	if err != nil {
		return &os.PathError{Op: "removeall", Path: name, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (d *Client) Rename(ctx context.Context, oldpath, newpath string) error {
	if ctx == nil {
		panic("nil context")
	}
	// The destination may not exist yet; resolve it once so both endpoints are
	// compared against the same namespace snapshot.
	newRoute, err := d.resolveRoute(ctx, newpath, true)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	defer newRoute.session.release()
	oldName, err := pathpkg.NormalizeUNC(pathpkg.ToSMBPath(oldpath))
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	_, err = d.execute(ctx, oldName, func(ctx context.Context, oldRoute *resolvedRoute) (any, error) {
		if oldRoute.isExactLink() || newRoute.isExactLink() {
			return nil, os.ErrPermission
		}
		if canonicalKey(oldRoute.path.Server, oldRoute.path.Share) != canonicalKey(newRoute.path.Server, newRoute.path.Share) {
			return nil, errCrossShareRename
		}
		return nil, oldRoute.share.Rename(ctx, oldRoute.path.RelPath, newRoute.path.RelPath)
	})
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (d *Client) Symlink(ctx context.Context, target, linkpath string) error {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(pathpkg.ToSMBPath(linkpath))
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}
	_, err = d.execute(ctx, path, func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Symlink(ctx, target, route.path.RelPath)
	})
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (d *Client) Readlink(ctx context.Context, name string) (string, error) {
	value, err := d.executeValue(ctx, name, "readlink", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.isExactLink() {
			return nil, os.ErrPermission
		}
		return route.share.Readlink(ctx, route.path.RelPath)
	})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

func (d *Client) Truncate(ctx context.Context, name string, size int64) error {
	return d.executeError(ctx, name, "truncate", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Truncate(ctx, route.path.RelPath, size)
	})
}

func (d *Client) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	return d.executeError(ctx, name, "chmod", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chmod(ctx, route.path.RelPath, mode)
	})
}

func (d *Client) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	return d.executeError(ctx, name, "chtimes", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chtimes(ctx, route.path.RelPath, atime, mtime)
	})
}

func (d *Client) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "stat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Stat(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (d *Client) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "lstat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.isExactLink() {
			return nil, os.ErrPermission
		}
		return route.share.Lstat(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (d *Client) Statfs(ctx context.Context, name string) (v2.FileFsInfo, error) {
	value, err := d.executeValue(ctx, name, "statfs", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Statfs(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(v2.FileFsInfo), nil
}

func (d *Client) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "readdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadDir(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.([]os.FileInfo), nil
}

// globNames resolves and opens a directory once, then enumerates candidates
// on that handle without restarting enumeration on a different share.
func (d *Client) globNames(ctx context.Context, dir, pattern string) ([]string, error) {
	var session *sessionEntry
	value, err := d.executeValue(ctx, dir, "glob", func(ctx context.Context, route *resolvedRoute) (any, error) {
		reader, err := directory.Open(ctx, route.share.Request, route.path.RelPath)
		if err != nil {
			return nil, err
		}
		session = route.session
		d.mu.Lock()
		session.retain()
		d.mu.Unlock()
		return reader, nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, nil
	} // Glob ignores directory lookup failures.
	defer session.release()
	reader := value.(*directory.Reader)
	defer reader.Close()
	names, err := reader.Names(ctx, pattern)
	if err != nil {
		return nil, &os.PathError{Op: "glob", Path: dir, Err: err}
	}
	return names, nil
}

// GetSecurityDescriptor returns the selected security information for name,
// following symbolic links and DFS referrals.
func (d *Client) GetSecurityDescriptor(ctx context.Context, name string, selection security.Information) (*security.Descriptor, error) {
	value, err := d.executeValue(ctx, name, "getsecuritydescriptor", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.GetSecurityDescriptor(ctx, route.path.RelPath, selection)
	})
	if err != nil {
		return nil, err
	}
	return value.(*security.Descriptor), nil
}

// SetSecurityDescriptor applies the non-nil fields of descriptor to name,
// following symbolic links and DFS referrals. Nil fields remain unchanged.
func (d *Client) SetSecurityDescriptor(ctx context.Context, name string, descriptor *security.Descriptor) error {
	return d.executeError(ctx, name, "setsecuritydescriptor", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.SetSecurityDescriptor(ctx, route.path.RelPath, descriptor)
	})
}
