package dfs

import (
	"context"
	"errors"
	"os"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
)

// unwrapFilesystemError removes lower-layer operation wrappers so upper
// errors display the original absolute UNC supplied by the caller.
func unwrapFilesystemError(err error) error {
	for err != nil {
		switch wrapped := err.(type) {
		case *os.PathError:
			err = wrapped.Err
		case *os.LinkError:
			err = wrapped.Err
		default:
			return err
		}
	}
	return nil
}

func (d *DFS) executeValue(ctx context.Context, name, op string, action routeAction) (any, error) {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(name)
	if err != nil {
		return nil, &os.PathError{Op: op, Path: name, Err: err}
	}
	value, err := d.execute(ctx, path, action)
	if err != nil {
		return nil, &os.PathError{Op: op, Path: name, Err: unwrapFilesystemError(err)}
	}
	return value, nil
}

func (d *DFS) executeError(ctx context.Context, path, op string, action routeAction) error {
	_, err := d.executeValue(ctx, path, op, action)
	return err
}

// resolveRoute resolves the DFS namespace for path and returns the route a
// mutation must target. The Lstat probe inspects the final symbolic link itself
// (FILE_OPEN_REPARSE_POINT) and lets execute follow referrals or links that
// cross a share/server boundary, matching os.Remove/os.Rename semantics. When
// allowMissing is set, a missing leaf is not an error.
func (d *DFS) resolveRoute(ctx context.Context, name string, allowMissing bool) (*resolvedRoute, error) {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(name)
	if err != nil {
		return nil, err
	}
	var final *resolvedRoute
	_, err = d.execute(ctx, path, func(ctx context.Context, route *resolvedRoute) (any, error) {
		final = route
		if routeLinkError(route) != nil {
			// The referral prefix itself is the object being removed or moved;
			// do not probe its selected target at all.
			return nil, nil
		}
		if _, probeErr := route.share.Lstat(ctx, route.path.RelPath); probeErr != nil {
			if allowMissing && errors.Is(probeErr, os.ErrNotExist) {
				return nil, nil
			}
			return nil, probeErr
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return final, nil
}

// Open opens an absolute UNC path and returns a file bound to its selected
// target tree.
func (d *DFS) Open(ctx context.Context, name string) (*File, error) {
	return d.OpenFile(ctx, name, os.O_RDONLY, 0)
}

func (d *DFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*File, error) {
	value, err := d.executeValue(ctx, name, "open", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.OpenFile(ctx, route.path.RelPath, flag, perm)
	})
	if err != nil {
		return nil, err
	}
	opened, ok := value.(*v2.File)
	if !ok || opened == nil {
		return nil, &v2.InternalError{Message: "unexpected file handle"}
	}
	return &File{File: opened, name: name}, nil
}

func (d *DFS) Create(ctx context.Context, name string) (*File, error) {
	return d.OpenFile(ctx, name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (d *DFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "stat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Stat(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (d *DFS) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "lstat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.source != nil && route.exact && !route.source.root {
			return nil, ErrDFSLinkOperation
		}
		return route.share.Lstat(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (d *DFS) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	value, err := d.executeValue(ctx, name, "readdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadDir(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.([]os.FileInfo), nil
}

func (d *DFS) ReadFile(ctx context.Context, name string) ([]byte, error) {
	value, err := d.executeValue(ctx, name, "readfile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadFile(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (d *DFS) WriteFile(ctx context.Context, name string, data []byte, perm os.FileMode) error {
	// WriteFile is a compound mutation. Its lower typed continuation errors
	// certify that a stopped CREATE did not execute the later write.
	return d.executeError(ctx, name, "writefile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.WriteFile(ctx, route.path.RelPath, data, perm)
	})
}

func (d *DFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return d.executeError(ctx, name, "mkdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Mkdir(ctx, route.path.RelPath, perm)
	})
}

func (d *DFS) Remove(ctx context.Context, name string) error {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(name)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}
	_, err = d.execute(ctx, path, func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.path.RelPath == "" {
			return nil, ErrShareRootOperation
		}
		if special := routeLinkError(route); special != nil {
			return nil, special
		}
		return nil, route.share.Remove(ctx, route.path.RelPath)
	})
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (d *DFS) Rename(ctx context.Context, oldpath, newpath string) error {
	if ctx == nil {
		panic("nil context")
	}
	// The destination may not exist yet; resolve it once so both endpoints are
	// compared against the same namespace snapshot.
	newRoute, err := d.resolveRoute(ctx, newpath, true)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	oldName, err := pathpkg.NormalizeUNC(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	_, err = d.execute(ctx, oldName, func(ctx context.Context, oldRoute *resolvedRoute) (any, error) {
		if oldRoute.path.RelPath == "" || newRoute.path.RelPath == "" {
			return nil, ErrShareRootOperation
		}
		if special := routeLinkError(oldRoute); special != nil {
			return nil, special
		}
		if special := routeLinkError(newRoute); special != nil {
			return nil, special
		}
		if canonicalKey(oldRoute.path.Server, oldRoute.path.Share) != canonicalKey(newRoute.path.Server, newRoute.path.Share) {
			return nil, ErrCrossShareRename
		}
		return nil, oldRoute.share.Rename(ctx, oldRoute.path.RelPath, newRoute.path.RelPath)
	})
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (d *DFS) Symlink(ctx context.Context, target, linkpath string) error {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(linkpath)
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

func (d *DFS) Readlink(ctx context.Context, name string) (string, error) {
	value, err := d.executeValue(ctx, name, "readlink", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.source != nil && route.exact && !route.source.root {
			return nil, ErrDFSLinkOperation
		}
		return route.share.Readlink(ctx, route.path.RelPath)
	})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

func (d *DFS) Truncate(ctx context.Context, name string, size int64) error {
	return d.executeError(ctx, name, "truncate", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Truncate(ctx, route.path.RelPath, size)
	})
}

func (d *DFS) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	return d.executeError(ctx, name, "chmod", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chmod(ctx, route.path.RelPath, mode)
	})
}

func (d *DFS) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	return d.executeError(ctx, name, "chtimes", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chtimes(ctx, route.path.RelPath, atime, mtime)
	})
}

func (d *DFS) Statfs(ctx context.Context, name string) (v2.FileFsInfo, error) {
	value, err := d.executeValue(ctx, name, "statfs", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Statfs(ctx, route.path.RelPath)
	})
	if err != nil {
		return nil, err
	}
	return value.(v2.FileFsInfo), nil
}
