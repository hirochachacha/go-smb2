package dfs

import (
	"context"
	"errors"
	"os"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
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

func (c *Client) executeValue(ctx context.Context, path, op string, action routeAction) (any, error) {
	value, err := c.execute(ctx, path, action)
	if err != nil {
		return nil, &os.PathError{Op: op, Path: path, Err: unwrapFilesystemError(err)}
	}
	return value, nil
}

func (c *Client) executeError(ctx context.Context, path, op string, action routeAction) error {
	_, err := c.executeValue(ctx, path, op, action)
	return err
}

// resolveRoute resolves the DFS namespace for path and returns the route a
// mutation must target. The Lstat probe inspects the final symbolic link itself
// (FILE_OPEN_REPARSE_POINT) and lets execute follow referrals or links that
// cross a share/server boundary, matching os.Remove/os.Rename semantics. When
// allowMissing is set, a missing leaf is not an error.
func (c *Client) resolveRoute(ctx context.Context, path string, allowMissing bool) (*resolvedRoute, error) {
	var final *resolvedRoute
	_, err := c.execute(ctx, path, func(ctx context.Context, route *resolvedRoute) (any, error) {
		final = route
		if routeLinkError(route) != nil {
			// The referral prefix itself is the object being removed or moved;
			// do not probe its selected target at all.
			return nil, nil
		}
		if _, probeErr := route.share.Lstat(ctx, route.path.rest); probeErr != nil {
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
func (c *Client) Open(ctx context.Context, name string) (*File, error) {
	return c.OpenFile(ctx, name, os.O_RDONLY, 0)
}

func (c *Client) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*File, error) {
	value, err := c.executeValue(ctx, name, "open", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.OpenFile(ctx, route.path.rest, flag, perm)
	})
	if err != nil {
		return nil, err
	}
	opened, ok := value.(*v2.File)
	if !ok || opened == nil {
		return nil, &v2.InternalError{"unexpected file handle"}
	}
	return &File{File: opened, name: name}, nil
}

func (c *Client) Create(ctx context.Context, name string) (*File, error) {
	return c.OpenFile(ctx, name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (c *Client) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := c.executeValue(ctx, name, "stat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Stat(ctx, route.path.rest)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (c *Client) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	value, err := c.executeValue(ctx, name, "lstat", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.source != nil && route.exact && !route.source.root {
			return nil, ErrDFSLinkOperation
		}
		return route.share.Lstat(ctx, route.path.rest)
	})
	if err != nil {
		return nil, err
	}
	return value.(os.FileInfo), nil
}

func (c *Client) ReadDir(ctx context.Context, name string) ([]os.FileInfo, error) {
	value, err := c.executeValue(ctx, name, "readdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadDir(ctx, route.path.rest)
	})
	if err != nil {
		return nil, err
	}
	return value.([]os.FileInfo), nil
}

func (c *Client) ReadFile(ctx context.Context, name string) ([]byte, error) {
	value, err := c.executeValue(ctx, name, "readfile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.ReadFile(ctx, route.path.rest)
	})
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (c *Client) WriteFile(ctx context.Context, name string, data []byte, perm os.FileMode) error {
	// WriteFile is a compound mutation. Its lower typed continuation errors
	// certify that a stopped CREATE did not execute the later write.
	return c.executeError(ctx, name, "writefile", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.WriteFile(ctx, route.path.rest, data, perm)
	})
}

func (c *Client) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return c.executeError(ctx, name, "mkdir", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Mkdir(ctx, route.path.rest, perm)
	})
}

func (c *Client) Remove(ctx context.Context, name string) error {
	if ctx == nil {
		panic("nil context")
	}
	_, err := c.execute(ctx, name, func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.path.rest == "" {
			return nil, ErrShareRootOperation
		}
		if special := routeLinkError(route); special != nil {
			return nil, special
		}
		return nil, route.share.Remove(ctx, route.path.rest)
	})
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (c *Client) Rename(ctx context.Context, oldpath, newpath string) error {
	if ctx == nil {
		panic("nil context")
	}
	// The destination may not exist yet; resolve it once so both endpoints are
	// compared against the same namespace snapshot.
	newRoute, err := c.resolveRoute(ctx, newpath, true)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	_, err = c.execute(ctx, oldpath, func(ctx context.Context, oldRoute *resolvedRoute) (any, error) {
		if oldRoute.path.rest == "" || newRoute.path.rest == "" {
			return nil, ErrShareRootOperation
		}
		if special := routeLinkError(oldRoute); special != nil {
			return nil, special
		}
		if special := routeLinkError(newRoute); special != nil {
			return nil, special
		}
		if canonicalKey(oldRoute.path.server, oldRoute.path.share) != canonicalKey(newRoute.path.server, newRoute.path.share) {
			return nil, ErrCrossShareRename
		}
		return nil, oldRoute.share.Rename(ctx, oldRoute.path.rest, newRoute.path.rest)
	})
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (c *Client) Symlink(ctx context.Context, target, linkpath string) error {
	_, err := c.execute(ctx, linkpath, func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Symlink(ctx, target, route.path.rest)
	})
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: unwrapFilesystemError(err)}
	}
	return nil
}

func (c *Client) Readlink(ctx context.Context, name string) (string, error) {
	value, err := c.executeValue(ctx, name, "readlink", func(ctx context.Context, route *resolvedRoute) (any, error) {
		if route.source != nil && route.exact && !route.source.root {
			return nil, ErrDFSLinkOperation
		}
		return route.share.Readlink(ctx, route.path.rest)
	})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

func (c *Client) Truncate(ctx context.Context, name string, size int64) error {
	return c.executeError(ctx, name, "truncate", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Truncate(ctx, route.path.rest, size)
	})
}

func (c *Client) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	return c.executeError(ctx, name, "chmod", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chmod(ctx, route.path.rest, mode)
	})
}

func (c *Client) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	return c.executeError(ctx, name, "chtimes", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.Chtimes(ctx, route.path.rest, atime, mtime)
	})
}

func (c *Client) Statfs(ctx context.Context, name string) (v2.FileFsInfo, error) {
	value, err := c.executeValue(ctx, name, "statfs", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Statfs(ctx, route.path.rest)
	})
	if err != nil {
		return nil, err
	}
	return value.(v2.FileFsInfo), nil
}
