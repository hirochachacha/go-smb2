// Package client provides transparent access to SMB paths, including DFS
// referrals and ordinary symbolic links.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
)

// Option configures a client.
type Option interface {
	applyOption(*config)
}

type config struct {
	sessionIdleTimeout time.Duration
}

type sessionIdleTimeoutOption time.Duration

func (o sessionIdleTimeoutOption) applyOption(c *config) {
	c.sessionIdleTimeout = time.Duration(o)
}

// WithSessionIdleTimeout returns an Option that sets the idle timeout for cached
// sessions.
func WithSessionIdleTimeout(d time.Duration) Option {
	return sessionIdleTimeoutOption(d)
}

// Client owns the sessions and shares it creates while resolving paths.
// Sessions remain owned until Close, including sessions used only for DFS
// referral queries.
type Client struct {
	dialer             *smb2.Dialer
	sessionIdleTimeout time.Duration

	mu        sync.Mutex
	lifetime  context.Context
	cancel    context.CancelFunc
	closing   bool
	closeDone chan struct{}
	closeErr  error

	sessions  map[string]*smb2.Session
	retired   map[*smb2.Session]struct{}
	shares    map[string]*shareEntry
	referrals map[string]*referralEntry
	inflight  map[string]*creation
	wg        sync.WaitGroup
}

type creation struct {
	done  chan struct{}
	value any
	err   error
}

type shareEntry struct {
	session *smb2.Session
	value   *smb2.Share
}

// New creates a client using dialer and optional configuration options.
// The client takes a reference to the dialer; callers must not modify the
// dialer while the client is in use.
func New(dialer *smb2.Dialer, options ...Option) *Client {
	var cfg config
	for _, opt := range options {
		if opt != nil {
			opt.applyOption(&cfg)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		dialer:             dialer,
		sessionIdleTimeout: cfg.sessionIdleTimeout,
		lifetime:           ctx,
		cancel:             cancel,
		closeDone:          make(chan struct{}),
		sessions:           make(map[string]*smb2.Session),
		retired:            make(map[*smb2.Session]struct{}),
		shares:             make(map[string]*shareEntry),
		referrals:          make(map[string]*referralEntry),
		inflight:           make(map[string]*creation),
	}
}

func canonicalKey(parts ...string) string {
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, "\\")
}

func (d *Client) beginCreation(key string) (*creation, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lifetime == nil {
		return nil, false, os.ErrInvalid
	}
	if d.closing {
		return nil, false, net.ErrClosed
	}
	if current := d.inflight[key]; current != nil {
		return current, false, nil
	}
	call := &creation{done: make(chan struct{})}
	d.inflight[key] = call
	d.wg.Add(1)
	return call, true, nil
}

func (d *Client) finishCreation(key string, call *creation, value any, err error) {
	d.mu.Lock()
	if d.inflight[key] == call {
		delete(d.inflight, key)
	}
	call.value, call.err = value, err
	close(call.done)
	d.mu.Unlock()
	d.wg.Done()
}

func waitCreation(ctx context.Context, call *creation) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		return call.value, call.err
	}
}

// acquire returns the cached value for key, or runs create once per key and
// shares the result with concurrent callers. cached is called with d.mu held.
// create runs once in its own goroutine and must publish the value itself,
// cleaning it up and returning an error if the client has closed.
func acquire[T any](d *Client, ctx context.Context, key string, cached func() (T, bool), create func() (T, error)) (T, error) {
	var zero T
	if ctx == nil {
		panic("nil context")
	}
	d.mu.Lock()
	if d.lifetime == nil {
		d.mu.Unlock()
		return zero, os.ErrInvalid
	}
	if d.closing {
		d.mu.Unlock()
		return zero, net.ErrClosed
	}
	if value, ok := cached(); ok {
		d.mu.Unlock()
		return value, nil
	}
	d.mu.Unlock()

	call, owner, err := d.beginCreation(key)
	if err != nil {
		return zero, err
	}
	if owner {
		// A creation may have completed between the fast path and
		// beginCreation, so re-check before starting a new one.
		d.mu.Lock()
		value, ok := cached()
		d.mu.Unlock()
		if ok {
			d.finishCreation(key, call, value, nil)
		} else {
			go func() {
				var (
					value any
					err   error
				)
				defer func() {
					if r := recover(); r != nil {
						d.finishCreation(key, call, nil, fmt.Errorf("client: creation panicked: %v", r))
						panic(r)
					}
				}()
				value, err = create()
				d.finishCreation(key, call, value, err)
			}()
		}
	}
	value, err := waitCreation(ctx, call)
	if err != nil {
		return zero, err
	}
	v, ok := value.(T)
	if !ok {
		return zero, errors.New("client: creation returned no value")
	}
	return v, nil
}

func (d *Client) acquireSession(ctx context.Context, server string) (*smb2.Session, error) {
	key := canonicalKey(server)
	return acquire(d, ctx, "session:"+key,
		func() (*smb2.Session, bool) {
			session := d.sessions[key]
			return session, session != nil
		},
		func() (*smb2.Session, error) {
			if d.dialer == nil {
				return nil, errors.New("client: nil Dialer")
			}
			session, err := d.dialer.Dial(d.lifetime, server)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errors.New("client: session creation returned no session")
			}
			d.mu.Lock()
			closed := d.closing
			if !closed {
				d.sessions[key] = session
			}
			d.mu.Unlock()
			if closed {
				_ = session.Close()
				return nil, net.ErrClosed
			}
			return session, nil
		},
	)
}

func shareKey(server, share string) string {
	return canonicalKey(server, share)
}

func (d *Client) acquireShare(ctx context.Context, server, share string) (*smb2.Share, error) {
	key := shareKey(server, share)
	return acquire(d, ctx, "share:"+key,
		func() (*smb2.Share, bool) {
			entry := d.shares[key]
			if entry == nil {
				return nil, false
			}
			return entry.value, true
		},
		func() (*smb2.Share, error) {
			session, err := d.acquireSession(d.lifetime, server)
			if err != nil {
				return nil, err
			}
			shareValue, err := session.Mount(d.lifetime, share)
			if err != nil {
				if isUnavailable(err) {
					d.invalidateSession(server, session)
				}
				return nil, err
			}
			if shareValue == nil {
				return nil, errors.New("client: share creation returned no share")
			}
			d.mu.Lock()
			closed := d.closing
			current := d.sessions[canonicalKey(server)]
			if !closed && current != nil && current == session {
				d.shares[key] = &shareEntry{session: session, value: shareValue}
			} else {
				closed = true
			}
			d.mu.Unlock()
			if closed {
				_ = shareValue.Unmount(context.Background())
				return nil, net.ErrClosed
			}
			return shareValue, nil
		},
	)
}

// invalidateSession discards one failed connection generation and every share
// mounted through it. Pointer identity prevents an older error from evicting a
// replacement session that was published concurrently.
func (d *Client) invalidateSession(server string, stale *smb2.Session) {
	if stale == nil {
		return
	}
	key := canonicalKey(server)
	d.mu.Lock()
	current := d.sessions[key]
	if current == nil || current != stale {
		d.mu.Unlock()
		return
	}
	delete(d.sessions, key)
	d.retired[stale] = struct{}{}
	for shareKey, entry := range d.shares {
		if entry != nil && entry.session == stale {
			delete(d.shares, shareKey)
		}
	}
	d.mu.Unlock()
	go stale.Close()
}

// Close stops new operations and closes all sessions owned by the client.
// Concurrent callers wait for the same shutdown result.
func (d *Client) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	if d.lifetime == nil {
		d.mu.Unlock()
		return nil
	}
	if d.closing {
		done := d.closeDone
		d.mu.Unlock()
		<-done
		return d.closeErr
	}
	d.closing = true
	d.cancel()
	sessions := make([]*smb2.Session, 0, len(d.sessions)+len(d.retired))
	for _, session := range d.sessions {
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	for session := range d.retired {
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	done := d.closeDone
	d.mu.Unlock()

	var closeWG sync.WaitGroup
	var closeMu sync.Mutex
	var closeErrs []error
	for _, session := range sessions {
		closeWG.Add(1)
		go func(s *smb2.Session) {
			defer closeWG.Done()
			if err := s.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeMu.Lock()
				closeErrs = append(closeErrs, err)
				closeMu.Unlock()
			}
		}(session)
	}
	closeWG.Wait()
	d.wg.Wait()
	d.mu.Lock()
	d.closeErr = errors.Join(closeErrs...)
	close(done)
	d.mu.Unlock()
	return d.closeErr
}

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
		return route.share.OpenFile(ctx, route.path.RelPath, flag, perm)
	})
	if err != nil {
		return nil, err
	}
	opened, ok := value.(*v2.File)
	if !ok || opened == nil {
		return nil, errors.New("client: unexpected file handle")
	}
	return &File{File: opened, name: name}, nil
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
	path, err := pathpkg.NormalizeUNC(name)
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
	if err := d.MkdirAll(ctx, path[:strings.LastIndexByte(path, '\\')], perm); err != nil {
		return err
	}
	if err := d.Mkdir(ctx, path, perm); err != nil {
		if info, statErr := d.Lstat(ctx, path); statErr == nil && info.IsDir() {
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
	path, err := pathpkg.ParseUNC(pathpkg.Normalize(name))
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
	oldName, err := pathpkg.NormalizeUNC(oldpath)
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

// GetSecurityDescriptor returns the selected security information for name,
// following symbolic links and DFS referrals.
func (d *Client) GetSecurityDescriptor(ctx context.Context, name string, selection security.Information) (*security.Descriptor, error) {
	value, err := d.executeValue(ctx, name, "getSecurityDescriptor", func(ctx context.Context, route *resolvedRoute) (any, error) {
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
	return d.executeError(ctx, name, "setSecurityDescriptor", func(ctx context.Context, route *resolvedRoute) (any, error) {
		return nil, route.share.SetSecurityDescriptor(ctx, route.path.RelPath, descriptor)
	})
}

// maxReferralDepth bounds how many times referral resolution may restart for a
// single operation. The SMB layer separately bounds same-tree symbolic links
// per CREATE, so alternating referral and symlink traversal stays finite.
const maxReferralDepth = 32

var (
	errCrossShareRename = errors.New("client: cross-share rename")
	errReferralDepth    = errors.New("client: referral traversal limit exceeded")
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

func (d *Client) executeValue(ctx context.Context, name, op string, action routeAction) (any, error) {
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

func (d *Client) executeError(ctx context.Context, path, op string, action routeAction) error {
	_, err := d.executeValue(ctx, path, op, action)
	return err
}

// resolveRoute resolves the DFS namespace for path and returns the route a
// mutation must target. The Lstat probe inspects the final symbolic link itself
// (FILE_OPEN_REPARSE_POINT) and lets execute follow referrals or links that
// cross a share/server boundary, matching os.Remove/os.Rename semantics. When
// allowMissing is set, a missing leaf is not an error.
func (d *Client) resolveRoute(ctx context.Context, name string, allowMissing bool) (*resolvedRoute, error) {
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
		if route.isExactLink() {
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

type referralTarget struct {
	unc      string
	boundary bool
}

type referralEntry struct {
	prefix                    string
	root, interlink, failback bool
	expires                   time.Time
	cacheable                 bool
	targets                   []referralTarget
	hint                      int
}

type resolvedRoute struct {
	share  *v2.Share
	path   pathpkg.UNC
	source *referralEntry
	exact  bool
}

func (r *resolvedRoute) isExactLink() bool {
	return r != nil && r.source != nil && r.exact && !r.source.root
}

func (d *Client) invalidateRoute(route *resolvedRoute) {
	if route == nil || route.share == nil {
		return
	}
	key := shareKey(route.path.Server, route.path.Share)
	var staleSession *v2.Session
	d.mu.Lock()
	if entry := d.shares[key]; entry != nil && entry.value == route.share {
		staleSession = entry.session
	}
	d.mu.Unlock()
	if staleSession != nil {
		d.invalidateSession(route.path.Server, staleSession)
	}
}

func (d *Client) lookupReferral(path string, checkExpiry bool) (*referralEntry, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best *referralEntry
	var bestSuffix string
	for _, entry := range d.referrals {
		if entry == nil || !entry.cacheable {
			continue
		}
		if checkExpiry && !time.Now().Before(entry.expires) {
			continue
		}
		suffix, ok := pathpkg.CutPrefix(path, entry.prefix)
		if !ok {
			continue
		}
		if best == nil || len(entry.prefix) > len(best.prefix) {
			best, bestSuffix = entry, suffix
		}
	}
	return best, bestSuffix
}

func (d *Client) cacheEntry(path string) (*referralEntry, string, bool) {
	entry, suffix := d.lookupReferral(path, true)
	return entry, suffix, entry != nil
}

func (d *Client) staleEntry(path string) *referralEntry {
	entry, _ := d.lookupReferral(path, false)
	return entry
}

func (d *Client) installReferral(response *dfs.ReferralResponse, request string) (*referralEntry, error) {
	if response == nil {
		return nil, errors.New("client: nil referral response")
	}
	if len(response.Entries) == 0 {
		return nil, fmt.Errorf("client: referral has no targets: %w", os.ErrNotExist)
	}
	prefix := response.Prefix
	if prefix == "" {
		return nil, errors.New("client: referral has no storage prefix")
	}
	if _, ok := pathpkg.CutPrefix(request, prefix); !ok {
		return nil, fmt.Errorf("client: referral prefix %q does not match %q", prefix, request)
	}
	first := response.Entries[0]
	entry := &referralEntry{
		prefix:    prefix,
		root:      first.ServerType == dfs.ServerRoot,
		interlink: response.HeaderFlags&(dfs.HeaderServers|dfs.HeaderStorage) == dfs.HeaderServers,
		failback:  response.HeaderFlags&dfs.HeaderFailback != 0,
		cacheable: first.Version > 1,
		targets:   make([]referralTarget, 0, len(response.Entries)),
	}
	if entry.cacheable {
		entry.expires = time.Now().Add(first.TTL)
	}
	for _, item := range response.Entries {
		if item.NetworkAddress == "" || item.Flags&dfs.FlagNameList != 0 {
			continue
		}
		target, err := pathpkg.ParseUNC(item.NetworkAddress)
		if err != nil {
			return nil, err
		}
		entry.targets = append(entry.targets, referralTarget{unc: target.String(), boundary: item.Flags&dfs.FlagTargetSetBoundary != 0})
	}
	if len(entry.targets) == 0 {
		return nil, fmt.Errorf("client: referral has no usable targets: %w", os.ErrNotExist)
	}
	d.mu.Lock()
	if entry.cacheable {
		if old := d.referrals[strings.ToLower(prefix)]; old != nil {
			merged := *old
			merged.targets = append([]referralTarget(nil), old.targets...)
			mergeReferral(&merged, entry)
			d.referrals[strings.ToLower(prefix)] = &merged
			entry = &merged
		} else {
			d.referrals[strings.ToLower(prefix)] = entry
		}
	}
	d.mu.Unlock()
	return entry, nil
}

func mergeReferral(old, fresh *referralEntry) {
	var hinted string
	if old.hint >= 0 && old.hint < len(old.targets) {
		hinted = old.targets[old.hint].unc
	}
	old.prefix, old.root = fresh.prefix, fresh.root
	old.interlink, old.failback = fresh.interlink, fresh.failback
	old.expires, old.cacheable = fresh.expires, fresh.cacheable
	if !equivalentTargets(old.targets, fresh.targets) {
		old.targets = fresh.targets
	}
	if hinted != "" {
		old.hint = 0
		for i, target := range old.targets {
			if strings.EqualFold(target.unc, hinted) {
				old.hint = i
				break
			}
		}
	} else {
		old.hint = 0
	}
	if old.failback {
		start, _ := targetSet(old.targets, old.hint)
		if start != 0 {
			old.hint = 0
		}
	}
}

func equivalentTargets(a, b []referralTarget) bool {
	sets := func(in []referralTarget) [][]string {
		var out [][]string
		for i, target := range in {
			if i == 0 || target.boundary {
				out = append(out, nil)
			}
			out[len(out)-1] = append(out[len(out)-1], strings.ToLower(target.unc))
		}
		return out
	}
	aa, bb := sets(a), sets(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if len(aa[i]) != len(bb[i]) {
			return false
		}
		for _, target := range aa[i] {
			found := false
			for _, other := range bb[i] {
				if target == other {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func targetSet(targets []referralTarget, index int) (int, int) {
	if len(targets) == 0 {
		return 0, 0
	}
	if index < 0 || index >= len(targets) {
		index = 0
	}
	start := index
	for start > 0 && !targets[start].boundary {
		start--
	}
	end := start + 1
	for end < len(targets) && !targets[end].boundary {
		end++
	}
	return start, end
}

func orderedTargets(targets []referralTarget, hint int) []int {
	if len(targets) == 0 {
		return nil
	}
	if hint < 0 || hint >= len(targets) {
		hint = 0
	}
	start, end := targetSet(targets, hint)
	order := []int{hint}
	for i := start; i < end; i++ {
		if i != hint {
			order = append(order, i)
		}
	}
	for i := 0; i < len(targets); i++ {
		if i < start || i >= end {
			order = append(order, i)
		}
	}
	return order
}

func isUnavailable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrPermission) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var transportErr *protocol.TransportError
	if errors.As(err, &transportErr) {
		return true
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

func sameUNCPath(a, b string) bool {
	return strings.EqualFold(strings.TrimLeft(a, `\`), strings.TrimLeft(b, `\`))
}

func (d *Client) queryReferral(ctx context.Context, path string) (*referralEntry, error) {
	unc, err := pathpkg.ParseUNC(path)
	if err != nil {
		return nil, err
	}
	session, err := d.acquireSession(ctx, unc.Server)
	if err != nil {
		return nil, err
	}
	response, err := session.GetDFSReferrals(ctx, path, nil)
	if err != nil {
		if isUnavailable(err) {
			d.invalidateSession(unc.Server, session)
		}
		return nil, err
	}
	return d.installReferral(response, path)
}

func (d *Client) queryInterlink(ctx context.Context, path string, entry *referralEntry) (string, *referralEntry, error) {
	suffix, ok := pathpkg.CutPrefix(path, entry.prefix)
	if !ok {
		return "", nil, errors.New("client: interlink prefix does not match path")
	}
	d.mu.Lock()
	targets := append([]referralTarget(nil), entry.targets...)
	hint := entry.hint
	d.mu.Unlock()
	var last error
	for _, index := range orderedTargets(targets, hint) {
		queryPath := targets[index].unc + suffix
		unc, err := pathpkg.ParseUNC(queryPath)
		if err != nil {
			return "", nil, err
		}
		session, err := d.acquireSession(ctx, unc.Server)
		if err != nil {
			last = err
			if isUnavailable(err) {
				continue
			}
			return "", nil, err
		}
		response, err := session.GetDFSReferrals(ctx, queryPath, nil)
		if err != nil {
			last = err
			if isUnavailable(err) {
				d.invalidateSession(unc.Server, session)
				continue
			}
			return "", nil, err
		}
		fresh, installErr := d.installReferral(response, queryPath)
		if installErr != nil {
			return "", nil, installErr
		}
		d.mu.Lock()
		entry.hint = index
		d.mu.Unlock()
		return queryPath, fresh, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return "", nil, last
}

func (d *Client) selectRoute(ctx context.Context, path string, entry *referralEntry, suffix string) (*resolvedRoute, error) {
	if entry.interlink {
		unc, err := pathpkg.ParseUNC(path)
		if err != nil {
			return nil, err
		}
		return &resolvedRoute{path: unc, source: entry, exact: suffix == ""}, nil
	}
	d.mu.Lock()
	targets := append([]referralTarget(nil), entry.targets...)
	hint := entry.hint
	d.mu.Unlock()
	var last error
	for _, index := range orderedTargets(targets, hint) {
		targetPath := targets[index].unc + suffix
		routePath, err := pathpkg.ParseUNC(targetPath)
		if err != nil {
			return nil, err
		}
		share, err := d.acquireShare(ctx, routePath.Server, routePath.Share)
		if err != nil {
			last = err
			if isUnavailable(err) {
				continue
			}
			return nil, err
		}
		d.mu.Lock()
		entry.hint = index
		d.mu.Unlock()
		return &resolvedRoute{share: share, path: routePath, source: entry, exact: suffix == ""}, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return nil, last
}

func (d *Client) route(ctx context.Context, path string) (*resolvedRoute, error) {
	if entry, suffix, ok := d.cacheEntry(path); ok {
		return d.selectRoute(ctx, path, entry, suffix)
	}
	// Expired entries are refreshed on demand. This deliberately uses a hard
	// expiry policy; a failed refresh must not route an operation using stale
	// namespace data.
	if stale := d.staleEntry(path); stale != nil {
		fresh, err := d.queryReferral(ctx, path)
		if err != nil {
			return nil, err
		}
		if suffix, ok := pathpkg.CutPrefix(path, fresh.prefix); ok {
			return d.selectRoute(ctx, path, fresh, suffix)
		}
	}
	unc, err := pathpkg.ParseUNC(path)
	if err != nil {
		return nil, err
	}
	share, err := d.acquireShare(ctx, unc.Server, unc.Share)
	if err != nil {
		return nil, err
	}
	return &resolvedRoute{share: share, path: unc}, nil
}

type routeAction func(context.Context, *resolvedRoute) (any, error)

func (d *Client) execute(ctx context.Context, path string, action routeAction) (any, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d == nil {
		return nil, os.ErrInvalid
	}
	var forcedRoute *resolvedRoute
	for range maxReferralDepth {
		var route *resolvedRoute
		var err error
		if forcedRoute != nil {
			route, forcedRoute = forcedRoute, nil
		} else {
			route, err = d.route(ctx, path)
			if err != nil {
				return nil, err
			}
		}
		if route.source != nil && route.source.interlink {
			// An interlink has no storage server. Query the next namespace using
			// the selected target path, then restart resolution there.
			queryPath, entry, err := d.queryInterlink(ctx, path, route.source)
			if err != nil {
				return nil, err
			}
			suffix, ok := pathpkg.CutPrefix(queryPath, entry.prefix)
			if !ok {
				return nil, errors.New("client: interlink referral prefix does not match continuation")
			}
			forcedRoute, err = d.selectRoute(ctx, queryPath, entry, suffix)
			if err != nil {
				return nil, err
			}
			path = queryPath
			continue
		}
		value, err := action(ctx, route)
		if err == nil {
			return value, nil
		}
		var linkErr *protocol.CrossShareSymlinkError
		if errors.As(err, &linkErr) {
			if linkErr.ResolvedPath == "" {
				return nil, err
			}
			path = linkErr.ResolvedPath
			continue
		}
		if isUnavailable(err) {
			d.invalidateRoute(route)
		}
		var referralErr *protocol.DFSReferralRequiredError
		if errors.As(err, &referralErr) {
			// A PATH_NOT_COVERED issued to a link target must fail the original
			// I/O. Only an initial/root-target context may request another link
			// referral.
			actualPath := route.path.String()
			if route.source != nil && !route.source.root && sameUNCPath(referralErr.Path, actualPath) {
				return nil, err
			}
			entry, qerr := d.queryReferral(ctx, referralErr.Path)
			if qerr != nil {
				return nil, qerr
			}
			suffix, ok := pathpkg.CutPrefix(referralErr.Path, entry.prefix)
			if !ok {
				return nil, errors.New("client: referral prefix does not match continuation")
			}
			if referralErr.ReparsePoint && suffix == "" && !entry.root {
				return nil, os.ErrPermission
			}
			forcedRoute, qerr = d.selectRoute(ctx, referralErr.Path, entry, suffix)
			if qerr != nil {
				return nil, qerr
			}
			path = referralErr.Path
			continue
		}
		return nil, err
	}
	return nil, errReferralDepth
}
