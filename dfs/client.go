// Package dfs provides transparent access to SMB paths, including DFS
// referrals and ordinary symbolic links.
package dfs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
)

// Option configures a DFS client.
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

// DFS owns the sessions and shares it creates while resolving paths.
// Sessions remain owned until Close, including sessions used only for DFS
// referral queries.
type DFS struct {
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

// New creates a DFS client using dialer and optional configuration options.
// The client takes a reference to the dialer; callers must not modify the
// dialer while the client is in use.
func New(dialer *smb2.Dialer, options ...Option) *DFS {
	var cfg config
	for _, opt := range options {
		if opt != nil {
			opt.applyOption(&cfg)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &DFS{
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

func (d *DFS) beginCreation(key string) (*creation, bool, error) {
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

func (d *DFS) finishCreation(key string, call *creation, value any, err error) {
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
func acquire[T any](d *DFS, ctx context.Context, key string, cached func() (T, bool), create func() (T, error)) (T, error) {
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
						d.finishCreation(key, call, nil, fmt.Errorf("dfs: creation panicked: %v", r))
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
		return zero, errors.New("dfs: creation returned no value")
	}
	return v, nil
}

func (d *DFS) acquireSession(ctx context.Context, server string) (*smb2.Session, error) {
	key := canonicalKey(server)
	return acquire(d, ctx, "session:"+key,
		func() (*smb2.Session, bool) {
			session := d.sessions[key]
			return session, session != nil
		},
		func() (*smb2.Session, error) {
			if d.dialer == nil {
				return nil, errors.New("dfs: nil Dialer")
			}
			session, err := d.dialer.Dial(d.lifetime, server)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errors.New("dfs: session creation returned no session")
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

func (d *DFS) acquireShare(ctx context.Context, server, share string) (*smb2.Share, error) {
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
				return nil, errors.New("dfs: share creation returned no share")
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
func (d *DFS) invalidateSession(server string, stale *smb2.Session) {
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
func (d *DFS) Close() error {
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
