// Package dfs provides transparent access to SMB paths, including DFS
// referrals and ordinary symbolic links.
package dfs

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/hirochachacha/go-smb2/v2"
)

// Client owns the sessions and shares it creates while resolving paths.
// Sessions remain owned until Close, including sessions used only for DFS
// referral queries.
type Client struct {
	dialer *smb2.Dialer

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

// New creates a DFS client using dialer. The client takes a reference to the
// dialer; callers must not modify the dialer while the client is in use.
func New(dialer *smb2.Dialer) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		dialer:    dialer,
		lifetime:  ctx,
		cancel:    cancel,
		closeDone: make(chan struct{}),
		sessions:  make(map[string]*smb2.Session),
		retired:   make(map[*smb2.Session]struct{}),
		shares:    make(map[string]*shareEntry),
		referrals: make(map[string]*referralEntry),
		inflight:  make(map[string]*creation),
	}
}

func canonicalKey(parts ...string) string {
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, "\\")
}

func (c *Client) beginCreation(key string) (*creation, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lifetime == nil {
		return nil, false, os.ErrInvalid
	}
	if c.closing {
		return nil, false, net.ErrClosed
	}
	if current := c.inflight[key]; current != nil {
		return current, false, nil
	}
	call := &creation{done: make(chan struct{})}
	c.inflight[key] = call
	c.wg.Add(1)
	return call, true, nil
}

func (c *Client) finishCreation(key string, call *creation, value any, err error) {
	c.mu.Lock()
	if c.inflight[key] == call {
		delete(c.inflight, key)
	}
	call.value, call.err = value, err
	close(call.done)
	c.mu.Unlock()
	c.wg.Done()
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
// shares the result with concurrent callers. cached is called with c.mu held.
// create runs once in its own goroutine and must publish the value itself,
// cleaning it up and returning an error if the client has closed.
func acquire[T any](c *Client, ctx context.Context, key string, cached func() (T, bool), create func() (T, error)) (T, error) {
	var zero T
	if ctx == nil {
		panic("nil context")
	}
	c.mu.Lock()
	if c.lifetime == nil {
		c.mu.Unlock()
		return zero, os.ErrInvalid
	}
	if c.closing {
		c.mu.Unlock()
		return zero, net.ErrClosed
	}
	if value, ok := cached(); ok {
		c.mu.Unlock()
		return value, nil
	}
	c.mu.Unlock()

	call, owner, err := c.beginCreation(key)
	if err != nil {
		return zero, err
	}
	if owner {
		// A creation may have completed between the fast path and
		// beginCreation, so re-check before starting a new one.
		c.mu.Lock()
		value, ok := cached()
		c.mu.Unlock()
		if ok {
			c.finishCreation(key, call, value, nil)
		} else {
			go func() {
				value, err := create()
				c.finishCreation(key, call, value, err)
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

func (c *Client) acquireSession(ctx context.Context, server string) (*smb2.Session, error) {
	key := canonicalKey(server)
	return acquire(c, ctx, "session:"+key,
		func() (*smb2.Session, bool) {
			session := c.sessions[key]
			return session, session != nil
		},
		func() (*smb2.Session, error) {
			if c.dialer == nil {
				return nil, errors.New("dfs: nil Dialer")
			}
			session, err := c.dialer.Dial(c.lifetime, server)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errors.New("dfs: session creation returned no session")
			}
			c.mu.Lock()
			closed := c.closing
			if !closed {
				c.sessions[key] = session
			}
			c.mu.Unlock()
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

func (c *Client) acquireShare(ctx context.Context, server, share string) (*smb2.Share, error) {
	key := shareKey(server, share)
	return acquire(c, ctx, "share:"+key,
		func() (*smb2.Share, bool) {
			entry := c.shares[key]
			if entry == nil {
				return nil, false
			}
			return entry.value, true
		},
		func() (*smb2.Share, error) {
			session, err := c.acquireSession(c.lifetime, server)
			if err != nil {
				return nil, err
			}
			shareValue, err := session.Mount(c.lifetime, share)
			if err != nil {
				if isUnavailable(err) {
					c.invalidateSession(server, session)
				}
				return nil, err
			}
			if shareValue == nil {
				return nil, errors.New("dfs: share creation returned no share")
			}
			c.mu.Lock()
			closed := c.closing
			current := c.sessions[canonicalKey(server)]
			if !closed && current != nil && current == session {
				c.shares[key] = &shareEntry{session: session, value: shareValue}
			} else {
				closed = true
			}
			c.mu.Unlock()
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
func (c *Client) invalidateSession(server string, stale *smb2.Session) {
	if stale == nil {
		return
	}
	key := canonicalKey(server)
	c.mu.Lock()
	current := c.sessions[key]
	if current == nil || current != stale {
		c.mu.Unlock()
		return
	}
	delete(c.sessions, key)
	c.retired[stale] = struct{}{}
	for shareKey, entry := range c.shares {
		if entry != nil && entry.session == stale {
			delete(c.shares, shareKey)
		}
	}
	c.mu.Unlock()
	go stale.Close()
}

// Close stops new operations and closes all sessions owned by the client.
// Concurrent callers wait for the same shutdown result.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.lifetime == nil {
		c.mu.Unlock()
		return nil
	}
	if c.closing {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		return c.closeErr
	}
	c.closing = true
	c.cancel()
	sessions := make([]*smb2.Session, 0, len(c.sessions)+len(c.retired))
	for _, session := range c.sessions {
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	for session := range c.retired {
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	done := c.closeDone
	c.mu.Unlock()

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
	c.wg.Wait()
	c.mu.Lock()
	c.closeErr = errors.Join(closeErrs...)
	close(done)
	c.mu.Unlock()
	return c.closeErr
}
