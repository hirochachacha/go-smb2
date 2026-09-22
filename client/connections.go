package client

import (
	"context"
	"errors"
	"fmt"
	v2 "github.com/hirochachacha/go-smb2/v2"
	"net"
	"os"
	"sync"
)

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
// shares the result with concurrent callers. cached and retain run with d.mu
// held. retain reserves one use, or rejects a generation already evicted.
// create runs once in its own goroutine and must publish the value itself,
// cleaning it up and returning an error if the client has closed.
func acquire[T any](d *Client, ctx context.Context, key string, cached func() (T, bool), create func() (T, error), retain func(T) bool) (T, error) {
	var zero T
	if ctx == nil {
		panic("nil context")
	}
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
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
		if value, ok := cached(); ok && retain(value) {
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
		d.mu.Lock()
		if d.closing {
			d.mu.Unlock()
			return zero, net.ErrClosed
		}
		retained := retain(v)
		d.mu.Unlock()
		if !retained {
			continue
		}
		return v, nil
	}
}

// acquireSession reserves one use; the caller must release the returned entry.
func (d *Client) acquireSession(ctx context.Context, server string) (*sessionEntry, error) {
	key := canonicalKey(server)
	return acquire(d, ctx, "session:"+key,
		func() (*sessionEntry, bool) {
			session := d.sessions[key]
			return session, session != nil
		},
		func() (*sessionEntry, error) {
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
			entry := &sessionEntry{Session: session, client: d, key: key}
			d.mu.Lock()
			closed := d.closing
			if !closed {
				d.sessions[key] = entry
				entry.startIdleTimer()
			}
			d.mu.Unlock()
			if closed {
				_ = session.Close()
				return nil, net.ErrClosed
			}
			return entry, nil
		},
		func(entry *sessionEntry) bool {
			if d.sessions[key] != entry {
				return false
			}
			entry.retain()
			return true
		},
	)
}

func shareKey(server, share string) string {
	return canonicalKey(server, share)
}

// acquireShare reserves one use of the share's session; the caller must release it.
func (d *Client) acquireShare(ctx context.Context, server, share string) (*shareEntry, error) {
	key := shareKey(server, share)
	return acquire(d, ctx, "share:"+key,
		func() (*shareEntry, bool) {
			entry := d.shares[key]
			if entry == nil {
				return nil, false
			}
			return entry, true
		},
		func() (*shareEntry, error) {
			session, err := d.acquireSession(d.lifetime, server)
			if err != nil {
				return nil, err
			}
			defer session.release()
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
			entry := &shareEntry{session: session, value: shareValue}
			d.mu.Lock()
			closed := d.closing
			current := d.sessions[canonicalKey(server)]
			if !closed && current != nil && current == session {
				d.shares[key] = entry
			} else {
				closed = true
			}
			d.mu.Unlock()
			if closed {
				_ = shareValue.Unmount(context.Background())
				return nil, net.ErrClosed
			}
			return entry, nil
		},
		func(entry *shareEntry) bool {
			if d.shares[key] != entry {
				return false
			}
			entry.session.retain()
			return true
		},
	)
}

// invalidateSession discards one failed connection generation and every share
// mounted through it. Pointer identity prevents an older error from evicting a
// replacement session that was published concurrently.
func (d *Client) invalidateSession(server string, stale *sessionEntry) {
	if stale == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || d.sessions[canonicalKey(server)] != stale {
		return
	}
	d.retireSession(stale)
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
	sessions := make([]*v2.Session, 0, len(d.sessions))
	for _, session := range d.sessions {
		if session != nil {
			if session.timer != nil {
				session.timer.Stop()
			}
			sessions = append(sessions, session.Session)
		}
	}
	done := d.closeDone
	d.mu.Unlock()

	var closeWG sync.WaitGroup
	var closeMu sync.Mutex
	var closeErrs []error
	for _, session := range sessions {
		closeWG.Add(1)
		go func(s *v2.Session) {
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
	d.closeErr = errors.Join(d.closeErr, errors.Join(closeErrs...))
	close(done)
	d.mu.Unlock()
	return d.closeErr
}
