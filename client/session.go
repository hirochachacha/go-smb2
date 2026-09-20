package client

import (
	"errors"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
)

// sessionEntry tracks uses of one connection generation. All fields other than
// Session, client, and key are protected by client.mu.
type sessionEntry struct {
	*smb2.Session
	client    *Client
	key       string
	users     int
	idleSince time.Time
	timer     *time.Timer
}

// retain is called with client.mu held, before exposing a cached resource.
func (s *sessionEntry) retain() {
	s.users++
	if s.timer != nil {
		s.timer.Stop()
	}
	s.idleSince = time.Time{}
}

func (s *sessionEntry) release() {
	d := s.client
	d.mu.Lock()
	defer d.mu.Unlock()
	s.users--
	if s.users == 0 && !d.closing && d.sessions[s.key] == s {
		s.startIdleTimer()
	}
}

// startIdleTimer is called with client.mu held.
func (s *sessionEntry) startIdleTimer() {
	d := s.client
	if d.sessionIdleTimeout <= 0 {
		return
	}
	s.idleSince = time.Now()
	idleSince := s.idleSince
	s.timer = time.AfterFunc(d.sessionIdleTimeout, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		// A stopped callback may already be running. Its idle interval must still
		// be current before it can retire this connection generation.
		if d.closing || d.sessions[s.key] != s || s.users != 0 || s.idleSince != idleSince {
			return
		}
		d.retireSession(s)
	})
}

// retireSession removes a generation and starts its teardown with client.mu
// held. Close joins teardown even after the entry leaves the cache.
func (d *Client) retireSession(s *sessionEntry) {
	if s.timer != nil {
		s.timer.Stop()
	}
	delete(d.sessions, s.key)
	for key, share := range d.shares {
		if share.session == s {
			delete(d.shares, key)
		}
	}
	d.retired[s] = struct{}{}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		err := s.Abort()
		d.mu.Lock()
		if d.closing && err != nil && !errors.Is(err, net.ErrClosed) {
			d.closeErr = errors.Join(d.closeErr, err)
		}
		delete(d.retired, s)
		d.mu.Unlock()
	}()
}
