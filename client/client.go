// Package client provides transparent access to SMB paths, including DFS
// referrals and ordinary symbolic links.
package client

import (
	"context"
	v2 "github.com/hirochachacha/go-smb2/v2"
	"strings"
	"sync"
	"time"
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
// sessions. A session is idle when no operation or open file is using it.
// The default is 10 seconds. Nonpositive durations disable automatic session closure.
func WithSessionIdleTimeout(d time.Duration) Option {
	return sessionIdleTimeoutOption(d)
}

// Client owns the sessions and shares it creates while resolving paths.
// Idle sessions may be closed automatically when an idle timeout is configured.
type Client struct {
	dialer             *v2.Dialer
	sessionIdleTimeout time.Duration

	mu        sync.Mutex
	lifetime  context.Context
	cancel    context.CancelFunc
	closing   bool
	closeDone chan struct{}
	closeErr  error

	sessions  map[string]*sessionEntry
	retired   map[*sessionEntry]struct{}
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
	session *sessionEntry
	value   *v2.Share
}

// New creates a client using dialer and optional configuration options.
// The client takes a reference to the dialer; callers must not modify the
// dialer while the client is in use.
func New(dialer *v2.Dialer, options ...Option) *Client {
	cfg := config{sessionIdleTimeout: clientSessionIdleTimeout}
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
		sessions:           make(map[string]*sessionEntry),
		retired:            make(map[*sessionEntry]struct{}),
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
