package smb2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ClientConfig configures a Client.
type ClientConfig struct {
	Credentials Credentials
	// Transport creates the transport for a server. nil uses Direct TCP on
	// port 445.
	Transport        func(context.Context, string) (Transport, error)
	MaxCreditBalance uint16
	WriteTimeout     time.Duration
	Negotiator       Negotiator
}

// Client owns connections and authenticated sessions created for direct and
// DFS referral targets.
type Client struct {
	config ClientConfig

	mu       sync.Mutex
	sessions []*Session
	closed   bool
}

// NewClient constructs a client that can establish sessions for servers named
// by UNC paths and DFS referrals.
func NewClient(config ClientConfig) (*Client, error) {
	if config.Credentials == nil {
		return nil, errors.New("smb2: Credentials is required")
	}
	return &Client{config: config}, nil
}

// Mount connects to and mounts the share identified by unc. unc must have the
// form \\server\share. The returned Share uses ctx for its operations.
func (c *Client) Mount(ctx context.Context, unc string) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	serverName, _, err := splitUNCShare(unc)
	if err != nil {
		return nil, err
	}
	session, err := c.connect(ctx, serverName)
	if err != nil {
		return nil, fmt.Errorf("connect %q: %w", serverName, err)
	}
	share, err := session.WithContext(ctx).Mount(unc)
	if err != nil {
		_ = c.closeSession(session)
		return nil, err
	}
	return share.WithContext(ctx), nil
}

// ListShareNames returns the names of shares exported by serverName.
func (c *Client) ListShareNames(ctx context.Context, serverName string) ([]string, error) {
	if ctx == nil {
		panic("nil context")
	}
	session, err := c.connect(ctx, serverName)
	if err != nil {
		return nil, fmt.Errorf("connect %q: %w", serverName, err)
	}
	names, listErr := session.WithContext(ctx).listShareNames(serverName, clientMaxShareResponseSize)
	closeErr := c.closeSession(session)
	if listErr != nil {
		return nil, listErr
	}
	return names, closeErr
}

func splitUNCShare(unc string) (string, string, error) {
	if err := validateMountPath(unc); err != nil {
		return "", "", err
	}
	parts := strings.Split(strings.TrimPrefix(unc, `\\`), `\`)
	return parts[0], parts[1], nil
}

func (c *Client) connect(ctx context.Context, serverName string) (*Session, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}

	initiator, err := c.config.Credentials.NewInitiator(ctx, serverName)
	if err != nil {
		return nil, err
	}
	if initiator == nil {
		return nil, errors.New("smb2: Credentials returned a nil Initiator")
	}

	var connection Transport
	if c.config.Transport == nil {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(serverName, "445"))
		if err != nil {
			return nil, err
		}
		connection = direct(conn)
	} else {
		custom, err := c.config.Transport(ctx, serverName)
		if err != nil {
			return nil, err
		}
		if custom == nil {
			return nil, errors.New("smb2: Transport returned nil")
		}
		connection = custom
	}
	dialer := &Dialer{
		MaxCreditBalance: c.config.MaxCreditBalance,
		WriteTimeout:     c.config.WriteTimeout,
		Negotiator:       c.config.Negotiator,
		Initiator:        initiator,
	}
	session, err := dialer.dialTransportContext(ctx, connection, serverName)
	if err != nil {
		return nil, err
	}
	session.client = c

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = session.Logoff()
		return nil, net.ErrClosed
	}
	c.sessions = append(c.sessions, session)
	c.mu.Unlock()
	return session, nil
}

func (c *Client) closeSession(session *Session) error {
	c.mu.Lock()
	found := false
	for i, candidate := range c.sessions {
		if candidate != session {
			continue
		}
		copy(c.sessions[i:], c.sessions[i+1:])
		c.sessions[len(c.sessions)-1] = nil
		c.sessions = c.sessions[:len(c.sessions)-1]
		found = true
		break
	}
	c.mu.Unlock()
	if !found {
		return nil
	}
	return session.Logoff()
}

// Close logs off every session created by Client. Shares should be unmounted
// before Close so their tree connections are disconnected cleanly.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := append([]*Session(nil), c.sessions...)
	c.sessions = nil
	c.mu.Unlock()

	var errs []error
	for _, session := range sessions {
		if err := session.Logoff(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
