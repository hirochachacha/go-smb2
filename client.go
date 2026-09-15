package smb2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// ClientConfig configures a Client.
type ClientConfig struct {
	Credentials Credentials
	// TransportDialer creates the transport for a server. If nil, TCPDialer{}
	// is used.
	TransportDialer  TransportDialer
	MaxCreditBalance uint16
	// IOPipelineDepth limits outstanding requests per Read/Write operation,
	// not per connection. Zero uses 4; 1 processes chunks sequentially.
	IOPipelineDepth uint
	// RequireMessageSigning requires SMB message signing.
	RequireMessageSigning bool
	// ClientGuid identifies this client. If zero, a GUID is generated for
	// each connection using crypto/rand.
	ClientGuid [16]byte
	// SpecifiedDialects restricts negotiation to these SMB dialects. Empty offers
	// all supported client dialects ([MS-SMB2] 3.2.4.2). QUIC requires SMB 3.1.1.
	SpecifiedDialects []uint16
	// Ciphers restricts encryption to these cipher IDs in order of preference.
	// Empty offers client defaults ([MS-SMB2] 3.2.4.2.2).
	Ciphers []uint16
	// DisableEncryptionOverSecureTransport offers QUIC transport security in
	// place of SMB encryption. SMB encryption is skipped only if the server
	// accepts the offer; this option has no effect on other transports.
	DisableEncryptionOverSecureTransport bool
}

// Client owns connections and authenticated sessions created for direct and
// DFS referral targets. Sessions are retained until Close, even when no shares
// are mounted.
type Client struct {
	config ClientConfig

	mu         sync.Mutex
	sessions   map[string]*clientSession
	connecting map[string]*sessionConnect
	closed     bool
}

type sessionConnect struct {
	done chan struct{}
	err  error
}

// NewClient constructs a client that can establish sessions for servers named
// by UNC paths and DFS referrals. It panics if config is invalid.
func NewClient(config ClientConfig) *Client {
	if config.Credentials == nil {
		panic("smb2: Credentials is required")
	}
	if config.TransportDialer == nil {
		config.TransportDialer = TCPDialer{}
	}
	return &Client{config: config, sessions: make(map[string]*clientSession), connecting: make(map[string]*sessionConnect)}
}

// Mount connects to and mounts the share identified by sharePath. sharePath must have the
// form \\server\share. The returned Share accepts an explicit context for
// each operation.
func (c *Client) Mount(ctx context.Context, sharePath string) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	serverName, _, err := splitUNCShare(sharePath)
	if err != nil {
		return nil, err
	}
	session, err := c.connect(ctx, serverName)
	if err != nil {
		return nil, fmt.Errorf("connect %q: %w", serverName, err)
	}
	return session.Mount(ctx, sharePath)
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
	return session.ListShareNames(ctx, serverName, clientMaxShareResponseSize)
}

func splitUNCShare(unc string) (string, string, error) {
	if err := validateMountPath(unc); err != nil {
		return "", "", err
	}
	parts := strings.Split(strings.TrimPrefix(unc, `\\`), `\`)
	return parts[0], parts[1], nil
}

func (c *Client) connect(ctx context.Context, serverName string) (*clientSession, error) {
	key := sessionKey(serverName)
	var stale *clientSession
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if session := c.sessions[key]; session != nil {
		if !session.s.broken() {
			c.mu.Unlock()
			return session, nil
		}
		delete(c.sessions, key)
		stale = session
	}
	if wait := c.connecting[key]; wait != nil {
		c.mu.Unlock()
		if stale != nil {
			_ = stale.Logoff(context.Background())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait.done:
			if wait.err != nil {
				return nil, wait.err
			}
			return c.connect(ctx, serverName)
		}
	}
	wait := &sessionConnect{done: make(chan struct{})}
	c.connecting[key] = wait
	c.mu.Unlock()
	if stale != nil {
		_ = stale.Logoff(context.Background())
	}
	initiator, err := c.config.Credentials.NewInitiator(ctx, serverName)
	if err != nil {
		c.finishConnect(key, wait, err)
		return nil, err
	}
	if initiator == nil {
		err := errors.New("smb2: Credentials returned a nil Initiator")
		c.finishConnect(key, wait, err)
		return nil, err
	}

	connection, err := c.config.TransportDialer.DialTransport(ctx, serverName)
	if err != nil {
		c.finishConnect(key, wait, err)
		return nil, err
	}
	if connection == nil {
		err := errors.New("smb2: TransportDialer returned nil")
		c.finishConnect(key, wait, err)
		return nil, err
	}
	dialer := &sessionDialer{
		MaxCreditBalance: c.config.MaxCreditBalance,
		Negotiator: negotiator{
			RequireMessageSigning:                c.config.RequireMessageSigning,
			ClientGuid:                           c.config.ClientGuid,
			SpecifiedDialects:                    append([]uint16(nil), c.config.SpecifiedDialects...),
			Ciphers:                              append([]uint16(nil), c.config.Ciphers...),
			DisableEncryptionOverSecureTransport: c.config.DisableEncryptionOverSecureTransport,
		},
		Initiator: initiator,
	}
	session, err := dialer.dialTransportContext(ctx, connection, serverName)
	if err != nil {
		c.finishConnect(key, wait, err)
		return nil, err
	}
	session.client = c
	session.s.conn.ioPipelineDepth = c.config.IOPipelineDepth

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = session.Logoff(context.Background())
		err := net.ErrClosed
		c.finishConnect(key, wait, err)
		return nil, err
	}
	c.sessions[key] = session
	delete(c.connecting, key)
	close(wait.done)
	c.mu.Unlock()
	return session, nil
}

func sessionKey(server string) string {
	b := []byte(server)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func (c *Client) finishConnect(key string, wait *sessionConnect, err error) {
	c.mu.Lock()
	if c.connecting[key] == wait {
		delete(c.connecting, key)
		wait.err = err
		close(wait.done)
	}
	c.mu.Unlock()
}

// Close logs off every session created by Client. It is safe to call before
// Share.Unmount; mounted shares become unusable after Close.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := c.sessions
	c.sessions = nil
	c.mu.Unlock()

	var errs []error
	for _, session := range sessions {
		if err := session.Logoff(context.Background()); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
