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
// DFS referral targets.
type Client struct {
	config ClientConfig

	mu         sync.Mutex
	sessions   map[string]*clientSessionEntry
	connecting map[string]*sessionConnect
	closed     bool
}

type clientSessionEntry struct {
	key    string
	sess   *clientSession
	refs   int
	closed bool
}

type sessionConnect struct {
	done chan struct{}
	err  error
}

// sessionRef is the ownership hook used by Client-managed Shares. Its
// implementation is intentionally private; a Share only needs to release it
// once when closed.
type sessionRef struct {
	releaseFn func(context.Context) error
}

func (r *sessionRef) release(ctx context.Context) error {
	if r == nil || r.releaseFn == nil {
		return nil
	}
	f := r.releaseFn
	r.releaseFn = nil
	return f(ctx)
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
	return &Client{config: config, sessions: make(map[string]*clientSessionEntry), connecting: make(map[string]*sessionConnect)}
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
	share, err := session.Mount(ctx, sharePath)
	if err != nil {
		_ = c.closeSession(ctx, session)
		return nil, err
	}
	// Mount transferred the acquisition reference to the Share.
	_ = c.closeSession(ctx, session)
	return share, nil
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
	names, listErr := session.ListShareNames(ctx, serverName, clientMaxShareResponseSize)
	closeErr := c.closeSession(ctx, session)
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

func (c *Client) connect(ctx context.Context, serverName string) (*clientSession, error) {
	key := sessionKey(serverName)
	var stale *clientSessionEntry
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if e := c.sessions[key]; e != nil && !e.closed && !e.sess.s.broken() {
		e.refs++
		s := *e.sess
		s.entry = e
		c.mu.Unlock()
		return &s, nil
	}
	if e := c.sessions[key]; e != nil && !e.closed {
		e.closed = true
		delete(c.sessions, key)
		stale = e
	}
	if wait := c.connecting[key]; wait != nil {
		c.mu.Unlock()
		if stale != nil {
			_ = stale.sess.Logoff(context.Background())
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
		_ = stale.sess.Logoff(context.Background())
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
	e := &clientSessionEntry{key: key, sess: session, refs: 1}
	session.entry = e
	c.sessions[key] = e
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

func (c *Client) closeSession(ctx context.Context, session *clientSession) error {
	if session == nil || session.entry == nil {
		return nil
	}
	e := session.entry
	c.mu.Lock()
	if e.closed || e.refs == 0 {
		c.mu.Unlock()
		return nil
	}
	e.refs--
	if e.refs != 0 {
		c.mu.Unlock()
		return nil
	}
	e.closed = true
	delete(c.sessions, e.key)
	c.mu.Unlock()
	err := e.sess.Logoff(ctx)
	if err != nil && e.sess.s != nil && e.sess.s.conn != nil {
		// No users remain after the final reference is released. A canceled
		// LOGOFF cannot be left on a reusable transport, so finish teardown at
		// the session boundary. Request cancellation elsewhere never reaches
		// this path while the session still has references.
		e.sess.s.conn.close(err)
	}
	return err
}

func (c *Client) acquireSessionRef(entry *clientSessionEntry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || entry.closed || entry.refs == 0 {
		return false
	}
	entry.refs++
	return true
}

// Close logs off every session created by Client. It is safe to call before
// Share.Unmount; later unmounts do not release a session twice.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := make([]*clientSessionEntry, 0, len(c.sessions))
	for _, e := range c.sessions {
		e.closed = true
		sessions = append(sessions, e)
	}
	c.sessions = make(map[string]*clientSessionEntry)
	c.mu.Unlock()

	var errs []error
	for _, entry := range sessions {
		if err := entry.sess.Logoff(context.Background()); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
