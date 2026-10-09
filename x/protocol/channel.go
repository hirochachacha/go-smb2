package protocol

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// sessionChannels owns a logical session's connections. A session holds only
// immutable negotiated state and the crypto state of its own connection.
// Neither a request failure nor cancellation closes a sibling connection.
type sessionChannels struct {
	mu             sync.Mutex
	channels       []*session
	retired        []*session
	pending        *conn
	closed         bool
	done           chan struct{}
	next           uint64
	sequence       atomic.Uint32
	bindGate       chan struct{}
	dialer         Dialer
	sessionKey     []byte
	initialPreauth [64]byte
}

func (g *sessionChannels) liveLocked() []*session {
	live := g.channels[:0]
	for _, s := range g.channels {
		if s.transportClosed.Load() {
			g.sequence.Add(1)
			g.retired = append(g.retired, s)
		} else {
			live = append(live, s)
		}
	}
	clear(g.channels[len(live):])
	g.channels = live
	return live
}

func (g *sessionChannels) selectChannel(reqs ...wire.Packet) (*session, error) {
	g.mu.Lock()
	if g.closed || len(g.liveLocked()) == 0 {
		g.mu.Unlock()
		return nil, &TransportError{Err: net.ErrClosed}
	}
	if len(g.channels) == 1 {
		s := g.channels[0]
		g.mu.Unlock()
		return s, nil
	}
	g.mu.Unlock()
	// Encoder.Size may be caller code; never invoke it under the group lock.
	_, charge, err := requestCreditCharges(reqs...)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.liveLocked()) == 0 {
		return nil, &TransportError{Err: net.ErrClosed}
	}
	first := g.channels[g.next%uint64(len(g.channels))]
	for range g.channels {
		s := g.channels[g.next%uint64(len(g.channels))]
		g.next++
		if charge == 0 || s.account == nil || charge <= s.account.maxCreditCap() {
			return s, nil
		}
	}
	// Let the original send path report an indivisible request's credit limit,
	// or let Tree fall back to sequential requests for an oversized compound.
	return first, nil
}

func (g *sessionChannels) selectSequentialChannel(reqs []wire.Packet) (*session, error) {
	charges, _, err := requestCreditCharges(reqs...)
	if err != nil {
		return nil, err
	}
	if len(charges) == 0 {
		return g.selectChannel()
	}
	largest := 0
	for i, charge := range charges {
		if charge > charges[largest] {
			largest = i
		}
	}
	return g.selectChannel(reqs[largest])
}

func (s *session) channelPayloadSize(command wire.Command, companions int) int {
	limit := func(c *conn) int {
		// Bound channels may advertise larger limits, but existing operations
		// and future binds must retain the initial session's common ceiling.
		size := s.maxReadSize
		if command == wire.SMB2_WRITE {
			size = s.maxWriteSize
		} else if command == wire.SMB2_IOCTL {
			size = s.maxTransactSize
		}
		return c.effectivePayloadSize(size, companions)
	}
	if s.channels == nil {
		return limit(s.conn)
	}
	g := s.channels
	g.mu.Lock()
	defer g.mu.Unlock()
	size := limit(s.conn)
	for i, channel := range g.liveLocked() {
		current := limit(channel.conn)
		if i == 0 || current < size {
			size = current
		}
	}
	return size
}

// shutdown prevents publication of an in-progress bind. Close every transport
// before waiting for receivers, so no blocked sender can delay its siblings.
func (s *session) shutdownChannels(err error) error {
	if s.channels == nil {
		return s.conn.close(err)
	}
	g := s.channels
	g.mu.Lock()
	g.closeLocked()
	connections := make([]*conn, 0, len(g.channels)+1)
	for _, channel := range g.channels {
		connections = append(connections, channel.conn)
	}
	for _, channel := range g.retired {
		connections = append(connections, channel.conn)
	}
	if g.pending != nil {
		connections = append(connections, g.pending)
	}
	g.mu.Unlock()
	for _, c := range connections {
		_ = c.closeTransport()
	}
	var first error
	for _, c := range connections {
		if e := c.close(err); first == nil {
			first = e
		}
	}
	return first
}

// BindChannel authenticates a new connection as part of this SMB 3.x session.
// Supply a fresh initiator for the same identity and a new transport to the
// same server. This method takes ownership of a non-nil transport even on
// failure. Binds are serialized and can be canceled while waiting. Failure
// closes only the supplied connection; requests already sent are never retried.
// GMAC binding follows the negotiated signing algorithm without downgrade.
// Security limitation: binding reuses Session.SigningKey across independent
// MessageId spaces, so signing nonce uniqueness is not guaranteed across binds.
func (c *Session) BindChannel(ctx context.Context, initiator Initiator, transport Transport) (err error) {
	if ctx == nil {
		panic("nil context")
	}
	if invalidBindingTransport(transport) {
		return errors.New("protocol: nil binding transport")
	}
	owned := transport
	defer func() {
		if owned != nil {
			_ = owned.Close()
		}
	}()
	if c == nil || c.s == nil || c.s.channels == nil {
		return errInvalidSession
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nilBindingArgument(initiator) || isAnonymousInitiator(initiator) {
		return errors.New("protocol: binding requires an authenticated initiator")
	}
	g := c.s.channels
	if c.s.dialect < wire.SMB300 || c.s.capabilities&wire.SMB2_GLOBAL_CAP_MULTI_CHANNEL == 0 || c.s.signingDisabled() {
		return errors.New("protocol: server or session does not support multichannel")
	}
	select {
	case g.bindGate <- struct{}{}:
		defer func() { <-g.bindGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-g.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return net.ErrClosed
	}
	g.mu.Lock()
	if g.closed || len(g.liveLocked()) == 0 {
		g.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		return net.ErrClosed
	}
	config := g.dialer
	config.bindingServer = c.s.conn
	config.SpecifiedDialects = []Dialect{Dialect(c.s.dialect)}
	maximum := config.MaxCreditBalance
	if maximum == 0 {
		maximum = clientMaxCreditBalance
	}
	connection := config.newConnection(transport, openAccount(maximum))
	owned = nil // The connection now owns teardown, including cancellation.
	g.pending = connection
	g.mu.Unlock()
	published := false
	defer func() {
		if !published {
			_ = connection.close(err)
		}
		g.mu.Lock()
		g.pending = nil
		g.mu.Unlock()
	}()
	watchDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(watchDone)
		_ = connection.close(ctx.Err())
	})
	var joinOnce sync.Once
	join := func() {
		joinOnce.Do(func() {
			if !stop() {
				<-watchDone
			}
		})
	}
	defer join()
	if _, err = config.negotiateConnection(ctx, connection); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err = c.s.validateChannel(connection); err != nil {
		return err
	}
	channel, err := connection.sessionSetupBinding(ctx, initiator, c.s)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	join() // No cancellation callback may close a published channel.
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.closed || len(g.liveLocked()) == 0 || connection.transportClosed.Load() {
		return net.ErrClosed
	}
	g.channels = append(g.channels, channel)
	published = true
	return nil
}

func nilBindingArgument(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func invalidBindingTransport(t Transport) bool {
	if nilBindingArgument(t) {
		return true
	}
	if direct, ok := t.(*transport); ok {
		return nilBindingArgument(direct.conn)
	}
	return false
}

func (s *session) validateChannel(c *conn) error {
	// [MS-SMB2] 3.2.5.2 requires the same server, dialect, security mode and
	// capabilities. Keep encryption policy and advertised I/O limits compatible
	// with existing Tree/File objects as well.
	if c.serverGuid != s.serverGuid || c.dialect != s.dialect || c.securityMode != s.securityMode || c.capabilities != s.capabilities ||
		c.cipherId != s.cipherId || c.signingAlgorithm != s.signingAlgorithm || c.acceptTransportSecurity != s.acceptTransportSecurity ||
		c.maxReadSize < s.maxReadSize || c.maxWriteSize < s.maxWriteSize || c.maxTransactSize < s.maxTransactSize {
		return errors.New("protocol: binding connection does not match the session's server and negotiated limits")
	}
	return nil
}

// beginClose blocks new requests and binds but retains one live connection
// for the bounded LOGOFF. Its send path is pinned to that connection.
func (s *session) beginClose() *session {
	if s.channels == nil {
		return s
	}
	g := s.channels
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closeLocked()
	if len(g.liveLocked()) == 0 {
		return s
	}
	pinned := *g.channels[0]
	pinned.channels = nil
	return &pinned
}

func (g *sessionChannels) closeLocked() {
	if !g.closed {
		g.closed = true
		if g.done != nil {
			close(g.done)
		}
	}
}
