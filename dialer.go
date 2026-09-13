package smb2

import (
	"context"
	"net"
	"time"
)

// Dialer contains options for func (*Dialer) Dial.
type Dialer struct {
	MaxCreditBalance uint16        // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	WriteTimeout     time.Duration // maximum duration of each transport write; zero uses the default.
	Negotiator       Negotiator
	Initiator        Initiator
}

// Dial performs negotiation and authentication.
// It returns a session. It doesn't support NetBIOS transport.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) Dial(tcpConn net.Conn) (*Session, error) {
	return d.DialContext(context.Background(), tcpConn)
}

// DialContext performs negotiation and authentication using the provided context.
// Note that returned session doesn't inherit context.
// If you want to use the same context, call Session.WithContext manually.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) DialContext(ctx context.Context, tcpConn net.Conn) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	return d.dialTransportContext(ctx, direct(tcpConn), tcpConn.RemoteAddr().String())
}

func (d *Dialer) dialTransportContext(ctx context.Context, t Transport, serverName string) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}

	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(ctx, t, a, d.writeTimeout())
	if err != nil {
		return nil, err
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		conn.close(err)
		return nil, err
	}

	return &Session{s: s, ctx: context.Background(), addr: serverName}, nil
}

const defaultWriteTimeout = 30 * time.Second

func (d *Dialer) writeTimeout() time.Duration {
	if d.WriteTimeout > 0 {
		return d.WriteTimeout
	}
	return defaultWriteTimeout
}
