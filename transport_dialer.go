package smb2

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
)

// TransportDialer establishes a transport for an SMB server.
// TransportDialer implementations must be safe for concurrent use.
type TransportDialer interface {
	DialTransport(ctx context.Context, serverName string) (Transport, error)
}

func resolveServerAddr(serverName string, defaultPort int) string {
	if _, _, err := net.SplitHostPort(serverName); err == nil {
		return serverName
	}
	return net.JoinHostPort(serverName, strconv.Itoa(defaultPort))
}

// TCPDialer establishes Direct TCP transports.
type TCPDialer struct {
	Port   int // 0 indicates port 445
	Dialer *net.Dialer
}

// DialTransport connects to serverName over TCP on the configured port.
func (d TCPDialer) DialTransport(ctx context.Context, serverName string) (Transport, error) {
	port := d.Port
	if port <= 0 {
		port = 445
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, "tcp", resolveServerAddr(serverName, port))
	if err != nil {
		return nil, err
	}
	return direct(conn), nil
}

// QUICDialer establishes SMB-over-QUIC transports.
type QUICDialer struct {
	Port      int // 0 indicates port 443
	TLSConfig *tls.Config
}

// DialTransport connects to serverName over QUIC on the configured port.
func (d QUICDialer) DialTransport(ctx context.Context, serverName string) (Transport, error) {
	port := d.Port
	if port <= 0 {
		port = 443
	}
	return DialQUICTransport(ctx, resolveServerAddr(serverName, port), d.TLSConfig)
}
