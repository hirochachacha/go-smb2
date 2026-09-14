package smb2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
)

const smbQUICALPN = "smb"

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

// DialQUICTransport establishes an SMB-over-QUIC transport to addr.
//
// The returned transport uses a dedicated QUIC connection with one
// bidirectional stream. The TLS configuration is cloned before its ServerName
// and ALPN are set; TLS certificate verification remains enabled by default.
// DialAddr is used instead of DialAddrEarly, so this transport never sends
// SMB messages using 0-RTT.
func DialQUICTransport(ctx context.Context, addr string, tlsConfig *tls.Config) (Transport, error) {
	if ctx == nil {
		panic("nil context")
	}

	config := cloneQUICClientTLS(addr, tlsConfig)
	conn, err := quic.DialAddr(ctx, addr, config, &quic.Config{
		// Keep the QUIC connection alive while an SMB session is idle. SMB
		// sessions can outlive individual operations by hours.
		KeepAlivePeriod: clientQUICKeepAlivePeriod,
	})
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "SMB stream setup failed")
		return nil, err
	}

	return &quicTransport{
		directTCP: direct(stream).(*directTCP),
		conn:      conn,
	}, nil
}

func cloneQUICClientTLS(addr string, tlsConfig *tls.Config) *tls.Config {
	var config tls.Config
	if tlsConfig != nil {
		config = *tlsConfig.Clone()
	}
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS13
	}
	if config.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			config.ServerName = strings.Trim(host, "[]")
		}
	}
	config.NextProtos = []string{smbQUICALPN}
	return &config
}

type quicTransport struct {
	*directTCP
	conn *quic.Conn

	closeOnce sync.Once
	closeErr  error
}

// isSMBQUICTransport identifies the built-in QUIC transport to negotiation.
// It is intentionally private so custom transports retain their existing
// dialect behavior.
func (*quicTransport) isSMBQUICTransport() {}

// Close closes the QUIC connection, which also unblocks a receiver waiting on
// the stream. Closing only the stream would send FIN and leave the connection
// alive for the shared SMB connection's receiver.
func (t *quicTransport) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.conn.CloseWithError(0, "SMB transport closed")
	})
	return t.closeErr
}

var _ Transport = (*quicTransport)(nil)
var _ transport = (*quicTransport)(nil)

var errQUICTransportDialect = errors.New("smb2: QUIC transport requires SMB 3.1.1")
