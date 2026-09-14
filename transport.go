package smb2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	maxDirectTCPSize = 0xffffff // 16777215
	// maxNetBTSize     = 0x1ffff  // 131071
)

type directSinkFinder func(head []byte, restSize int) (sink []byte, frontSize int)

// packetStream is the byte stream used by Direct TCP framing. QUIC streams
// implement the same operations, while their connection lifetime is managed
// by quicTransport.
type packetStream interface {
	io.Reader
	io.Writer
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

// Transport sends and receives complete SMB packets.
//
// Transport is a sealed interface implemented by built-in transports
// (such as Direct TCP and SMB over QUIC).
type Transport interface {
	Close() error
	send(parts ...[]byte) error
	setReadDeadline(time.Time) error
	setWriteDeadline(time.Time) error
	setPacketReadTimeout(time.Duration)
	receive() ([]byte, error)
}

type transport interface {
	Transport
	// Writev sends the given parts as a single packet: the parts are
	// concatenated on the wire behind a single length header without being
	// copied into one contiguous buffer (scatter/gather, cf. writev(2)).
	Writev(parts ...[]byte) (n int, err error)
	ReadPacket(findSink ...directSinkFinder) (*recvPacket, error)
}

func receiveTransportPacket(t Transport, findSink directSinkFinder) (*recvPacket, error) {
	if direct, ok := t.(interface {
		ReadPacket(...directSinkFinder) (*recvPacket, error)
	}); ok {
		return direct.ReadPacket(findSink)
	}
	pkt, err := t.receive()
	if err != nil {
		return nil, err
	}
	if len(pkt) == 0 || len(pkt) > maxDirectTCPSize {
		return nil, errors.New("invalid transport packet size")
	}
	return &recvPacket{pkt: pkt}, nil
}


// NewDirectTCPTransport applies Direct TCP framing to conn.
func NewDirectTCPTransport(conn net.Conn) Transport {
	return direct(conn)
}

type directTCP struct {
	sb                [4]byte
	conn              packetStream
	packetReadTimeout time.Duration

	recvBuf *recvBuf
	rpos    int
	wpos    int
	// io.Reader permits data and an error together (https://pkg.go.dev/io#Reader).
	// Drain complete buffered frames before reporting this saved error.
	readErr error

	// pending is the number of body bytes of the in-flight packet that have
	// not been consumed by readRestInto yet.
	pending int
}

func direct(tcpConn packetStream) transport {
	return &directTCP{conn: tcpConn}
}

func (t *directTCP) send(parts ...[]byte) error {
	_, err := t.Writev(parts...)
	return err
}

func (t *directTCP) receive() ([]byte, error) {
	pkt, err := t.ReadPacket()
	if err != nil {
		return nil, err
	}
	defer pkt.close()
	return append([]byte(nil), pkt.bytes()...), nil
}

func (t *directTCP) Writev(parts ...[]byte) (n int, err error) {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	if size > maxDirectTCPSize {
		return -1, errors.New("max transport size exceeds")
	}

	be.PutUint32(t.sb[:], uint32(size))

	buffers := append(net.Buffers{t.sb[:]}, parts...)
	n64, err := buffers.WriteTo(t.conn)
	if err != nil {
		return -1, err
	}

	return int(n64), nil
}

func (t *directTCP) setWriteDeadline(time time.Time) error {
	return t.conn.SetWriteDeadline(time)
}

func (t *directTCP) setReadDeadline(time time.Time) error {
	return t.conn.SetReadDeadline(time)
}

func (t *directTCP) setPacketReadTimeout(d time.Duration) {
	t.packetReadTimeout = d
}

func (t *directTCP) packetReadTimeoutDuration() time.Duration {
	if t.packetReadTimeout > 0 {
		return t.packetReadTimeout
	}
	return clientPacketReadTimeout
}

func (t *directTCP) dropBuf() {
	if t.recvBuf != nil {
		releaseRecvBuf(t.recvBuf)
		t.recvBuf = nil
	}
	t.rpos = 0
	t.wpos = 0
}

func (t *directTCP) fill(need int) error {
	if t.wpos-t.rpos >= need {
		return nil
	}
	if t.readErr != nil {
		t.dropBuf()
		return t.readErr
	}

	if t.recvBuf == nil {
		t.recvBuf = allocRecvBuf(need)
		t.rpos = 0
		t.wpos = 0
	} else if t.rpos+need > len(t.recvBuf.data) {
		avail := t.wpos - t.rpos
		newBuf := allocRecvBuf(avail + need)
		if avail > 0 {
			copy(newBuf.data[:avail], t.recvBuf.data[t.rpos:t.wpos])
		}
		releaseRecvBuf(t.recvBuf)
		t.recvBuf = newBuf
		t.rpos = 0
		t.wpos = avail
	}

	for t.wpos-t.rpos < need {
		n, err := t.conn.Read(t.recvBuf.data[t.wpos:])
		t.wpos += n
		if err != nil {
			t.readErr = err
		}
		if t.wpos-t.rpos >= need {
			return nil
		}
		if t.readErr != nil {
			t.dropBuf()
			return t.readErr
		}
	}

	return nil
}

// readRestInto consumes len(b) bytes of the in-flight packet body, first from
// the internal buffer, then directly from the underlying connection, writing
// them into b without an intermediate copy.
func (t *directTCP) readRestInto(b []byte) error {
	if len(b) > t.pending {
		t.dropBuf()
		return errors.New("incomplete packet")
	}
	t.pending -= len(b)

	// consume bytes already buffered by previous reads
	if t.recvBuf != nil {
		if n := copy(b, t.recvBuf.data[t.rpos:t.wpos]); n > 0 {
			t.rpos += n
			b = b[n:]
		}
	}

	if len(b) > 0 {
		if t.readErr != nil {
			t.dropBuf()
			return t.readErr
		}

		for len(b) > 0 {
			n, err := t.conn.Read(b)
			if n > 0 {
				b = b[n:]
			}
			if err != nil {
				t.readErr = err
			}
			if len(b) == 0 {
				break
			}
			if t.readErr != nil {
				t.dropBuf()
				return t.readErr
			}
		}
	}

	if t.pending == 0 && t.rpos == t.wpos {
		t.dropBuf()
	}

	return nil
}

func (t *directTCP) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	if err := t.fill(4); err != nil {
		return nil, err
	}

	header := t.recvBuf.data[t.rpos : t.rpos+4]
	if header[0] != 0 {
		t.dropBuf()
		return nil, errors.New("invalid transport format")
	}

	pktSize := int(be.Uint32(header))
	if pktSize > maxDirectTCPSize {
		t.dropBuf()
		return nil, errors.New("max transport size exceeds")
	}
	t.rpos += 4

	if t.wpos-t.rpos < pktSize {
		if err := t.conn.SetReadDeadline(time.Now().Add(t.packetReadTimeoutDuration())); err != nil {
			t.dropBuf()
			return nil, err
		}
		defer t.conn.SetReadDeadline(time.Time{})
	}

	n := min(pktSize, 80)
	if err := t.fill(n); err != nil {
		return nil, err
	}

	t.pending = pktSize - n
	head := t.recvBuf.data[t.rpos : t.rpos+n]
	t.rpos += n

	if len(findSink) > 0 && findSink[0] != nil {
		if sink, frontSize := findSink[0](head, t.pending); sink != nil {
			rp := allocRecvPacket(frontSize)
			copy(rp.pkt[:len(head)], head)
			if pad := frontSize - len(head); pad > 0 {
				if err := t.readRestInto(rp.pkt[len(head):frontSize]); err != nil {
					rp.close()
					return nil, err
				}
			}
			if len(sink) > 0 {
				if err := t.readRestInto(sink); err != nil {
					rp.close()
					return nil, err
				}
			}
			rp.ext = sink
			return rp, nil
		}
	}

	spare := 0
	if len(head) >= 4 && head[0] == 0xfd && head[1] == 'S' && head[2] == 'M' && head[3] == 'B' {
		// [MS-SMB2] 2.2.41 stores the 16-byte authentication tag in the
		// transform header. Spare tail capacity lets session.decrypt append it
		// to the ciphertext and authenticate/decrypt in the receive buffer.
		spare = 16
	}
	rp := allocRecvPacketWithSpare(pktSize, spare)
	copy(rp.pkt[:len(head)], head)
	if t.pending > 0 {
		if err := t.readRestInto(rp.pkt[len(head):]); err != nil {
			rp.close()
			return nil, err
		}
	}

	return rp, nil
}

func (t *directTCP) Close() error {
	return t.conn.Close()
}

const smbQUICALPN = "smb"

var errQUICTransportDialect = errors.New("smb2: QUIC transport requires SMB 3.1.1")

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

