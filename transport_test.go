package smb2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/quic-go/quic-go"
)

func TestDirectTCPWrite(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := direct(client)

	payload := []byte("hello smb2")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.Writev(payload)
	if err != nil {
		t.Fatalf("Writev() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("Writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}

	header := binary.BigEndian.Uint32(written[:4])
	if int(header) != len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", header, len(payload))
	}
	if !bytes.Equal(written[4:], payload) {
		t.Errorf("payload = %q, want %q", written[4:], payload)
	}
}

// individualWriteConn wraps a *net.TCPConn and counts individual Write calls.
// It keeps the *net.TCPConn-embedded writeBuffers (writev aggregation) so that
// net.Buffers.WriteTo can still take the aggregated path.
type individualWriteConn struct {
	*net.TCPConn
	writes int
}

func (c *individualWriteConn) Write(p []byte) (int, error) {
	c.writes++
	return c.TCPConn.Write(p)
}

func TestDirectTCPWritevParts(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := direct(client)

	header := []byte("header-part")
	payload := []byte("payload-part")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(header)+len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.Writev(header, payload)
	if err != nil {
		t.Fatalf("Writev() returned error: %v", err)
	}
	if want := len(header) + len(payload) + 4; n != want {
		t.Errorf("Writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}

	// the NetBIOS header must cover the concatenated parts
	size := binary.BigEndian.Uint32(written[:4])
	if int(size) != len(header)+len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", size, len(header)+len(payload))
	}
	if !bytes.Equal(written[4:], append(append([]byte{}, header...), payload...)) {
		t.Errorf("written = %q, want %q", written[4:], append(append([]byte{}, header...), payload...))
	}
}

func TestDirectTCPWriteAggregatesHeaderAndPayload(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("failed to accept: %v", err)
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	tcpConn := client.(*net.TCPConn)
	conn := &individualWriteConn{TCPConn: tcpConn}
	tr := &directTransport{conn: conn}

	payload := []byte("hello smb2")

	done := make(chan error, 1)
	var written []byte
	go func() {
		buf := make([]byte, len(payload)+4)
		_, err := io.ReadFull(server, buf)
		written = buf
		done <- err
	}()

	n, err := tr.Writev(payload)
	if err != nil {
		t.Fatalf("Writev() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("Writev() = %d bytes, want %d", n, want)
	}

	if err := <-done; err != nil {
		t.Fatalf("failed to read written data: %v", err)
	}
	if header := binary.BigEndian.Uint32(written[:4]); int(header) != len(payload) {
		t.Errorf("NetBIOS header = %d, want %d", header, len(payload))
	}
	if !bytes.Equal(written[4:], payload) {
		t.Errorf("payload = %q, want %q", written[4:], payload)
	}

	if conn.writes != 0 {
		t.Errorf("header and payload written with %d individual Write calls, want a single aggregated write", conn.writes)
	}
}

func TestDirectTCPWriteError(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	tr := direct(client)
	server.Close() // close the peer so writes fail

	payload := []byte("hello smb2")
	n, err := tr.Writev(payload)
	if err == nil {
		t.Fatal("Writev() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("Writev() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPWriteDeadline(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := direct(client)
	if err := tr.setWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("setWriteDeadline() returned error: %v", err)
	}

	if _, err := tr.Writev([]byte("hello smb2")); err == nil {
		t.Fatal("Writev() expected deadline error, got nil")
	}
}

func TestDirectTCPWriteTooLarge(t *testing.T) {
	t.Parallel()
	_, client := net.Pipe()
	defer client.Close()

	tr := direct(client)

	n, err := tr.Writev(make([]byte, maxDirectTCPSize+1))
	if err == nil {
		t.Fatal("Writev() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("Writev() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPReadEncryptedPacketReservesAuthenticationTag(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pkt := make([]byte, 128)
	copy(pkt, []byte{0xfd, 'S', 'M', 'B'})
	done := make(chan error, 1)
	go func() {
		wire := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(wire, uint32(len(pkt)))
		copy(wire[4:], pkt)
		_, err := server.Write(wire)
		done <- err
	}()

	rp, err := direct(client).ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer rp.close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rp.pkt, pkt) {
		t.Fatal("encrypted packet changed during reception")
	}
	if cap(rp.pkt)-len(rp.pkt) < 16 {
		t.Fatalf("encrypted packet spare capacity = %d, want at least 16", cap(rp.pkt)-len(rp.pkt))
	}
}

type transportReadStep struct {
	data []byte
	err  error
}

type stagedReadConn struct {
	steps         []transportReadStep
	reads         int
	readDeadlines []time.Time
}

func (c *stagedReadConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.steps) == 0 {
		return 0, errors.New("unexpected read after terminal error")
	}

	step := &c.steps[0]
	n := copy(p, step.data)
	if n < len(step.data) {
		step.data = step.data[n:]
		return n, nil
	}
	c.steps = c.steps[1:]
	return n, step.err
}

func (c *stagedReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *stagedReadConn) Close() error                { return nil }
func (c *stagedReadConn) LocalAddr() net.Addr         { return nil }
func (c *stagedReadConn) RemoteAddr() net.Addr        { return nil }
func (c *stagedReadConn) SetDeadline(time.Time) error { return nil }
func (c *stagedReadConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}
func (c *stagedReadConn) SetWriteDeadline(time.Time) error { return nil }

func transportFrame(body []byte) []byte {
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire, uint32(len(body)))
	copy(wire[4:], body)
	return wire
}

func TestDirectTCPReadPacketRetainsDataWithError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("complete packet")
			conn := &stagedReadConn{steps: []transportReadStep{{data: transportFrame(body), err: tt.err}}}
			tr := direct(conn)

			rp, err := tr.ReadPacket()
			if err != nil {
				t.Fatalf("ReadPacket() returned error: %v", err)
			}
			defer rp.close()
			if !bytes.Equal(rp.pkt, body) {
				t.Fatalf("packet = %q, want %q", rp.pkt, body)
			}

			if _, err := tr.ReadPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next ReadPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketRetainsDirectPayloadWithError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.Repeat([]byte{'p'}, 100)
			first := make([]byte, 4+80)
			binary.BigEndian.PutUint32(first, uint32(len(body)))
			copy(first[4:], body[:80])
			conn := &stagedReadConn{steps: []transportReadStep{
				{data: first},
				{data: body[80:], err: tt.err},
			}}
			tr := direct(conn)
			sink := make([]byte, len(body)-80)

			rp, err := tr.ReadPacket(func(head []byte, restSize int) ([]byte, int) {
				if restSize != len(sink) {
					t.Fatalf("restSize = %d, want %d", restSize, len(sink))
				}
				return sink, len(head)
			})
			if err != nil {
				t.Fatalf("ReadPacket() returned error: %v", err)
			}
			defer rp.close()
			if !bytes.Equal(rp.pkt, body[:80]) {
				t.Fatalf("packet head = %q, want %q", rp.pkt, body[:80])
			}
			if !bytes.Equal(sink, body[80:]) {
				t.Fatalf("direct payload = %q, want %q", sink, body[80:])
			}

			if _, err := tr.ReadPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next ReadPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 2 {
				t.Fatalf("underlying Read calls = %d, want 2", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketReturnsBufferedFramesBeforeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "error", err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := []byte("first packet")
			second := []byte("second packet")
			wire := append(transportFrame(first), transportFrame(second)...)
			conn := &stagedReadConn{steps: []transportReadStep{{data: wire, err: tt.err}}}
			tr := direct(conn)

			for _, want := range [][]byte{first, second} {
				rp, err := tr.ReadPacket()
				if err != nil {
					t.Fatalf("ReadPacket() returned error: %v", err)
				}
				if !bytes.Equal(rp.pkt, want) {
					t.Fatalf("packet = %q, want %q", rp.pkt, want)
				}
				rp.close()
			}

			if _, err := tr.ReadPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("final ReadPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketRejectsIncompleteFrameAfterError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		wire  []byte
		first bool
		err   error
	}{
		{name: "complete then short header EOF", wire: append(transportFrame([]byte("first")), 0, 0), first: true, err: io.EOF},
		{name: "complete then short body EOF", wire: append(transportFrame([]byte("first")), 0, 0, 0, 3, 'a', 'b'), first: true, err: io.EOF},
		{name: "complete then short header error", wire: append(transportFrame([]byte("first")), 0, 0), first: true, err: errors.New("read failed")},
		{name: "complete then short body error", wire: append(transportFrame([]byte("first")), 0, 0, 0, 3, 'a', 'b'), first: true, err: errors.New("read failed")},
		{name: "short header EOF", wire: []byte{0, 0}, err: io.EOF},
		{name: "short body EOF", wire: []byte{0, 0, 0, 3, 'a', 'b'}, err: io.EOF},
		{name: "short header error", wire: []byte{0, 0}, err: errors.New("read failed")},
		{name: "short body error", wire: []byte{0, 0, 0, 3, 'a', 'b'}, err: errors.New("read failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &stagedReadConn{steps: []transportReadStep{{data: tt.wire, err: tt.err}}}
			tr := direct(conn)
			if tt.first {
				rp, err := tr.ReadPacket()
				if err != nil {
					t.Fatalf("complete frame: %v", err)
				}
				if !bytes.Equal(rp.pkt, []byte("first")) {
					t.Errorf("complete frame = %q", rp.pkt)
				}
				rp.close()
			}

			if _, err := tr.ReadPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("ReadPacket() error = %v, want %v", err, tt.err)
			}
			if _, err := tr.ReadPacket(); !errors.Is(err, tt.err) {
				t.Fatalf("next ReadPacket() error = %v, want %v", err, tt.err)
			}
			if conn.reads != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", conn.reads)
			}
		})
	}
}

func TestDirectTCPReadPacketSetsDeadlineForIncompleteFrame(t *testing.T) {
	t.Parallel()
	t.Run("incomplete frame sets and clears deadline", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: []byte{0, 0, 0, 10}},
				{data: []byte("0123456789")},
			},
		}
		tr := direct(conn)
		rp, err := tr.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 2 {
			t.Fatalf("readDeadlines calls = %d, want 2", len(conn.readDeadlines))
		}
		if conn.readDeadlines[0].IsZero() {
			t.Errorf("initial deadline was zero, want non-zero")
		}
		if !conn.readDeadlines[1].IsZero() {
			t.Errorf("final deadline was non-zero, want zero")
		}
	})

	t.Run("already buffered frame skips deadline", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: transportFrame([]byte("hello"))},
			},
		}
		tr := direct(conn)
		rp, err := tr.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 0 {
			t.Errorf("readDeadlines calls = %d, want 0", len(conn.readDeadlines))
		}
	})

	t.Run("custom read timeout applies", func(t *testing.T) {
		conn := &stagedReadConn{
			steps: []transportReadStep{
				{data: []byte{0, 0, 0, 10}},
				{data: []byte("0123456789")},
			},
		}
		dt := direct(conn).(*directTransport)
		dt.setPacketReadTimeout(5 * time.Second)
		start := time.Now()
		rp, err := dt.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket() error: %v", err)
		}
		rp.close()

		if len(conn.readDeadlines) != 2 {
			t.Fatalf("readDeadlines calls = %d, want 2", len(conn.readDeadlines))
		}
		deadline := conn.readDeadlines[0]
		if deadline.Before(start.Add(4*time.Second)) || deadline.After(start.Add(6*time.Second)) {
			t.Errorf("deadline = %v, expected ~5s from %v", deadline, start)
		}
	})
}

func TestDialQUICTransportFramesPackets(t *testing.T) {
	t.Parallel()
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.CloseWithError(0, "test complete")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		frame := make([]byte, 4)
		if _, err := io.ReadFull(stream, frame); err != nil {
			serverDone <- err
			return
		}
		got := be.Uint32(frame)
		if got != uint32(len("request")) {
			serverDone <- errors.New("unexpected request frame size")
			return
		}
		body := make([]byte, got)
		if _, err := io.ReadFull(stream, body); err != nil {
			serverDone <- err
			return
		}
		if string(body) != "request" {
			serverDone <- errors.New("unexpected request body")
			return
		}
		be.PutUint32(frame, uint32(len("response")))
		if _, err := stream.Write(append(frame, []byte("response")...)); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
		// Keep the connection open until the client closes it. This avoids
		// combining the final response with an EOF before the client has
		// consumed the framed packet.
		_, _ = io.Copy(io.Discard, stream)
	}()

	transport, err := dialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.send([]byte("req"), []byte("uest")); err != nil {
		t.Fatal(err)
	}
	response, err := transport.receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q, want response", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialQUICTransportCloseUnblocksReceive(t *testing.T) {
	t.Parallel()
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()

	serverReady := make(chan struct{})
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "test complete")
		stream, err := conn.AcceptStream(context.Background())
		if err == nil {
			close(serverReady)
			_, _ = io.Copy(io.Discard, stream)
		}
	}()

	transport, err := dialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverReady:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept the QUIC stream")
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := transport.receive()
		readDone <- err
	}()
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err == nil {
		t.Fatal("Receive did not return an error after Close")
	}
}

func TestDialQUICTransportSendTimesOut(t *testing.T) {
	t.Parallel()
	listener, clientTLS := newQUICTestListener(t, &quic.Config{
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         64 << 10,
		InitialConnectionReceiveWindow: 64 << 10,
		MaxConnectionReceiveWindow:     64 << 10,
	})
	defer listener.Close()

	serverStop := make(chan struct{})
	defer close(serverStop)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "test complete")
		_, err = conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		<-serverStop
	}()

	transport, err := dialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.setWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	err = transport.send(make([]byte, 8<<20))
	if err == nil {
		t.Fatal("Send completed despite a blocked QUIC peer")
	}
	var timeoutErr interface{ Timeout() bool }
	if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
		t.Fatalf("Send error = %T %v, want a timeout", err, err)
	}
}

func TestDialQUICTransportRejectsCertificateName(t *testing.T) {
	t.Parallel()
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()
	clientTLS.ServerName = "other.example"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialQUICTransport(ctx, listener.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("DialQUICTransport accepted a certificate name mismatch")
	}
	var hostnameErr x509.HostnameError
	if !errors.As(err, &hostnameErr) {
		t.Fatalf("certificate mismatch error = %T %v, want x509.HostnameError", err, err)
	}
}

func TestDialQUICTransportRejectsUntrustedCertificate(t *testing.T) {
	t.Parallel()
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()
	clientTLS.RootCAs = nil

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialQUICTransport(ctx, listener.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("DialQUICTransport accepted an untrusted certificate")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("untrusted certificate error = %T %v, want x509.UnknownAuthorityError", err, err)
	}
}

func TestCloneQUICClientTLSDoesNotMutateConfig(t *testing.T) {
	t.Parallel()
	original := &tls.Config{NextProtos: []string{"other"}}
	cloned := cloneQUICClientTLS("localhost:443", original)
	if cloned.MinVersion != tls.VersionTLS13 || cloned.ServerName != "localhost" {
		t.Fatalf("cloned TLS config = %#v", cloned)
	}
	if len(cloned.NextProtos) != 1 || cloned.NextProtos[0] != smbQUICALPN {
		t.Fatalf("cloned ALPN = %v", cloned.NextProtos)
	}
	if len(original.NextProtos) != 1 || original.NextProtos[0] != "other" {
		t.Fatalf("original TLS config was mutated: %v", original.NextProtos)
	}
}

func TestQUICTransportRequiresSMB311(t *testing.T) {
	t.Parallel()
	_, err := (&Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
		}),
		SpecifiedDialects: []uint16{smb2.SMB302},
		TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
			return quicDialectTransport{}, nil
		}),
	}).Dial(context.Background(), "server")
	if !errors.Is(err, errQUICTransportDialect) {
		t.Fatalf("Dial error = %v, want %v", err, errQUICTransportDialect)
	}
}

type quicDialectTransport struct{}

func (quicDialectTransport) transportType() string              { return "quic" }
func (quicDialectTransport) send(...[]byte) error               { return nil }
func (quicDialectTransport) setReadDeadline(time.Time) error    { return nil }
func (quicDialectTransport) setWriteDeadline(time.Time) error   { return nil }
func (quicDialectTransport) setPacketReadTimeout(time.Duration) {}
func (quicDialectTransport) receive() ([]byte, error)           { return nil, io.EOF }
func (quicDialectTransport) Close() error                       { return nil }

func newQUICTestListener(t *testing.T, configs ...*quic.Config) (*quic.Listener, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	var config *quic.Config
	if len(configs) > 0 {
		config = configs[0]
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{smbQUICALPN},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return listener, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}
