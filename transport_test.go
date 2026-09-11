package smb2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDirectTCPWrite(t *testing.T) {
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
	tr := &directTCP{conn: conn}

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
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := direct(client)
	if err := tr.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline() returned error: %v", err)
	}

	if _, err := tr.Writev([]byte("hello smb2")); err == nil {
		t.Fatal("Writev() expected deadline error, got nil")
	}
}

func TestDirectTCPWriteTooLarge(t *testing.T) {
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
	steps []transportReadStep
	reads int
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

func (c *stagedReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stagedReadConn) Close() error                     { return nil }
func (c *stagedReadConn) LocalAddr() net.Addr              { return nil }
func (c *stagedReadConn) RemoteAddr() net.Addr             { return nil }
func (c *stagedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *stagedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stagedReadConn) SetWriteDeadline(time.Time) error { return nil }

func transportFrame(body []byte) []byte {
	wire := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(wire, uint32(len(body)))
	copy(wire[4:], body)
	return wire
}

func TestDirectTCPReadPacketRetainsDataWithError(t *testing.T) {
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
