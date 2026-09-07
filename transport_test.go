package smb2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
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

	n, err := tr.Write(payload)
	if err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("Write() = %d bytes, want %d", n, want)
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

	n, err := tr.Write(payload)
	if err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}
	if want := len(payload) + 4; n != want {
		t.Errorf("Write() = %d bytes, want %d", n, want)
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
	n, err := tr.Write(payload)
	if err == nil {
		t.Fatal("Write() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("Write() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPWriteTooLarge(t *testing.T) {
	_, client := net.Pipe()
	defer client.Close()

	tr := direct(client)

	n, err := tr.Write(make([]byte, maxDirectTCPSize+1))
	if err == nil {
		t.Fatal("Write() expected error, got nil")
	}
	if n != -1 {
		t.Errorf("Write() = %d bytes on error, want -1", n)
	}
}

func TestDirectTCPReadSizeRejectsOversizedFrame(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tr := direct(client)
	header := make([]byte, 4)
	be.PutUint32(header, uint32(maxDirectTCPRecvSize+1))

	written := make(chan error, 1)
	go func() {
		_, err := server.Write(header)
		written <- err
	}()

	size, err := tr.ReadSize()
	if err == nil {
		t.Fatalf("ReadSize() = %d, want error for oversized frame", size)
	}
	if size != -1 {
		t.Errorf("ReadSize() = %d on error, want -1", size)
	}
	if err := <-written; err != nil {
		t.Fatalf("failed to write transport header: %v", err)
	}
}
