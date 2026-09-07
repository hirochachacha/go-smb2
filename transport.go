package smb2

import (
	"errors"
	"io"
	"net"
	"time"
)

const (
	maxDirectTCPSize = 0xffffff // 16777215
	// maxNetBTSize     = 0x1ffff  // 131071
)

type transport interface {
	Write(p []byte) (n int, err error)
	SetWriteDeadline(t time.Time) error
	ReadSize() (size int, err error)
	Read(p []byte) (n int, err error)
	Close() error
}

type directTCP struct {
	sb   [4]byte
	rb   [4]byte
	conn net.Conn
}

func direct(tcpConn net.Conn) transport {
	return &directTCP{conn: tcpConn}
}

func (t *directTCP) Write(p []byte) (n int, err error) {
	if len(p) > maxDirectTCPSize {
		return -1, errors.New("max transport size exceeds")
	}

	be.PutUint32(t.sb[:], uint32(len(p)))

	buffers := net.Buffers{t.sb[:], p}
	n64, err := buffers.WriteTo(t.conn)
	if err != nil {
		return -1, err
	}

	return int(n64), nil
}

func (t *directTCP) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

func (t *directTCP) ReadSize() (size int, err error) {
	bs := t.rb[:]

	_, err = io.ReadFull(t.conn, bs)
	if err != nil {
		return -1, err
	}

	if bs[0] != 0 {
		return -1, errors.New("invalid transport format")
	}

	return int(be.Uint32(bs)), nil
}

func (t *directTCP) Read(p []byte) (n int, err error) {
	n, err = io.ReadFull(t.conn, p)
	if err != nil {
		return -1, err
	}

	return n, err
}

func (t *directTCP) Close() error {
	return t.conn.Close()
}
