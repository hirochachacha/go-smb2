package smb2

import (
	"errors"
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
	ReadPacket() (*recvPacket, error)
	Close() error
}

type directTCP struct {
	sb   [4]byte
	conn net.Conn

	recvBuf *recvBuf
	rpos    int
	wpos    int
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
			t.dropBuf()
			return err
		}
	}

	return nil
}

func (t *directTCP) ReadPacket() (*recvPacket, error) {
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

	if err := t.fill(pktSize); err != nil {
		return nil, err
	}

	pkt := t.recvBuf.data[t.rpos : t.rpos+pktSize]
	t.recvBuf.refCount.Add(1)
	rp := &recvPacket{pkt: pkt, buf: t.recvBuf}
	t.rpos += pktSize

	if t.rpos == t.wpos {
		t.dropBuf()
	}

	return rp, nil
}

func (t *directTCP) Close() error {
	return t.conn.Close()
}
