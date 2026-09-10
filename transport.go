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

type directSinkFinder func(head []byte, restSize int) (sink []byte, frontSize int)

type transport interface {
	Write(p []byte) (n int, err error)
	SetWriteDeadline(t time.Time) error
	ReadPacket(findSink ...directSinkFinder) (*recvPacket, error)
	Close() error
}

type directTCP struct {
	sb   [4]byte
	conn net.Conn

	recvBuf *recvBuf
	rpos    int
	wpos    int

	// pending is the number of body bytes of the in-flight packet that have
	// not been consumed by readRestInto yet.
	pending int
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

func (t *directTCP) SetWriteDeadline(time time.Time) error {
	return t.conn.SetWriteDeadline(time)
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

	for len(b) > 0 {
		n, err := t.conn.Read(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			t.dropBuf()
			return err
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

	rp := allocRecvPacket(pktSize)
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
