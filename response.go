package smb2

import (
	"sync"
	"sync/atomic"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// ----------------------------------------------------------------------------
// Received Packet Buffer Pool
//

var recvBufPool atomic.Pointer[sync.Pool]

func init() {
	recvBufPool.Store(&sync.Pool{
		New: func() any {
			return &recvBuf{
				data: make([]byte, 0, clientMinBufSize),
			}
		},
	})
}

type recvBuf struct {
	data     []byte
	refCount atomic.Int32
}

type recvPacket struct {
	pkt []byte
	buf *recvBuf

	// ext is the direct I/O segment of the packet: the payload was received
	// directly into a caller-provided buffer, so it is not owned by the
	// packet and must not be released by close. It is only set on a
	// standalone successful READ response (see directTCP.ReadPacket and conn.directReadSink).
	ext []byte
}

func (rp *recvPacket) bytes() []byte {
	if rp == nil {
		return nil
	}
	return rp.pkt
}

func (rp *recvPacket) codec() smb2.PacketCodec {
	if rp == nil {
		return nil
	}
	return smb2.PacketCodec(rp.pkt)
}

func (rp *recvPacket) data() []byte {
	if rp == nil {
		return nil
	}
	return rp.codec().Body()
}

func (rp *recvPacket) transformCodec() smb2.TransformCodec {
	if rp == nil {
		return nil
	}
	return smb2.TransformCodec(rp.pkt)
}

func (rp *recvPacket) close() {
	if rp == nil || rp.buf == nil {
		return
	}
	buf := rp.buf
	rp.buf = nil

	releaseRecvBuf(buf)
}

func (rp *recvPacket) split(next uint32) *recvPacket {
	buf := rp.buf
	nextPkt := rp.pkt[next:]
	rp.pkt = rp.pkt[:next]
	if buf != nil {
		buf.refCount.Add(1)
	}
	return &recvPacket{pkt: nextPkt, buf: buf}
}

func allocRecvBuf(size int) *recvBuf {
	pool := recvBufPool.Load()
	buf := pool.Get().(*recvBuf)
	if cap(buf.data) < size {
		pool.Put(buf)

		buf = &recvBuf{
			data: make([]byte, size),
		}
	} else {
		buf.data = buf.data[:cap(buf.data)]
	}

	buf.refCount.Store(1)

	return buf
}

func releaseRecvBuf(buf *recvBuf) {
	if buf.refCount.Add(-1) == 0 {
		data := buf.data
		if cap(data) > clientMinBufSize {
			return // discard large buffer
		}
		recvBufPool.Load().Put(buf)
	}
}

func allocRecvPacket(size int) *recvPacket {
	return allocRecvPacketWithSpare(size, 0)
}

func allocRecvPacketWithSpare(size, spare int) *recvPacket {
	buf := allocRecvBuf(size + spare)
	return &recvPacket{pkt: buf.data[:size], buf: buf}
}

// ----------------------------------------------------------------------------
// Response
//

type response struct {
	rpkts    []*recvPacket
	treeConn *treeConn
}

func (r *response) close() {
	if r == nil {
		return
	}
	for _, res := range r.rpkts {
		if res != nil {
			res.close()
		}
	}
}

func (r *response) packet(i int) *recvPacket {
	if r == nil || i < 0 || i >= len(r.rpkts) {
		return nil
	}
	return r.rpkts[i]
}

func (r *response) bytes(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.bytes()
}

func (r *response) data(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.data()
}

// ext returns the direct I/O segment of the i-th packet, if any.
func (r *response) ext(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.ext
}

type packetReceiver interface {
	recv(*outstandingRequest) (*recvPacket, error)
}

func recvAll(rrs []*outstandingRequest, r packetReceiver) (*response, error) {
	if len(rrs) == 0 {
		return nil, &InternalError{"empty request"}
	}
	if len(rrs) == 1 {
		rp, err := r.recv(rrs[0])
		if err != nil {
			return nil, err
		}
		return &response{rpkts: []*recvPacket{rp}}, nil
	}

	rpkts := make([]*recvPacket, len(rrs))
	errs := make([]error, len(rrs))
	var hasErr bool

	// Related compound operations still receive individual responses after an
	// error; process every request so each CreditResponse is accounted for
	// ([MS-SMB2] 3.3.5.2.7.2 and 3.2.5.1.4).
	for i, rr := range rrs {
		rp, err := r.recv(rr)
		if err != nil {
			hasErr = true
			errs[i] = err
			continue
		}
		rpkts[i] = rp
	}

	if hasErr {
		return &response{rpkts: rpkts}, &CompoundResponseError{Errors: errs}
	}

	return &response{rpkts: rpkts}, nil
}
