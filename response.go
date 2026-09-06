package smb2

import (
	"sync"
	"sync/atomic"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// ----------------------------------------------------------------------------
// Received Packet Buffer Pool
//

var recvBufPool = &sync.Pool{
	New: func() interface{} {
		return &recvBuf{
			data: make([]byte, 0, singleCreditMaxPayloadSize),
		}
	},
}

type recvBuf struct {
	data     []byte
	refCount atomic.Int32
}

type recvPacket struct {
	pkt []byte
	buf *recvBuf
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
	return rp.codec().Data()
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

	if buf.refCount.Add(-1) == 0 {
		data := buf.data
		if cap(data) > 1024*1024 {
			return // discard large buffer
		}
		recvBufPool.Put(buf)
	}
}

func (rp *recvPacket) split(next uint32) *recvPacket {
	buf := rp.buf
	nextPkt := rp.pkt[next:]
	rp.pkt = rp.pkt[:next]
	buf.refCount.Add(1)
	return &recvPacket{pkt: nextPkt, buf: buf}
}

func allocRecvPacket(size int) *recvPacket {
	buf := recvBufPool.Get().(*recvBuf)
	if cap(buf.data) < size {
		recvBufPool.Put(buf)

		buf = &recvBuf{
			data: make([]byte, size),
		}
	} else {
		clear(buf.data[:size])
	}

	pkt := buf.data[:size]
	buf.refCount.Add(1)
	return &recvPacket{pkt: pkt, buf: buf}
}

// ----------------------------------------------------------------------------
// Response
//

type response struct {
	rpkts []*recvPacket
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

type packetReceiver interface {
	recv(*outstandingRequest) (*recvPacket, error)
}

func recvAll(rrs []*outstandingRequest, r packetReceiver) (*response, error) {
	rpkts := make([]*recvPacket, len(rrs))
	var firstErr error
	for i, rr := range rrs {
		rp, err := r.recv(rr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rpkts[i] = rp
	}

	if firstErr != nil {
		for _, rp := range rpkts {
			if rp != nil {
				rp.close()
			}
		}
		return nil, firstErr
	}

	return &response{rpkts: rpkts}, nil
}
