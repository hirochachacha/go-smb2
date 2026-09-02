package smb2

import (
	"sync"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// ----------------------------------------------------------------------------
// Received Packet Buffer Pool
//

var receivedPacketPool = sync.Pool{
	New: func() interface{} {
		return &receivedPacket{
			pkt: make([]byte, 0, 64*1024),
		}
	},
}

type receivedPacket struct {
	pkt []byte
}

func (rp *receivedPacket) bytes() []byte {
	if rp == nil {
		return nil
	}
	return rp.pkt
}

func (rp *receivedPacket) packetCodec() smb2.PacketCodec {
	if rp == nil {
		return nil
	}
	return smb2.PacketCodec(rp.pkt)
}

func (rp *receivedPacket) data() []byte {
	if rp == nil {
		return nil
	}
	return rp.packetCodec().Data()
}

func (rp *receivedPacket) transformCodec() smb2.TransformCodec {
	if rp == nil {
		return nil
	}
	return smb2.TransformCodec(rp.pkt)
}

func (rp *receivedPacket) close() {
	if rp == nil || rp.pkt == nil {
		return
	}
	b := rp.pkt
	if cap(b) > 1024*1024 {
		rp.pkt = nil
		return
	}
	clear(b[:cap(b)])
	rp.pkt = b[:0]
	receivedPacketPool.Put(rp)
}

func allocReceivedPacket(size int) *receivedPacket {
	rp := receivedPacketPool.Get().(*receivedPacket)
	if cap(rp.pkt) < size {
		rp.pkt = make([]byte, size)
	} else {
		rp.pkt = rp.pkt[:size]
	}
	return rp
}

// ----------------------------------------------------------------------------
// Response
//

type response struct {
	rpkts []*receivedPacket
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

func (r *response) packet(i int) *receivedPacket {
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
	recv(*outstandingRequest) (*receivedPacket, error)
}

func recvAll(rrs []*outstandingRequest, r packetReceiver) (*response, error) {
	rpkts := make([]*receivedPacket, len(rrs))
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
