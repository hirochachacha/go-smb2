package protocol

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// ----------------------------------------------------------------------------
// Received Packet Buffer Pool
//

// Receive buffers are pooled by size class. Class i holds buffers of
// clientMinBufSize<<i bytes plus recvBufSlack, so a response carrying a
// power-of-two payload fits one class together with its SMB2 and transform
// headers. The largest class covers maxDirectTCPSize.
const (
	recvBufClasses = 15
	recvBufSlack   = 4 << 10
)

type recvBufPools [recvBufClasses]sync.Pool

var recvBufPool atomic.Pointer[recvBufPools]

func init() {
	recvBufPool.Store(newRecvBufPools(func(capacity int) *recvBuf {
		return &recvBuf{data: make([]byte, 0, capacity)}
	}))
}

func newRecvBufPools(newBuf func(capacity int) *recvBuf) *recvBufPools {
	pools := new(recvBufPools)
	for i := range pools {
		capacity := recvBufClassSize(i)
		pools[i].New = func() any { return newBuf(capacity) }
	}
	return pools
}

func recvBufClassSize(class int) int {
	return clientMinBufSize<<class + recvBufSlack
}

type recvBuf struct {
	data     []byte
	refCount atomic.Int32
}

type recvPacket struct {
	payloadRequest payloadRequest
	pkt            []byte
	buf            *recvBuf

	// ext is the direct I/O segment of the packet: the payload was received
	// directly into a caller-provided buffer, so it is not owned by the
	// packet and must not be released by close. It is only set on a
	// standalone successful READ Response (see transport.readPacket and conn.directReadSink).
	ext []byte
}

func (rp *recvPacket) bytes() []byte {
	if rp == nil {
		return nil
	}
	return rp.pkt
}

func (rp *recvPacket) codec() wire.PacketCodec {
	if rp == nil {
		return nil
	}
	return wire.PacketCodec(rp.pkt)
}

func (rp *recvPacket) data() []byte {
	if rp == nil {
		return nil
	}
	return rp.codec().Body()
}

func (rp *recvPacket) transformCodec() wire.TransformCodec {
	if rp == nil {
		return nil
	}
	return wire.TransformCodec(rp.pkt)
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
	if next > uint32(len(rp.pkt)) {
		return nil
	}
	buf := rp.buf
	nextPkt := rp.pkt[next:]
	rp.pkt = rp.pkt[:next]
	if buf != nil {
		buf.refCount.Add(1)
	}
	return &recvPacket{pkt: nextPkt, buf: buf}
}

func allocRecvBuf(size int) *recvBuf {
	var buf *recvBuf
	// Use the smallest class that fits size.
	for class := range recvBufClasses {
		if size <= recvBufClassSize(class) {
			buf = recvBufPool.Load()[class].Get().(*recvBuf)
			buf.data = buf.data[:cap(buf.data)]
			break
		}
	}
	if buf == nil {
		buf = &recvBuf{data: make([]byte, size)}
	}

	buf.refCount.Store(1)

	return buf
}

func releaseRecvBuf(buf *recvBuf) {
	if buf.refCount.Add(-1) == 0 {
		// Return the buffer to the largest class it can serve.
		for class := recvBufClasses - 1; class >= 0; class-- {
			if cap(buf.data) >= recvBufClassSize(class) {
				recvBufPool.Load()[class].Put(buf)
				return
			}
		}
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

type Response struct {
	rpkts        []*recvPacket
	tree         *Tree
	resolvedPath string
}

// ResolvedPath returns the path used by the leading CREATE after symbolic-link
// resolution, or an empty string if the request did not start with CREATE.
func (r *Response) ResolvedPath() string {
	if r == nil {
		return ""
	}
	return r.resolvedPath
}

// Close releases pooled receive buffers owned by the response. It is safe to
// call more than once; all byte slices returned by this response become
// invalid for reuse after Close.
func (r *Response) Close() { r.close() }

// Bytes returns the complete encoded SMB packet at index i as a read-only view.
// Converting these raw bytes to a decoder requires an IsInvalid check.
func (r *Response) Bytes(i int) []byte { return r.bytes(i) }

// Data returns the SMB body bytes at index i as a read-only view. Converting
// these raw bytes to a decoder requires an IsInvalid check. Prefer the typed
// response accessors when interpreting a response envelope.
func (r *Response) Data(i int) []byte { return r.data(i) }

// DirectData returns the caller buffer used by a direct I/O READ response, if
// the response at index i used direct reception.
func (r *Response) DirectData(i int) []byte { return r.ext(i) }

func (r *Response) close() {
	if r == nil {
		return
	}
	for _, res := range r.rpkts {
		if res != nil {
			res.close()
		}
	}
	r.rpkts = nil
}

func (r *Response) packet(i int) *recvPacket {
	if r == nil || i < 0 || i >= len(r.rpkts) {
		return nil
	}
	return r.rpkts[i]
}

func (r *Response) bytes(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.bytes()
}

func (r *Response) data(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.data()
}

// ext returns the direct I/O segment of the i-th packet, if any.
func (r *Response) ext(i int) []byte {
	res := r.packet(i)
	if res == nil {
		return nil
	}
	return res.ext
}

type packetReceiver interface {
	recv(*outstandingRequest) (*recvPacket, error)
}

func recvAll(rrs []*outstandingRequest, r packetReceiver) (*Response, error) {
	if len(rrs) == 0 {
		return nil, errors.New("protocol: empty request")
	}
	if len(rrs) == 1 {
		rp, err := r.recv(rrs[0])
		if err != nil {
			return nil, err
		}
		return &Response{rpkts: []*recvPacket{rp}}, nil
	}

	rpkts := make([]*recvPacket, len(rrs))
	var errs []error

	// Related compound operations still receive individual responses after an
	// error; process every request so each CreditResponse is accounted for
	// ([MS-SMB2] 3.3.5.2.7.2 and 3.2.5.1.4).
	for i, rr := range rrs {
		rp, err := r.recv(rr)
		if err != nil {
			if errs == nil {
				errs = make([]error, len(rrs))
			}
			errs[i] = err
			continue
		}
		rpkts[i] = rp
	}

	if errs != nil {
		return &Response{rpkts: rpkts}, &CompoundResponseError{Errors: errs}
	}

	return &Response{rpkts: rpkts}, nil
}
