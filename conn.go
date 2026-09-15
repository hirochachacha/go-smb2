package smb2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

func newHashContext() (*smb2.HashContext, error) {
	hc := &smb2.HashContext{
		HashAlgorithms: clientHashAlgorithms,
		HashSalt:       make([]byte, 32),
	}
	if _, err := rand.Read(hc.HashSalt); err != nil {
		return nil, &InternalError{err.Error()}
	}
	return hc, nil
}

func newCipherContext(ciphers []uint16) *smb2.CipherContext {
	if len(ciphers) == 0 {
		ciphers = clientCiphers
	}
	return &smb2.CipherContext{
		Ciphers: ciphers,
	}
}

func newCompressionContext() *smb2.CompressionContext {
	return &smb2.CompressionContext{
		CompressionAlgorithms: clientCompressionAlgorithms,
		Flags:                 smb2.SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE,
	}
}

const (
	directStateIdle     uint32 = 0
	directStateReading  uint32 = 1
	directStateDone     uint32 = 2
	directStateCanceled uint32 = 3
)

type outstandingRequest struct {
	msgId      uint64
	asyncId    atomic.Uint64
	cmd        smb2.Command
	ctx        context.Context
	recv       chan *recvPacket
	err        error
	canceled   atomic.Bool
	cancelOnce sync.Once
	// requireEncryption records Request.IsEncrypted. [MS-SMB2] 3.3.4.1.4
	// requires every response to such a request to be encrypted. The send
	// paths derive this from session ([MS-SMB2] 2.2.6) and share policy,
	// preserving negotiation, SESSION_SETUP and share TREE_CONNECT exceptions.
	// Keep it per request so compound and async responses cannot lose it.
	requireEncryption bool
	creditCharge      uint16
	lockWait          bool
	// waitFinal preserves CREATE and related responses after cancellation so
	// the tree connection can reclaim an open that the server did not cancel.
	waitFinal bool

	// readBuf is the caller-provided buffer that the payload of a direct
	// I/O READ response is received into. It is registered by
	// makeOutstandingRequest and consumed directly by the transport.
	readBuf []byte

	// directDone is closed when direct reception into readBuf has finished
	// (either successfully or aborted by error).
	directDone  chan struct{}
	directOnce  sync.Once
	directState atomic.Uint32
}

func (rr *outstandingRequest) finishDirect() {
	if rr.directDone != nil {
		rr.directOnce.Do(func() {
			close(rr.directDone)
		})
	}
}

func (rr *outstandingRequest) abort() {
	rr.canceled.Store(true)

	if rr.directState.Swap(directStateCanceled) == directStateReading {
		// A direct read is currently reading directly into the caller's
		// buffer. Wait for in-flight reception to complete so late bytes
		// never overwrite the returned buffer.
		<-rr.directDone
	} else {
		rr.finishDirect()
	}

	select {
	case rp := <-rr.recv:
		if rp != nil {
			rp.close()
		}
	default:
	}
}

type outstandingRequests struct {
	m        sync.Mutex
	requests map[uint64]*outstandingRequest
}

func newOutstandingRequests() *outstandingRequests {
	return &outstandingRequests{
		requests: make(map[uint64]*outstandingRequest),
	}
}

func (r *outstandingRequests) pop(msgId uint64) (*outstandingRequest, bool) {
	r.m.Lock()
	defer r.m.Unlock()

	rr, ok := r.requests[msgId]
	if !ok {
		return nil, false
	}

	delete(r.requests, msgId)

	return rr, true
}

func (r *outstandingRequests) peek(msgId uint64) (*outstandingRequest, bool) {
	r.m.Lock()
	defer r.m.Unlock()

	rr, ok := r.requests[msgId]
	return rr, ok
}

func (r *outstandingRequests) set(msgId uint64, rr *outstandingRequest) {
	r.m.Lock()
	defer r.m.Unlock()

	r.requests[msgId] = rr
}

func (r *outstandingRequests) shutdown(err error) {
	r.m.Lock()
	defer r.m.Unlock()

	for _, rr := range r.requests {
		rr.err = err
		rr.finishDirect()
		close(rr.recv)
	}
	clear(r.requests)
}

type conn struct {
	t Transport

	session                    *session
	outstandingRequests        *outstandingRequests
	dialect                    uint16
	maxTransactSize            uint32
	maxReadSize                uint32
	maxWriteSize               uint32
	compressionIds             []uint16
	supportsChainedCompression bool
	ioPipelineDepth            uint
	requireSigning             bool
	capabilities               uint32
	preauthIntegrityHashId     uint16
	preauthIntegrityHashValue  [64]byte
	cipherId                   uint16
	acceptTransportSecurity    bool

	account *account

	rdone        chan struct{}
	writeTimeout time.Duration
	receiverDone chan struct{}

	m              sync.Mutex
	transportClose sync.Once
	transportErr   error

	err error

	// gssNegotiateToken []byte
	// serverGuid        [16]byte
	// clientGuid        [16]byte

	_useSession atomic.Int32 // receiver use session?

	// Reusable packet transformation buffers. Use them with conn.m held.

	encodeBuf      []byte
	compressionBuf []byte
	encryptBuf     []byte
}

func (conn *conn) allocEncodeBuf(size int) []byte {
	return conn.allocBuf(&conn.encodeBuf, size)
}

func (conn *conn) allocEncryptBuf(size int) []byte {
	return conn.allocBuf(&conn.encryptBuf, size)
}

func (conn *conn) allocCompressionBuf(size int) []byte {
	if cap(conn.compressionBuf) < size {
		newCap := max(size, clientMinBufSize)
		conn.compressionBuf = make([]byte, newCap)
	}
	conn.compressionBuf = conn.compressionBuf[:size]
	return conn.compressionBuf
}

func (conn *conn) allocBuf(buf *[]byte, size int) []byte {
	if cap(*buf) < size {
		newCap := max(size, clientMinBufSize)
		*buf = make([]byte, newCap)
	} else {
		clear((*buf)[:size])
	}
	*buf = (*buf)[:size]
	return *buf
}

func updatePreauthHash(hashVal *[64]byte, pkt []byte) {
	h := sha512.New()
	h.Write(hashVal[:])
	h.Write(pkt)
	h.Sum(hashVal[:0])
}

func (conn *conn) useSession() bool {
	return conn._useSession.Load() != 0
}

func (conn *conn) enableSession() {
	conn._useSession.Store(1)
}

func (conn *conn) maxCreditSize(companions int) int {
	maxSize := maxSingleCreditPayloadSize
	if conn.account != nil {
		credits := max(int(conn.account.maxCreditCap())-companions, 1)
		if creditCap := int64(credits) * maxSingleCreditPayloadSize; creditCap > 0 {
			maxSize = int(min(creditCap, int64(winMaxPayloadSize)))
		}
	}
	return maxSize
}

func (conn *conn) effectivePayloadSize(limit uint32, companions int) int {
	size := int(limit)
	if size <= 0 {
		size = maxSingleCreditPayloadSize
	}
	creditSize := conn.maxCreditSize(companions)
	if conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		return min(size, maxSingleCreditPayloadSize, creditSize)
	}
	return min(size, winMaxPayloadSize, creditSize)
}

func (conn *conn) closeLocked(err error) error {
	if conn.err != nil {
		return nil
	}
	if err == nil {
		err = &TransportError{Err: net.ErrClosed}
	}
	conn.err = err

	if conn.account != nil {
		conn.account.abort(err)
	}

	select {
	case conn.rdone <- struct{}{}:
	default:
	}

	return nil
}

func (conn *conn) close(err error) error {
	conn.m.Lock()
	if conn.err == nil {
		conn.closeLocked(err)
	}
	conn.m.Unlock()
	errClose := conn.closeTransport()
	conn.waitReceiver()
	return errClose
}

// shutdownTransport closes the transport without acquiring conn.m. Shutdown
// uses this path when another goroutine is blocked in synchronous send I/O.
func (conn *conn) shutdownTransport(err error) error {
	if conn == nil || conn.t == nil {
		return nil
	}
	// Close the transport first. A sender can be blocked in Writev while
	// holding conn.m, so acquiring that mutex before transport shutdown can
	// deadlock Session.Close.
	errClose := conn.closeTransport()
	conn.m.Lock()
	if conn.err == nil {
		conn.closeLocked(err)
	}
	conn.m.Unlock()
	return errClose
}

func (conn *conn) closeTransport() error {
	if conn == nil || conn.t == nil {
		return nil
	}
	conn.transportClose.Do(func() { conn.transportErr = conn.t.Close() })
	return conn.transportErr
}

func (conn *conn) sendRecv(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	rrs, err := conn.send(ctx, false, reqs...)
	if err != nil {
		return nil, err
	}
	return recvAll(rrs, conn)
}

/*
mustSign returns true if req needs to be signed.

MS-SMB2 3.2.4.1.1 describes when a message needs to be signed.
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d
*/
func (conn *conn) mustSign(s *session, req smb2.Packet) bool {
	if _, isSessionSetup := req.(*smb2.SessionSetupRequest); isSessionSetup {
		return false
	}

	// a 'guest' or anonymous user or a session without a key can't sign requests
	if s.signingDisabled() {
		return false
	}

	// true if the library user requested it at initialization or if the server
	// requires it
	if conn.requireSigning {
		return true
	}

	// Only SMB 3.1.1 requires TREE_CONNECT to always be signed, but for
	// simplicity's sake, we'll sign it no matter the dialect version.
	_, isTreeConnect := req.(*smb2.TreeConnectRequest)
	return isTreeConnect
}

func (conn *conn) send(ctx context.Context, encrypt bool, reqs ...smb2.Packet) (rrs []*outstandingRequest, err error) {
	msgIds, totalCreditCharge, err := conn.account.loan(ctx, reqs...)
	if err != nil {
		return nil, err
	}

	conn.m.Lock()

	if conn.err != nil {
		err := conn.err
		conn.account.unloan(totalCreditCharge)
		conn.m.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		conn.account.unloan(totalCreditCharge)
		conn.m.Unlock()
		return nil, ctx.Err()
	default:
		// do nothing
	}

	rrs, parts, err := conn.makeOutstandingRequest(ctx, encrypt, msgIds, reqs...)
	if err != nil {
		conn.account.unloan(totalCreditCharge)
		conn.m.Unlock()
		return nil, err
	}

	// Once frame transmission starts, wait for its completion so cancellation
	// can remain a separate SMB2 CANCEL request ([MS-SMB2] 3.2.4.24).
	// Only the transport timeout bounds this write; recv handles request
	// cancellation after a successful send.
	err = conn.sendRaw(parts...)
	if err != nil {
		conn.account.unloan(totalCreditCharge)
		terr := &TransportError{err}
		// the transport is broken, tear down the connection
		conn.closeLocked(terr)
		// The request stays registered so the receiver's normal completion
		// path (tryHandle or the runReceiver shutdown) can unregister it and
		// close directDone. Responses are matched to OutstandingRequests by
		// MessageId ([MS-SMB2] 3.2.5.1.2); popping it here would hide the
		// request and leave the direct reception wait below without a
		// completion. Release the connection lock first: the receiver needs
		// it to tear the connection down, and holding it here would deadlock
		// the wait below. A direct READ that already published its sink may
		// still be writing into the caller's buffer, so abort every request
		// before returning the buffer for reuse.
		conn.m.Unlock()
		_ = conn.closeTransport()
		for _, rr := range rrs {
			rr.abort()
		}
		return nil, terr
	}

	conn.m.Unlock()
	return rrs, nil
}

func (conn *conn) sendRaw(parts ...[]byte) error {
	timeout := conn.writeTimeout
	if timeout <= 0 {
		timeout = clientWriteTimeout
	}
	deadline := time.Now().Add(timeout)
	if err := conn.t.setWriteDeadline(deadline); err != nil {
		return err
	}
	defer conn.t.setWriteDeadline(time.Time{})

	return conn.t.send(parts...)
}

func (conn *conn) makeOutstandingRequest(ctx context.Context, encrypt bool, msgIds []uint64, reqs ...smb2.Packet) (rrs []*outstandingRequest, parts [][]byte, err error) {
	encrypt = encrypt && !conn.acceptTransportSecurity
	s := conn.session
	rrs = make([]*outstandingRequest, len(reqs))
	compress := conn.useSession() && conn.compressionEnabled()
	for _, req := range reqs {
		if req.Command() == smb2.SMB2_NEGOTIATE {
			compress = false
			break
		}
	}

	// Direct I/O write: a non-empty WRITE is encoded without first copying its
	// payload into the ordinary packet buffer. For an unencrypted message the
	// payload is sent as an extra transport segment. Encrypted messages still
	// need one contiguous plaintext input for AEAD, so the payload is copied
	// directly into the encryption buffer instead. An empty write is excluded:
	// its generic encoding carries an extra dangling byte (see
	// WriteRequest.Size), which the direct path would drop. At most one WRITE
	// is sent directly; the rest falls back to the generic path. Compression
	// transforms the complete SMB2 message ([MS-SMB2] 3.1.4.4), so compressed
	// writes also use the contiguous generic path.
	directIdx := -1
	if !compress {
		for i, req := range reqs {
			wr, ok := req.(*smb2.WriteRequest)
			if !ok || wr.WriteChannelInfo != nil || len(wr.Data) == 0 {
				continue
			}
			if directIdx >= 0 {
				directIdx = -1
				break
			}
			directIdx = i
		}
	}

	var data []byte
	if directIdx >= 0 {
		data = reqs[directIdx].(*smb2.WriteRequest).Data
	}

	// Compound request (len(reqs) > 1)
	var totalSize int
	fixedSpans := make([]int, len(reqs)) // bytes encoded into pkt (payload excluded for directIdx); NextCommand uses the full wire span
	for i, req := range reqs {
		span := req.Size()
		if i < len(reqs)-1 {
			span = smb2.Roundup(span, 8)
			req.SetNextCommand(uint32(span))
		} else {
			req.SetNextCommand(0)
		}
		fixedSpans[i] = span
		totalSize += span
	}
	if directIdx >= 0 && !encrypt {
		fixedSpans[directIdx] -= len(data)
		totalSize -= len(data)
	}

	// wrHeaderLen is the length of the direct WRITE's fixed part encoded
	// into pkt: SMB2 header + fixed body, without payload (WriteChannelInfo
	// is required to be nil by the detection above).
	const wrHeaderLen = 64 + 48

	for i, req := range reqs {
		switch r := req.(type) {
		case *directReadRequest:
			if compress {
				r.Flags |= smb2.SMB2_READFLAG_REQUEST_COMPRESSED
			}
		case *smb2.ReadRequest:
			if compress {
				r.Flags |= smb2.SMB2_READFLAG_REQUEST_COMPRESSED
			}
		}

		msgId := msgIds[i]

		if i > 0 {
			req.SetFlags(req.HeaderFlags() | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		}

		rr := &outstandingRequest{
			cmd:               req.Command(),
			msgId:             msgId,
			ctx:               ctx,
			recv:              make(chan *recvPacket, 1),
			requireEncryption: s != nil && encrypt,
			creditCharge:      req.CreditCharge(),
			lockWait:          req.Command() == smb2.SMB2_LOCK,
		}

		if drr, ok := req.(*directReadRequest); ok {
			rr.readBuf = drr.b
			rr.directDone = make(chan struct{})
		}

		rrs[i] = rr
	}

	var pkt []byte
	var encryptBuf []byte
	if s != nil && encrypt && directIdx >= 0 {
		// Keep the plaintext immediately before encryption in the same buffer
		// that will hold the transformed packet. AEAD permits exact in-place
		// operation, avoiding an intermediate encoded packet for direct I/O.
		encryptBuf = conn.allocEncryptBuf(52 + totalSize + 16)
		pkt = encryptBuf[52 : 52+totalSize]
	} else {
		pkt = conn.allocEncodeBuf(totalSize)
	}

	off := 0
	for i, req := range reqs {
		if i == directIdx {
			// Encode only the fixed part of the request. Encode computes
			// Length and DataOffset from wr.Data even though the payload
			// does not fit in pkt, so the fixed bytes stay identical to
			// the contiguous encoding. The padding after the payload (if
			// any) is left zeroed by the buffer allocator.
			req.Encode(pkt[off : off+wrHeaderLen])
			if encrypt {
				copy(pkt[off+wrHeaderLen:off+wrHeaderLen+len(data)], data)
			}
		} else {
			req.Encode(pkt[off : off+fixedSpans[i]])
		}
		// [MS-SMB2] 2.2.1.2 and 3.2.4.1.5 require a reserved zero wire
		// CreditCharge for SMB 2.0.2, without changing internal accounting.
		// Include SMB 2.0.2-only NEGOTIATE before the dialect is known, and
		// correct the header before signing, compression and encryption.
		zeroCreditCharge := conn.dialect == smb2.SMB202
		if nr, ok := req.(*smb2.NegotiateRequest); ok && len(nr.Dialects) == 1 && nr.Dialects[0] == smb2.SMB202 {
			zeroCreditCharge = true
		}
		if zeroCreditCharge {
			smb2.PacketCodec(pkt[off : off+64]).SetCreditCharge(0)
		}
		off += fixedSpans[i]
	}

	if s != nil && !encrypt {
		off = 0
		requireSigning := false
		for _, req := range reqs {
			if conn.mustSign(s, req) {
				requireSigning = true
				break
			}
		}
		for i := range reqs {
			subPkt := pkt[off : off+fixedSpans[i]]
			if requireSigning {
				if i == directIdx {
					// The signed region covers the payload in between,
					// matching the contiguous encoding.
					s.sign(subPkt[:wrHeaderLen], data, subPkt[wrHeaderLen:])
				} else {
					s.sign(subPkt)
				}
			}
			off += fixedSpans[i]
		}
	}

	// [MS-SMB2] 3.1.4.3 requires compression before encryption when both
	// transforms apply to the same message.
	if compress {
		compressionBuf := conn.allocCompressionBuf(maxCompressedPacketSize(len(pkt)))
		pkt, err = compressPacketInto(pkt, compressionBuf)
		if err != nil {
			return nil, nil, &InternalError{err.Error()}
		}
	}

	if s != nil && encrypt {
		if encryptBuf == nil {
			encSize := 52 + len(pkt) + 16
			encryptBuf = conn.allocEncryptBuf(encSize)
		}
		pkt, err = s.encrypt(pkt, encryptBuf)
		if err != nil {
			return nil, nil, &InternalError{err.Error()}
		}
	}

	for _, rr := range rrs {
		conn.outstandingRequests.set(rr.msgId, rr)
	}

	if directIdx < 0 || encrypt {
		parts = [][]byte{pkt}
	} else {
		cut := 0
		for i := 0; i < directIdx; i++ {
			cut += fixedSpans[i]
		}
		cut += wrHeaderLen

		parts = make([][]byte, 0, 3)
		if cut > 0 {
			parts = append(parts, pkt[:cut])
		}
		parts = append(parts, data)
		if cut < len(pkt) {
			parts = append(parts, pkt[cut:])
		}
	}

	return rrs, parts, nil
}

func (conn *conn) recv(rr *outstandingRequest) (*recvPacket, error) {
	acceptResponse := func(rp *recvPacket) (*recvPacket, error) {
		if rp == nil {
			// the channel was closed by conn.close while rr was outstanding
			if rr.err != nil {
				return nil, rr.err
			}
			return nil, &TransportError{Err: net.ErrClosed}
		}
		if rr.err != nil {
			rp.close()
			return nil, rr.err
		}
		res, err := accept(rr.cmd, rp, conn.dialect)
		if rr.lockWait && rr.ctx.Err() != nil {
			if responseErr, ok := err.(*ResponseError); ok && responseErr.Code == uint32(erref.STATUS_CANCELLED) {
				return nil, rr.ctx.Err()
			}
		}
		return res, err
	}

	// A response may have already arrived while the context was being
	// canceled: prefer the buffered response over the cancellation.
	select {
	case rp := <-rr.recv:
		return acceptResponse(rp)
	default:
	}

	select {
	case rp := <-rr.recv:
		return acceptResponse(rp)
	case <-rr.ctx.Done():
		rr.cancelOnce.Do(func() { go conn.sendCancel(rr) })
		if !rr.lockWait && !rr.waitFinal {
			rr.abort()
			return nil, rr.ctx.Err()
		}

		// CREATE groups also need their final responses to reclaim handles
		// when the server cannot cancel ([MS-SMB2] 3.3.5.16).
		// [MS-SMB2] 3.2.5.13 returns the result of a LOCK even after
		// CANCEL. Keep the request registered so a final success is not
		// hidden as a context error and its credits are charged once.
		return acceptResponse(<-rr.recv)
	}
}

func (conn *conn) sendCancel(rr *outstandingRequest) {
	req := &smb2.CancelRequest{}
	req.SetMessageId(rr.msgId)
	if asyncId := rr.asyncId.Load(); asyncId != 0 {
		req.SetFlags(smb2.SMB2_FLAGS_ASYNC_COMMAND)
		req.AsyncId = asyncId
	}

	conn.m.Lock()
	if conn.err != nil {
		conn.m.Unlock()
		return
	}

	s := conn.session
	if rr.requireEncryption && s == nil {
		conn.m.Unlock()
		return
	}
	if s != nil {
		req.SetSessionId(s.sessionId)
	}

	pkt := conn.allocEncodeBuf(req.Size())
	req.Encode(pkt)

	if rr.requireEncryption {
		// [MS-SMB2] 3.2.4.1.8 does not exempt CANCEL from required
		// encryption, so do not send a plaintext fallback on failure.
		encryptBuf := conn.allocEncryptBuf(52 + len(pkt) + 16)
		var err error
		pkt, err = s.encrypt(pkt, encryptBuf)
		if err != nil {
			conn.m.Unlock()
			return
		}
	} else if s != nil {
		if !s.signingDisabled() {
			s.sign(pkt)
		}
	}

	if err := conn.sendRaw(pkt); err != nil {
		conn.closeLocked(&TransportError{err})
		conn.m.Unlock()
		_ = conn.closeTransport()
		return
	}
	conn.m.Unlock()
}

func (conn *conn) runReceiver() {
	var err error
	if conn.receiverDone != nil {
		defer close(conn.receiverDone)
	}

	// A panic should shutdown the connection
	defer func() {
		if r := recover(); r != nil {
			err = &InvalidResponseError{fmt.Sprintf("receiver panic: %v", r)}
			conn.finishReceiver(err)
		}
	}()

	for {
		rp, e := receiveTransportPacket(conn.t, conn.responseReadSink)
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		hasSession := conn.useSession()

		var isEncrypted bool

		if hasSession {
			var errDecrypt error
			rp, isEncrypted, errDecrypt = conn.tryDecrypt(rp)
			if errDecrypt != nil {
				rp.close()
				err = errDecrypt
				goto exit
			}

			p := rp.codec()
			if s := conn.session; s != nil {
				if s.sessionId != p.SessionId() {
					rp.close()
					err = &InvalidResponseError{"unknown session id"}
					goto exit
				}
			}
		}

		p := rp.codec()

		// validate the packet if it doesn't have a session yet. tryDecrypt
		// already checks the packet validity when there is a session.
		if !hasSession && p.IsInvalid() {
			rp.close()
			err = &InvalidResponseError{"invalid packet header"}
			goto exit
		}

		for {
			// split must be called before tryHandle because tryHandle may
			// close rp.
			next := p.NextCommand()

			var sub *recvPacket
			if next != 0 {
				sub = rp.split(next)
				if sp := sub.codec(); sp.IsInvalid() {
					rp.close()
					sub.close()
					err = &InvalidResponseError{"invalid chained packet header"}
					goto exit
				}
			}

			responseErr := validateResponseDirection(p)
			if responseErr == nil && hasSession {
				responseErr = conn.tryVerify(rp, isEncrypted)
			}

			if e := conn.tryHandle(rp, responseErr); e != nil {
				logger.Println("skip:", e)
			}

			if sub == nil {
				break
			}

			rp = sub
			p = rp.codec()
		}
	}

exit:
	select {
	case <-conn.rdone:
		err = nil
	default:
		logger.Println("error:", err)
	}

	conn.finishReceiver(err)
}

// finishReceiver records the terminal connection error and wakes all request
// waiters before closing the transport. It never closes the transport while
// holding conn.m, because synchronous senders may hold that mutex while they
// are waiting for transport I/O to return.
func (conn *conn) finishReceiver(err error) {
	if err == nil {
		err = &TransportError{Err: net.ErrClosed}
	}
	conn.m.Lock()
	if conn.err != nil {
		err = conn.err
	} else {
		conn.err = err
	}
	if conn.account != nil {
		conn.account.abort(err)
	}
	conn.outstandingRequests.shutdown(err)
	conn.m.Unlock()
	_ = conn.closeTransport()
}

func (conn *conn) waitReceiver() {
	if conn != nil && conn.receiverDone != nil {
		<-conn.receiverDone
	}
}

// directReadSink inspects the packet head and returns the caller-owned
// buffer (and front-end header size) for a direct I/O READ response.
func (conn *conn) directReadSink(head []byte, restSize int) ([]byte, int) {
	p := smb2.PacketCodec(head)
	if p.IsInvalid() ||
		p.Command() != smb2.SMB2_READ ||
		p.NextCommand() != 0 ||
		erref.NtStatus(p.Status()) != erref.STATUS_SUCCESS {
		return nil, 0
	}

	r := smb2.ReadResponseDecoder(p.Body())
	if r.IsInvalidHeader() || r.HasInvalidFlags(conn.dialect) {
		return nil, 0
	}

	rr, ok := conn.outstandingRequests.peek(p.MessageId())
	if !ok || len(rr.readBuf) == 0 {
		return nil, 0
	}

	// [MS-SMB2] 2.2.20 defines DataOffset as one byte and DataLength as
	// four bytes; validate their relationship before converting DataLength
	// to int. The data must exactly fill the rest of the packet, be at least
	// one byte long, and fit in the caller's buffer.
	frontSize := int(r.DataOffset())
	dataLength := uint64(r.DataLength())
	pad := frontSize - 80
	if restSize < 0 || pad < 0 || uint64(pad)+dataLength != uint64(restSize) || dataLength == 0 || dataLength > uint64(len(rr.readBuf)) {
		return nil, 0
	}

	if rr.canceled.Load() || !rr.directState.CompareAndSwap(directStateIdle, directStateReading) {
		return nil, 0
	}
	return rr.readBuf[:int(dataLength)], frontSize
}

func (conn *conn) responseReadSink(head []byte, restSize int) ([]byte, int) {
	p := smb2.PacketCodec(head)
	if p.IsInvalid() || validateResponseDirection(p) != nil {
		return nil, 0
	}

	// SessionSetup publishes authentication state with enableSession after
	// final verification. Until then, avoid session state and direct sinks;
	// [MS-SMB2] 3.2.5.1.3 requires a session lookup before accepting a response.
	if !conn.useSession() {
		return nil, 0
	}
	s := conn.session
	if s == nil || s.sessionId != p.SessionId() {
		return nil, 0
	}

	// [MS-SMB2] 3.3.4.1.4 requires encrypted responses to encrypted requests.
	if rr, ok := conn.outstandingRequests.peek(p.MessageId()); ok && rr.requireEncryption {
		return nil, 0
	}

	if s != nil &&
		!s.signingDisabled() &&
		(conn.requireSigning || p.Flags()&smb2.SMB2_FLAGS_SIGNED != 0) {
		// [MS-SMB2] 3.2.5.1.3 requires failed signatures to be discarded.
		return nil, 0
	}

	return conn.directReadSink(head, restSize)
}

func accept(cmd smb2.Command, rp *recvPacket, dialect uint16) (res *recvPacket, err error) {
	defer func() {
		if res == nil {
			rp.close()
		}
	}()

	p := rp.codec()

	if command := p.Command(); cmd != command {
		return nil, &InvalidResponseError{fmt.Sprintf("expected command: %s, got %s", cmd.String(), command.String())}
	}

	status := erref.NtStatus(p.Status())

	switch status {
	case erref.STATUS_SUCCESS:
		if cmd == smb2.SMB2_READ {
			r := smb2.ReadResponseDecoder(p.Body())
			if r.HasInvalidFlags(dialect) {
				// [MS-SMB2] 3.2.5.11 requires STATUS_INVALID_NETWORK_RESPONSE
				// for RDMA_TRANSFORM on a non-RDMA SMB 3.1.1 READ response.
				return nil, invalidNetworkResponseError()
			}
		}

		// For a direct I/O response, the payload is already in the caller's
		// buffer and was validated during reception (see directReadSink),
		// so the generic data coverage check doesn't apply.
		if rp.ext == nil && cmd.IsInvalid(p.Body()) {
			return nil, &InvalidResponseError{fmt.Sprintf("broken %s response format", cmd.String())}
		}
		return rp, nil

	case erref.STATUS_MORE_PROCESSING_REQUIRED:
		if cmd == smb2.SMB2_SESSION_SETUP {
			return rp, nil
		}

	case erref.STATUS_BUFFER_OVERFLOW:
		switch cmd {
		case smb2.SMB2_QUERY_INFO:
			r := smb2.QueryInfoResponseDecoder(p.Body())
			if !r.IsInvalid() {
				return nil, &ResponseError{Code: uint32(status), data: [][]byte{append([]byte(nil), r.OutputBuffer()...)}}
			}
		case smb2.SMB2_IOCTL:
			r := smb2.IoctlResponseDecoder(p.Body())
			if !r.IsInvalid() {
				return nil, &ResponseError{Code: uint32(status), data: [][]byte{append([]byte(nil), r.Output()...)}}
			}
		case smb2.SMB2_READ:
			r := smb2.ReadResponseDecoder(p.Body())
			if !r.IsInvalid() {
				return nil, &ResponseError{Code: uint32(status), data: [][]byte{append([]byte(nil), r.Data()...)}}
			}
		}

	case erref.STATUS_NOTIFY_ENUM_DIR:
		if cmd == smb2.SMB2_CHANGE_NOTIFY {
			if cmd.IsInvalid(p.Body()) {
				return nil, &InvalidResponseError{"broken SMB2 CHANGE_NOTIFY response format"}
			}
			return rp, nil
		}
	}

	if cmd == smb2.SMB2_IOCTL {
		r := smb2.IoctlResponseDecoder(p.Body())
		if !r.IsInvalid() {
			switch r.CtlCode() {
			case smb2.FSCTL_SRV_COPYCHUNK, smb2.FSCTL_SRV_COPYCHUNK_WRITE:
				// [MS-SMB2] 3.3.5.15.6.1 returns copy failures as IOCTL
				// responses. Section 3.2.5.14.3 preserves their status;
				// accompanying results (or INVALID_PARAMETER limits) are
				// not transferred bytes. Section 2.2.32 defines boundaries.
				return nil, &ResponseError{Code: uint32(status)}
			}
		}
	}

	return nil, acceptError(uint32(status), p.Body(), dialect)
}

func invalidNetworkResponseError() *ResponseError {
	return &ResponseError{Code: uint32(erref.STATUS_INVALID_NETWORK_RESPONSE)}
}

func validateResponseDirection(p smb2.PacketCodec) error {
	// [MS-SMB2] 2.2.1.2 and 3.3.4.3 require SERVER_TO_REDIR on responses.
	if p.Flags()&smb2.SMB2_FLAGS_SERVER_TO_REDIR == 0 {
		return &InvalidResponseError{"response missing server-to-redir flag"}
	}
	return nil
}

func acceptError(status uint32, res []byte, dialect uint16) error {
	r := smb2.ErrorResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken error response format"}
	}

	eData := r.ErrorData()
	isSizeError := erref.NtStatus(status) == erref.STATUS_BUFFER_TOO_SMALL || erref.NtStatus(status) == erref.STATUS_INFO_LENGTH_MISMATCH

	if count := r.ErrorContextCount(); count != 0 {
		data := make([][]byte, count)
		var requiredBufferLength uint32

		for i := range data {
			ctx := smb2.ErrorContextResponseDecoder(eData)
			if ctx.IsInvalid() {
				return &InvalidResponseError{"broken error context response format"}
			}

			contextData := ctx.ErrorContextData()
			data[i] = append([]byte(nil), contextData...)
			// [MS-SMB2] 2.2.2.2 / 3.2.5.17 carry the four-byte required length
			// in the SMB 3.1.1 Error Context (ErrorId 0).
			if isSizeError && r.ByteCount() == 12 && len(data) == 1 && i == 0 && ctx.ErrorId() == smb2.SMB2_ERROR_ID_DEFAULT && len(contextData) == 4 && dialect == smb2.SMB311 {
				requiredBufferLength = binary.LittleEndian.Uint32(contextData)
			}

			// the last error context need not be padded to the 8-byte boundary (MS-SMB2 2.2.2)
			if i == len(data)-1 {
				break
			}

			next64 := uint64(8) + (uint64(ctx.ErrorDataLength())+7)&^uint64(7)
			if next64 > uint64(len(eData)) {
				return &InvalidResponseError{"broken error context response format"}
			}
			next := int(next64)
			eData = eData[next:]
		}
		return &ResponseError{
			Code:                 status,
			data:                 data,
			requiredBufferLength: requiredBufferLength,
		}
	}
	data := append([]byte(nil), eData...)
	err := &ResponseError{Code: status, data: [][]byte{data}}
	// Before SMB 3.1.1, [MS-SMB2] 2.2.2.2 / 3.2.5.17 carry the required length
	// as four bytes of the SMB2 ERROR response data.
	if isSizeError && len(data) == 4 && dialect != smb2.SMB311 {
		err.requiredBufferLength = binary.LittleEndian.Uint32(data)
	}
	return err
}

func (conn *conn) tryDecrypt(rp *recvPacket) (*recvPacket, bool, error) {
	p := rp.codec()
	if p.IsInvalid() {
		if len(rp.pkt) >= 4 && bytes.Equal(rp.pkt[:4], []byte(smb2.MAGIC3)) {
			pkt, ext, err := decompressPacketForReceive(conn, rp.bytes(), conn.responseReadSink)
			if err != nil {
				return rp, false, err
			}
			rp.pkt = pkt
			rp.ext = ext
			return rp, false, nil
		}

		t := rp.transformCodec()
		if t.IsInvalid() {
			return rp, false, &InvalidResponseError{"broken packet header format"}
		}

		if t.Flags() != smb2.Encrypted {
			return rp, false, &InvalidResponseError{"encrypted flag is not on"}
		}

		if conn.session == nil || conn.session.sessionId != t.SessionId() {
			return rp, false, &InvalidResponseError{"unknown session id returned"}
		}

		pkt, err := conn.session.decrypt(rp.bytes())
		if err != nil {
			return rp, false, &InvalidResponseError{err.Error()}
		}

		if len(pkt) >= 4 && bytes.Equal(pkt[:4], []byte(smb2.MAGIC3)) {
			var ext []byte
			// Keep encrypted compressed data in receive-owned storage until the
			// inner session and direction checks succeed ([MS-SMB2] 3.2.5.1.1.1).
			pkt, ext, err = decompressPacketForReceive(conn, pkt, nil)
			if err != nil {
				return rp, true, err
			}
			rp.ext = ext
		}

		if smb2.PacketCodec(pkt).IsInvalid() {
			return rp, false, &InvalidResponseError{"broken decrypted packet format"}
		}

		rp.pkt = pkt
		// [MS-SMB2] 3.2.5.1.1.1 requires disconnecting on a SessionId
		// mismatch after decompression and recommends it for uncompressed
		// compounds. Validate every element before delivering any response.
		if err := validateEncryptedResponseSessionIDs(pkt, t.SessionId()); err != nil {
			return rp, true, err
		}
		if err := validateResponseDirections(pkt); err != nil {
			return rp, true, err
		}
		conn.copyDecryptedReadPayload(rp)
		return rp, true, nil
	}

	return rp, false, nil
}

func validateResponseDirections(pkt []byte) error {
	for {
		p := smb2.PacketCodec(pkt)
		if p.IsInvalid() {
			return &InvalidResponseError{"broken response packet format"}
		}
		if err := validateResponseDirection(p); err != nil {
			return err
		}
		if p.NextCommand() == 0 {
			return nil
		}
		pkt = pkt[p.NextCommand():]
	}
}

func validateEncryptedResponseSessionIDs(pkt []byte, sessionID uint64) error {
	for {
		p := smb2.PacketCodec(pkt)
		if p.IsInvalid() {
			return &InvalidResponseError{"broken decrypted packet format"}
		}
		if p.SessionId() != sessionID {
			return &InvalidResponseError{"unknown session id in encrypted response"}
		}
		if p.NextCommand() == 0 {
			return nil
		}
		pkt = pkt[p.NextCommand():]
	}
}

// copyDecryptedReadPayload completes the direct I/O path for encrypted READ
// responses. The transform is authenticated as one contiguous message, so
// the AEAD must first produce the decrypted SMB2 packet. Once it does, copy
// only the READ payload into the caller's registered buffer and expose it as
// the response's direct segment.
func (conn *conn) copyDecryptedReadPayload(rp *recvPacket) {
	if rp.ext != nil {
		return
	}
	p := rp.codec()
	if p.SessionId() != conn.session.sessionId ||
		p.Command() != smb2.SMB2_READ || p.NextCommand() != 0 ||
		erref.NtStatus(p.Status()) != erref.STATUS_SUCCESS {
		return
	}

	rr, ok := conn.outstandingRequests.peek(p.MessageId())
	if !ok || len(rr.readBuf) == 0 {
		return
	}

	r := smb2.ReadResponseDecoder(p.Body())
	if r.IsInvalid() || r.HasInvalidFlags(conn.dialect) || r.DataLength() == 0 || int(r.DataLength()) > len(rr.readBuf) {
		return
	}

	if rr.canceled.Load() || !rr.directState.CompareAndSwap(directStateIdle, directStateReading) {
		return
	}
	copy(rr.readBuf, r.Data())
	rp.ext = rr.readBuf[:r.DataLength()]
	// Publish completion only after the caller's buffer is safe to reuse,
	// preserving cancellation if it arrived during the copy.
	rr.directState.CompareAndSwap(directStateReading, directStateDone)
}

func (conn *conn) tryVerify(rp *recvPacket, isEncrypted bool) error {
	p := rp.codec()
	if err := validateResponseDirection(p); err != nil {
		return err
	}

	msgID := p.MessageId()

	if rr, ok := conn.outstandingRequests.peek(msgID); ok && rr.requireEncryption && !isEncrypted {
		// [MS-SMB2] 3.3.4.1.4 requires encryption for every response to an
		// encrypted request, including interim asynchronous responses.
		return &InvalidResponseError{"encrypted response required"}
	}

	// MS-SMB2 3.2.5.1.3 states that the client MUST skip signature processing if:
	// - MessageId is 0xFFFFFFFFFFFFFFFF
	// - Status in the SMB2 header is STATUS_PENDING
	// 		- 3.3.4.1.1 says servers should skip signing interim responses to async requests - STATUS_PENDING is an interim response
	// - Client is using the SMB 3.x dialect and the message was successfully decrypted+authenticated (isEncrypted=true)
	if msgID == 0xFFFFFFFFFFFFFFFF {
		return nil
	}
	if erref.NtStatus(p.Status()) == erref.STATUS_PENDING {
		return nil
	}
	if isEncrypted {
		return nil
	}

	s := conn.session
	if s == nil {
		return &InvalidResponseError{"packet received before session established"}
	}
	if s.sessionId != p.SessionId() {
		return &InvalidResponseError{"packet for unknown session"}
	}

	// guest and anonymous sessions can't produce signatures, so they don't need to be verified
	if s.signingDisabled() {
		return nil
	}

	// verify if 1) the connection requires signing or 2) if the message itself is signed
	if conn.requireSigning || p.Flags()&smb2.SMB2_FLAGS_SIGNED != 0 {
		if !s.verify(rp.pkt, rp.ext) {
			return &InvalidResponseError{"packet failed signature verification"}
		}
		return nil
	}

	// the message was not signed AND signing is not required
	return nil
}

func (conn *conn) tryHandle(rp *recvPacket, e error) error {
	p := rp.codec()
	if e == nil {
		e = validateResponseDirection(p)
	}

	msgId := p.MessageId()

	rr, ok := conn.outstandingRequests.pop(msgId)
	switch {
	case !ok:
		// [MS-SMB2] 3.2.5.1.2 requires responses without a matching
		// OutstandingRequests entry to be discarded as invalid.
		rp.close()
		if e != nil {
			return e
		}
		return &InvalidResponseError{"unknown message id returned"}
	case e != nil:
		// [MS-SMB2] 3.2.5.1.3 requires a response with a failed signature
		// verification to be discarded. Unloan the request's credit charge
		// without granting the unauthenticated CreditResponse.
		conn.account.unloan(rr.creditCharge)
		rr.finishDirect()
		rp.close()
		rr.err = e

		if !rr.canceled.Load() {
			close(rr.recv)
		}
		return e
	case erref.NtStatus(p.Status()) == erref.STATUS_PENDING:
		conn.account.charge(p.CreditResponse(), 0)
		// p aliases the receive buffer, which rp.close returns to the pool,
		// so every header field must be read while the buffer is still
		// owned. [MS-SMB2] 3.3.4.2 requires an async interim response to set
		// SMB2_FLAGS_ASYNC_COMMAND with a nonzero AsyncId that stays valid
		// until the final response. Only such a response carries an async
		// id; for a synchronous pending response the field actually holds the
		// tree id and must not be adopted.
		if p.Flags()&smb2.SMB2_FLAGS_ASYNC_COMMAND != 0 {
			rr.asyncId.Store(p.AsyncId())
		}
		rp.close()
		conn.outstandingRequests.set(msgId, rr)
	default:
		conn.account.charge(p.CreditResponse(), rr.creditCharge)

		rr.finishDirect()

		if rr.canceled.Load() {
			rp.close()
			return nil
		}

		rr.recv <- rp

		// rr.ctx may have been canceled between the canceled check and the
		// send above. Drain the response back, otherwise nobody will close
		// it and its buffer leaks.
		if rr.canceled.Load() {
			select {
			case rp := <-rr.recv:
				if rp != nil {
					rp.close()
				}
			default:
			}
		}
	}

	return nil
}
