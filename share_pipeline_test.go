package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const pipelineChunk = 64 << 10

type pipelineRequest struct {
	packet []byte
	cmd    wire.Command
	msgID  uint64
	off    uint64
	length uint32
}

func setupPipelineFile(t testing.TB, credits uint16, options ...testServerOptions) (*File, net.Conn) {
	t.Helper()
	opts := testServerOptions{
		credits:         credits,
		maxReadSize:     pipelineChunk,
		maxWriteSize:    pipelineChunk,
		maxTransactSize: pipelineChunk,
	}
	if len(options) != 0 {
		opts.ioPipelineDepth = options[0].ioPipelineDepth
		opts.wrapClient = options[0].wrapClient
	}
	f, peer := newTestFile(t, opts)
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return f, peer
}

func collectPipelineRequest(t *testing.T, dt net.Conn) pipelineRequest {
	t.Helper()
	packet, err := readMsg(dt)
	if err != nil {
		t.Fatal(err)
	}
	p := wire.PacketCodec(packet)
	r := pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId()}
	switch r.cmd {
	case wire.SMB2_READ:
		req := wire.ReadRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	case wire.SMB2_WRITE:
		req := wire.WriteRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	}
	return r
}

func sendPipelineResponse(t net.Conn, req pipelineRequest, res wire.Packet, status erref.NtStatus) error {
	buf := pipelineResponseBytes(req, res, status)
	_, err := testWritePacket(t, buf)
	return err
}

func pipelineResponseBytes(req pipelineRequest, res wire.Packet, status erref.NtStatus) []byte {
	buf := make([]byte, res.Size())
	res.Encode(buf)
	p := wire.PacketCodec(req.packet)
	r := wire.PacketCodec(buf)
	r.SetMessageId(req.msgID)
	r.SetSessionId(p.SessionId())
	r.SetTreeId(p.TreeId())
	r.SetStatus(uint32(status))
	r.SetCreditResponse(1)
	r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	return buf
}

func pipelineReadData(off uint64, n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(off/pipelineChunk + 1)
	}
	return data
}

func pipelineReadResponse(t net.Conn, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &wire.ReadResponse{Data: pipelineReadData(req.off, n)}, erref.STATUS_SUCCESS)
}

func pipelineWriteResponse(t net.Conn, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &wire.WriteResponse{Count: uint32(n)}, erref.STATUS_SUCCESS)
}

func waitPipelineResult[T any](t *testing.T, ch <-chan pipelineResult[T]) pipelineResult[T] {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline operation timed out")
		return pipelineResult[T]{}
	}
}

type pipelineResult[T any] struct {
	n   int
	err error
	val T
}

func TestIOPipelineReadCollectsAndReorders(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := peer
	buf := bytes.Repeat([]byte{0xa5}, 4*pipelineChunk)
	const baseOffset = int64(7*pipelineChunk + 13)
	done := make(chan pipelineResult[[]byte], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, baseOffset)
		done <- pipelineResult[[]byte]{n: n, err: err, val: buf}
	}()

	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
		if reqs[i].cmd != wire.SMB2_READ || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
			t.Fatalf("request %d = command %v offset %d length %d", i, reqs[i].cmd, reqs[i].off, reqs[i].length)
		}
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		if err := pipelineReadResponse(dt, reqs[i], pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
	for i := 0; i < len(buf); i += pipelineChunk {
		if !bytes.Equal(buf[i:i+pipelineChunk], pipelineReadData(uint64(baseOffset+int64(i)), pipelineChunk)) {
			t.Fatalf("read chunk at offset %d has wrong data", i)
		}
	}
}

func TestIOPipelineWriteCollectsAndReorders(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := peer
	data := make([]byte, 4*pipelineChunk)
	const baseOffset = int64(9*pipelineChunk + 29)
	for i := range data {
		data[i] = byte(i/pipelineChunk + 1)
	}
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.WriteAt(context.Background(), data, baseOffset)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()

	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
		if reqs[i].cmd != wire.SMB2_WRITE || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
			t.Fatalf("request %d = command %v offset %d length %d", i, reqs[i].cmd, reqs[i].off, reqs[i].length)
		}
		body := wire.WriteRequestDecoder(wire.PacketCodec(reqs[i].packet).Body())
		start, end := int(body.DataOffset()), int(body.DataOffset())+int(body.Length())
		if !bytes.Equal(reqs[i].packet[start:end], data[i*pipelineChunk:(i+1)*pipelineChunk]) {
			t.Fatalf("write request %d has wrong payload", i)
		}
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		if err := pipelineWriteResponse(dt, reqs[i], pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(data) {
		t.Fatalf("WriteAt = (%d, %v), want (%d, nil)", result.n, result.err, len(data))
	}
}

func TestIOPipelineMakesProgressWithOneCredit(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 1)
	dt := peer
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	if first.off != 0 || first.length != pipelineChunk {
		t.Fatalf("first request = offset %d length %d", first.off, first.length)
	}
	if err := pipelineReadResponse(dt, first, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	second := collectPipelineRequest(t, dt)
	if second.off != pipelineChunk || second.length != pipelineChunk {
		t.Fatalf("second request = offset %d length %d", second.off, second.length)
	}
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineKeepsBoundedWindow(t *testing.T) {
	t.Parallel()
	for _, depth := range []uint{0, 1, 2, 6} {
		for _, write := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth=%d/write=%t", depth, write), func(t *testing.T) {
				testIOPipelineWindow(t, depth, write)
			})
		}
	}
}

func testIOPipelineWindow(t *testing.T, depth uint, write bool) {
	f, peer := setupPipelineFile(t, 8, testServerOptions{ioPipelineDepth: depth})
	if depth == 0 {
		depth = 4
	}
	dt := peer
	respond := pipelineReadResponse
	if write {
		respond = pipelineWriteResponse
	}
	buf := make([]byte, 8*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		var n int
		var err error
		if write {
			n, err = f.WriteAt(context.Background(), buf, 0)
		} else {
			n, err = f.ReadAt(context.Background(), buf, 0)
		}
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	requests := make([]pipelineRequest, depth)
	for i := range requests {
		requests[i] = collectPipelineRequest(t, dt)
	}

	// A further request must wait until a response releases a pipeline slot.
	next := make(chan struct {
		req pipelineRequest
		err error
	}, 1)
	go func() {
		packet, err := readMsg(dt)
		if err != nil {
			next <- struct {
				req pipelineRequest
				err error
			}{err: err}
			return
		}
		p := wire.PacketCodec(packet)
		r := wire.ReadRequestDecoder(p.Body())
		offset, length := r.Offset(), r.Length()
		if write {
			w := wire.WriteRequestDecoder(p.Body())
			offset, length = w.Offset(), w.Length()
		}
		next <- struct {
			req pipelineRequest
			err error
		}{req: pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId(), off: offset, length: length}}
	}()
	select {
	case got := <-next:
		t.Fatalf("received next request before any response: req=%+v err=%v", got.req, got.err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := respond(dt, requests[0], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	var nextRequest pipelineRequest
	select {
	case got := <-next:
		if got.err != nil {
			t.Fatal(got.err)
		}
		nextRequest = got.req
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not send a request after a slot was released")
	}
	if nextRequest.off != uint64(depth*pipelineChunk) || nextRequest.length != pipelineChunk {
		t.Fatalf("next request = offset %d length %d", nextRequest.off, nextRequest.length)
	}
	requests = append(requests, nextRequest)
	for _, req := range requests[1:] {
		if err := respond(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	for len(requests) < 8 {
		req := collectPipelineRequest(t, dt)
		requests = append(requests, req)
		if err := respond(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func executePipelineEcho(f *File, ctx context.Context) error {
	res, err := f.fs.Request().Append(&wire.EchoRequest{}).Do(ctx)
	if res != nil {
		res.Close()
	}
	return err
}

// The test supplies the fixed READ header separately. A socket read into the
// entire chunk therefore starts only after the transport selects the direct
// destination; observing the header alone would race that selection.
type directReadSignalConn struct {
	net.Conn
	ready chan<- struct{}
	once  sync.Once
}

func (c *directReadSignalConn) Read(p []byte) (int, error) {
	if len(p) == pipelineChunk {
		c.once.Do(func() { close(c.ready) })
	}
	return c.Conn.Read(p)
}

func TestIOPipelineReadErrorReportsContiguousPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := peer
	buf := make([]byte, 4*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
	}
	if err := pipelineReadResponse(dt, reqs[3], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := sendPipelineResponse(dt, reqs[2], &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_ACCESS_DENIED); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, reqs[1], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, reqs[0], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != 2*pipelineChunk || !errors.Is(result.err, erref.STATUS_ACCESS_DENIED) {
		t.Fatalf("ReadAt = (%d, %v), want contiguous prefix %d and access denied", result.n, result.err, 2*pipelineChunk)
	}
}

func TestIOPipelineReadRefillsShortResponse(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := peer
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	short := pipelineChunk / 2
	if err := pipelineReadResponse(dt, first, short); err != nil {
		t.Fatal(err)
	}
	refill := collectPipelineRequest(t, dt)
	if refill.off != uint64(short) || refill.length != uint32(pipelineChunk-short) {
		t.Fatalf("refill request = offset %d length %d", refill.off, refill.length)
	}
	if err := pipelineReadResponse(dt, refill, pipelineChunk-short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadRefillsBufferOverflow(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := peer
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	short := pipelineChunk / 2
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := sendPipelineResponse(dt, first, &wire.ReadResponse{Data: pipelineReadData(0, short)}, erref.STATUS_BUFFER_OVERFLOW); err != nil {
		t.Fatal(err)
	}
	refill := collectPipelineRequest(t, dt)
	if refill.off != uint64(short) || refill.length != uint32(pipelineChunk-short) {
		t.Fatalf("overflow refill request = offset %d length %d", refill.off, refill.length)
	}
	if err := pipelineReadResponse(dt, refill, pipelineChunk-short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadEOFReportsPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := peer
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := sendPipelineResponse(dt, second, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_END_OF_FILE); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, first, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != pipelineChunk || !errors.Is(result.err, io.EOF) {
		t.Fatalf("ReadAt = (%d, %v), want EOF after %d bytes", result.n, result.err, pipelineChunk)
	}
}

func TestIOPipelineWriteShortWriteReportsPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := peer
	data := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.WriteAt(context.Background(), data, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := pipelineWriteResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	short := pipelineChunk / 2
	if err := pipelineWriteResponse(dt, first, short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != short || !errors.Is(result.err, io.ErrShortWrite) {
		t.Fatalf("WriteAt = (%d, %v), want short write after %d bytes", result.n, result.err, short)
	}
}

func TestIOPipelineCancellationDrainsDirectReads(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := peer
	buf := bytes.Repeat([]byte{0xa5}, 4*pipelineChunk)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(ctx, buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reads := make([]pipelineRequest, 4)
	for i := range reads {
		reads[i] = collectPipelineRequest(t, dt)
	}
	cancel()
	wantCancel := make(map[uint64]bool, len(reads))
	for _, req := range reads {
		wantCancel[req.msgID] = true
	}
	for i := range reads {
		cancelReq := collectPipelineRequest(t, dt)
		if cancelReq.cmd != wire.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
			t.Fatalf("cancel %d = command %v message %d", i, cancelReq.cmd, cancelReq.msgID)
		}
		delete(wantCancel, cancelReq.msgID)
	}
	result := waitPipelineResult(t, done)
	if !errors.Is(result.err, context.Canceled) || result.n != 0 {
		t.Fatalf("ReadAt = (%d, %v), want cancellation", result.n, result.err)
	}
	// Replies are deliberately late relative to cancellation and operation
	// return. They must be drained without copying into the caller's buffer.
	for _, req := range reads {
		if err := pipelineReadResponse(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}

	echoDone := make(chan error, 1)
	go func() { echoDone <- executePipelineEcho(f, context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != wire.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &wire.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ECHO did not complete after canceled reads")
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatal("late direct READ response altered returned buffer")
	}
}

func TestIOPipelineCancellationWaitsForInFlightDirectRead(t *testing.T) {
	t.Parallel()
	directReadReady := make(chan struct{})
	f, peer := setupPipelineFile(t, 2, testServerOptions{
		wrapClient: func(conn net.Conn) net.Conn {
			return &directReadSignalConn{Conn: conn, ready: directReadReady}
		},
	})
	dt := peer
	buf := bytes.Repeat([]byte{0xa5}, 2*pipelineChunk)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(ctx, buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reads := []pipelineRequest{collectPipelineRequest(t, dt), collectPipelineRequest(t, dt)}

	// Feed only the response header and fixed READ body first. The transport
	// has selected the caller's direct buffer and is blocked while receiving
	// the payload when cancellation starts.
	response := pipelineResponseBytes(reads[0], &wire.ReadResponse{Data: pipelineReadData(0, pipelineChunk)}, erref.STATUS_SUCCESS)
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(response)))
	copy(frame[4:], response)
	if _, err := peer.Write(frame[:4+80]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-directReadReady:
	case <-time.After(5 * time.Second):
		t.Fatal("direct READ reception did not become in-flight")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("operation returned before in-flight direct reception completed")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := peer.Write(frame[4+80:]); err != nil {
		t.Fatal(err)
	}

	wantCancel := map[uint64]bool{reads[0].msgID: true, reads[1].msgID: true}
	for range reads {
		cancelReq := collectPipelineRequest(t, dt)
		if cancelReq.cmd != wire.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
			t.Fatalf("unexpected cancellation request: command %v message %d", cancelReq.cmd, cancelReq.msgID)
		}
		delete(wantCancel, cancelReq.msgID)
	}
	result := waitPipelineResult(t, done)
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("ReadAt error = %v, want context cancellation", result.err)
	}

	// Reinitialize the returned buffer and send the other late response. A
	// response still in flight must not write into caller memory after return.
	for i := range buf {
		buf[i] = 0xa5
	}
	if err := pipelineReadResponse(dt, reads[1], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan error, 1)
	go func() { echoDone <- executePipelineEcho(f, context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != wire.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &wire.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ECHO did not complete after canceled reads")
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatal("late direct READ response altered returned buffer")
	}
}

type pipelineBenchResponse struct {
	packet  []byte
	readyAt time.Time
}

func startPipelineBenchServer(peer net.Conn, latency time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := peer
		responses := make(chan pipelineBenchResponse, 32)
		var writers sync.WaitGroup
		writers.Add(1)
		go func() {
			defer writers.Done()
			for response := range responses {
				if wait := time.Until(response.readyAt); wait > 0 {
					time.Sleep(wait)
				}
				if _, err := testWritePacket(dt, response.packet); err != nil {
					return
				}
			}
		}()
		for {
			packet, err := readMsg(dt)
			if err != nil {
				close(responses)
				writers.Wait()
				return
			}
			p := wire.PacketCodec(packet)
			var response wire.Packet
			switch p.Command() {
			case wire.SMB2_READ:
				req := wire.ReadRequestDecoder(p.Body())
				response = &wire.ReadResponse{Data: pipelineReadData(req.Offset(), int(req.Length()))}
			case wire.SMB2_WRITE:
				req := wire.WriteRequestDecoder(p.Body())
				response = &wire.WriteResponse{Count: req.Length()}
			default:
				continue
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			r := wire.PacketCodec(buf)
			r.SetMessageId(p.MessageId())
			r.SetSessionId(p.SessionId())
			r.SetTreeId(p.TreeId())
			r.SetCreditResponse(1)
			r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			responses <- pipelineBenchResponse{packet: buf, readyAt: time.Now().Add(latency)}
		}
	}()
	return done
}

func BenchmarkIOPipeline(b *testing.B) {
	for _, latency := range []struct {
		name  string
		delay time.Duration
	}{
		{name: "0ms", delay: 0},
		{name: "2ms", delay: 2 * time.Millisecond},
	} {
		for _, op := range []string{"Read", "Write"} {
			for _, mode := range []string{"Sequential", "Pipelined"} {
				b.Run(latency.name+"/"+op+"/"+mode, func(b *testing.B) {
					f, peer := newTestFile(b, testServerOptions{
						credits:         16,
						maxReadSize:     pipelineChunk,
						maxWriteSize:    pipelineChunk,
						maxTransactSize: pipelineChunk,
					})
					serverDone := startPipelineBenchServer(peer, latency.delay)
					defer func() {
						_ = peer.Close()
						<-serverDone
					}()
					buf := make([]byte, 16*pipelineChunk)
					b.SetBytes(int64(len(buf)))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						var n int
						var err error
						if op == "Read" {
							if mode == "Sequential" {
								for n < len(buf) {
									var nn int
									nn, err = f.fs.readAtChunk(context.Background(), f.fd, buf[n:], int64(n))
									n += nn
									if err != nil {
										break
									}
								}
							} else {
								n, err = f.fs.readAt(context.Background(), f.fd, buf, 0)
							}
						} else if mode == "Sequential" {
							for n < len(buf) {
								var nn int
								nn, err = f.fs.writeAtChunk(context.Background(), f.fd, buf[n:], int64(n))
								n += nn
								if err != nil {
									break
								}
							}
						} else {
							n, err = f.fs.writeAt(context.Background(), f.fd, buf, 0)
						}
						if err != nil || n != len(buf) {
							b.Fatalf("%s %s = (%d, %v), want (%d, nil)", op, mode, n, err, len(buf))
						}
					}
				})
			}
		}
	}
}
