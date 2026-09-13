package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

const pipelineChunk = 64 << 10

type pipelineRequest struct {
	packet []byte
	cmd    smb2.Command
	msgID  uint64
	off    uint64
	length uint32
}

func setupPipelineFile(t *testing.T, credits uint16) (*File, net.Conn) {
	t.Helper()
	f, peer := newTestFile(t)
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c := f.fs.conn
	c.maxReadSize = pipelineChunk
	c.maxWriteSize = pipelineChunk
	f.fs.treeConn.shareType = smb2.SMB2_SHARE_TYPE_DISK
	c.account.m.Lock()
	c.account.availableCredits = credits
	c.account.inFlightCredits = 0
	c.account.maxCredits = credits
	c.account.maxCreditBalance = credits
	c.account.m.Unlock()
	return f, peer
}

func collectPipelineRequest(t *testing.T, dt transport) pipelineRequest {
	t.Helper()
	packet, err := readMsg(dt)
	if err != nil {
		t.Fatal(err)
	}
	p := smb2.PacketCodec(packet)
	r := pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId()}
	switch r.cmd {
	case smb2.SMB2_READ:
		req := smb2.ReadRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	case smb2.SMB2_WRITE:
		req := smb2.WriteRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	}
	return r
}

func sendPipelineResponse(t transport, req pipelineRequest, res smb2.Packet, status erref.NtStatus) error {
	buf := pipelineResponseBytes(req, res, status)
	_, err := t.Writev(buf)
	return err
}

func pipelineResponseBytes(req pipelineRequest, res smb2.Packet, status erref.NtStatus) []byte {
	buf := make([]byte, res.Size())
	res.Encode(buf)
	p := smb2.PacketCodec(req.packet)
	r := smb2.PacketCodec(buf)
	r.SetMessageId(req.msgID)
	r.SetSessionId(p.SessionId())
	r.SetTreeId(p.TreeId())
	r.SetStatus(uint32(status))
	r.SetCreditResponse(1)
	r.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	return buf
}

func pipelineReadData(off uint64, n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(off/pipelineChunk + 1)
	}
	return data
}

func pipelineReadResponse(t transport, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &smb2.ReadResponse{Data: pipelineReadData(req.off, n)}, erref.STATUS_SUCCESS)
}

func pipelineWriteResponse(t transport, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &smb2.WriteResponse{Count: uint32(n)}, erref.STATUS_SUCCESS)
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
	f, peer := setupPipelineFile(t, 4)
	dt := direct(peer)
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
		if reqs[i].cmd != smb2.SMB2_READ || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
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
	f, peer := setupPipelineFile(t, 4)
	dt := direct(peer)
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
		if reqs[i].cmd != smb2.SMB2_WRITE || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
			t.Fatalf("request %d = command %v offset %d length %d", i, reqs[i].cmd, reqs[i].off, reqs[i].length)
		}
		body := smb2.WriteRequestDecoder(smb2.PacketCodec(reqs[i].packet).Body())
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
	f, peer := setupPipelineFile(t, 1)
	dt := direct(peer)
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
	f, peer := setupPipelineFile(t, 8)
	dt := direct(peer)
	buf := make([]byte, 8*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	requests := make([]pipelineRequest, 4)
	for i := range requests {
		requests[i] = collectPipelineRequest(t, dt)
	}

	// Keep a reader pending so a fifth request would be observed. The sender
	// must wait for a response to release one of the four pipeline slots.
	fifth := make(chan struct {
		req pipelineRequest
		err error
	}, 1)
	go func() {
		packet, err := readMsg(dt)
		if err != nil {
			fifth <- struct {
				req pipelineRequest
				err error
			}{err: err}
			return
		}
		p := smb2.PacketCodec(packet)
		r := smb2.ReadRequestDecoder(p.Body())
		fifth <- struct {
			req pipelineRequest
			err error
		}{req: pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId(), off: r.Offset(), length: r.Length()}}
	}()
	select {
	case got := <-fifth:
		t.Fatalf("received fifth request before any response: req=%+v err=%v", got.req, got.err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := pipelineReadResponse(dt, requests[0], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	var fifthRequest pipelineRequest
	select {
	case got := <-fifth:
		if got.err != nil {
			t.Fatal(got.err)
		}
		fifthRequest = got.req
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not send a request after a slot was released")
	}
	if fifthRequest.off != uint64(4*pipelineChunk) || fifthRequest.length != pipelineChunk {
		t.Fatalf("fifth request = offset %d length %d", fifthRequest.off, fifthRequest.length)
	}
	requests = append(requests, fifthRequest)
	for _, req := range requests[1:4] {
		if err := pipelineReadResponse(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	for len(requests) < 8 {
		requests = append(requests, collectPipelineRequest(t, dt))
	}
	for _, req := range requests[4:] {
		if err := pipelineReadResponse(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadErrorReportsContiguousPrefix(t *testing.T) {
	f, peer := setupPipelineFile(t, 4)
	dt := direct(peer)
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
	if err := sendPipelineResponse(dt, reqs[2], &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, erref.STATUS_ACCESS_DENIED); err != nil {
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
	f, peer := setupPipelineFile(t, 2)
	dt := direct(peer)
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
	f, peer := setupPipelineFile(t, 2)
	dt := direct(peer)
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
	if err := sendPipelineResponse(dt, first, &smb2.ReadResponse{Data: pipelineReadData(0, short)}, erref.STATUS_BUFFER_OVERFLOW); err != nil {
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
	f, peer := setupPipelineFile(t, 2)
	dt := direct(peer)
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := sendPipelineResponse(dt, second, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, erref.STATUS_END_OF_FILE); err != nil {
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
	f, peer := setupPipelineFile(t, 2)
	dt := direct(peer)
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
	f, peer := setupPipelineFile(t, 4)
	dt := direct(peer)
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
		if cancelReq.cmd != smb2.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
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
	go func() { echoDone <- f.fs.session.echo(context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != smb2.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &smb2.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
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
	f, peer := setupPipelineFile(t, 2)
	dt := direct(peer)
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
	response := pipelineResponseBytes(reads[0], &smb2.ReadResponse{Data: pipelineReadData(0, pipelineChunk)}, erref.STATUS_SUCCESS)
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(response)))
	copy(frame[4:], response)
	if _, err := peer.Write(frame[:4+80]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr, ok := f.fs.conn.outstandingRequests.peek(reads[0].msgID)
		if ok && rr.directState.Load() == directStateReading {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("direct READ reception did not become in-flight")
		}
		time.Sleep(time.Millisecond)
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
		if cancelReq.cmd != smb2.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
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
	go func() { echoDone <- f.fs.session.echo(context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != smb2.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &smb2.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
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
		dt := direct(peer)
		responses := make(chan pipelineBenchResponse, 32)
		var writers sync.WaitGroup
		writers.Add(1)
		go func() {
			defer writers.Done()
			for response := range responses {
				if wait := time.Until(response.readyAt); wait > 0 {
					time.Sleep(wait)
				}
				if _, err := dt.Writev(response.packet); err != nil {
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
			p := smb2.PacketCodec(packet)
			var response smb2.Packet
			switch p.Command() {
			case smb2.SMB2_READ:
				req := smb2.ReadRequestDecoder(p.Body())
				response = &smb2.ReadResponse{Data: pipelineReadData(req.Offset(), int(req.Length()))}
			case smb2.SMB2_WRITE:
				req := smb2.WriteRequestDecoder(p.Body())
				response = &smb2.WriteResponse{Count: req.Length()}
			default:
				continue
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			r := smb2.PacketCodec(buf)
			r.SetMessageId(p.MessageId())
			r.SetSessionId(p.SessionId())
			r.SetTreeId(p.TreeId())
			r.SetCreditResponse(1)
			r.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
					client, peer := net.Pipe()
					c, cleanup := newBenchConn(client)
					defer cleanup()
					defer peer.Close()
					c.session = &session{conn: c, sessionId: 0x100}
					c.enableSession()
					c.maxReadSize = pipelineChunk
					c.maxWriteSize = pipelineChunk
					c.account.m.Lock()
					c.account.availableCredits = 16
					c.account.inFlightCredits = 0
					c.account.maxCredits = 16
					c.account.maxCreditBalance = 16
					c.account.m.Unlock()
					f := newBenchFile(c)
					f.fs.treeConn.shareType = smb2.SMB2_SHARE_TYPE_DISK
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
