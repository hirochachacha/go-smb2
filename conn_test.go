package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/pierrec/lz4/v4"
	"github.com/stretchr/testify/require"
)

func readMsg(t transport) ([]byte, error) {
	rp, err := t.ReadPacket()
	if err != nil {
		return nil, err
	}
	defer rp.close()
	return append([]byte(nil), rp.bytes()...), nil
}

func TestSessionRecv(t *testing.T) {
	require := require.New(t)

	// helper sends one request through c and returns the result of s.recv.
	roundTrip := func(t *testing.T, c *conn, s *session) error {
		t.Helper()
		req := smb2.ReadRequest{Length: 1}
		rrs, err := c.send(context.Background(), false, &req)
		require.NoError(err)
		rr := rrs[0]
		_, err = s.recv(rr)
		return err
	}

	t.Run("AdoptsSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const serverSessionId uint64 = 0x1234
		go fakeServer(direct(serverConn), []byte{1}, serverSessionId)

		s := &session{conn: c, sessionId: 0}

		require.NoError(roundTrip(t, c, s))
		require.Equal(serverSessionId, s.sessionId)
	})

	t.Run("MatchingSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const id uint64 = 0xCAFE
		go fakeServer(direct(serverConn), []byte{1}, id)

		s := &session{conn: c, sessionId: id}

		require.NoError(roundTrip(t, c, s))
		require.Equal(id, s.sessionId)
	})

	t.Run("RejectsSessionIdMismatch", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		go fakeServer(direct(serverConn), []byte{1}, 0xBBBB)

		s := &session{conn: c, sessionId: 0xAAAA}

		err := roundTrip(t, c, s)
		require.Error(err)
		require.IsType(&InvalidResponseError{}, err)
	})
}

func TestConnRecvPrefersBufferedResponseOverCanceledContext(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
	}

	echoRes := &smb2.EchoResponse{}
	resBuf := make([]byte, echoRes.Size())
	echoRes.Encode(resBuf)
	p := smb2.PacketCodec(resBuf)
	p.SetMessageId(1)
	p.SetStatus(uint32(erref.STATUS_SUCCESS))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	// The response has already arrived on the request's channel while the
	// context is already canceled: the response must win over the
	// cancellation instead of being discarded as a ContextError.
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		rr := &outstandingRequest{
			msgId: uint64(i) + 1,
			cmd:   smb2.SMB2_ECHO,
			ctx:   ctx,
			recv:  make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(rr.msgId, rr)

		rp := allocRecvPacket(len(resBuf))
		copy(rp.pkt, resBuf)
		buf := rp.buf
		rr.recv <- rp

		got, err := c.recv(rr)
		require.NoError(err, "buffered response must not be dropped in favor of context cancellation")
		require.NotNil(got)
		require.Equal(resBuf, got.bytes())
		got.close()

		// the response buffer must not leak either
		require.Equal(int32(0), buf.refCount.Load())
	}
}

func TestConnRecvLockCancelKeepsFinalOutcome(t *testing.T) {
	require := require.New(t)

	for _, test := range []struct {
		name       string
		status     erref.NtStatus
		wantCtxErr bool
	}{
		{name: "success", status: erref.STATUS_SUCCESS},
		{name: "cancelled", status: erref.STATUS_CANCELLED, wantCtxErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			rr := &outstandingRequest{
				msgId:    1,
				cmd:      smb2.SMB2_LOCK,
				ctx:      ctx,
				recv:     make(chan *recvPacket, 1),
				lockWait: true,
			}
			c := &conn{
				outstandingRequests: newOutstandingRequests(),
				err:                 &TransportError{Err: net.ErrClosed},
			}

			cancel()
			go func() {
				var res smb2.Packet = &smb2.LockResponse{}
				if test.wantCtxErr {
					res = &smb2.ErrorResponse{CommandCode: smb2.SMB2_LOCK}
				}
				buf := make([]byte, res.Size())
				res.Encode(buf)
				p := smb2.PacketCodec(buf)
				p.SetMessageId(rr.msgId)
				p.SetStatus(uint32(test.status))
				p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				rr.recv <- &recvPacket{pkt: buf}
			}()

			got, err := c.recv(rr)
			if test.wantCtxErr {
				require.Nil(got)
				require.IsType(&ContextError{}, err)
			} else {
				require.NoError(err)
				require.NotNil(got)
				got.close()
			}
		})
	}
}

func TestConnRecvLockFinalResponseWinsWhenAlreadyBuffered(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     erref.NtStatus
		wantCtxErr bool
	}{
		{name: "success", status: erref.STATUS_SUCCESS},
		{name: "cancelled", status: erref.STATUS_CANCELLED, wantCtxErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rr := &outstandingRequest{
				msgId:    1,
				cmd:      smb2.SMB2_LOCK,
				ctx:      ctx,
				recv:     make(chan *recvPacket, 1),
				lockWait: true,
			}
			var res smb2.Packet = &smb2.LockResponse{}
			if test.wantCtxErr {
				res = &smb2.ErrorResponse{CommandCode: smb2.SMB2_LOCK}
			}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			p := smb2.PacketCodec(buf)
			p.SetMessageId(rr.msgId)
			p.SetStatus(uint32(test.status))
			p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rr.recv <- &recvPacket{pkt: buf}
			cancel()

			c := &conn{outstandingRequests: newOutstandingRequests()}
			got, err := c.recv(rr)
			if test.wantCtxErr {
				require.Nil(t, got)
				require.IsType(t, &ContextError{}, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				got.close()
			}
		})
	}
}

func TestRecvClosedChannelNilErr(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
	}

	t.Run("returns rr.err when set", func(t *testing.T) {
		// simulates conn.close(err) shutting down outstanding requests
		rr := &outstandingRequest{
			cmd:  smb2.SMB2_ECHO,
			ctx:  context.Background(),
			recv: make(chan *recvPacket),
			err:  fmt.Errorf("connection closed"),
		}
		close(rr.recv)

		_, err := c.recv(rr)
		require.Error(err)
		require.Equal(rr.err, err)
	})

	t.Run("returns TransportError when rr.err is nil", func(t *testing.T) {
		// simulates conn.close(nil) during logoff shutting down outstanding requests
		rr := &outstandingRequest{
			cmd:  smb2.SMB2_ECHO,
			ctx:  context.Background(),
			recv: make(chan *recvPacket),
			err:  nil,
		}
		close(rr.recv)

		_, err := c.recv(rr)
		require.Error(err)
		require.ErrorIs(err, net.ErrClosed)
		var te *TransportError
		require.ErrorAs(err, &te)
	})
}

func TestConnRecvShutdownWithBufferedPacketClosesPacket(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
	}

	rr := &outstandingRequest{
		msgId: 1,
		cmd:   smb2.SMB2_ECHO,
		ctx:   context.Background(),
		recv:  make(chan *recvPacket, 1),
	}
	c.outstandingRequests.set(rr.msgId, rr)

	rp := allocRecvPacket(64)
	buf := rp.buf

	// The response arrives on the request's channel right before the
	// connection is torn down.
	rr.recv <- rp

	shutdownErr := fmt.Errorf("connection closed by peer")
	c.outstandingRequests.shutdown(shutdownErr)

	_, err := c.recv(rr)
	require.Error(err)
	require.Equal(shutdownErr, err)

	// The buffered packet must be closed so its buffer refcount drops to 0;
	// otherwise the pooled buffer leaks.
	require.Equal(int32(0), buf.refCount.Load(), "buffered response packet leaked on shutdown")
}

type mockReceiver struct {
	pkts []*recvPacket
	errs []error
	idx  int
}

func (m *mockReceiver) recv(*outstandingRequest) (*recvPacket, error) {
	if m.idx < len(m.errs) && m.errs[m.idx] != nil {
		err := m.errs[m.idx]
		m.idx++
		return nil, err
	}
	rp := m.pkts[m.idx]
	m.idx++
	return rp, nil
}

func TestRecvAllReturnsPartialResponsesOnCompoundError(t *testing.T) {
	require := require.New(t)

	p0 := allocRecvPacket(64)
	p1 := allocRecvPacket(64)
	p3 := allocRecvPacket(64)
	failErr := fmt.Errorf("fail at op 2")
	lastErr := fmt.Errorf("fail at op 4")

	mock := &mockReceiver{
		pkts: []*recvPacket{p0, p1, nil, p3, nil},
		errs: []error{nil, nil, failErr, nil, lastErr},
	}

	rrs := []*outstandingRequest{
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
	}

	res, err := recvAll(rrs, mock)
	require.NotNil(res)
	require.Error(err)

	var cerr *CompoundResponseError
	require.ErrorAs(err, &cerr)
	require.Equal(5, len(cerr.Errors))
	require.Nil(cerr.OpError(0))
	require.Nil(cerr.OpError(1))
	require.ErrorIs(cerr.OpError(2), failErr)
	require.Nil(cerr.OpError(3))
	require.ErrorIs(cerr.OpError(4), lastErr)

	// Packets received before and after the error must remain at their
	// corresponding compound operation indexes.
	require.Equal(p0, res.rpkts[0])
	require.Equal(p1, res.rpkts[1])
	require.Equal(p3, res.rpkts[3])

	// Closing res closes every retained packet.
	res.close()
	require.Nil(p0.buf)
	require.Nil(p1.buf)
	require.Nil(p3.buf)
}

type compoundTestReceiver func(*outstandingRequest) (*recvPacket, error)

func (receive compoundTestReceiver) recv(rr *outstandingRequest) (*recvPacket, error) {
	return receive(rr)
}

func compoundEchoResponse(msgID uint64, status erref.NtStatus, grant uint16) []byte {
	var res smb2.Packet = &smb2.EchoResponse{}
	if status != erref.STATUS_SUCCESS {
		res = &smb2.ErrorResponse{CommandCode: smb2.SMB2_ECHO}
	}
	buf := make([]byte, res.Size())
	res.Encode(buf)
	p := smb2.PacketCodec(buf)
	p.SetMessageId(msgID)
	p.SetStatus(uint32(status))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetCreditResponse(grant)
	return buf
}

func TestCompoundResponsesPreserveCreditsAndIndexes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		grants []uint16
		wait   bool
	}{
		{name: "wait-after-first-error", grants: []uint16{1, 0, 0}, wait: true},
		{name: "wait-after-first-error-with-three-grant", grants: []uint16{0, 0, 3}, wait: true},
		{name: "responses-already-buffered", grants: []uint16{1, 0, 0}},
		{name: "responses-already-buffered-with-three-grant", grants: []uint16{0, 0, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c := &conn{
				t:                   direct(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(3),
				rdone:               make(chan struct{}, 1),
			}
			c.account.charge(2) // Initial available balance is three credits.
			go c.runReceiver()
			defer c.close(nil)

			firstWritten := make(chan struct{})
			allWritten := make(chan struct{})
			release := make(chan struct{})
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				st := direct(serverConn)
				reqBuf, err := readMsg(st)
				if err != nil {
					return
				}
				p := smb2.PacketCodec(reqBuf)
				statuses := []erref.NtStatus{
					erref.STATUS_ACCESS_DENIED,
					erref.STATUS_SUCCESS,
					erref.STATUS_INVALID_PARAMETER,
				}
				writeResponse := func(i int) error {
					buf := compoundEchoResponse(p.MessageId()+uint64(i), statuses[i], tc.grants[i])
					if i > 0 {
						rp := smb2.PacketCodec(buf)
						rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
					}
					_, err := st.Writev(buf)
					return err
				}

				if err := writeResponse(0); err != nil {
					return
				}
				close(firstWritten)
				if tc.wait {
					<-release
				}
				for i := 2; i >= 1; i-- {
					if err := writeResponse(i); err != nil {
						return
					}
				}
				close(allWritten)
			}()

			reqs := []smb2.Packet{&smb2.EchoRequest{}, &smb2.EchoRequest{}, &smb2.EchoRequest{}}
			rrs, err := c.send(context.Background(), false, reqs...)
			require.NoError(t, err)

			if !tc.wait {
				<-allWritten
				require.Eventually(t, func() bool {
					return len(rrs[0].recv) == 1 && len(rrs[1].recv) == 1 && len(rrs[2].recv) == 1
				}, time.Second, time.Millisecond)
			}
			waitingForSecond := make(chan struct{})
			receiver := compoundTestReceiver(func(rr *outstandingRequest) (*recvPacket, error) {
				if rr == rrs[1] {
					close(waitingForSecond)
				}
				return c.recv(rr)
			})
			var res *response
			var recvErr error
			recvDone := make(chan struct{})
			go func() {
				res, recvErr = recvAll(rrs, receiver)
				close(recvDone)
			}()

			if tc.wait {
				<-firstWritten
				select {
				case <-waitingForSecond:
				case <-time.After(time.Second):
					t.Fatal("recvAll did not request the response after the first error")
				}
				select {
				case <-recvDone:
					t.Fatal("recvAll returned before the later responses")
				default:
				}
				require.Eventually(t, func() bool {
					c.account.m.Lock()
					defer c.account.m.Unlock()
					return c.account.availableCredits == tc.grants[0] && c.account.inFlightCredits == 2
				}, time.Second, time.Millisecond)
				close(release)
			}

			select {
			case <-recvDone:
			case <-time.After(time.Second):
				t.Fatal("recvAll did not collect every compound response")
			}
			require.NotNil(t, res)
			var cerr *CompoundResponseError
			require.ErrorAs(t, recvErr, &cerr)
			require.ErrorIs(t, cerr.OpError(0), erref.STATUS_ACCESS_DENIED)
			require.Nil(t, cerr.OpError(1))
			require.ErrorIs(t, cerr.OpError(2), erref.STATUS_INVALID_PARAMETER)
			require.Nil(t, res.packet(0))
			require.NotNil(t, res.packet(1))
			require.Nil(t, res.packet(2))
			res.close()

			require.Eventually(t, func() bool {
				c.account.m.Lock()
				defer c.account.m.Unlock()
				return c.account.availableCredits == tc.grants[0]+tc.grants[1]+tc.grants[2] && c.account.inFlightCredits == 0
			}, time.Second, time.Millisecond)
			<-serverDone
		})
	}
}

func TestCompoundCancellationKeepsRequestsForDelayedResponses(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(3),
		rdone:               make(chan struct{}, 1),
	}
	c.account.charge(2) // Initial available balance is three credits.
	go c.runReceiver()
	defer c.close(nil)

	grants := []uint16{0, 0, 3}
	serverReady := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		for i := 0; i < 3; i++ {
			cancelBuf, err := readMsg(st)
			if err != nil || smb2.PacketCodec(cancelBuf).Command() != smb2.SMB2_CANCEL {
				return
			}
		}
		close(serverReady)
		<-release
		statuses := []erref.NtStatus{
			erref.STATUS_ACCESS_DENIED,
			erref.STATUS_SUCCESS,
			erref.STATUS_INVALID_PARAMETER,
		}
		for i := range grants {
			buf := compoundEchoResponse(p.MessageId()+uint64(i), statuses[i], grants[i])
			if i > 0 {
				rp := smb2.PacketCodec(buf)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
			}
			if _, err := st.Writev(buf); err != nil {
				return
			}
		}
		// The same transport must still serve a new request after cancellation.
		echo, err := readMsg(st)
		if err != nil {
			return
		}
		_, _ = st.Writev(compoundEchoResponse(smb2.PacketCodec(echo).MessageId(), erref.STATUS_SUCCESS, 1))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	reqs := []smb2.Packet{&smb2.EchoRequest{}, &smb2.EchoRequest{}, &smb2.EchoRequest{}}
	rrs, err := c.send(ctx, false, reqs...)
	require.NoError(t, err)
	cancel()

	recvDone := make(chan struct{})
	var recvErr error
	go func() {
		_, recvErr = recvAll(rrs, c)
		close(recvDone)
	}()
	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("compound cancellation did not return")
	}
	var cerr *CompoundResponseError
	require.ErrorAs(t, recvErr, &cerr)
	require.Error(t, cerr.OpError(0))
	require.Error(t, cerr.OpError(1))
	require.Error(t, cerr.OpError(2))

	<-serverReady
	c.account.m.Lock()
	available, inFlight := c.account.availableCredits, c.account.inFlightCredits
	c.account.m.Unlock()
	require.Zero(t, available, "cancellation must not refund sent credits")
	require.EqualValues(t, 3, inFlight)
	for _, rr := range rrs {
		_, registered := c.outstandingRequests.peek(rr.msgId)
		require.True(t, registered)
	}
	close(release)
	require.Eventually(t, func() bool {
		c.account.m.Lock()
		defer c.account.m.Unlock()
		return c.account.availableCredits == 3 && c.account.inFlightCredits == 0
	}, time.Second, time.Millisecond)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	res, err := c.sendRecv(ctx, &smb2.EchoRequest{})
	require.NoError(t, err)
	res.close()
	<-serverDone
	c.account.m.Lock()
	available, inFlight = c.account.availableCredits, c.account.inFlightCredits
	c.account.m.Unlock()
	require.EqualValues(t, 3, available)
	require.Zero(t, inFlight)
}

func TestConnCloseNilSetsDefaultError(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		rdone:               make(chan struct{}, 1),
	}

	err := c.close(nil)
	require.NoError(err)

	c.m.Lock()
	connErr := c.err
	c.m.Unlock()

	require.Error(connErr)
	require.ErrorIs(connErr, net.ErrClosed)
	var te *TransportError
	require.ErrorAs(connErr, &te)

	// Idempotent: subsequent close calls are no-ops returning nil
	require.NoError(c.close(nil))

	// send on closed connection fails immediately with connErr
	c.account = openAccount(10)
	_, sendErr := c.send(context.Background(), false, &smb2.EchoRequest{})
	require.Error(sendErr)
	require.ErrorIs(sendErr, net.ErrClosed)
}

func TestConnCloseUnblocksCreditLoan(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}
	t.Cleanup(func() {
		_ = c.close(nil)
	})

	// Exhaust the initial credit so the next send blocks inside account.loan.
	_, _, err := c.account.loan(context.Background(), &smb2.EchoRequest{})
	require.NoError(err)

	sendDone := make(chan error, 1)
	go func() {
		_, err := c.send(context.Background(), false, &smb2.EchoRequest{})
		sendDone <- err
	}()

	select {
	case <-sendDone:
		t.Fatal("expected send to block on credit loan")
	case <-time.After(50 * time.Millisecond):
		// Expected: send is blocked waiting for credits
	}

	// Closing the connection must abort the credit wait and unblock send.
	require.NoError(c.close(nil))

	var te *TransportError
	select {
	case err := <-sendDone:
		require.Error(err)
		require.ErrorAs(err, &te)
	case <-time.After(1 * time.Second):
		t.Fatal("expected send to unblock after conn.close")
	}
}

func TestTryVerify(t *testing.T) {
	// builds an SMB2 response header
	makeHdr := func(status uint32, flags uint32, sessionId, msgID uint64) smb2.PacketCodec {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetCommand(smb2.SMB2_CREATE)
		p.SetStatus(status)
		p.SetFlags(flags)
		p.SetMessageId(msgID)
		p.SetSessionId(sessionId)
		return pkt
	}

	require := require.New(t)
	const sessionID uint64 = 0xCAFE

	// SMB 3.0.x-style signing-required conn with a CMAC verifier.
	ciph, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		requireSigning:      true,
		dialect:             smb2.SMB302,
	}
	c.session = &session{conn: c, sessionId: sessionID, verifier: cmac.New(ciph)}
	c.enableSession()

	t.Run("response without server-to-redir is rejected before signature verification", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SIGNED, sessionID, 22)
		verifier := cmac.New(ciph)
		_, _ = verifier.Write(pkt)
		pkt.SetSignature(verifier.Sum(nil))

		err := c.tryVerify(&recvPacket{pkt: pkt}, false)
		require.ErrorContains(err, "server-to-redir")
	})

	t.Run("STATUS_PENDING should skip verification", func(t *testing.T) {
		pkt := makeHdr(uint32(erref.STATUS_PENDING), smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_ASYNC_COMMAND, sessionID, uint64(smb2.SMB2_CREATE))
		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, false))
	})

	t.Run("regular message, signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, 21)
		pkt.SetSignature(zero[:])
		require.IsType(&InvalidResponseError{}, c.tryVerify(&recvPacket{pkt: pkt}, false))
	})

	t.Run("regular message, unset signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, uint64(smb2.SMB2_CREATE))
		pkt.SetSignature(zero[:])
		err := c.tryVerify(&recvPacket{pkt: pkt}, false)
		require.IsType(&InvalidResponseError{}, err)
		require.ErrorContains(err, "packet failed signature verification")
	})

	t.Run("OPLOCK_BREAK should skip verification", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, 0xFFFFFFFFFFFFFFFF)
		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, false))
	})

	t.Run("unsigned message, signing not negotiated - succeeds", func(t *testing.T) {
		// we need a connection that doesn't require signing for this subtest
		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			dialect:             smb2.SMB302,
		}
		c.session = &session{conn: c, sessionId: sessionID}
		c.enableSession()

		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, uint64(smb2.SMB2_CREATE))
		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, false))
	})

	t.Run("encrypted message without signature, succeeds", func(t *testing.T) {
		// pass an invalid session id, and use a connection that requires
		// signing to make sure we're getting an early return due to encryption
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, 0, uint64(smb2.SMB2_CREATE))
		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, true))
	})

	t.Run("encrypted request rejects an unencrypted response", func(t *testing.T) {
		const msgID uint64 = 22
		rr := &outstandingRequest{
			msgId:             msgID,
			requireEncryption: true,
			recv:              make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(msgID, rr)
		defer c.outstandingRequests.pop(msgID)

		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, msgID)
		err := c.tryVerify(&recvPacket{pkt: pkt}, false)
		require.Error(err)
		require.ErrorContains(err, "encrypted response required")
		pkt.SetStatus(uint32(erref.STATUS_PENDING))
		pkt.SetFlags(pkt.Flags() | smb2.SMB2_FLAGS_ASYNC_COMMAND)
		require.ErrorContains(c.tryVerify(&recvPacket{pkt: pkt}, false), "encrypted response required")

	})

	t.Run("encrypted request accepts an encrypted response", func(t *testing.T) {
		const msgID uint64 = 23
		rr := &outstandingRequest{
			msgId:             msgID,
			requireEncryption: true,
			recv:              make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(msgID, rr)
		defer c.outstandingRequests.pop(msgID)

		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, msgID)
		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, true))
	})

	t.Run("signed message succeeds", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, uint64(smb2.SMB2_CREATE))

		// actually sign the packet
		verifier := cmac.New(ciph)
		verifier.Write(pkt)
		pkt.SetSignature(verifier.Sum(nil))

		require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, false))
	})

	t.Run("signed message with direct I/O segment succeeds", func(t *testing.T) {
		// header in pkt, payload in a second (caller-owned) segment: the
		// signature must be computed over both segments
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, uint64(smb2.SMB2_CREATE))
		payload := []byte("direct I/O payload")

		verifier := cmac.New(ciph)
		verifier.Write(pkt)
		verifier.Write(payload)
		pkt.SetSignature(verifier.Sum(nil))

		require.NoError(c.tryVerify(&recvPacket{pkt: pkt, ext: payload}, false))

		// a corrupted payload must fail verification
		payload[0] ^= 0xff
		require.IsType(&InvalidResponseError{}, c.tryVerify(&recvPacket{pkt: pkt, ext: payload}, false))
	})

	t.Run("verify with empty or truncated packet returns false", func(t *testing.T) {
		require.False(c.session.verify())
		require.False(c.session.verify(nil))
		require.False(c.session.verify([]byte("short")))
	})
}

func TestAcceptRejectsInvalidIoctlOutputOffset(t *testing.T) {
	require := require.New(t)

	pkt := make([]byte, 64+49)
	p := smb2.PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_IOCTL)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	// A non-empty output buffer cannot point into the SMB2 header or the
	// fixed IOCTL response structure ([MS-SMB2] 2.2.32).
	binary.LittleEndian.PutUint16(pkt[64:66], 49)  // StructureSize
	binary.LittleEndian.PutUint32(pkt[96:100], 1)  // OutputOffset
	binary.LittleEndian.PutUint32(pkt[100:104], 1) // OutputCount

	_, err := accept(smb2.SMB2_IOCTL, &recvPacket{pkt: pkt}, smb2.SMB311)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("broken SMB2_IOCTL response format", ire.Message)
}

func TestAcceptCopyIoctlErrorResponses(t *testing.T) {
	newPacket := func(body []byte, status uint32) (*recvPacket, *recvBuf) {
		pkt := make([]byte, 64+len(body))
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetCommand(smb2.SMB2_IOCTL)
		p.SetStatus(status)
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		copy(pkt[64:], body)

		rp := allocRecvPacket(len(pkt))
		copy(rp.pkt, pkt)
		return rp, rp.buf
	}

	validCopyResponse := func(ctlCode uint32) []byte {
		res := &smb2.IoctlResponse{
			CtlCode: ctlCode,
			Output:  rawEncoder(make([]byte, 12)),
		}
		pkt := make([]byte, res.Size())
		res.Encode(pkt)
		return pkt[64:]
	}

	for _, ctlCode := range []uint32{
		smb2.FSCTL_SRV_COPYCHUNK,
		smb2.FSCTL_SRV_COPYCHUNK_WRITE,
	} {
		for _, status := range []erref.NtStatus{
			erref.STATUS_DISK_FULL,
			erref.STATUS_INVALID_PARAMETER,
		} {
			t.Run(fmt.Sprintf("copy response/%#x/%v", ctlCode, status), func(t *testing.T) {
				rp, buf := newPacket(validCopyResponse(ctlCode), uint32(status))
				_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
				require := require.New(t)

				require.Error(err)
				var responseErr *ResponseError
				require.ErrorAs(err, &responseErr)
				require.Equal(uint32(status), responseErr.Code)
				require.Empty(responseErr.data)
				require.NotErrorAs(err, new(*InvalidResponseError))
				require.Nil(rp.buf)
				require.Zero(buf.refCount.Load())
			})
		}
	}

	for _, status := range []erref.NtStatus{
		erref.STATUS_DISK_FULL,
		erref.STATUS_INVALID_PARAMETER,
	} {
		t.Run(fmt.Sprintf("error response/%v", status), func(t *testing.T) {
			eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}
			pkt := make([]byte, eres.Size())
			eres.Encode(pkt)
			body := pkt[64:]
			rp, buf := newPacket(body, uint32(status))
			_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
			require := require.New(t)

			require.Error(err)
			var responseErr *ResponseError
			require.ErrorAs(err, &responseErr)
			require.Equal(uint32(status), responseErr.Code)
			require.Nil(rp.buf)
			require.Zero(buf.refCount.Load())
		})
	}

	t.Run("truncated fixed part", func(t *testing.T) {
		body := validCopyResponse(smb2.FSCTL_SRV_COPYCHUNK_WRITE)[:47]
		rp, buf := newPacket(body, uint32(erref.STATUS_DISK_FULL))
		_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
		require := require.New(t)

		var invalid *InvalidResponseError
		require.ErrorAs(err, &invalid)
		require.Equal("broken error response format", invalid.Message)
		require.Nil(rp.buf)
		require.Zero(buf.refCount.Load())
	})

	t.Run("invalid output range", func(t *testing.T) {
		body := validCopyResponse(smb2.FSCTL_SRV_COPYCHUNK_WRITE)
		binary.LittleEndian.PutUint32(body[32:36], 1) // OutputOffset
		binary.LittleEndian.PutUint32(body[36:40], 1) // OutputCount
		rp, buf := newPacket(body, uint32(erref.STATUS_DISK_FULL))
		_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
		require := require.New(t)

		var invalid *InvalidResponseError
		require.ErrorAs(err, &invalid)
		require.Equal("broken error response format", invalid.Message)
		require.Nil(rp.buf)
		require.Zero(buf.refCount.Load())
	})
	t.Run("non-copy ioctl retains generic error handling", func(t *testing.T) {
		rp, buf := newPacket(validCopyResponse(smb2.FSCTL_PIPE_TRANSCEIVE), uint32(erref.STATUS_DISK_FULL))
		_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
		require.ErrorAs(t, err, new(*InvalidResponseError))
		require.Nil(t, rp.buf)
		require.Zero(t, buf.refCount.Load())
	})

	t.Run("invalid input range", func(t *testing.T) {
		body := validCopyResponse(smb2.FSCTL_SRV_COPYCHUNK_WRITE)
		le.PutUint32(body[24:28], 1)
		le.PutUint32(body[28:32], 1)
		rp, buf := newPacket(body, uint32(erref.STATUS_DISK_FULL))
		_, err := accept(smb2.SMB2_IOCTL, rp, smb2.SMB311)
		require.ErrorAs(t, err, new(*InvalidResponseError))
		require.Nil(t, rp.buf)
		require.Zero(t, buf.refCount.Load())
	})
}

func TestAcceptRejectsInvalidQueryInfoOutputOffset(t *testing.T) {
	require := require.New(t)

	pkt := make([]byte, 64+8)
	p := smb2.PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_QUERY_INFO)
	p.SetStatus(uint32(erref.STATUS_SUCCESS))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	// A non-empty output buffer cannot point into the SMB2 header or the
	// fixed QUERY_INFO response structure ([MS-SMB2] 2.2.38).
	binary.LittleEndian.PutUint16(pkt[64:66], 9)  // StructureSize
	binary.LittleEndian.PutUint16(pkt[66:68], 71) // OutputBufferOffset
	binary.LittleEndian.PutUint32(pkt[68:72], 1)  // OutputBufferLength

	res, err := accept(smb2.SMB2_QUERY_INFO, &recvPacket{pkt: pkt}, smb2.SMB311)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("broken SMB2_QUERY_INFO response format", ire.Message)
	require.Nil(res)
}

func TestAcceptRejectsInvalidCreateContextOffset(t *testing.T) {
	require := require.New(t)

	pkt := make([]byte, 64+88)
	p := smb2.PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_CREATE)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	binary.LittleEndian.PutUint16(pkt[64:66], 89)    // StructureSize
	binary.LittleEndian.PutUint32(pkt[144:148], 144) // CreateContextsOffset
	binary.LittleEndian.PutUint32(pkt[148:152], 8)   // CreateContextsLength

	res, err := accept(smb2.SMB2_CREATE, &recvPacket{pkt: pkt}, smb2.SMB311)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("broken SMB2_CREATE response format", ire.Message)
	require.Nil(res)
}

func TestSessionEchoRejectsReflectedRequest(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed-%t", signed), func(t *testing.T) {
			require := require.New(t)
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			defer serverConn.Close()

			const sessionID uint64 = 0xCAFE
			s := &session{conn: c, sessionId: sessionID}
			c.session = s
			c.requireSigning = signed
			if signed {
				block, err := aes.NewCipher(make([]byte, 16))
				require.NoError(err)
				s.signer = cmac.New(block)
				block, err = aes.NewCipher(make([]byte, 16))
				require.NoError(err)
				s.verifier = cmac.New(block)
			}
			c.enableSession()

			serverErr := make(chan error, 1)
			go func() {
				request, err := readMsg(direct(serverConn))
				if err == nil {
					err = func() error {
						p := smb2.PacketCodec(request)
						if signed && p.Flags()&smb2.SMB2_FLAGS_SIGNED == 0 {
							return fmt.Errorf("echo request was not signed")
						}
						_, err := direct(serverConn).Writev(request)
						return err
					}()
				}
				serverErr <- err
			}()

			err := s.echo(context.Background())
			require.Error(err)
			require.IsType(&InvalidResponseError{}, err)
			require.ErrorContains(err, "server-to-redir")
			require.NoError(<-serverErr)
		})
	}
}

func TestRunReceiverRejectsMissingDirectionInCompoundResponse(t *testing.T) {
	require := require.New(t)
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	defer serverConn.Close()

	const sessionID uint64 = 0xCAFE
	c.session = &session{conn: c, sessionId: sessionID}
	c.enableSession()

	newResponse := func(messageID uint64, flags uint32, next uint32) []byte {
		res := &smb2.EchoResponse{}
		pkt := make([]byte, (res.Size()+7)&^7)
		res.Encode(pkt)
		p := smb2.PacketCodec(pkt)
		p.SetMessageId(messageID)
		p.SetSessionId(sessionID)
		p.SetFlags(flags)
		p.SetNextCommand(next)
		p.SetCreditResponse(1)
		return pkt
	}

	requests := []*outstandingRequest{
		{msgId: 1, cmd: smb2.SMB2_ECHO, creditCharge: 1, recv: make(chan *recvPacket, 1)},
		{msgId: 2, cmd: smb2.SMB2_ECHO, creditCharge: 1, recv: make(chan *recvPacket, 1)},
	}
	for _, rr := range requests {
		c.outstandingRequests.set(rr.msgId, rr)
	}

	first := newResponse(1, smb2.SMB2_FLAGS_SERVER_TO_REDIR, 72)
	second := newResponse(2, 0, 0)
	_, err := direct(serverConn).Writev(append(first, second...))
	require.NoError(err)

	select {
	case rp := <-requests[0].recv:
		require.NotNil(rp)
		accepted, err := accept(smb2.SMB2_ECHO, rp, c.dialect)
		require.NoError(err)
		accepted.close()
	case <-time.After(time.Second):
		t.Fatal("valid first compound response was not delivered")
	}

	select {
	case _, ok := <-requests[1].recv:
		require.False(ok, "compound response without server-to-redir must not be delivered")
	case <-time.After(time.Second):
		t.Fatal("invalid second compound response was not rejected")
	}
}

func TestConnTryHandleDiscardsInvalidSignature(t *testing.T) {
	require := require.New(t)

	const sessionID uint64 = 0xCAFE
	const msgID uint64 = 1

	ciph, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)

	newConn := func() *conn {
		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(1),
			requireSigning:      true,
			dialect:             smb2.SMB302,
		}
		c.session = &session{
			conn:      c,
			sessionId: sessionID,
			signer:    cmac.New(ciph),
			verifier:  cmac.New(ciph),
		}
		c.enableSession()
		c.account.m.Lock()
		c.account.availableCredits = 0
		c.account.inFlightCredits = 1
		c.account.maxCredits = 1
		c.account.m.Unlock()
		return c
	}

	newResponse := func(creditResponse uint16) *recvPacket {
		res := &smb2.EchoResponse{}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		p := smb2.PacketCodec(buf)
		p.SetMessageId(msgID)
		p.SetSessionId(sessionID)
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_SIGNED)
		p.SetCreditResponse(creditResponse)
		rp := allocRecvPacket(len(buf))
		copy(rp.pkt, buf)
		return rp
	}

	t.Run("matching request", func(t *testing.T) {
		c := newConn()
		rr := &outstandingRequest{
			msgId:        msgID,
			creditCharge: 1,
			recv:         make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(msgID, rr)

		bad := newResponse(65535)
		verifyErr := c.tryVerify(bad, false)
		require.Error(verifyErr)
		require.Error(c.tryHandle(bad, verifyErr))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, loanErr := c.account.loan(ctx, &smb2.ReadRequest{Length: 2 * singleCreditMaxPayloadSize})
		require.IsType(&InternalError{}, loanErr, "invalid signature must not expand the request limit")

		c.account.m.Lock()
		require.Equal(uint16(1), c.account.availableCredits)
		require.Equal(uint16(0), c.account.inFlightCredits)
		require.Equal(uint16(1), c.account.maxCredits)
		c.account.m.Unlock()
		_, ok := c.outstandingRequests.peek(msgID)
		require.False(ok)
		require.Equal(verifyErr, rr.err)
		_, open := <-rr.recv
		require.False(open)
	})

	t.Run("unknown request", func(t *testing.T) {
		c := newConn()
		bad := newResponse(65535)
		verifyErr := c.tryVerify(bad, false)
		require.Error(verifyErr)
		require.Error(c.tryHandle(bad, verifyErr))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, loanErr := c.account.loan(ctx, &smb2.ReadRequest{Length: 2 * singleCreditMaxPayloadSize})
		require.IsType(&InternalError{}, loanErr, "invalid signature must not expand the request limit")

		c.account.m.Lock()
		require.Equal(uint16(0), c.account.availableCredits)
		require.Equal(uint16(1), c.account.inFlightCredits)
		require.Equal(uint16(1), c.account.maxCredits)
		c.account.m.Unlock()
	})
}

func TestConnTryHandleDiscardsUnknownResponsesWithoutCredits(t *testing.T) {
	newResponse := func(messageID uint64) *recvPacket {
		res := &smb2.EchoResponse{}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		p := smb2.PacketCodec(buf)
		p.SetMessageId(messageID)
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		p.SetCreditResponse(65535)
		rp := allocRecvPacket(len(buf))
		copy(rp.pkt, buf)
		return rp
	}

	for _, test := range []struct {
		name      string
		messageID uint64
	}{
		{name: "unknown message id", messageID: 42},
		{name: "all bits set echo", messageID: ^uint64(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			c := &conn{
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(1),
			}

			c.account.m.Lock()
			availableBefore := c.account.availableCredits
			maxBefore := c.account.maxCredits
			inFlightBefore := c.account.inFlightCredits
			c.account.m.Unlock()

			err := c.tryHandle(newResponse(test.messageID), nil)
			require.Error(err)
			var invalid *InvalidResponseError
			require.ErrorAs(err, &invalid)
			require.Equal("unknown message id returned", invalid.Message)

			c.account.m.Lock()
			require.Equal(availableBefore, c.account.availableCredits)
			require.Equal(maxBefore, c.account.maxCredits)
			require.Equal(inFlightBefore, c.account.inFlightCredits)
			c.account.m.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, _, loanErr := c.account.loan(ctx, &smb2.ReadRequest{Length: 2 * singleCreditMaxPayloadSize})
			require.IsType(&InternalError{}, loanErr)
		})
	}
}

func TestNegotiateDoesNotMutateNegotiator(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Round 1: server replies with SMB2 wildcard (0x2FF)
		buf1, err := readMsg(st)
		if err != nil {
			return
		}
		p1 := smb2.PacketCodec(buf1)
		resp1 := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p1.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB2,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf1 := make([]byte, resp1.Size())
		resp1.Encode(respBuf1)
		smb2.PacketCodec(respBuf1).SetCreditResponse(1)
		if _, err := st.Writev(respBuf1); err != nil {
			return
		}

		// Round 2: server replies with SMB210 (0x210)
		buf2, err := readMsg(st)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(buf2)
		resp2 := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p2.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB210,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf2 := make([]byte, resp2.Size())
		resp2.Encode(respBuf2)
		smb2.PacketCodec(respBuf2).SetCreditResponse(1)
		_, _ = st.Writev(respBuf2)
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	conn, err := n.negotiate(context.Background(), direct(clientConn), a, defaultWriteTimeout)
	require.NoError(err)
	require.NotNil(conn)
	require.Equal(uint16(smb2.SMB210), conn.dialect)
	// Caller's Negotiator must remain untouched
	require.Equal(uint16(smb2.UnknownSMB), n.SpecifiedDialect)
}

func TestNegotiateClosesTransportOnError(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Read negotiate request then abruptly close serverConn to simulate failure
		_, _ = readMsg(st)
		_ = serverConn.Close()
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	_, err := n.negotiate(context.Background(), direct(clientConn), a, defaultWriteTimeout)
	require.Error(err)

	// clientConn must be closed by negotiate cleanup; reading from it should return an error
	buf := make([]byte, 1)
	_, readErr := clientConn.Read(buf)
	require.Error(readErr, "clientConn should be closed after failed negotiate")
}

func TestNegotiateRejectsUnsupportedDialectRevision(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		buf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: 0x0312, // not in clientDialects
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		_, _ = st.Writev(respBuf)
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	_, err := n.negotiate(context.Background(), direct(clientConn), a, defaultWriteTimeout)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("unexpected dialect returned", ire.Message)

	// clientConn must be closed by negotiate cleanup; reading from it should return an error
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(readErr, "clientConn should be closed after failed negotiate")
}

func TestNegotiateRejectsRepeatedSMB2WildcardResponse(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Server keeps replying with the SMB2 wildcard dialect (0x0200)
		// even after the client re-negotiates with a specified dialect.
		for i := 0; i < 10; i++ {
			buf, err := readMsg(st)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(buf)
			resp := &smb2.NegotiateResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					MessageId: p.MessageId(),
				},
				SecurityMode:    1,
				DialectRevision: smb2.SMB2,
				MaxTransactSize: 65536,
				MaxReadSize:     65536,
				MaxWriteSize:    65536,
				SystemTime:      &smb2.Filetime{},
				ServerStartTime: &smb2.Filetime{},
			}
			respBuf := make([]byte, resp.Size())
			resp.Encode(respBuf)
			smb2.PacketCodec(respBuf).SetCreditResponse(1)
			if _, err := st.Writev(respBuf); err != nil {
				return
			}
		}
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := n.negotiate(ctx, direct(clientConn), a, defaultWriteTimeout)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("unexpected dialect returned", ire.Message)

	// clientConn must be closed by negotiate cleanup; reading from it should return an error
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(readErr, "clientConn should be closed after failed negotiate")
}

func TestNegotiateRejectsInvalidNegotiateContexts(t *testing.T) {
	tests := map[string]struct {
		contexts []smb2.Encoder
		message  string
	}{
		"missing preauth context": {
			contexts: []smb2.Encoder{
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}},
			},
			message: "missing preauth integrity capabilities context",
		},
		"duplicate preauth contexts": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}},
			},
			message: "duplicate preauth integrity capabilities context",
		},
		"unsupported preauth hash algorithm": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{0xffff}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}},
			},
			message: "unsupported hash algorithm",
		},
		"unsupported cipher algorithm": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{Ciphers: []uint16{0xffff}},
			},
			message: "unsupported cipher algorithm",
		},
		"missing cipher algorithm": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{},
			},
			message: "multiple cipher algorithms",
		},
		"multiple cipher algorithms": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM, smb2.AES128CCM}},
			},
			message: "multiple cipher algorithms",
		},
		"duplicate encryption contexts": {
			contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}},
				&smb2.CipherContext{Ciphers: []uint16{smb2.AES128CCM}},
			},
			message: "duplicate encryption capabilities context",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()

			st := direct(serverConn)

			go func() {
				buf, err := readMsg(st)
				if err != nil {
					return
				}
				p := smb2.PacketCodec(buf)
				resp := &smb2.NegotiateResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						MessageId: p.MessageId(),
					},
					SecurityMode:    1,
					DialectRevision: smb2.SMB311,
					MaxTransactSize: 65536,
					MaxReadSize:     65536,
					MaxWriteSize:    65536,
					SystemTime:      &smb2.Filetime{},
					ServerStartTime: &smb2.Filetime{},
					Contexts:        tc.contexts,
				}
				respBuf := make([]byte, resp.Size())
				resp.Encode(respBuf)
				smb2.PacketCodec(respBuf).SetCreditResponse(1)
				_, _ = st.Writev(respBuf)
			}()

			n := &Negotiator{
				SpecifiedDialect: smb2.UnknownSMB,
			}

			a := openAccount(128)
			_, err := n.negotiate(context.Background(), direct(clientConn), a, defaultWriteTimeout)
			require.Error(err)
			var ire *InvalidResponseError
			require.ErrorAs(err, &ire)
			require.Equal(tc.message, ire.Message)
		})
	}
}

func TestNegotiateRejectsContextInsideFixedResponse(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	st := direct(serverConn)
	go func() {
		buf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		context := &smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)}
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB311,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
			Contexts:        []smb2.Encoder{context},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		// Move a structurally valid preauth context into ServerGuid and point
		// NegotiateContextOffset at it, simulating a context in the fixed part.
		copy(respBuf[72:72+context.Size()], respBuf[128:128+context.Size()])
		binary.LittleEndian.PutUint32(respBuf[64+60:64+64], 72)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		_, _ = st.Writev(respBuf)
	}()

	n := &Negotiator{SpecifiedDialect: smb2.UnknownSMB}
	_, err := n.negotiate(context.Background(), direct(clientConn), openAccount(128), defaultWriteTimeout)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
}

func TestNegotiateRejectsMissingNegotiateContextElement(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	st := direct(serverConn)
	go func() {
		buf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB311,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
			Contexts: []smb2.Encoder{
				&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
			},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		// Claim two contexts while providing only the one encoded element.
		binary.LittleEndian.PutUint16(respBuf[64+6:64+8], 2)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		_, _ = st.Writev(respBuf)
	}()

	n := &Negotiator{SpecifiedDialect: smb2.UnknownSMB}
	_, err := n.negotiate(context.Background(), direct(clientConn), openAccount(128), defaultWriteTimeout)
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("broken negotiate context format", ire.Message)
}

func TestNegotiateAcceptsSelectedCiphers(t *testing.T) {
	for _, cipherID := range []uint16{0, smb2.AES128GCM, smb2.AES128CCM} {
		t.Run(fmt.Sprintf("cipher-%d", cipherID), func(t *testing.T) {
			require := require.New(t)

			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()

			st := direct(serverConn)
			go func() {
				buf, err := readMsg(st)
				if err != nil {
					return
				}
				p := smb2.PacketCodec(buf)
				resp := &smb2.NegotiateResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						MessageId: p.MessageId(),
					},
					SecurityMode:    1,
					DialectRevision: smb2.SMB311,
					MaxTransactSize: 65536,
					MaxReadSize:     65536,
					MaxWriteSize:    65536,
					SystemTime:      &smb2.Filetime{},
					ServerStartTime: &smb2.Filetime{},
					Contexts: []smb2.Encoder{
						&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}, HashSalt: make([]byte, 32)},
						&smb2.CipherContext{Ciphers: []uint16{cipherID}},
					},
				}
				respBuf := make([]byte, resp.Size())
				resp.Encode(respBuf)
				smb2.PacketCodec(respBuf).SetCreditResponse(1)
				_, _ = st.Writev(respBuf)
			}()

			n := &Negotiator{SpecifiedDialect: smb2.UnknownSMB}
			c, err := n.negotiate(context.Background(), direct(clientConn), openAccount(128), defaultWriteTimeout)
			require.NoError(err)
			require.Equal(cipherID, c.cipherId)

			if cipherID == 0 {
				s := &session{
					conn: &conn{
						dialect:  smb2.SMB311,
						cipherId: cipherID,
					},
					sessionFlags: 0,
				}
				require.NoError(s.setupKeys(bytes.Repeat([]byte{0x42}, 16)))
				require.NotNil(s.signer)
				require.NotNil(s.verifier)
				require.Nil(s.encrypter)
				require.Nil(s.decrypter)

				req := &smb2.EchoRequest{}
				pkt := make([]byte, req.Size())
				req.Encode(pkt)
				s.sign(pkt)
				require.True(smb2.PacketCodec(pkt).Flags()&smb2.SMB2_FLAGS_SIGNED != 0)
				require.True(s.verify(pkt))
			}

			require.NoError(c.close(nil))
		})
	}
}

func TestAcceptErrorSingleContextWithoutTrailingPadding(t *testing.T) {
	require := require.New(t)

	// The last error context in an SMB2 ERROR response need not be padded to
	// the 8-byte boundary (MS-SMB2 2.2.2). acceptError must not treat the
	// missing trailing padding as a broken response format.
	contextData := []byte{0xde, 0xad, 0xbe, 0xef}

	payload := make([]byte, 8+8+len(contextData))
	// SMB2 Error Response header
	binary.LittleEndian.PutUint16(payload[0:2], 9)                          // StructureSize
	payload[2] = 1                                                          // ErrorContextCount
	binary.LittleEndian.PutUint32(payload[4:8], uint32(8+len(contextData))) // ByteCount
	// SMB2 Error Context Response
	binary.LittleEndian.PutUint32(payload[8:12], uint32(len(contextData))) // ErrorDataLength
	binary.LittleEndian.PutUint32(payload[12:16], 0x1234)                  // ErrorId
	copy(payload[16:], contextData)

	err := acceptError(uint32(erref.STATUS_INVALID_PARAMETER), payload, smb2.SMB202)
	require.Error(err)
	var re *ResponseError
	require.ErrorAs(err, &re)
	require.Equal(uint32(erref.STATUS_INVALID_PARAMETER), re.Code)
	require.Equal([][]byte{contextData}, re.data)
}

func TestAcceptErrorCopiesReceivedBuffers(t *testing.T) {
	require := require.New(t)

	contextData := []byte{0xde, 0xad, 0xbe, 0xef}

	newErrorPayload := func(contextCount uint16) []byte {
		switch contextCount {
		case 0:
			// SMB2 Error Response with raw ErrorData (no contexts)
			payload := make([]byte, 8+len(contextData))
			binary.LittleEndian.PutUint16(payload[0:2], 9)                        // StructureSize
			binary.LittleEndian.PutUint32(payload[4:8], uint32(len(contextData))) // ByteCount
			copy(payload[8:], contextData)
			return payload
		default:
			// SMB2 Error Response with a single Error Context
			payload := make([]byte, 8+8+len(contextData))
			binary.LittleEndian.PutUint16(payload[0:2], 9)                          // StructureSize
			payload[2] = byte(contextCount)                                         // ErrorContextCount
			binary.LittleEndian.PutUint32(payload[4:8], uint32(8+len(contextData))) // ByteCount
			// SMB2 Error Context Response
			binary.LittleEndian.PutUint32(payload[8:12], uint32(len(contextData))) // ErrorDataLength
			binary.LittleEndian.PutUint32(payload[12:16], 0x1234)                  // ErrorId
			copy(payload[16:], contextData)
			return payload
		}
	}

	for _, tc := range []struct {
		name         string
		contextCount uint16
	}{
		{"RawErrorData", 0},
		{"ErrorContext", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := newErrorPayload(tc.contextCount)
			err := acceptError(uint32(erref.STATUS_INVALID_PARAMETER), payload, smb2.SMB202)
			require.Error(err)
			var re *ResponseError
			require.ErrorAs(err, &re)
			require.Equal(uint32(erref.STATUS_INVALID_PARAMETER), re.Code)
			require.Equal([][]byte{contextData}, re.data)

			// The received buffer is recycled by the receiver, so acceptError
			// must not alias it: mutating the source buffer must not corrupt
			// the data held by the returned ResponseError.
			for i := range payload {
				payload[i] = 0
			}
			require.Equal([][]byte{contextData}, re.data)
		})
	}
}

func TestAcceptErrorSecurityQueryRequiredLengthForms(t *testing.T) {
	required := uint32(8192)
	plain := make([]byte, 12)
	binary.LittleEndian.PutUint16(plain[0:2], 9)
	binary.LittleEndian.PutUint32(plain[4:8], 4)
	binary.LittleEndian.PutUint32(plain[8:12], required)
	err := acceptError(uint32(erref.STATUS_BUFFER_TOO_SMALL), plain, smb2.SMB202)
	var responseErr *ResponseError
	require.True(t, errors.As(err, &responseErr))
	require.True(t, responseErr.hasRequiredBufferLength)
	require.Equal(t, required, responseErr.requiredBufferLength)

	context := make([]byte, 20)
	binary.LittleEndian.PutUint16(context[0:2], 9)
	context[2] = 1
	binary.LittleEndian.PutUint32(context[4:8], 12)
	binary.LittleEndian.PutUint32(context[8:12], 4)
	binary.LittleEndian.PutUint32(context[12:16], smb2.SMB2_ERROR_ID_DEFAULT)
	binary.LittleEndian.PutUint32(context[16:20], required)
	err = acceptError(uint32(erref.STATUS_INFO_LENGTH_MISMATCH), context, smb2.SMB311)
	require.True(t, errors.As(err, &responseErr))
	require.True(t, responseErr.hasRequiredBufferLength)
	require.Equal(t, required, responseErr.requiredBufferLength)

	binary.LittleEndian.PutUint32(context[12:16], 1)
	err = acceptError(uint32(erref.STATUS_INFO_LENGTH_MISMATCH), context, smb2.SMB311)
	require.True(t, errors.As(err, &responseErr))
	require.False(t, responseErr.hasRequiredBufferLength)
}

func TestConn_RecvContextCancelReclaimsCredits(t *testing.T) {
	require := require.New(t)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}
	c.account.charge(9) // availableCredits = 10
	go c.runReceiver()
	t.Cleanup(func() {
		_ = c.close(nil)
	})

	st := direct(serverConn)

	var serverErr error
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		// 1. Read Echo request
		reqBuf, err := readMsg(st)
		if err != nil {
			serverErr = err
			return
		}
		p := smb2.PacketCodec(reqBuf)

		// 2. Read Cancel request sent asynchronously by client
		cancelBuf, err := readMsg(st)
		if err != nil {
			serverErr = err
			return
		}
		pCancel := smb2.PacketCodec(cancelBuf)
		if pCancel.Command() != smb2.SMB2_CANCEL || pCancel.MessageId() != p.MessageId() {
			serverErr = fmt.Errorf("unexpected cancel command %v id %v", pCancel.Command(), pCancel.MessageId())
			return
		}

		// 3. Send delayed response to the Echo request with CreditResponse = 5
		echoRes := &smb2.EchoResponse{}
		resBuf := make([]byte, echoRes.Size())
		echoRes.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(p.MessageId())
		rp.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetCreditResponse(5)

		if _, err := st.Writev(resBuf); err != nil {
			serverErr = err
			return
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	// Send an Echo request (costs 1 credit -> availableCredits becomes 9)
	req := &smb2.EchoRequest{}
	rrs, err := c.send(ctx, false, req)
	require.NoError(err)
	require.Equal(uint16(9), c.account.availableCredits)

	// Cancel context before receiving response
	cancel()

	// Recv should return ContextError immediately
	_, recvErr := c.recv(rrs[0])
	require.Error(recvErr)
	require.IsType(&ContextError{}, recvErr)

	<-serverDone
	require.NoError(serverErr)

	// The 5 credits granted by server must be reclaimed by account even though request was canceled
	require.Eventually(func() bool {
		c.account.m.Lock()
		defer c.account.m.Unlock()
		return c.account.availableCredits == 14 // 9 + 5
	}, 1*time.Second, 10*time.Millisecond, "credits from delayed response must be reclaimed after cancellation")
}

type notifyingReadTransport struct {
	transport
	selected chan struct{}
	once     sync.Once
}

func (t *notifyingReadTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	if len(findSink) == 0 || findSink[0] == nil {
		return t.transport.ReadPacket(findSink...)
	}

	finder := findSink[0]
	return t.transport.ReadPacket(func(head []byte, restSize int) ([]byte, int) {
		sink, frontSize := finder(head, restSize)
		if sink != nil {
			t.once.Do(func() { close(t.selected) })
		}
		return sink, frontSize
	})
}

type cancelTransport struct{}

func (cancelTransport) Writev(p ...[]byte) (int, error) {
	var n int
	for _, part := range p {
		n += len(part)
	}
	return n, nil
}

func (cancelTransport) SetWriteDeadline(time.Time) error { return nil }

func (cancelTransport) ReadPacket(...directSinkFinder) (*recvPacket, error) {
	return nil, io.EOF
}

func (cancelTransport) Close() error { return nil }

func readResponseHead(messageID uint64, data []byte) ([]byte, int) {
	res := &smb2.ReadResponse{Data: data}
	buf := make([]byte, res.Size())
	res.Encode(buf)
	p := smb2.PacketCodec(buf)
	p.SetMessageId(messageID)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	return buf[:80], len(buf) - 80
}

func zeroLengthReadResponse(extra int) []byte {
	res := &smb2.ReadResponse{}
	buf := make([]byte, 80+extra)
	res.Encode(buf)
	return buf
}

func TestConnRejectsZeroLengthReadAcrossReceivePaths(t *testing.T) {
	run := func(t *testing.T, path string, plain []byte, aead cipher.AEAD) {
		t.Helper()
		require := require.New(t)

		const (
			sessionID = uint64(0xCAFE)
			messageID = uint64(7)
		)
		original := bytes.Repeat([]byte{0xa5}, 32)
		c := &conn{
			dialect:             smb2.SMB311,
			outstandingRequests: newOutstandingRequests(),
		}
		c.session = &session{conn: c, sessionId: sessionID}
		if path == "compressed" {
			c.compressionIds = []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4}
		}
		if path == "encrypted" {
			c.session.encrypter = aead
			c.session.decrypter = aead
		}

		readBuf := bytes.Clone(original)
		rr := &outstandingRequest{
			msgId:      messageID,
			readBuf:    readBuf,
			directDone: make(chan struct{}),
		}
		c.outstandingRequests.set(messageID, rr)

		p := smb2.PacketCodec(plain)
		p.SetMessageId(messageID)
		p.SetSessionId(sessionID)
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

		var rp *recvPacket
		switch path {
		case "direct":
			sink, frontSize := c.directReadSink(plain[:min(80, len(plain))], max(0, len(plain)-80))
			require.Nil(sink)
			require.Zero(frontSize)
			rp = &recvPacket{pkt: plain}
		case "compressed":
			compressed := compressReadResponseForTest(t, plain)
			decompressed, ext, err := decompressPacketForReceive(c, compressed, c.responseReadSink)
			require.NoError(err)
			require.Nil(ext)
			rp = &recvPacket{pkt: decompressed}
		case "encrypted":
			encrypted, err := c.session.encrypt(plain, make([]byte, 52+len(plain)+aead.Overhead()))
			require.NoError(err)
			var errDecrypt error
			rp, _, errDecrypt = c.tryDecrypt(&recvPacket{pkt: encrypted})
			require.NoError(errDecrypt)
		}

		require.Nil(rp.ext)
		require.Equal(directStateIdle, rr.directState.Load())
		require.Equal(original, readBuf)

		accepted, err := accept(smb2.SMB2_READ, rp, c.dialect)
		require.Nil(accepted)
		if p.Status() == uint32(erref.STATUS_END_OF_FILE) {
			var responseErr *ResponseError
			require.ErrorAs(err, &responseErr)
			require.Equal(uint32(erref.STATUS_END_OF_FILE), responseErr.Code)
		} else {
			var invalid *InvalidResponseError
			require.ErrorAs(err, &invalid)
		}
		require.Equal(directStateIdle, rr.directState.Load())
		require.Equal(original, readBuf)
	}

	// [MS-SMB2] 2.2.20 uses an error response for a read with no data.
	for _, path := range []string{"direct", "compressed", "encrypted"} {
		t.Run("end-of-file/"+path, func(t *testing.T) {
			res := &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}
			plain := make([]byte, res.Size())
			res.Encode(plain)
			smb2.PacketCodec(plain).SetStatus(uint32(erref.STATUS_END_OF_FILE))
			if path == "encrypted" {
				for name, aead := range directIOCiphers(t) {
					t.Run(name, func(t *testing.T) { run(t, path, bytes.Clone(plain), aead) })
				}
			} else {
				run(t, path, plain, nil)
			}
		})
	}

	t.Run("direct-without-trailing-bytes", func(t *testing.T) {
		run(t, "direct", zeroLengthReadResponse(0), nil)
	})
	t.Run("direct-with-trailing-bytes", func(t *testing.T) {
		run(t, "direct", zeroLengthReadResponse(1), nil)
	})
	t.Run("compressed", func(t *testing.T) {
		run(t, "compressed", zeroLengthReadResponse(32), nil)
	})
	for name, aead := range directIOCiphers(t) {
		t.Run("encrypted/"+name, func(t *testing.T) {
			run(t, "encrypted", zeroLengthReadResponse(0), aead)
		})
	}
}

func TestConnCancellationSerializesReadBufferAccess(t *testing.T) {
	for _, decrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("decrypted-%t", decrypted), func(t *testing.T) {
			c := &conn{outstandingRequests: newOutstandingRequests()}
			c.session = &session{conn: c, sessionId: 42}
			rr := &outstandingRequest{msgId: 7, readBuf: bytes.Repeat([]byte{0xa5}, 32)}
			c.outstandingRequests.set(rr.msgId, rr)
			res := &smb2.ReadResponse{Data: []byte("payload")}
			pkt := make([]byte, res.Size())
			res.Encode(pkt)
			p := smb2.PacketCodec(pkt)
			p.SetMessageId(rr.msgId)
			p.SetSessionId(42)
			p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp := &recvPacket{pkt: pkt}

			// Cancel the request before the receiver tries to publish or copy.
			// The atomic state transition ensures the receiver sees cancellation
			// and never accesses or exposes the caller's buffer.
			rr.canceled.Store(true)
			rr.directState.Store(directStateCanceled)

			var sink []byte
			if decrypted {
				c.copyDecryptedReadPayload(rp)
			} else {
				sink, _ = c.directReadSink(pkt[:80], len(pkt)-80)
			}
			require.Nil(t, sink)
			require.Nil(t, rp.ext)
			require.Equal(t, bytes.Repeat([]byte{0xa5}, 32), rr.readBuf)
		})
	}
}

func TestConnDirectReadCancellationBeforeSinkPublication(t *testing.T) {
	require := require.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{t: cancelTransport{}, outstandingRequests: newOutstandingRequests()}
	rr := &outstandingRequest{
		msgId:      3,
		cmd:        smb2.SMB2_READ,
		ctx:        ctx,
		recv:       make(chan *recvPacket, 1),
		readBuf:    make([]byte, 32),
		directDone: make(chan struct{}),
	}
	c.outstandingRequests.set(rr.msgId, rr)
	cancel()

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		_, _ = c.recv(rr)
	}()

	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("canceled direct READ did not return")
	}
	require.True(rr.canceled.Load())
	require.Equal(directStateCanceled, rr.directState.Load())

	head, restSize := readResponseHead(rr.msgId, []byte("late payload"))
	sink, _ := c.directReadSink(head, restSize)
	require.Nil(sink)
}

func TestConnDirectReadCancellationAfterSinkPublicationWaits(t *testing.T) {
	require := require.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{t: cancelTransport{}, outstandingRequests: newOutstandingRequests()}
	rr := &outstandingRequest{
		msgId:      4,
		cmd:        smb2.SMB2_READ,
		ctx:        ctx,
		recv:       make(chan *recvPacket, 1),
		readBuf:    make([]byte, 32),
		directDone: make(chan struct{}),
	}
	c.outstandingRequests.set(rr.msgId, rr)

	want := []byte("direct payload")
	head, restSize := readResponseHead(rr.msgId, want)
	sink, _ := c.directReadSink(head, restSize)
	require.NotNil(sink)

	recvDone := make(chan struct{})
	var recvErr error
	go func() {
		defer close(recvDone)
		_, recvErr = c.recv(rr)
	}()
	cancel()

	select {
	case <-recvDone:
		t.Fatal("canceled direct READ returned before direct reception completed")
	case <-time.After(20 * time.Millisecond):
	}

	copy(sink, want)
	close(rr.directDone)

	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("canceled direct READ did not return")
	}
	require.IsType(&ContextError{}, recvErr)
	require.Equal(want, rr.readBuf[:len(want)])
}

func TestConnDecryptedDirectReadCancellationBeforeCopy(t *testing.T) {
	require := require.New(t)

	const (
		messageID uint64 = 5
		sessionID uint64 = 0xCAFE
	)

	buf := bytes.Repeat([]byte{0xa5}, 32)
	c := &conn{outstandingRequests: newOutstandingRequests()}
	c.session = &session{conn: c, sessionId: sessionID}
	rr := &outstandingRequest{msgId: messageID, readBuf: buf}
	c.outstandingRequests.set(messageID, rr)
	rr.canceled.Store(true)

	res := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			SessionId: sessionID,
		},
		Data: []byte("decrypted payload"),
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	p := smb2.PacketCodec(pkt)
	p.SetMessageId(messageID)
	rp := &recvPacket{pkt: pkt}

	c.copyDecryptedReadPayload(rp)
	require.Nil(rp.ext)
	require.Equal(bytes.Repeat([]byte{0xa5}, len(buf)), buf)
}

func TestConnDecryptedDirectReadCancellationDuringCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &conn{t: cancelTransport{}, outstandingRequests: newOutstandingRequests()}
	c.session = &session{conn: c, sessionId: 42, sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST}
	rr := &outstandingRequest{
		msgId:      7,
		cmd:        smb2.SMB2_READ,
		ctx:        ctx,
		recv:       make(chan *recvPacket, 1),
		readBuf:    make([]byte, 8<<20),
		directDone: make(chan struct{}),
	}
	c.outstandingRequests.set(rr.msgId, rr)
	res := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			SessionId: c.session.sessionId,
		},
		Data: make([]byte, len(rr.readBuf)),
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	smb2.PacketCodec(pkt).SetMessageId(rr.msgId)
	rp := &recvPacket{pkt: pkt}

	copyDone := make(chan struct{})
	go func() {
		c.copyDecryptedReadPayload(rp)
		rr.finishDirect()
		close(copyDone)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for rr.directState.Load() == directStateIdle {
		if time.Now().After(deadline) {
			t.Fatal("decrypted READ copy did not start")
		}
		runtime.Gosched()
	}
	cancel()
	_, err := c.recv(rr)
	// Reuse the caller's buffer immediately after cancellation returns.
	// Under -race, this must synchronize with the receiver's payload copy.
	rr.readBuf[0] = 0x5a
	<-copyDone
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, byte(0x5a), rr.readBuf[0])
	require.Equal(t, directStateCanceled, rr.directState.Load())
}

func TestConnCanceledDirectReadDoesNotWriteCallerBuffer(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	selected := make(chan struct{})
	c := &conn{
		t:                   &notifyingReadTransport{transport: direct(clientConn), selected: selected},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}
	t.Cleanup(func() { _ = c.close(nil) })
	go c.runReceiver()

	const messageID = 1
	ctx, cancel := context.WithCancel(context.Background())
	rr := &outstandingRequest{
		msgId:      messageID,
		cmd:        smb2.SMB2_READ,
		ctx:        ctx,
		recv:       make(chan *recvPacket, 1),
		readBuf:    make([]byte, 32),
		directDone: make(chan struct{}),
	}
	for i := range rr.readBuf {
		rr.readBuf[i] = 0xa5
	}
	c.outstandingRequests.set(messageID, rr)

	want := []byte("late payload")
	res := &smb2.ReadResponse{Data: want}
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := smb2.PacketCodec(resBuf)
	p.SetMessageId(messageID)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	serverDone := make(chan error, 1)
	go func() {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(resBuf)))
		if _, err := serverConn.Write(size[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := serverConn.Write(resBuf[:80]); err != nil {
			serverDone <- err
			return
		}
		<-selected

		cancelBuf, err := readMsg(direct(serverConn))
		if err == nil {
			cancelPacket := smb2.PacketCodec(cancelBuf)
			if cancelPacket.Command() != smb2.SMB2_CANCEL || cancelPacket.MessageId() != messageID {
				err = fmt.Errorf("unexpected cancel command %v id %v", cancelPacket.Command(), cancelPacket.MessageId())
			}
		}
		if _, writeErr := serverConn.Write(want); err == nil {
			err = writeErr
		}
		serverDone <- err
	}()

	recvDone := make(chan struct{})
	var recvErr error
	go func() {
		defer close(recvDone)
		_, recvErr = c.recv(rr)
	}()

	select {
	case <-selected:
	case <-time.After(time.Second):
		t.Fatal("direct READ payload was not selected")
	}

	cancel()
	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("canceled direct READ did not return")
	}
	require.IsType(&ContextError{}, recvErr)
	require.NoError(<-serverDone)

	// Reuse the caller's buffer immediately after cancellation returns.
	// Reception of the in-flight packet has completed, so no late writes occur.
	for i := range rr.readBuf {
		rr.readBuf[i] = 0x5a
	}

	require.Eventually(func() bool {
		_, ok := c.outstandingRequests.peek(messageID)
		return !ok
	}, time.Second, time.Millisecond)
	require.Equal(bytes.Repeat([]byte{0x5a}, len(rr.readBuf)), rr.readBuf)

	// Another request must still succeed on the same connection.
	echoCtx, echoCancel := context.WithTimeout(context.Background(), time.Second)
	defer echoCancel()
	echo := &outstandingRequest{msgId: 99, cmd: smb2.SMB2_ECHO,
		ctx: echoCtx, recv: make(chan *recvPacket, 1)}
	c.outstandingRequests.set(echo.msgId, echo)
	echoRes := &smb2.EchoResponse{}
	echoPacket := make([]byte, echoRes.Size())
	echoRes.Encode(echoPacket)
	smb2.PacketCodec(echoPacket).SetMessageId(echo.msgId)
	smb2.PacketCodec(echoPacket).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	_, err := direct(serverConn).Writev(echoPacket)
	require.NoError(err)
	got, err := c.recv(echo)
	require.NoError(err)
	got.close()
}

func TestConnDirectReadZeroCopy(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	selected := make(chan struct{})
	c := &conn{
		t:                   &notifyingReadTransport{transport: direct(clientConn), selected: selected},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}
	t.Cleanup(func() { _ = c.close(nil) })
	go c.runReceiver()

	const messageID = 2
	rr := &outstandingRequest{
		msgId:      messageID,
		cmd:        smb2.SMB2_READ,
		ctx:        context.Background(),
		recv:       make(chan *recvPacket, 1),
		readBuf:    make([]byte, 32),
		directDone: make(chan struct{}),
	}
	c.outstandingRequests.set(messageID, rr)

	want := []byte("direct payload")
	res := &smb2.ReadResponse{Data: want}
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := smb2.PacketCodec(resBuf)
	p.SetMessageId(messageID)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	serverDone := make(chan error, 1)
	go func() {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(resBuf)))
		if _, err := serverConn.Write(size[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := serverConn.Write(resBuf[:80]); err != nil {
			serverDone <- err
			return
		}
		<-selected
		_, err := serverConn.Write(want)
		serverDone <- err
	}()

	recvDone := make(chan struct{})
	var got *recvPacket
	var recvErr error
	go func() {
		defer close(recvDone)
		got, recvErr = c.recv(rr)
	}()

	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("direct READ did not return")
	}
	require.NoError(recvErr)
	require.NotNil(got)
	require.Equal(want, got.ext)
	require.Same(&rr.readBuf[0], &got.ext[0])
	require.Equal(want, rr.readBuf[:len(want)])
	require.NoError(<-serverDone)
	got.close()
}

func TestResponseReadSinkRejectsUnvalidatedRead(t *testing.T) {
	require := require.New(t)

	const (
		sessionID = uint64(0xCAFE)
		messageID = uint64(7)
	)

	makePacket := func(sessionID uint64, flags uint32) []byte {
		res := &smb2.ReadResponse{
			PacketHeader: smb2.PacketHeader{Flags: flags, SessionId: sessionID},
			Data:         []byte("payload"),
		}
		pkt := make([]byte, res.Size())
		res.Encode(pkt)
		p := smb2.PacketCodec(pkt)
		p.SetMessageId(messageID)
		return pkt
	}

	tests := []struct {
		name            string
		responseSession uint64
		flags           uint32
		requireEncrypt  bool
		requireSigning  bool
		useSession      bool
	}{
		{
			name:            "session mismatch",
			responseSession: sessionID + 1,
		},
		{
			name:           "encryption required",
			requireEncrypt: true,
		},
		{
			name:  "signed response",
			flags: smb2.SMB2_FLAGS_SIGNED,
		},
		{
			name:           "signing required",
			requireSigning: true,
		},
		{
			name:       "session in use without session",
			useSession: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xa5}, 32)
			c := &conn{
				dialect:             smb2.SMB311,
				outstandingRequests: newOutstandingRequests(),
				requireSigning:      test.requireSigning,
			}
			if test.useSession {
				c.enableSession()
			} else {
				c.session = &session{conn: c, sessionId: sessionID}
				c.enableSession()
			}
			c.outstandingRequests.set(messageID, &outstandingRequest{
				msgId:             messageID,
				readBuf:           buf,
				requireEncryption: test.requireEncrypt,
			})

			responseSession := test.responseSession
			if responseSession == 0 {
				responseSession = sessionID
			}
			pkt := makePacket(responseSession, smb2.SMB2_FLAGS_SERVER_TO_REDIR|test.flags)

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})
			writeDone := make(chan error, 1)
			go func() {
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(pkt)))
				if _, err := serverConn.Write(size[:]); err != nil {
					writeDone <- err
					return
				}
				_, err := serverConn.Write(pkt)
				writeDone <- err
			}()

			rp, err := direct(clientConn).ReadPacket(c.responseReadSink)
			writeErr := <-writeDone
			require.NoError(err)
			require.NoError(writeErr)
			require.NotNil(rp)
			require.Nil(rp.ext)
			require.Equal(pkt, rp.bytes())
			rp.close()
			require.Equal(bytes.Repeat([]byte{0xa5}, len(buf)), buf)
		})
	}
}

func TestTryDecryptCompressedDirectReadValidatesBeforeCopy(t *testing.T) {
	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			const (
				sessionID = uint64(0xCAFE)
				messageID = uint64(7)
			)
			want := bytes.Repeat([]byte("compressed encrypted payload "), 32)
			makePlain := func(innerSessionID uint64) []byte {
				res := &smb2.ReadResponse{
					PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR, SessionId: innerSessionID},
					Data:         want,
				}
				plain := make([]byte, res.Size())
				res.Encode(plain)
				smb2.PacketCodec(plain).SetMessageId(messageID)
				return plain
			}

			c := &conn{
				dialect:             smb2.SMB311,
				compressionIds:      []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
				maxReadSize:         uint32(len(want)),
				maxWriteSize:        uint32(len(want)),
				maxTransactSize:     uint32(len(want)),
				outstandingRequests: newOutstandingRequests(),
			}
			c.session = &session{
				conn:      c,
				sessionId: sessionID,
				decrypter: aead,
				encrypter: aead,
			}

			makeEncrypted := func(compressed []byte) *recvPacket {
				pkt, err := c.session.encrypt(compressed, make([]byte, 52+len(compressed)+aead.Overhead()))
				require.NoError(err)
				return &recvPacket{pkt: pkt}
			}

			badBuf := bytes.Repeat([]byte{0xa5}, len(want)+16)
			c.outstandingRequests.set(messageID, &outstandingRequest{
				msgId:      messageID,
				readBuf:    badBuf,
				directDone: make(chan struct{}),
			})
			bad := makeEncrypted(compressReadResponseForTest(t, makePlain(sessionID+1)))
			decoded, encrypted, err := c.tryDecrypt(bad)
			require.ErrorContains(err, "unknown session id")
			require.True(encrypted)
			require.Same(bad, decoded)
			require.Equal(bytes.Repeat([]byte{0xa5}, len(badBuf)), badBuf)

			goodBuf := bytes.Repeat([]byte{0xa5}, len(want)+16)
			goodRR := &outstandingRequest{
				msgId:      messageID,
				readBuf:    goodBuf,
				directDone: make(chan struct{}),
			}
			c.outstandingRequests.set(messageID, goodRR)
			good := makeEncrypted(compressReadResponseForTest(t, makePlain(sessionID)))
			decoded, encrypted, err = c.tryDecrypt(good)
			require.NoError(err)
			require.True(encrypted)
			require.Same(&goodBuf[0], &decoded.ext[0])
			require.Equal(want, goodBuf[:len(want)])
			require.NotEqual(directStateReading, goodRR.directState.Load())
		})
	}
}

func TestSessionSetupRejectsInvalidIntermediateResponse(t *testing.T) {
	// A malicious server can return a malformed SESSION_SETUP response with
	// STATUS_MORE_PROCESSING_REQUIRED. Because accept() skips packet validation
	// for the intermediate leg, sessionSetup must validate the response itself
	// (via SessionSetupResponseDecoder.IsInvalid) instead of decoding its fields.
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			// payload shorter than the fixed 8-byte part
			name:    "TruncatedPayload",
			payload: make([]byte, 2),
		},
		{
			// security buffer pointing far outside of the packet
			name: "SecurityBufferOutOfBounds",
			payload: func() []byte {
				payload := make([]byte, 8)
				binary.LittleEndian.PutUint16(payload[0:2], 9)      // StructureSize
				binary.LittleEndian.PutUint16(payload[4:6], 0xffff) // SecurityBufferOffset
				binary.LittleEndian.PutUint16(payload[6:8], 0xffff) // SecurityBufferLength
				return payload
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})

			st := direct(serverConn)

			go func() {
				// Read the client's SESSION_SETUP request and reply with a
				// malformed SESSION_SETUP response with
				// STATUS_MORE_PROCESSING_REQUIRED.
				buf, err := readMsg(st)
				if err != nil {
					return
				}
				p := smb2.PacketCodec(buf)

				respBuf := make([]byte, 64+len(test.payload))
				copy(respBuf[64:], test.payload)
				rp := smb2.PacketCodec(respBuf)
				rp.SetProtocolId()
				rp.SetStructureSize()
				rp.SetCommand(smb2.SMB2_SESSION_SETUP)
				rp.SetStatus(uint32(erref.STATUS_MORE_PROCESSING_REQUIRED))
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				rp.SetMessageId(p.MessageId())
				rp.SetCreditResponse(p.CreditRequest())
				rp.SetSessionId(0x1234)

				if _, err := st.Writev(respBuf); err != nil {
					return
				}
			}()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			_, err := sessionSetup(c, &NTLMInitiator{}, context.Background())
			require.Error(err)
			var ire *InvalidResponseError
			require.ErrorAs(err, &ire)
			require.Equal("broken session setup response format", ire.Message)
		})
	}
}

// stubDecrypter is a cipher.AEAD that "decrypts" ciphertext into a fixed
// plaintext, allowing tests to simulate arbitrary decrypted payloads.
type stubDecrypter struct {
	plaintext []byte
	err       error
}

func (d *stubDecrypter) NonceSize() int { return 11 }
func (d *stubDecrypter) Overhead() int  { return 16 }

func (d *stubDecrypter) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}

func (d *stubDecrypter) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	return append(dst, d.plaintext...), nil
}

func TestTryDecrypt(t *testing.T) {
	require := require.New(t)

	const sessionID uint64 = 0xCAFE

	// makeEncryptedPacket builds a packet with a valid transform header whose
	// encrypted payload will be "decrypted" by the stub decrypter.
	makeEncryptedPacket := func(encryptedData []byte) *recvPacket {
		pkt := make([]byte, 52+len(encryptedData))
		tc := smb2.TransformCodec(pkt)
		tc.SetProtocolId()
		tc.SetFlags(smb2.Encrypted)
		tc.SetOriginalMessageSize(uint32(len(encryptedData)))
		tc.SetSessionId(sessionID)
		copy(tc.EncryptedData(), encryptedData)
		return &recvPacket{pkt: pkt}
	}

	c := &conn{}
	c.session = &session{conn: c, sessionId: sessionID}

	t.Run("RejectsShortDecryptedPayload", func(t *testing.T) {
		c.session.decrypter = &stubDecrypter{plaintext: make([]byte, 30)} // shorter than SMB2 header

		rp := makeEncryptedPacket(make([]byte, 64))
		defer rp.close()

		var (
			res         *recvPacket
			isEncrypted bool
			errDecrypt  error
		)
		require.NotPanics(func() {
			res, isEncrypted, errDecrypt = c.tryDecrypt(rp)
		})

		require.Error(errDecrypt)
		var ire *InvalidResponseError
		require.ErrorAs(errDecrypt, &ire)
		require.Equal("broken decrypted packet format", ire.Message)
		require.False(isEncrypted)
		require.NotNil(res) // the caller is responsible for closing the returned packet
	})

	t.Run("RejectsOriginalMessageSizeMismatch", func(t *testing.T) {
		plaintext := make([]byte, 64)
		p := smb2.PacketCodec(plaintext)
		p.SetProtocolId()
		p.SetStructureSize()
		c.session.decrypter = &stubDecrypter{plaintext: plaintext}

		rp := makeEncryptedPacket(make([]byte, 80))
		tc := smb2.TransformCodec(rp.pkt)
		tc.SetOriginalMessageSize(81) // mismatch: len(pkt) == 52 + 80 != 52 + 81
		defer rp.close()

		_, isEncrypted, errDecrypt := c.tryDecrypt(rp)
		require.Error(errDecrypt)
		var ire *InvalidResponseError
		require.ErrorAs(errDecrypt, &ire)
		require.Equal("broken packet header format", ire.Message)
		require.False(isEncrypted)
	})

	t.Run("AcceptsValidDecryptedPacket", func(t *testing.T) {
		plaintext := make([]byte, 64)
		p := smb2.PacketCodec(plaintext)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		p.SetSessionId(sessionID)
		c.session.decrypter = &stubDecrypter{plaintext: plaintext}

		rp := makeEncryptedPacket(make([]byte, 80))
		defer rp.close()

		res, isEncrypted, errDecrypt := c.tryDecrypt(rp)
		defer res.close()

		require.NoError(errDecrypt)
		require.True(isEncrypted)
		require.Equal(plaintext, res.bytes())
	})

}

func TestTryDecryptDirectRead(t *testing.T) {
	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			const (
				sessionID uint64 = 0xCAFE
				messageID uint64 = 7
			)

			c := &conn{
				outstandingRequests: newOutstandingRequests(),
			}
			c.session = &session{
				conn:      c,
				sessionId: sessionID,
				decrypter: aead,
			}

			want := []byte("encrypted direct read payload")
			readBuf := make([]byte, len(want)+16)
			c.outstandingRequests.set(messageID, &outstandingRequest{
				msgId:   messageID,
				readBuf: readBuf,
			})

			res := &smb2.ReadResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					SessionId: sessionID,
				},
				Data: want,
			}
			plain := make([]byte, res.Size())
			res.Encode(plain)
			p := smb2.PacketCodec(plain)
			p.SetMessageId(messageID)

			pkt := make([]byte, 52+len(plain)+aead.Overhead())
			tc := smb2.TransformCodec(pkt)
			nonce := tc.Nonce()[:aead.NonceSize()]
			for i := range nonce {
				nonce[i] = byte(i + 1)
			}
			tc.SetProtocolId()
			tc.SetOriginalMessageSize(uint32(len(plain)))
			tc.SetFlags(smb2.Encrypted)
			tc.SetSessionId(sessionID)
			sealed := aead.Seal(pkt[:52], nonce, plain, tc.AssociatedData())
			copy(tc.Signature(), sealed[len(sealed)-aead.Overhead():])
			rp := &recvPacket{pkt: pkt[:52+len(plain)]}

			tampered := append([]byte(nil), rp.pkt...)
			tampered[4] ^= 1
			_, _, err := c.tryDecrypt(&recvPacket{pkt: tampered})
			require.Error(err)
			require.Equal(make([]byte, len(readBuf)), readBuf)

			decoded, encrypted, err := c.tryDecrypt(rp)
			require.NoError(err)
			require.True(encrypted)
			require.Same(&pkt[52], &decoded.pkt[0])
			require.Same(&readBuf[0], &decoded.ext[0])
			require.Equal(want, decoded.ext)
			require.Equal(want, readBuf[:len(want)])
		})
	}
}

func TestSessionNilEncrypterDecrypter(t *testing.T) {
	require := require.New(t)

	s := &session{}

	require.NotPanics(func() {
		_, err := s.encrypt(nil, make([]byte, 52))
		var ire *InternalError
		require.ErrorAs(err, &ire)
		require.Equal("encryption required but no cipher negotiated", ire.Message)
	})

	require.NotPanics(func() {
		_, err := s.decrypt(nil)
		var ire *InternalError
		require.ErrorAs(err, &ire)
		require.Equal("decryption required but no cipher negotiated", ire.Message)
	})
}

// panicTransport is a mock transport whose Read panics, simulating a
// malformed packet triggering an unexpected panic inside the receiver.
type panicTransport struct {
	closed chan struct{}
}

func (t *panicTransport) Writev(p ...[]byte) (int, error) {
	return 0, net.ErrClosed
}

func (t *panicTransport) SetWriteDeadline(time.Time) error { return nil }

func (t *panicTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	panic("malformed packet")
}

func (t *panicTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func TestRunReceiverPanicClosesTransport(t *testing.T) {
	require := require.New(t)

	mt := &panicTransport{closed: make(chan struct{})}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runReceiver()
	}()

	select {
	case <-mt.closed:
		// transport was closed by the receiver after recovering from the panic
	case <-time.After(2 * time.Second):
		t.Fatal("transport was not closed after receiver panic")
	}
	<-done

	c.m.Lock()
	err := c.err
	c.m.Unlock()
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Contains(ire.Message, "receiver panic")
}

// readErrorTransport is a mock transport whose reads fail immediately,
// simulating a broken transport that terminates the receiver loop.
type readErrorTransport struct {
	readErr error
	closed  chan struct{}
}

func (t *readErrorTransport) Writev(p ...[]byte) (int, error) {
	return 0, t.readErr
}

func (t *readErrorTransport) SetWriteDeadline(time.Time) error { return nil }

func (t *readErrorTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	return nil, t.readErr
}

func (t *readErrorTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func TestRunReceiverReadErrorClosesTransport(t *testing.T) {
	require := require.New(t)

	mt := &readErrorTransport{
		readErr: fmt.Errorf("simulated read failure"),
		closed:  make(chan struct{}),
	}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runReceiver()
	}()

	select {
	case <-mt.closed:
		// transport was closed by the receiver after a read error
	case <-time.After(2 * time.Second):
		t.Fatal("transport was not closed after receiver read error")
	}
	<-done

	c.m.Lock()
	err := c.err
	c.m.Unlock()
	require.Error(err)
	var te *TransportError
	require.ErrorAs(err, &te)
	require.ErrorIs(err, mt.readErr)
}

type invalidPacketTransport struct {
	closed chan struct{}
	stop   chan struct{}
	once   sync.Once
}

func (t *invalidPacketTransport) Writev(p ...[]byte) (int, error) {
	return 0, net.ErrClosed
}

func (t *invalidPacketTransport) SetWriteDeadline(time.Time) error { return nil }

func (t *invalidPacketTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	select {
	case <-t.stop:
		return nil, io.EOF
	default:
		return allocRecvPacket(64), nil
	}
}

func (t *invalidPacketTransport) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.stop)
	})
	return nil
}

func TestRunReceiverInvalidPacketBeforeSessionClosesTransport(t *testing.T) {
	require := require.New(t)

	mt := &invalidPacketTransport{
		closed: make(chan struct{}),
		stop:   make(chan struct{}),
	}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runReceiver()
	}()

	select {
	case <-mt.closed:
		// transport was closed after the invalid pre-session packet
	case <-time.After(2 * time.Second):
		t.Fatal("transport was not closed after an invalid pre-session packet")
	}
	<-done

	c.m.Lock()
	err := c.err
	c.m.Unlock()
	require.Error(err)
	var ire *InvalidResponseError
	require.ErrorAs(err, &ire)
	require.Equal("invalid packet header", ire.Message)
}

// errorTransport is a mock transport whose Write always fails, simulating a
// broken connection (partial or failed write).
type errorTransport struct {
	writeErr error
	closed   chan struct{}
}

type countingWriteTransport struct {
	writes int
	closes int
}

func (t *countingWriteTransport) Writev(p ...[]byte) (int, error) {
	t.writes++
	var n int
	for _, part := range p {
		n += len(part)
	}
	return n, nil
}

func (t *countingWriteTransport) SetWriteDeadline(time.Time) error { return nil }

func (t *countingWriteTransport) ReadPacket(...directSinkFinder) (*recvPacket, error) {
	return nil, io.EOF
}

func (t *countingWriteTransport) Close() error {
	t.closes++
	return nil
}

func (t *errorTransport) Writev(p ...[]byte) (int, error) {
	return 0, t.writeErr
}

func (t *errorTransport) SetWriteDeadline(time.Time) error { return nil }

func (t *errorTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	return nil, t.writeErr
}

func (t *errorTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func TestConnWriteFailure(t *testing.T) {
	require := require.New(t)

	mt := &errorTransport{
		writeErr: fmt.Errorf("simulated write failure"),
		closed:   make(chan struct{}),
	}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
	}

	_, err := c.send(context.Background(), false, &smb2.EchoRequest{})
	require.Error(err)
	var te *TransportError
	require.ErrorAs(err, &te)
	require.ErrorIs(err, mt.writeErr)

	// the connection must be marked as broken
	c.m.Lock()
	connErr := c.err
	c.m.Unlock()
	require.Error(connErr)
	require.ErrorIs(connErr, mt.writeErr)

	// the underlying transport must be closed
	select {
	case <-mt.closed:
	default:
		t.Fatal("transport was not closed after write failure")
	}

	// subsequent sends fail immediately with the recorded error
	_, err = c.send(context.Background(), false, &smb2.EchoRequest{})
	require.Error(err)
	require.ErrorIs(err, mt.writeErr)
}

func TestConnSendWriteDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	c := &conn{
		t:                   direct(client),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		writeTimeout:        10 * time.Millisecond,
	}

	_, err := c.send(context.Background(), false, &smb2.EchoRequest{})
	if err == nil {
		t.Fatal("send() expected write deadline error, got nil")
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("send() error = %T, want *TransportError", err)
	}
	require.Error(t, c.err)
	require.True(t, c.account.closed)

}

func TestConnSendCancellationWaitsForFrameCompletion(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("deadline-%t/partial-%t", deadline, partial), func(t *testing.T) {
				testConnSendCancellationDuringFrame(t, deadline, partial)
			})
		}
	}
}

func testConnSendCancellationDuringFrame(t *testing.T, deadline bool, partial bool) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
		rdone:               make(chan struct{}, 1),
		writeTimeout:        time.Second,
	}
	go c.runReceiver()
	t.Cleanup(func() {
		_ = c.close(nil)
		_ = serverConn.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	if deadline {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	}
	defer cancel()
	require.NoError(serverConn.SetDeadline(time.Now().Add(3 * time.Second)))

	type sendResult struct {
		rrs []*outstandingRequest
		err error
	}
	sendDone := make(chan sendResult, 1)
	go func() {
		rrs, err := c.send(ctx, false, &smb2.EchoRequest{})
		sendDone <- sendResult{rrs: rrs, err: err}
	}()

	// Observing the transport header proves send has borrowed credits and
	// entered Writev before cancellation. Optionally consume payload too.
	var header [4]byte
	_, err := io.ReadFull(serverConn, header[:])
	require.NoError(err)
	reqBuf := make([]byte, int(binary.BigEndian.Uint32(header[:])))
	prefix := 0
	if partial {
		prefix = 1
		_, err = io.ReadFull(serverConn, reqBuf[:prefix])
		require.NoError(err)
	}
	if !deadline {
		cancel()
	}
	<-ctx.Done()
	select {
	case <-sendDone:
		t.Fatal("send returned before the frame was completed")
	default:
	}
	c.account.m.Lock()
	require.False(c.account.closed)
	require.Zero(c.account.availableCredits)
	require.Equal(uint16(1), c.account.inFlightCredits)
	c.account.m.Unlock()

	releaseResponse := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		st := direct(serverConn)

		_, err := io.ReadFull(serverConn, reqBuf[prefix:])
		if err != nil {
			serverDone <- err
			return
		}
		req := smb2.PacketCodec(reqBuf)
		expected := &smb2.EchoRequest{}
		expected.SetMessageId(req.MessageId())
		expected.SetCreditRequest(10)
		want := make([]byte, expected.Size())
		expected.Encode(want)
		if !bytes.Equal(want, reqBuf) {
			serverDone <- fmt.Errorf("request frame changed during cancellation")
			return
		}

		cancelBuf, err := readMsg(st)
		if err != nil {
			serverDone <- err
			return
		}
		cancelPkt := smb2.PacketCodec(cancelBuf)
		if cancelPkt.Command() != smb2.SMB2_CANCEL || cancelPkt.MessageId() != req.MessageId() {
			serverDone <- fmt.Errorf("unexpected cancel command %v id %v", cancelPkt.Command(), cancelPkt.MessageId())
			return
		}

		writeEchoResponse := func(messageID uint64) error {
			res := &smb2.EchoResponse{}
			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			resPkt := smb2.PacketCodec(resBuf)
			resPkt.SetMessageId(messageID)
			resPkt.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			resPkt.SetCreditResponse(1)
			_, err := st.Writev(resBuf)
			return err
		}

		<-releaseResponse
		if err := writeEchoResponse(req.MessageId()); err != nil {
			serverDone <- err
			return
		}

		secondReq, err := readMsg(st)
		if err != nil {
			serverDone <- err
			return
		}
		if smb2.PacketCodec(secondReq).Command() != smb2.SMB2_ECHO {
			serverDone <- fmt.Errorf("expected follow-up ECHO, got another command")
			return
		}
		if err := writeEchoResponse(smb2.PacketCodec(secondReq).MessageId()); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	var result sendResult
	select {
	case result = <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("send did not finish after the transport resumed reading")
	}
	require.NoError(result.err)
	require.Len(result.rrs, 1)

	_, recvErr := c.recv(result.rrs[0])
	require.Error(recvErr)
	require.IsType(&ContextError{}, recvErr)

	c.account.m.Lock()
	require.Zero(c.account.availableCredits)
	require.Equal(uint16(1), c.account.inFlightCredits)
	c.account.m.Unlock()
	_, outstanding := c.outstandingRequests.peek(result.rrs[0].msgId)
	require.True(outstanding)
	close(releaseResponse)

	secondRrs, err := c.send(context.Background(), false, &smb2.EchoRequest{})
	require.NoError(err)
	_, err = c.recv(secondRrs[0])
	require.NoError(err)

	select {
	case err := <-serverDone:
		require.NoError(err)
	case <-time.After(time.Second):
		t.Fatal("server did not observe the request, cancel, and follow-up request")
	}

	c.m.Lock()
	require.NoError(c.err)
	c.m.Unlock()
	c.account.m.Lock()
	require.False(c.account.closed)
	require.Zero(c.account.inFlightCredits)
	c.account.m.Unlock()
}

func TestConnSendCanceledBeforeWriteUnloansOnce(t *testing.T) {
	require := require.New(t)

	mt := &countingWriteTransport{}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Block send after loan, so the pre-write cancellation must unloan.
	c.m.Lock()
	sendDone := make(chan error, 1)
	go func() {
		_, err := c.send(ctx, false, &smb2.EchoRequest{})
		sendDone <- err
	}()
	<-c.account.notify
	c.account.m.Lock()
	require.Zero(c.account.availableCredits)
	require.Equal(uint16(1), c.account.inFlightCredits)
	c.account.m.Unlock()
	cancel()
	c.m.Unlock()

	err := <-sendDone
	require.Error(err)
	require.IsType(&ContextError{}, err)
	require.Zero(mt.writes)

	c.account.m.Lock()
	require.Equal(uint16(1), c.account.availableCredits)
	require.Zero(c.account.inFlightCredits)
	c.account.m.Unlock()
}

func TestMaxCreditSize32BitOverflow(t *testing.T) {
	require := require.New(t)

	c := &conn{account: openAccount(65535)}
	c.account.maxCredits = 65535

	size := c.maxCreditSize()
	require.Positive(size)
	require.LessOrEqual(size, winMaxPayloadSize)
}

func TestConnTryHandleCancelRaceClosesOrphanPacket(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr := &outstandingRequest{
		msgId: 1,
		cmd:   smb2.SMB2_ECHO,
		ctx:   ctx,
		recv:  make(chan *recvPacket, 1),
	}
	c.outstandingRequests.set(rr.msgId, rr)

	echoRes := &smb2.EchoResponse{}
	resBuf := make([]byte, echoRes.Size())
	echoRes.Encode(resBuf)
	p := smb2.PacketCodec(resBuf)
	p.SetMessageId(rr.msgId)
	p.SetStatus(uint32(erref.STATUS_SUCCESS))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	rp := allocRecvPacket(len(resBuf))
	copy(rp.pkt, resBuf)
	buf := rp.buf

	// Occupy rr.recv so that tryHandle blocks on the channel send right
	// after its canceled check, reproducing the race window where
	// conn.recv takes the ctx.Done() branch before the response is sent.
	filler := allocRecvPacket(1)
	rr.recv <- filler

	tryDone := make(chan struct{})
	go func() {
		defer close(tryDone)
		_ = c.tryHandle(rp, nil)
	}()

	// Give tryHandle time to pass its canceled check and block on the send.
	time.Sleep(50 * time.Millisecond)

	// Emulate conn.recv taking the ctx.Done() branch: mark the request as
	// canceled, then drain and close whatever the channel holds.
	cancel()
	rr.canceled.Store(true)
	select {
	case orphan := <-rr.recv:
		require.Same(filler, orphan)
		orphan.close()
	default:
		t.Fatal("expected filler packet to be still queued in rr.recv")
	}

	<-tryDone

	// tryHandle must notice the cancellation after its send and close the
	// response; otherwise the underlying buffer leaks.
	require.Equal(int32(0), buf.refCount.Load(), "response packet leaked after cancellation race")

	select {
	case orphan := <-rr.recv:
		require.Fail("packet left unconsumed in rr.recv", "packet length %d", len(orphan.pkt))
	default:
	}
}

func TestConnPendingAsyncIdRaceWithSendCancel(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Drain the SMB2_CANCEL requests emitted by sendCancel so its writes
	// never block while conn.m is held.
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}

	const asyncId = uint64(0xABCD)

	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())

		rr := &outstandingRequest{
			msgId: uint64(i) + 1,
			cmd:   smb2.SMB2_ECHO,
			ctx:   ctx,
			recv:  make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(rr.msgId, rr)

		pendingRes := &smb2.EchoResponse{}
		resBuf := make([]byte, pendingRes.Size())
		pendingRes.Encode(resBuf)
		p := smb2.PacketCodec(resBuf)
		p.SetMessageId(rr.msgId)
		p.SetStatus(uint32(erref.STATUS_PENDING))
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
		p.SetAsyncId(asyncId)

		rp := allocRecvPacket(len(resBuf))
		copy(rp.pkt, resBuf)

		recvDone := make(chan struct{})
		go func() {
			defer close(recvDone)
			_, _ = c.recv(rr)
		}()

		// Let c.recv block on the select.
		time.Sleep(2 * time.Millisecond)

		tryDone := make(chan struct{})
		go func() {
			defer close(tryDone)
			_ = c.tryHandle(rp, nil)
		}()

		// Let tryHandle adopt rr.asyncId while the context is still alive.
		time.Sleep(20 * time.Millisecond)

		// Canceling afterwards spawns sendCancel from the ctx.Done() branch,
		// which reads rr.asyncId concurrently with the store made by the
		// STATUS_PENDING branch of tryHandle in another goroutine.
		cancel()

		<-tryDone
		<-recvDone
	}
}

func TestConnPendingWithoutAsyncCommandFlagIgnoresAsyncId(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}

	const msgId = uint64(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr := &outstandingRequest{
		msgId: msgId,
		cmd:   smb2.SMB2_ECHO,
		ctx:   ctx,
		recv:  make(chan *recvPacket, 1),
	}
	c.outstandingRequests.set(rr.msgId, rr)

	// Synchronous STATUS_PENDING interim response: no
	// SMB2_FLAGS_ASYNC_COMMAND, so the async id field actually carries the
	// tree id. It must not be adopted as an async id.
	pendingRes := &smb2.EchoResponse{}
	resBuf := make([]byte, pendingRes.Size())
	pendingRes.Encode(resBuf)
	p := smb2.PacketCodec(resBuf)
	p.SetMessageId(msgId)
	p.SetStatus(uint32(erref.STATUS_PENDING))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetTreeId(0x1234)

	rp := allocRecvPacket(len(resBuf))
	copy(rp.pkt, resBuf)

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		_, _ = c.recv(rr)
	}()

	// Let c.recv block on the select.
	time.Sleep(2 * time.Millisecond)

	require.NoError(c.tryHandle(rp, nil))
	require.Zero(rr.asyncId.Load())

	// The cancel request emitted afterwards must remain synchronous: no
	// SMB2_FLAGS_ASYNC_COMMAND and no async id.
	cancelRes := make(chan smb2.PacketCodec, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		st := direct(serverConn)
		cancelBuf, err := readMsg(st)
		if err != nil {
			return
		}
		cancelRes <- smb2.PacketCodec(cancelBuf)
	}()

	cancel()
	<-recvDone
	<-serverDone

	select {
	case pCancel := <-cancelRes:
		require.Equal(smb2.SMB2_CANCEL, pCancel.Command())
		require.Equal(msgId, pCancel.MessageId())
		require.Zero(pCancel.Flags() & smb2.SMB2_FLAGS_ASYNC_COMMAND)
	default:
		t.Fatal("no cancel request was sent")
	}
}

// TestConnPendingAsyncIdSurvivesRecvBufReuse drives tryHandle with standalone
// small STATUS_PENDING responses while another goroutine continuously
// allocates, overwrites, and releases same-sized receive buffers from the pool.
// The pending branch must read the SMB2 header while it still owns the buffer;
// otherwise a released buffer can be reused and overwrite the AsyncId, which is
// then adopted into rr.asyncId ([MS-SMB2] 3.3.4.2). Each final async response is
// checked through treeConn.recv, which rejects a request whose stored async id
// no longer matches.
func TestConnPendingAsyncIdSurvivesRecvBufReuse(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Drain any SMB2_CANCEL written by sendCancel so it cannot block.
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}

	const (
		sessionId  = uint64(0x55)
		treeId     = uint32(0x66)
		iterations = 250
	)

	s := &session{conn: c, sessionId: sessionId}
	tc := &treeConn{session: s, treeId: treeId}

	pendingRes := &smb2.ErrorResponse{CommandCode: smb2.SMB2_ECHO}
	pendingBuf := make([]byte, pendingRes.Size())
	pendingRes.Encode(pendingBuf)

	finalRes := &smb2.EchoResponse{}
	finalBuf := make([]byte, finalRes.Size())
	finalRes.Encode(finalBuf)

	// Legitimately churn same-sized buffers through the shared pool. The
	// goroutine only touches buffers it acquires itself, never the packets
	// handed to tryHandle.
	start := make(chan struct{})
	stop := make(chan struct{})
	reuseDone := make(chan struct{})
	go func() {
		defer close(reuseDone)
		<-start
		for {
			select {
			case <-stop:
				return
			default:
			}
			rp := allocRecvPacket(len(pendingBuf))
			for i := range rp.pkt {
				rp.pkt[i] = 0xFF
			}
			rp.close()
		}
	}()
	close(start)
	defer func() {
		close(stop)
		<-reuseDone
	}()

	for i := 0; i < iterations; i++ {
		msgId := uint64(i) + 1
		asyncId := uint64(0x1000) + uint64(i)

		ctx, cancel := context.WithCancel(context.Background())
		rr := &outstandingRequest{
			msgId: msgId,
			cmd:   smb2.SMB2_ECHO,
			ctx:   ctx,
			recv:  make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(msgId, rr)

		rp := allocRecvPacket(len(pendingBuf))
		copy(rp.pkt, pendingBuf)
		p := rp.codec()
		p.SetMessageId(msgId)
		p.SetStatus(uint32(erref.STATUS_PENDING))
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
		p.SetAsyncId(asyncId)

		require.NoError(c.tryHandle(rp, nil))
		require.Equal(asyncId, rr.asyncId.Load())

		stored, ok := c.outstandingRequests.peek(msgId)
		require.True(ok, "pending request must stay outstanding")
		require.Same(rr, stored)

		// Deliver the matching final async response through the receive
		// path, then let treeConn.recv verify it against the adopted
		// rr.asyncId.
		frp := allocRecvPacket(len(finalBuf))
		copy(frp.pkt, finalBuf)
		fp := frp.codec()
		fp.SetMessageId(msgId)
		fp.SetSessionId(sessionId)
		fp.SetStatus(uint32(erref.STATUS_SUCCESS))
		fp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
		fp.SetAsyncId(asyncId)
		require.NoError(c.tryHandle(frp, nil))

		res, err := tc.recv(rr)
		require.NoError(err)
		res.close()

		_, ok = c.outstandingRequests.peek(msgId)
		require.False(ok, "final response must complete the request")

		cancel()
	}

}

func TestTreeConnEncryptionPolicyIsStoredForCancel(t *testing.T) {
	for _, policy := range []string{"session", "share"} {
		t.Run(policy, func(t *testing.T) {
			require := require.New(t)
			mt := &countingWriteTransport{}
			c := &conn{
				t:                   mt,
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(1),
			}
			s := &session{
				conn:      c,
				sessionId: 0xCAFE,
				encrypter: newGCM(make([]byte, 16)),
			}
			c.session = s
			tc := &treeConn{session: s}
			if policy == "session" {
				s.sessionFlags = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
			} else {
				tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
			}

			rrs, err := tc.send(context.Background(), &smb2.EchoRequest{})
			require.NoError(err)
			require.Len(rrs, 1)
			require.True(rrs[0].requireEncryption)
		})
	}
}

func TestConnSendCancelEncryptsRequiredRequest(t *testing.T) {
	for _, policy := range []string{"session", "share"} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/async-%t", policy, async), func(t *testing.T) {
				require := require.New(t)
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()
				defer serverConn.Close()

				const (
					messageID uint64 = 0x1234
					sessionID uint64 = 0xCAFE
					asyncID   uint64 = 0xABCD
				)
				aead := newGCM(make([]byte, 16))
				c := &conn{
					t:                   &countingWriteTransport{},
					account:             openAccount(1),
					outstandingRequests: newOutstandingRequests(),
				}
				s := &session{
					conn:      c,
					sessionId: sessionID,
					encrypter: aead,
					decrypter: aead,
				}
				c.session = s
				tc := &treeConn{session: s}
				if policy == "session" {
					s.sessionFlags = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
				} else {
					tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
				}
				rrs, err := tc.send(context.Background(), &smb2.EchoRequest{})
				require.NoError(err)
				rr := rrs[0]
				require.True(rr.requireEncryption)
				rr.msgId = messageID
				c.t = direct(clientConn)

				if async {
					rr.asyncId.Store(asyncID)
				}

				sendDone := make(chan struct{})
				go func() {
					c.sendCancel(rr)
					close(sendDone)
				}()

				wire, err := readMsg(direct(serverConn))
				require.NoError(err)
				require.Equal([]byte(smb2.MAGIC2), wire[:4])
				transform := smb2.TransformCodec(wire)
				require.Equal(uint16(smb2.Encrypted), transform.Flags())
				require.Equal(sessionID, transform.SessionId())

				plain, err := s.decrypt(wire)
				require.NoError(err)
				p := smb2.PacketCodec(plain)
				require.Equal(smb2.SMB2_CANCEL, p.Command())
				require.Equal(messageID, p.MessageId())
				require.Zero(p.Flags() & smb2.SMB2_FLAGS_SIGNED)
				require.Equal(sessionID, p.SessionId())
				if async {
					require.NotZero(p.Flags() & smb2.SMB2_FLAGS_ASYNC_COMMAND)
					require.Equal(asyncID, p.AsyncId())
				} else {
					require.Zero(p.Flags() & smb2.SMB2_FLAGS_ASYNC_COMMAND)
				}
				<-sendDone
			})
		}
	}
}

func TestConnSendCancelEncryptionFailureDoesNotFallback(t *testing.T) {
	require := require.New(t)
	mt := &countingWriteTransport{}
	c := &conn{
		t:                   mt,
		outstandingRequests: newOutstandingRequests(),
	}
	c.session = &session{conn: c, sessionId: 0xCAFE}

	c.sendCancel(&outstandingRequest{msgId: 1, requireEncryption: true})
	c.session = nil
	c.sendCancel(&outstandingRequest{msgId: 2, requireEncryption: true})

	require.Zero(mt.writes)
	require.Zero(mt.closes)
	c.m.Lock()
	require.NoError(c.err)
	c.m.Unlock()
}

func TestConnSendCancelSignsUnencryptedRequest(t *testing.T) {
	require := require.New(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	block, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)
	verifyBlock, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)
	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		requireSigning:      true,
	}
	s := &session{
		conn:      c,
		sessionId: 0xCAFE,
		signer:    cmac.New(block),
		verifier:  cmac.New(verifyBlock),
	}
	c.session = s

	sendDone := make(chan struct{})
	go func() {
		c.sendCancel(&outstandingRequest{msgId: 1})
		close(sendDone)
	}()

	wire, err := readMsg(direct(serverConn))
	require.NoError(err)
	require.NotEqual([]byte(smb2.MAGIC2), wire[:4])
	p := smb2.PacketCodec(wire)
	require.Equal(smb2.SMB2_CANCEL, p.Command())
	require.NotZero(p.Flags() & smb2.SMB2_FLAGS_SIGNED)
	require.True(s.verify(wire))
	<-sendDone
}

func TestConnTryHandlePendingReRegistersCanceledRequest(t *testing.T) {
	require := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}

	// Loan a credit for the request so it is tracked in inFlightCredits.
	req := &smb2.EchoRequest{}
	msgIds, totalCreditCharge, err := c.account.loan(context.Background(), req)
	require.NoError(err)
	require.Equal(uint16(1), totalCreditCharge)

	rr := &outstandingRequest{
		msgId:        msgIds[0],
		cmd:          smb2.SMB2_ECHO,
		ctx:          context.Background(),
		recv:         make(chan *recvPacket, 1),
		creditCharge: totalCreditCharge,
	}
	c.outstandingRequests.set(rr.msgId, rr)

	// The caller gives up while the request is still in flight.
	rr.canceled.Store(true)

	// A STATUS_PENDING interim response arrives for the canceled request.
	pendingRes := &smb2.EchoResponse{}
	pendingBuf := make([]byte, pendingRes.Size())
	pendingRes.Encode(pendingBuf)
	p := smb2.PacketCodec(pendingBuf)
	p.SetMessageId(rr.msgId)
	p.SetStatus(uint32(erref.STATUS_PENDING))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	rp := allocRecvPacket(len(pendingBuf))
	copy(rp.pkt, pendingBuf)
	require.NoError(c.tryHandle(rp, nil))

	// The canceled request must be re-registered so the final response can
	// still be routed back to it.
	popped, ok := c.outstandingRequests.pop(rr.msgId)
	require.True(ok, "canceled request must be re-registered after STATUS_PENDING")
	require.Equal(rr, popped)
	c.outstandingRequests.set(rr.msgId, rr)

	// The final response arrives.
	finalRes := &smb2.EchoResponse{}
	finalBuf := make([]byte, finalRes.Size())
	finalRes.Encode(finalBuf)
	p = smb2.PacketCodec(finalBuf)
	p.SetMessageId(rr.msgId)
	p.SetStatus(uint32(erref.STATUS_SUCCESS))
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

	rp = allocRecvPacket(len(finalBuf))
	copy(rp.pkt, finalBuf)
	require.NoError(c.tryHandle(rp, nil))

	c.account.m.Lock()
	inFlight := c.account.inFlightCredits
	c.account.m.Unlock()
	require.Zero(inFlight, "in-flight credits must be returned when the canceled request is resolved")
}

func TestAllocEncodeBufSetsLengthToRequestedSize(t *testing.T) {
	require := require.New(t)

	const size = 512

	c := &conn{}

	// new allocation
	pkt := c.allocEncodeBuf(size)
	require.Len(pkt, size)
	// the reusable buffer itself must be trimmed to the requested size,
	// otherwise the preauth integrity hash would be computed over
	// zero-padded bytes beyond the encoded packet.
	require.Len(c.encodeBuf, size)

	// existing buffer reuse
	pkt = c.allocEncodeBuf(size)
	require.Len(pkt, size)
	require.Len(c.encodeBuf, size)
}

func TestNegotiatorMakeRequest(t *testing.T) {
	require := require.New(t)

	t.Run("SMB202ClearsCapabilities", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.SMB202,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Zero(req.Capabilities)
	})

	t.Run("SMB210ClearsCapabilities", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.SMB210,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Zero(req.Capabilities)
	})

	for _, dialect := range []uint16{smb2.SMB300, smb2.SMB302} {
		t.Run(fmt.Sprintf("SMB%XHasNoContexts", dialect), func(t *testing.T) {
			req, err := (&Negotiator{SpecifiedDialect: dialect}).makeRequest()
			require.NoError(err)
			require.Empty(req.Contexts)
		})
	}

	t.Run("SMB311HasHashAndCipherContexts", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.SMB311,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Len(req.Contexts, 3)

		hc, ok := req.Contexts[0].(*smb2.HashContext)
		require.True(ok, "first context should be *smb2.HashContext")
		require.Equal(clientHashAlgorithms, hc.HashAlgorithms)
		require.Len(hc.HashSalt, 32)

		cc, ok := req.Contexts[1].(*smb2.CipherContext)
		require.True(ok, "second context should be *smb2.CipherContext")
		require.Equal(clientCiphers, cc.Ciphers)

		compression, ok := req.Contexts[2].(*smb2.CompressionContext)
		require.True(ok, "third context should be *smb2.CompressionContext")
		require.Equal(clientCompressionAlgorithms, compression.CompressionAlgorithms)
		require.Zero(compression.Flags)
	})

	t.Run("UnknownSMBHasHashAndCipherContexts", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.UnknownSMB,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Len(req.Contexts, 3)

		hc, ok := req.Contexts[0].(*smb2.HashContext)
		require.True(ok, "first context should be *smb2.HashContext")
		require.Equal(clientHashAlgorithms, hc.HashAlgorithms)
		require.Len(hc.HashSalt, 32)

		cc, ok := req.Contexts[1].(*smb2.CipherContext)
		require.True(ok, "second context should be *smb2.CipherContext")
		require.Equal(clientCiphers, cc.Ciphers)

		compression, ok := req.Contexts[2].(*smb2.CompressionContext)
		require.True(ok, "third context should be *smb2.CompressionContext")
		require.Equal(clientCompressionAlgorithms, compression.CompressionAlgorithms)
		require.Zero(compression.Flags)
	})
}

func TestRunReceiverFatalErrors(t *testing.T) {
	require := require.New(t)

	const (
		validSessionID   uint64 = 0xCAFE
		unknownSessionID uint64 = 0xDEAD
		msgID            uint64 = 1
	)

	runFatalTest := func(t *testing.T, packetToSend []byte, decrypter cipher.AEAD, expectedErrSubstr string, compressed ...bool) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(10),
			rdone:               make(chan struct{}, 1),
		}
		if len(compressed) > 0 && compressed[0] {
			c.dialect = smb2.SMB311
			c.compressionIds = []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4}
		}
		c.enableSession()
		c.session = &session{conn: c, sessionId: validSessionID, decrypter: decrypter}

		rr := &outstandingRequest{
			msgId: msgID,
			ctx:   context.Background(),
			recv:  make(chan *recvPacket, 1),
		}
		c.outstandingRequests.set(msgID, rr)

		done := make(chan struct{})
		go func() {
			defer close(done)
			c.runReceiver()
		}()

		st := direct(serverConn)
		_, err := st.Writev(packetToSend)
		require.NoError(err)

		select {
		case rp, ok := <-rr.recv:
			if ok && rp != nil {
				rp.close()
				t.Fatal("expected request to fail, but received packet")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for outstanding request to fail")
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for receiver loop to exit")
		}

		c.m.Lock()
		connErr := c.err
		c.m.Unlock()
		require.Error(connErr)
		if expectedErrSubstr != "" {
			require.Contains(connErr.Error(), expectedErrSubstr)
		}
		require.Error(rr.err)
	}

	makeCompound := func(sessionIDs ...uint64) []byte {
		compound := make([]byte, 64*len(sessionIDs))
		for i, sessionID := range sessionIDs {
			p := smb2.PacketCodec(compound[i*64:])
			p.SetProtocolId()
			p.SetStructureSize()
			p.SetCommand(smb2.SMB2_ECHO)
			p.SetMessageId(uint64(i + 1))
			p.SetSessionId(sessionID)
			if i+1 < len(sessionIDs) {
				p.SetNextCommand(64)
			}
		}
		return compound
	}

	block, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)
	aead, err := cipher.NewGCM(block)
	require.NoError(err)
	makeEncryptedPacket := func(plaintext []byte) []byte {
		s := &session{sessionId: validSessionID, encrypter: aead}
		pkt, err := s.encrypt(plaintext, make([]byte, 52+len(plaintext)+aead.Overhead()))
		require.NoError(err)
		return pkt
	}

	t.Run("BrokenTransformHeader", func(t *testing.T) {
		bogus := make([]byte, 64)
		runFatalTest(t, bogus, nil, "broken packet header format")
	})

	t.Run("UnknownSessionIDEncrypted", func(t *testing.T) {
		pkt := make([]byte, 52+64)
		tc := smb2.TransformCodec(pkt)
		tc.SetProtocolId()
		tc.SetFlags(smb2.Encrypted)
		tc.SetOriginalMessageSize(64)
		tc.SetSessionId(unknownSessionID)
		runFatalTest(t, pkt, nil, "unknown session id returned")
	})

	t.Run("DecryptionFailure", func(t *testing.T) {
		pkt := make([]byte, 52+64)
		tc := smb2.TransformCodec(pkt)
		tc.SetProtocolId()
		tc.SetFlags(smb2.Encrypted)
		tc.SetOriginalMessageSize(64)
		tc.SetSessionId(validSessionID)
		dec := &stubDecrypter{err: errors.New("cipher: message authentication failed")}
		runFatalTest(t, pkt, dec, "cipher: message authentication failed")
	})

	t.Run("OriginalMessageSizeMismatch", func(t *testing.T) {
		pkt := make([]byte, 52+64)
		tc := smb2.TransformCodec(pkt)
		tc.SetProtocolId()
		tc.SetFlags(smb2.Encrypted)
		tc.SetOriginalMessageSize(80) // len(pkt) == 52 + 64 != 52 + 80
		tc.SetSessionId(validSessionID)
		runFatalTest(t, pkt, nil, "broken packet header format")
	})

	t.Run("UnknownSessionIDPlain", func(t *testing.T) {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetSessionId(unknownSessionID)
		p.SetMessageId(msgID)
		runFatalTest(t, pkt, nil, "unknown session id")
	})

	t.Run("NextCommandOutOfBounds", func(t *testing.T) {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetSessionId(validSessionID)
		p.SetMessageId(msgID)
		p.SetNextCommand(16) // out of bounds: < 64 (but 8-byte aligned)
		runFatalTest(t, pkt, nil, "broken packet header format")
	})

	t.Run("InvalidChainedPacketHeader", func(t *testing.T) {
		pkt := make([]byte, 128)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetSessionId(validSessionID)
		p.SetMessageId(msgID)
		p.SetNextCommand(64)
		runFatalTest(t, pkt, nil, "invalid chained packet header")
	})

	t.Run("EncryptedCompoundSessionIDMismatch", func(t *testing.T) {
		plaintext := makeCompound(validSessionID, unknownSessionID)
		runFatalTest(t, makeEncryptedPacket(plaintext), aead, "unknown session id in encrypted response")
	})

	t.Run("EncryptedCompressedCompoundSessionIDMismatch", func(t *testing.T) {
		plaintext, err := compressPacket(makeCompound(validSessionID, unknownSessionID))
		require.NoError(err)
		runFatalTest(t, makeEncryptedPacket(plaintext), aead, "unknown session id in encrypted response", true)
	})
}

func TestRunReceiverAcceptsEncryptedCompound(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed-%t", compressed), func(t *testing.T) {
			require := require.New(t)
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()
			require.NoError(serverConn.SetDeadline(time.Now().Add(2 * time.Second)))
			block, err := aes.NewCipher(make([]byte, 16))
			require.NoError(err)
			aead, err := cipher.NewGCM(block)
			require.NoError(err)
			c := &conn{
				t:                   direct(clientConn),
				dialect:             smb2.SMB311,
				compressionIds:      []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(10),
				rdone:               make(chan struct{}, 1),
			}
			c.session = &session{conn: c, sessionId: 0xCAFE, decrypter: aead, encrypter: aead}
			c.enableSession()
			done := make(chan struct{})
			go func() { defer close(done); c.runReceiver() }()
			t.Cleanup(func() { _ = c.close(nil); <-done })
			var requests []*outstandingRequest
			var compound []byte
			for i := 0; i < 2; i++ {
				rr := &outstandingRequest{msgId: uint64(i + 1), cmd: smb2.SMB2_ECHO, ctx: context.Background(), recv: make(chan *recvPacket, 1)}
				c.outstandingRequests.set(rr.msgId, rr)
				requests = append(requests, rr)
				res := &smb2.EchoResponse{}
				pkt := make([]byte, (res.Size()+7)&^7)
				res.Encode(pkt)
				p := smb2.PacketCodec(pkt)
				p.SetSessionId(c.session.sessionId)
				p.SetMessageId(rr.msgId)
				p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				if i == 0 {
					p.SetNextCommand(uint32(len(pkt)))
				}
				compound = append(compound, pkt...)
			}
			if compressed {
				compound, err = compressPacket(compound)
				require.NoError(err)
			}
			pkt, err := c.session.encrypt(compound, make([]byte, 52+len(compound)+aead.Overhead()))
			require.NoError(err)
			_, err = direct(serverConn).Writev(pkt)
			require.NoError(err)
			for _, rr := range requests {
				select {
				case rp := <-rr.recv:
					require.NotNil(rp)
					accepted, err := accept(rr.cmd, rp, c.dialect)
					require.NoError(err)
					accepted.close()
				case <-time.After(time.Second):
					t.Fatal("matching encrypted response was not delivered")
				}
			}
			c.m.Lock()
			connErr := c.err
			c.m.Unlock()
			require.NoError(connErr)
		})
	}
}

func TestReadResponseEncryptionPolicy(t *testing.T) {
	for _, policy := range []string{"session", "share", "optional"} {
		for _, shape := range []string{"single", "compound", "async"} {
			for _, encrypted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/encrypted-%t", policy, shape, encrypted), func(t *testing.T) {
					require := require.New(t)
					clientConn, serverConn := net.Pipe()
					c, cleanup := newBenchConn(clientConn)
					defer cleanup()
					defer serverConn.Close()
					require.NoError(serverConn.SetDeadline(time.Now().Add(3 * time.Second)))
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					s := &session{conn: c, sessionId: 42, encrypter: newGCM(make([]byte, 16)), decrypter: newGCM(make([]byte, 16))}
					c.session = s
					tc := &treeConn{session: s, treeId: 7}
					if policy == "session" {
						s.sessionFlags = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
					} else if policy == "share" {
						tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
					}
					c.enableSession()
					serverErr := make(chan error, 1)
					go func() {
						_, err := readMsg(direct(serverConn))
						serverErr <- err
					}()
					reqs := []smb2.Packet{&smb2.ReadRequest{Length: 1}}
					if shape == "compound" {
						reqs = append(reqs, &smb2.ReadRequest{Length: 1})
					}
					rrs, err := tc.send(ctx, reqs...)
					require.NoError(err)
					require.NoError(<-serverErr)
					writeResponse := func(pkt []byte, encrypt bool) {
						if encrypt {
							var err error
							pkt, err = s.encrypt(pkt, make([]byte, 52+len(pkt)+16))
							require.NoError(err)
						}
						_, err := direct(serverConn).Writev(pkt)
						require.NoError(err)
					}
					var compound []byte
					for i, rr := range rrs {
						require.Equal(policy != "optional", rr.requireEncryption)
						res := &smb2.ReadResponse{Data: []byte{99}}
						pkt := make([]byte, smb2.Roundup(res.Size(), 8))
						res.Encode(pkt)
						p := smb2.PacketCodec(pkt)
						p.SetMessageId(rr.msgId)
						p.SetSessionId(s.sessionId)
						p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
						p.SetCreditResponse(1)
						// A substituted TreeId must not erase the request policy.
						p.SetTreeId(0)
						if shape == "async" {
							p.SetFlags(p.Flags() | smb2.SMB2_FLAGS_ASYNC_COMMAND)
							p.SetAsyncId(13)
							p.SetStatus(uint32(erref.STATUS_PENDING))
							writeResponse(pkt, true)
							p.SetStatus(0)
						}
						if i+1 < len(rrs) {
							p.SetNextCommand(uint32(len(pkt)))
						}
						compound = append(compound, pkt...)
					}
					writeResponse(compound, encrypted)
					for _, rr := range rrs {
						rp, err := s.recv(rr)
						if policy != "optional" && !encrypted {
							require.ErrorContains(err, "encrypted response required")
							require.Nil(rp)
							continue
						}
						require.NoError(err)
						rp, err = accept(smb2.SMB2_READ, rp, c.dialect)
						require.NoError(err)
						require.Equal([]byte{99}, smb2.ReadResponseDecoder(rp.codec().Body()).Data())
						rp.close()
					}
				})
			}
		}
	}
}

func TestResponseEncryptionExceptions(t *testing.T) {
	for _, req := range []smb2.Packet{&smb2.NegotiateRequest{}, &smb2.SessionSetupRequest{}, &smb2.TreeConnectRequest{Path: `\\server\share`}} {
		t.Run(req.Command().String(), func(t *testing.T) {
			require := require.New(t)
			c := &conn{outstandingRequests: newOutstandingRequests()}
			c.session = &session{conn: c, sessionId: 42}
			// SESSION_SETUP can establish an encrypted session in plaintext;
			// TREE_CONNECT has not established a share encryption policy yet.
			if req.Command() == smb2.SMB2_SESSION_SETUP {
				c.session.sessionFlags = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
			}
			rrs, _, err := c.makeOutstandingRequest(context.Background(), false, []uint64{1}, req)
			require.NoError(err)
			require.False(rrs[0].requireEncryption)
			pkt := make([]byte, 64)
			p := smb2.PacketCodec(pkt)
			p.SetProtocolId()
			p.SetStructureSize()
			p.SetCommand(req.Command())
			p.SetMessageId(1)
			p.SetSessionId(42)
			p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			require.NoError(c.tryVerify(&recvPacket{pkt: pkt}, false))
		})
	}
}

func compressReadResponseForTest(t *testing.T, plain []byte) []byte {
	t.Helper()
	require := require.New(t)
	frontSize := int(smb2.ReadResponseDecoder(plain[64:]).DataOffset())
	payload := plain[frontSize:]
	compressed := make([]byte, lz4.CompressBlockBound(len(payload)))
	var compressor lz4.Compressor
	n, err := compressor.CompressBlock(payload, compressed)
	require.NoError(err)
	require.NotZero(n)

	pkt := make([]byte, compressionHeaderSize+frontSize+n)
	c := smb2.CompressionCodec(pkt)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(payload)))
	c.SetCompressionAlgorithm(smb2.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(smb2.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(uint32(frontSize))
	copy(pkt[compressionHeaderSize:], plain[:frontSize])
	copy(pkt[compressionHeaderSize+frontSize:], compressed[:n])
	return pkt
}

func TestReadValidatesBeforeWritingCallerBuffer(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, mode := range []string{"session mismatch", "encryption required", "bad signature", "signed", "encrypted", "encrypted session mismatch", "unsigned"} {
			t.Run(fmt.Sprintf("%s/compressed-%t", mode, compressed), func(t *testing.T) {
				require := require.New(t)
				clientConn, serverConn := net.Pipe()
				defer serverConn.Close()
				require.NoError(serverConn.SetDeadline(time.Now().Add(3 * time.Second)))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c := &conn{
					t: direct(clientConn), outstandingRequests: newOutstandingRequests(),
					account: openAccount(10), rdone: make(chan struct{}, 1),
					dialect: smb2.SMB311, maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
					compressionIds: []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4},
				}
				defer func() {
					serverConn.Close()
					c.close(nil)
				}()
				c.account.charge(10)
				block, err := aes.NewCipher(make([]byte, 16))
				require.NoError(err)
				c.session = &session{conn: c, sessionId: 42, signer: cmac.New(block), verifier: cmac.New(block),
					encrypter: newGCM(make([]byte, 16)), decrypter: newGCM(make([]byte, 16))}
				c.enableSession()
				tc := &treeConn{session: c.session, treeId: 7}
				if mode == "encryption required" {
					tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
				}
				fs := &Share{treeConn: tc, ctx: ctx}
				go c.runReceiver()

				want := bytes.Repeat([]byte("validated payload "), recvBufSize)
				serverDone := make(chan error, 1)
				go func() {
					dt := direct(serverConn)
					req, err := readMsg(dt)
					if err != nil {
						serverDone <- err
						return
					}
					if mode == "encryption required" {
						req, err = c.session.decrypt(req)
						if err != nil {
							serverDone <- err
							return
						}
					}
					if bytes.Equal(req[:4], []byte(smb2.MAGIC3)) {
						req, err = decompressPacket(c, req)
						if err != nil {
							serverDone <- err
							return
						}
					}
					res := &smb2.ReadResponse{Data: want}
					pkt := make([]byte, res.Size())
					res.Encode(pkt)
					p := smb2.PacketCodec(pkt)
					p.SetMessageId(smb2.PacketCodec(req).MessageId())
					p.SetSessionId(42)
					p.SetTreeId(7)
					p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					p.SetCreditResponse(1)
					if mode == "session mismatch" || mode == "encrypted session mismatch" {
						p.SetSessionId(99)
					}
					if mode == "signed" || mode == "bad signature" {
						serverSession := &session{signer: cmac.New(block)}
						serverSession.sign(pkt)
						if mode == "bad signature" {
							pkt[len(pkt)-1] ^= 1
						}
					}
					if compressed {
						pkt = compressReadResponseForTest(t, pkt)
					}
					if mode == "encrypted" || mode == "encrypted session mismatch" {
						pkt, err = c.session.encrypt(pkt, make([]byte, 52+len(pkt)+16))
						if err != nil {
							serverDone <- err
							return
						}
					}
					_, err = dt.Writev(pkt)
					serverDone <- err
				}()

				buf := bytes.Repeat([]byte{0xa5}, len(want)+16)
				n, err := fs.readAtChunk(&smb2.FileId{}, buf[:len(want)], 0)
				if mode == "signed" || mode == "encrypted" || mode == "unsigned" {
					require.NoError(err)
					require.Equal(len(want), n)
					require.Equal(want, buf[:len(want)])
					require.Equal(bytes.Repeat([]byte{0xa5}, 16), buf[len(want):])
				} else {
					var invalid *InvalidResponseError
					require.ErrorAs(err, &invalid)
					switch mode {
					case "session mismatch", "encrypted session mismatch":
						require.Contains(invalid.Message, "unknown session id")
					case "encryption required":
						require.Equal("encrypted response required", invalid.Message)
					case "bad signature":
						require.Equal("packet failed signature verification", invalid.Message)
					}
					require.Zero(n)
					require.Equal(bytes.Repeat([]byte{0xa5}, len(buf)), buf)
				}
				require.NoError(<-serverDone)
			})
		}
	}
}

func TestDirectReadBoundsResponseToRequestedLength(t *testing.T) {
	const maxReadSize = 4096
	for _, encrypted := range []bool{false, true} {
		for _, test := range []struct {
			name      string
			dataLen   int
			wantError bool
		}{
			{"overlong", 2 * maxReadSize, true},
			{"exact", maxReadSize, false},
			{"short", maxReadSize / 2, false},
		} {
			t.Run(fmt.Sprintf("encrypted-%t/%s", encrypted, test.name), func(t *testing.T) {
				require := require.New(t)
				clientConn, serverConn := net.Pipe()
				defer serverConn.Close()
				require.NoError(serverConn.SetDeadline(time.Now().Add(3 * time.Second)))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c := &conn{
					t: direct(clientConn), outstandingRequests: newOutstandingRequests(),
					account: openAccount(10), rdone: make(chan struct{}, 1),
					dialect: smb2.SMB311, maxReadSize: maxReadSize, maxWriteSize: 65536, maxTransactSize: 65536,
				}
				defer func() {
					serverConn.Close()
					c.close(nil)
				}()
				c.account.charge(10)
				block, err := aes.NewCipher(make([]byte, 16))
				require.NoError(err)
				c.session = &session{conn: c, sessionId: 42, signer: cmac.New(block), verifier: cmac.New(block),
					encrypter: newGCM(make([]byte, 16)), decrypter: newGCM(make([]byte, 16))}
				c.enableSession()
				tc := &treeConn{session: c.session, treeId: 7}
				if encrypted {
					tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
				}
				fs := &Share{treeConn: tc, ctx: ctx}
				go c.runReceiver()

				want := make([]byte, test.dataLen)
				for i := range want {
					want[i] = byte(i)
				}

				serverDone := make(chan error, 1)
				go func() {
					dt := direct(serverConn)
					req, err := readMsg(dt)
					if err != nil {
						serverDone <- err
						return
					}
					if encrypted {
						req, err = c.session.decrypt(req)
						if err != nil {
							serverDone <- err
							return
						}
					}
					if got := smb2.ReadRequestDecoder(smb2.PacketCodec(req).Body()).Length(); got != maxReadSize {
						serverDone <- fmt.Errorf("server received Length=%d, want %d", got, maxReadSize)
						return
					}
					res := &smb2.ReadResponse{Data: want}
					pkt := make([]byte, res.Size())
					res.Encode(pkt)
					p := smb2.PacketCodec(pkt)
					p.SetMessageId(smb2.PacketCodec(req).MessageId())
					p.SetSessionId(42)
					p.SetTreeId(7)
					p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					p.SetCreditResponse(1)
					if encrypted {
						pkt, err = c.session.encrypt(pkt, make([]byte, 52+len(pkt)+16))
						if err != nil {
							serverDone <- err
							return
						}
					}
					_, err = dt.Writev(pkt)
					serverDone <- err
				}()

				buf := bytes.Repeat([]byte{0xa5}, 2*maxReadSize)
				n, err := fs.readAtChunk(&smb2.FileId{}, buf, 0)
				if test.wantError {
					var invalid *InvalidResponseError
					require.ErrorAs(err, &invalid)
					require.Equal("read length exceeds requested length", invalid.Message)
					require.Zero(n)
					require.Equal(bytes.Repeat([]byte{0xa5}, len(buf)), buf)
				} else {
					require.NoError(err)
					require.Equal(test.dataLen, n)
					require.Equal(want, buf[:n])
					require.Equal(bytes.Repeat([]byte{0xa5}, len(buf)-n), buf[n:])
				}
				require.NoError(<-serverDone)
			})
		}
	}
}

func TestChangeNotifyCancellationPreservesSharedConnection(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprintf("async=%v", async), func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			f.fileStat.FileAttributes = smb2.FILE_ATTRIBUTE_DIRECTORY
			other := f.fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "other")
			other.fileStat.FileAttributes = smb2.FILE_ATTRIBUTE_DIRECTORY
			other.fd = &smb2.FileId{Volatile: [8]byte{2}}
			c := f.fs.conn
			dt := direct(peer)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := startNotify(f, ctx, ChangeFileName, false)
			request, err := readMsg(dt)
			require.NoError(t, err)
			p := smb2.PacketCodec(request)
			require.EqualValues(t, 65536, smb2.ChangeNotifyRequestDecoder(p.Body()).OutputBufferLength())
			rr, ok := c.outstandingRequests.peek(p.MessageId())
			require.True(t, ok)
			const asyncID = 0x12345678
			if async {
				pending := &smb2.ErrorResponse{CommandCode: smb2.SMB2_CHANGE_NOTIFY}
				buf := make([]byte, pending.Size())
				pending.Encode(buf)
				r := smb2.PacketCodec(buf)
				r.SetMessageId(p.MessageId())
				r.SetSessionId(p.SessionId())
				r.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
				r.SetAsyncId(asyncID)
				r.SetStatus(uint32(erref.STATUS_PENDING))
				r.SetCreditResponse(0)
				_, err := dt.Writev(buf)
				require.NoError(t, err)
				require.Eventually(t, func() bool { return rr.asyncId.Load() == asyncID }, time.Second, time.Millisecond)
			}
			otherDone := startNotify(other, context.Background(), ChangeDirName, true)
			otherRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, other.fd, smb2.ChangeNotifyRequestDecoder(smb2.PacketCodec(otherRequest).Body()).FileId().Decode())
			cancel()
			cancelRequest, err := readMsg(dt)
			require.NoError(t, err)
			cp := smb2.PacketCodec(cancelRequest)
			require.Equal(t, smb2.SMB2_CANCEL, cp.Command())
			require.Equal(t, p.MessageId(), cp.MessageId())
			require.Zero(t, cp.CreditCharge())
			require.Zero(t, cp.CreditRequest())
			if async {
				require.NotZero(t, cp.Flags()&smb2.SMB2_FLAGS_ASYNC_COMMAND)
				require.EqualValues(t, asyncID, cp.AsyncId())
			} else {
				require.Zero(t, cp.Flags()&smb2.SMB2_FLAGS_ASYNC_COMMAND)
			}
			_, err = finishNotify(t, done)
			require.ErrorIs(t, err, context.Canceled)
			require.False(t, f.closed.Load())
			_, ok = c.outstandingRequests.peek(p.MessageId())
			require.True(t, ok, "canceled notification remains outstanding until its final response")

			// ECHO completes while both notification responses are still pending.
			echoDone := make(chan error, 1)
			go func() { echoDone <- c.session.echo(context.Background()) }()
			echoRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, smb2.SMB2_ECHO, smb2.PacketCodec(echoRequest).Command())
			sendTestResponse(dt, echoRequest, &smb2.EchoResponse{}, 0)
			select {
			case err := <-echoDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked ECHO")
			}
			checkCredits := func(available, inFlight uint16) {
				t.Helper()
				require.Eventually(t, func() bool {
					c.account.m.Lock()
					defer c.account.m.Unlock()
					return c.account.availableCredits == available && c.account.inFlightCredits == inFlight
				}, time.Second, time.Millisecond)
			}
			checkCredits(510, 2)
			final := &smb2.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(ChangeActionAdded, "late"))}
			buf := make([]byte, final.Size())
			final.Encode(buf)
			fp := smb2.PacketCodec(buf)
			fp.SetMessageId(p.MessageId())
			fp.SetSessionId(p.SessionId())
			fp.SetTreeId(p.TreeId())
			fp.SetCreditResponse(1)
			fp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			if async {
				fp.SetFlags(fp.Flags() | smb2.SMB2_FLAGS_ASYNC_COMMAND)
				fp.SetAsyncId(asyncID)
			}
			_, err = dt.Writev(buf)
			require.NoError(t, err)
			checkCredits(511, 1)
			_, ok = c.outstandingRequests.peek(p.MessageId())
			require.False(t, ok)
			sendTestResponse(dt, otherRequest, &smb2.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(ChangeActionAdded, "other"))}, 0)
			result, err := finishNotify(t, otherDone)
			require.NoError(t, err)
			require.Equal(t, []ChangeEvent{{ChangeActionAdded, "other"}}, result.Events)
			checkCredits(512, 0)
		})
	}
}

func TestAcceptChangeNotifyRejectsMalformedEnum(t *testing.T) {
	for _, body := range [][]byte{nil, make([]byte, 7), {8, 0, 0, 0, 0, 0, 0, 0}, {9, 0, 72, 0, 1, 0, 0, 0}} {
		buf := make([]byte, 64+len(body))
		p := smb2.PacketCodec(buf)
		p.SetCommand(smb2.SMB2_CHANGE_NOTIFY)
		p.SetStatus(uint32(erref.STATUS_NOTIFY_ENUM_DIR))
		copy(buf[64:], body)
		res, err := accept(smb2.SMB2_CHANGE_NOTIFY, &recvPacket{pkt: buf}, smb2.SMB302)
		require.Nil(t, res)
		var invalid *InvalidResponseError
		require.ErrorAs(t, err, &invalid)
	}
}

func TestChangeNotifyCannotReadNextCompoundResponse(t *testing.T) {
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.fileStat.FileAttributes = smb2.FILE_ATTRIBUTE_DIRECTORY
	dt := direct(peer)
	done := startNotify(f, context.Background(), ChangeFileName, false)
	notifyRequest, err := readMsg(dt)
	require.NoError(t, err)
	echoDone := make(chan error, 1)
	go func() { echoDone <- f.fs.session.echo(context.Background()) }()
	echoRequest, err := readMsg(dt)
	require.NoError(t, err)
	makeResponse := func(request []byte, response smb2.Packet) []byte {
		buf := make([]byte, response.Size())
		response.Encode(buf)
		p, r := smb2.PacketCodec(request), smb2.PacketCodec(buf)
		r.SetMessageId(p.MessageId())
		r.SetSessionId(p.SessionId())
		r.SetTreeId(p.TreeId())
		r.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		r.SetCreditResponse(1)
		return buf
	}
	first := makeResponse(notifyRequest, &smb2.ChangeNotifyResponse{})
	smb2.PacketCodec(first).SetNextCommand(uint32(len(first)))
	le.PutUint16(first[66:68], 80) // Points into the next SMB2 command.
	le.PutUint32(first[68:72], 16)
	second := makeResponse(echoRequest, &smb2.EchoResponse{})
	_, err = dt.Writev(append(first, second...))
	require.NoError(t, err)
	_, err = finishNotify(t, done)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	select {
	case err := <-echoDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ECHO response following malformed CHANGE_NOTIFY was lost")
	}
}
