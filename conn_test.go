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
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
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
		var req smb2.ReadRequest
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
		go fakeServer(direct(serverConn), nil, serverSessionId)

		s := &session{conn: c, sessionId: 0}

		require.NoError(roundTrip(t, c, s))
		require.Equal(serverSessionId, s.sessionId)
	})

	t.Run("MatchingSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const id uint64 = 0xCAFE
		go fakeServer(direct(serverConn), nil, id)

		s := &session{conn: c, sessionId: id}

		require.NoError(roundTrip(t, c, s))
		require.Equal(id, s.sessionId)
	})

	t.Run("RejectsSessionIdMismatch", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		go fakeServer(direct(serverConn), nil, 0xBBBB)

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

type failingReceiver struct {
	err error
}

func (r failingReceiver) recv(*outstandingRequest) (*recvPacket, error) {
	return nil, r.err
}

func TestRecvAllAbandonsPendingRequests(t *testing.T) {
	require := require.New(t)

	firstErr := fmt.Errorf("first request failed")

	rrs := []*outstandingRequest{
		{cmd: smb2.SMB2_ECHO, ctx: context.Background(), recv: make(chan *recvPacket)},
		{cmd: smb2.SMB2_ECHO, ctx: context.Background(), recv: make(chan *recvPacket, 1)},
		{cmd: smb2.SMB2_ECHO, ctx: context.Background(), recv: make(chan *recvPacket, 1)},
	}

	// packets that have already arrived on the pending requests' channels
	abandoned := []*recvPacket{
		allocRecvPacket(64),
		allocRecvPacket(64),
	}
	rrs[1].recv <- abandoned[0]
	rrs[2].recv <- abandoned[1]

	_, err := recvAll(rrs, failingReceiver{err: firstErr})
	require.Error(err)
	require.Equal(firstErr, err)

	// the failed request itself is not marked as canceled, but the rest of
	// the compound requests are abandoned
	require.False(rrs[0].canceled.Load())
	require.True(rrs[1].canceled.Load())
	require.True(rrs[2].canceled.Load())

	// arrived packets must have been drained and closed (buffer released)
	require.Nil(abandoned[0].buf)
	require.Nil(abandoned[1].buf)
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

	err := acceptError(uint32(erref.STATUS_INVALID_PARAMETER), payload)
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
			err := acceptError(uint32(erref.STATUS_INVALID_PARAMETER), payload)
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
					accepted, err := accept(rr.cmd, rp)
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
