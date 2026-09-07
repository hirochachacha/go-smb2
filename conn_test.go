package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

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
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("regular message, signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, 21)
		pkt.SetSignature(zero[:])
		require.IsType(&InvalidResponseError{}, c.tryVerify(pkt, false))
	})

	t.Run("regular message, unset signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, uint64(smb2.SMB2_CREATE))
		pkt.SetSignature(zero[:])
		err := c.tryVerify(pkt, false)
		require.IsType(&InvalidResponseError{}, err)
		require.ErrorContains(err, "packet failed signature verification")
	})

	t.Run("OPLOCK_BREAK should skip verification", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, 0xFFFFFFFFFFFFFFFF)
		require.NoError(c.tryVerify(pkt, false))
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
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("encrypted message without signature, succeeds", func(t *testing.T) {
		// pass an invalid session id, and use a connection that requires
		// signing to make sure we're getting an early return due to encryption
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, 0, uint64(smb2.SMB2_CREATE))
		require.NoError(c.tryVerify(pkt, true))
	})

	t.Run("signed message succeeds", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, uint64(smb2.SMB2_CREATE))

		// actually sign the packet
		verifier := cmac.New(ciph)
		verifier.Write(pkt)
		pkt.SetSignature(verifier.Sum(nil))

		require.NoError(c.tryVerify(pkt, false))
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
		sz1, err := st.ReadSize()
		if err != nil {
			return
		}
		buf1 := make([]byte, sz1)
		if _, err := st.Read(buf1); err != nil {
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
		if _, err := st.Write(respBuf1); err != nil {
			return
		}

		// Round 2: server replies with SMB210 (0x210)
		sz2, err := st.ReadSize()
		if err != nil {
			return
		}
		buf2 := make([]byte, sz2)
		if _, err := st.Read(buf2); err != nil {
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
		_, _ = st.Write(respBuf2)
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	c, err := n.negotiate(direct(clientConn), a, context.Background())
	require.NoError(err)
	defer func() {
		c.rdone <- struct{}{}
		_ = c.t.Close()
	}()

	require.Equal(uint16(smb2.SMB210), c.dialect)
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
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		buf := make([]byte, sz)
		_, _ = st.Read(buf)
		_ = serverConn.Close()
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	_, err := n.negotiate(direct(clientConn), a, context.Background())
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
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		buf := make([]byte, sz)
		if _, err := st.Read(buf); err != nil {
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
		_, _ = st.Write(respBuf)
	}()

	n := &Negotiator{
		SpecifiedDialect: smb2.UnknownSMB,
	}

	a := openAccount(128)
	_, err := n.negotiate(direct(clientConn), a, context.Background())
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
			sz, err := st.ReadSize()
			if err != nil {
				return
			}
			buf := make([]byte, sz)
			if _, err := st.Read(buf); err != nil {
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
			if _, err := st.Write(respBuf); err != nil {
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
	_, err := n.negotiate(direct(clientConn), a, ctx)
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
				sz, err := st.ReadSize()
				if err != nil {
					return
				}
				buf := make([]byte, sz)
				if _, err := st.Read(buf); err != nil {
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
				_, _ = st.Write(respBuf)
			}()

			n := &Negotiator{
				SpecifiedDialect: smb2.UnknownSMB,
			}

			a := openAccount(128)
			_, err := n.negotiate(direct(clientConn), a, context.Background())
			require.Error(err)
			var ire *InvalidResponseError
			require.ErrorAs(err, &ire)
			require.Equal(tc.message, ire.Message)
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
		sz1, err := st.ReadSize()
		if err != nil {
			serverErr = err
			return
		}
		reqBuf := make([]byte, sz1)
		if _, err := st.Read(reqBuf); err != nil {
			serverErr = err
			return
		}
		p := smb2.PacketCodec(reqBuf)

		// 2. Read Cancel request sent asynchronously by client
		sz2, err := st.ReadSize()
		if err != nil {
			serverErr = err
			return
		}
		cancelBuf := make([]byte, sz2)
		if _, err := st.Read(cancelBuf); err != nil {
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

		if _, err := st.Write(resBuf); err != nil {
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
				sz, err := st.ReadSize()
				if err != nil {
					return
				}
				buf := make([]byte, sz)
				if _, err := st.Read(buf); err != nil {
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

				if _, err := st.Write(respBuf); err != nil {
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

		rp := makeEncryptedPacket(make([]byte, 46))
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
		require.Equal("original message size mismatch", ire.Message)
		require.False(isEncrypted)
	})

	t.Run("AcceptsValidDecryptedPacket", func(t *testing.T) {
		plaintext := make([]byte, 64)
		p := smb2.PacketCodec(plaintext)
		p.SetProtocolId()
		p.SetStructureSize()
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

func (t *panicTransport) Write(p []byte) (int, error) {
	return 0, net.ErrClosed
}

func (t *panicTransport) ReadSize() (int, error) {
	return 64, nil
}

func (t *panicTransport) Read(p []byte) (int, error) {
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

func (t *readErrorTransport) Write(p []byte) (int, error) {
	return 0, t.readErr
}

func (t *readErrorTransport) ReadSize() (int, error) {
	return 0, t.readErr
}

func (t *readErrorTransport) Read(p []byte) (int, error) {
	return 0, t.readErr
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

// errorTransport is a mock transport whose Write always fails, simulating a
// broken connection (partial or failed write).
type errorTransport struct {
	writeErr error
	closed   chan struct{}
}

func (t *errorTransport) Write(p []byte) (int, error) {
	return 0, t.writeErr
}

func (t *errorTransport) ReadSize() (int, error) {
	return 0, t.writeErr
}

func (t *errorTransport) Read(p []byte) (int, error) {
	return 0, t.writeErr
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
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		cancelBuf := make([]byte, sz)
		if _, err := st.Read(cancelBuf); err != nil {
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

	t.Run("SMB311HasHashAndCipherContexts", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.SMB311,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Len(req.Contexts, 2)

		hc, ok := req.Contexts[0].(*smb2.HashContext)
		require.True(ok, "first context should be *smb2.HashContext")
		require.Equal(clientHashAlgorithms, hc.HashAlgorithms)
		require.Len(hc.HashSalt, 32)

		cc, ok := req.Contexts[1].(*smb2.CipherContext)
		require.True(ok, "second context should be *smb2.CipherContext")
		require.Equal(clientCiphers, cc.Ciphers)
	})

	t.Run("UnknownSMBHasHashAndCipherContexts", func(t *testing.T) {
		neg := &Negotiator{
			SpecifiedDialect: smb2.UnknownSMB,
		}

		req, err := neg.makeRequest()
		require.NoError(err)
		require.Len(req.Contexts, 2)

		hc, ok := req.Contexts[0].(*smb2.HashContext)
		require.True(ok, "first context should be *smb2.HashContext")
		require.Equal(clientHashAlgorithms, hc.HashAlgorithms)
		require.Len(hc.HashSalt, 32)

		cc, ok := req.Contexts[1].(*smb2.CipherContext)
		require.True(ok, "second context should be *smb2.CipherContext")
		require.Equal(clientCiphers, cc.Ciphers)
	})
}

func TestRunReceiverFatalErrors(t *testing.T) {
	require := require.New(t)

	const (
		validSessionID   uint64 = 0xCAFE
		unknownSessionID uint64 = 0xDEAD
		msgID            uint64 = 1
	)

	runFatalTest := func(t *testing.T, packetToSend []byte, decrypter cipher.AEAD, expectedErrSubstr string) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(10),
			rdone:               make(chan struct{}, 1),
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
		_, err := st.Write(packetToSend)
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
		runFatalTest(t, pkt, nil, "original message size mismatch")
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
		runFatalTest(t, pkt, nil, "NextCommand offset out of bounds")
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
}

