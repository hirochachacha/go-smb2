package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
	"uuid"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestSessionChannelsSelectLiveConnections(t *testing.T) {
	t.Parallel()
	a := &session{conn: &conn{t: new(sessionCloseTransport)}}
	b := &session{conn: &conn{t: new(sessionCloseTransport)}}
	g := &sessionChannels{channels: []*session{a, b}}
	for _, want := range []*session{a, b, a, b} {
		got, err := g.selectChannel()
		require.NoError(t, err)
		require.Same(t, want, got)
	}
	require.NoError(t, a.conn.close(nil))
	got, err := g.selectChannel()
	require.NoError(t, err)
	require.Same(t, b, got)
	require.Equal(t, uint32(1), g.sequence.Load())
	require.NoError(t, b.conn.close(nil))
	_, err = g.selectChannel()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestSessionChannelsRespectIndependentCreditWindows(t *testing.T) {
	t.Parallel()
	a, b := &session{conn: &conn{account: openAccount(8)}}, &session{conn: &conn{account: openAccount(8)}}
	a.account.maxCredits = 2
	b.account.maxCredits = 1
	g := &sessionChannels{channels: []*session{a, b}, next: 1}
	got, err := g.selectChannel(&wire.ReadRequest{Length: 2 * 65536})
	require.NoError(t, err)
	require.Same(t, a, got, "a new channel's smaller credit window must not break existing large reads")
	g.next = 1
	got, err = g.selectSequentialChannel([]wire.Packet{&wire.EchoRequest{}, &wire.ReadRequest{Length: 2 * 65536}})
	require.NoError(t, err)
	require.Same(t, a, got, "sequential fallback must support the largest member")
}

func TestSessionChannelsAbortClosesEveryConnection(t *testing.T) {
	t.Parallel()
	a, b, pending := new(sessionCloseTransport), new(sessionCloseTransport), new(sessionCloseTransport)
	s := &session{conn: &conn{t: a}}
	s.channels = &sessionChannels{channels: []*session{s, {conn: &conn{t: b}}}, pending: &conn{t: pending}}
	c := &Session{s: s}
	require.NoError(t, c.Abort())
	require.NoError(t, c.Abort())
	for _, transport := range []*sessionCloseTransport{a, b, pending} {
		require.Equal(t, int32(1), transport.closes.Load())
	}
	_, err := s.channels.selectChannel()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestBindChannelRejectsInvalidSessionAndOwnsTransport(t *testing.T) {
	t.Parallel()
	for _, s := range []*Session{nil, {}, {s: &session{conn: &conn{dialect: wire.SMB210}}}} {
		transport := new(sessionCloseTransport)
		require.Error(t, s.BindChannel(context.Background(), &singleRoundInitiator{}, transport))
		require.Equal(t, int32(1), transport.closes.Load())
	}
}

func TestBindChannelRejectsTypedNilArguments(t *testing.T) {
	t.Parallel()
	s := &Session{s: &session{conn: &conn{}, channels: &sessionChannels{}}}
	var initiator *singleRoundInitiator
	var transport *transport
	require.NotPanics(t, func() { require.Error(t, s.BindChannel(context.Background(), &singleRoundInitiator{}, transport)) })
	owned := new(sessionCloseTransport)
	require.NotPanics(t, func() { require.Error(t, s.BindChannel(context.Background(), initiator, owned)) })
	require.Equal(t, int32(1), owned.closes.Load())
	require.NotPanics(t, func() {
		require.Error(t, s.BindChannel(context.Background(), &singleRoundInitiator{}, NewTransport(nil)))
	})
}

// channelPeer is an in-memory server, never an external SMB endpoint. Its
// independently calculated signatures bind the new GSS key to this connection's
// transcript, while binding requests use the original session transcript/key.
type channelPeer struct {
	transport          Transport
	dialect            uint16
	key                []byte
	preauth            [64]byte
	clientGuid         uuid.UUID
	requests           chan []byte
	done               chan struct{}
	holdRequests       bool
	dropWrites         bool
	rounds             int
	tamperIntermediate bool
	serverGuid         uuid.UUID
	algorithm          wire.SigningAlgorithm
}

func startChannelPeer(t *testing.T, dialect uint16, key []byte, original *channelPeer, tamper bool, options ...func(*channelPeer)) (Transport, *channelPeer) {
	t.Helper()
	client, server := net.Pipe()
	p := &channelPeer{transport: NewTransport(server), dialect: dialect, key: key, requests: make(chan []byte, 16), done: make(chan struct{}), rounds: 1, serverGuid: uuid.UUID{1}, algorithm: wire.AES128CMAC}
	for _, option := range options {
		option(p)
	}
	go func() {
		defer close(p.done)
		defer p.transport.Close()
		request, err := readMsg(p.transport)
		if err != nil {
			return
		}
		negotiate := wire.NegotiateRequestDecoder(request[64:])
		if negotiate.IsInvalid() {
			t.Error("invalid negotiate")
			return
		}
		p.clientGuid = negotiate.ClientGuid()
		if original != nil && p.clientGuid != original.clientGuid {
			t.Error("binding changed ClientGuid")
			return
		}
		response := &wire.NegotiateResponse{SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_REQUIRED, DialectRevision: dialect,
			ServerGuid: p.serverGuid, Capabilities: clientCapabilities, MaxReadSize: 65536, MaxWriteSize: 65536, MaxTransactSize: 65536}
		response.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
		response.MessageId = wire.PacketCodec(request).MessageId()
		if dialect == wire.SMB311 {
			response.Contexts = wire.NegotiateContexts{&wire.HashContext{HashAlgorithms: []uint16{wire.SHA512}}, &wire.CipherContext{Ciphers: []wire.Cipher{wire.AES128GCM}}, &wire.SigningContext{SigningAlgorithms: []wire.SigningAlgorithm{p.algorithm}}}
		}
		data := make([]byte, response.Size())
		response.Encode(data)
		wire.PacketCodec(data).SetCreditResponse(8)
		if dialect == wire.SMB311 {
			updatePreauthHash(&p.preauth, request)
			updatePreauthHash(&p.preauth, data)
		}
		if _, err := p.transport.writev(data); err != nil {
			return
		}
		for round := 1; round <= p.rounds; round++ {
			request, err = readMsg(p.transport)
			if err != nil {
				return
			}
			header := wire.PacketCodec(request)
			setup := wire.SessionSetupRequestDecoder(request[64:])
			if setup.IsInvalid() {
				t.Error("invalid setup")
				return
			}
			if original != nil {
				if setup.Flags() != wire.SMB2_SESSION_FLAG_BINDING || header.SessionId() != 0x1234 || setup.PreviousSessionId() != 0 {
					t.Error("invalid binding fields")
					return
				}
				if !original.verify(t, request) {
					t.Error("binding request not signed with original session key")
					return
				}
			}
			if dialect == wire.SMB311 {
				updatePreauthHash(&p.preauth, request)
			}
			state := asn1.Enumerated(0)
			if round < p.rounds {
				state = 1
			}
			token, err := spnego.EncodeNegTokenResp(state, spnego.NlmpOid, []byte("server-final-token"), nil)
			if err != nil {
				t.Error(err)
				return
			}
			setupResponse := &wire.SessionSetupResponse{SecurityBuffer: token}
			setupResponse.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
			setupResponse.MessageId = header.MessageId()
			setupResponse.SessionId = 0x1234
			data = make([]byte, setupResponse.Size())
			setupResponse.Encode(data)
			wire.PacketCodec(data).SetCreditResponse(1)
			if round < p.rounds {
				wire.PacketCodec(data).SetStatus(uint32(erref.STATUS_MORE_PROCESSING_REQUIRED))
				original.sign(t, data)
				if p.tamperIntermediate {
					data[48] ^= 1
				}
				if dialect == wire.SMB311 {
					updatePreauthHash(&p.preauth, data)
				}
			} else {
				p.sign(t, data)
			}
			if tamper && round == p.rounds {
				data[48] ^= 1
			}
			if _, err := p.transport.writev(data); err != nil {
				return
			}
		}
		for {
			request, err = readMsg(p.transport)
			if err != nil {
				return
			}
			p.requests <- append([]byte(nil), request...)
			if p.dropWrites && wire.PacketCodec(request).Command() == wire.SMB2_WRITE {
				return
			}
			if p.holdRequests && wire.PacketCodec(request).Command() != wire.SMB2_LOGOFF {
				continue
			}
			var out []byte
			for offset := 0; offset < len(request); {
				header := wire.PacketCodec(request[offset:])
				n := int(header.NextCommand())
				length := len(request) - offset
				if n != 0 {
					length = n
				}
				if !p.verify(t, request[offset:offset+length]) {
					t.Error("wrong channel request signature")
					return
				}
				if header.Command() == wire.SMB2_CANCEL {
					break
				}
				response := &wire.EchoResponse{PacketHeader: wire.PacketHeader{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: header.MessageId(), SessionId: 0x1234}}
				data := make([]byte, response.Size())
				if n != 0 {
					data = make([]byte, 72)
				}
				response.Encode(data)
				rh := wire.PacketCodec(data)
				rh.SetCommand(header.Command())
				rh.SetTreeId(header.TreeId())
				rh.SetCreditResponse(max(header.CreditCharge(), 1))
				if n != 0 {
					rh.SetNextCommand(72)
				}
				p.sign(t, data)
				out = append(out, data...)
				if n == 0 {
					break
				}
				offset += n
			}
			if len(out) > 0 {
				if _, err := p.transport.writev(out); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { _ = p.transport.Close(); <-p.done })
	return NewTransport(client), p
}

func (p *channelPeer) sign(t *testing.T, data []byte) {
	header := wire.PacketCodec(data)
	header.SetFlags(header.Flags() | wire.SMB2_FLAGS_SIGNED)
	clear(header.Signature())
	header.SetSignature(p.signature(t, data))
}

func (p *channelPeer) verify(t *testing.T, data []byte) bool {
	header := wire.PacketCodec(data)
	if header.Flags()&wire.SMB2_FLAGS_SIGNED == 0 {
		return false
	}
	signature := append([]byte(nil), header.Signature()...)
	clear(header.Signature())
	expected := p.signature(t, data)
	header.SetSignature(signature)
	return bytes.Equal(signature, expected)
}

func (p *channelPeer) signature(t *testing.T, data []byte) []byte {
	if p.algorithm != wire.AES128GMAC {
		return expectedSessionSignatureForTest(t, p.dialect, p.key, p.preauth[:], data)
	}
	key := kdfForTest(normalizeSessionKeyForTest(p.key), []byte("SMBSigningKey\x00"), p.preauth[:], 16)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, 12)
	header := wire.PacketCodec(data)
	binary.LittleEndian.PutUint64(nonce, header.MessageId())
	if header.Flags()&wire.SMB2_FLAGS_SERVER_TO_REDIR != 0 {
		nonce[8] = 1
	}
	if header.Command() == wire.SMB2_CANCEL {
		nonce[8] |= 2
	}
	return gcm.Seal(nil, nonce, nil, data)
}

func TestBindChannelAuthenticatesAndDistributesRequests(t *testing.T) {
	t.Parallel()
	for _, dialect := range []uint16{wire.SMB302, wire.SMB311} {
		t.Run(fmt.Sprint(dialect), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			key1, key2 := []byte("first channel key"), []byte("bound channel key")
			transport, primary := startChannelPeer(t, dialect, key1, nil, false)
			s, err := (&Dialer{SpecifiedDialects: []Dialect{Dialect(dialect)}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key1}, transport)
			require.NoError(t, err)
			defer s.Abort()
			transport, bound := startChannelPeer(t, dialect, key2, primary, false)
			require.NoError(t, s.BindChannel(ctx, &singleRoundInitiator{key: key2}, transport))
			boundSession := s.s.channels.channels[1]
			require.Same(t, s.s.nonces, boundSession.nonces, "binding must retain the original encryption key's nonce allocator")
			require.NotSame(t, s.s.account, boundSession.account)
			require.NotSame(t, s.s.outstandingRequests, boundSession.outstandingRequests)
			nonce := make([]byte, s.s.encrypter.NonceSize())
			require.Equal(t, s.s.encrypter.Seal(nil, nonce, []byte("payload"), nil), boundSession.encrypter.Seal(nil, nonce, []byte("payload"), nil), "binding preserves the original encryption key")
			for range 2 {
				require.NoError(t, s.Echo(ctx))
			}
			first, second := <-primary.requests, <-bound.requests
			require.Equal(t, wire.PacketCodec(first).MessageId(), wire.PacketCodec(second).MessageId(), "MID spaces are independent")
			require.NotEqual(t, wire.PacketCodec(first).Signature(), wire.PacketCodec(second).Signature())
			res, err := s.s.sendRecv(ctx, &wire.EchoRequest{}, &wire.EchoRequest{})
			require.NoError(t, err)
			res.close()
			compound := <-primary.requests
			require.NotZero(t, wire.PacketCodec(compound).NextCommand())
			require.Empty(t, bound.requests, "compound must stay on one channel")
			require.NoError(t, s.s.conn.close(nil))
			require.NoError(t, s.Echo(ctx))
			require.Equal(t, uint16(1), wire.PacketCodec(<-bound.requests).ChannelSequence())
			require.NoError(t, s.Close())
		})
	}
}

func TestBindChannelFailurePreservesExistingSession(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := []byte("existing session key")
	transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false)
	s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
	require.NoError(t, err)
	defer s.Abort()
	transport, _ = startChannelPeer(t, wire.SMB311, key, primary, true)
	require.Error(t, s.BindChannel(ctx, &singleRoundInitiator{key: key}, transport))
	require.NoError(t, s.Echo(ctx))
	require.Len(t, s.s.channels.channels, 1)
}

func TestBindChannelMultiRoundAuthentication(t *testing.T) {
	t.Parallel()
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprint(tamper), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			key, freshKey := []byte("original GSS key"), []byte("fresh GSS key")
			transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false)
			s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
			require.NoError(t, err)
			defer s.Abort()
			transport, _ = startChannelPeer(t, wire.SMB311, freshKey, primary, false, func(p *channelPeer) { p.rounds = 3; p.tamperIntermediate = tamper })
			initiator := &finalKeyInitiator{rounds: 3, finalKey: freshKey}
			err = s.BindChannel(ctx, initiator, transport)
			if tamper {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, s.Echo(ctx))
			if !tamper {
				require.NoError(t, s.Echo(ctx))
			}
		})
	}
}

func TestBindChannelGMACAuthenticationAndRetry(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"none", "intermediate", "final"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			key, freshKey := []byte("original GSS key"), []byte("fresh GSS key")
			gmac := func(p *channelPeer) { p.algorithm = wire.AES128GMAC }
			transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false, gmac)
			s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
			require.NoError(t, err)
			defer s.Abort()
			if failure != "none" {
				transport, failed := startChannelPeer(t, wire.SMB311, freshKey, primary, failure == "final", gmac, func(p *channelPeer) { p.rounds = 3; p.tamperIntermediate = failure == "intermediate" })
				err = s.BindChannel(ctx, &finalKeyInitiator{rounds: 3, finalKey: freshKey}, transport)
				require.ErrorContains(t, err, "signature verification")
				require.Len(t, s.s.channels.channels, 1)
				require.NoError(t, s.Echo(ctx))
				<-primary.requests
				<-failed.done
			}
			for range 2 {
				transport, _ = startChannelPeer(t, wire.SMB311, freshKey, primary, false, gmac, func(p *channelPeer) { p.rounds = 3 })
				require.NoError(t, s.BindChannel(ctx, &finalKeyInitiator{rounds: 3, finalKey: freshKey}, transport))
			}
			require.Len(t, s.s.channels.channels, 3)
			for _, channel := range s.s.channels.channels {
				require.Equal(t, wire.AES128GMAC, channel.signingAlgorithm)
				require.Same(t, s.s.nonces, channel.nonces)
				require.NoError(t, s.Echo(ctx)) // Each peer verifies its own channel key/transcript.
			}
			require.NoError(t, s.s.conn.close(nil))
			require.NoError(t, s.Echo(ctx))
		})
	}
}

func TestBindChannelRejectsAnotherServer(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := []byte("original GSS key")
	transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false)
	s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
	require.NoError(t, err)
	defer s.Abort()
	transport, _ = startChannelPeer(t, wire.SMB311, key, primary, false, func(p *channelPeer) { p.serverGuid = uuid.UUID{2} })
	require.Error(t, s.BindChannel(ctx, &singleRoundInitiator{key: key}, transport))
	require.NoError(t, s.Echo(ctx))
}

// Each subtest owns its peers; callers retain their top-level Parallel call.
func testChannelSigningAlgorithms(t *testing.T, run func(*testing.T, func(*channelPeer))) {
	t.Helper()
	for _, tc := range []struct {
		name      string
		algorithm wire.SigningAlgorithm
	}{
		{"CMAC", wire.AES128CMAC},
		{"GMAC", wire.AES128GMAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run(t, func(p *channelPeer) { p.algorithm = tc.algorithm })
		})
	}
}

func TestConcurrentBindChannels(t *testing.T) {
	t.Parallel()
	testChannelSigningAlgorithms(t, func(t *testing.T, signing func(*channelPeer)) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		key := []byte("original GSS key")
		transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false, signing)
		s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
		require.NoError(t, err)
		defer s.Abort()
		results := make(chan error, 2)
		for range 2 {
			transport, _ := startChannelPeer(t, wire.SMB311, key, primary, false, signing)
			go func() { results <- s.BindChannel(ctx, &singleRoundInitiator{key: key}, transport) }()
		}
		for range 2 {
			require.NoError(t, <-results)
		}
		require.Len(t, s.s.channels.channels, 3)
		for range 3 {
			require.NoError(t, s.Echo(ctx))
		}
	})
}

func TestBoundWriteIsNotReplayedAfterConnectionLoss(t *testing.T) {
	t.Parallel()
	testChannelSigningAlgorithms(t, func(t *testing.T, signing func(*channelPeer)) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		key := []byte("original GSS key")
		transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false, signing)
		s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
		require.NoError(t, err)
		defer s.Abort()
		transport, bound := startChannelPeer(t, wire.SMB311, key, primary, false, signing, func(p *channelPeer) { p.dropWrites = true })
		require.NoError(t, s.BindChannel(ctx, &singleRoundInitiator{key: key}, transport))
		require.NoError(t, s.Echo(ctx))
		<-primary.requests
		_, err = s.s.sendRecv(ctx, &wire.WriteRequest{Data: []byte("uncertain write")})
		require.Error(t, err)
		require.Equal(t, wire.SMB2_WRITE, wire.PacketCodec(<-bound.requests).Command())
		require.Empty(t, primary.requests, "a transmitted write must not be replayed")
		require.NoError(t, s.Echo(ctx))
		require.NoError(t, s.s.conn.close(nil))
		newTransport := new(sessionCloseTransport)
		require.ErrorIs(t, s.BindChannel(ctx, &singleRoundInitiator{key: key}, newTransport), net.ErrClosed)
		require.Equal(t, int32(1), newTransport.closes.Load())
	})
}

func TestBoundRequestCancellationUsesOriginalChannel(t *testing.T) {
	t.Parallel()
	testChannelSigningAlgorithms(t, func(t *testing.T, signing func(*channelPeer)) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		key := []byte("original authentication")
		transport, primary := startChannelPeer(t, wire.SMB311, key, nil, false, signing)
		s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
		require.NoError(t, err)
		defer s.Abort()
		transport, bound := startChannelPeer(t, wire.SMB311, key, primary, false, signing, func(p *channelPeer) { p.holdRequests = true })
		require.NoError(t, s.BindChannel(ctx, &singleRoundInitiator{key: key}, transport))
		require.NoError(t, s.Echo(ctx)) // Advance round robin to the bound connection.
		<-primary.requests
		requestCtx, cancelRequest := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- s.Echo(requestCtx) }()
		request := <-bound.requests
		s.s.channels.sequence.Store(7)
		cancelRequest()
		require.ErrorIs(t, <-done, context.Canceled)
		select {
		case cancelPacket := <-bound.requests:
			require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(cancelPacket).Command())
			require.Equal(t, wire.PacketCodec(request).MessageId(), wire.PacketCodec(cancelPacket).MessageId())
			require.Equal(t, uint16(7), wire.PacketCodec(cancelPacket).ChannelSequence())
		case <-ctx.Done():
			t.Fatal("CANCEL was not sent to bound channel")
		}
		require.Empty(t, primary.requests)
		require.NoError(t, s.Echo(ctx))
	})
}

func TestCloseAndAbortInterruptPendingBind(t *testing.T) {
	t.Parallel()
	testChannelSigningAlgorithms(t, func(t *testing.T, signing func(*channelPeer)) {
		for _, graceful := range []bool{false, true} {
			t.Run(fmt.Sprint(graceful), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				key := []byte("original authentication")
				transport, _ := startChannelPeer(t, wire.SMB311, key, nil, false, signing)
				s, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, transport)
				require.NoError(t, err)
				defer s.Abort()
				client, server := net.Pipe()
				defer server.Close()
				result := make(chan error, 1)
				go func() { result <- s.BindChannel(ctx, &singleRoundInitiator{key: key}, NewTransport(client)) }()
				_, err = readMsg(NewTransport(server)) // Hold the first bind in NEGOTIATE.
				require.NoError(t, err)
				waiting := new(sessionCloseTransport)
				canceled, stop := context.WithCancel(ctx)
				stop()
				require.ErrorIs(t, s.BindChannel(canceled, &singleRoundInitiator{key: key}, waiting), context.Canceled)
				require.Equal(t, int32(1), waiting.closes.Load())
				if graceful {
					require.NoError(t, s.Close())
				} else {
					require.NoError(t, s.Abort())
				}
				select {
				case err := <-result:
					require.Error(t, err)
				case <-ctx.Done():
					t.Fatal("pending bind survived shutdown")
				}
				require.Len(t, s.s.channels.channels, 1, "pending connection must never be published")
			})
		}
	})
}
