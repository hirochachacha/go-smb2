package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestLegacyCipherPolicy(t *testing.T) {
	t.Parallel()
	for _, dialect := range []Dialect{SMB210, SMB300, SMB302} {
		for _, policy := range []struct {
			name     string
			ciphers  []Cipher
			allowCCM bool
		}{
			{name: "nil", allowCCM: true},
			{name: "empty", ciphers: []Cipher{}, allowCCM: true},
			{name: "CCM-included", ciphers: []Cipher{AES256GCM, AES128CCM}, allowCCM: true},
			{name: "CCM-excluded", ciphers: []Cipher{AES256GCM}},
		} {
			for _, scope := range []string{"plaintext", "session", "share"} {
				if dialect == SMB210 && scope != "plaintext" {
					continue
				}
				t.Run(fmt.Sprintf("%x/%s/%s", dialect, policy.name, scope), func(t *testing.T) {
					client, peer := net.Pipe()
					defer peer.Close()
					defer client.Close()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16)}
					var flags uint16
					if scope == "session" {
						flags = wire.SMB2_SESSION_FLAG_ENCRYPT_DATA
					}
					type result struct {
						packet []byte
						err    error
					}
					done := make(chan result, 1)
					go func() {
						st := NewTransport(peer)
						request, err := readMsg(st)
						if err != nil {
							done <- result{err: err}
							return
						}
						response := &wire.NegotiateResponse{
							Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: wire.PacketCodec(request).MessageId(),
							SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_ENABLED, DialectRevision: uint16(dialect),
							Capabilities: wire.SMB2_GLOBAL_CAP_ENCRYPTION, MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536,
						}
						data := make([]byte, response.Size())
						response.Encode(data)
						wire.PacketCodec(data).SetCreditResponse(1)
						if _, err := st.writev(data); err != nil {
							done <- result{err: err}
							return
						}
						runSingleRoundSessionSetupServerModeWithCapabilities(st, initiator, singleRoundUnsigned, false, nil, flags)
						packet, err := readMsg(st)
						done <- result{packet, err}
					}()
					d := &Dialer{SpecifiedDialects: []Dialect{dialect}, Ciphers: policy.ciphers}
					session, err := d.Dial(ctx, initiator, NewTransport(client))
					require.NoError(t, err, "plaintext legacy connections remain permitted")
					defer session.Abort()
					s := session.s
					if scope == "share" {
						tree := &Tree{session: s, treeId: 42, shareFlags: wire.SMB2_SHAREFLAG_ENCRYPT_DATA}
						_, err = tree.send(ctx, &wire.FlushRequest{})
					} else {
						_, err = s.send(ctx, s.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0, &wire.EchoRequest{})
					}
					blocked := scope != "plaintext" && !policy.allowCCM
					if blocked {
						if err == nil {
							got := <-done
							require.NoError(t, got.err)
							transform := wire.TransformCodec(got.packet)
							decryptor := newSessionTestAEAD(t, wire.AES128CCM, kdfForTest(initiator.key, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16))
							ciphertext := append(bytes.Clone(got.packet[52:]), transform.Signature()...)
							_, err := decryptor.Open(nil, transform.Nonce()[:11], ciphertext, transform.AssociatedData())
							require.NoError(t, err)
							t.Fatal("sent an AES-128-CCM transform excluded by Ciphers")
						}
						require.ErrorContains(t, err, "encryption required but no cipher negotiated")
						require.NoError(t, session.Abort())
						got := <-done
						require.Empty(t, got.packet, "excluded CCM must never be sent")
						require.Error(t, got.err)
						return
					}
					require.NoError(t, err)
					got := <-done
					require.NoError(t, got.err)
					packet := got.packet
					if scope != "plaintext" {
						require.Equal(t, byte(0xfd), packet[0], "legacy encryption uses an SMB transform")
						decryptor := newSessionTestAEAD(t, wire.AES128CCM, kdfForTest(initiator.key, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16))
						transform := wire.TransformCodec(packet)
						ciphertext := append(bytes.Clone(packet[52:]), transform.Signature()...)
						packet, err = decryptor.Open(nil, transform.Nonce()[:11], ciphertext, transform.AssociatedData())
						require.NoError(t, err, "on-wire packet must decrypt with AES-128-CCM")
					} else {
						require.Equal(t, byte(0xfe), packet[0])
					}
					if scope == "share" {
						require.Equal(t, wire.SMB2_FLUSH, wire.PacketCodec(packet).Command())
						require.EqualValues(t, 42, wire.PacketCodec(packet).TreeId())
					} else {
						require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(packet).Command())
					}
				})
			}
		}
	}
}

func TestDialerInvalidArgumentsPanic(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nil Dialer", "nil Initiator", "nil Transport"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			d := &Dialer{}
			var initiator Initiator = &singleRoundInitiator{}
			transport := NewTransport(client)
			switch name {
			case "nil Dialer":
				d = nil
			case "nil Initiator":
				initiator = nil
			case "nil Transport":
				transport = nil
			}
			require.PanicsWithValue(t, "protocol: "+name, func() {
				_, _ = d.Dial(context.Background(), initiator, transport)
			})
			if transport != nil {
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				_, err := server.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

func signingDataContext(data []byte) wire.Encoder {
	b := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(b, wire.SMB2_SIGNING_CAPABILITIES)
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(data)))
	copy(b[8:], data)
	return rawEncoder(b)
}

func signingNegotiatePeer(st Transport, dialect Dialect, contexts wire.NegotiateContexts) (preauth [64]byte, err error) {
	request, err := readMsg(st)
	if err != nil {
		return preauth, err
	}
	r := wire.NegotiateRequestDecoder(request[64:])
	if r.IsInvalid() {
		return preauth, fmt.Errorf("invalid request")
	}
	found := false
	for _, ctx := range r.Contexts().Contexts() {
		if ctx.ContextType() == wire.SMB2_SIGNING_CAPABILITIES {
			found = true
			d := wire.SigningContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return preauth, fmt.Errorf("invalid signing offer")
			}
			if !slices.Equal(d.SigningAlgorithms(), []wire.SigningAlgorithm{wire.AES128GMAC, wire.AES128CMAC}) {
				return preauth, fmt.Errorf("unexpected signing offer")
			}
		}
	}
	if found != (dialect == SMB311) {
		return preauth, fmt.Errorf("signing capabilities scope mismatch")
	}
	response := &wire.NegotiateResponse{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: wire.PacketCodec(request).MessageId(), SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_REQUIRED, DialectRevision: uint16(dialect), MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536}
	if dialect == SMB311 {
		response.Contexts = append(wire.NegotiateContexts{&wire.HashContext{HashAlgorithms: []uint16{wire.SHA512}}}, contexts...)
	}
	data := make([]byte, response.Size())
	response.Encode(data)
	wire.PacketCodec(data).SetCreditResponse(10)
	if dialect == SMB311 {
		preauth = sha512.Sum512(append(preauth[:], request...))
		preauth = sha512.Sum512(append(preauth[:], data...))
	}
	_, err = st.writev(data)
	return preauth, err
}

func TestSigningNegotiation(t *testing.T) {
	selected := func(ids ...wire.SigningAlgorithm) wire.Encoder { return &wire.SigningContext{SigningAlgorithms: ids} }
	for _, tc := range []struct {
		name     string
		contexts wire.NegotiateContexts
		want     wire.SigningAlgorithm
		invalid  bool
	}{
		{"GMAC", wire.NegotiateContexts{selected(wire.AES128GMAC)}, wire.AES128GMAC, false},
		{"CMAC", wire.NegotiateContexts{selected(wire.AES128CMAC)}, wire.AES128CMAC, false},
		{"absent", nil, wire.AES128CMAC, false},
		{"duplicate", wire.NegotiateContexts{selected(wire.AES128GMAC), selected(wire.AES128GMAC)}, 0, true},
		{"empty", wire.NegotiateContexts{selected()}, 0, true},
		{"multiple", wire.NegotiateContexts{selected(wire.AES128GMAC, wire.AES128CMAC)}, 0, true},
		{"unoffered HMAC", wire.NegotiateContexts{selected(wire.HMACSHA256)}, 0, true},
		{"unknown", wire.NegotiateContexts{selected(0xffff)}, 0, true},
		{"partial ID", wire.NegotiateContexts{signingDataContext([]byte{1, 0, 2})}, 0, true},
		{"count exceeds data", wire.NegotiateContexts{signingDataContext([]byte{2, 0, 2, 0})}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			defer client.Close()
			done := make(chan error, 1)
			go func() { _, err := signingNegotiatePeer(NewTransport(peer), SMB311, tc.contexts); done <- err }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}}).negotiate(ctx, NewTransport(client), openAccount(128))
			if tc.invalid {
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			} else {
				require.NoError(t, err)
				defer c.close(nil)
				require.Equal(t, tc.want, c.signingAlgorithm)
			}
			require.NoError(t, <-done)
		})
	}
}

func peerMessageTag(t *testing.T, dialect Dialect, algorithm wire.SigningAlgorithm, key []byte, preauth [64]byte, packet []byte, fromServer bool) []byte {
	t.Helper()
	if dialect != SMB311 || algorithm != wire.AES128GMAC {
		return expectedSessionSignatureForTest(t, uint16(dialect), key, preauth[:], packet)
	}
	block, err := aes.NewCipher(kdfForTest(key, []byte("SMBSigningKey\x00"), preauth[:], 16))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	n := [12]byte{}
	binary.LittleEndian.PutUint64(n[:8], wire.PacketCodec(packet).MessageId())
	if fromServer {
		n[8] = 1
	}
	return gcm.Seal(nil, n[:], nil, packet)
}

func signingSessionPeer(t *testing.T, st Transport, dialect Dialect, selected *wire.SigningAlgorithm, badFinal, async bool, key []byte) error {
	var contexts wire.NegotiateContexts
	algorithm := wire.AES128CMAC
	if selected != nil {
		algorithm = *selected
		contexts = wire.NegotiateContexts{&wire.SigningContext{SigningAlgorithms: []wire.SigningAlgorithm{algorithm}}}
	}
	preauth, err := signingNegotiatePeer(st, dialect, contexts)
	if err != nil {
		return err
	}
	request, err := readMsg(st)
	if err != nil {
		return err
	}
	p := wire.PacketCodec(request)
	if p.Command() != wire.SMB2_SESSION_SETUP {
		return fmt.Errorf("expected SESSION_SETUP")
	}
	if dialect == SMB311 {
		preauth = sha512.Sum512(append(preauth[:], request...))
	}
	token, err := spnego.EncodeNegTokenResp(negStateAcceptCompleted, spnego.NlmpOid, []byte("server-final-token"), nil)
	if err != nil {
		return err
	}
	setup := &wire.SessionSetupResponse{SecurityBuffer: token}
	setup.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_SIGNED)
	setup.SetSessionId(0x1234)
	setup.SetMessageId(p.MessageId())
	data := make([]byte, setup.Size())
	setup.Encode(data)
	wire.PacketCodec(data).SetCreditResponse(1)
	actual := algorithm
	if badFinal {
		actual = wire.AES128CMAC
	}
	copy(data[48:64], peerMessageTag(t, dialect, actual, key, preauth, data, true))
	if _, err = st.writev(data); err != nil {
		return err
	}
	if badFinal {
		return nil
	}
	request, err = readMsg(st)
	if err != nil {
		return err
	}
	p = wire.PacketCodec(request)
	if p.Command() != wire.SMB2_ECHO {
		return fmt.Errorf("expected ECHO")
	}
	signature := append([]byte(nil), p.Signature()...)
	clear(p.Signature())
	if !bytes.Equal(signature, peerMessageTag(t, dialect, algorithm, key, preauth, request, false)) {
		return fmt.Errorf("client ECHO signature invalid")
	}
	if async {
		pending := &wire.ErrorResponse{CommandCode: wire.SMB2_ECHO}
		pending.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND)
		pending.SetMessageId(p.MessageId())
		pending.SetSessionId(0x1234)
		data = make([]byte, pending.Size())
		pending.Encode(data)
		r := wire.PacketCodec(data)
		r.SetStatus(uint32(erref.STATUS_PENDING))
		r.SetAsyncId(0xabcd)
		r.SetCreditResponse(0)
		if _, err = st.writev(data); err != nil {
			return err
		}
	}
	echo := &wire.EchoResponse{}
	echo.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_SIGNED)
	echo.SetSessionId(0x1234)
	echo.SetMessageId(p.MessageId())
	data = make([]byte, echo.Size())
	echo.Encode(data)
	r := wire.PacketCodec(data)
	r.SetCreditResponse(1)
	if async {
		r.SetFlags(r.Flags() | wire.SMB2_FLAGS_ASYNC_COMMAND)
		r.SetAsyncId(0xabcd)
	}
	copy(data[48:64], peerMessageTag(t, dialect, algorithm, key, preauth, data, true))
	_, err = st.writev(data)
	return err
}

func TestSigningNegotiationSessionRoundTrip(t *testing.T) {
	gmac, cmac := wire.AES128GMAC, wire.AES128CMAC
	for _, tc := range []struct {
		name            string
		dialect         Dialect
		selected        *wire.SigningAlgorithm
		badFinal, async bool
	}{
		{"GMAC", SMB311, &gmac, false, false}, {"GMAC async", SMB311, &gmac, false, true},
		{"CMAC", SMB311, &cmac, false, false}, {"context absent", SMB311, nil, false, false},
		{"GMAC rejects CMAC final", SMB311, &gmac, true, false},
		{"SMB302", SMB302, nil, false, false}, {"SMB300", SMB300, nil, false, false},
		{"SMB210", SMB210, nil, false, false}, {"SMB202", SMB202, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			defer client.Close()
			release := make(chan struct{})
			defer close(release)
			key := bytes.Repeat([]byte{0x42}, 16)
			done := make(chan error, 1)
			go func() {
				done <- signingSessionPeer(t, NewTransport(peer), tc.dialect, tc.selected, tc.badFinal, tc.async, key)
				<-release
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, err := (&Dialer{SpecifiedDialects: []Dialect{tc.dialect}, RequireMessageSigning: true}).Dial(ctx, &singleRoundInitiator{key: key}, NewTransport(client))
			if tc.badFinal {
				require.ErrorContains(t, err, "signature verification")
				require.Nil(t, s)
			} else {
				require.NoError(t, err)
				defer s.Abort()
				require.NoError(t, s.Echo(ctx))
				if tc.selected != nil && *tc.selected == wire.AES128GMAC {
					require.NotNil(t, s.s.gmacSigner)
				} else {
					require.NotNil(t, s.s.signer)
					require.Nil(t, s.s.gmacSigner)
				}
			}
			require.NoError(t, <-done)
		})
	}
}
