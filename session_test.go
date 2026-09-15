package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/v2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/stretchr/testify/require"
)

func TestDialClosesConnectionOnSessionSetupError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Round 1: server replies to Negotiate request with success
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
			DialectRevision: smb2.SMB210,
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

		// Round 2: read SessionSetup request then close serverConn to simulate network/auth failure
		if _, err := readMsg(st); err != nil {
			return
		}
		_ = serverConn.Close()
	}()

	d := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &NTLMInitiator{
				User:     "user",
				Password: "password",
			}, nil
		}),
		TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
			return direct(clientConn), nil
		}),
	}

	_, err := d.Dial(context.Background(), "server")
	require.Error(t, err)

	// clientConn must be closed on sessionSetup failure
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(t, readErr, "clientConn should be closed after failed sessionSetup")
}

// installTrackingRecvBufPool temporarily replaces the global receive buffer
// pool with a pool that records every buffer it creates. The returned
// function yields the tracked buffers so tests can assert that sessionSetup
// released all of them (refCount back to 0) instead of leaking.
func installTrackingRecvBufPool(t *testing.T) (trackedBufs func() []*recvBuf) {
	t.Helper()

	origPool := recvBufPool.Load()

	var mu sync.Mutex
	var bufs []*recvBuf

	recvBufPool.Store(&sync.Pool{
		New: func() any {
			buf := &recvBuf{data: make([]byte, 0, maxSingleCreditPayloadSize)}
			mu.Lock()
			bufs = append(bufs, buf)
			mu.Unlock()
			return buf
		},
	})
	t.Cleanup(func() { recvBufPool.Store(origPool) })

	return func() []*recvBuf {
		mu.Lock()
		defer mu.Unlock()
		return append([]*recvBuf(nil), bufs...)
	}
}

// requireAllRecvBufsReleased asserts that every pooled buffer allocated
// during the test was closed, i.e. handed back to the pool.
func requireAllRecvBufsReleased(t *testing.T, trackedBufs func() []*recvBuf) {
	t.Helper()

	require.Eventually(t, func() bool {
		bufs := trackedBufs()
		if len(bufs) == 0 {
			return false
		}
		for _, buf := range bufs {
			if buf.refCount.Load() != 0 {
				return false
			}
		}
		return true
	}, 2*time.Second, 5*time.Millisecond, "every pooled receive buffer must be released after sessionSetup returns")
}

// runFakeSessionSetupServer reads SESSION_SETUP requests and replies
// according to the given mode. For the NTLM modes it performs a real NTLMv2
// handshake backed by ntlmServer.
func runFakeSessionSetupServer(t transport, mode int, ntlmServer *ntlm.Server) {
	// Mirror of the client's preauth integrity hash for SMB 3.1.1 signing.
	var preauth [64]byte

	for round := 1; ; round++ {
		reqBuf, err := readMsg(t)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_SESSION_SETUP {
			return
		}
		req := smb2.SessionSetupRequestDecoder(reqBuf[64:])

		var status uint32
		var sessionFlags uint16
		var token []byte
		var signed bool

		switch {
		case mode == sessionSetupServerGuestReject:
			// Intermediate response flagged as guest; the client rejects it
			// before touching the security buffer when signing is required.
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			sessionFlags = smb2.SMB2_SESSION_FLAG_IS_GUEST
		case mode == sessionSetupServerNullReject:
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			sessionFlags = smb2.SMB2_SESSION_FLAG_IS_NULL
		case mode == sessionSetupServerInvalidSecurityContext && round == 1:
			// Valid framing, but the security buffer is garbage so the SPNEGO
			// decoder fails on the client side.
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			token = []byte{0xde, 0xad, 0xbe, 0xef}
		case (mode == sessionSetupServerSuccess || mode == sessionSetupServerSuccessSigned || mode == sessionSetupServerTamperedFinalSignature || mode == sessionSetupServerFinalGuest || mode == sessionSetupServerFinalNull || mode == sessionSetupServerFinalReject || mode == sessionSetupServerFinalIncomplete || mode == sessionSetupServerFinalInvalid) && round == 1:
			init, err := spnego.DecodeNegTokenInit(req.SecurityBuffer())
			if err != nil {
				return
			}
			cmsg, err := ntlmServer.Challenge(init.MechToken)
			if err != nil {
				return
			}
			token, err = spnego.EncodeNegTokenResp(1, spnego.NlmpOid, cmsg, nil)
			if err != nil {
				return
			}
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
		case (mode == sessionSetupServerSuccess || mode == sessionSetupServerSuccessSigned || mode == sessionSetupServerTamperedFinalSignature || mode == sessionSetupServerFinalGuest || mode == sessionSetupServerFinalNull || mode == sessionSetupServerFinalReject || mode == sessionSetupServerFinalIncomplete || mode == sessionSetupServerFinalInvalid) && round == 2:
			resp, err := spnego.DecodeNegTokenResp(req.SecurityBuffer())
			if err != nil {
				return
			}
			if err := ntlmServer.Authenticate(resp.ResponseToken); err != nil {
				return
			}
			status = uint32(erref.STATUS_SUCCESS)
			signed = mode == sessionSetupServerTamperedFinalSignature
			switch mode {
			case sessionSetupServerFinalGuest:
				sessionFlags = smb2.SMB2_SESSION_FLAG_IS_GUEST
				token, err = spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, nil)
			case sessionSetupServerFinalNull:
				sessionFlags = smb2.SMB2_SESSION_FLAG_IS_NULL
				token, err = spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, nil)
			case sessionSetupServerSuccess, sessionSetupServerSuccessSigned, sessionSetupServerTamperedFinalSignature:
				token, err = spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, nil)
			case sessionSetupServerFinalReject:
				token, err = spnego.EncodeNegTokenResp(negStateReject, spnego.NlmpOid, nil, nil)
				signed = true
			case sessionSetupServerFinalIncomplete:
				token, err = spnego.EncodeNegTokenResp(negStateAcceptIncomplete, spnego.NlmpOid, nil, nil)
				signed = true
			case sessionSetupServerFinalInvalid:
				token = []byte{0xde, 0xad, 0xbe, 0xef}
				signed = true
			}
			if err != nil {
				return
			}
		default:
			return
		}

		respBuf := make([]byte, 64+8+len(token))
		copy(respBuf[64+8:], token)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9)                  // StructureSize
		binary.LittleEndian.PutUint16(respBuf[66:68], sessionFlags)       // SessionFlags
		binary.LittleEndian.PutUint16(respBuf[68:70], 8+64)               // SecurityBufferOffset
		binary.LittleEndian.PutUint16(respBuf[70:72], uint16(len(token))) // SecurityBufferLength

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_SESSION_SETUP)
		rp.SetStatus(status)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(p.CreditRequest())
		rp.SetSessionId(0x1234)

		if signed {
			// Sign final GSS failures so rejection tests reach token validation.
			// The tampering mode instead supplies a bogus signature.
			rp.SetFlags(rp.Flags() | smb2.SMB2_FLAGS_SIGNED)
			if mode == sessionSetupServerFinalReject || mode == sessionSetupServerFinalIncomplete || mode == sessionSetupServerFinalInvalid {
				signer := hmac.New(sha256.New, normalizeSessionKeyForTest(ntlmServer.Session().SessionKey()))
				signer.Write(respBuf)
				rp.SetSignature(signer.Sum(nil))
			} else {
				for i := range rp.Signature() {
					rp.Signature()[i] = 0xA5
				}
			}
		}

		if mode == sessionSetupServerSuccessSigned {
			switch round {
			case 1:
				// Mirror the client's preauth integrity hash updates
				// (SESSION_SETUP request, then its response).
				updatePreauthHash(&preauth, reqBuf)
				updatePreauthHash(&preauth, respBuf)
			case 2:
				updatePreauthHash(&preauth, reqBuf)

				// Sign the final response with the SMB 3.1.1 signing key so
				// the client can complete signature verification.
				signingKey := kdf(ntlmServer.Session().SessionKey(), []byte("SMBSigningKey\x00"), preauth[:], 16)
				ciph, err := aes.NewCipher(signingKey)
				if err != nil {
					return
				}
				signer := cmac.New(ciph)
				rp.SetFlags(rp.Flags() | smb2.SMB2_FLAGS_SIGNED)
				signer.Write(respBuf)
				rp.SetSignature(signer.Sum(nil))
			}
		}

		if _, err := t.Writev(respBuf); err != nil {
			return
		}
	}
}

const (
	sessionSetupServerSuccess = iota
	sessionSetupServerSuccessSigned
	sessionSetupServerGuestReject
	sessionSetupServerInvalidSecurityContext
	sessionSetupServerTamperedFinalSignature
	sessionSetupServerFinalGuest
	sessionSetupServerFinalNull
	sessionSetupServerNullReject
	sessionSetupServerFinalReject
	sessionSetupServerFinalIncomplete
	sessionSetupServerFinalInvalid
)

type singleRoundInitiator struct {
	key         []byte
	acceptErr   error
	accepted    []byte
	outputToken []byte
	negState    asn1.Enumerated
	anonymous   bool
}

func (i *singleRoundInitiator) isAnonymous() bool { return i.anonymous }

func (i *singleRoundInitiator) OID() asn1.ObjectIdentifier { return spnego.NlmpOid }

func (i *singleRoundInitiator) InitSecContext() ([]byte, error) {
	return []byte("client-initial-token"), nil
}

func (i *singleRoundInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	i.accepted = append([]byte(nil), sc...)
	if i.acceptErr != nil {
		return nil, i.acceptErr
	}
	return i.outputToken, nil
}

func (i *singleRoundInitiator) GetMIC([]byte) ([]byte, error)  { return nil, nil }
func (i *singleRoundInitiator) Complete() bool                 { return true }
func (i *singleRoundInitiator) VerifyMIC([]byte, []byte) error { return nil }

func (i *singleRoundInitiator) SessionKey() []byte { return i.key }

func normalizeSessionKeyForTest(key []byte) []byte {
	var normalized [16]byte
	copy(normalized[:], key)
	return normalized[:]
}

func kdfForTest(key, label, context []byte, keySize int) []byte {
	h := hmac.New(sha256.New, key)
	var outputBits [4]byte
	binary.BigEndian.PutUint32(outputBits[:], uint32(keySize*8))
	h.Write([]byte{0, 0, 0, 1})
	h.Write(label)
	h.Write([]byte{0})
	h.Write(context)
	h.Write(outputBits[:])
	return h.Sum(nil)[:keySize]
}

func expectedSessionSignatureForTest(t *testing.T, dialect uint16, key []byte, preauth []byte, pkt []byte) []byte {
	t.Helper()

	normalized := normalizeSessionKeyForTest(key)
	var signer hash.Hash
	switch dialect {
	case smb2.SMB202, smb2.SMB210:
		signer = hmac.New(sha256.New, normalized)
	case smb2.SMB300, smb2.SMB302:
		ciph, err := aes.NewCipher(kdfForTest(normalized, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16))
		require.NoError(t, err)
		signer = cmac.New(ciph)
	case smb2.SMB311:
		ciph, err := aes.NewCipher(kdfForTest(normalized, []byte("SMBSigningKey\x00"), preauth, 16))
		require.NoError(t, err)
		signer = cmac.New(ciph)
	default:
		t.Fatalf("unsupported dialect %d", dialect)
	}

	signer.Write(pkt)
	return signer.Sum(nil)[:16]
}

func runSingleRoundSessionSetupServer(t transport, initiator *singleRoundInitiator, signatureMode int) {
	runSingleRoundSessionSetupServerMode(t, initiator, signatureMode, true)
}

// runSingleRoundSessionSetupServerKeepOpen is used by client lifecycle tests
// that need to observe requests after authentication completes.
func runSingleRoundSessionSetupServerKeepOpen(t transport, initiator *singleRoundInitiator, signatureMode int) {
	runSingleRoundSessionSetupServerMode(t, initiator, signatureMode, false)
}

func runSingleRoundSessionSetupServerMode(t transport, initiator *singleRoundInitiator, signatureMode int, closeTransport bool) {
	runSingleRoundSessionSetupServerModeWithCapabilities(t, initiator, signatureMode, closeTransport, nil)
}

func runSingleRoundSessionSetupServerWithCapabilities(t transport, initiator *singleRoundInitiator, signatureMode int, capabilities chan<- uint32) {
	runSingleRoundSessionSetupServerModeWithCapabilities(t, initiator, signatureMode, true, capabilities)
}

func runSingleRoundSessionSetupServerModeWithCapabilities(t transport, initiator *singleRoundInitiator, signatureMode int, closeTransport bool, capabilities chan<- uint32) {
	reqBuf, err := readMsg(t)
	if err != nil {
		return
	}
	p := smb2.PacketCodec(reqBuf)
	if p.Command() != smb2.SMB2_SESSION_SETUP {
		return
	}
	req := smb2.SessionSetupRequestDecoder(reqBuf[64:])
	if capabilities != nil {
		capabilities <- req.Capabilities()
	}
	init, err := spnego.DecodeNegTokenInit(req.SecurityBuffer())
	if err != nil || !bytes.Equal(init.MechToken, []byte("client-initial-token")) {
		return
	}

	token, err := spnego.EncodeNegTokenResp(initiator.negState, spnego.NlmpOid, []byte("server-final-token"), nil)
	if err != nil {
		return
	}

	respBuf := make([]byte, 64+8+len(token))
	copy(respBuf[64+8:], token)
	binary.LittleEndian.PutUint16(respBuf[64:66], 9)
	binary.LittleEndian.PutUint16(respBuf[66:68], 0)
	binary.LittleEndian.PutUint16(respBuf[68:70], 8+64)
	binary.LittleEndian.PutUint16(respBuf[70:72], uint16(len(token)))

	rp := smb2.PacketCodec(respBuf)
	rp.SetProtocolId()
	rp.SetStructureSize()
	rp.SetCommand(smb2.SMB2_SESSION_SETUP)
	rp.SetStatus(uint32(erref.STATUS_SUCCESS))
	rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	rp.SetMessageId(p.MessageId())
	rp.SetCreditResponse(p.CreditRequest())
	rp.SetSessionId(0x1234)

	if signatureMode != singleRoundUnsigned {
		preauth := [64]byte{0x37}
		updatePreauthHash(&preauth, reqBuf)
		signingKey := kdfForTest(normalizeSessionKeyForTest(initiator.key), []byte("SMBSigningKey\x00"), preauth[:], 16)
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return
		}
		signer := cmac.New(ciph)
		rp.SetFlags(rp.Flags() | smb2.SMB2_FLAGS_SIGNED)
		signer.Write(respBuf)
		rp.SetSignature(signer.Sum(nil))
		if signatureMode == singleRoundTampered {
			for i := range rp.Signature() {
				rp.Signature()[i] ^= 0xff
			}
		}
	}

	_, _ = t.Writev(respBuf)
	if closeTransport {
		_ = t.Close()
	}
}

const (
	singleRoundUnsigned = iota
	singleRoundSigned
	singleRoundTampered
)

func TestSessionSetupAcceptsSingleRoundAuthentication(t *testing.T) {
	for _, test := range []struct {
		name    string
		dialect uint16
		signed  bool
	}{
		{name: "SMB302", dialect: smb2.SMB302},
		{name: "SMB311", dialect: smb2.SMB311, signed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16)}
			serverMode := singleRoundUnsigned
			if test.signed {
				serverMode = singleRoundSigned
			}
			go runSingleRoundSessionSetupServer(direct(serverConn), initiator, serverMode)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.dialect = test.dialect
			c.preauthIntegrityHashId = smb2.SHA512
			c.preauthIntegrityHashValue = [64]byte{0x37}
			c.cipherId = smb2.AES128GCM

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, err := c.sessionSetup(ctx, initiator)
			require.NoError(t, err)
			require.NotNil(t, s)
			require.Equal(t, []byte("server-final-token"), initiator.accepted)
			require.Equal(t, uint64(0x1234), s.sessionId)
			require.NotNil(t, s.signer)
			require.NotNil(t, s.verifier)
			require.NotNil(t, s.encrypter)
			require.NotNil(t, s.decrypter)
			require.True(t, c.useSession())
		})
	}
}

func TestSessionSetupAdvertisesDFSWithoutServerCapability(t *testing.T) {
	for _, serverCapabilities := range []uint32{0, smb2.SMB2_GLOBAL_CAP_DFS} {
		t.Run(fmt.Sprintf("server-capabilities-%x", serverCapabilities), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16)}
			capabilities := make(chan uint32, 1)
			go runSingleRoundSessionSetupServerWithCapabilities(direct(serverConn), initiator, singleRoundUnsigned, capabilities)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.capabilities = serverCapabilities

			s, err := c.sessionSetup(context.Background(), initiator)
			require.NoError(t, err)
			require.NotNil(t, s)
			require.Equal(t, uint32(smb2.SMB2_GLOBAL_CAP_DFS), <-capabilities)
		})
	}
}

func TestSetupKeysNormalizesGSSSessionKey(t *testing.T) {
	tests := []struct {
		name     string
		dialect  uint16
		cipherID uint16
	}{
		{name: "SMB202", dialect: smb2.SMB202},
		{name: "SMB210", dialect: smb2.SMB210},
		{name: "SMB300", dialect: smb2.SMB300},
		{name: "SMB302", dialect: smb2.SMB302},
		{name: "SMB311-AES128", dialect: smb2.SMB311, cipherID: smb2.AES128GCM},
		{name: "SMB311-AES256", dialect: smb2.SMB311, cipherID: smb2.AES256GCM},
	}

	keys := [][]byte{
		bytes.Repeat([]byte{0x11}, 8),
		bytes.Repeat([]byte{0x22}, 16),
		append(bytes.Repeat([]byte{0x33}, 16), bytes.Repeat([]byte{0x44}, 16)...),
	}
	preauth := bytes.Repeat([]byte{0x37}, 64)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range keys {
				t.Run(fmt.Sprintf("key-%d", len(key)), func(t *testing.T) {
					originalKey := bytes.Clone(key)
					s := &session{
						conn: &conn{
							dialect:  test.dialect,
							cipherId: test.cipherID,
						},
					}
					copy(s.preauthIntegrityHashValue[:], preauth)
					require.NoError(t, s.setupKeys(key))
					require.Equal(t, originalKey, key)

					req := &smb2.EchoRequest{}
					pkt := make([]byte, req.Size())
					req.Encode(pkt)
					expectedPkt := bytes.Clone(pkt)
					smb2.PacketCodec(expectedPkt).SetFlags(smb2.SMB2_FLAGS_SIGNED)
					expected := expectedSessionSignatureForTest(t, test.dialect, key, preauth, expectedPkt)

					s.sign(pkt)
					require.Equal(t, expected, smb2.PacketCodec(pkt).Signature())
				})
			}

			keyA := append(bytes.Repeat([]byte{0x5a}, 16), bytes.Repeat([]byte{0xa5}, 16)...)
			keyB := append(bytes.Repeat([]byte{0x5a}, 16), bytes.Repeat([]byte{0x3c}, 16)...)
			sign := func(key []byte) []byte {
				s := &session{conn: &conn{dialect: test.dialect, cipherId: test.cipherID}}
				copy(s.preauthIntegrityHashValue[:], preauth)
				require.NoError(t, s.setupKeys(key))
				req := &smb2.EchoRequest{}
				pkt := make([]byte, req.Size())
				req.Encode(pkt)
				s.sign(pkt)
				return bytes.Clone(smb2.PacketCodec(pkt).Signature())
			}
			require.Equal(t, sign(keyA), sign(keyB), "bytes after the first 16 must not affect SMB2 keys")
		})
	}
}

func newSessionTestAEAD(t *testing.T, cipherID uint16, key []byte) cipher.AEAD {
	t.Helper()
	ciph, err := aes.NewCipher(key)
	require.NoError(t, err)

	switch cipherID {
	case smb2.AES128CCM, smb2.AES256CCM:
		aead, err := ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		require.NoError(t, err)
		return aead
	case smb2.AES128GCM, smb2.AES256GCM:
		aead, err := cipher.NewGCMWithNonceSize(ciph, 12)
		require.NoError(t, err)
		return aead
	default:
		t.Fatalf("unsupported cipher %d", cipherID)
		return nil
	}
}

func TestSetupKeysNormalizesEncryptionKey(t *testing.T) {
	tests := []struct {
		name         string
		dialect      uint16
		cipherID     uint16
		keyLabel     string
		decryptLabel string
		serverIn     string
		serverOut    string
		keySize      int
		fullKey      bool
	}{
		{
			name:         "SMB302-CCM",
			dialect:      smb2.SMB302,
			cipherID:     smb2.AES128CCM,
			keyLabel:     "SMB2AESCCM\x00",
			decryptLabel: "SMB2AESCCM\x00",
			serverIn:     "ServerIn \x00",
			serverOut:    "ServerOut\x00",
			keySize:      16,
		},
		{
			name:         "SMB311-CCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES128CCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			serverIn:     "",
			serverOut:    "",
			keySize:      16,
		},
		{
			name:         "SMB311-GCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES128GCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			serverIn:     "",
			serverOut:    "",
			keySize:      16,
		},
		{
			name:         "SMB311-AES256-CCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES256CCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			keySize:      32,
			fullKey:      true,
		},
		{
			name:         "SMB311-AES256-GCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES256GCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			keySize:      32,
			fullKey:      true,
		},
	}
	preauth := bytes.Repeat([]byte{0x37}, 64)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range [][]byte{
				bytes.Repeat([]byte{0x11}, 8),
				bytes.Repeat([]byte{0x22}, 16),
				append(bytes.Repeat([]byte{0x33}, 16), bytes.Repeat([]byte{0x44}, 16)...),
			} {
				t.Run(fmt.Sprintf("key-%d", len(key)), func(t *testing.T) {
					s := &session{
						conn: &conn{
							dialect:  test.dialect,
							cipherId: test.cipherID,
						},
						sessionId: 0x1234,
					}
					copy(s.preauthIntegrityHashValue[:], preauth)
					originalKey := bytes.Clone(key)
					require.NoError(t, s.setupKeys(key))
					require.Equal(t, originalKey, key)

					context := preauth
					if test.dialect != smb2.SMB311 {
						context = []byte(test.serverIn)
					}
					derivationKey := normalizeSessionKeyForTest(key)
					if test.fullKey {
						derivationKey = key
					}
					serverDecryptKey := kdfForTest(derivationKey, []byte(test.keyLabel), context, test.keySize)
					serverDecrypt := newSessionTestAEAD(t, test.cipherID, serverDecryptKey)

					req := &smb2.EchoRequest{}
					plain := make([]byte, req.Size())
					req.Encode(plain)
					wire, err := s.encrypt(plain, make([]byte, 52+len(plain)+s.encrypter.Overhead()))
					require.NoError(t, err)
					tc := smb2.TransformCodec(wire)
					ciphertext := append(bytes.Clone(tc.EncryptedData()), tc.Signature()...)
					decrypted, err := serverDecrypt.Open(nil, tc.Nonce()[:serverDecrypt.NonceSize()], ciphertext, tc.AssociatedData())
					require.NoError(t, err)
					require.Equal(t, plain, decrypted)

					if test.dialect == smb2.SMB311 {
						context = preauth
					} else {
						context = []byte(test.serverOut)
					}
					serverEncryptKey := kdfForTest(derivationKey, []byte(test.decryptLabel), context, test.keySize)
					serverEncrypt := newSessionTestAEAD(t, test.cipherID, serverEncryptKey)
					serverWire := make([]byte, 52+len(plain)+serverEncrypt.Overhead())
					serverTC := smb2.TransformCodec(serverWire)
					serverTC.SetProtocolId()
					serverTC.SetOriginalMessageSize(uint32(len(plain)))
					serverTC.SetFlags(smb2.Encrypted)
					serverTC.SetSessionId(s.sessionId)
					copy(serverTC.Nonce(), []byte("test nonce for smb"))
					sealed := serverEncrypt.Seal(serverWire[:52], serverTC.Nonce()[:serverEncrypt.NonceSize()], plain, serverTC.AssociatedData())
					serverTC.SetSignature(sealed[len(sealed)-serverEncrypt.Overhead():])
					serverWire = serverWire[:52+len(plain)]

					decrypted, err = s.decrypt(serverWire)
					require.NoError(t, err)
					require.Equal(t, plain, decrypted)
				})
			}
		})
	}
}

func TestSessionSetupRejectsSingleRoundGSSFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	initiator := &singleRoundInitiator{
		key:       bytes.Repeat([]byte{0x42}, 16),
		acceptErr: errors.New("GSS failure"),
	}
	go runSingleRoundSessionSetupServer(direct(serverConn), initiator, singleRoundUnsigned)

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s, err := c.sessionSetup(context.Background(), initiator)
	require.Error(t, err)
	require.Nil(t, s)
	require.Contains(t, err.Error(), "spnego accept security context failed")
	require.False(t, c.useSession())
	require.Nil(t, c.session)
}

func TestSessionSetupSingleRoundSMB311ResponseSignature(t *testing.T) {
	for _, test := range []struct {
		name          string
		signatureMode int
		anonymous     bool
		wantErr       string
	}{
		{name: "valid", signatureMode: singleRoundSigned},
		{name: "missing", signatureMode: singleRoundUnsigned, wantErr: "session setup response missing signature"},
		{name: "tampered", signatureMode: singleRoundTampered, wantErr: "session setup response failed signature verification"},
		{name: "anonymous unsigned", signatureMode: singleRoundUnsigned, anonymous: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16), anonymous: test.anonymous}
			go runSingleRoundSessionSetupServer(direct(serverConn), initiator, test.signatureMode)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.dialect = smb2.SMB311
			c.preauthIntegrityHashId = smb2.SHA512
			c.preauthIntegrityHashValue = [64]byte{0x37}
			c.cipherId = smb2.AES128GCM

			s, err := c.sessionSetup(context.Background(), initiator)
			if test.wantErr == "" {
				require.NoError(t, err)
				require.NotNil(t, s)
				require.True(t, c.useSession())
				return
			}

			require.Error(t, err)
			require.Nil(t, s)
			require.Contains(t, err.Error(), test.wantErr)
			require.False(t, c.useSession())
		})
	}
}

func TestSessionSetupSingleRoundSMB311AES256ResponseSignature(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	key := append(bytes.Repeat([]byte{0x42}, 16), bytes.Repeat([]byte{0xa5}, 16)...)
	initiator := &singleRoundInitiator{key: key}
	originalKey := bytes.Clone(key)
	go runSingleRoundSessionSetupServer(direct(serverConn), initiator, singleRoundSigned)

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	c.dialect = smb2.SMB311
	c.preauthIntegrityHashId = smb2.SHA512
	c.preauthIntegrityHashValue = [64]byte{0x37}
	c.cipherId = smb2.AES256GCM

	s, err := c.sessionSetup(context.Background(), initiator)
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, originalKey, initiator.key)
}

func TestSessionSetupClosesInitialResponseBuffer(t *testing.T) {
	tests := []struct {
		name           string
		mode           int
		requireSigning bool
		wantErr        bool
		errorContains  string
	}{
		{
			name:    "SuccessfulAuthentication",
			mode:    sessionSetupServerSuccess,
			wantErr: false,
		},
		{
			name:           "GuestAccountRejected",
			mode:           sessionSetupServerGuestReject,
			requireSigning: true,
			wantErr:        true,
			errorContains:  "guest account doesn't support signing",
		},
		{
			name:           "NullAccountRejected",
			mode:           sessionSetupServerNullReject,
			requireSigning: true,
			wantErr:        true,
			errorContains:  "anonymous account doesn't support signing",
		},
		{
			name:          "InvalidSecurityContext",
			mode:          sessionSetupServerInvalidSecurityContext,
			wantErr:       true,
			errorContains: "spnego accept security context failed",
		},
		{
			name:          "TamperedFinalResponseSignature",
			mode:          sessionSetupServerTamperedFinalSignature,
			wantErr:       true,
			errorContains: "session setup response failed signature verification",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			trackedBufs := installTrackingRecvBufPool(t)

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})

			st := direct(serverConn)

			var ntlmServer *ntlm.Server
			if test.mode == sessionSetupServerSuccess || test.mode == sessionSetupServerTamperedFinalSignature || test.mode == sessionSetupServerFinalReject || test.mode == sessionSetupServerFinalIncomplete || test.mode == sessionSetupServerFinalInvalid {
				ntlmServer = ntlm.NewServer("test-server")
				ntlmServer.AddAccount("user", "password")
			}
			go runFakeSessionSetupServer(st, test.mode, ntlmServer)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.requireSigning = test.requireSigning

			s, err := c.sessionSetup(context.Background(), &NTLMInitiator{User: "user", Password: "password"})

			if test.wantErr {
				require.Error(err)
				require.Nil(s)
				require.Contains(err.Error(), test.errorContains)
			} else {
				require.NoError(err)
				require.NotNil(s)
				require.Equal(uint64(0x1234), s.sessionId)
			}

			// The initial SessionSetup response buffer must be handed back to
			// the pool on every exit path, successful or not.
			cleanup()
			serverConn.Close()
			clientConn.Close()
			requireAllRecvBufsReleased(t, trackedBufs)
		})
	}
}

func TestSessionSetupFinalGuestOrNullSigningPolicy(t *testing.T) {
	tests := []struct {
		name        string
		dialect     uint16
		mode        int
		errorString string
	}{
		{name: "SMB202Guest", dialect: smb2.SMB202, mode: sessionSetupServerFinalGuest, errorString: "guest account doesn't support signing"},
		{name: "SMB202Null", dialect: smb2.SMB202, mode: sessionSetupServerFinalNull, errorString: "anonymous account doesn't support signing"},
		{name: "SMB302Guest", dialect: smb2.SMB302, mode: sessionSetupServerFinalGuest, errorString: "guest account doesn't support signing"},
		{name: "SMB302Null", dialect: smb2.SMB302, mode: sessionSetupServerFinalNull, errorString: "anonymous account doesn't support signing"},
		{name: "SMB311Guest", dialect: smb2.SMB311, mode: sessionSetupServerFinalGuest, errorString: "guest account doesn't support signing"},
		{name: "SMB311Null", dialect: smb2.SMB311, mode: sessionSetupServerFinalNull, errorString: "anonymous account doesn't support signing"},
	}

	for _, signing := range []bool{true, false} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("%s/signing=%t", test.name, signing), func(t *testing.T) {
				clientConn, serverConn := net.Pipe()
				t.Cleanup(func() {
					clientConn.Close()
					serverConn.Close()
				})

				ntlmServer := ntlm.NewServer("test-server")
				ntlmServer.AddAccount("user", "password")
				go runFakeSessionSetupServer(direct(serverConn), test.mode, ntlmServer)

				c, cleanup := newBenchConn(clientConn)
				defer cleanup()
				c.dialect = test.dialect
				c.requireSigning = signing
				if test.dialect == smb2.SMB311 {
					c.preauthIntegrityHashId = smb2.SHA512
				}

				s, err := c.sessionSetup(context.Background(), &NTLMInitiator{User: "user", Password: "password"})
				if !signing {
					require.NoError(t, err)
					require.NotNil(t, s)
					require.True(t, c.useSession())
					return
				}
				require.Error(t, err)
				require.Nil(t, s)
				require.Contains(t, err.Error(), test.errorString)
				require.False(t, c.useSession())
				require.NotNil(t, c.session)
				require.Zero(t, c.session.sessionFlags)
			})
		}
	}
}

func TestSessionSetupRejectsSignedFinalGSSResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		mode int
	}{
		{name: "reject", mode: sessionSetupServerFinalReject},
		{name: "accept-incomplete", mode: sessionSetupServerFinalIncomplete},
		{name: "invalid-encoding", mode: sessionSetupServerFinalInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			trackedBufs := installTrackingRecvBufPool(t)
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})

			ntlmServer := ntlm.NewServer("test-server")
			ntlmServer.AddAccount("user", "password")
			go runFakeSessionSetupServer(direct(serverConn), test.mode, ntlmServer)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.dialect = smb2.SMB202
			c.requireSigning = true

			s, err := c.sessionSetup(context.Background(), &NTLMInitiator{User: "user", Password: "password"})
			require.Error(t, err)
			require.Nil(t, s)
			require.False(t, c.useSession())
			require.Contains(t, err.Error(), "spnego accept security context failed")
			serverConn.Close()
			clientConn.Close()
			requireAllRecvBufsReleased(t, trackedBufs)
		})
	}
}

// oversizedTokenInitiator is a stub Initiator that emits a security token
// larger than the 64KiB SMB2 security buffer limit.
type oversizedTokenInitiator struct{}

func (oversizedTokenInitiator) OID() asn1.ObjectIdentifier { return spnego.NlmpOid }

func (oversizedTokenInitiator) InitSecContext() ([]byte, error) {
	return make([]byte, math.MaxUint16+1), nil
}

func (oversizedTokenInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	return nil, nil
}

func (oversizedTokenInitiator) GetMIC([]byte) ([]byte, error)  { return nil, nil }
func (oversizedTokenInitiator) Complete() bool                 { return true }
func (oversizedTokenInitiator) VerifyMIC([]byte, []byte) error { return nil }

func (oversizedTokenInitiator) SessionKey() []byte { return nil }

func TestSessionSetupRejectsOversizedSecurityToken(t *testing.T) {
	require := require.New(t)

	// The oversized token must be rejected before any packet is sent,
	// so a bare conn is sufficient for this test.
	s, err := (&conn{}).sessionSetup(context.Background(), oversizedTokenInitiator{})

	require.Error(err)
	require.Nil(s)
	require.Contains(err.Error(), "security buffer exceeds 64KiB")
}

// cmacBlock returns the AES cipher block backing a cmac-based hash.Hash.
func cmacBlock(t *testing.T, h hash.Hash) uintptr {
	t.Helper()

	v := reflect.ValueOf(h).Elem().FieldByName("c")
	require.Equal(t, reflect.Interface, v.Kind())
	v = v.Elem()
	require.Equal(t, reflect.Pointer, v.Kind())
	return v.Pointer()
}

func TestSessionSetupSignerAndVerifierAreDistinctInstances(t *testing.T) {
	tests := []struct {
		name          string
		dialect       uint16
		preauthHashId uint16
		mode          int
	}{
		{
			name:    "SMB300",
			dialect: smb2.SMB300,
			mode:    sessionSetupServerSuccess,
		},
		{
			name:    "SMB302",
			dialect: smb2.SMB302,
			mode:    sessionSetupServerSuccess,
		},
		{
			name:          "SMB311",
			dialect:       smb2.SMB311,
			preauthHashId: smb2.SHA512,
			mode:          sessionSetupServerSuccessSigned,
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
			ntlmServer := ntlm.NewServer("test-server")
			ntlmServer.AddAccount("user", "password")
			go runFakeSessionSetupServer(st, test.mode, ntlmServer)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.dialect = test.dialect
			c.preauthIntegrityHashId = test.preauthHashId

			s, err := c.sessionSetup(context.Background(), &NTLMInitiator{User: "user", Password: "password"})
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(s.signer)
			require.NotNil(s.verifier)

			// Keep signer and verifier as distinct hash.Hash instances so that
			// concurrent signing and verification never share mutable digest
			// state.
			require.False(s.signer == s.verifier, "signer and verifier must be distinct instances")
			require.NotEqual(cmacBlock(t, s.signer), cmacBlock(t, s.verifier),
				"signer and verifier must not share the underlying AES cipher block")
		})
	}
}

func TestSessionSetup_SMB311FinalResponseMustBeSigned(t *testing.T) {
	require := require.New(t)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	st := direct(serverConn)
	ntlmServer := ntlm.NewServer("test-server")
	ntlmServer.AddAccount("user", "password")
	go runFakeSessionSetupServer(st, sessionSetupServerSuccess, ntlmServer)

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	c.dialect = smb2.SMB311
	c.requireSigning = false

	s, err := c.sessionSetup(context.Background(), &NTLMInitiator{User: "user", Password: "password"})
	require.Error(err)
	require.Nil(s)
	require.Contains(err.Error(), "session setup response missing signature")
}

func TestIoctlBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	expectedData := []byte("partial output data from buffer overflow")

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_IOCTL {
			return
		}

		iores := &smb2.IoctlResponse{
			CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
			Output:  rawEncoder(expectedData),
		}
		respBuf := make([]byte, iores.Size())
		iores.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	output, err := fs.ioctl(context.Background(), &smb2.FileId{}, &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, expectedData, output)

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestIoctlErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_IOCTL {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_IOCTL)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	output, err := fs.ioctl(context.Background(), &smb2.FileId{}, &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr.Code)
	require.Nil(t, output)

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	expectedData := []byte("partial read data from buffer overflow")

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		readres := &smb2.ReadResponse{
			Data:          expectedData,
			DataRemaining: 100,
		}
		respBuf := make([]byte, readres.Size())
		readres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(context.Background(), &smb2.FileId{}, buf, 0)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, buf[:n])

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadBufferOverflowInReadMethodReturnsSuccess(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	expectedData := []byte("pipe chunk data")

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		readres := &smb2.ReadResponse{
			Data:          expectedData,
			DataRemaining: 50,
		}
		respBuf := make([]byte, readres.Size())
		readres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.read(context.Background(), &smb2.FileId{}, buf, 0)

	require.NoError(t, err)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, buf[:n])

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_READ)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(context.Background(), &smb2.FileId{}, buf, 0)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr.Code)
	require.Equal(t, 0, n)

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestQueryInfoBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	expectedData := []byte("partial query info output data")

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_QUERY_INFO {
			return
		}

		qres := &smb2.QueryInfoResponse{
			Output: rawEncoder(expectedData),
		}
		respBuf := make([]byte, qres.Size())
		qres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	output, err := fs.queryInfo(context.Background(), &smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, expectedData, output)

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestQueryInfoErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	go func() {
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_QUERY_INFO {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_QUERY_INFO)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Writev(respBuf)
	}()

	output, err := fs.queryInfo(context.Background(), &smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

	require.Error(t, err)
	var rerr2 *ResponseError
	require.True(t, errors.As(err, &rerr2))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr2.Code)
	require.Nil(t, output)

	// Verify buffer pool is completely released
	cleanup()
	clientConn.Close()
	serverConn.Close()
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestDecryptRejectsTruncatedTransformPacket(t *testing.T) {
	ciph, err := aes.NewCipher(make([]byte, 16))
	require.NoError(t, err)
	decrypter, err := ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
	require.NoError(t, err)

	s := &session{decrypter: decrypter}

	// A transform header is 52 bytes and a valid encrypted packet carries at
	// least 1 byte of ciphertext plus a 16-byte signature (69 bytes total).
	// Packets in [52, 68] are truncated and must be rejected without panicking.
	for size := 52; size <= 68; size++ {
		pkt := make([]byte, size)
		copy(pkt[:4], smb2.MAGIC2)

		out, err := s.decrypt(pkt)

		require.Error(t, err, "size = %d", size)
		var ierr *InvalidResponseError
		require.ErrorAs(t, err, &ierr, "size = %d", size)
		require.Nil(t, out, "size = %d", size)
	}
}

func TestLogoffErrorClosesConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_LOGOFF {
			return
		}
		sendTestResponse(st, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_LOGOFF}, uint32(erref.STATUS_USER_SESSION_DELETED))
	}()

	err := s.logoff(context.Background())

	var rerr *ResponseError
	require.ErrorAs(t, err, &rerr)
	require.Equal(t, uint32(erref.STATUS_USER_SESSION_DELETED), rerr.Code)

	// Even when LOGOFF fails with an error status, the underlying connection
	// must be closed so the session does not leak an open transport.
	<-done

	c.m.Lock()
	connErr := c.err
	c.m.Unlock()
	require.Error(t, connErr, "conn.close must be called when logoff fails")
}

func TestSessionSetupRejectsIncompleteSingleRoundAuthentication(t *testing.T) {
	for _, test := range []struct {
		name        string
		negState    asn1.Enumerated
		outputToken []byte
	}{
		{name: "incomplete negotiation", negState: negStateAcceptIncomplete},
		{name: "pending output token", outputToken: []byte("continuation")},
		{name: "rejected negotiation", negState: negStateReject},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16), negState: test.negState, outputToken: test.outputToken}
			go runSingleRoundSessionSetupServer(direct(serverConn), initiator, singleRoundUnsigned)
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, err := c.sessionSetup(ctx, initiator)
			require.Error(t, err)
			require.Nil(t, s)
			require.False(t, c.useSession())
			require.Nil(t, c.session)
		})
	}
}

// finalKeyInitiator models a mechanism whose final peer token establishes the
// context key, as an AES Kerberos AP-REP does.
type finalKeyInitiator struct {
	singleRoundInitiator
	rounds         int
	acceptedRounds int
	finalKey       []byte
}

func (i *finalKeyInitiator) AcceptSecContext([]byte) ([]byte, error) {
	i.acceptedRounds++
	if i.acceptedRounds == i.rounds {
		i.key = append([]byte(nil), i.finalKey...)
		return nil, nil
	}
	return []byte("continue"), nil
}
func (i *finalKeyInitiator) Complete() bool { return i.acceptedRounds == i.rounds }

func TestSessionSetupUsesFinalContextKey(t *testing.T) {
	for _, rounds := range []int{1, 2, 3} {
		for _, tampered := range []bool{false, true} {
			t.Run(fmt.Sprintf("rounds=%d/tampered=%v", rounds, tampered), func(t *testing.T) {
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()
				defer serverConn.Close()
				key := bytes.Repeat([]byte{0x63}, 32)
				initiator := &finalKeyInitiator{rounds: rounds, finalKey: key}
				initiator.key = bytes.Repeat([]byte{0x27}, 16)
				done := make(chan error, 1)
				go func() {
					var err error
					defer func() { done <- err }()
					transport := direct(serverConn)
					preauth := [64]byte{0x37}
					for round := 1; round <= rounds; round++ {
						var request []byte
						request, err = readMsg(transport)
						if err != nil {
							return
						}
						updatePreauthHash(&preauth, request)
						state := negStateAcceptIncomplete
						status := erref.STATUS_MORE_PROCESSING_REQUIRED
						if round == rounds {
							state, status = negStateAcceptCompleted, erref.STATUS_SUCCESS
						}
						var oid asn1.ObjectIdentifier
						if round == 1 {
							oid = spnego.NlmpOid
						}
						var token []byte
						token, err = spnego.EncodeNegTokenResp(state, oid, []byte("peer-token"), nil)
						if err != nil {
							return
						}
						response := make([]byte, 72+len(token))
						binary.LittleEndian.PutUint16(response[64:], 9)
						binary.LittleEndian.PutUint16(response[68:], 72)
						binary.LittleEndian.PutUint16(response[70:], uint16(len(token)))
						copy(response[72:], token)
						p := smb2.PacketCodec(response)
						p.SetProtocolId()
						p.SetStructureSize()
						p.SetCommand(smb2.SMB2_SESSION_SETUP)
						p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
						p.SetStatus(uint32(status))
						p.SetSessionId(0x1234)
						requestHeader := smb2.PacketCodec(request)
						p.SetMessageId(requestHeader.MessageId())
						p.SetCreditResponse(requestHeader.CreditRequest())
						if round == rounds {
							signingKey := kdfForTest(normalizeSessionKeyForTest(key), []byte("SMBSigningKey\x00"), preauth[:], 16)
							var block cipher.Block
							block, err = aes.NewCipher(signingKey)
							if err != nil {
								return
							}
							signer := cmac.New(block)
							p.SetFlags(p.Flags() | smb2.SMB2_FLAGS_SIGNED)
							signer.Write(response)
							p.SetSignature(signer.Sum(nil))
							if tampered {
								p.Signature()[0] ^= 1
							}
						} else {
							updatePreauthHash(&preauth, response)
						}
						_, err = transport.Writev(response)
						if err != nil {
							return
						}
					}
				}()
				c, cleanup := newBenchConn(clientConn)
				defer cleanup()
				c.dialect = smb2.SMB311
				c.cipherId = smb2.AES128GCM
				c.preauthIntegrityHashId = smb2.SHA512
				c.preauthIntegrityHashValue = [64]byte{0x37}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				s, err := c.sessionSetup(ctx, initiator)
				if tampered {
					require.ErrorContains(t, err, "signature verification")
					require.Nil(t, s)
					require.False(t, c.useSession())
				} else {
					require.NoError(t, err)
					require.True(t, c.useSession())
					require.Equal(t, key, initiator.SessionKey())
				}
				require.NoError(t, <-done)
			})
		}
	}
}

func TestSessionServername(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "ipv4 address", addr: "192.0.2.10:445", want: "192.0.2.10"},
		{name: "ipv6 address", addr: "[2001:db8::10]:445", want: "2001:db8::10"},
		{name: "unparseable address", addr: "server", want: "server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{addr: tt.addr}
			if got := s.serverName(); got != tt.want {
				t.Errorf("servername = %q, want %q", got, tt.want)
			}
		})
	}
}

type sessionCloseTransport struct {
	closes atomic.Int32
}

func (*sessionCloseTransport) send(...[]byte) error               { return io.ErrClosedPipe }
func (*sessionCloseTransport) setReadDeadline(time.Time) error    { return nil }
func (*sessionCloseTransport) setWriteDeadline(time.Time) error   { return nil }
func (*sessionCloseTransport) setPacketReadTimeout(time.Duration) {}
func (*sessionCloseTransport) receive() ([]byte, error)           { return nil, io.EOF }
func (t *sessionCloseTransport) Close() error {
	t.closes.Add(1)
	return nil
}

func TestSessionCloseConcurrentCallsShareOutcome(t *testing.T) {
	transport := new(sessionCloseTransport)
	c := &conn{
		t:                   transport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(8),
		rdone:               make(chan struct{}, 1),
	}
	c.session = &session{conn: c, sessionId: 1}
	s := &Session{s: c.session, addr: "server", closeDone: make(chan struct{})}

	results := make(chan error, 2)
	go func() { results <- s.Close() }()
	go func() { results <- s.Close() }()
	first := <-results
	second := <-results
	require.Error(t, first)
	require.ErrorIs(t, first, io.ErrClosedPipe)
	require.ErrorIs(t, second, io.ErrClosedPipe)
	require.Equal(t, first, second)
	require.Equal(t, int32(1), transport.closes.Load())
	// A completed close remains safe and returns the same stored result.
	require.ErrorIs(t, s.Close(), io.ErrClosedPipe)
}

func TestCanceledOperationDoesNotCloseTransport(t *testing.T) {
	transport := new(sessionCloseTransport)
	c := &conn{
		t:                   transport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(8),
		rdone:               make(chan struct{}, 1),
	}
	c.session = &session{conn: c, sessionId: 1}
	s := &Session{s: c.session, addr: "server", closeDone: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.session.echo(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, transport.closes.Load(), "canceling one operation must not close the shared transport")

	require.ErrorIs(t, s.Close(), io.ErrClosedPipe)
	require.Equal(t, int32(1), transport.closes.Load())
}

type blockedSendTransport struct {
	Transport
	entered   chan struct{}
	enterOnce sync.Once
}

func (t *blockedSendTransport) send(parts ...[]byte) error {
	t.enterOnce.Do(func() { close(t.entered) })
	return t.Transport.send(parts...)
}

func TestSessionCloseUnblocksSynchronousSendAtDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := &blockedSendTransport{Transport: direct(clientConn), entered: make(chan struct{})}
	c := &conn{
		t:                   transport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(8),
		rdone:               make(chan struct{}, 1),
	}
	c.session = &session{conn: c, sessionId: 1}
	s := &Session{s: c.session, addr: "server", closeDone: make(chan struct{})}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- c.session.echo(context.Background())
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("synchronous send did not reach the transport")
	}

	started := time.Now()
	closeErr := s.Close()
	elapsed := time.Since(started)
	require.Error(t, closeErr)
	require.GreaterOrEqual(t, elapsed, 4*time.Second)
	require.Less(t, elapsed, 8*time.Second)
	select {
	case sendErr := <-sendDone:
		require.Error(t, sendErr)
	case <-time.After(time.Second):
		t.Fatal("Session.Close did not unblock the synchronous sender")
	}
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

			_, err := c.sessionSetup(context.Background(), &NTLMInitiator{})
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

func (d *stubDecrypter) Overhead() int { return 16 }

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

func TestSignSegments(t *testing.T) {
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, 112) // SMB2 header + WRITE body
	pkt[0], pkt[1] = 0xfe, 'S'

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}

	s := &session{signer: cmac.New(ciph)}

	// signing segments must produce the same signature as signing the
	// concatenated packet
	contiguous := append(append([]byte{}, pkt...), payload...)
	signedContiguous := s.sign(contiguous)

	signedSegments := s.sign(pkt, payload)

	if !bytes.Equal(smb2.PacketCodec(signedContiguous).Signature(), smb2.PacketCodec(signedSegments).Signature()) {
		t.Error("fail")
	}

	// the signature must also match a manual CMAC computation
	p := smb2.PacketCodec(signedSegments)
	signature := append([]byte(nil), p.Signature()...)
	p.SetSignature(zero[:])

	h := cmac.New(ciph)
	h.Write(pkt)
	h.Write(payload)
	h.Sum(pkt[:48])

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}

func TestSignEmptyOrTruncated(t *testing.T) {
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	s := &session{signer: cmac.New(ciph)}

	if res := s.sign(); res != nil {
		t.Errorf("sign() = %v, want nil", res)
	}
	if res := s.sign(nil); res != nil {
		t.Errorf("sign(nil) = %v, want nil", res)
	}
	short := []byte("short")
	if res := s.sign(short); !bytes.Equal(res, short) {
		t.Errorf("sign(short) = %v, want %v", res, short)
	}
}

func TestSign(t *testing.T) {
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4041393e756a048c9092c4e52dc7037190900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}

	signature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := cmac.New(ciph)

	p := smb2.PacketCodec(pkt)

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}

	p.SetSignature(zero[:])

	signer.Reset()
	signer.Write(pkt)
	signer.Sum(pkt[:48])
	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}
