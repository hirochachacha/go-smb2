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
	"errors"
	"fmt"
	"hash"
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/spnego"
	"github.com/stretchr/testify/require"
)

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
		New: func() interface{} {
			buf := &recvBuf{data: make([]byte, 0, singleCreditMaxPayloadSize)}
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
				signingKey := kdf(ntlmServer.Session().SessionKey(), []byte("SMBSigningKey\x00"), preauth[:])
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
}

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

func (i *singleRoundInitiator) Sum([]byte) []byte { return nil }

func (i *singleRoundInitiator) SessionKey() []byte { return i.key }

func normalizeSessionKeyForTest(key []byte) []byte {
	var normalized [16]byte
	copy(normalized[:], key)
	return normalized[:]
}

func kdfForTest(key, label, context []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0, 0, 0, 1})
	h.Write(label)
	h.Write([]byte{0})
	h.Write(context)
	h.Write([]byte{0, 0, 0, 0x80})
	return h.Sum(nil)[:16]
}

func expectedSessionSignatureForTest(t *testing.T, dialect uint16, key []byte, preauth []byte, pkt []byte) []byte {
	t.Helper()

	normalized := normalizeSessionKeyForTest(key)
	var signer hash.Hash
	switch dialect {
	case smb2.SMB202, smb2.SMB210:
		signer = hmac.New(sha256.New, normalized)
	case smb2.SMB300, smb2.SMB302:
		ciph, err := aes.NewCipher(kdfForTest(normalized, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00")))
		require.NoError(t, err)
		signer = cmac.New(ciph)
	case smb2.SMB311:
		ciph, err := aes.NewCipher(kdfForTest(normalized, []byte("SMBSigningKey\x00"), preauth))
		require.NoError(t, err)
		signer = cmac.New(ciph)
	default:
		t.Fatalf("unsupported dialect %d", dialect)
	}

	signer.Write(pkt)
	return signer.Sum(nil)[:16]
}

func runSingleRoundSessionSetupServer(t transport, initiator *singleRoundInitiator, signatureMode int) {
	reqBuf, err := readMsg(t)
	if err != nil {
		return
	}
	p := smb2.PacketCodec(reqBuf)
	if p.Command() != smb2.SMB2_SESSION_SETUP {
		return
	}
	req := smb2.SessionSetupRequestDecoder(reqBuf[64:])
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
		signingKey := kdfForTest(normalizeSessionKeyForTest(initiator.key), []byte("SMBSigningKey\x00"), preauth[:])
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
	_ = t.Close()
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
			s, err := sessionSetup(c, initiator, ctx)
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

func TestSetupKeysNormalizesGSSSessionKey(t *testing.T) {
	tests := []struct {
		name    string
		dialect uint16
	}{
		{name: "SMB202", dialect: smb2.SMB202},
		{name: "SMB210", dialect: smb2.SMB210},
		{name: "SMB300", dialect: smb2.SMB300},
		{name: "SMB302", dialect: smb2.SMB302},
		{name: "SMB311", dialect: smb2.SMB311},
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
				key := key
				t.Run(fmt.Sprintf("key-%d", len(key)), func(t *testing.T) {
					originalKey := bytes.Clone(key)
					s := &session{
						conn: &conn{
							dialect: test.dialect,
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
				s := &session{conn: &conn{dialect: test.dialect}}
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
	case smb2.AES128CCM:
		aead, err := ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		require.NoError(t, err)
		return aead
	case smb2.AES128GCM:
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
	}{
		{
			name:         "SMB302-CCM",
			dialect:      smb2.SMB302,
			cipherID:     smb2.AES128CCM,
			keyLabel:     "SMB2AESCCM\x00",
			decryptLabel: "SMB2AESCCM\x00",
			serverIn:     "ServerIn \x00",
			serverOut:    "ServerOut\x00",
		},
		{
			name:         "SMB311-CCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES128CCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			serverIn:     "",
			serverOut:    "",
		},
		{
			name:         "SMB311-GCM",
			dialect:      smb2.SMB311,
			cipherID:     smb2.AES128GCM,
			keyLabel:     "SMBC2SCipherKey\x00",
			decryptLabel: "SMBS2CCipherKey\x00",
			serverIn:     "",
			serverOut:    "",
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
				key := key
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
					serverDecryptKey := kdfForTest(normalizeSessionKeyForTest(key), []byte(test.keyLabel), context)
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
					serverEncryptKey := kdfForTest(normalizeSessionKeyForTest(key), []byte(test.decryptLabel), context)
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

	s, err := sessionSetup(c, initiator, context.Background())
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
		wantErr       string
	}{
		{name: "valid", signatureMode: singleRoundSigned},
		{name: "missing", signatureMode: singleRoundUnsigned, wantErr: "session setup response missing signature"},
		{name: "tampered", signatureMode: singleRoundTampered, wantErr: "session setup response failed signature verification"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16)}
			go runSingleRoundSessionSetupServer(direct(serverConn), initiator, test.signatureMode)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.dialect = smb2.SMB311
			c.preauthIntegrityHashId = smb2.SHA512
			c.preauthIntegrityHashValue = [64]byte{0x37}
			c.cipherId = smb2.AES128GCM

			s, err := sessionSetup(c, initiator, context.Background())
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

func TestSessionSetupSingleRoundSMB311ResponseSignatureWith32ByteKey(t *testing.T) {
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
	c.cipherId = smb2.AES128GCM

	s, err := sessionSetup(c, initiator, context.Background())
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

			s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())

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

				s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())
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

			s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())
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

func (oversizedTokenInitiator) Sum(bs []byte) []byte { return nil }

func (oversizedTokenInitiator) SessionKey() []byte { return nil }

func TestSessionSetupRejectsOversizedSecurityToken(t *testing.T) {
	require := require.New(t)

	// The oversized token must be rejected before any packet is sent,
	// so a bare conn is sufficient for this test.
	s, err := sessionSetup(&conn{}, oversizedTokenInitiator{}, context.Background())

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
	require.Equal(t, reflect.Ptr, v.Kind())
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

			s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())
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

	s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())
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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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

	output, err := fs.ioctl(&smb2.FileId{}, &smb2.IoctlRequest{
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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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

	output, err := fs.ioctl(&smb2.FileId{}, &smb2.IoctlRequest{
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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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
	n, err := fs.readAtChunk(&smb2.FileId{}, buf, 0)

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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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
	n, err := fs.read(&smb2.FileId{}, buf, 0)

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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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
	n, err := fs.readAtChunk(&smb2.FileId{}, buf, 0)

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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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

	output, err := fs.queryInfo(&smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

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
	fs := &Share{treeConn: tc, ctx: context.Background()}

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

	output, err := fs.queryInfo(&smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

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
			s, err := sessionSetup(c, initiator, ctx)
			require.Error(t, err)
			require.Nil(t, s)
			require.False(t, c.useSession())
			require.Nil(t, c.session)
		})
	}
}
