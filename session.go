package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/hirochachacha/go-smb2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})

	outputToken, err := spnego.initSecContext()
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("spnego init security context failed: %v", err)}
	}

	if len(outputToken) > math.MaxUint16 {
		return nil, &InternalError{"security buffer exceeds 64KiB"}
	}

	req := &smb2.SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (smb2.SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    outputToken,
		PreviousSessionId: 0,
	}

	if conn.requireSigning {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	res, err := conn.sendRecv(ctx, req)
	if err != nil {
		return nil, err
	}
	defer res.close()

	p := res.packet(0).codec()

	status := erref.NtStatus(p.Status())
	if status != erref.STATUS_SUCCESS && status != erref.STATUS_MORE_PROCESSING_REQUIRED {
		return nil, &InvalidResponseError{fmt.Sprintf("expected status: %v or %v, got %v", erref.STATUS_SUCCESS, erref.STATUS_MORE_PROCESSING_REQUIRED, status)}
	}

	r := smb2.SessionSetupResponseDecoder(res.data(0))

	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	sessionFlags := r.SessionFlags()
	if conn.requireSigning {
		if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_GUEST != 0 {
			return nil, &InvalidResponseError{"guest account doesn't support signing"}
		}
		if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_NULL != 0 {
			return nil, &InvalidResponseError{"anonymous account doesn't support signing"}
		}
	}

	s := &session{
		conn:         conn,
		sessionFlags: sessionFlags,
		sessionId:    p.SessionId(),
	}

	switch conn.dialect {
	case smb2.SMB311:
		s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue

		switch conn.preauthIntegrityHashId {
		case smb2.SHA512:
			// Handshake requests are executed sequentially without concurrent access,
			// so conn.encodeBuf still holds the encoded request packet.
			updatePreauthHash(&s.preauthIntegrityHashValue, conn.encodeBuf)
			if status == erref.STATUS_MORE_PROCESSING_REQUIRED {
				updatePreauthHash(&s.preauthIntegrityHashValue, res.bytes(0))
			}
		}
	}

	outputToken, err = spnego.acceptSecContext(r.SecurityBuffer(), status == erref.STATUS_SUCCESS)
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("spnego accept security context failed: %v", err)}
	}

	if status == erref.STATUS_SUCCESS {
		if err := s.setupKeys(spnego.sessionKey()); err != nil {
			return nil, err
		}
		if err := s.verifySessionSetupResponse(res.packet(0)); err != nil {
			return nil, err
		}

		conn.session = s
		s.enableSession()

		return s, nil
	}

	if len(outputToken) > math.MaxUint16 {
		return nil, &InternalError{"security buffer exceeds 64KiB"}
	}

	req.SecurityBuffer = outputToken

	// We set session before sending packet just for setting hdr.SessionId.
	// But, we should not permit access from receiver until the session information is completed.
	conn.session = s

	rrs, err := s.send(ctx, false, req)
	if err != nil {
		return nil, err
	}

	rr := rrs[0]

	if conn.dialect == smb2.SMB311 && conn.preauthIntegrityHashId == smb2.SHA512 {
		// Handshake requests are executed sequentially without concurrent access,
		// so conn.encodeBuf still holds the encoded continuation request packet.
		updatePreauthHash(&s.preauthIntegrityHashValue, conn.encodeBuf)
	}

	if err := s.setupKeys(spnego.sessionKey()); err != nil {
		return nil, err
	}

	rp, err := s.recv(rr)
	if err != nil {
		return nil, err
	}
	defer rp.close()

	if err := s.verifySessionSetupResponse(rp); err != nil {
		return nil, err
	}

	// now, allow access from receiver
	s.enableSession()

	return s, nil
}

func (s *session) setupKeys(sessionKey []byte) error {
	if s.sessionFlags&(smb2.SMB2_SESSION_FLAG_IS_GUEST|smb2.SMB2_SESSION_FLAG_IS_NULL) != 0 {
		return nil
	}

	switch s.dialect {
	case smb2.SMB202, smb2.SMB210:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)
	case smb2.SMB300, smb2.SMB302:
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)

		// As a hardening measure, give the verifier its own cipher block:
		// cipher.Block does not guarantee that implementations are safe for
		// concurrent use.
		ciph, err = aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.verifier = cmac.New(ciph)

		// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

		ciph, err = aes.NewCipher(encryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}

		ciph, err = aes.NewCipher(decryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}
	case smb2.SMB311:
		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)

		// As a hardening measure, give the verifier its own cipher block:
		// cipher.Block does not guarantee that implementations are safe for
		// concurrent use.
		ciph, err = aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.verifier = cmac.New(ciph)

		// s.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue)

		encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
		decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

		switch s.cipherId {
		case smb2.AES128CCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}
		case smb2.AES128GCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}
		}
	}

	return nil
}

func (s *session) verifySessionSetupResponse(rp *recvPacket) error {
	r := smb2.SessionSetupResponseDecoder(rp.data())

	if erref.NtStatus(rp.codec().Status()) != erref.STATUS_SUCCESS || r.IsInvalid() {
		return &InvalidResponseError{"broken session setup response format"}
	}

	s.sessionFlags = r.SessionFlags()

	// The receiver goroutine doesn't verify packets received before
	// enableSession, so the final SESSION_SETUP response must be verified here.
	if s.verifier != nil && s.sessionFlags&(smb2.SMB2_SESSION_FLAG_IS_GUEST|smb2.SMB2_SESSION_FLAG_IS_NULL) == 0 {
		isSigned := rp.codec().Flags()&smb2.SMB2_FLAGS_SIGNED != 0
		if s.dialect == smb2.SMB311 && !isSigned {
			return &InvalidResponseError{"session setup response missing signature"}
		}
		if s.requireSigning || isSigned {
			if !s.verify(rp.bytes()) {
				return &InvalidResponseError{"session setup response failed signature verification"}
			}
		}
	}

	return nil
}

type session struct {
	*conn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) logoff(ctx context.Context) error {
	req := new(smb2.LogoffRequest)

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		var cerr *ContextError
		if !errors.As(err, &cerr) {
			s.conn.close(err)
		}
		return err
	}
	defer res.close()

	return s.conn.close(nil)
}

func (s *session) echo(ctx context.Context) error {
	req := new(smb2.EchoRequest)

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		return err
	}
	defer res.close()

	return nil
}

func (s *session) send(ctx context.Context, encrypt bool, reqs ...smb2.Packet) (rrs []*outstandingRequest, err error) {
	for _, req := range reqs {
		req.SetSessionId(s.sessionId)
	}

	rrs, err = s.conn.send(ctx, encrypt, reqs...)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

func (s *session) sendRecv(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	encrypt := s.sessionFlags&smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0
	rrs, err := s.send(ctx, encrypt, reqs...)
	if err != nil {
		return nil, err
	}
	return recvAll(rrs, s)
}

func (s *session) recv(rr *outstandingRequest) (rp *recvPacket, err error) {
	rp, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	// IBM i NetServer (iSeries/AS400) assigns the session ID only in the
	// STATUS_MORE_PROCESSING_REQUIRED response, while the client's sessionId
	// is still 0. Adopt the server's session ID in that case.
	sessionId := rp.codec().SessionId()
	if s.sessionId == 0 {
		s.sessionId = sessionId
	} else if sessionId != s.sessionId {
		rp.close()
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return rp, err
}

func (s *session) unloan(rrs ...*outstandingRequest) {
	if s == nil || s.conn == nil {
		return
	}
	s.conn.unloan(rrs...)
}

// sign computes the signature over one or more contiguous segments of a
// packet. Direct I/O requests deliver their payload from a second segment
// located in the caller's buffer.
func (s *session) sign(pkts ...[]byte) []byte {
	if s == nil || s.signer == nil || len(pkts) == 0 || len(pkts[0]) < 64 {
		if len(pkts) > 0 {
			return pkts[0]
		}
		return nil
	}

	p := smb2.PacketCodec(pkts[0])

	p.SetFlags(p.Flags() | smb2.SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	for _, pkt := range pkts {
		if len(pkt) > 0 {
			h.Write(pkt)
		}
	}

	p.SetSignature(h.Sum(nil))

	return pkts[0]
}

// verify computes the signature over one or more contiguous segments of a
// packet. The first segment must contain the SMB2 header. Direct I/O responses
// deliver their payload in a second segment located in the caller's buffer.
func (s *session) verify(pkts ...[]byte) (ok bool) {
	if s == nil || s.verifier == nil || len(pkts) == 0 || len(pkts[0]) < 64 {
		return false
	}

	p := smb2.PacketCodec(pkts[0])

	var signature [16]byte

	copy(signature[:], p.Signature())

	clear(p.Signature())

	h := s.verifier

	h.Reset()

	for _, pkt := range pkts {
		if len(pkt) > 0 {
			h.Write(pkt)
		}
	}

	p.SetSignature(h.Sum(nil))

	return bytes.Equal(signature[:], p.Signature())
}

func (s *session) encrypt(pkt, c []byte) ([]byte, error) {
	if s.encrypter == nil {
		return nil, &InternalError{"encryption required but no cipher negotiated"}
	}

	t := smb2.TransformCodec(c)

	// fill nonce directly instead of using SetNonce for avoiding allocation
	nonce := t.Nonce()[:s.encrypter.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	t.SetProtocolId()
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(smb2.Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	if s.decrypter == nil {
		return nil, &InternalError{"decryption required but no cipher negotiated"}
	}

	t := smb2.TransformCodec(pkt)
	if t.IsInvalid() {
		return nil, &InvalidResponseError{"broken transform header format"}
	}

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}
