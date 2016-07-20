package smb2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"

	"github.com/hirochachacha/go-smb2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/spnego"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

type Authenticator interface {
	sessionSetup(*conn) (*session, error)
}

// NTLMAuthenticator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMAuthenticator struct {
	User        string
	Password    string
	Hash        [16]byte
	Domain      string
	Workstation string
	TargetSPN   string
}

func (a *NTLMAuthenticator) sessionSetup(conn *conn) (*session, error) {
	ntlm := &ntlm.Client{
		User:        a.User,
		Password:    a.Password,
		Hash:        a.Hash,
		Domain:      a.Domain,
		Workstation: a.Workstation,
		TargetSPN:   a.TargetSPN,
	}

	nmsg, err := ntlm.Negotiate()
	if err != nil {
		return nil, &InternalError{err.Error()}
	}

	mechList := []asn1.ObjectIdentifier{spnego.NlmpOid}

	negTokenInitBytes, err := spnego.EncodeNegTokenInit(mechList, nmsg)
	if err != nil {
		return nil, &InternalError{err.Error()}
	}

	req := &SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    negTokenInitBytes,
		PreviousSessionId: 0,
	}

	if conn.requireSigning {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.CreditCharge = 1
	req.CreditRequest = conn.account.initRequest()

	rr, err := conn.send(req)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	p := PacketCodec(pkt)

	if command := p.Command(); command != SMB2_SESSION_SETUP {
		return nil, &InvalidResponseError{fmt.Sprintf("expected command: %v, got %v", SMB2_SESSION_SETUP, command)}
	}

	if status := NtStatus(p.Status()); status != STATUS_MORE_PROCESSING_REQUIRED {
		if status != STATUS_SUCCESS {
			return nil, acceptError(p)
		}
		return nil, &InvalidResponseError{"BUG: unexpected status"}
	}

	r := SessionSetupResponseDecoder(p.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	sessionFlags := r.SessionFlags()
	if conn.requireSigning {
		if sessionFlags&SMB2_SESSION_FLAG_IS_GUEST != 0 {
			return nil, &InvalidResponseError{"guest account doesn't support signing"}
		}
	}

	negTokenResp, err := spnego.DecodeNegTokenResp(r.SecurityBuffer())
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	amsg, err := ntlm.Authenticate(nmsg, negTokenResp.ResponseToken)
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	ms, err := asn1.Marshal(mechList)
	if err != nil {
		return nil, &InternalError{err.Error()}
	}

	mechListMIC, _ := ntlm.Sum(ms, 0)

	negTokenRespBytes, err := spnego.EncodeNegTokenResp(nil, amsg, mechListMIC)
	if err != nil {
		return nil, &InternalError{err.Error()}
	}

	req.SecurityBuffer = negTokenRespBytes

	req.CreditRequest = 0

	s := &session{
		conn:         conn,
		sessionFlags: sessionFlags,
		sessionId:    p.SessionId(),
	}

	conn.session = s

	switch conn.dialect {
	case SMB311:
		s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue

		switch conn.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])

			h.Reset()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])
		}

	}

	rr, err = s.send(req)
	if err != nil {
		return nil, err
	}

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL|SMB2_SESSION_FLAG_ENCRYPT_DATA) != SMB2_SESSION_FLAG_ENCRYPT_DATA {
		sessionKey := ntlm.SessionKey()

		switch conn.dialect {
		case SMB202, SMB210:
			s.signer = hmac.New(sha256.New, sessionKey)
		case SMB300, SMB302:
			signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)

			// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

			encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
			decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

			ciph, err = aes.NewCipher(encryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
		case SMB311:
			switch conn.preauthIntegrityHashId {
			case SHA512:
				h := sha512.New()
				h.Write(s.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(s.preauthIntegrityHashValue[:0])
			}

			signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)

			// s.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue)

			encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
			decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

			switch s.conn.cipherId {
			case AES128CCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			case AES128GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			}
		}
	}

	pkt, err = s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r = SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	return s, nil
}

type session struct {
	*conn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	// applicationKey []byte

	signer    hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

func (s *session) logoff() error {
	req := new(LogoffRequest)

	req.CreditCharge = 1

	_, err := s.sendRecv(SMB2_LOGOFF, req)
	if err != nil {
		return err
	}

	return nil
}

func (s *session) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	rr, err := s.send(req)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *session) send(req Packet) (rr *requestResponse, err error) {
	return s.sendWith(req, nil)
}

func (s *session) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	if sessionId := PacketCodec(pkt).SessionId(); sessionId != s.sessionId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return pkt, err
}

func (s *session) sign(pkt []byte) []byte {
	p := PacketCodec(pkt)

	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return bytes.Equal(signature, p.Signature())
}

func (s *session) encrypt(pkt []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 52+len(pkt)+16)

	t := TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := TransformCodec(pkt)

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}
