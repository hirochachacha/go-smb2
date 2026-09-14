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
	"net"
	"os"
	"strings"

	"github.com/hirochachacha/go-smb2/v2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/v2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// sessionDialer contains options for func (*sessionDialer) Dial.
type sessionDialer struct {
	MaxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	Negotiator       negotiator
	Initiator        Initiator
}

// Dial performs negotiation and authentication.
// It returns a session. It doesn't support NetBIOS transport.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *sessionDialer) Dial(tcpConn net.Conn) (*clientSession, error) {
	return d.DialContext(context.Background(), tcpConn)
}

// DialContext performs negotiation and authentication using the provided context.
// Note that returned session doesn't inherit context.
// If you want to use the same context, call clientSession.WithContext manually.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *sessionDialer) DialContext(ctx context.Context, tcpConn net.Conn) (*clientSession, error) {
	if ctx == nil {
		panic("nil context")
	}
	return d.dialTransportContext(ctx, direct(tcpConn), tcpConn.RemoteAddr().String())
}

func (d *sessionDialer) dialTransportContext(ctx context.Context, t Transport, serverName string) (*clientSession, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}

	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(ctx, t, a)
	if err != nil {
		return nil, err
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		conn.close(err)
		return nil, err
	}

	return &clientSession{s: s, addr: serverName}, nil
}

// clientSession represents a SMB session.
type clientSession struct {
	s      *session
	addr   string
	client *Client
	entry  *clientSessionEntry
}

// Logoff invalidates the current SMB session.
func (c *clientSession) Logoff(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	return c.s.logoff(ctx)
}

// Echo sends an echo request to the server.
func (c *clientSession) Echo(ctx context.Context) error {
	return c.s.echo(ctx)
}

func (c *clientSession) serverName() string {
	serverName := c.addr
	if hostname, _, err := net.SplitHostPort(c.addr); err == nil {
		serverName = hostname
	}
	return serverName
}

// Mount mounts the SMB share. path must follow the form <share> or
// \\<server>\<share>.
func (c *clientSession) Mount(ctx context.Context, path string) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c.entry != nil && !c.client.acquireSessionRef(c.entry) {
		return nil, net.ErrClosed
	}
	refAcquired := c.entry != nil
	sharePath := normPath(path)
	if !strings.ContainsRune(sharePath, '\\') {
		sharePath = `\\` + join(c.serverName(), sharePath)
	}

	serverName, shareName, err := splitUNCShare(sharePath)
	if err != nil {
		if refAcquired {
			_ = c.client.closeSession(ctx, c)
		}
		return nil, err
	}

	tc, err := c.s.treeConnect(ctx, sharePath, 0)
	if err != nil {
		if refAcquired {
			_ = c.client.closeSession(ctx, c)
		}
		return nil, &os.PathError{Op: "mount", Path: sharePath, Err: err}
	}
	if tc.shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) == 0 {
		return &Share{treeConn: tc, sessionRef: c.ref()}, nil
	}
	state := newDFSState(c, serverName, shareName, tc.shareFlags)
	state.setLogicalTree(tc)
	return &Share{
		treeConn:   tc,
		dfs:        state,
		sessionRef: c.ref(),
	}, nil
}

func (c *clientSession) ref() *sessionRef {
	if c.entry == nil || c.client == nil {
		return nil
	}
	return &sessionRef{releaseFn: func(ctx context.Context) error { return c.client.closeSession(ctx, c) }}
}

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})
	outputToken, err := spnego.initSecContext()
	if err != nil {
		return nil, fmt.Errorf("spnego init security context failed: %w", err)
	}
	// A DFS-capable client must advertise DFS in SESSION_SETUP regardless of
	// the server's NEGOTIATE response ([MS-SMB2] 3.2.4.2.3).
	req := &smb2.SessionSetupRequest{
		Capabilities: clientCapabilities & smb2.SMB2_GLOBAL_CAP_DFS,
		SecurityMode: smb2.SMB2_NEGOTIATE_SIGNING_ENABLED,
	}
	if conn.requireSigning {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED
	}
	s := &session{conn: conn, anonymous: isAnonymousInitiator(i), preauthIntegrityHashValue: conn.preauthIntegrityHashValue}
	first := true
	for {
		if len(outputToken) > math.MaxUint16 {
			return nil, &InternalError{"security buffer exceeds 64KiB"}
		}
		req.SecurityBuffer = outputToken
		req.SetSessionId(s.sessionId)
		rrs, err := conn.send(ctx, false, req)
		if err != nil {
			return nil, err
		}
		// Requests in the authentication exchange are sent sequentially; capture
		// the request hash before receiving or sending another handshake packet.
		if conn.dialect == smb2.SMB311 && conn.preauthIntegrityHashId == smb2.SHA512 {
			updatePreauthHash(&s.preauthIntegrityHashValue, conn.encodeBuf)
		}
		var rp *recvPacket
		if first {
			rp, err = conn.recv(rrs[0])
		} else {
			rp, err = s.recv(rrs[0])
		}
		if err != nil {
			return nil, err
		}
		complete := false
		// Release each response before the next exchange, including error paths.
		err = func() error {
			defer rp.close()
			status := erref.NtStatus(rp.codec().Status())
			if status != erref.STATUS_SUCCESS && status != erref.STATUS_MORE_PROCESSING_REQUIRED {
				return &InvalidResponseError{fmt.Sprintf("unexpected session setup status: %v", status)}
			}
			r := smb2.SessionSetupResponseDecoder(rp.data())
			if r.IsInvalid() {
				return &InvalidResponseError{"broken session setup response format"}
			}
			if err := validateSessionFlags(r.SessionFlags(), s.anonymous, conn.requireSigning); err != nil {
				return err
			}
			s.sessionFlags = r.SessionFlags()
			if first {
				s.sessionId = rp.codec().SessionId()
			}
			complete = status == erref.STATUS_SUCCESS
			if !complete && conn.dialect == smb2.SMB311 && conn.preauthIntegrityHashId == smb2.SHA512 {
				updatePreauthHash(&s.preauthIntegrityHashValue, rp.bytes())
			}
			outputToken, err = spnego.acceptSecContext(r.SecurityBuffer(), complete)
			if err != nil {
				return fmt.Errorf("spnego accept security context failed: %w", err)
			}
			if complete {
				// The final AP-REP may supply the key used to sign this very response.
				// Authenticate it before deriving SMB keys and checking the signature.
				if err := s.setupKeys(spnego.sessionKey()); err != nil {
					return err
				}
				return s.verifySessionSetupResponse(rp)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
		if complete {
			conn.session = s
			s.enableSession()
			return s, nil
		}
		// The receiver must not use this session until authentication and the
		// final response's signature have both been verified.
		conn.session = s
		first = false
	}
}

func (s *session) setupKeys(sessionKey []byte) error {
	if s.signingDisabled() {
		return nil
	}

	fullSessionKey := sessionKey

	// SMB2 SessionKey is the first 16 bytes of the GSS key, right-padded
	// with zeroes when shorter ([MS-SMB2] 3.2.5.3.1).
	var normalizedSessionKey [16]byte
	copy(normalizedSessionKey[:], sessionKey)
	sessionKey = normalizedSessionKey[:]

	switch s.dialect {
	case smb2.SMB202, smb2.SMB210:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)
	case smb2.SMB300, smb2.SMB302:
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
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

		// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"), 16)

		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16)
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"), 16)

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
		keySize := 16
		encryptionKeyInput := sessionKey
		if s.cipherId == smb2.AES256CCM || s.cipherId == smb2.AES256GCM {
			keySize = 32
			encryptionKeyInput = fullSessionKey
		}

		// SMB signing remains AES-128-CMAC even when encryption uses AES-256.
		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:], 16)
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

		// s.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue, 16)

		encryptionKey := kdf(encryptionKeyInput, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:], keySize)
		decryptionKey := kdf(encryptionKeyInput, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:], keySize)

		switch s.cipherId {
		case smb2.AES128CCM, smb2.AES256CCM:
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
		case smb2.AES128GCM, smb2.AES256GCM:
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

	sessionFlags := r.SessionFlags()
	if err := validateSessionFlags(sessionFlags, s.anonymous, s.requireSigning); err != nil {
		return err
	}
	s.sessionFlags = sessionFlags

	// The receiver goroutine doesn't verify packets received before
	// enableSession, so the final SESSION_SETUP response must be verified here.
	if s.verifier != nil && !s.signingDisabled() {
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

// Guest and anonymous sessions cannot support required signing ([MS-SMB2]
// 3.2.5.3.1), so reject those sessions before they can alter session behavior.
func validateSessionFlags(sessionFlags uint16, anonymous bool, requireSigning bool) error {
	if !requireSigning {
		return nil
	}
	if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_GUEST != 0 {
		return &InvalidResponseError{"guest account doesn't support signing"}
	}
	if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_NULL != 0 {
		return &InvalidResponseError{"anonymous account doesn't support signing"}
	}
	if anonymous {
		return &InvalidResponseError{"anonymous account doesn't support signing"}
	}
	return nil
}

// isAnonymousInitiator reports whether the initiator authenticates without
// credentials. Such sessions are established as anonymous by the server, which
// does not set the guest/null session flags nor sign the final SESSION_SETUP
// response ([MS-SMB2] 3.3.5.5.3).
type anonymousInitiator interface {
	isAnonymous() bool
}

func isAnonymousInitiator(i Initiator) bool {
	if ai, ok := i.(anonymousInitiator); ok {
		return ai.isAnonymous()
	}
	return false
}

type session struct {
	*conn
	anonymous                 bool
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) broken() bool {
	if s == nil || s.conn == nil {
		return true
	}
	s.conn.m.Lock()
	defer s.conn.m.Unlock()
	return s.conn.err != nil
}

// signingDisabled reports whether the session cannot sign messages because it
// was established as a guest or anonymous session.
func (s *session) signingDisabled() bool {
	return s.anonymous || s.sessionFlags&(smb2.SMB2_SESSION_FLAG_IS_GUEST|smb2.SMB2_SESSION_FLAG_IS_NULL) != 0
}

func (s *session) logoff(ctx context.Context) error {
	req := new(smb2.LogoffRequest)

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
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
