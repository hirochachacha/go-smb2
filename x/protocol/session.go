package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net"
	"sync"
	"sync/atomic"

	"github.com/hirochachacha/go-smb2/v2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/v2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Session represents one authenticated SMB session and its connection.
type Session struct {
	s         *session
	closeOnce sync.Once
	closeErr  error
	closing   atomic.Bool
}

var errInvalidSession = errors.New("protocol: invalid session")

// Echo sends an echo request to the server.
func (c *Session) Echo(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	return c.s.echo(ctx)
}

// TreeConnect connects to shareName on serverName.
// After sending TREE_CONNECT, cancellation waits for the final response and
// disconnects any tree the server created. A server that does not complete
// the request can delay cancellation until the connection is closed.
func (c *Session) TreeConnect(ctx context.Context, serverName, shareName string, flags uint16) (*Tree, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return nil, errInvalidSession
	}
	if c.closing.Load() {
		return nil, net.ErrClosed
	}
	return c.s.treeConnect(ctx, serverName, shareName, flags)
}

// Close logs off this session and closes its transport. It is idempotent and
// concurrent callers wait for the same shutdown to finish.
//
// Note: While [MS-SMB2] 3.2.4.23 specifies disconnecting each tree connect
// before sending SMB2 LOGOFF, [MS-SMB2] 3.3.5.7 dictates that the server must
// close all open files and tree connects on the session upon receiving LOGOFF.
// Furthermore, [MS-SMB2] 3.2.6.2 and 3.3.7.1 note that tearing down the
// connection implicitly tears down all associated sessions and tree connects on
// the server. Session.Close attempts a graceful LOGOFF first with a timeout,
// followed by closing the connection.
func (c *Session) Close() error {
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), clientSessionCloseTimeout)
		defer cancel()
		// Force the connection closed if the graceful logoff cannot finish in
		// time. conn.close is idempotent and safe to call concurrently.
		stop := context.AfterFunc(ctx, func() { _ = c.s.conn.close(net.ErrClosed) })
		defer stop()
		c.closeErr = c.s.logoff(ctx)
		// Close the connection and wait for the receiver whether logoff
		// completed, timed out, or failed.
		if err := c.s.conn.close(nil); c.closeErr == nil {
			c.closeErr = err
		}
		c.closing.Store(true)
	})
	return c.closeErr
}

// Abort closes the session's connection without sending LOGOFF or
// TREE_DISCONNECT, as permitted for idle connections by [MS-SMB2] 3.2.6.2.
// It also interrupts a concurrent Close waiting for LOGOFF to complete.
// Abort is idempotent and returns the connection shutdown error; a concurrent
// Close may separately report that its LOGOFF was interrupted.
func (c *Session) Abort() error {
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	c.closing.Store(true)
	// Tear down before joining Close so its LOGOFF cannot delay Abort.
	err := c.s.conn.close(nil)
	c.closeOnce.Do(func() { c.closeErr = err })
	return err
}

func (conn *conn) sessionSetup(ctx context.Context, i Initiator) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})
	outputToken, err := spnego.initSecContext()
	if err != nil {
		return nil, fmt.Errorf("spnego init security context failed: %w", err)
	}
	// A DFS-capable client must advertise DFS in SESSION_SETUP regardless of
	// the server's NEGOTIATE Response ([MS-SMB2] 3.2.4.2.3).
	req := &wire.SessionSetupRequest{
		Capabilities: clientCapabilities & wire.SMB2_GLOBAL_CAP_DFS,
		SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
	}
	if conn.requireSigning {
		req.SecurityMode = wire.SMB2_NEGOTIATE_SIGNING_REQUIRED
	}
	s := &session{conn: conn, anonymous: isAnonymousInitiator(i), preauthIntegrityHashValue: conn.preauthIntegrityHashValue}
	first := true
	for {
		if len(outputToken) > math.MaxUint16 {
			return nil, errors.New("protocol: security buffer exceeds 64KiB")
		}
		req.SecurityBuffer = outputToken
		req.SetSessionId(s.sessionId)
		rrs, err := conn.send(ctx, false, req)
		if err != nil {
			return nil, err
		}
		// Requests in the authentication exchange are sent sequentially; capture
		// the request hash before receiving or sending another handshake packet.
		if conn.dialect == wire.SMB311 && conn.preauthIntegrityHashId == wire.SHA512 {
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
				return invalidResponse(wire.SMB2_SESSION_SETUP, fmt.Sprintf("unexpected session setup status: %v", status))
			}
			r := wire.SessionSetupResponseDecoder(rp.data())
			if r.IsInvalid() {
				return invalidResponse(wire.SMB2_SESSION_SETUP, "broken session setup response format")
			}
			if err := validateSessionFlags(r.SessionFlags(), s.anonymous, conn.requireSigning); err != nil {
				return err
			}
			s.sessionFlags = r.SessionFlags()
			if first {
				s.sessionId = rp.codec().SessionId()
			}
			complete = status == erref.STATUS_SUCCESS
			// [MS-SMB2] 3.3.5.5.1 reserves zero and -1 as invalid sessions.
			if complete && (s.sessionId == 0 || s.sessionId == ^uint64(0)) {
				return invalidResponse(wire.SMB2_SESSION_SETUP, "reserved session id in successful session setup")
			}
			if !complete && conn.dialect == wire.SMB311 && conn.preauthIntegrityHashId == wire.SHA512 {
				updatePreauthHash(&s.preauthIntegrityHashValue, rp.bytes())
			}
			outputToken, err = spnego.acceptSecContext(r.SecurityBuffer(), complete)
			if err != nil {
				return fmt.Errorf("spnego accept security context failed: %w", err)
			}
			if complete {
				// The final AP-REP may supply the key used to sign this very Response.
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
	case wire.SMB202, wire.SMB210:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)
	case wire.SMB300, wire.SMB302:
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return fmt.Errorf("protocol: initialize signing cipher: %w", err)
		}
		s.signer = cmac.New(ciph)

		// As a hardening measure, give the verifier its own cipher block:
		// cipher.Block does not guarantee that implementations are safe for
		// concurrent use.
		ciph, err = aes.NewCipher(signingKey)
		if err != nil {
			return fmt.Errorf("protocol: initialize verification cipher: %w", err)
		}
		s.verifier = cmac.New(ciph)

		if s.cipherId == 0 {
			return nil
		}

		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16)
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"), 16)

		ciph, err = aes.NewCipher(encryptionKey)
		if err != nil {
			return fmt.Errorf("protocol: initialize encryption cipher: %w", err)
		}
		s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return fmt.Errorf("protocol: initialize CCM encryption: %w", err)
		}

		ciph, err = aes.NewCipher(decryptionKey)
		if err != nil {
			return fmt.Errorf("protocol: initialize decryption cipher: %w", err)
		}
		s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return fmt.Errorf("protocol: initialize CCM decryption: %w", err)
		}
	case wire.SMB311:
		keySize := 16
		encryptionKeyInput := sessionKey
		if s.cipherId == wire.AES256CCM || s.cipherId == wire.AES256GCM {
			keySize = 32
			encryptionKeyInput = fullSessionKey
		}

		// Signing uses an independent 128-bit key even with AES-256 encryption.
		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:], 16)
		if s.signingAlgorithm == wire.AES128GMAC {
			var err error
			s.gmacSigner, err = newGMAC(signingKey)
			if err != nil {
				return err
			}
			s.gmacVerifier, err = newGMAC(signingKey)
			if err != nil {
				return err
			}
		} else {
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize signing cipher: %w", err)
			}
			s.signer = cmac.New(ciph)
			// Keep TX/RX cipher and mutable digest state independent.
			ciph, err = aes.NewCipher(signingKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize verification cipher: %w", err)
			}
			s.verifier = cmac.New(ciph)
		}

		encryptionKey := kdf(encryptionKeyInput, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:], keySize)
		decryptionKey := kdf(encryptionKeyInput, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:], keySize)

		switch s.cipherId {
		case wire.AES128CCM, wire.AES256CCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize encryption cipher: %w", err)
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return fmt.Errorf("protocol: initialize CCM encryption: %w", err)
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize decryption cipher: %w", err)
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return fmt.Errorf("protocol: initialize CCM decryption: %w", err)
			}
		case wire.AES128GCM, wire.AES256GCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize encryption cipher: %w", err)
			}
			s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return fmt.Errorf("protocol: initialize GCM encryption: %w", err)
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return fmt.Errorf("protocol: initialize decryption cipher: %w", err)
			}
			s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return fmt.Errorf("protocol: initialize GCM decryption: %w", err)
			}
		}
	}

	return nil
}

func (s *session) verifySessionSetupResponse(rp *recvPacket) error {
	r := wire.SessionSetupResponseDecoder(rp.data())

	if erref.NtStatus(rp.codec().Status()) != erref.STATUS_SUCCESS || r.IsInvalid() {
		return invalidResponse(wire.SMB2_SESSION_SETUP, "broken session setup response format")
	}

	sessionFlags := r.SessionFlags()
	if err := validateSessionFlags(sessionFlags, s.anonymous, s.requireSigning); err != nil {
		return err
	}
	s.sessionFlags = sessionFlags

	// The receiver goroutine doesn't verify packets received before
	// enableSession, so the final SESSION_SETUP Response must be verified here.
	if (s.verifier != nil || s.gmacVerifier != nil) && !s.signingDisabled() {
		isSigned := rp.codec().Flags()&wire.SMB2_FLAGS_SIGNED != 0
		if s.dialect == wire.SMB311 && !isSigned {
			return invalidResponse(wire.SMB2_SESSION_SETUP, "session setup response missing signature")
		}
		if s.requireSigning || isSigned {
			if !s.verify(rp.bytes()) {
				return invalidResponse(wire.SMB2_SESSION_SETUP, "session setup response failed signature verification")
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
	if sessionFlags&wire.SMB2_SESSION_FLAG_IS_GUEST != 0 {
		return invalidResponse(wire.SMB2_SESSION_SETUP, "guest account doesn't support signing")
	}
	if sessionFlags&wire.SMB2_SESSION_FLAG_IS_NULL != 0 {
		return invalidResponse(wire.SMB2_SESSION_SETUP, "anonymous account doesn't support signing")
	}
	if anonymous {
		return invalidResponse(wire.SMB2_SESSION_SETUP, "anonymous account doesn't support signing")
	}
	return nil
}

// isAnonymousInitiator reports whether the initiator authenticates without
// credentials. The server may omit SMB2_SESSION_FLAG_IS_NULL for anonymous
// sessions, so response flags alone cannot identify them ([MS-SMB2] 3.3.5.5.3).
func isAnonymousInitiator(i Initiator) bool {
	if ai, ok := i.(anonymousInitiator); ok {
		return ai.IsAnonymous()
	}
	return false
}

type session struct {
	*conn
	anonymous                 bool
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	// TX is serialized by conn.m; RX is owned by the receiver (or handshake).
	gmacSigner   messageAuthenticator
	gmacVerifier messageAuthenticator
	signer       hash.Hash
	verifier     hash.Hash
	encrypter    cipher.AEAD
	decrypter    cipher.AEAD
}

// signingDisabled reports whether the session cannot sign messages because it
// was established as a guest or anonymous session.
func (s *session) signingDisabled() bool {
	return s.anonymous || s.sessionFlags&(wire.SMB2_SESSION_FLAG_IS_GUEST|wire.SMB2_SESSION_FLAG_IS_NULL) != 0
}

func (s *session) logoff(ctx context.Context) error {
	req := new(wire.LogoffRequest)

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		return err
	}
	res.close()

	return nil
}

func (s *session) echo(ctx context.Context) error {
	req := new(wire.EchoRequest)

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		return err
	}
	defer res.close()

	return nil
}

func (s *session) send(ctx context.Context, encrypt bool, reqs ...wire.Packet) (rrs []*outstandingRequest, err error) {
	for _, req := range reqs {
		req.SetSessionId(s.sessionId)
	}

	rrs, err = s.conn.send(ctx, encrypt, reqs...)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

func (s *session) sendRecv(ctx context.Context, reqs ...wire.Packet) (*Response, error) {
	encrypt := s.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0
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
	// STATUS_MORE_PROCESSING_REQUIRED Response, while the client's sessionId
	// is still 0. Adopt the server's session ID in that case.
	sessionId := rp.codec().SessionId()
	if s.sessionId == 0 {
		s.sessionId = sessionId
	} else if sessionId != s.sessionId {
		rp.close()
		return nil, invalidResponse(rr.cmd, fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId))
	}
	return rp, err
}

// sign computes the signature over one or more contiguous segments of a
// packet. Direct I/O requests deliver their payload from a second segment
// located in the caller's buffer.
func (s *session) sign(pkts ...[]byte) ([]byte, error) {
	if s == nil || (s.signer == nil && s.gmacSigner == nil) || len(pkts) == 0 || len(pkts[0]) < 64 {
		if len(pkts) > 0 {
			return pkts[0], nil
		}
		return nil, nil
	}

	p := wire.PacketCodec(pkts[0])

	p.SetFlags(p.Flags() | wire.SMB2_FLAGS_SIGNED)
	clear(p.Signature())
	if s.gmacSigner != nil {
		tag, err := s.gmacSigner.sum(gmacNonce(p, false), pkts...)
		if err != nil {
			return nil, err
		}
		p.SetSignature(tag[:])
		return pkts[0], nil
	}

	h := s.signer

	h.Reset()

	for _, pkt := range pkts {
		if len(pkt) > 0 {
			h.Write(pkt)
		}
	}

	p.SetSignature(h.Sum(nil))

	return pkts[0], nil
}

// verify computes the signature over one or more contiguous segments of a
// packet. The first segment must contain the SMB2 header. Direct I/O responses
// deliver their payload in a second segment located in the caller's buffer.
func (s *session) verify(pkts ...[]byte) (ok bool) {
	if s == nil || (s.verifier == nil && s.gmacVerifier == nil) || len(pkts) == 0 || len(pkts[0]) < 64 {
		return false
	}

	p := wire.PacketCodec(pkts[0])

	var signature [16]byte

	copy(signature[:], p.Signature())

	clear(p.Signature())
	if s.gmacVerifier != nil {
		tag, err := s.gmacVerifier.sum(gmacNonce(p, true), pkts...)
		if err != nil {
			return false
		}
		p.SetSignature(tag[:])
		return subtle.ConstantTimeCompare(signature[:], tag[:]) == 1
	}

	h := s.verifier

	h.Reset()

	for _, pkt := range pkts {
		if len(pkt) > 0 {
			h.Write(pkt)
		}
	}

	p.SetSignature(h.Sum(nil))

	return subtle.ConstantTimeCompare(signature[:], p.Signature()) == 1
}

func (s *session) encrypt(pkt, c []byte) ([]byte, error) {
	if s.encrypter == nil {
		return nil, errors.New("protocol: encryption required but no cipher negotiated")
	}
	if len(c) < 52+len(pkt)+s.encrypter.Overhead() {
		return nil, errors.New("protocol: destination buffer too small")
	}

	t := wire.TransformCodec(c)

	// fill nonce directly instead of using SetNonce for avoiding allocation
	nonce := t.Nonce()[:s.encrypter.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("protocol: generate encryption nonce: %w", err)
	}

	t.SetProtocolId()
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(wire.Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	if s.decrypter == nil {
		return nil, errors.New("protocol: decryption required but no cipher negotiated")
	}

	t := wire.TransformCodec(pkt)
	if t.IsInvalid() {
		return nil, &InvalidResponseError{Message: "broken transform header format"}
	}

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}

// Keep a normal 1 MiB payload plus SMB headers/padding in reusable storage.
// Larger frames are supported but their scratch is not retained by the session.
const maxSigningScratch = (1 << 20) + (64 << 10)

type messageAuthenticator interface {
	sum([12]byte, ...[]byte) ([16]byte, error)
}

type gmac struct {
	aead    cipher.AEAD
	scratch []byte
}

func newGMAC(key []byte) (*gmac, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("protocol: initialize GMAC cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("protocol: initialize GMAC: %w", err)
	}
	return &gmac{aead: aead}, nil
}

// gmacNonce uses sender direction and CANCEL command, never the ASYNC flag
// ([MS-SMB2] 3.1.4.1). The first packet segment has a validated SMB2 header.
func gmacNonce(p wire.PacketCodec, fromServer bool) (nonce [12]byte) {
	binary.LittleEndian.PutUint64(nonce[:8], p.MessageId())
	var flags uint32
	if fromServer {
		flags = 1
	}
	if p.Command() == wire.SMB2_CANCEL {
		flags |= 2
	}
	binary.LittleEndian.PutUint32(nonce[8:], flags)
	return
}

func (g *gmac) sum(nonce [12]byte, pkts ...[]byte) (tag [16]byte, err error) {
	total := 0
	nonempty := 0
	var aad []byte
	for _, pkt := range pkts {
		if len(pkt) > maxDirectTCPSize-total {
			return tag, errors.New("protocol: signing message exceeds transport size")
		}
		total += len(pkt)
		if len(pkt) != 0 {
			nonempty++
			aad = pkt
		}
	}
	// Empty arguments do not require joining a single real AAD segment.
	if nonempty > 1 {
		if total <= maxSigningScratch {
			if cap(g.scratch) < total {
				g.scratch = make([]byte, total)
			}
			aad = g.scratch[:total]
		} else {
			aad = make([]byte, total)
		}
		off := 0
		for _, pkt := range pkts {
			off += copy(aad[off:], pkt)
		}
	}
	// GMAC is GCM with no plaintext and the whole signed message as AAD.
	g.aead.Seal(tag[:0], nonce[:], nil, aad)
	return tag, nil
}
