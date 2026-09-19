package smb2

import (
	"context"
	"slices"
	"uuid"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// Dialect represents an SMB dialect revision.
type Dialect = smb2.Dialect

const (
	SMB202 = smb2.SMB202
	SMB210 = smb2.SMB210
	SMB300 = smb2.SMB300
	SMB302 = smb2.SMB302
	SMB311 = smb2.SMB311
)

// Cipher represents an SMB 3.x encryption cipher algorithm ID.
type Cipher = smb2.Cipher

const (
	AES128CCM = smb2.AES128CCM
	AES128GCM = smb2.AES128GCM
	AES256CCM = smb2.AES256CCM
	AES256GCM = smb2.AES256GCM
)

// Dialer configures independent SMB sessions. A Dialer may be used by
// concurrent callers; callers must not modify it or referenced configuration
// while it is in use.
type Dialer struct {
	Credentials Credentials
	// TransportDialer creates the transport for a server. If nil, TCPDialer{}
	// is used.
	TransportDialer  TransportDialer
	MaxCreditBalance uint16
	// IOPipelineDepth limits outstanding requests per Read/Write operation,
	// not per connection. Zero uses 4; 1 processes chunks sequentially.
	IOPipelineDepth uint
	// RequireMessageSigning requires SMB message signing.
	RequireMessageSigning bool
	// ClientGuid identifies this client. If zero (uuid.Nil()), a version 4
	// UUID is generated for each connection.
	ClientGuid uuid.UUID
	// SpecifiedDialects restricts negotiation to these SMB dialects. Empty
	// offers all supported client dialects ([MS-SMB2] 3.2.4.2). QUIC requires
	// SMB 3.1.1.
	SpecifiedDialects []Dialect
	// Ciphers restricts encryption to these cipher IDs in order of preference.
	// Empty offers client defaults ([MS-SMB2] 3.2.4.2.2).
	Ciphers []Cipher
	// DisableEncryptionOverSecureTransport offers QUIC transport security in
	// place of SMB encryption. SMB encryption is skipped only if the server
	// accepts the offer; this option has no effect on other transports.
	DisableEncryptionOverSecureTransport bool
}

// Dial establishes a new authenticated session and transfers ownership of its
// connection to the returned Session.
func (d *Dialer) Dial(ctx context.Context, serverName string) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d == nil {
		return nil, &InternalError{"nil Dialer"}
	}
	if d.Credentials == nil {
		return nil, &InternalError{"Credentials is required"}
	}
	td := d.TransportDialer
	if td == nil {
		td = TCPDialer{}
	}
	initiator, err := d.Credentials.NewInitiator(ctx, serverName)
	if err != nil {
		return nil, err
	}
	if initiator == nil {
		return nil, &InternalError{"Credentials returned a nil Initiator"}
	}
	t, err := td.Dial(ctx, serverName)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, &InternalError{"TransportDialer returned nil"}
	}
	if t.transportType() == "quic" {
		if len(d.SpecifiedDialects) > 0 && !slices.Contains(d.SpecifiedDialects, SMB311) {
			// [MS-SMB2] 2.1: SMB over QUIC requires the SMB 3.1.1 dialect. The
			// transport has not been published to the caller, so Dial still owns
			// it and must close it before returning the configuration error.
			_ = t.Close()
			return nil, errQUICTransportDialect
		}
	}
	// [MS-SMB2] 3.2.4.2 requires valid SpecifiedDialects. Dial still owns
	// the transport during configuration validation, before connect takes over.
	for _, dialect := range d.SpecifiedDialects {
		if !slices.Contains(clientDialects, dialect) {
			_ = t.Close()
			return nil, &InternalError{"unsupported dialect specified"}
		}
	}
	for _, cipher := range d.Ciphers {
		if !slices.Contains(clientCiphers, cipher) {
			_ = t.Close()
			return nil, &InternalError{"unsupported cipher specified"}
		}
	}
	// A caller's context must be able to terminate synchronous negotiation or
	// authentication I/O. The unpublished transport belongs to this Dial until
	// the session is returned.
	//
	// context.AfterFunc's stop does not wait for a callback that has already
	// started, so the watcher must be joined before ownership can be returned.
	// Otherwise the callback could still close the transport after Dial returns
	// and hand the caller a dead Session.
	watchDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(watchDone)
		_ = t.Close()
	})
	ws, err := d.connect(ctx, t, serverName, initiator)
	// Stop the watcher and wait for any in-flight Close to complete before
	// deciding whether the transport may be published. stop reports false when
	// the callback already started, in which case watchDone signals its end.
	if !stop() {
		<-watchDone
	}
	if err != nil {
		return nil, err
	}
	// Treat cancellation observed before ownership is handed to the caller as
	// a failed Dial. Once this function returns, no watcher remains that could
	// close the caller-owned Session.
	if err := ctx.Err(); err != nil {
		_ = ws.Close()
		return nil, err
	}
	return ws, nil
}

// connect negotiates and authenticates on t, which is owned by this Dial
// until it returns.
func (d *Dialer) connect(ctx context.Context, t Transport, serverName string, initiator Initiator) (*Session, error) {
	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	conn, err := d.negotiate(ctx, t, openAccount(maxCreditBalance))
	if err != nil {
		return nil, err
	}

	s, err := conn.sessionSetup(ctx, initiator)
	if err != nil {
		conn.close(err)
		return nil, err
	}

	return &Session{s: s, addr: serverName}, nil
}

func (d *Dialer) negotiate(ctx context.Context, t Transport, a *account) (c *conn, err error) {
	t.setPacketReadTimeout(clientPacketReadTimeout)
	conn := &conn{
		t:                   t,
		outstandingRequests: newOutstandingRequests(),
		account:             a,
		receiverDone:        make(chan struct{}),
		writeTimeout:        clientWriteTimeout,
		ioPipelineDepth:     d.IOPipelineDepth,
	}

	defer func() {
		if err != nil {
			conn.close(err)
		}
	}()

	go conn.runReceiver()

	isQUIC := t.transportType() == "quic"

	dialects := d.SpecifiedDialects
	if len(dialects) == 0 {
		dialects = clientDialects
	}
	if isQUIC {
		dialects = []Dialect{SMB311}
	}

	req, err := d.makeNegotiateRequest(dialects, isQUIC && d.DisableEncryptionOverSecureTransport)
	if err != nil {
		return nil, err
	}

	res, err := conn.sendRecv(ctx, req)
	if err != nil {
		return nil, err
	}
	defer res.close()

	r := smb2.NegotiateResponseDecoder(res.data(0))
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken negotiate response format"}
	}

	// Don't accept wildcard nor UnknownSMB
	switch r.DialectRevision() {
	case smb2.SMB2, smb2.UnknownSMB:
		return nil, &InvalidResponseError{"unexpected dialect returned"}
	}

	if !slices.Contains(req.Dialects, Dialect(r.DialectRevision())) {
		return nil, &InvalidResponseError{"unexpected dialect returned"}
	}

	// [MS-SMB2] 3.2.5.2: The client SHOULD disconnect the connection if the
	// size, in bytes, received in MaxTransactSize, MaxReadSize, or
	// MaxWriteSize is less than 65536.
	if r.MaxTransactSize() < maxSingleCreditPayloadSize || r.MaxReadSize() < maxSingleCreditPayloadSize || r.MaxWriteSize() < maxSingleCreditPayloadSize {
		return nil, &InvalidResponseError{"payload size below 64KB"}
	}

	conn.requireSigning = d.RequireMessageSigning || r.SecurityMode()&smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED != 0
	conn.capabilities = clientCapabilities & r.Capabilities()
	conn.dialect = r.DialectRevision()
	conn.maxTransactSize = r.MaxTransactSize()
	conn.maxReadSize = r.MaxReadSize()
	conn.maxWriteSize = r.MaxWriteSize()

	// conn.gssNegotiateToken = r.SecurityBuffer()
	// conn.clientGuid = n.ClientGuid
	// copy(conn.serverGuid[:], r.ServerGuid())

	if conn.dialect != smb2.SMB311 {
		return conn, nil
	}

	// handle context for SMB311
	var seenPreauth, seenEncryption, seenCompression, seenTransport bool
	list := r.Contexts()
	for count := r.NegotiateContextCount(); count > 0; count-- {
		nc := smb2.NegotiateContextDecoder(list)
		if nc.IsInvalid() {
			return nil, &InvalidResponseError{"broken negotiate context format"}
		}

		switch nc.ContextType() {
		case smb2.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			if seenPreauth {
				return nil, &InvalidResponseError{"duplicate preauth integrity capabilities context"}
			}
			seenPreauth = true

			data := smb2.HashContextDataDecoder(nc.Data())
			if data.IsInvalid() {
				return nil, &InvalidResponseError{"broken hash context data format"}
			}

			algs := data.HashAlgorithms()

			if len(algs) != 1 {
				return nil, &InvalidResponseError{"multiple hash algorithms"}
			}

			if !slices.Contains(clientHashAlgorithms, algs[0]) {
				return nil, &InvalidResponseError{"unsupported hash algorithm"}
			}

			conn.preauthIntegrityHashId = algs[0]

			// Handshake requests are executed sequentially without concurrent access,
			// so conn.encodeBuf still holds the encoded request packet.
			updatePreauthHash(&conn.preauthIntegrityHashValue, conn.encodeBuf)
			updatePreauthHash(&conn.preauthIntegrityHashValue, res.bytes(0))
		case smb2.SMB2_ENCRYPTION_CAPABILITIES:
			if seenEncryption {
				return nil, &InvalidResponseError{"duplicate encryption capabilities context"}
			}
			seenEncryption = true

			data := smb2.CipherContextDataDecoder(nc.Data())
			if data.IsInvalid() {
				return nil, &InvalidResponseError{"broken cipher context data format"}
			}

			ciphs := data.Ciphers()

			if len(ciphs) != 1 {
				return nil, &InvalidResponseError{"multiple cipher algorithms"}
			}

			offeredCiphers := d.Ciphers
			if len(offeredCiphers) == 0 {
				offeredCiphers = clientCiphers
			}
			// [MS-SMB2] 3.2.5.2 permits Ciphers[0] == 0 to disable encryption;
			// zero is valid only as the server's selected value, not as a client offer.
			if ciphs[0] != 0 && !slices.Contains(offeredCiphers, ciphs[0]) {
				return nil, &InvalidResponseError{"unsupported cipher algorithm"}
			}

			conn.cipherId = uint16(ciphs[0])
		case smb2.SMB2_TRANSPORT_CAPABILITIES:
			if seenTransport {
				return nil, &InvalidResponseError{"duplicate transport capabilities context"}
			}
			seenTransport = true
			data := smb2.TransportContextDataDecoder(nc.Data())
			if data.IsInvalid() {
				return nil, &InvalidResponseError{"broken transport context data format"}
			}
			conn.acceptTransportSecurity = isQUIC && d.DisableEncryptionOverSecureTransport && data.Flags()&smb2.SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY != 0
		case smb2.SMB2_COMPRESSION_CAPABILITIES:
			if seenCompression {
				return nil, &InvalidResponseError{"duplicate compression capabilities context"}
			}
			seenCompression = true

			data := smb2.CompressionContextDataDecoder(nc.Data())
			if data.IsInvalid() {
				return nil, &InvalidResponseError{"broken compression context data format"}
			}
			if data.Flags() != smb2.SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE && data.Flags() != smb2.SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED {
				return nil, &InvalidResponseError{"invalid compression context flags"}
			}

			algorithms := data.CompressionAlgorithms()
			if len(algorithms) == 0 {
				return nil, &InvalidResponseError{"no compression algorithms"}
			}

			seenAlgorithms := make(map[uint16]struct{}, len(algorithms))
			for _, algorithm := range algorithms {
				if algorithm >= 32 {
					return nil, &InvalidResponseError{"invalid compression algorithm"}
				}
				if _, ok := seenAlgorithms[algorithm]; ok {
					return nil, &InvalidResponseError{"duplicate compression algorithm"}
				}
				seenAlgorithms[algorithm] = struct{}{}
			}

			if len(algorithms) == 1 && algorithms[0] == smb2.SMB2_COMPRESSION_ALGORITHM_NONE {
				conn.compressionIds = nil
				break
			}

			for _, algorithm := range algorithms {
				if !slices.Contains(clientCompressionAlgorithms, algorithm) {
					return nil, &InvalidResponseError{"unsupported compression algorithm"}
				}
			}
			conn.compressionIds = append([]uint16(nil), algorithms...)
			// The client offers unchained LZ4 only. A server's CHAINED bit
			// does not opt this connection into chained compression.
			conn.supportsChainedCompression = false
		default:
			// skip unsupported context
		}

		off := nc.Next()

		if len(list) < off {
			list = nil
		} else {
			list = list[off:]
		}
	}

	if !seenPreauth {
		return nil, &InvalidResponseError{"missing preauth integrity capabilities context"}
	}

	return conn, nil
}

// makeNegotiateRequest builds the NEGOTIATE request from the Dialer configuration.
func (d *Dialer) makeNegotiateRequest(dialects []Dialect, acceptTransportSecurity bool) (*smb2.NegotiateRequest, error) {
	req := new(smb2.NegotiateRequest)

	if d.RequireMessageSigning {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.Capabilities = clientCapabilities

	if d.ClientGuid == uuid.Nil() {
		req.ClientGuid = uuid.NewV4()
	} else {
		req.ClientGuid = d.ClientGuid
	}

	req.Dialects = dialects

	hasSMB311 := slices.Contains(dialects, SMB311)
	hasSMB3 := false
	for _, dialect := range dialects {
		if SMB300 <= dialect {
			hasSMB3 = true
			break
		}
	}

	if !hasSMB3 {
		req.Capabilities = 0
	}

	if hasSMB311 {
		hc, err := newHashContext()
		if err != nil {
			return nil, err
		}
		req.Contexts = append(req.Contexts, hc, newCipherContext(d.Ciphers), newCompressionContext())
		if acceptTransportSecurity {
			req.Contexts = append(req.Contexts, &smb2.TransportContext{Flags: smb2.SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY})
		}
	}

	return req, nil
}
