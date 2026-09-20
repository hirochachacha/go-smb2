package smb2

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// testInitiator and testHandshake establish the smallest authenticated SMB
// session needed by the parent-package API tests. Requests after TREE_CONNECT
// remain on the raw peer so each test can provide its own server behavior.
type testInitiator struct{ complete bool }

var testMechanismOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

func (*testInitiator) OID() asn1.ObjectIdentifier { return testMechanismOID }
func (i *testInitiator) InitSecContext() ([]byte, error) {
	i.complete = false
	return []byte{1}, nil
}
func (i *testInitiator) AcceptSecContext([]byte) ([]byte, error) {
	i.complete = true
	return nil, nil
}
func (*testInitiator) GetMIC([]byte) ([]byte, error)  { return nil, nil }
func (*testInitiator) VerifyMIC([]byte, []byte) error { return nil }
func (i *testInitiator) Complete() bool               { return i.complete }
func (*testInitiator) SessionKey() []byte             { return nil }

type testServerOptions struct {
	sessionID                                  uint64
	treeID                                     uint32
	wrapClient                                 func(net.Conn) net.Conn
	dialect                                    uint16
	capabilities                               uint32
	singleCredit                               bool
	maxReadSize, maxWriteSize, maxTransactSize uint32
	credits                                    uint16
	ioPipelineDepth                            uint
	sessionFlags                               uint16
	shareFlags                                 uint32
	shareType                                  uint8
	isDFSShare                                 bool
	serverName, shareName                      string
}

func testServerDefaults(options []testServerOptions) testServerOptions {
	var o testServerOptions
	if len(options) != 0 {
		o = options[0]
	}
	if o.sessionID == 0 {
		o.sessionID = 0x100
	}
	if o.treeID == 0 {
		o.treeID = 0x200
	}
	if o.dialect == 0 {
		o.dialect = wire.SMB302
	}
	if o.capabilities == 0 && !o.singleCredit {
		o.capabilities = wire.SMB2_GLOBAL_CAP_LARGE_MTU
	}
	if o.maxReadSize == 0 {
		o.maxReadSize = 1 << 20
	}
	if o.maxWriteSize == 0 {
		o.maxWriteSize = 1 << 20
	}
	if o.maxTransactSize == 0 {
		o.maxTransactSize = 1 << 20
	}
	if o.credits == 0 {
		o.credits = 512
	}
	if o.sessionFlags == 0 {
		o.sessionFlags = wire.SMB2_SESSION_FLAG_IS_GUEST
	}
	if o.shareType == 0 {
		o.shareType = wire.SMB2_SHARE_TYPE_DISK
	}
	if o.serverName == "" {
		o.serverName = "server"
	}
	if o.shareName == "" {
		o.shareName = "share"
	}
	return o
}

func newProtocolTestSession(t testing.TB, options ...testServerOptions) (*Session, net.Conn) {
	t.Helper()
	o := testServerDefaults(options)
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- testSessionHandshake(server, o) }()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	dialer := protocol.Dialer{SpecifiedDialects: []wire.Dialect{wire.Dialect(o.dialect)}, MaxCreditBalance: o.credits, IOPipelineDepth: o.ioPipelineDepth}
	transportConn := net.Conn(client)
	if o.wrapClient != nil {
		transportConn = o.wrapClient(client)
	}
	session, err := dialer.Dial(context.Background(), &testInitiator{}, protocol.NewTransport(transportConn))
	if err != nil {
		t.Fatalf("connect test session: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("test handshake: %v", err)
	}
	return &Session{s: session, addr: o.serverName}, server
}

func newProtocolTestShare(t testing.TB, options ...testServerOptions) (*Share, net.Conn) {
	t.Helper()
	o := testServerDefaults(options)
	session, server := newProtocolTestSession(t, o)
	done := make(chan error, 1)
	go func() {
		req, err := testReadPacket(server)
		if err != nil {
			done <- err
			return
		}
		if wire.PacketCodec(req).Command() != wire.SMB2_TREE_CONNECT {
			done <- fmt.Errorf("expected TREE_CONNECT")
			return
		}
		caps := uint32(0)
		if o.isDFSShare {
			caps = wire.SMB2_SHARE_CAP_DFS
		}
		done <- testWriteResponse(server, req, &wire.TreeConnectResponse{ShareType: o.shareType, ShareFlags: o.shareFlags, Capabilities: caps}, erref.STATUS_SUCCESS, o.sessionID, o.treeID)
	}()
	share, err := session.Mount(context.Background(), o.shareName)
	if err != nil {
		t.Fatalf("connect test tree: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("mount handshake: %v", err)
	}
	return share, server
}

func testSessionHandshake(conn net.Conn, o testServerOptions) error {
	req, err := testReadPacket(conn)
	if err != nil {
		return err
	}
	if wire.PacketCodec(req).Command() != wire.SMB2_NEGOTIATE {
		return fmt.Errorf("expected NEGOTIATE")
	}
	neg := &wire.NegotiateResponse{
		PacketHeader:    wire.PacketHeader{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR},
		SecurityMode:    wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
		DialectRevision: o.dialect,
		Capabilities:    o.capabilities,
		MaxTransactSize: o.maxTransactSize, MaxReadSize: o.maxReadSize, MaxWriteSize: o.maxWriteSize,
		SystemTime: &wire.Filetime{}, ServerStartTime: &wire.Filetime{},
	}
	if err := testWriteResponse(conn, req, neg, erref.STATUS_SUCCESS, 0, 0); err != nil {
		return err
	}
	req, err = testReadPacket(conn)
	if err != nil {
		return err
	}
	if wire.PacketCodec(req).Command() != wire.SMB2_SESSION_SETUP {
		return fmt.Errorf("expected SESSION_SETUP")
	}
	token, err := spnego.EncodeNegTokenResp(0, testMechanismOID, []byte{2}, nil)
	if err != nil {
		return err
	}
	setup := &wire.SessionSetupResponse{SessionFlags: o.sessionFlags, SecurityBuffer: token}
	return testWriteResponse(conn, req, setup, erref.STATUS_SUCCESS, o.sessionID, 0)
}

func testReadPacket(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 64 || n > 4<<20 {
		return nil, fmt.Errorf("invalid packet length %d", n)
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(conn, pkt)
	return pkt, err
}

// readMsg is retained as a small raw Direct TCP framing helper for the
// high-level tests. The server side deliberately uses net.Conn directly;
// protocol.Transport is sealed and is only used by the client under test.
func readMsg(conn net.Conn) ([]byte, error) { return testReadPacket(conn) }

func testWritePacket(conn net.Conn, pkt []byte) (int, error) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(pkt)))
	if _, err := conn.Write(header[:]); err != nil {
		return 0, err
	}
	n, err := conn.Write(pkt)
	return 4 + n, err
}

func testWriteResponse(conn net.Conn, req []byte, response wire.Packet, status erref.NtStatus, sessionID uint64, treeID uint32) error {
	buf := make([]byte, response.Size())
	response.Encode(buf)
	reqPacket := wire.PacketCodec(req)
	p := wire.PacketCodec(buf)
	p.SetMessageId(reqPacket.MessageId())
	p.SetSessionId(sessionID)
	p.SetTreeId(treeID)
	p.SetStatus(uint32(status))
	p.SetCreditResponse(reqPacket.CreditRequest())
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	_, err := testWritePacket(conn, buf)
	return err
}

type compoundResponse struct {
	packet wire.Packet
	status erref.NtStatus
}

func sendCompoundResponse(conn net.Conn, request []byte, responses []compoundResponse) error {
	if len(responses) == 0 {
		return fmt.Errorf("empty compound response")
	}
	var out []byte
	offset := 0
	for i, response := range responses {
		req := wire.PacketCodec(request[offset:])
		span := wire.Roundup(response.packet.Size(), 8)
		buf := make([]byte, span)
		response.packet.Encode(buf)
		p := wire.PacketCodec(buf)
		p.SetMessageId(req.MessageId())
		p.SetSessionId(req.SessionId())
		p.SetTreeId(req.TreeId())
		p.SetStatus(uint32(response.status))
		p.SetCreditResponse(req.CreditRequest())
		flags := uint32(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		if i > 0 {
			flags |= wire.SMB2_FLAGS_RELATED_OPERATIONS
		}
		p.SetFlags(flags)
		if i < len(responses)-1 {
			p.SetNextCommand(uint32(span))
		}
		out = append(out, buf...)
		if next := req.NextCommand(); next != 0 {
			offset += int(next)
		} else {
			offset = len(request)
		}
	}
	_, err := testWritePacket(conn, out)
	return err
}
