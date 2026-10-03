package client

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	proto "github.com/hirochachacha/go-smb2/v2/x/wire"
)

type clientTestInitiator struct{}

func TestSessionExpiryIsUnavailable(t *testing.T) {
	t.Parallel()
	for _, status := range []erref.NtStatus{erref.STATUS_NETWORK_SESSION_EXPIRED, erref.STATUS_USER_SESSION_DELETED, erref.STATUS_CONNECTION_DISCONNECTED} {
		err := &os.PathError{Op: "open", Path: "file", Err: &protocol.ResponseError{Code: uint32(status)}}
		if !isUnavailable(err) {
			t.Errorf("status %v did not invalidate the cached session", status)
		}
	}
	if isUnavailable(&protocol.ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}) {
		t.Fatal("access denied invalidated the cached session")
	}
	if isUnavailable(&protocol.ResponseError{Code: uint32(erref.STATUS_FILE_CLOSED)}) {
		t.Fatal("closed file invalidated the cached session")
	}
}

func (clientTestInitiator) OID() asn1.ObjectIdentifier { return spnego.NlmpOid }

func (clientTestInitiator) InitSecContext() ([]byte, error) {
	return []byte("client-initial-token"), nil
}

func (clientTestInitiator) AcceptSecContext([]byte) ([]byte, error) { return nil, nil }

func (clientTestInitiator) GetMIC([]byte) ([]byte, error) { return nil, nil }

func (clientTestInitiator) VerifyMIC([]byte, []byte) error { return nil }

func (clientTestInitiator) Complete() bool { return true }

func (clientTestInitiator) SessionKey() []byte { return nil }

type clientTestCredentials struct {
	mu       sync.Mutex
	servers  []string
	block    <-chan struct{}
	started  chan struct{}
	canceled chan struct{}
}

type clientTestNotifyContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *clientTestNotifyContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func (c *clientTestCredentials) NewInitiator(ctx context.Context, server string) (auth.Initiator, error) {
	c.mu.Lock()
	c.servers = append(c.servers, server)
	c.mu.Unlock()
	if c.started != nil {
		closeOnce(c.started)
	}
	if c.block != nil {
		select {
		case <-c.block:
		case <-ctx.Done():
			if c.canceled != nil {
				close(c.canceled)
			}
			return nil, ctx.Err()
		}
	}
	return clientTestInitiator{}, nil
}

type clientTestEndpoint struct {
	name          string
	handleRequest func(net.Conn, []byte) bool

	mu              sync.Mutex
	dials           int
	treeConnects    int
	treeDisconnects int
	logoffs         int
	creates         int
	active          []net.Conn
	logoffStatus    erref.NtStatus
	blockNegotiate  bool
	blockSetup      bool
	blockTree       bool
	blockWriteTree  bool
	blockLogoff     bool
	logoffStarted   chan struct{}
	negotiated      chan struct{}
	setupStarted    chan struct{}
	treeStarted     chan struct{}
	writeStarted    chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
	treeGate        <-chan struct{}
	closeGate       <-chan struct{}
}

func (e *clientTestEndpoint) closeActivePeers() {
	e.mu.Lock()
	peers := append([]net.Conn(nil), e.active...)
	e.mu.Unlock()
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func newClientTestEndpoint(name string) *clientTestEndpoint {
	return &clientTestEndpoint{
		name: name, logoffStarted: make(chan struct{}), negotiated: make(chan struct{}), setupStarted: make(chan struct{}),
		treeStarted: make(chan struct{}), writeStarted: make(chan struct{}), closed: make(chan struct{}),
	}
}

type clientTestTransportDialer struct {
	mu        sync.Mutex
	endpoints map[string]*clientTestEndpoint
}

func (d *clientTestTransportDialer) Dial(_ context.Context, server string) (v2.Transport, error) {
	d.mu.Lock()
	ep := d.endpoints[strings.ToLower(server)]
	d.mu.Unlock()
	if ep == nil {
		return nil, errors.New("unexpected endpoint " + server)
	}
	client, peer := net.Pipe()
	ep.mu.Lock()
	ep.dials++
	ep.active = append(ep.active, peer)
	ep.mu.Unlock()
	if ep.blockWriteTree {
		client = &clientTestBlockingConn{Conn: client, entered: ep.writeStarted, closed: make(chan struct{})}
	}
	if ep.closeGate != nil {
		client = &clientTestClosingConn{Conn: client, gate: ep.closeGate}
	}
	go ep.serve(peer)
	return v2.NewTransport(client), nil
}

type clientTestClosingConn struct {
	net.Conn
	gate <-chan struct{}
}

func (c *clientTestClosingConn) Close() error {
	<-c.gate
	return c.Conn.Close()
}

type clientTestBlockingConn struct {
	net.Conn
	entered   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *clientTestBlockingConn) Write(p []byte) (int, error) {
	if len(p) >= 64 && proto.PacketCodec(p).Command() == proto.SMB2_TREE_CONNECT {
		select {
		case <-c.entered:
		default:
			close(c.entered)
		}
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *clientTestBlockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newClientTestDialer(creds *clientTestCredentials, endpoints ...*clientTestEndpoint) *v2.Dialer {
	byName := make(map[string]*clientTestEndpoint, len(endpoints))
	for _, ep := range endpoints {
		byName[strings.ToLower(ep.name)] = ep
	}
	return &v2.Dialer{
		Credentials:       creds,
		TransportDialer:   &clientTestTransportDialer{endpoints: byName},
		SpecifiedDialects: []v2.Dialect{v2.SMB210},
	}
}

func (e *clientTestEndpoint) serve(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		e.closeOnce.Do(func() { close(e.closed) })
	}()
	negReq, err := readClientTestPacket(conn)
	if err != nil {
		return
	}
	closeOnce(e.negotiated)
	if e.blockNegotiate {
		waitClientTestConnClosed(conn)
		return
	}
	if err := writeClientTestNegotiate(conn, negReq); err != nil {
		return
	}
	setupReq, err := readClientTestPacket(conn)
	if err != nil {
		return
	}
	closeOnce(e.setupStarted)
	if e.blockSetup {
		waitClientTestConnClosed(conn)
		return
	}
	if err := writeClientTestSetup(conn, setupReq); err != nil {
		return
	}
	for {
		req, err := readClientTestPacket(conn)
		if err != nil {
			return
		}
		if e.handleRequest != nil && e.handleRequest(conn, req) {
			continue
		}
		p := proto.PacketCodec(req)
		switch p.Command() {
		case proto.SMB2_TREE_CONNECT:
			closeOnce(e.treeStarted)
			if e.blockTree && e.treeGate != nil {
				if waitClientTestGateOrClose(conn, e.treeGate) {
					return
				}
			}
			e.mu.Lock()
			e.treeConnects++
			e.mu.Unlock()
			if err := writeClientTestTreeConnect(conn, req); err != nil {
				return
			}
		case proto.SMB2_CREATE:
			if !isClientTestAAPLRequest(req) {
				e.mu.Lock()
				e.creates++
				e.mu.Unlock()
			}
			if err := writeClientTestCreate(conn, req); err != nil {
				return
			}
		case proto.SMB2_CLOSE:
			if err := writeClientTestClose(conn, req); err != nil {
				return
			}
		case proto.SMB2_TREE_DISCONNECT:
			e.mu.Lock()
			e.treeDisconnects++
			e.mu.Unlock()
			if err := writeClientTestTreeDisconnect(conn, req); err != nil {
				return
			}
		case proto.SMB2_LOGOFF:
			closeOnce(e.logoffStarted)
			if e.blockLogoff {
				waitClientTestConnClosed(conn)
				return
			}
			e.mu.Lock()
			e.logoffs++
			e.mu.Unlock()
			_ = writeClientTestLogoff(conn, req, e.logoffStatus)
			return
		default:
			return
		}
	}
}

func waitClientTestConnClosed(conn net.Conn) {
	var b [1]byte
	_, _ = conn.Read(b[:])
}

func waitClientTestGateOrClose(conn net.Conn, gate <-chan struct{}) bool {
	closed := make(chan struct{})
	go func() {
		var b [1]byte
		_, _ = conn.Read(b[:])
		close(closed)
	}()
	select {
	case <-gate:
		_ = conn.SetReadDeadline(time.Now())
		<-closed
		_ = conn.SetReadDeadline(time.Time{})
		return false
	case <-closed:
		return true
	}
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func readClientTestPacket(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(header[:]))
	if n < 64 || n > 1<<20 {
		return nil, errors.New("invalid test packet length")
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(conn, pkt)
	return pkt, err
}

func writeClientTestPacket(conn net.Conn, pkt []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(pkt)))
	if _, err := conn.Write(header[:]); err != nil {
		return err
	}
	_, err := conn.Write(pkt)
	return err
}

func writeClientTestNegotiate(conn net.Conn, req []byte) error {
	res := &proto.NegotiateResponse{
		Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(),
		SecurityMode: 1, DialectRevision: proto.SMB210,
		MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536,
		SystemTime: proto.Filetime{}, ServerStartTime: proto.Filetime{},
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(1)
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestSetup(conn net.Conn, req []byte) error {
	token, err := spnego.EncodeNegTokenResp(0, spnego.NlmpOid, []byte("server-final-token"), nil)
	if err != nil {
		return err
	}
	res := &proto.SessionSetupResponse{
		Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: 0x1234,
		SecurityBuffer: token,
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestTreeConnect(conn net.Conn, req []byte) error {
	res := &proto.TreeConnectResponse{
		Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: 0x77,
		ShareType: proto.SMB2_SHARE_TYPE_DISK,
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestCreate(conn net.Conn, req []byte) error {
	res := &proto.CreateResponse{
		PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: proto.PacketCodec(req).TreeId()},
		CreationTime: proto.Filetime{}, LastAccessTime: proto.Filetime{}, LastWriteTime: proto.Filetime{}, ChangeTime: proto.Filetime{}, FileId: proto.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
		FileAttributes: proto.FILE_ATTRIBUTE_NORMAL,
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	if next := proto.PacketCodec(req).NextCommand(); next != 0 && isClientTestAAPLRequest(req) {
		closeReq := proto.PacketCodec(req[next:])
		closeRes := &proto.CloseResponse{PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR | proto.SMB2_FLAGS_RELATED_OPERATIONS, MessageId: closeReq.MessageId(), SessionId: closeReq.SessionId(), TreeId: closeReq.TreeId()}}
		closePkt := make([]byte, closeRes.Size())
		closeRes.Encode(closePkt)
		proto.PacketCodec(closePkt).SetCreditResponse(closeReq.CreditRequest())
		span := proto.Roundup(len(pkt), 8)
		combined := make([]byte, span+len(closePkt))
		copy(combined, pkt)
		copy(combined[span:], closePkt)
		proto.PacketCodec(combined).SetNextCommand(uint32(span))
		return writeClientTestPacket(conn, combined)
	}
	return writeClientTestPacket(conn, pkt)
}

func isClientTestAAPLRequest(req []byte) bool {
	create := proto.CreateRequestDecoder(proto.PacketCodec(req).Body())
	if create.IsInvalid() || create.CreateContextsLength() == 0 {
		return false
	}
	for _, ctx := range create.Contexts().Contexts() {
		nameOffset := int(binary.LittleEndian.Uint16(ctx[4:6]))
		nameLength := int(binary.LittleEndian.Uint16(ctx[6:8]))
		if nameLength == 4 && string(ctx[nameOffset:nameOffset+nameLength]) == "AAPL" {
			return true
		}
	}
	return false
}

func writeClientTestClose(conn net.Conn, req []byte) error {
	res := &proto.CloseResponse{PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: proto.PacketCodec(req).TreeId()}, CreationTime: proto.Filetime{}, LastAccessTime: proto.Filetime{}, LastWriteTime: proto.Filetime{}, ChangeTime: proto.Filetime{}}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestTreeDisconnect(conn net.Conn, req []byte) error {
	res := &proto.TreeDisconnectResponse{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: proto.PacketCodec(req).TreeId()}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestLogoff(conn net.Conn, req []byte, status erref.NtStatus) error {
	res := &proto.LogoffResponse{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), Status: uint32(status)}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func TestClientCoalescesCaseInsensitiveSessionAndShareCreation(t *testing.T) {
	ep := newClientTestEndpoint("server")
	gate := make(chan struct{})
	ep.blockTree, ep.treeGate = true, gate
	creds := &clientTestCredentials{}
	d := New(newClientTestDialer(creds, ep))
	defer d.Close()

	type result struct {
		share *shareEntry
		err   error
	}
	results := make(chan result, 2)
	go func() { s, err := d.acquireShare(context.Background(), "SERVER", "Share"); results <- result{s, err} }()
	select {
	case <-ep.treeStarted:
	case <-time.After(time.Second):
		t.Fatal("first mount did not reach the wire")
	}
	waiting := make(chan struct{})
	waitCtx := &clientTestNotifyContext{Context: context.Background(), entered: waiting}
	go func() { s, err := d.acquireShare(waitCtx, "server", "sHaRe"); results <- result{s, err} }()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("second caller did not become a waiter")
	}
	close(gate)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("coalesced shares: %v, %v", a.err, b.err)
	}
	if a.share != b.share {
		t.Fatal("case-insensitive waiters received different shares")
	}
	ep.mu.Lock()
	dials, trees := ep.dials, ep.treeConnects
	ep.mu.Unlock()
	if dials != 1 || trees != 1 {
		t.Fatalf("wire creation counts = dials %d, tree connects %d; want 1, 1", dials, trees)
	}
}

func TestClientCanceledWaitersRetainSuccessfulEstablishment(t *testing.T) {
	ep := newClientTestEndpoint("server")
	gate := make(chan struct{})
	ep.blockTree, ep.treeGate = true, gate
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	defer d.Close()

	firstCtx, firstCancel := context.WithCancel(context.Background())
	secondCtx, secondCancel := context.WithCancel(context.Background())
	results := make(chan error, 2)
	go func() { _, err := d.acquireShare(firstCtx, "server", "share"); results <- err }()
	select {
	case <-ep.treeStarted:
	case <-time.After(time.Second):
		t.Fatal("mount did not reach the wire")
	}
	go func() { _, err := d.acquireShare(secondCtx, "SERVER", "SHARE"); results <- err }()
	firstCancel()
	secondCancel()
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiter error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled waiter did not return")
		}
	}
	close(gate)
	share, err := d.acquireShare(context.Background(), "server", "share")
	if err != nil || share == nil {
		t.Fatalf("retained share = %v, %v", share, err)
	}
	ep.mu.Lock()
	dials, trees := ep.dials, ep.treeConnects
	ep.mu.Unlock()
	if dials != 1 || trees != 1 {
		t.Fatalf("establishment repeated: dials %d, tree connects %d", dials, trees)
	}
}

func TestClientUsesEndpointSpecificCredentialsAndTransports(t *testing.T) {
	a, b := newClientTestEndpoint("alpha"), newClientTestEndpoint("beta")
	creds := &clientTestCredentials{}
	d := New(newClientTestDialer(creds, a, b))
	defer d.Close()
	if _, err := d.acquireSession(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.acquireSession(context.Background(), "BETA"); err != nil {
		t.Fatal(err)
	}
	creds.mu.Lock()
	gotCreds := append([]string(nil), creds.servers...)
	creds.mu.Unlock()
	if len(gotCreds) != 2 || gotCreds[0] != "alpha" || gotCreds[1] != "BETA" {
		t.Fatalf("credential endpoints = %v", gotCreds)
	}
	a.mu.Lock()
	ad := a.dials
	a.mu.Unlock()
	b.mu.Lock()
	bd := b.dials
	b.mu.Unlock()
	if ad != 1 || bd != 1 {
		t.Fatalf("transport dials = alpha %d beta %d", ad, bd)
	}
}

func TestClientCloseUnblocksDialAuthenticationAndMount(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*clientTestEndpoint, *clientTestCredentials)
		wait  func(*clientTestEndpoint)
	}{
		{name: "dial", setup: func(_ *clientTestEndpoint, creds *clientTestCredentials) {
			creds.block = make(chan struct{})
			creds.started = make(chan struct{})
			creds.canceled = make(chan struct{})
		}, wait: func(_ *clientTestEndpoint) {}},
		{name: "authentication", setup: func(ep *clientTestEndpoint, _ *clientTestCredentials) { ep.blockSetup = true }, wait: func(ep *clientTestEndpoint) { <-ep.setupStarted }},
		{name: "mount", setup: func(ep *clientTestEndpoint, _ *clientTestCredentials) {
			ep.blockTree = true
			ep.treeGate = make(chan struct{})
		}, wait: func(ep *clientTestEndpoint) { <-ep.treeStarted }},
		{name: "blocked tree connect send", setup: func(ep *clientTestEndpoint, _ *clientTestCredentials) {
			ep.blockWriteTree = true
		}, wait: func(ep *clientTestEndpoint) { <-ep.writeStarted }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			creds := &clientTestCredentials{}
			test.setup(ep, creds)
			d := New(newClientTestDialer(creds, ep))
			result := make(chan error, 1)
			go func() { _, err := d.acquireShare(context.Background(), "server", "share"); result <- err }()
			if test.name == "dial" {
				select {
				case <-creds.started:
				case <-time.After(time.Second):
					t.Fatal("Dial did not start")
				}
			} else {
				test.wait(ep)
			}
			started := time.Now()
			closeErr := d.Close()
			if elapsed := time.Since(started); elapsed > 7*time.Second {
				t.Fatalf("Client.Close took %s", elapsed)
			}
			_ = closeErr // A forced transport shutdown may report its I/O error.
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("establishment was not joined")
			}
			ep.mu.Lock()
			dials := ep.dials
			ep.mu.Unlock()
			if dials > 0 {
				select {
				case <-ep.closed:
				case <-time.After(time.Second):
					t.Fatal("transport was not closed")
				}
			}
		})
	}
}

func TestClientConcurrentCloseSharesResult(t *testing.T) {
	ep := newClientTestEndpoint("server")
	ep.logoffStatus = erref.STATUS_ACCESS_DENIED
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	if _, err := d.acquireSession(context.Background(), "server"); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() { results <- d.Close() }()
	go func() { results <- d.Close() }()
	a, b := <-results, <-results
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatalf("concurrent Close results = %v, %v", a, b)
	}
}

func TestClientCloseInvalidatesOpenFileAndRejectsNewOpen(t *testing.T) {
	ep := newClientTestEndpoint("server")
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	f, err := d.Open(context.Background(), `\\server\share\file`)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Open(context.Background(), `\\server\share\other`); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v", err)
	}
	if _, err := f.Stat(context.Background()); err == nil {
		t.Fatalf("open File remained usable after Client.Close: %v", err)
	}
	_ = f.Close(context.Background())
}

func TestClientStaleFailureCannotDeleteReplacementSession(t *testing.T) {
	ep := newClientTestEndpoint("server")
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	defer d.Close()
	oldShare, err := d.acquireShare(context.Background(), "server", "share")
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	oldSession := d.sessions[canonicalKey("server")]
	d.mu.Unlock()
	oldRoute := &resolvedRoute{share: oldShare.value, path: pathpkg.UNC{Server: "server", Share: "share"}}
	// Break the first real transport and run an operation through the normal
	// resolver. Its communication failure invalidates the old generation.
	ep.closeActivePeers()
	_, err = d.execute(context.Background(), `\\server\share\file`, func(ctx context.Context, route *resolvedRoute) (any, error) {
		return route.share.Stat(ctx, route.path.RelPath)
	})
	if err == nil {
		t.Fatal("operation on broken generation unexpectedly succeeded")
	}
	replacement, err := d.acquireShare(context.Background(), "SERVER", "SHARE")
	if err != nil {
		t.Fatal(err)
	}
	if replacement == oldShare {
		t.Fatal("replacement reused the failed share")
	}
	d.invalidateRoute(oldRoute)
	d.mu.Lock()
	current := d.shares[shareKey("server", "share")]
	currentSession := d.sessions[canonicalKey("server")]
	d.mu.Unlock()
	if current == nil || current != replacement || currentSession == nil || currentSession == oldSession {
		t.Fatal("stale old failure removed replacement session or share")
	}
}

func TestNewWithSessionIdleTimeout(t *testing.T) {
	d := New(nil, WithSessionIdleTimeout(5*time.Minute))
	if d.sessionIdleTimeout != 5*time.Minute {
		t.Fatalf("sessionIdleTimeout = %v, want %v", d.sessionIdleTimeout, 5*time.Minute)
	}
}

func TestUNCPathRequiresServerAndShare(t *testing.T) {
	for _, path := range []string{`server\share\file`, `\server\share`, `\\server`, `\\server\share\..`, "\\\\server\\share\\bad\x00name"} {
		if _, err := pathpkg.ParseUNC(path); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("ParseUNC(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
	p, err := pathpkg.ParseUNC(`\\server\share\folder\file`)
	if err != nil || p.Server != "server" || p.Share != "share" || p.RelPath != `folder\file` {
		t.Fatalf("parsed UNC = %#v, %v", p, err)
	}
}

func TestInvalidPathsReturnErrInvalidBeforeRouting(t *testing.T) {
	d := New(nil)
	for _, path := range []string{
		`server\share\file`,
		`\\server`,
		`\\server\share\..`,
		`\\server\share\.\file`,
		`\\server\share\..\secret`,
	} {
		if _, err := d.Stat(context.Background(), path); err != os.ErrInvalid {
			t.Errorf("Stat(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
}

func TestInstallReferralWireTarget(t *testing.T) {
	d := New(nil)
	response := &dfs.ReferralResponse{
		Prefix: `\\namespace\root`,
		Entries: []dfs.ReferralEntry{{
			Version: 3, TTL: time.Minute, NetworkAddress: `\server\share\入口`,
		}},
	}
	entry, err := d.installReferral(response, response.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.targets) != 1 || entry.targets[0].unc != `\\server\share\入口` {
		t.Fatalf("unexpected referral targets: %+v", entry.targets)
	}
	if d.referrals[response.Prefix] != entry {
		t.Fatal("referral was not cached")
	}
}

func TestReferralRejectsMalformedTargetBeforeCaching(t *testing.T) {
	for _, target := range []string{
		`server\share`,
		`\server`,
		`\server\\share`,
		`\server\share\`,
		`\server\share\..\file`,
		`\\\server\share`,
		`//server/share`,
		`\\server\\share`,
		`\\server\share\`,
		`\\server\share\.\file`,
		`\\server\share\..\file`,
		"\\\\server\\share\\bad\x00name",
		"\\\\server\\share\\bad\xffname",
	} {
		t.Run(target, func(t *testing.T) {
			d := New(nil)
			response := &dfs.ReferralResponse{
				Prefix: `\\namespace\root`,
				Entries: []dfs.ReferralEntry{{
					Version: 3, NetworkAddress: target,
				}},
			}
			if _, err := d.installReferral(response, response.Prefix); !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("installReferral(%q) = %v, want os.ErrInvalid", target, err)
			}
			if len(d.referrals) != 0 {
				t.Fatal("malformed target was cached")
			}
		})
	}
}

func TestInstallReferralMissingTargetsIsNotMissingFile(t *testing.T) {
	d := New(nil)
	if _, err := d.installReferral(&dfs.ReferralResponse{}, `\\namespace\root`); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty referral = %v, want referral error", err)
	}
	if _, err := d.installReferral(nil, `\\namespace\root`); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil referral = %v, want distinct contract error", err)
	}
	response := &dfs.ReferralResponse{
		Prefix:  `\\namespace\root`,
		Entries: []dfs.ReferralEntry{{Version: 3, NetworkAddress: `\\server\share`}},
	}
	response.Entries[0].NetworkAddress = ""
	if _, err := d.installReferral(response, response.Prefix); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("referral without usable target = %v, want referral error", err)
	}
}

func TestTargetOrderingStaysWithinHintedSet(t *testing.T) {
	targets := []referralTarget{{unc: `\\a\s`, boundary: true}, {unc: `\\b\s`}, {unc: `\\c\s`, boundary: true}, {unc: `\\d\s`}}
	got := orderedTargets(targets, 1)
	want := []int{1, 0, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRefreshPreservesHintWithinEquivalentTargetSets(t *testing.T) {
	old := &referralEntry{prefix: `\\n\r`, targets: []referralTarget{{unc: `\\a\s`, boundary: true}, {unc: `\\b\s`}, {unc: `\\c\s`, boundary: true}}, hint: 2}
	fresh := &referralEntry{prefix: old.prefix, targets: []referralTarget{{unc: `\\b\s`, boundary: true}, {unc: `\\a\s`}, {unc: `\\c\s`, boundary: true}}, failback: true, expires: time.Now().Add(time.Minute), cacheable: true}
	mergeReferral(old, fresh)
	if old.targets[old.hint].unc != `\\a\s` {
		t.Fatalf("hint target = %q", old.targets[old.hint].unc)
	}
	if old.hint != 0 {
		t.Fatalf("failback hint = %d, want first set", old.hint)
	}
}

func TestReferralCacheUsesLongestComponentPrefix(t *testing.T) {
	d := New(nil)
	d.referrals[`\\n\root`] = &referralEntry{prefix: `\\n\root`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\a\s`}}}
	d.referrals[`\\n\root\dir`] = &referralEntry{prefix: `\\n\root\dir`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\b\s`}}}
	entry, suffix, ok := d.cacheEntry(`\\n\root\dir\file`)
	if !ok || entry.prefix != `\\n\root\dir` || suffix != `\file` {
		t.Fatalf("cache match = %#v, %q, %v", entry, suffix, ok)
	}
}

func TestReferralCacheUsesUnicodeComponentPrefix(t *testing.T) {
	for _, tc := range []struct{ prefix, path string }{
		{`\\server\Straße`, `\\SERVER\STRAẞE`},
		{`\\SERVER\STRAẞE`, `\\server\Straße`},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			d := New(nil)
			defer d.Close()
			entry := &referralEntry{prefix: tc.prefix, cacheable: true, expires: time.Now().Add(time.Minute)}
			d.referrals[tc.prefix] = entry
			for _, suffix := range []string{"", `\Ordner\File.Ä.txt`} {
				got, gotSuffix, ok := d.cacheEntry(tc.path + suffix)
				if !ok || got != entry || gotSuffix != suffix {
					t.Fatalf("cacheEntry(%q)=%p, %q, %t; want %p, %q, true", tc.path+suffix, got, gotSuffix, ok, entry, suffix)
				}
			}
			if _, _, ok := d.cacheEntry(tc.path + `2\file`); ok {
				t.Fatal("cache entry matched a longer component")
			}
		})
	}
}

func TestV1ReferralRoutesWithoutCaching(t *testing.T) {
	d := New(nil)
	r := &dfs.ReferralResponse{Prefix: `\\n\root`, Entries: []dfs.ReferralEntry{{Version: 1, ServerType: dfs.ServerRoot, NetworkAddress: `\\a\s`}}}
	entry, err := d.installReferral(r, `\\n\root\file`)
	if err != nil || entry == nil || entry.cacheable {
		t.Fatalf("V1 install = %#v, %v", entry, err)
	}
	if _, _, ok := d.cacheEntry(`\\n\root\file`); ok {
		t.Fatal("V1 referral was cached")
	}
}

func TestReferralHeaderClassifiesRootAndInterlink(t *testing.T) {
	for _, test := range []struct {
		name                    string
		header                  uint32
		serverType              uint16
		wantRoot, wantInterlink bool
	}{
		{name: "storage link", header: dfs.HeaderStorage, serverType: dfs.ServerLink},
		{name: "interlink", header: dfs.HeaderServers, serverType: dfs.ServerLink, wantInterlink: true},
		{name: "root", header: dfs.HeaderServers | dfs.HeaderStorage, serverType: dfs.ServerRoot, wantRoot: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := New(nil)
			entry, err := d.installReferral(&dfs.ReferralResponse{
				HeaderFlags: test.header,
				Prefix:      `\\namespace\root\link`,
				Entries: []dfs.ReferralEntry{{
					Version: 3, ServerType: test.serverType,
					NetworkAddress: `\\target\share`,
				}},
			}, `\\namespace\root\link\file`)
			if err != nil {
				t.Fatal(err)
			}
			if entry.root != test.wantRoot || entry.interlink != test.wantInterlink {
				t.Fatalf("entry root=%v interlink=%v, want %v %v", entry.root, entry.interlink, test.wantRoot, test.wantInterlink)
			}
		})
	}
}

func TestReferralRefreshDoesNotMutateActiveRouteMetadata(t *testing.T) {
	d := New(nil)
	prefix := `\\namespace\root\link`
	first, err := d.installReferral(&dfs.ReferralResponse{
		HeaderFlags: dfs.HeaderStorage,
		Prefix:      prefix,
		Entries:     []dfs.ReferralEntry{{Version: 3, ServerType: dfs.ServerLink, TTL: time.Minute, NetworkAddress: `\\target\share`}},
	}, prefix+`\file`)
	if err != nil {
		t.Fatal(err)
	}
	active := &resolvedRoute{source: first}
	var wg sync.WaitGroup
	failed := make(chan string, 1)
	wg.Go(func() {
		for range 1000 {
			if active.source.interlink || active.source.root {
				select {
				case failed <- "active route metadata changed":
				default:
				}
				return
			}
		}
	})
	for range 100 {
		_, err := d.installReferral(&dfs.ReferralResponse{
			HeaderFlags: dfs.HeaderServers,
			Prefix:      prefix,
			Entries:     []dfs.ReferralEntry{{Version: 3, ServerType: dfs.ServerLink, TTL: time.Minute, NetworkAddress: `\\target\namespace`}},
		}, prefix+`\file`)
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	select {
	case message := <-failed:
		t.Fatal(message)
	default:
	}
	if active.source == nil || active.source.interlink || active.source.root {
		t.Fatal("active referral entry was mutated during refresh")
	}
	current, _, ok := d.cacheEntry(prefix + `\file`)
	if !ok || !current.interlink {
		t.Fatal("refreshed referral did not publish new interlink metadata")
	}
}

func TestEquivalentTargetSetsRespectBoundaries(t *testing.T) {
	old := []referralTarget{
		{unc: `\\a\share`, boundary: true}, {unc: `\\b\share`},
		{unc: `\\c\share`, boundary: true}, {unc: `\\d\share`},
	}
	if equivalentTargets(old, []referralTarget{
		{unc: `\\a\share`, boundary: true}, {unc: `\\c\share`},
		{unc: `\\b\share`, boundary: true}, {unc: `\\d\share`},
	}) {
		t.Fatal("target membership moved across sets but was considered equivalent")
	}
	if !equivalentTargets(old, []referralTarget{
		{unc: `\\b\share`, boundary: true}, {unc: `\\a\share`},
		{unc: `\\c\share`, boundary: true}, {unc: `\\d\share`},
	}) {
		t.Fatal("target order within a set changed equivalence")
	}
}

func TestRefreshResetsRemovedHint(t *testing.T) {
	old := &referralEntry{
		prefix:  `\\namespace\root`,
		targets: []referralTarget{{unc: `\\old\share`, boundary: true}, {unc: `\\other\share`}},
		hint:    1,
	}
	fresh := &referralEntry{
		prefix:    old.prefix,
		targets:   []referralTarget{{unc: `\\new\share`, boundary: true}},
		cacheable: true,
		expires:   time.Now().Add(time.Minute),
	}
	mergeReferral(old, fresh)
	if old.hint != 0 || old.targets[old.hint].unc != `\\new\share` {
		t.Fatalf("removed hint retained: hint=%d targets=%v", old.hint, old.targets)
	}
}

func TestInterlinkRouteDoesNotMountNamespaceShare(t *testing.T) {
	d := New(nil)
	entry := &referralEntry{
		prefix:    `\\namespace\root\link`,
		interlink: true,
		targets:   []referralTarget{{unc: `\\target\namespace`}},
	}
	route, err := d.selectRoute(context.Background(), `\\namespace\root\link\file`, entry, `\file`)
	if err != nil {
		t.Fatal(err)
	}
	if route.share != nil || route.path.RelPath != `link\file` || route.exact {
		t.Fatalf("interlink route = %#v, want namespace-only route", route)
	}
}

func TestCloseAndInvalidClientOperationsAreSafe(t *testing.T) {
	d := New(nil)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := d.Open(context.Background(), `\\server\share\file`)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v", err)
	}
}

func TestZeroClientOperationsDoNotPanic(t *testing.T) {
	var d Client
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := d.Open(context.Background(), `\\server\share\file`)
	if err == nil {
		t.Fatal("zero Client Open succeeded")
	}
}

func TestUpperErrorsStripResolvedPathWrappers(t *testing.T) {
	inner := &protocol.DFSReferralRequiredError{Path: `\\target\share\file`}
	lower := &os.PathError{Op: "open", Path: `target\share\file`, Err: inner}
	wrapped := &os.PathError{Op: "open", Path: `\\namespace\root\file`, Err: lower}
	if got := unwrapFilesystemError(wrapped); got != inner {
		t.Fatalf("unwrapped error = %v, want referral error", got)
	}
}

func TestRemoveAllEmptyAndShareRoot(t *testing.T) {
	// No dialer is configured: neither case should attempt a connection.
	d := New(nil)
	defer d.Close()
	if err := d.RemoveAll(context.Background(), ""); err != nil {
		t.Fatalf("empty RemoveAll = %v", err)
	}
	for _, path := range []string{`\\server\share`, `\\server\share\`, `//server/share/`} {
		if err := d.RemoveAll(context.Background(), path); err != os.ErrInvalid {
			t.Fatalf("RemoveAll(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
}

func TestGlobRejectsInvalidPatternsBeforeConnecting(t *testing.T) {
	d := New(nil)
	defer d.Close()
	for _, pattern := range []string{"/server/share/*", "../share/*"} {
		if _, err := d.WithContext(context.Background()).Glob(pattern); err != os.ErrInvalid {
			t.Fatalf("Glob(%q) = %v", pattern, err)
		}
	}
	for _, pattern := range []string{"server/share/[", "server/share/" + strings.Repeat("*/", 10000) + "file"} {
		if _, err := d.WithContext(context.Background()).Glob(pattern); !errors.Is(err, path.ErrBadPattern) {
			t.Fatalf("invalid Glob = %v", err)
		}
	}
}

func TestAppendFileRejectsWriteAt(t *testing.T) {
	ep := newClientTestEndpoint("server")
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := d.OpenFile(ctx, `\\server\share\file`, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close(ctx)
	for _, b := range [][]byte{nil, []byte("x")} {
		for _, write := range []func([]byte, int64) (int, error){
			func(p []byte, off int64) (int, error) { return f.WriteAt(ctx, p, off) },
			f.WithContext(ctx).WriteAt,
		} {
			if n, err := write(b, 0); n != 0 || err == nil || !strings.Contains(err.Error(), "O_APPEND") {
				t.Fatalf("WriteAt = %d, %v", n, err)
			}
		}
	}
}

func TestCanonicalKeyDoesNotMutate(t *testing.T) {
	if got := canonicalKey(); got != "" {
		t.Fatalf("canonicalKey() = %q, want empty", got)
	}
	if got := canonicalKey("SERVER"); got != "server" {
		t.Fatalf("canonicalKey(1) = %q, want server", got)
	}
	parts := []string{"SERVER", "SHARE"}
	key := canonicalKey(parts...)
	if key != "server\\share" {
		t.Fatalf("canonicalKey = %q, want %q", key, "server\\share")
	}
	if parts[0] != "SERVER" || parts[1] != "SHARE" {
		t.Fatalf("canonicalKey mutated parts: %v", parts)
	}
	if got := canonicalKey("A", "B", "C"); got != "a\\b\\c" {
		t.Fatalf("canonicalKey(3) = %q, want a\\b\\c", got)
	}
}

func TestFileNilAndInvalidContextOperations(t *testing.T) {
	t.Parallel()
	var nilFile *File
	ctx := context.Background()

	if _, err := nilFile.ReadFrom(ctx, strings.NewReader("data")); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("nilFile.ReadFrom = %v, want os.ErrInvalid", err)
	}
	if _, err := nilFile.WriteTo(ctx, io.Discard); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("nilFile.WriteTo = %v, want os.ErrInvalid", err)
	}
	if nilFile.WithContext(ctx) != nil {
		t.Error("nilFile.WithContext(ctx) != nil")
	}

	var fc fileContext
	if err := fc.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.Close() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.Read(make([]byte, 1)); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.Read() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.ReadAt() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.Write([]byte("a")); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.Write() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.WriteAt([]byte("a"), 0); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.WriteAt() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.Seek(0, io.SeekStart); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.Seek() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.Stat(); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.Stat() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.ReadDir(1); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.ReadDir() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.ReadFrom(strings.NewReader("data")); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.ReadFrom() = %v, want os.ErrInvalid", err)
	}
	if _, err := fc.WriteTo(io.Discard); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("fc.WriteTo() = %v, want os.ErrInvalid", err)
	}

	var uninitFile File
	if err := uninitFile.Close(ctx); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("uninitFile.Close() = %v, want os.ErrInvalid", err)
	}

	var bcf boundClientFile
	if err := bcf.Close(); err != os.ErrInvalid {
		t.Errorf("bcf.Close() = %v, want os.ErrInvalid", err)
	}
	if _, err := bcf.Stat(); err != os.ErrInvalid {
		t.Errorf("bcf.Stat() = %v, want os.ErrInvalid", err)
	}
	if _, err := bcf.Read(make([]byte, 1)); err != os.ErrInvalid {
		t.Errorf("bcf.Read() = %v, want os.ErrInvalid", err)
	}
	if _, err := bcf.ReadDir(1); err != os.ErrInvalid {
		t.Errorf("bcf.ReadDir() = %v, want os.ErrInvalid", err)
	}

	var nilVD *virtualDirectory
	if err := nilVD.Close(); err != os.ErrInvalid {
		t.Errorf("nilVD.Close() = %v, want os.ErrInvalid directly", err)
	}
	if _, err := nilVD.Stat(); err != os.ErrInvalid {
		t.Errorf("nilVD.Stat() = %v, want os.ErrInvalid directly", err)
	}
	if _, err := nilVD.Read(make([]byte, 1)); err != os.ErrInvalid {
		t.Errorf("nilVD.Read() = %v, want os.ErrInvalid directly", err)
	}
	if _, err := nilVD.ReadDir(1); err != os.ErrInvalid {
		t.Errorf("nilVD.ReadDir() = %v, want os.ErrInvalid directly", err)
	}
}

func TestVirtualPathReadsReturnInvalid(t *testing.T) {
	t.Parallel()
	s := (&Client{}).WithContext(context.Background())
	if _, err := s.ReadFile("."); err != os.ErrInvalid {
		t.Errorf("ReadFile(.) = %v, want os.ErrInvalid directly", err)
	}
	if _, err := s.ReadLink("."); err != os.ErrInvalid {
		t.Errorf("ReadLink(.) = %v, want os.ErrInvalid directly", err)
	}
}

func TestVirtualDirectoryReadReturnsInvalid(t *testing.T) {
	t.Parallel()
	d := &virtualDirectory{name: "."}
	if _, err := d.Read(make([]byte, 1)); err != os.ErrInvalid {
		t.Fatalf("Read() = %v, want os.ErrInvalid directly", err)
	}
}

func TestVirtualDirectoryClosedReturnsClosed(t *testing.T) {
	t.Parallel()
	d := &virtualDirectory{name: "."}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op  string
		run func() error
	}{
		{"close", d.Close},
		{"stat", func() error { _, err := d.Stat(); return err }},
		{"read", func() error { _, err := d.Read(make([]byte, 1)); return err }},
		{"readdir", func() error { _, err := d.ReadDir(1); return err }},
	} {
		err := tc.run()
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Op != tc.op || pathErr.Path != "." || pathErr.Err != os.ErrClosed {
			t.Errorf("%s error = %v, want PathError wrapping os.ErrClosed", tc.op, err)
		}
	}
}

func TestClosedFileCloseReturnsPathError(t *testing.T) {
	t.Parallel()
	f := &File{name: `\\server\share\file`, closed: true}
	err := f.Close(context.Background())
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "close" || pathErr.Path != f.name || pathErr.Err != os.ErrClosed {
		t.Fatalf("Close() = %v, want PathError wrapping os.ErrClosed", err)
	}
}

func TestClosedClientFileErrorsKeepOriginalUNC(t *testing.T) {
	for _, name := range []string{`\\server\share\dir\file`, "//server/share/dir/file"} {
		t.Run(name, func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			d := New(newClientTestDialer(&clientTestCredentials{}, ep))
			defer d.Close()
			ctx := context.Background()
			f, err := d.Open(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(ctx); err != nil {
				t.Fatal(err)
			}
			bound := f.WithContext(ctx)
			for _, test := range []struct {
				name, op string
				call     func() error
			}{
				{"ReadAt", "read", func() error { _, err := f.ReadAt(ctx, make([]byte, 1), 0); return err }},
				{"WriteAt", "write", func() error { _, err := f.WriteAt(ctx, []byte("x"), 0); return err }},
				{"Seek", "seek", func() error { _, err := f.Seek(ctx, 0, io.SeekStart); return err }},
				{"Truncate", "truncate", func() error { return f.Truncate(ctx, 0) }},
				{"Sync", "sync", func() error { return f.Sync(ctx) }},
				{"Chmod", "chmod", func() error { return f.Chmod(ctx, 0600) }},
				{"Read", "read", func() error { _, err := f.Read(ctx, make([]byte, 1)); return err }},
				{"Write", "write", func() error { _, err := f.Write(ctx, []byte("x")); return err }},
				{"Stat", "stat", func() error { _, err := f.Stat(ctx); return err }},
				{"Statfs", "statfs", func() error { _, err := f.Statfs(ctx); return err }},
				{"Readdir", "readdir", func() error { _, err := f.Readdir(ctx, 1); return err }},
				{"ReadDir", "readdir", func() error { _, err := f.ReadDir(ctx, 1); return err }},
				{"Readdirnames", "readdir", func() error { _, err := f.Readdirnames(ctx, 1); return err }},
				{"Lock", "lock", func() error { return f.Lock(ctx, nil, true) }},
				{"Unlock", "unlock", func() error { return f.Unlock(ctx, nil) }},
				{"WaitForChange", "waitforchange", func() error { _, err := f.WaitForChange(ctx, 0, false); return err }},
				{"Close", "close", func() error { return f.Close(ctx) }},
				{"bound ReadAt", "read", func() error { _, err := bound.ReadAt(make([]byte, 1), 0); return err }},
				{"bound WriteAt", "write", func() error { _, err := bound.WriteAt([]byte("x"), 0); return err }},
				{"bound Seek", "seek", func() error { _, err := bound.Seek(0, io.SeekStart); return err }},
				{"bound ReadDir", "readdir", func() error { _, err := bound.ReadDir(1); return err }},
			} {
				t.Run(test.name, func(t *testing.T) {
					err := test.call()
					var pathErr *os.PathError
					if !errors.Is(err, os.ErrClosed) || !errors.As(err, &pathErr) || pathErr.Op != test.op || pathErr.Path != name {
						t.Fatalf("error=%v; want %s %q wrapping os.ErrClosed", err, test.op, name)
					}
					if _, nested := pathErr.Err.(*os.PathError); nested {
						t.Fatalf("nested PathError: %v", err)
					}
				})
			}
		})
	}
}

func TestClientFileReadErrorsKeepUNCAndCause(t *testing.T) {
	ep := newClientTestEndpoint("server")
	reads := 0
	ep.handleRequest = func(conn net.Conn, request []byte) bool {
		p := proto.PacketCodec(request)
		if p.Command() != proto.SMB2_READ {
			return false
		}
		reads++
		status := erref.STATUS_ACCESS_DENIED
		if reads > 1 {
			status = erref.STATUS_END_OF_FILE
		}
		response := &proto.ErrorResponse{CommandCode: proto.SMB2_READ}
		data := make([]byte, response.Size())
		response.Encode(data)
		out := proto.PacketCodec(data)
		out.SetMessageId(p.MessageId())
		out.SetSessionId(p.SessionId())
		out.SetTreeId(p.TreeId())
		out.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
		out.SetCreditResponse(1)
		out.SetStatus(uint32(status))
		if err := writeClientTestPacket(conn, data); err != nil {
			t.Error(err)
		}
		return true
	}
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	defer d.Close()
	ctx := context.Background()
	const name = `\\server\share\dir\file`
	f, err := d.Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close(ctx)
	_, err = f.ReadAt(ctx, make([]byte, 1), 0)
	var pathErr *os.PathError
	var responseErr *protocol.ResponseError
	if !errors.Is(err, os.ErrPermission) || !errors.As(err, &pathErr) || pathErr.Path != name || pathErr.Op != "read" || !errors.As(err, &responseErr) || responseErr.Code != uint32(erref.STATUS_ACCESS_DENIED) {
		t.Fatalf("read error lost UNC or cause: %v", err)
	}
	if _, nested := pathErr.Err.(*os.PathError); nested {
		t.Fatalf("nested PathError: %v", err)
	}
	if _, err := f.ReadAt(ctx, make([]byte, 1), 0); err != io.EOF {
		t.Fatalf("EOF must remain bare: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = f.ReadAt(canceled, make([]byte, 1), 0)
	if !errors.Is(err, context.Canceled) || !errors.As(err, &pathErr) || pathErr.Path != name {
		t.Fatalf("cancellation lost UNC or cause: %v", err)
	}
	var nilFile *File
	if _, err := nilFile.ReadAt(ctx, make([]byte, 1), 0); err != os.ErrInvalid {
		t.Fatalf("nil file must return bare ErrInvalid: %v", err)
	}
}

type clientTestBytes []byte

func (b clientTestBytes) Size() int         { return len(b) }
func (b clientTestBytes) Encode(dst []byte) { copy(dst, b) }

func clientTestDirectoryPage(names ...string) clientTestBytes {
	var page clientTestBytes
	for i, name := range names {
		encoded := utf16le.EncodeStringToBytes(name)
		entry := make([]byte, proto.Roundup(104+len(encoded), 8))
		binary.LittleEndian.PutUint32(entry[60:64], uint32(len(encoded)))
		copy(entry[104:], encoded)
		if i+1 < len(names) {
			binary.LittleEndian.PutUint32(entry, uint32(len(entry)))
		}
		page = append(page, entry...)
	}
	return page
}

func TestClientReadDirPreservesPartialEntries(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprint(bound), func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			queries := 0
			ep.handleRequest = func(conn net.Conn, req []byte) bool {
				p := proto.PacketCodec(req)
				if p.Command() != proto.SMB2_QUERY_DIRECTORY {
					return false
				}
				queries++
				var response proto.Packet = &proto.ErrorResponse{CommandCode: proto.SMB2_QUERY_DIRECTORY}
				status := erref.STATUS_ACCESS_DENIED
				if queries <= 2 {
					page := clientTestDirectoryPage("z", "b")
					if queries == 2 {
						page = clientTestDirectoryPage("y", "a")
					}
					response = &proto.QueryDirectoryResponse{Output: page}
					status = erref.STATUS_SUCCESS
				}
				data := make([]byte, response.Size())
				response.Encode(data)
				r := proto.PacketCodec(data)
				r.SetMessageId(p.MessageId())
				r.SetSessionId(p.SessionId())
				r.SetTreeId(p.TreeId())
				r.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
				r.SetCreditResponse(1)
				r.SetStatus(uint32(status))
				if err := writeClientTestPacket(conn, data); err != nil {
					t.Error(err)
				}
				return true
			}
			dialer := newClientTestDialer(&clientTestCredentials{}, ep)
			dialer.MaxCreditBalance = 1
			d := New(dialer)
			defer d.Close()
			var names []string
			var err error
			if bound {
				entries, e := d.WithContext(context.Background()).ReadDir("server/share/dir")
				err = e
				for _, entry := range entries {
					names = append(names, entry.Name())
				}
			} else {
				infos, e := d.ReadDir(context.Background(), `\\server\share\dir`)
				err = e
				for _, info := range infos {
					names = append(names, info.Name())
				}
			}
			if !errors.Is(err, os.ErrPermission) || !slices.Equal(names, []string{"a", "b", "y", "z"}) {
				t.Fatalf("ReadDir = %v, %v; want sorted partial entries and permission error", names, err)
			}
			var responseErr *protocol.ResponseError
			if !errors.As(err, &responseErr) || responseErr.Code != uint32(erref.STATUS_ACCESS_DENIED) {
				t.Fatalf("original directory error lost: %v", err)
			}
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) || pathErr.Op != "readdir" {
				t.Fatalf("PathError lost: %v", err)
			}
			if _, nested := pathErr.Err.(*os.PathError); nested {
				t.Fatalf("nested PathError: %v", err)
			}
		})
	}
}

func TestClientFileDirectoryReadsPreservePartialEntries(t *testing.T) {
	for _, method := range []string{"Readdir", "ReadDir", "Readdirnames", "WithContext", "FS.Open"} {
		for _, n := range []int{0, 1, 3, 4} {
			t.Run(fmt.Sprintf("%s/n=%d", method, n), func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				queries := 0
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := proto.PacketCodec(request)
					if p.Command() != proto.SMB2_QUERY_DIRECTORY {
						return false
					}
					queries++
					status := erref.STATUS_NO_MORE_FILES
					var response proto.Packet = &proto.ErrorResponse{CommandCode: proto.SMB2_QUERY_DIRECTORY}
					switch queries {
					case 1:
						response = &proto.QueryDirectoryResponse{Output: clientTestDirectoryPage("z", "a")}
						status = erref.STATUS_SUCCESS
					case 2:
						status = erref.STATUS_ACCESS_DENIED
					case 3:
						response = &proto.QueryDirectoryResponse{Output: clientTestDirectoryPage("next")}
						status = erref.STATUS_SUCCESS
					}
					data := make([]byte, response.Size())
					response.Encode(data)
					out := proto.PacketCodec(data)
					out.SetMessageId(p.MessageId())
					out.SetSessionId(p.SessionId())
					out.SetTreeId(p.TreeId())
					out.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
					out.SetCreditResponse(1)
					out.SetStatus(uint32(status))
					if err := writeClientTestPacket(conn, data); err != nil {
						t.Error(err)
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.MaxCreditBalance = 1
				d := New(dialer)
				defer d.Close()
				ctx := context.Background()
				var f *File
				var bound fs.ReadDirFile
				if method == "FS.Open" {
					opened, err := d.WithContext(ctx).Open("server/share/dir")
					if err != nil {
						t.Fatal(err)
					}
					defer opened.Close()
					bound = opened.(fs.ReadDirFile)
				} else {
					var err error
					f, err = d.Open(ctx, `\\server\share\dir`)
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close(ctx)
					bound = f.WithContext(ctx)
				}
				read := func(count int) (names []string, err error) {
					switch method {
					case "Readdir":
						var infos []os.FileInfo
						infos, err = f.Readdir(ctx, count)
						for _, info := range infos {
							names = append(names, info.Name())
						}
					case "Readdirnames":
						names, err = f.Readdirnames(ctx, count)
					default:
						var entries []fs.DirEntry
						if method == "ReadDir" {
							entries, err = f.ReadDir(ctx, count)
						} else {
							entries, err = bound.ReadDir(count)
						}
						for _, entry := range entries {
							names = append(names, entry.Name())
						}
					}
					return
				}
				want := []string{"z", "a"}
				if n == 4 {
					names, err := read(1)
					if err != nil || !slices.Equal(names, []string{"z"}) {
						t.Fatalf("first read=%v, %v", names, err)
					}
					want = []string{"a"}
				}
				if n == 1 {
					for _, name := range want {
						names, err := read(1)
						if err != nil || !slices.Equal(names, []string{name}) {
							t.Fatalf("cached read=%v, %v", names, err)
						}
					}
					want = nil
				}
				names, err := read(n)
				if !errors.Is(err, os.ErrPermission) || !slices.Equal(names, want) {
					t.Fatalf("partial read=%v, %v; want %v and permission error", names, err, want)
				}
				var responseErr *protocol.ResponseError
				if !errors.As(err, &responseErr) || responseErr.Code != uint32(erref.STATUS_ACCESS_DENIED) {
					t.Fatalf("original error lost: %v", err)
				}
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) || pathErr.Op != "readdir" {
					t.Fatalf("PathError lost: %v", err)
				}
				if _, nested := pathErr.Err.(*os.PathError); nested {
					t.Fatalf("nested PathError: %v", err)
				}
				names, err = read(n)
				if err != nil || !slices.Equal(names, []string{"next"}) {
					t.Fatalf("retry=%v, %v; returned entries must not repeat", names, err)
				}
				names, err = read(n)
				if (n > 0 && !errors.Is(err, io.EOF)) || (n <= 0 && err != nil) || len(names) != 0 {
					t.Fatalf("end=%v, %v", names, err)
				}
			})
		}
	}
}

func TestExpiredReferralRefreshFailureDoesNotUseStaleTarget(t *testing.T) {
	namespace, target := newClientTestEndpoint("namespace"), newClientTestEndpoint("target")
	namespace.handleRequest = func(conn net.Conn, request []byte) bool {
		p := proto.PacketCodec(request)
		if p.Command() != proto.SMB2_IOCTL {
			return false
		}
		response := &proto.ErrorResponse{CommandCode: proto.SMB2_IOCTL}
		data := make([]byte, response.Size())
		response.Encode(data)
		r := proto.PacketCodec(data)
		r.SetMessageId(p.MessageId())
		r.SetSessionId(p.SessionId())
		r.SetTreeId(p.TreeId())
		r.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
		r.SetCreditResponse(1)
		r.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		if err := writeClientTestPacket(conn, data); err != nil {
			t.Error(err)
		}
		return true
	}
	d := New(newClientTestDialer(&clientTestCredentials{}, namespace, target))
	defer d.Close()
	prefix := `\\namespace\root\link`
	entry, err := d.installReferral(&dfs.ReferralResponse{
		HeaderFlags: dfs.HeaderStorage, Prefix: prefix,
		Entries: []dfs.ReferralEntry{{Version: 3, ServerType: dfs.ServerLink, TTL: time.Minute, NetworkAddress: `\target\share`}},
	}, prefix+`\file`)
	if err != nil {
		t.Fatal(err)
	}
	route, err := d.route(context.Background(), prefix+`\file`)
	if err != nil {
		t.Fatal(err)
	}
	if route.path.Server != "target" {
		t.Fatal("fresh referral did not select target")
	}
	route.session.release()
	d.mu.Lock()
	entry.expires = time.Now().Add(-time.Second)
	d.mu.Unlock()
	route, err = d.route(context.Background(), prefix+`\file`)
	if route != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expired route = %#v, %v; want refresh failure without stale target", route, err)
	}
	if _, _, ok := d.cacheEntry(prefix + `\file`); ok {
		t.Fatal("failed refresh revived expired entry")
	}
}

func TestClientSymlinkCurrentDirectoryTarget(t *testing.T) {
	for _, target := range []string{".", "./", ""} {
		t.Run(target, func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			got := make(chan []byte, 1)
			ep.handleRequest = func(conn net.Conn, request []byte) bool {
				p := proto.PacketCodec(request)
				if p.Command() != proto.SMB2_IOCTL {
					return false
				}
				r := proto.IoctlRequestDecoder(request[64:])
				if r.IsInvalid() || r.CtlCode() != proto.FSCTL_SET_REPARSE_POINT {
					t.Error("unexpected IOCTL")
					return false
				}
				got <- append([]byte(nil), r.Input()...)
				response := &proto.IoctlResponse{CtlCode: r.CtlCode()}
				data := make([]byte, response.Size())
				response.Encode(data)
				out := proto.PacketCodec(data)
				out.SetMessageId(p.MessageId())
				out.SetSessionId(p.SessionId())
				out.SetTreeId(p.TreeId())
				out.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
				out.SetCreditResponse(1)
				if err := writeClientTestPacket(conn, data); err != nil {
					t.Error(err)
				}
				return true
			}
			dialer := newClientTestDialer(&clientTestCredentials{}, ep)
			dialer.MaxCreditBalance = 1
			d := New(dialer)
			defer d.Close()
			err := d.Symlink(context.Background(), target, `\\server\share\dir\alias`)
			if target == "" {
				if !errors.Is(err, os.ErrInvalid) || len(got) != 0 {
					t.Fatalf("empty target: err=%v, IOCTLs=%d", err, len(got))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r := proto.SymbolicLinkReparseDataBufferDecoder(<-got)
			if r.IsInvalid() {
				t.Fatal("invalid reparse data")
			}
			want := "."
			if r.SubstituteName() != want || r.PrintName() != want || r.Flags() != proto.SYMLINK_FLAG_RELATIVE {
				t.Fatalf("reparse names=%q, %q; flags=%d", r.SubstituteName(), r.PrintName(), r.Flags())
			}
		})
	}
}

func TestClientReadFilePreservesPrefixOnReadError(t *testing.T) {
	for _, bound := range []bool{false, true} {
		for _, failRead := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("bound=%v/failRead=%d", bound, failRead), func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				contents := strings.Repeat("x", 3*(64<<10))
				closes := make(chan struct{}, 4)
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := proto.PacketCodec(request)
					var response proto.Packet
					status := uint32(0)
					switch p.Command() {
					case proto.SMB2_CANCEL:
						return true
					case proto.SMB2_CREATE:
						response = &proto.CreateResponse{EndofFile: int64(len(contents)), FileId: proto.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}}
					case proto.SMB2_READ:
						r := proto.ReadRequestDecoder(request[64:])
						if r.Offset() >= uint64((failRead-1)*(64<<10)) {
							response = &proto.ErrorResponse{CommandCode: proto.SMB2_READ}
							status = uint32(erref.STATUS_ACCESS_DENIED)
						} else {
							response = &proto.ReadResponse{Data: []byte(contents[int(r.Offset()) : int(r.Offset())+int(r.Length())])}
						}
					case proto.SMB2_CLOSE:
						closes <- struct{}{}
						return false
					default:
						return false
					}
					data := make([]byte, response.Size())
					response.Encode(data)
					out := proto.PacketCodec(data)
					out.SetMessageId(p.MessageId())
					out.SetSessionId(p.SessionId())
					out.SetTreeId(p.TreeId())
					out.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
					out.SetCreditResponse(1)
					out.SetStatus(status)
					if err := writeClientTestPacket(conn, data); err != nil {
						t.Error(err)
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.MaxCreditBalance = 1
				dialer.DisableAAPLExtension = true
				d := New(dialer)
				defer d.Close()
				var data []byte
				var err error
				name := `\\server\share\file`
				if bound {
					name = "server/share/file"
					data, err = d.WithContext(context.Background()).ReadFile(name)
				} else {
					data, err = d.ReadFile(context.Background(), name)
				}
				if !errors.Is(err, os.ErrPermission) {
					t.Fatalf("error = %v", err)
				}
				if string(data) != contents[:(failRead-1)*(64<<10)] {
					t.Fatalf("returned prefix length=%d; want %d", len(data), (failRead-1)*(64<<10))
				}
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) || pathErr.Op != "readfile" || pathErr.Path != name {
					t.Fatalf("PathError = %#v", err)
				}
				if _, nested := pathErr.Err.(*os.PathError); nested || len(closes) != 1 {
					t.Fatalf("nested error=%v; CLOSE count=%d", nested, len(closes))
				}
			})
		}
	}
}
