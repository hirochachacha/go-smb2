package client

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path"
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
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	proto "github.com/hirochachacha/go-smb2/v2/x/wire"
)

type clientTestInitiator struct{}

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
	name string

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
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		}
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
			e.mu.Lock()
			e.creates++
			e.mu.Unlock()
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
		PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId()},
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
		PacketHeader:   proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: 0x1234},
		SecurityBuffer: token,
	}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestTreeConnect(conn net.Conn, req []byte) error {
	res := &proto.TreeConnectResponse{
		PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: 0x77},
		ShareType:    proto.SMB2_SHARE_TYPE_DISK,
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
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestClose(conn net.Conn, req []byte) error {
	res := &proto.CloseResponse{PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: proto.PacketCodec(req).TreeId()}, CreationTime: proto.Filetime{}, LastAccessTime: proto.Filetime{}, LastWriteTime: proto.Filetime{}, ChangeTime: proto.Filetime{}}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestTreeDisconnect(conn net.Conn, req []byte) error {
	res := &proto.TreeDisconnectResponse{PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), TreeId: proto.PacketCodec(req).TreeId()}}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	proto.PacketCodec(pkt).SetCreditResponse(proto.PacketCodec(req).CreditRequest())
	return writeClientTestPacket(conn, pkt)
}

func writeClientTestLogoff(conn net.Conn, req []byte, status erref.NtStatus) error {
	res := &proto.LogoffResponse{PacketHeader: proto.PacketHeader{Flags: proto.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: proto.PacketCodec(req).MessageId(), SessionId: proto.PacketCodec(req).SessionId(), Status: uint32(status)}}
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
		if _, err := d.Stat(context.Background(), path); !errors.Is(err, os.ErrInvalid) {
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

func TestInstallReferralReportsMissingTargetsAsNotExist(t *testing.T) {
	d := New(nil)
	if _, err := d.installReferral(&dfs.ReferralResponse{}, `\\namespace\root`); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty referral = %v, want os.ErrNotExist", err)
	}
	if _, err := d.installReferral(nil, `\\namespace\root`); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil referral = %v, want distinct contract error", err)
	}
	response := &dfs.ReferralResponse{
		Prefix:  `\\namespace\root`,
		Entries: []dfs.ReferralEntry{{Version: 3, NetworkAddress: `\\server\share`}},
	}
	response.Entries[0].NetworkAddress = ""
	if _, err := d.installReferral(response, response.Prefix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("referral without usable target = %v, want os.ErrNotExist", err)
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if active.source.interlink || active.source.root {
				select {
				case failed <- "active route metadata changed":
				default:
				}
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
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
		if err := d.RemoveAll(context.Background(), path); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("RemoveAll(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
}

func TestGlobRejectsInvalidPatternsBeforeConnecting(t *testing.T) {
	d := New(nil)
	defer d.Close()
	for _, pattern := range []string{"/server/share/*", "../share/*"} {
		if _, err := d.WithContext(context.Background()).Glob(pattern); !errors.Is(err, os.ErrInvalid) {
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
