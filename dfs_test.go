package smb2

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

func TestDFSClientReceivesReferralServer(t *testing.T) {
	var called string
	wantErr := errors.New("dial failed")
	client := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &NTLMInitiator{}, nil
		}),
		TransportDialer: testTransportDialerFunc(func(_ context.Context, server string) (Transport, error) {
			called = server
			return nil, wantErr
		}),
	})
	owner := &clientSession{client: client}
	_, err := connectDFSTree(context.Background(), owner, "ns", "files.example.com", "share")
	if !errors.Is(err, wantErr) || called != "files.example.com" {
		t.Fatalf("Client called with %q, err %v", called, err)
	}
}

func TestDFSRenameRejectsDifferentTargetTrees(t *testing.T) {
	d := newTestDFSResolver(t, map[string]*treeConn{
		`one\share`: {}, `two\share`: {},
	}, map[string][]byte{
		`\ns\root\old\file`: makeDFSReferralV3(`\ns\root\old`, `\\one\share`),
		`\ns\root\new\file`: makeDFSReferralV3(`\ns\root\new`, `\\two\share`),
	})
	fs := &Share{treeConn: &treeConn{}, dfs: d}
	if err := fs.Rename(context.Background(), `old\file`, `new\file`); err == nil || !strings.Contains(err.Error(), "cross-device DFS rename") {
		t.Fatalf("expected cross-target DFS rename error, got %v", err)
	}
}

func TestDFSRoutedCreateRejectsOversizedLogicalPath(t *testing.T) {
	d := newDFSResolver(&clientSession{}, strings.Repeat("s", 100), "root")
	fs := &Share{treeConn: &treeConn{}, dfs: d}
	name := strings.Repeat("a", 32720)
	if _, err := fs.sendRouted(context.Background(), &smb2.CreateRequest{Name: name}); err == nil {
		t.Fatal("oversized logical DFS path was accepted")
	}
}

func TestDFSRoutedCreateUsesTargetRelativeNameAndBindsFile(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	s.enableSession()
	base := &treeConn{session: s, treeId: 1}
	target := &treeConn{session: s, treeId: 2}
	d := newTestDFSResolver(t, map[string]*treeConn{`target\share`: target}, map[string][]byte{
		`\ns\root\link\file`: makeDFSReferralV3(`\ns\root\link`, `\\target\share\dir`),
	})
	// Populate the referral cache through the resolver's API.
	if _, err := d.Resolve(context.Background(), `\ns\root\link\file`); err != nil {
		t.Fatal(err)
	}
	fs := &Share{treeConn: base, dfs: d}

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		msg, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(msg)
		if p.TreeId() != 2 || p.Flags()&smb2.SMB2_FLAGS_DFS_OPERATIONS != 0 {
			t.Errorf("target header = tree %d flags %#x", p.TreeId(), p.Flags())
		}
		cr := smb2.CreateRequestDecoder(p.Body())
		nameBytes := p[int(cr.NameOffset()) : int(cr.NameOffset())+int(cr.NameLength())]
		if got := smb2.UTF16ToString(func() []uint16 {
			u := make([]uint16, len(nameBytes)/2)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(nameBytes[2*i:])
			}
			return u
		}()); got != `dir\file` {
			t.Errorf("target CREATE name = %q", got)
		}
		body := &smb2.CreateResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}, FileId: &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}}
		resp := make([]byte, body.Size())
		body.Encode(resp)
		rp := smb2.PacketCodec(resp)
		rp.SetProtocolId()
		rp.SetCommand(smb2.SMB2_CREATE)
		rp.SetStatus(0)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetSessionId(0x1234)
		rp.SetTreeId(2)
		_, _ = st.Writev(resp)
	}()
	create := &smb2.CreateRequest{Name: `link\file`, DesiredAccess: smb2.GENERIC_READ, CreateDisposition: smb2.FILE_OPEN, ShareAccess: smb2.FILE_SHARE_READ}
	f, err := fs.createFile(context.Background(), create.Name, create, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.fs.treeConn != target {
		t.Fatal("File lost routed tree")
	}
	f.closed.Store(true)
	<-done
}

func TestDFSRootPathNotCoveredReferralAndRetry(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	s.enableSession()
	base := &treeConn{session: s, treeId: 1}
	owner := &clientSession{s: s}
	d := newDFSResolver(owner, "ns", "root")
	fs := &Share{treeConn: base, dfs: d}

	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(serverConn)
		// 1. The opening CREATE uses the logical namespace path and DFS flag.
		first, err := readMsg(dt)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(first)
		cr := smb2.CreateRequestDecoder(p.Body())
		name := utf16le.DecodeToString(first[int(cr.NameOffset()) : int(cr.NameOffset())+int(cr.NameLength())])
		if name != `\ns\root\link\file` {
			t.Errorf("logical CREATE name = %q", name)
		}
		if p.Flags()&smb2.SMB2_FLAGS_DFS_OPERATIONS == 0 {
			t.Error("logical CREATE omitted DFS flag")
		}
		sendDFSResponse(dt, first, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_PATH_NOT_COVERED), 1)

		// 2. Referral lookup uses IPC$ and an all-ones FileId.
		ipcReq, err := readMsg(dt)
		if err != nil {
			return
		}
		if smb2.PacketCodec(ipcReq).Command() != smb2.SMB2_TREE_CONNECT {
			t.Errorf("IPC command = %v", smb2.PacketCodec(ipcReq).Command())
		}
		sendDFSResponse(dt, ipcReq, &smb2.TreeConnectResponse{ShareType: smb2.SMB2_SHARE_TYPE_PIPE}, 0, 3)
		ioctlReq, err := readMsg(dt)
		if err != nil {
			return
		}
		id := smb2.IoctlRequestDecoder(ioctlReq[64:]).FileId()
		for _, b := range append(append([]byte{}, id.Persistent()...), id.Volatile()...) {
			if b != 0xff {
				t.Errorf("referral FileId is not all ones: %x", id)
				break
			}
		}
		ir := smb2.IoctlRequestDecoder(ioctlReq[64:])
		in := ioctlReq[int(ir.InputOffset()) : int(ir.InputOffset())+int(ir.InputCount())]
		if len(in) < 4 || binary.LittleEndian.Uint16(in[:2]) != 4 {
			t.Errorf("referral request = %x", in)
		}
		path := utf16le.DecodeToString(in[2:])
		if path != `\ns\root\link\file` {
			t.Errorf("referral path = %q", path)
		}
		sendDFSResponse(dt, ioctlReq, &smb2.IoctlResponse{CtlCode: smb2.FSCTL_DFS_GET_REFERRALS, FileId: smb2.RelatedFileId, Output: rawEncoder(makeDFSReferralV3(`\ns\root\link`, `\\ns\target\dir`))}, 0, 3)

		// 3. The selected target is connected and the CREATE is retried relative
		// to the target share, without DFS routing on the physical tree.
		targetConnect, err := readMsg(dt)
		if err != nil {
			return
		}
		sendDFSResponse(dt, targetConnect, &smb2.TreeConnectResponse{ShareType: smb2.SMB2_SHARE_TYPE_DISK}, 0, 4)
		targetCreate, err := readMsg(dt)
		if err != nil {
			return
		}
		tp := smb2.PacketCodec(targetCreate)
		tcr := smb2.CreateRequestDecoder(tp.Body())
		targetName := utf16le.DecodeToString(targetCreate[int(tcr.NameOffset()) : int(tcr.NameOffset())+int(tcr.NameLength())])
		if targetName != `dir\file` {
			t.Errorf("target CREATE name = %q", targetName)
		}
		if tp.Flags()&smb2.SMB2_FLAGS_DFS_OPERATIONS != 0 {
			t.Error("target CREATE retained DFS flag")
		}
		sendDFSResponse(dt, targetCreate, &smb2.CreateResponse{CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{}, LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{}, FileId: &smb2.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}}, 0, 4)
	}()
	f, err := fs.createFile(context.Background(), `link\file`, &smb2.CreateRequest{Name: `link\file`, DesiredAccess: smb2.GENERIC_READ, CreateDisposition: smb2.FILE_OPEN, ShareAccess: smb2.FILE_SHARE_READ}, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.fs.treeConn == base {
		t.Fatal("opened File remained on logical tree")
	}
	f.closed.Store(true)
	<-done
}

func sendDFSResponse(dt transport, req []byte, response smb2.Packet, status uint32, treeID uint32) {
	buf := make([]byte, response.Size())
	response.Encode(buf)
	rp := smb2.PacketCodec(buf)
	p := smb2.PacketCodec(req)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(treeID)
	rp.SetStatus(status)
	rp.SetCreditResponse(1)
	rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	_, _ = dt.Writev(buf)
}

func makeDFSReferralV3(prefix, target string) []byte {
	path := append(utf16le.EncodeStringToBytes(prefix), 0, 0)
	network := append(utf16le.EncodeStringToBytes(target), 0, 0)
	const entrySize = 34
	b := make([]byte, 8+entrySize+len(path)+len(path)+len(network))
	le := binary.LittleEndian
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(prefix)))
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], entrySize)
	le.PutUint32(b[16:20], 300)
	le.PutUint16(b[20:22], entrySize)
	le.PutUint16(b[22:24], entrySize+uint16(len(path)))
	le.PutUint16(b[24:26], entrySize+uint16(len(path)*2))
	copy(b[8+entrySize:], path)
	copy(b[8+entrySize+len(path):], path)
	copy(b[8+entrySize+len(path)*2:], network)
	return b
}

func TestDFSInterlinkQueriesNextNamespaceAndCaches(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	s.enableSession()
	target := &treeConn{session: s, treeId: 5}
	initial := makeDFSReferralV3(`\ns\root\link`, `\mid\dfs\入口`)
	binary.LittleEndian.PutUint32(initial[4:8], dfsc.ReferralHeaderServers)
	d := newTestDFSResolver(t, map[string]*treeConn{
		`mid\ipc$`:      {session: s, treeId: 3},
		`hop\ipc$`:      {session: s, treeId: 4},
		`storage\files`: target,
	}, map[string][]byte{`\ns\root\link\dir\file`: initial})
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(serverConn)
		for _, step := range []struct {
			tree                 uint32
			path, prefix, target string
			flags                uint32
		}{
			{3, `\mid\dfs\入口\dir\file`, `\mid\dfs\入口`, `\hop\dfs\出口`, dfsc.ReferralHeaderServers},
			{4, `\hop\dfs\出口\dir\file`, `\hop\dfs\出口`, `\storage\files\base`, dfsc.ReferralHeaderStorage},
		} {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			packet := smb2.PacketCodec(req)
			if packet.Command() != smb2.SMB2_IOCTL || packet.TreeId() != step.tree {
				t.Errorf("referral routed to command=%v tree=%d, want IOCTL tree=%d", packet.Command(), packet.TreeId(), step.tree)
				return
			}
			ir := smb2.IoctlRequestDecoder(packet.Body())
			input := req[int(ir.InputOffset()) : int(ir.InputOffset())+int(ir.InputCount())]
			if got := utf16le.DecodeToString(input[2:]); got != step.path {
				t.Errorf("query path=%q, want %q", got, step.path)
			}
			response := makeDFSReferralV3(step.prefix, step.target)
			binary.LittleEndian.PutUint32(response[4:8], step.flags)
			sendDFSResponse(dt, req, &smb2.IoctlResponse{CtlCode: smb2.FSCTL_DFS_GET_REFERRALS, FileId: smb2.RelatedFileId, Output: rawEncoder(response)}, 0, step.tree)
		}
	}()
	for range 2 {
		route, err := d.Resolve(ctx, `\ns\root\link\dir\file`)
		if err != nil {
			t.Fatal(err)
		}
		if route.Tree.treeConn != target || route.Path != `\storage\files\base\dir\file` || route.Name != `base\dir\file` {
			t.Fatalf("resolved route=%+v", route)
		}
	}
	<-done
}

// newTestDFSResolver supplies referral packets over a separate SMB connection,
// while target I/O uses the provided trees. It does not access resolver internals.
func newTestDFSResolver(t *testing.T, trees map[string]*treeConn, referrals map[string][]byte) *dfsc.Resolver[*dfsTree] {
	t.Helper()
	fs, server := newTestShare(t)
	go func() {
		dt := direct(server)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			ir := smb2.IoctlRequestDecoder(smb2.PacketCodec(req).Body())
			input := req[int(ir.InputOffset()) : int(ir.InputOffset())+int(ir.InputCount())]
			path := utf16le.DecodeToString(input[2:])
			payload, found := referrals[path]
			if !found {
				t.Errorf("unexpected referral query %q", path)
				sendDFSResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND), fs.treeId)
				continue
			}
			sendDFSResponse(dt, req, &smb2.IoctlResponse{CtlCode: smb2.FSCTL_DFS_GET_REFERRALS, FileId: smb2.RelatedFileId, Output: rawEncoder(payload)}, 0, fs.treeId)
		}
	}()
	return dfsc.NewResolver("ns", "root", func(_ context.Context, server, share string) (*dfsTree, error) {
		if tree := trees[strings.ToLower(server+`\`+share)]; tree != nil {
			return &dfsTree{treeConn: tree}, nil
		}
		if server == "ns" && share == "IPC$" {
			return &dfsTree{treeConn: fs.treeConn}, nil
		}
		return nil, errors.New("unexpected DFS connection: " + server + `\` + share)
	})
}

func TestDFSTreeCloseReleasesSessionAfterDisconnectError(t *testing.T) {
	fs, server := newTestShare(t)
	client := &Client{sessions: make(map[string]*clientSessionEntry), connecting: make(map[string]*sessionConnect)}
	entry := &clientSessionEntry{key: "server", refs: 1}
	owner := &clientSession{s: fs.session, addr: "server", client: client, entry: entry}
	entry.sess = owner
	client.sessions[entry.key] = entry
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(server)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			switch command := smb2.PacketCodec(req).Command(); command {
			case smb2.SMB2_TREE_CONNECT:
				sendTestResponse(dt, req, &smb2.TreeConnectResponse{}, 0)
			case smb2.SMB2_TREE_DISCONNECT:
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: command}, uint32(erref.STATUS_ACCESS_DENIED))
			case smb2.SMB2_LOGOFF:
				sendTestResponse(dt, req, &smb2.LogoffResponse{}, 0)
				return
			default:
				t.Errorf("unexpected command: %v", command)
				return
			}
		}
	}()
	tree, err := connectDFSTree(context.Background(), owner, "server", "server", "share")
	if err != nil {
		t.Fatal(err)
	}
	if entry.refs != 2 {
		t.Fatalf("refs after connect = %d, want 2", entry.refs)
	}
	if err := tree.Close(context.Background()); !errors.Is(err, erref.STATUS_ACCESS_DENIED) {
		t.Fatalf("Close = %v, want access denied", err)
	}
	if entry.refs != 1 || entry.closed {
		t.Fatalf("closing DFS tree changed other ownership: %+v", entry)
	}
	if err := client.closeSession(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	<-done
	if entry.refs != 0 || !entry.closed {
		t.Fatalf("final ownership not released: %+v", entry)
	}
}
