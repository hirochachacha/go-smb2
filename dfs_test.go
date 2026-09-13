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

func TestDFSCacheLongestComponentPrefix(t *testing.T) {
	d := newDFSState(&clientSession{}, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	now := time.Now().Add(time.Minute)
	d.cache[`\ns\root`] = &dfsCacheEntry{prefix: `\ns\root`, cacheable: true, ttl: now, targets: []dfsTarget{{unc: `\\one\share`}}}
	d.cache[`\ns\root\foo`] = &dfsCacheEntry{prefix: `\ns\root\foo`, cacheable: true, ttl: now, targets: []dfsTarget{{unc: `\\two\share`}}}
	if got := d.find(`\NS\ROOT\foo\file`); got == nil || got.targets[0].unc != `\\two\share` {
		t.Fatalf("longest prefix = %#v", got)
	}
	if got := d.find(`\ns\root\foobar\file`); got == nil || got.targets[0].unc != `\\one\share` {
		t.Fatalf("component boundary = %#v", got)
	}
	d.cache[`\ns\root\foo`] = &dfsCacheEntry{prefix: `\ns\root\foo`, cacheable: true, ttl: time.Now().Add(-time.Second), targets: []dfsTarget{{unc: `\\two\share`}}}
	if got := d.find(`\ns\root\foo\file`); got == nil || got.targets[0].unc != `\\one\share` {
		t.Fatalf("expired prefix = %#v", got)
	}
}

func TestDFSPathSuffixIsCaseInsensitiveAndComponentBounded(t *testing.T) {
	if got := dfsPathSuffix(`\NS\ROOT\Link\file`, `\ns\root\link`); got != `\file` {
		t.Fatalf("suffix = %q", got)
	}
	if got := dfsPathSuffix(`\ns\root\foobar\file`, `\ns\root\foo`); got != "" {
		t.Fatalf("non-component suffix = %q", got)
	}
}

func TestDFSTargetOrderPreservesTargetSets(t *testing.T) {
	targets := []dfsTarget{{boundary: true}, {}, {boundary: true}, {}}
	got := dfsTargetOrder(targets, 1)
	want := []int{1, 0, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestDFSTargetTreesAreSharedByServerAndShare(t *testing.T) {
	tc := &treeConn{}
	d := newDFSState(&clientSession{}, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	d.targetTrees[dfsTreeKey("server", "share")] = tc
	e := &dfsCacheEntry{targets: []dfsTarget{{unc: `\\server\share\other-base`}}}
	got, base, err := d.target(context.Background(), e)
	if err != nil || got != tc || base != "other-base" {
		t.Fatalf("target = %p, %q, %v; want %p, %q, nil", got, base, err, tc, "other-base")
	}
}

func TestDFSTargetFallsBackAndUpdatesHint(t *testing.T) {
	tc := &treeConn{}
	d := newDFSState(&clientSession{}, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	d.targetTrees[dfsTreeKey("ns", "share")] = tc
	e := &dfsCacheEntry{targets: []dfsTarget{
		{unc: `invalid`},
		{unc: `\\ns\share\base`},
	}}
	got, base, err := d.target(context.Background(), e)
	if err != nil || got != tc || base != "base" || e.hint != 1 {
		t.Fatalf("fallback = %p, %q, hint %d, %v", got, base, e.hint, err)
	}
}

func TestDFSClientReceivesReferralServer(t *testing.T) {
	var called string
	wantErr := errors.New("dial failed")
	client, err := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &NTLMInitiator{}, nil
		}),
		Transport: func(_ context.Context, server string) (Transport, error) {
			called = server
			return nil, wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := &clientSession{client: client}
	d := newDFSState(owner, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	_, _, err = d.target(context.Background(), &dfsCacheEntry{targets: []dfsTarget{{unc: `\\files.example.com\share`}}})
	if !errors.Is(err, wantErr) || called != "files.example.com" {
		t.Fatalf("Client called with %q, err %v", called, err)
	}
}

func TestDFSRenameRejectsDifferentTargetTrees(t *testing.T) {
	d := newDFSState(&clientSession{}, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	now := time.Now().Add(time.Minute)
	d.cache[`\ns\root\old`] = &dfsCacheEntry{prefix: `\ns\root\old`, cacheable: true, ttl: now, targets: []dfsTarget{{unc: `\\one\share`}}}
	d.cache[`\ns\root\new`] = &dfsCacheEntry{prefix: `\ns\root\new`, cacheable: true, ttl: now, targets: []dfsTarget{{unc: `\\two\share`}}}
	d.targetTrees[dfsTreeKey("one", "share")] = &treeConn{}
	d.targetTrees[dfsTreeKey("two", "share")] = &treeConn{}
	fs := &Share{treeConn: &treeConn{}, dfs: d}
	if err := fs.Rename(context.Background(), `old\file`, `new\file`); err == nil {
		t.Fatal("cross-target DFS rename was accepted")
	}
}

func TestDFSRoutedCreateRejectsOversizedLogicalPath(t *testing.T) {
	d := newDFSState(&clientSession{}, strings.Repeat("s", 100), "root", smb2.SMB2_SHAREFLAG_DFS)
	fs := &Share{treeConn: &treeConn{}, dfs: d}
	name := strings.Repeat("a", 32720)
	if _, err := fs.sendRouted(context.Background(), &smb2.CreateRequest{Name: name}); err == nil {
		t.Fatal("oversized logical DFS path was accepted")
	}
}

func TestDFSReferralV1IsNotCached(t *testing.T) {
	d := newDFSState(&clientSession{}, "ns", "root", smb2.SMB2_SHAREFLAG_DFS)
	r := &dfsc.ReferralResponse{PathConsumed: 12, Entries: []dfsc.ReferralEntry{{Version: 1, NetworkAddress: `\\server\share`}}}
	e, err := d.put(r, `\ns\root`)
	if err != nil || e == nil || e.cacheable {
		t.Fatalf("V1 cache entry = %#v, %v", e, err)
	}
	if d.find(`\ns\root\file`) != nil {
		t.Fatal("V1 referral unexpectedly reusable")
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
	owner := &clientSession{s: s}
	d := newDFSState(owner, "ns", "root", smb2.SMB2_SHAREFLAG_DFS_ROOT)
	d.setLogicalTree(base)
	d.cache[`\ns\root\link`] = &dfsCacheEntry{prefix: `\ns\root\link`, cacheable: true, ttl: time.Now().Add(time.Minute), targets: []dfsTarget{{unc: `\\target\share\dir`}}}
	d.targetTrees[dfsTreeKey("target", "share")] = target
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
	d := newDFSState(owner, "ns", "root", smb2.SMB2_SHAREFLAG_DFS_ROOT)
	d.setLogicalTree(base)
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
