package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestTreeConn_SendRecv_CollectsSubsequentErrorsAfterFailure(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &Tree{session: s, treeId: 1}

	// 3-command compound request: CREATE + READ + CLOSE
	req0 := &wire.CreateRequest{Name: "test.txt"}
	req1 := &wire.ReadRequest{Length: 64}
	req2 := &wire.CloseRequest{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := NewTransport(serverConn)
		// Read compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)

		// A related compound request returns a response for every operation,
		// including the operations that follow the CREATE failure.
		responses := []struct {
			command wire.Command
			status  erref.NtStatus
		}{
			{wire.SMB2_CREATE, erref.STATUS_OBJECT_NAME_NOT_FOUND},
			{wire.SMB2_READ, erref.STATUS_INVALID_PARAMETER},
			{wire.SMB2_CLOSE, erref.STATUS_INVALID_PARAMETER},
		}
		for i, Response := range responses {
			resp := make([]byte, 64+8)
			binary.LittleEndian.PutUint16(resp[64:66], 9)
			rp := wire.PacketCodec(resp)
			rp.SetProtocolId()
			rp.SetStructureSize()
			rp.SetCommand(Response.command)
			rp.SetStatus(uint32(Response.status))
			flags := uint32(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			if i > 0 {
				flags |= wire.SMB2_FLAGS_RELATED_OPERATIONS
			}
			rp.SetFlags(flags)
			rp.SetMessageId(p.MessageId() + uint64(i))
			rp.SetCreditResponse(1)
			rp.SetSessionId(0x1234)
			rp.SetTreeId(p.TreeId())
			if _, err := st.writev(resp); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c.account.m.Lock()
	initialAvailable := c.account.availableCredits
	c.account.m.Unlock()

	start := time.Now()
	res, err := tc.Request().Append(req0, req1, req2).Do(ctx)
	elapsed := time.Since(start)

	require.Nil(t, res)
	require.Error(t, err)
	// It should fail fast without waiting for ctx timeout (which is 2s)
	require.Less(t, elapsed, 1*time.Second)

	var cerr *CompoundResponseError
	require.ErrorAs(t, err, &cerr)
	require.Equal(t, 3, len(cerr.Errors))
	require.NotNil(t, cerr.OpError(0))
	var rerr *ResponseError
	require.ErrorAs(t, cerr.OpError(0), &rerr)
	require.Equal(t, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND), rerr.Code)

	// outstanding requests should be cleaned up (no lingering op 1 or op 2)
	c.outstandingRequests.m.Lock()
	numOutstanding := len(c.outstandingRequests.requests)
	c.outstandingRequests.m.Unlock()
	require.Equal(t, 0, numOutstanding)

	// in-flight credits should be refunded to 0
	c.account.m.Lock()
	inFlight := c.account.inFlightCredits
	c.account.m.Unlock()
	require.Equal(t, uint16(0), inFlight)

	// abandoned requests' credits should be fully returned: the available
	// credit balance must be restored to the pre-request value with no leak
	c.account.m.Lock()
	available := c.account.availableCredits
	c.account.m.Unlock()
	require.Equal(t, initialAvailable, available)

	<-done
}

func TestTreeCreateWirePathAndFlags(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		isDFSShare bool
		shareFlags uint32
		wantName   string
		wantDFS    bool
	}{
		{"capability only", true, wire.SMB2_SHAREFLAG_DFS_ROOT, `\server\namespace\folder\файл`, true},
		{"share flags only", false, wire.SMB2_SHAREFLAG_DFS_ROOT, `folder\файл`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			s.enableSession()
			tc := &Tree{
				session:    s,
				treeId:     7,
				shareFlags: test.shareFlags,
				isDFSShare: test.isDFSShare,
				serverName: "server",
				shareName:  "namespace",
			}
			result := make(chan struct {
				name  string
				flags uint32
				err   error
			}, 1)
			go func() {
				st := NewTransport(serverConn)
				request, err := readMsg(st)
				if err != nil {
					result <- struct {
						name  string
						flags uint32
						err   error
					}{err: err}
					return
				}
				p := wire.PacketCodec(request)
				create := wire.CreateRequestDecoder(p.Body())
				if create.IsInvalid() {
					result <- struct {
						name  string
						flags uint32
						err   error
					}{err: fmt.Errorf("invalid CREATE request")}
					return
				}
				nameStart := int(create.NameOffset())
				nameEnd := nameStart + int(create.NameLength())
				if nameStart < 64 || nameEnd > len(request) {
					result <- struct {
						name  string
						flags uint32
						err   error
					}{err: fmt.Errorf("CREATE name outside packet")}
					return
				}
				sendTestResponse(st, request, &wire.CreateResponse{
					CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{},
					LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{},
					FileId: wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}, uint32(erref.STATUS_SUCCESS))
				result <- struct {
					name  string
					flags uint32
					err   error
				}{name: utf16le.DecodeToString(request[nameStart:nameEnd]), flags: p.Flags()}
			}()

			res, err := tc.Request().Create(`folder\файл`, wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).Do(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			res.Close()
			got := <-result
			if got.err != nil || got.name != test.wantName {
				t.Fatalf("CREATE = (%q, %v), want %q", got.name, got.err, test.wantName)
			}
			if (got.flags&wire.SMB2_FLAGS_DFS_OPERATIONS != 0) != test.wantDFS {
				t.Fatalf("DFS flag = %#x, want %v", got.flags, test.wantDFS)
			}
		})
	}
}

func TestTreeConn_SendRecv_MiddleCommandFailureAutoClosesFile(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &Tree{session: s, treeId: 1}

	req0 := &wire.CreateRequest{Name: "test.txt"}
	req1 := &wire.ReadRequest{Length: 64}
	req2 := &wire.CloseRequest{}

	var receivedCommands []wire.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := NewTransport(serverConn)
		// 1. Read compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		// Server responds to op 0 (Create SUCCESS), op 1 (Read ACCESS_DENIED),
		// and op 2 (Close STATUS_ACCESS_DENIED).
		createRes := &wire.CreateResponse{
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
			FileId: wire.FileId{
				Persistent: [8]byte{1, 2, 3, 4},
				Volatile:   [8]byte{5, 6, 7, 8},
			},
		}
		resp0 := make([]byte, wire.Roundup(createRes.Size(), 8))
		createRes.Encode(resp0)
		rp0 := wire.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetCommand(wire.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(uint32(len(resp0)))

		resp1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp1[64:66], 9)
		rp1 := wire.PacketCodec(resp1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(wire.SMB2_READ)
		rp1.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetCreditResponse(1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := wire.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(wire.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetCreditResponse(1)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, resp1...)
		allResp = append(allResp, resp2...)
		_, _ = st.writev(allResp)

		// 2. Since op 0 succeeded but op 1 failed and op 2's CLOSE failed,
		// requestBuilder.sendRecv MUST auto-close the opened file.
		closeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pClose := wire.PacketCodec(closeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pClose.Command())
		mu.Unlock()

		// Respond to auto-close
		closeResp := make([]byte, 64+60)
		binary.LittleEndian.PutUint16(closeResp[64:66], 60)
		rpClose := wire.PacketCodec(closeResp)
		rpClose.SetProtocolId()
		rpClose.SetStructureSize()
		rpClose.SetCommand(wire.SMB2_CLOSE)
		rpClose.SetStatus(uint32(erref.STATUS_SUCCESS))
		rpClose.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rpClose.SetMessageId(pClose.MessageId())
		rpClose.SetCreditResponse(1)
		rpClose.SetSessionId(0x1234)
		rpClose.SetTreeId(pClose.TreeId())
		_, _ = st.writev(closeResp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	res, err := tc.Request().Append(req0, req1, req2).Do(ctx)
	elapsed := time.Since(start)

	require.Nil(t, res)
	require.Error(t, err)
	require.Less(t, elapsed, 1*time.Second)

	var cerr *CompoundResponseError
	require.ErrorAs(t, err, &cerr)
	require.Nil(t, cerr.OpError(0))
	require.NotNil(t, cerr.OpError(1))

	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_CLOSE}, receivedCommands)
}

func TestTreeConn_SendRecv_MiddleCommandFailureKeepsSuccessfulClose(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()

		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		s := &session{conn: c, sessionId: 0x1234}
		c.session = s
		c.enableSession()
		tc := &Tree{session: s, treeId: 1}

		createReq := &wire.CreateRequest{Name: "test.txt"}
		readReq := &wire.ReadRequest{Length: 64}
		closeReq := &wire.CloseRequest{}

		extraClose := make(chan bool, 1)
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			st := NewTransport(serverConn)
			reqBuf, err := readMsg(st)
			if err != nil {
				return
			}
			p := wire.PacketCodec(reqBuf)

			createRes := &wire.CreateResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
				FileId: wire.FileId{
					Persistent: [8]byte{1, 2, 3, 4},
					Volatile:   [8]byte{5, 6, 7, 8},
				},
			}
			resp0 := make([]byte, wire.Roundup(createRes.Size(), 8))
			createRes.Encode(resp0)
			rp0 := wire.PacketCodec(resp0)
			rp0.SetProtocolId()
			rp0.SetCommand(wire.SMB2_CREATE)
			rp0.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp0.SetMessageId(p.MessageId())
			rp0.SetCreditResponse(1)
			rp0.SetSessionId(0x1234)
			rp0.SetTreeId(p.TreeId())
			rp0.SetNextCommand(uint32(len(resp0)))

			resp1 := make([]byte, 64+8)
			binary.LittleEndian.PutUint16(resp1[64:66], 9)
			rp1 := wire.PacketCodec(resp1)
			rp1.SetProtocolId()
			rp1.SetStructureSize()
			rp1.SetCommand(wire.SMB2_READ)
			rp1.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
			rp1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
			rp1.SetMessageId(p.MessageId() + 1)
			rp1.SetCreditResponse(1)
			rp1.SetSessionId(0x1234)
			rp1.SetTreeId(p.TreeId())
			rp1.SetNextCommand(uint32(len(resp1)))

			resp2 := make([]byte, 64+60)
			binary.LittleEndian.PutUint16(resp2[64:66], 60)
			rp2 := wire.PacketCodec(resp2)
			rp2.SetProtocolId()
			rp2.SetStructureSize()
			rp2.SetCommand(wire.SMB2_CLOSE)
			rp2.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
			rp2.SetMessageId(p.MessageId() + 2)
			rp2.SetCreditResponse(1)
			rp2.SetSessionId(0x1234)
			rp2.SetTreeId(p.TreeId())

			allResp := append(resp0, resp1...)
			allResp = append(allResp, resp2...)
			if _, err := st.writev(allResp); err != nil {
				return
			}

			_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			extra, err := st.readPacket()
			if err == nil {
				extra.close()
				extraClose <- true
				return
			}
			extraClose <- false
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		res, err := tc.Request().Append(createReq, readReq, closeReq).Do(ctx)
		require.Nil(t, res)
		require.Error(t, err)

		<-serverDone
		require.False(t, <-extraClose, "successful compound CLOSE must not trigger an additional CLOSE")
	})
}

func TestTreeConnEncryptionPolicyIsStoredForCancel(t *testing.T) {
	t.Parallel()
	for _, policy := range []string{"session", "share"} {
		t.Run(policy, func(t *testing.T) {
			require := require.New(t)
			mt := &countingWriteTransport{}
			c := &conn{
				t:                   mt,
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(1),
			}
			s := &session{
				conn:      c,
				sessionId: 0xCAFE,
				encrypter: newGCM(make([]byte, 16)),
			}
			c.session = s
			tc := &Tree{session: s}
			if policy == "session" {
				s.sessionFlags = wire.SMB2_SESSION_FLAG_ENCRYPT_DATA
			} else {
				tc.shareFlags = wire.SMB2_SHAREFLAG_ENCRYPT_DATA
			}

			rrs, err := tc.send(context.Background(), &wire.EchoRequest{})
			require.NoError(err)
			require.Len(rrs, 1)
			require.True(rrs[0].requireEncryption)
		})
	}
}

func TestTreeCloseResponseFileClosesEveryUnreleasedCreate(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &Tree{session: s, treeId: 1}

	first := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
	second := wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	res := &Response{rpkts: []*recvPacket{
		testTreeResponsePacket(wire.SMB2_CREATE, erref.STATUS_SUCCESS, 0, testTreeCreateResponse(first)),
		testTreeResponsePacket(wire.SMB2_CREATE, erref.STATUS_SUCCESS, 1, testTreeCreateResponse(second)),
		testTreeResponsePacket(wire.SMB2_READ, erref.STATUS_ACCESS_DENIED, 2, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}),
	}}

	got := make(chan wire.FileId, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		st := NewTransport(serverConn)
		for range 2 {
			request, err := readMsg(st)
			if err != nil {
				return
			}
			decoded := wire.CloseRequestDecoder(wire.PacketCodec(request).Body()).FileId().Decode()
			got <- decoded
			sendTestCloseResponse(st, request)
		}
	}()

	tc.closeResponseFile([]wire.Packet{
		&wire.CreateRequest{Name: "first"},
		&wire.CreateRequest{Name: "second"},
		&wire.ReadRequest{Length: 1},
	}, res)
	res.Close()
	<-done

	if gotFirst, gotSecond := <-got, <-got; gotFirst != first || gotSecond != second {
		t.Fatalf("auto-closed handles = %#v, %#v; want %#v, %#v", gotFirst, gotSecond, first, second)
	}
}

func TestTreeCloseResponseFileFailedNewestCreateKeepsEarlierHandle(t *testing.T) {
	t.Parallel()
	first := wire.FileId{Persistent: [8]byte{21}, Volatile: [8]byte{22}}
	res := &Response{rpkts: []*recvPacket{
		testTreeResponsePacket(wire.SMB2_CREATE, erref.STATUS_SUCCESS, 0, testTreeCreateResponse(first)),
		testTreeResponsePacket(wire.SMB2_CREATE, erref.STATUS_ACCESS_DENIED, 1, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}),
		testTreeResponsePacket(wire.SMB2_READ, erref.STATUS_INVALID_HANDLE, 2, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}),
	}}
	runTreeCleanupCase(t, []wire.Packet{
		&wire.CreateRequest{Name: "first"},
		&wire.CreateRequest{Name: "newest"},
		&wire.ReadRequest{Length: 1},
	}, res, []wire.FileId{first})
}

func TestTreeCloseResponseFileExistingCloseFailureDoesNotRetry(t *testing.T) {
	t.Parallel()
	fd := wire.FileId{Persistent: [8]byte{31}, Volatile: [8]byte{32}}
	res := &Response{rpkts: []*recvPacket{
		testTreeResponsePacket(wire.SMB2_CLOSE, erref.STATUS_ACCESS_DENIED, 0, &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}),
	}}
	runTreeCleanupCase(t, []wire.Packet{&wire.CloseRequest{FileId: fd}}, res, nil)
}

func runTreeCleanupCase(t *testing.T, reqs []wire.Packet, res *Response, want []wire.FileId) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()
		s := &session{conn: c, sessionId: 0x1234}
		c.session = s
		c.enableSession()
		tc := &Tree{session: s, treeId: 1}

		if len(want) > 0 {
			go func() {
				st := NewTransport(serverConn)
				for range want {
					request, err := readMsg(st)
					if err != nil {
						return
					}
					sendTestCloseResponse(st, request)
				}
			}()
		} else {
			_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		tc.closeResponseFile(reqs, res)
		res.Close()
		if len(want) == 0 {
			st := NewTransport(serverConn)
			if _, err := readMsg(st); err == nil {
				t.Fatal("cleanup sent an unexpected CLOSE")
			}
		}
	})
}

func testTreeCreateResponse(id wire.FileId) *wire.CreateResponse {
	return &wire.CreateResponse{
		FileId:         id,
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}
}

func testTreeResponsePacket(command wire.Command, status erref.NtStatus, messageID uint64, body wire.Packet) *recvPacket {
	buf := make([]byte, wire.Roundup(body.Size(), 8))
	body.Encode(buf)
	p := wire.PacketCodec(buf)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(command)
	p.SetStatus(uint32(status))
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetMessageId(messageID)
	p.SetCreditResponse(1)
	p.SetSessionId(0x1234)
	p.SetTreeId(1)
	return &recvPacket{pkt: buf}
}

func TestTreeConnectCancellationReclaimsDelayedSuccess(t *testing.T) {
	t.Parallel()
	for _, cleanupTimeout := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanupTimeout=%v", cleanupTimeout), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testTreeConnectCancellationReclaimsDelayedSuccess(t, cleanupTimeout)
			})
		})
	}
}

func testTreeConnectCancellationReclaimsDelayedSuccess(t *testing.T, cleanupTimeout bool) {
	tc, peer := newTestTree(t)
	defer peer.Close()
	st := NewTransport(peer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tree, err := (&Session{s: tc.session}).TreeConnect(ctx, "server", "share", 0)
		if tree != nil {
			done <- fmt.Errorf("canceled TreeConnect returned a tree")
			return
		}
		done <- err
	}()
	request, err := readMsg(st)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_TREE_CONNECT, wire.PacketCodec(request).Command())
	cancel()
	cancellation, err := readMsg(st)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(cancellation).Command())
	require.Equal(t, wire.PacketCodec(request).MessageId(), wire.PacketCodec(cancellation).MessageId())
	const createdTreeID = 42
	response := &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_DISK}
	data := make([]byte, response.Size())
	response.Encode(data)
	p := wire.PacketCodec(data)
	p.SetTreeId(createdTreeID)
	p.SetSessionId(tc.sessionId)
	p.SetMessageId(wire.PacketCodec(request).MessageId())
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetCreditResponse(1)
	_, err = st.writev(data)
	require.NoError(t, err)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	disconnect, err := readMsg(st)
	require.NoError(t, err, "a delayed successful TREE_CONNECT must release its tree")
	require.Equal(t, wire.SMB2_TREE_DISCONNECT, wire.PacketCodec(disconnect).Command())
	require.EqualValues(t, createdTreeID, wire.PacketCodec(disconnect).TreeId())
	if cleanupTimeout {
		require.NoError(t, peer.SetReadDeadline(time.Time{}))
		time.Sleep(6 * time.Second)
		cleanupCancel, err := readMsg(st)
		require.NoError(t, err)
		require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(cleanupCancel).Command())
		cleanupErr := <-done
		require.ErrorIs(t, cleanupErr, context.Canceled)
		require.ErrorIs(t, cleanupErr, context.DeadlineExceeded)
		// Even a late cleanup response must not tear down the session.
		sendTestResponse(st, disconnect, &wire.TreeDisconnectResponse{}, 0)
	} else {
		sendTestResponse(st, disconnect, &wire.TreeDisconnectResponse{}, 0)
		require.ErrorIs(t, <-done, context.Canceled)
	}
	go func() { done <- tc.session.echo(context.Background()) }()
	echo, err := readMsg(st)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echo).Command(), "no duplicate disconnect; shared session remains usable")
	sendTestResponse(st, echo, &wire.EchoResponse{}, 0)
	require.NoError(t, <-done)
}

func TestTreeConnectCanceledWithoutCreatedTree(t *testing.T) {
	t.Parallel()
	for _, beforeSend := range []bool{false, true} {
		t.Run(fmt.Sprintf("beforeSend=%v", beforeSend), func(t *testing.T) {
			tc, peer := newTestTree(t)
			defer peer.Close()
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			st := NewTransport(peer)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if beforeSend {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				tree, err := (&Session{s: tc.session}).TreeConnect(ctx, "server", "share", 0)
				if tree != nil {
					done <- fmt.Errorf("canceled TreeConnect returned a tree")
					return
				}
				done <- err
			}()
			if !beforeSend {
				request, err := readMsg(st)
				require.NoError(t, err)
				require.Equal(t, wire.SMB2_TREE_CONNECT, wire.PacketCodec(request).Command())
				cancel()
				cancellation, err := readMsg(st)
				require.NoError(t, err)
				require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(cancellation).Command())
				sendTestResponse(st, request, &wire.ErrorResponse{CommandCode: wire.SMB2_TREE_CONNECT}, uint32(erref.STATUS_CANCELLED))
			}
			require.ErrorIs(t, <-done, context.Canceled)
			go func() { done <- tc.session.echo(context.Background()) }()
			echo, err := readMsg(st)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echo).Command(), "no TREE_DISCONNECT when no tree was created")
			sendTestResponse(st, echo, &wire.EchoResponse{}, 0)
			require.NoError(t, <-done)
		})
	}
}

func TestTreeConnectCancellationUnblocksOnConnectionClose(t *testing.T) {
	t.Parallel()
	tc, peer := newTestTree(t)
	defer peer.Close()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	st := NewTransport(peer)
	session := &Session{s: tc.session}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tree, err := session.TreeConnect(ctx, "server", "share", 0)
		if tree != nil {
			done <- fmt.Errorf("canceled TreeConnect returned a tree")
			return
		}
		done <- err
	}()
	request, err := readMsg(st)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_TREE_CONNECT, wire.PacketCodec(request).Command())
	cancel()
	cancellation, err := readMsg(st)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(cancellation).Command())
	require.NoError(t, session.Abort())
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("TreeConnect remained blocked after connection shutdown")
	}
}

func TestTreeConnectSuccessCancellationRace(t *testing.T) {
	t.Parallel()
	tc, peer := newTestTree(t)
	defer peer.Close()
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	st := NewTransport(peer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		tree *Tree
		err  error
	}
	done := make(chan result, 1)
	go func() {
		tree, err := (&Session{s: tc.session}).TreeConnect(ctx, "server", "share", 0)
		done <- result{tree, err}
	}()
	request, err := readMsg(st)
	require.NoError(t, err)
	response := &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_DISK}
	data := make([]byte, response.Size())
	response.Encode(data)
	p := wire.PacketCodec(data)
	p.SetTreeId(42)
	p.SetSessionId(tc.sessionId)
	p.SetMessageId(wire.PacketCodec(request).MessageId())
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetCreditResponse(1)
	serverDone := make(chan error, 1)
	go func() {
		if _, err := st.writev(data); err != nil {
			serverDone <- err
			return
		}
		disconnects := 0
		for {
			req, err := readMsg(st)
			if err != nil {
				serverDone <- err
				return
			}
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CANCEL:
			case wire.SMB2_TREE_DISCONNECT:
				disconnects++
				if p.TreeId() != 42 || disconnects != 1 {
					serverDone <- fmt.Errorf("disconnect tree=%d, count=%d", p.TreeId(), disconnects)
					return
				}
				sendTestResponse(st, req, &wire.TreeDisconnectResponse{}, 0)
			case wire.SMB2_ECHO:
				sendTestResponse(st, req, &wire.EchoResponse{}, 0)
				if disconnects != 1 {
					serverDone <- fmt.Errorf("disconnect count=%d", disconnects)
				} else {
					serverDone <- nil
				}
				return
			default:
				serverDone <- fmt.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}()
	cancel()
	r := <-done
	if r.err == nil {
		require.NotNil(t, r.tree)
		require.NoError(t, r.tree.Disconnect(context.Background()))
	} else {
		require.Nil(t, r.tree)
		require.ErrorIs(t, r.err, context.Canceled)
	}
	require.NoError(t, tc.session.echo(context.Background()))
	require.NoError(t, <-serverDone)
}

func TestShare_MaxPayloadSizeCappedByCredits(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// Initially, maxCredits = 1 -> capped to 1 * 64KB = 64KB
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))

	// Replenish to 4 credits (maxCreditBalance) -> capped to 4 * 64KB = 256KB
	c.account.charge(3)
	require.Equal(t, 256*1024, fs.MaxReadSize(0))
	require.Equal(t, 256*1024, fs.MaxWriteSize(0))
	require.Equal(t, 256*1024, fs.MaxTransactSize(0))

	// More credits allow the full server-advertised size.
	c.account.maxCreditBalance = 128
	c.account.charge(30)
	require.Equal(t, 1024*1024, fs.MaxReadSize(0))
	require.Equal(t, 1024*1024, fs.MaxWriteSize(0))
	require.Equal(t, 1024*1024, fs.MaxTransactSize(0))
}

func TestShare_MaxPayloadSizeLargeRequests(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		limit      uint32
		credits    uint16
		companions int
		largeMTU   bool
		want       int
	}{
		{"server limit", 2 * 1024 * 1024, 128, 0, true, 2 * 1024 * 1024},
		{"eight MiB", 8 * 1024 * 1024, 128, 0, true, 8 * 1024 * 1024},
		{"credit limit", 8 * 1024 * 1024, 32, 0, true, 2 * 1024 * 1024},
		{"compound credits", 8 * 1024 * 1024, 128, 2, true, 126 * 64 * 1024},
		{"single credit", 8 * 1024 * 1024, 128, 0, false, 64 * 1024},
		{"transport limit", math.MaxUint32, math.MaxUint16, 0, true, 255 * 64 * 1024},
		{"negative companions", 8 * 1024 * 1024, 128, math.MinInt, true, 8 * 1024 * 1024},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{account: openAccount(tt.credits), maxReadSize: tt.limit, maxWriteSize: tt.limit, maxTransactSize: tt.limit}
			c.account.charge(tt.credits - 1)
			if tt.largeMTU {
				c.capabilities = wire.SMB2_GLOBAL_CAP_LARGE_MTU
			}
			tree := &Tree{session: &session{conn: c}}
			require.Equal(t, tt.want, tree.MaxReadSize(tt.companions))
			require.Equal(t, tt.want, tree.MaxWriteSize(tt.companions))
			require.Equal(t, tt.want, tree.MaxTransactSize(tt.companions))
		})
	}
}

func TestShare_MaxPayloadSizeReservesCompoundCredits(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// Replenish to maxCreditBalance so the cap is 4 * 64KB.
	c.account.charge(3)

	// A standalone request may use the whole credit cap.
	require.Equal(t, 256*1024, fs.MaxReadSize(0))
	require.Equal(t, 256*1024, fs.MaxWriteSize(0))
	require.Equal(t, 256*1024, fs.MaxTransactSize(0))

	// A compound leaves room for its single-credit companions.
	require.Equal(t, 128*1024, fs.MaxWriteSize(2))
	require.Equal(t, 128*1024, fs.MaxTransactSize(2))
	require.Equal(t, 192*1024, fs.MaxTransactSize(1))

	// Sizing never drops below a single credit.
	require.Equal(t, 64*1024, fs.MaxTransactSize(8))
}

func TestShare_MaxPayloadSizeRespectsServerAdvertisedValues(t *testing.T) {
	t.Parallel()
	c := &conn{
		account:         openAccount(4),
		capabilities:    wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s := &session{conn: c}
	tc := &Tree{session: s}
	fs := tc

	// server advertises 32KB (< singleCreditMaxPayloadSize) -> respect it
	require.Equal(t, 32*1024, fs.MaxReadSize(0))
	require.Equal(t, 32*1024, fs.MaxWriteSize(0))
	require.Equal(t, 32*1024, fs.MaxTransactSize(0))

	// non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))

	// without LARGE_MTU, server-advertised sizes are still respected
	c = &conn{
		account:         openAccount(4),
		capabilities:    0,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s = &session{conn: c}
	tc = &Tree{session: s}
	fs = tc
	require.Equal(t, 32*1024, fs.MaxReadSize(0))
	require.Equal(t, 32*1024, fs.MaxWriteSize(0))
	require.Equal(t, 32*1024, fs.MaxTransactSize(0))

	// without LARGE_MTU, non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.MaxReadSize(0))
	require.Equal(t, 64*1024, fs.MaxWriteSize(0))
	require.Equal(t, 64*1024, fs.MaxTransactSize(0))
}
