package smb2

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestTreeConn_SendRecv_CollectsSubsequentErrorsAfterFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}

	// 3-command compound request: CREATE + READ + CLOSE
	req0 := &smb2.CreateRequest{Name: "test.txt"}
	req1 := &smb2.ReadRequest{Length: 64}
	req2 := &smb2.CloseRequest{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		// Read compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)

		// A related compound request returns a response for every operation,
		// including the operations that follow the CREATE failure.
		responses := []struct {
			command smb2.Command
			status  erref.NtStatus
		}{
			{smb2.SMB2_CREATE, erref.STATUS_OBJECT_NAME_NOT_FOUND},
			{smb2.SMB2_READ, erref.STATUS_INVALID_PARAMETER},
			{smb2.SMB2_CLOSE, erref.STATUS_INVALID_PARAMETER},
		}
		for i, response := range responses {
			resp := make([]byte, 64+8)
			binary.LittleEndian.PutUint16(resp[64:66], 9)
			rp := smb2.PacketCodec(resp)
			rp.SetProtocolId()
			rp.SetStructureSize()
			rp.SetCommand(response.command)
			rp.SetStatus(uint32(response.status))
			flags := uint32(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			if i > 0 {
				flags |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
			}
			rp.SetFlags(flags)
			rp.SetMessageId(p.MessageId() + uint64(i))
			rp.SetCreditResponse(1)
			rp.SetSessionId(0x1234)
			rp.SetTreeId(p.TreeId())
			if _, err := st.Writev(resp); err != nil {
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
	res, err := tc.request().add(req0).add(req1).add(req2).sendRecv(ctx)
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

func TestTreeConn_SendRecv_MiddleCommandFailureAutoClosesFile(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}

	req0 := &smb2.CreateRequest{Name: "test.txt"}
	req1 := &smb2.ReadRequest{Length: 64}
	req2 := &smb2.CloseRequest{}

	var receivedCommands []smb2.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		// 1. Read compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		// Server responds to op 0 (Create SUCCESS), op 1 (Read ACCESS_DENIED),
		// and op 2 (Close STATUS_ACCESS_DENIED).
		createRes := &smb2.CreateResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			FileId: &smb2.FileId{
				Persistent: [8]byte{1, 2, 3, 4},
				Volatile:   [8]byte{5, 6, 7, 8},
			},
		}
		resp0 := make([]byte, smb2.Roundup(createRes.Size(), 8))
		createRes.Encode(resp0)
		rp0 := smb2.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetCommand(smb2.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(uint32(len(resp0)))

		resp1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp1[64:66], 9)
		rp1 := smb2.PacketCodec(resp1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_READ)
		rp1.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetCreditResponse(1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := smb2.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetCreditResponse(1)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, resp1...)
		allResp = append(allResp, resp2...)
		_, _ = st.Writev(allResp)

		// 2. Since op 0 succeeded but op 1 failed and op 2's CLOSE failed,
		// requestBuilder.sendRecv MUST auto-close the opened file.
		closeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pClose := smb2.PacketCodec(closeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pClose.Command())
		mu.Unlock()

		// Respond to auto-close
		closeResp := make([]byte, 64+60)
		binary.LittleEndian.PutUint16(closeResp[64:66], 60)
		rpClose := smb2.PacketCodec(closeResp)
		rpClose.SetProtocolId()
		rpClose.SetStructureSize()
		rpClose.SetCommand(smb2.SMB2_CLOSE)
		rpClose.SetStatus(uint32(erref.STATUS_SUCCESS))
		rpClose.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rpClose.SetMessageId(pClose.MessageId())
		rpClose.SetCreditResponse(1)
		rpClose.SetSessionId(0x1234)
		rpClose.SetTreeId(pClose.TreeId())
		_, _ = st.Writev(closeResp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	res, err := tc.request().add(req0).add(req1).add(req2).sendRecv(ctx)
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
	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CLOSE}, receivedCommands)
}

func TestTreeConn_SendRecv_MiddleCommandFailureKeepsSuccessfulClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}

	createReq := &smb2.CreateRequest{Name: "test.txt"}
	readReq := &smb2.ReadRequest{Length: 64}
	closeReq := &smb2.CloseRequest{}

	extraClose := make(chan bool, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)

		createRes := &smb2.CreateResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			FileId: &smb2.FileId{
				Persistent: [8]byte{1, 2, 3, 4},
				Volatile:   [8]byte{5, 6, 7, 8},
			},
		}
		resp0 := make([]byte, smb2.Roundup(createRes.Size(), 8))
		createRes.Encode(resp0)
		rp0 := smb2.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetCommand(smb2.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(uint32(len(resp0)))

		resp1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp1[64:66], 9)
		rp1 := smb2.PacketCodec(resp1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_READ)
		rp1.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetCreditResponse(1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+60)
		binary.LittleEndian.PutUint16(resp2[64:66], 60)
		rp2 := smb2.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetCreditResponse(1)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())

		allResp := append(resp0, resp1...)
		allResp = append(allResp, resp2...)
		if _, err := st.Writev(allResp); err != nil {
			return
		}

		_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		extra, err := st.ReadPacket()
		if err == nil {
			extra.close()
			extraClose <- true
			return
		}
		extraClose <- false
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := tc.request().add(createReq).add(readReq).add(closeReq).sendRecv(ctx)
	require.Nil(t, res)
	require.Error(t, err)

	<-serverDone
	require.False(t, <-extraClose, "successful compound CLOSE must not trigger an additional CLOSE")
}

func TestTreeConnEncryptionPolicyIsStoredForCancel(t *testing.T) {
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
			tc := &treeConn{session: s}
			if policy == "session" {
				s.sessionFlags = smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA
			} else {
				tc.shareFlags = smb2.SMB2_SHAREFLAG_ENCRYPT_DATA
			}

			rrs, err := tc.send(context.Background(), &smb2.EchoRequest{})
			require.NoError(err)
			require.Len(rrs, 1)
			require.True(rrs[0].requireEncryption)
		})
	}
}
