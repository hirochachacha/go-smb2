package smb2

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestTreeConn_SendRecv_AbandonSubsequentRequestsOnFailure(t *testing.T) {
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

		// Server halts on error and responds ONLY to op 0 (Create) with STATUS_OBJECT_NAME_NOT_FOUND.
		// It does NOT send any response for op 1 or op 2.
		resp0 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp0[64:66], 9)
		rp0 := smb2.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetStructureSize()
		rp0.SetCommand(smb2.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		rp0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(0)

		_, _ = st.Writev(resp0)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c.account.m.Lock()
	initialAvailable := c.account.availableCredits
	c.account.m.Unlock()

	start := time.Now()
	res, err := tc.sendRecv(ctx, req0, req1, req2)
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

		// Server responds to op 0 (Create SUCCESS) and op 1 (Read ACCESS_DENIED).
		// Server halts and does NOT send op 2 (Close).
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
		rp1.SetNextCommand(0)

		allResp := append(resp0, resp1...)
		_, _ = st.Writev(allResp)

		// 2. Since op 0 succeeded but op 1 failed and op 2 was abandoned,
		// treeConn.sendRecv MUST auto-close the opened file.
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
	res, err := tc.sendRecv(ctx, req0, req1, req2)
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
