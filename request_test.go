package smb2

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestMakeOutstandingCompoundRequest(t *testing.T) {
	req := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)

	req1 := &smb2.CreateRequest{
		DesiredAccess: smb2.DELETE,
	}

	req2 := &smb2.CloseRequest{}

	reqs := []smb2.Packet{req1, req2}

	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)

	rrs, pkt, err := c.makeOutstandingRequest(context.Background(), msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, 2)
	req.Equal(uint64(0), rrs[0].msgId)
	req.Equal(uint64(1), rrs[1].msgId)

	// Check NextCommand alignment in header
	p1 := smb2.PacketCodec(pkt)
	req.Equal(smb2.SMB2_CREATE, p1.Command())
	req.Equal(uint64(0), p1.MessageId())
	req.True(p1.NextCommand() > 0)
	req.Equal(uint32(0), p1.NextCommand()&7) // 8-byte aligned

	nextOff := p1.NextCommand()
	p2 := smb2.PacketCodec(pkt[nextOff:])
	req.Equal(smb2.SMB2_CLOSE, p2.Command())
	req.Equal(uint64(1), p2.MessageId())
	req.Equal(uint32(0), p2.NextCommand())
	req.True(p2.Flags()&smb2.SMB2_FLAGS_RELATED_OPERATIONS != 0)
}

func TestCompoundBuilderIntegration(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}

	// Mock server reading compound request and responding with compound response
	go func() {
		dt := direct(serverConn)
		size, err := dt.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, size)
		_, err = dt.Read(reqBuf)
		if err != nil {
			return
		}

		p1 := smb2.PacketCodec(reqBuf)

		// Build compound response: Response 1 (CREATE, 64 header + 88 body = 152 bytes, aligned to 160)
		res1 := make([]byte, 160)
		rp1 := smb2.PacketCodec(res1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_CREATE)
		rp1.SetMessageId(p1.MessageId())
		rp1.SetSessionId(p1.SessionId())
		rp1.SetTreeId(p1.TreeId())
		rp1.SetNextCommand(160)
		binary.LittleEndian.PutUint16(res1[64:66], 89) // CreateResponse structure size

		// Response 2 (CLOSE, 64 header + 60 body = 124 bytes)
		res2 := make([]byte, 124)
		rp2 := smb2.PacketCodec(res2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetMessageId(p1.MessageId() + 1)
		rp2.SetSessionId(p1.SessionId())
		rp2.SetTreeId(p1.TreeId())
		rp2.SetNextCommand(0)
		binary.LittleEndian.PutUint16(res2[64:66], 60) // CloseResponse structure size

		compoundResp := append(res1, res2...)
		direct(serverConn).Write(compoundResp)
	}()

	go c.runReciever()

	cReq := &smb2.CreateRequest{DesiredAccess: smb2.DELETE}
	clsReq := &smb2.CloseRequest{}

	res, err := tc.request().
		add(cReq).
		add(clsReq).
		sendRecv(context.Background())

	req.NoError(err)
	defer res.close()
	req.NotNil(res.get(0))
	req.NotNil(res.get(1))
	req.Equal(smb2.SMB2_CREATE, res.get(0).packetCodec().Command())
	req.Equal(smb2.SMB2_CLOSE, res.get(1).packetCodec().Command())
}
