package smb2

import (
	"context"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestDialClosesConnectionOnSessionSetupError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Round 1: server replies to Negotiate request with success
		buf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB210,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		if _, err := st.Writev(respBuf); err != nil {
			return
		}

		// Round 2: read SessionSetup request then close serverConn to simulate network/auth failure
		if _, err := readMsg(st); err != nil {
			return
		}
		_ = serverConn.Close()
	}()

	d := &dialer{
		Initiator: &NTLMInitiator{
			User:     "user",
			Password: "password",
		},
	}

	_, err := d.DialContext(context.Background(), clientConn)
	require.Error(t, err)

	// clientConn must be closed on sessionSetup failure
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(t, readErr, "clientConn should be closed after failed sessionSetup")
}
