package smb2

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/spnego"
	"github.com/stretchr/testify/require"
)

// installTrackingRecvBufPool temporarily replaces the global receive buffer
// pool with a pool that records every buffer it creates. The returned
// function yields the tracked buffers so tests can assert that sessionSetup
// released all of them (refCount back to 0) instead of leaking.
func installTrackingRecvBufPool(t *testing.T) (trackedBufs func() []*recvBuf) {
	t.Helper()

	origPool := recvBufPool

	var mu sync.Mutex
	var bufs []*recvBuf

	recvBufPool = sync.Pool{
		New: func() interface{} {
			buf := &recvBuf{data: make([]byte, 0, singleCreditMaxPayloadSize)}
			mu.Lock()
			bufs = append(bufs, buf)
			mu.Unlock()
			return buf
		},
	}
	t.Cleanup(func() { recvBufPool = origPool })

	return func() []*recvBuf {
		mu.Lock()
		defer mu.Unlock()
		return append([]*recvBuf(nil), bufs...)
	}
}

// requireAllRecvBufsReleased asserts that every pooled buffer allocated
// during the test was closed, i.e. handed back to the pool.
func requireAllRecvBufsReleased(t *testing.T, trackedBufs func() []*recvBuf) {
	t.Helper()

	require.Eventually(t, func() bool {
		bufs := trackedBufs()
		if len(bufs) == 0 {
			return false
		}
		for _, buf := range bufs {
			if buf.refCount.Load() != 0 {
				return false
			}
		}
		return true
	}, 2*time.Second, 5*time.Millisecond, "every pooled receive buffer must be released after sessionSetup returns")
}

// runFakeSessionSetupServer reads SESSION_SETUP requests and replies
// according to the given mode. For sessionSetupSuccess it performs a real
// NTLMv2 handshake backed by ntlmServer.
func runFakeSessionSetupServer(t transport, mode int, ntlmServer *ntlm.Server) {
	reqBuf := make([]byte, 4096)

	for round := 1; ; round++ {
		sz, err := t.ReadSize()
		if err != nil {
			return
		}
		if _, err := t.Read(reqBuf[:sz]); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf[:sz])
		if p.Command() != smb2.SMB2_SESSION_SETUP {
			return
		}
		req := smb2.SessionSetupRequestDecoder(reqBuf[64:sz])

		var status uint32
		var sessionFlags uint16
		var token []byte

		switch {
		case mode == sessionSetupServerGuestReject:
			// Intermediate response flagged as guest; the client rejects it
			// before touching the security buffer when signing is required.
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			sessionFlags = smb2.SMB2_SESSION_FLAG_IS_GUEST
		case mode == sessionSetupServerInvalidSecurityContext && round == 1:
			// Valid framing, but the security buffer is garbage so the SPNEGO
			// decoder fails on the client side.
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
			token = []byte{0xde, 0xad, 0xbe, 0xef}
		case mode == sessionSetupServerSuccess && round == 1:
			init, err := spnego.DecodeNegTokenInit(req.SecurityBuffer())
			if err != nil {
				return
			}
			cmsg, err := ntlmServer.Challenge(init.MechToken)
			if err != nil {
				return
			}
			token, err = spnego.EncodeNegTokenResp(1, spnego.NlmpOid, cmsg, nil)
			if err != nil {
				return
			}
			status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
		case mode == sessionSetupServerSuccess && round == 2:
			resp, err := spnego.DecodeNegTokenResp(req.SecurityBuffer())
			if err != nil {
				return
			}
			if err := ntlmServer.Authenticate(resp.ResponseToken); err != nil {
				return
			}
			status = uint32(erref.STATUS_SUCCESS)
		default:
			return
		}

		respBuf := make([]byte, 64+8+len(token))
		copy(respBuf[64+8:], token)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9)                  // StructureSize
		binary.LittleEndian.PutUint16(respBuf[66:68], sessionFlags)       // SessionFlags
		binary.LittleEndian.PutUint16(respBuf[68:70], 8+64)               // SecurityBufferOffset
		binary.LittleEndian.PutUint16(respBuf[70:72], uint16(len(token))) // SecurityBufferLength

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_SESSION_SETUP)
		rp.SetStatus(status)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(p.CreditRequest())
		rp.SetSessionId(0x1234)

		if _, err := t.Write(respBuf); err != nil {
			return
		}
	}
}

const (
	sessionSetupServerSuccess = iota
	sessionSetupServerGuestReject
	sessionSetupServerInvalidSecurityContext
)

func TestSessionSetupClosesInitialResponseBuffer(t *testing.T) {
	tests := []struct {
		name           string
		mode           int
		requireSigning bool
		wantErr        bool
		errorContains  string
	}{
		{
			name:    "SuccessfulAuthentication",
			mode:    sessionSetupServerSuccess,
			wantErr: false,
		},
		{
			name:           "GuestAccountRejected",
			mode:           sessionSetupServerGuestReject,
			requireSigning: true,
			wantErr:        true,
			errorContains:  "guest account doesn't support signing",
		},
		{
			name:          "InvalidSecurityContext",
			mode:          sessionSetupServerInvalidSecurityContext,
			wantErr:       true,
			errorContains: "spnego accept security context failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			trackedBufs := installTrackingRecvBufPool(t)

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})

			st := direct(serverConn)

			var ntlmServer *ntlm.Server
			if test.mode == sessionSetupServerSuccess {
				ntlmServer = ntlm.NewServer("test-server")
				ntlmServer.AddAccount("user", "password")
			}
			go runFakeSessionSetupServer(st, test.mode, ntlmServer)

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.requireSigning = test.requireSigning

			s, err := sessionSetup(c, &NTLMInitiator{User: "user", Password: "password"}, context.Background())

			if test.wantErr {
				require.Error(err)
				require.Nil(s)
				require.Contains(err.Error(), test.errorContains)
			} else {
				require.NoError(err)
				require.NotNil(s)
				require.Equal(uint64(0x1234), s.sessionId)
			}

			// The initial SessionSetup response buffer must be handed back to
			// the pool on every exit path, successful or not.
			requireAllRecvBufsReleased(t, trackedBufs)
		})
	}
}
