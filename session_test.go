package smb2

import (
	"context"
	"encoding/binary"
	"errors"
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

	recvBufPool = &sync.Pool{
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
		var signed bool

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
		case (mode == sessionSetupServerSuccess || mode == sessionSetupServerTamperedFinalSignature) && round == 1:
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
		case (mode == sessionSetupServerSuccess || mode == sessionSetupServerTamperedFinalSignature) && round == 2:
			resp, err := spnego.DecodeNegTokenResp(req.SecurityBuffer())
			if err != nil {
				return
			}
			if err := ntlmServer.Authenticate(resp.ResponseToken); err != nil {
				return
			}
			status = uint32(erref.STATUS_SUCCESS)
			signed = mode == sessionSetupServerTamperedFinalSignature
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

		if signed {
			// Claim the packet is signed but put a bogus signature in it, so
			// the client must detect the tampering during sessionSetup.
			rp.SetFlags(rp.Flags() | smb2.SMB2_FLAGS_SIGNED)
			for i := range rp.Signature() {
				rp.Signature()[i] = 0xA5
			}
		}

		if _, err := t.Write(respBuf); err != nil {
			return
		}
	}
}

const (
	sessionSetupServerSuccess = iota
	sessionSetupServerGuestReject
	sessionSetupServerInvalidSecurityContext
	sessionSetupServerTamperedFinalSignature
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
		{
			name:          "TamperedFinalResponseSignature",
			mode:          sessionSetupServerTamperedFinalSignature,
			wantErr:       true,
			errorContains: "session setup response failed signature verification",
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
			if test.mode == sessionSetupServerSuccess || test.mode == sessionSetupServerTamperedFinalSignature {
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

func TestIoctlBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	expectedData := []byte("partial output data from buffer overflow")

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_IOCTL {
			return
		}

		iores := &smb2.IoctlResponse{
			CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
			Output:  rawEncoder(expectedData),
		}
		respBuf := make([]byte, iores.Size())
		iores.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	output, err := fs.ioctl(&smb2.FileId{}, &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, expectedData, output)

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestIoctlErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_IOCTL {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_IOCTL)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	output, err := fs.ioctl(&smb2.FileId{}, &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr.Code)
	require.Nil(t, output)

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	expectedData := []byte("partial read data from buffer overflow")

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		readres := &smb2.ReadResponse{
			Data:          expectedData,
			DataRemaining: 100,
		}
		respBuf := make([]byte, readres.Size())
		readres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(&smb2.FileId{}, buf, 0)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, buf[:n])

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadBufferOverflowInReadMethodReturnsSuccess(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	expectedData := []byte("pipe chunk data")

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		readres := &smb2.ReadResponse{
			Data:          expectedData,
			DataRemaining: 50,
		}
		respBuf := make([]byte, readres.Size())
		readres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.read(&smb2.FileId{}, buf, 0)

	require.NoError(t, err)
	require.Equal(t, len(expectedData), n)
	require.Equal(t, expectedData, buf[:n])

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestReadErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_READ {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_READ)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(&smb2.FileId{}, buf, 0)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr.Code)
	require.Equal(t, 0, n)

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestQueryInfoBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	expectedData := []byte("partial query info output data")

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_QUERY_INFO {
			return
		}

		qres := &smb2.QueryInfoResponse{
			Output: rawEncoder(expectedData),
		}
		respBuf := make([]byte, qres.Size())
		qres.Encode(respBuf)

		rp := smb2.PacketCodec(respBuf)
		rp.SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	output, err := fs.queryInfo(&smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

	require.Error(t, err)
	var rerr *ResponseError
	require.True(t, errors.As(err, &rerr))
	require.Equal(t, uint32(erref.STATUS_BUFFER_OVERFLOW), rerr.Code)
	require.Equal(t, expectedData, output)

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}

func TestQueryInfoErrorReleasesBuffer(t *testing.T) {
	trackedBufs := installTrackingRecvBufPool(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go func() {
		st := direct(serverConn)
		sz, err := st.ReadSize()
		if err != nil {
			return
		}
		reqBuf := make([]byte, sz)
		if _, err := st.Read(reqBuf); err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		if p.Command() != smb2.SMB2_QUERY_INFO {
			return
		}

		respBuf := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(respBuf[64:66], 9) // ErrorResponse StructureSize

		rp := smb2.PacketCodec(respBuf)
		rp.SetProtocolId()
		rp.SetStructureSize()
		rp.SetCommand(smb2.SMB2_QUERY_INFO)
		rp.SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(1)
		rp.SetSessionId(0x1234)
		rp.SetTreeId(p.TreeId())

		_, _ = st.Write(respBuf)
	}()

	output, err := fs.queryInfo(&smb2.FileId{}, smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 1024)

	require.Error(t, err)
	var rerr2 *ResponseError
	require.True(t, errors.As(err, &rerr2))
	require.Equal(t, uint32(erref.STATUS_ACCESS_DENIED), rerr2.Code)
	require.Nil(t, output)

	// Verify buffer pool is completely released
	requireAllRecvBufsReleased(t, trackedBufs)
}
