package smb2

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

func acceptedBindAck(callId uint32) []byte {
	ack := []byte{
		5, 0, 12, 3, 0x10, 0, 0, 0,
		56, 0, 0, 0, 0, 0, 0, 0,
		0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		2, 0, 0, 0,
	}
	le.PutUint32(ack[12:16], callId)
	return ack
}

func TestListShareNames_BindAck(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		modify    func([]byte) []byte
		wantError string
	}{
		{name: "accepted"},
		{name: "header only", modify: func(b []byte) []byte { b[8] = 24; return b[:24] }, wantError: "broken bind ack response format"},
		{name: "length mismatch", modify: func(b []byte) []byte { b[8]--; return b }, wantError: "broken bind ack response format"},
		{name: "secondary address out of bounds", modify: func(b []byte) []byte { le.PutUint16(b[24:26], 0xffff); return b }, wantError: "broken bind ack response format"},
		{name: "incomplete results", modify: func(b []byte) []byte { b[8]--; return b[:55] }, wantError: "broken bind ack response format"},
		{name: "wrong call ID", modify: func(b []byte) []byte { le.PutUint32(b[12:16], le.Uint32(b[12:16])+1); return b }, wantError: "broken bind ack response format"},
		{name: "user rejection", modify: func(b []byte) []byte { b[32] = 1; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "provider rejection", modify: func(b []byte) []byte { b[32] = 2; b[34] = 2; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "zero results", modify: func(b []byte) []byte { b[28] = 0; b[8] = 32; return b[:32] }, wantError: "bind ack did not accept NDR v2"},
		{name: "two results", modify: func(b []byte) []byte { b[28] = 2; b[8] = 80; return append(b, b[32:56]...) }, wantError: "bind ack did not accept NDR v2"},
		{name: "different UUID", modify: func(b []byte) []byte { b[36]++; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "different version", modify: func(b []byte) []byte { b[52]++; return b }, wantError: "bind ack did not accept NDR v2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			c := &conn{
				t:                   NewTransport(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()
			s := &Session{s: c.session, addr: "testserver"}
			go c.runReceiver()

			var ioctlCount atomic.Int32
			var bindCallId uint32
			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt Transport) bool {
				ioctlCount.Add(1)
				req := smb2.IoctlRequestDecoder(reqBuf[64:])
				input := reqBuf[req.InputOffset() : req.InputOffset()+req.InputCount()]
				var output []byte
				if input[2] == msrpc.RPC_TYPE_BIND {
					bindCallId = le.Uint32(input[12:16])
					output = acceptedBindAck(bindCallId)
					if tt.modify != nil {
						output = tt.modify(output)
					}
				} else {
					// A complete successful level 1 response with no shares.
					output = make([]byte, 56)
					output[0] = msrpc.RPC_VERSION
					output[2] = msrpc.RPC_TYPE_RESPONSE
					output[3] = msrpc.RPC_PACKET_FLAG_FIRST | msrpc.RPC_PACKET_FLAG_LAST
					output[4] = 0x10
					le.PutUint16(output[8:10], uint16(len(output)))
					le.PutUint32(output[12:16], bindCallId+1)
					le.PutUint32(output[24:28], 1)       // level
					le.PutUint32(output[28:32], 1)       // switch
					le.PutUint32(output[32:36], 0x20004) // container pointer
				}
				sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
					Output:  rawEncoder(output),
				}, 0)
				return true
			}, nil)

			names, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
			if tt.wantError == "" {
				require.NoError(t, err)
				require.Empty(t, names)
				require.Equal(t, int32(2), ioctlCount.Load())
			} else {
				var pathErr *os.PathError
				require.ErrorAs(t, err, &pathErr)
				require.Equal(t, "listShareNames", pathErr.Op)
				require.Equal(t, "srvsvc", pathErr.Path)
				var invalidRespErr *InvalidResponseError
				require.ErrorAs(t, pathErr.Err, &invalidRespErr)
				require.Equal(t, "invalid response error: "+tt.wantError, invalidRespErr.Error())
				require.Equal(t, int32(1), ioctlCount.Load())
			}
			// Deferred CLOSE and tree teardown have completed; the shared connection
			// must still service a new request after either bind outcome.
			fs, err := s.Mount(context.Background(), "IPC$")
			require.NoError(t, err)
			require.NoError(t, fs.Unmount(context.Background()))
		})
	}
}

func TestListShareNames_RejectsExcessiveResponseSize(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 300 // 300 * ~4KB > 1MB

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment read: level 1, large count (incomplete)
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Subsequent incomplete fragments
						frag = make([]byte, 4000)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4000)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	_, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Less(t, readCount, maxReads)
}

func TestListShareNames_MaxShareResponseSize(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment: PFC_FIRST_FRAG (0x01)
						// Its 65-byte stub already exceeds the 64-byte limit.
						frag = make([]byte, 89)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 1 // PFC_FIRST_FRAG
						le.PutUint16(frag[8:10], 89)
						le.PutUint32(frag[12:16], rpcCallId)
					} else if readCount == 2 {
						// Second fragment: PFC_LAST_FRAG (0x02)
						frag = make([]byte, 128)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 2 // PFC_LAST_FRAG
						le.PutUint16(frag[8:10], 128)
						le.PutUint32(frag[12:16], rpcCallId)
					} else {
						serverConn.Close()
						return
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	// The first fragment's 65-byte Stub exceeds the low limit and must be
	// rejected before the client reads another RPC fragment.
	_, err := s.listShareNames(context.Background(), 64)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Equal(t, "invalid response error: net share enum response exceeds maximum size", invalidRespErr.Error())
	require.Equal(t, 1, readCount)
}

func TestListShareNames_MaxShareResponseSizeBoundaries(t *testing.T) {
	t.Parallel()
	enc := msrpc.NewEncoder()
	// Level 1, one container entry, and one disk share with no remark.
	for _, v := range []uint32{
		1, 1, 1, // Level, discriminant, container pointer.
		1, 1, 1, // EntriesRead, buffer pointer, array count.
		1, 0, 0, // Name pointer, share type, remark pointer.
	} {
		enc.WriteUint32(v)
	}
	enc.WriteConformantVaryingString("SHARE1")
	for _, v := range []uint32{1, 0, 0} { // TotalEntries, NULL ResumeHandle, success.
		enc.WriteUint32(v)
	}
	stub := enc.Bytes()
	names, err := msrpc.NetShareEnumAllResponseDecoder(stub).Sharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)

	for _, tt := range []struct {
		name       string
		overflow   bool
		split      bool
		invalidNDR bool
		limit      int
		wantError  bool
	}{
		{name: "single exceeds", limit: len(stub) - 1, wantError: true},
		{name: "single equals", limit: len(stub)},
		{name: "unlimited", limit: -1},
		{name: "single invalid NDR exceeds", invalidNDR: true, limit: len(stub) - 1, wantError: true},
		{name: "overflow first last exceeds", overflow: true, limit: len(stub) - 1, wantError: true},
		{name: "overflow first last equals", overflow: true, limit: len(stub)},
		{name: "multiple equals", overflow: true, split: true, limit: len(stub)},
		{name: "multiple cumulative exceeds", overflow: true, split: true, limit: len(stub) - 1, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c := &conn{
				t:                   NewTransport(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()

			s := &Session{
				s:    c.session,
				addr: "testserver",
			}

			go c.runReceiver()

			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt Transport) bool {
				iReq := smb2.IoctlRequestDecoder(reqBuf[64:])
				input := reqBuf[iReq.InputOffset() : iReq.InputOffset()+iReq.InputCount()]

				if input[2] == msrpc.RPC_TYPE_BIND {
					bindAck := acceptedBindAck(le.Uint32(input[12:16]))
					sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
						CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
						Output:  rawEncoder(bindAck),
					}, 0)
					return true
				}

				responseStub := append([]byte(nil), stub...)
				if tt.invalidNDR {
					le.PutUint32(responseStub, 99) // Unsupported NDR level.
				}
				chunks := [][]byte{responseStub}
				if tt.split {
					chunks = [][]byte{responseStub[:len(stub)/2], responseStub[len(stub)/2:]}
				}
				var response []byte
				for i, chunk := range chunks {
					fragment := make([]byte, msrpc.HeaderSize+len(chunk))
					fragment[0] = msrpc.RPC_VERSION
					fragment[2] = msrpc.RPC_TYPE_RESPONSE
					if i == 0 {
						fragment[3] |= msrpc.RPC_PACKET_FLAG_FIRST
					}
					if i == len(chunks)-1 {
						fragment[3] |= msrpc.RPC_PACKET_FLAG_LAST
					}
					le.PutUint16(fragment[8:10], uint16(len(fragment)))
					copy(fragment[12:16], input[12:16])
					copy(fragment[msrpc.HeaderSize:], chunk)
					response = append(response, fragment...)
				}
				var status uint32
				if tt.overflow {
					status = uint32(erref.STATUS_BUFFER_OVERFLOW)
				}
				sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
					Output:  rawEncoder(response),
				}, status)
				return true
			}, nil)

			names, err := s.listShareNames(context.Background(), tt.limit)
			if !tt.wantError {
				require.NoError(t, err)
				require.Equal(t, []string{"SHARE1"}, names)
				return
			}
			require.Error(t, err)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			var invalidRespErr *InvalidResponseError
			require.ErrorAs(t, pathErr.Err, &invalidRespErr)
			require.Equal(t, "invalid response error: net share enum response exceeds maximum size", invalidRespErr.Error())
		})
	}
}

func TestListShareNames_RejectsEmptyFragment(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 10

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Return empty fragment (header only: 24 bytes, Buffer() is 0 bytes)
						frag = make([]byte, 24)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 24)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	_, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Equal(t, 2, readCount)
}

func TestListShareNames_TerminatesOnLastFrag(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment: PFC_FIRST_FRAG (0x01)
						frag = make([]byte, 60)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 1 // PFC_FIRST_FRAG
						le.PutUint16(frag[8:10], 60)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)       // level 1
						le.PutUint32(frag[28:32], 1)       // CTR pointer
						le.PutUint32(frag[32:36], 0x20004) // Referent ID
						le.PutUint32(frag[36:40], 1)       // Count = 1
						le.PutUint32(frag[40:44], 0x20008) // Array pointer
						le.PutUint32(frag[44:48], 1)       // Array MaxCount = 1
						le.PutUint32(frag[48:52], 0x2000c) // Name pointer
						le.PutUint32(frag[52:56], 0)       // Type
						le.PutUint32(frag[56:60], 0x20010) // Comment pointer
					} else if readCount == 2 {
						// Second fragment: PFC_LAST_FRAG (0x02) containing deferred name
						nameBytes := utf16le.EncodeStringToBytes("SHARE1")
						nameCount := uint32(len(nameBytes)/2 + 1)
						commentBytes := utf16le.EncodeStringToBytes("")
						commentCount := uint32(1)

						frag = make([]byte, 128)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 2 // PFC_LAST_FRAG
						le.PutUint32(frag[12:16], rpcCallId)

						off := 24
						// Name deferred
						le.PutUint32(frag[off:off+4], nameCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], nameCount)
						copy(frag[off+12:], nameBytes)
						off = (off + 12 + int(nameCount*2) + 3) &^ 3

						// Comment deferred
						le.PutUint32(frag[off:off+4], commentCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], commentCount)
						copy(frag[off+12:], commentBytes)
						off = (off + 12 + int(commentCount*2) + 3) &^ 3
						le.PutUint32(frag[off:off+4], 1) // TotalEntries
						off += 4
						le.PutUint32(frag[off:off+4], 0) // ResumeHandle (NULL)
						off += 4
						le.PutUint32(frag[off:off+4], 0) // ReturnStatus (NERR_Success)
						off += 4

						frag = frag[:off]
						le.PutUint16(frag[8:10], uint16(off))
					} else {
						// Should not reach here if PFC_LAST_FRAG terminates
						serverConn.Close()
						return
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	names, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestListShareNames_StatusSuccessFirstFragment(t *testing.T) {
	t.Parallel()
	enc := msrpc.NewEncoder()
	for _, v := range []uint32{
		1, 1, 1, // Level, discriminant, container pointer.
		1, 1, 1, // EntriesRead, buffer pointer, array count.
		1, 0, 0, // Name pointer, share type, remark pointer.
	} {
		enc.WriteUint32(v)
	}
	enc.WriteConformantVaryingString("SHARE1")
	for _, v := range []uint32{1, 0, 0} { // TotalEntries, NULL ResumeHandle, success.
		enc.WriteUint32(v)
	}
	stub := enc.Bytes()

	makeFragment := func(flags uint8, chunk []byte) []byte {
		fragment := make([]byte, msrpc.HeaderSize+len(chunk))
		fragment[0] = msrpc.RPC_VERSION
		fragment[2] = msrpc.RPC_TYPE_RESPONSE
		fragment[3] = flags
		le.PutUint16(fragment[8:10], uint16(len(fragment)))
		copy(fragment[msrpc.HeaderSize:], chunk)
		return fragment
	}

	for _, tt := range []struct {
		name      string
		first     []byte
		readFrags [][]byte
		readCount int
	}{
		{
			name:      "single fragment",
			first:     makeFragment(msrpc.RPC_PACKET_FLAG_FIRST|msrpc.RPC_PACKET_FLAG_LAST, stub),
			readCount: 0,
		},
		{
			name:      "success first fragment followed by read",
			first:     makeFragment(msrpc.RPC_PACKET_FLAG_FIRST, stub[:len(stub)/2]),
			readFrags: [][]byte{makeFragment(msrpc.RPC_PACKET_FLAG_LAST, stub[len(stub)/2:])},
			readCount: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c := &conn{
				t:                   NewTransport(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()

			s := &Session{s: c.session, addr: "testserver"}

			go c.runReceiver()
			var readCount int
			go func() {
				dt := NewTransport(serverConn)
				var callID uint32
				for {
					reqBuf, err := readMsg(dt)
					if err != nil {
						return
					}
					var responseBufs [][]byte
					currBuf := reqBuf
					for {
						p := smb2.PacketCodec(currBuf)
						var response smb2.Packet
						var status uint32

						switch p.Command() {
						case smb2.SMB2_TREE_CONNECT:
							response = &smb2.TreeConnectResponse{ShareType: smb2.SMB2_SHARE_TYPE_PIPE}
						case smb2.SMB2_CREATE:
							response = &smb2.CreateResponse{
								CreationTime:   &smb2.Filetime{},
								LastAccessTime: &smb2.Filetime{},
								LastWriteTime:  &smb2.Filetime{},
								ChangeTime:     &smb2.Filetime{},
								FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
							}
						case smb2.SMB2_CLOSE:
							response = &smb2.CloseResponse{
								CreationTime:   &smb2.Filetime{},
								LastAccessTime: &smb2.Filetime{},
								LastWriteTime:  &smb2.Filetime{},
								ChangeTime:     &smb2.Filetime{},
							}
						case smb2.SMB2_TREE_DISCONNECT:
							response = &smb2.TreeDisconnectResponse{}
						case smb2.SMB2_IOCTL:
							iReq := smb2.IoctlRequestDecoder(currBuf[64:])
							input := currBuf[int(iReq.InputOffset()):int(iReq.InputOffset()+iReq.InputCount())]
							callID = le.Uint32(input[12:16])
							if input[2] == msrpc.RPC_TYPE_BIND {
								bindAck := acceptedBindAck(callID)
								response = &smb2.IoctlResponse{
									CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
									Output:  rawEncoder(bindAck),
								}
							} else {
								first := append([]byte(nil), tt.first...)
								le.PutUint32(first[12:16], callID)
								response = &smb2.IoctlResponse{
									CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
									Output:  rawEncoder(first),
								}
							}
						case smb2.SMB2_READ:
							if readCount >= len(tt.readFrags) {
								serverConn.Close()
								return
							}
							fragment := append([]byte(nil), tt.readFrags[readCount]...)
							readCount++
							le.PutUint32(fragment[12:16], callID)
							response = &smb2.ReadResponse{Data: fragment}
						}

						if response != nil {
							resBuf := make([]byte, response.Size())
							response.Encode(resBuf)
							rp := smb2.PacketCodec(resBuf)
							rp.SetMessageId(p.MessageId())
							rp.SetSessionId(p.SessionId())
							rp.SetTreeId(p.TreeId())
							rp.SetStatus(status)
							rp.SetCreditResponse(1)
							rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
							responseBufs = append(responseBufs, resBuf)
						}

						if p.NextCommand() == 0 {
							break
						}
						currBuf = currBuf[p.NextCommand():]
					}

					if len(responseBufs) > 0 {
						var finalBuf []byte
						for i, rb := range responseBufs {
							if i < len(responseBufs)-1 {
								pad := (8 - (len(rb) % 8)) % 8
								nextCmd := uint32(len(rb) + pad)
								padded := make([]byte, nextCmd)
								copy(padded, rb)
								smb2.PacketCodec(padded).SetNextCommand(nextCmd)
								finalBuf = append(finalBuf, padded...)
							} else {
								finalBuf = append(finalBuf, rb...)
							}
						}
						dt.writev(finalBuf)
					}
				}
			}()

			names, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
			require.NoError(t, err)
			require.Equal(t, []string{"SHARE1"}, names)
			require.Equal(t, tt.readCount, readCount)
		})
	}
}

func TestListShareNames_HandlesShortRead(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					// Build PDU 1 (60 bytes)
					pdu1 := make([]byte, 60)
					pdu1[0] = 5                  // RPC_VERSION
					pdu1[1] = 0                  // RPC_VERSION_MINOR
					pdu1[2] = 2                  // RPC_TYPE_RESPONSE
					pdu1[3] = 1                  // PFC_FIRST_FRAG
					le.PutUint16(pdu1[8:10], 60) // FragLength = 60
					le.PutUint32(pdu1[12:16], rpcCallId)
					le.PutUint32(pdu1[24:28], 1)       // level 1
					le.PutUint32(pdu1[28:32], 1)       // CTR pointer
					le.PutUint32(pdu1[32:36], 0x20004) // Referent ID
					le.PutUint32(pdu1[36:40], 1)       // Count = 1
					le.PutUint32(pdu1[40:44], 0x20008) // Array pointer
					le.PutUint32(pdu1[44:48], 1)       // Array MaxCount = 1
					le.PutUint32(pdu1[48:52], 0x2000c) // Name pointer
					le.PutUint32(pdu1[52:56], 0)       // Type
					le.PutUint32(pdu1[56:60], 0x20010) // Comment pointer

					// Build PDU 2 (72 bytes)
					nameBytes := utf16le.EncodeStringToBytes("SHARE1")
					nameCount := uint32(len(nameBytes)/2 + 1)
					commentBytes := utf16le.EncodeStringToBytes("")
					commentCount := uint32(1)

					pdu2 := make([]byte, 128)
					pdu2[0] = 5 // RPC_VERSION
					pdu2[1] = 0 // RPC_VERSION_MINOR
					pdu2[2] = 2 // RPC_TYPE_RESPONSE
					pdu2[3] = 2 // PFC_LAST_FRAG
					le.PutUint32(pdu2[12:16], rpcCallId)

					off := 24
					le.PutUint32(pdu2[off:off+4], nameCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], nameCount)
					copy(pdu2[off+12:], nameBytes)
					off = (off + 12 + int(nameCount*2) + 3) &^ 3

					le.PutUint32(pdu2[off:off+4], commentCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], commentCount)
					copy(pdu2[off+12:], commentBytes)
					off = (off + 12 + int(commentCount*2) + 3) &^ 3
					le.PutUint32(pdu2[off:off+4], 1) // TotalEntries
					off += 4
					le.PutUint32(pdu2[off:off+4], 0) // ResumeHandle (NULL)
					off += 4
					le.PutUint32(pdu2[off:off+4], 0) // ReturnStatus (NERR_Success)
					off += 4
					pdu2 = pdu2[:off]
					le.PutUint16(pdu2[8:10], uint16(len(pdu2))) // FragLength

					stream := append(pdu1, pdu2...)
					// Chunks to serve: 20, 4 (completes pdu1 header), 36 (completes pdu1 stub), 24 (pdu2 header), 48 (pdu2 stub)
					chunkSizes := []int{20, 4, 36, 24, len(pdu2) - 24}
					if readCount > len(chunkSizes) {
						serverConn.Close()
						return
					}

					chunkOffset := 0
					for i := 0; i < readCount-1; i++ {
						chunkOffset += chunkSizes[i]
					}
					fragData := stream[chunkOffset : chunkOffset+chunkSizes[readCount-1]]

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	names, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 5, readCount)
}

func TestListShareNames_HandlesResidualData(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := NewTransport(serverConn)
		var frag1, frag2 []byte

		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)

							// Prepare frag1 and frag2
							frag1 = make([]byte, 60)
							frag1[0] = 5 // RPC_VERSION
							frag1[1] = 0 // RPC_VERSION_MINOR
							frag1[2] = 2 // RPC_TYPE_RESPONSE
							frag1[3] = 1 // PFC_FIRST_FRAG
							le.PutUint16(frag1[8:10], 60)
							le.PutUint32(frag1[12:16], rpcCallId)
							le.PutUint32(frag1[24:28], 1)       // level 1
							le.PutUint32(frag1[28:32], 1)       // CTR pointer
							le.PutUint32(frag1[32:36], 0x20004) // Referent ID
							le.PutUint32(frag1[36:40], 1)       // Count = 1
							le.PutUint32(frag1[40:44], 0x20008) // Array pointer
							le.PutUint32(frag1[44:48], 1)       // Array MaxCount = 1
							le.PutUint32(frag1[48:52], 0x2000c) // Name pointer
							le.PutUint32(frag1[52:56], 0)       // Type
							le.PutUint32(frag1[56:60], 0x20010) // Comment pointer

							nameBytes := utf16le.EncodeStringToBytes("SHARE1")
							nameCount := uint32(len(nameBytes)/2 + 1)
							commentBytes := utf16le.EncodeStringToBytes("")
							commentCount := uint32(1)

							frag2 = make([]byte, 128)
							frag2[0] = 5 // RPC_VERSION
							frag2[1] = 0 // RPC_VERSION_MINOR
							frag2[2] = 2 // RPC_TYPE_RESPONSE
							frag2[3] = 2 // PFC_LAST_FRAG
							le.PutUint32(frag2[12:16], rpcCallId)

							off := 24
							le.PutUint32(frag2[off:off+4], nameCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], nameCount)
							copy(frag2[off+12:], nameBytes)
							off = (off + 12 + int(nameCount*2) + 3) &^ 3

							le.PutUint32(frag2[off:off+4], commentCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], commentCount)
							copy(frag2[off+12:], commentBytes)
							off = (off + 12 + int(commentCount*2) + 3) &^ 3
							le.PutUint32(frag2[off:off+4], 1) // TotalEntries
							off += 4
							le.PutUint32(frag2[off:off+4], 0) // ResumeHandle (NULL)
							off += 4
							le.PutUint32(frag2[off:off+4], 0) // ReturnStatus (NERR_Success)
							off += 4

							frag2 = frag2[:off]
							le.PutUint16(frag2[8:10], uint16(off))
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var fragData []byte
					if readCount == 1 {
						// Return frag1 + first 30 bytes of frag2 (overflowing frag1)
						fragData = append(append([]byte(nil), frag1...), frag2[:30]...)
					} else if readCount == 2 {
						// Return remainder of frag2
						fragData = frag2[30:]
					}

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	names, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestListShareNames_IncompleteResponse(t *testing.T) {
	t.Parallel()
	// Craft a level 1 NetShareEnumAll response that advertises one share
	// entry but truncates the buffer before the share name data:
	// IsInvalid() is false, but ShareNames() fails.
	frag := make([]byte, 84)
	frag[0] = msrpc.RPC_VERSION
	frag[1] = msrpc.RPC_VERSION_MINOR
	frag[2] = msrpc.RPC_TYPE_RESPONSE
	frag[3] = msrpc.RPC_PACKET_FLAG_LAST
	le.PutUint16(frag[8:10], 84)   // frag length
	le.PutUint32(frag[12:16], 123) // call id (patched later)
	le.PutUint32(frag[24:28], 1)   // level 1
	le.PutUint32(frag[36:40], 1)   // count = 1
	le.PutUint32(frag[48:52], 1)   // name ptr
	le.PutUint32(frag[64:68], 0)   // name offset
	le.PutUint32(frag[68:72], 10)  // name max count (10 -> 20 bytes)

	enumResp := msrpc.NetShareEnumAllResponseDecoder(frag[msrpc.HeaderSize:])
	require.False(t, msrpc.ResponseFragmentDecoder(frag).IsInvalid(), "fixture must be a valid response PDU")
	_, decodeErr := enumResp.Sharenames()
	require.Error(t, decodeErr, "fixture must fail to decode incomplete response PDU")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{
		s:    c.session,
		addr: "testserver",
	}

	go c.runReceiver()

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId := le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns a complete (LAST flag set)
							// response whose buffer is truncated mid share entry.
							rpcCallId := le.Uint32(in[12:16])
							le.PutUint32(frag[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(frag),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	_, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Contains(t, invalidRespErr.Error(), "broken net share enum response format")
}

func TestListShareNames_RejectsDataOutsideFragment(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	s := &Session{s: c.session, addr: "testserver"}

	go c.runReceiver()
	startFullFakeServer(serverConn, nil, func(_ *uint32, msgId uint64, reqBuf []byte, dt Transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		if smb2.IoctlRequestDecoder(reqData).CtlCode() != smb2.FSCTL_PIPE_TRANSCEIVE {
			return false
		}
		in := reqBuf[smb2.IoctlRequestDecoder(reqData).InputOffset():]
		if len(in) < 16 {
			return false
		}
		callId := le.Uint32(in[12:16])

		var output []byte
		if in[2] == msrpc.RPC_TYPE_BIND {
			output = acceptedBindAck(callId)
		} else {
			// The declared fragment ends after TotalEntries. ResumeHandle and
			// ReturnStatus are outside the fragment boundary.
			output = make([]byte, 56)
			output[0] = msrpc.RPC_VERSION
			output[1] = msrpc.RPC_VERSION_MINOR
			output[2] = msrpc.RPC_TYPE_RESPONSE
			output[3] = msrpc.RPC_PACKET_FLAG_FIRST | msrpc.RPC_PACKET_FLAG_LAST
			le.PutUint16(output[8:10], 48)
			le.PutUint32(output[12:16], callId)
			le.PutUint32(output[24:28], 1)       // Level
			le.PutUint32(output[28:32], 1)       // switch
			le.PutUint32(output[32:36], 0x20004) // container pointer
			le.PutUint32(output[36:40], 0)       // EntriesRead
			le.PutUint32(output[40:44], 0)       // Buffer (NULL)
			le.PutUint32(output[44:48], 0)       // TotalEntries
			le.PutUint32(output[48:52], 0)       // ResumeHandle (outside fragment)
			le.PutUint32(output[52:56], 0)       // ReturnStatus (outside fragment)
		}

		iores := &smb2.IoctlResponse{
			CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
			Output:  rawEncoder(output),
		}
		resBuf := make([]byte, iores.Size())
		iores.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		dt.writev(resBuf)
		if in[2] != msrpc.RPC_TYPE_BIND {
			// The malformed response is expected to make ListShareNames return
			// before the fake server needs to service the deferred unmount.
			serverConn.Close()
		}
		return true
	}, nil)

	_, err := s.listShareNames(context.Background(), clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
}

func TestListShareNames_OversizedServerName(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	oversizedHostname := strings.Repeat("a", 32760)
	s := &Session{s: c.session, addr: oversizedHostname}

	go c.runReceiver()

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId := le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(p.MessageId())
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(uint32(erref.STATUS_SUCCESS))
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.writev(finalBuf)
			}
		}
	}()

	_, err := s.ListShareNames(context.Background())
	require.Error(t, err)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	var ierr *InternalError
	require.ErrorAs(t, pathErr.Err, &ierr)
	require.Contains(t, ierr.Error(), "server name exceeds max MSRPC fragment size")
}
