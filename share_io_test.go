package smb2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChmodStillUsesFileBasicInformation(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	dt := NewTransport(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		query, err := readMsg(dt)
		if err != nil {
			return
		}
		queryPacket := wire.PacketCodec(query)
		queryRequest := wire.QueryInfoRequestDecoder(queryPacket.Body())
		if queryPacket.Command() != wire.SMB2_QUERY_INFO || queryRequest.IsInvalid() ||
			queryRequest.InfoType() != wire.SMB2_0_INFO_FILE || queryRequest.FileInfoClass() != wire.FileBasicInformation {
			return
		}
		sendTestResponse(dt, query, &wire.QueryInfoResponse{
			Output: &wire.FileBasicInformationEncoder{FileAttributes: wire.FILE_ATTRIBUTE_NORMAL},
		}, uint32(erref.STATUS_SUCCESS))

		set, err := readMsg(dt)
		if err != nil {
			return
		}
		setPacket := wire.PacketCodec(set)
		setRequest := wire.SetInfoRequestDecoder(setPacket.Body())
		if setPacket.Command() != wire.SMB2_SET_INFO || setRequest.IsInvalid() ||
			setRequest.InfoType() != wire.SMB2_0_INFO_FILE || setRequest.FileInfoClass() != wire.FileBasicInformation ||
			setRequest.AdditionalInformation() != 0 {
			return
		}
		sendTestResponse(dt, set, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
	}()

	if err := f.Chmod(context.Background(), 0o644); err != nil {
		t.Fatal(err)
	}
	<-done
}

func validateChtimesTime(t time.Time) error {
	if t.IsZero() {
		return nil
	}
	if wire.TimeToFiletime(t) == nil {
		return os.ErrInvalid
	}
	return nil
}

func TestValidateChtimesTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		when time.Time
		want bool
	}{
		{name: "zero", when: time.Time{}, want: true},
		{name: "filetime epoch", when: time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "before filetime epoch", when: time.Date(1600, time.December, 31, 23, 59, 59, 0, time.UTC), want: false},
		{name: "normal", when: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "future FILETIME", when: time.Date(2300, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "after FILETIME range", when: time.Date(100000, time.January, 1, 0, 0, 0, 0, time.UTC), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChtimesTime(tt.when)
			if (err == nil) != tt.want {
				t.Errorf("validateChtimesTime(%v) error = %v, want valid=%v", tt.when, err, tt.want)
			}
		})
	}
}

func TestSymlinkRejectsEmptyTarget(t *testing.T) {
	t.Parallel()
	fs := &Share{}
	var err error

	require.NotPanics(t, func() {
		err = fs.Symlink(context.Background(), "", "link")
	})
	require.Error(t, err)
}

func TestSymlinkReparseDataBufferBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		target         string
		flags          uint32
		substituteName string
		printName      string
	}{
		{
			name:           "relative",
			target:         strings.Repeat("r\\", 2045) + "r",
			flags:          wire.SYMLINK_FLAG_RELATIVE,
			substituteName: strings.Repeat("r\\", 2045) + "r",
			printName:      strings.Repeat("r\\", 2045) + "r",
		},
		{
			name:           "leading backslash",
			target:         `\` + strings.Repeat("a\\", 2044) + "aa",
			flags:          0,
			substituteName: `\` + strings.Repeat("a\\", 2044) + "aa",
			printName:      `\` + strings.Repeat("a\\", 2044) + "aa",
		},
		{
			name:           "drive",
			target:         `C:\` + strings.Repeat("d\\", 2042) + "dd",
			flags:          0,
			substituteName: `\??\C:\` + strings.Repeat("d\\", 2042) + "dd",
			printName:      `C:\` + strings.Repeat("d\\", 2042) + "dd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			tc := &treeConn{session: s, treeId: 1}
			fs := &Share{treeConn: tc}

			var input []byte
			var ctlCode uint32
			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt Transport) bool {
				req := wire.IoctlRequestDecoder(reqBuf[64:])
				ctlCode = req.CtlCode()
				inputOffset := int(req.InputOffset()) - 64
				inputCount := int(req.InputCount())
				input = append([]byte(nil), reqBuf[64+inputOffset:64+inputOffset+inputCount]...)

				res := &wire.IoctlResponse{
					CtlCode: wire.FSCTL_SET_REPARSE_POINT,
					FileId:  &wire.FileId{},
				}
				sendTestResponse(dt, reqBuf, res, 0)
				return true
			}, nil)

			require.NoError(t, fs.Symlink(context.Background(), tt.target, "link"))
			require.Equal(t, uint32(wire.FSCTL_SET_REPARSE_POINT), ctlCode)
			require.Len(t, input, 16384)

			rdbuf := wire.SymbolicLinkReparseDataBufferDecoder(input)
			require.False(t, rdbuf.IsInvalid())
			require.Equal(t, uint16(16376), rdbuf.ReparseDataLength())
			require.Equal(t, tt.flags, rdbuf.Flags())
			require.Equal(t, uint16(0), rdbuf.SubstituteNameOffset())
			require.Equal(t, uint16(utf16le.EncodedStringLen(tt.substituteName)), rdbuf.SubstituteNameLength())
			require.Equal(t, rdbuf.SubstituteNameLength(), rdbuf.PrintNameOffset())
			require.Equal(t, uint16(utf16le.EncodedStringLen(tt.printName)), rdbuf.PrintNameLength())

			pathBuffer := rdbuf.PathBuffer()
			substituteEnd := int(rdbuf.SubstituteNameOffset()) + int(rdbuf.SubstituteNameLength())
			printStart := int(rdbuf.PrintNameOffset())
			printEnd := printStart + int(rdbuf.PrintNameLength())
			require.Equal(t, utf16le.EncodeStringToBytes(tt.substituteName), pathBuffer[:substituteEnd])
			require.Equal(t, utf16le.EncodeStringToBytes(tt.printName), pathBuffer[printStart:printEnd])
		})
	}
}

func TestSymlinkRejectsOversizedReparseDataBuffer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
	}{
		{name: "relative", target: strings.Repeat("r", 4092)},
		{name: "leading backslash", target: `\` + strings.Repeat("a", 4091)},
		{name: "drive", target: `C:\` + strings.Repeat("d", 4087)},
		{name: "large target", target: strings.Repeat("x", 32767)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			tc := &treeConn{session: s, treeId: 1}
			fs := &Share{treeConn: tc}

			errCh := make(chan error, 1)
			go func() { errCh <- fs.Symlink(context.Background(), tt.target, "link") }()

			var err error
			select {
			case err = <-errCh:
			case <-time.After(time.Second):
				t.Fatal("oversized symlink did not return before sending a request")
			}

			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "symlink", linkErr.Op)
			require.Equal(t, tt.target, linkErr.Old)
			require.Equal(t, "link", linkErr.New)
			require.ErrorIs(t, err, os.ErrInvalid)

			require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			_, readErr := readMsg(NewTransport(serverConn))
			require.Error(t, readErr, "oversized symlink must not send CREATE, IOCTL, or CLOSE")
		})
	}
}

func TestSymlinkCreateCollisionDoesNotRemove(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	var receivedCommands []wire.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := NewTransport(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		resp0 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp0[64:66], 9) // ErrorResponse StructureSize
		rp0 := wire.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetStructureSize()
		rp0.SetCommand(wire.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_OBJECT_NAME_COLLISION))
		rp0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
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
		rp1.SetCommand(wire.SMB2_IOCTL)
		rp1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := wire.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(wire.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, append(resp1, resp2...)...)
		_, _ = st.writev(allResp)

		for {
			reqBuf2, err := readMsg(st)
			if err != nil {
				return
			}
			p2 := wire.PacketCodec(reqBuf2)
			mu.Lock()
			receivedCommands = append(receivedCommands, p2.Command())
			mu.Unlock()
		}
	}()

	err := fs.Symlink(context.Background(), "target", "existing_file")
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrExist))

	_ = clientConn.Close()
	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	// Should only have received the initial CREATE (compound start) and NOT a second CREATE (for Remove)
	require.Equal(t, []wire.Command{wire.SMB2_CREATE}, receivedCommands)
}

func TestSymlinkIoctlFailureDoesRemove(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	var receivedCommands []wire.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := NewTransport(serverConn)
		// 1. Read initial Symlink compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		// Server responds: op 0 (Create) SUCCESS, op 1 (Ioctl) NOT_SUPPORTED, op 2 (Close) NOT_SUPPORTED
		createRes := &wire.CreateResponse{
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
			FileId: &wire.FileId{
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
		rp0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
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
		rp1.SetCommand(wire.SMB2_IOCTL)
		rp1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := wire.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(wire.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, append(resp1, resp2...)...)
		_, _ = st.writev(allResp)

		// 2. Since op 0 succeeded but op 2 failed, treeConn.sendRecv will auto-close the opened file.
		// Read closeFile request
		closeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pClose := wire.PacketCodec(closeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pClose.Command())
		mu.Unlock()

		// Respond to closeFile
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

		// 3. Now Symlink should call fs.Remove!
		// Read Remove compound request (starts with CREATE)
		removeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pRemove := wire.PacketCodec(removeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pRemove.Command())
		mu.Unlock()

		// Respond to Remove compound chain (Create, SetInfo, Close)
		rem0 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem0[64:66], 9)
		rpRem0 := wire.PacketCodec(rem0)
		rpRem0.SetProtocolId()
		rpRem0.SetStructureSize()
		rpRem0.SetCommand(wire.SMB2_CREATE)
		rpRem0.SetStatus(uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		rpRem0.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem0.SetMessageId(pRemove.MessageId())
		rpRem0.SetCreditResponse(1)
		rpRem0.SetSessionId(0x1234)
		rpRem0.SetTreeId(pRemove.TreeId())
		rpRem0.SetNextCommand(uint32(len(rem0)))

		rem1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem1[64:66], 9)
		rpRem1 := wire.PacketCodec(rem1)
		rpRem1.SetProtocolId()
		rpRem1.SetStructureSize()
		rpRem1.SetCommand(wire.SMB2_SET_INFO)
		rpRem1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rpRem1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem1.SetMessageId(pRemove.MessageId() + 1)
		rpRem1.SetSessionId(0x1234)
		rpRem1.SetTreeId(pRemove.TreeId())
		rpRem1.SetNextCommand(uint32(len(rem1)))

		rem2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem2[64:66], 9)
		rpRem2 := wire.PacketCodec(rem2)
		rpRem2.SetProtocolId()
		rpRem2.SetStructureSize()
		rpRem2.SetCommand(wire.SMB2_CLOSE)
		rpRem2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rpRem2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem2.SetMessageId(pRemove.MessageId() + 2)
		rpRem2.SetSessionId(0x1234)
		rpRem2.SetTreeId(pRemove.TreeId())
		rpRem2.SetNextCommand(0)

		allRemResp := append(rem0, append(rem1, rem2...)...)
		_, _ = st.writev(allRemResp)
	}()

	err := fs.Symlink(context.Background(), "target", "new_link")
	require.Error(t, err)

	<-done

	mu.Lock()
	defer mu.Unlock()
	// Received: initial CREATE (symlink), CLOSE (auto-cleanup fileId), CREATE (fs.Remove)
	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_CLOSE, wire.SMB2_CREATE}, receivedCommands)
}

func TestParallelChunkedReadWrite(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc}

	const fileSize = 512 * 1024
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case wire.SMB2_WRITE:
				wreq := wire.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &wire.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.writev(resBuf)

			case wire.SMB2_READ:
				rreq := wire.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				var chunkData []byte
				if int(off) < len(mockStorage) {
					end := min(int(off)+int(length), len(mockStorage))
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &wire.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.writev(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	_, err := rand.Read(testPayload)
	req.NoError(err)

	dummyFd := &wire.FileId{}
	wn, err := fs.writeAt(context.Background(), dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(context.Background(), dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestLargeMockFileCopy(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc}

	const fileSize = 10 * 1024 * 1024 // 10MB
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case wire.SMB2_WRITE:
				wreq := wire.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &wire.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.writev(resBuf)

			case wire.SMB2_READ:
				rreq := wire.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				end := min(int(off)+int(length), len(mockStorage))
				var chunkData []byte
				if int(off) < len(mockStorage) {
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &wire.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.writev(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	for i := range testPayload {
		testPayload[i] = byte((i*17 + 13) % 251)
	}

	dummyFd := &wire.FileId{}
	wn, err := fs.writeAt(context.Background(), dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(context.Background(), dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func resolveTestSymlink(name string, data []byte) (string, error) {
	req := &requestBuilder{tc: &treeConn{serverName: "server", shareName: "share"}}
	return req.resolveSymlink(context.Background(), name,
		&ResponseError{Code: uint32(erref.STATUS_STOPPED_ON_SYMLINK)}, data)
}

func TestResolveSymlinkRelativePath(t *testing.T) {
	t.Parallel()
	unparsed := func(s string) uint16 { return uint16(utf16le.EncodedStringLen(s)) }

	tests := []struct {
		name               string
		path               string
		substituteName     string
		unparsedPathLength uint16
		want               string
		wantErr            bool
	}{
		{
			name:           "replace link name",
			path:           `sub1\sub2\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\sub2\target.txt`,
		},
		{
			name:           "parent reference in substitute name",
			path:           `sub1\sub2\symlink`,
			substituteName: `..\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "current directory reference in substitute name",
			path:           `sub1\symlink`,
			substituteName: `.\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "multiple parent references",
			path:           `a\b\link`,
			substituteName: `..\..\x`,
			want:           `x`,
		},
		{
			name:           "root level symlink",
			path:           `symlink`,
			substituteName: `target.txt`,
			want:           `target.txt`,
		},
		{
			name:           "parent beyond root stays at root",
			path:           `symlink`,
			substituteName: `..\target.txt`,
			wantErr:        true,
		},
		{
			name:           "result is share root",
			path:           `a\link`,
			substituteName: `..`,
			want:           ``,
		},
		{
			name:           "leading backslash is removed",
			path:           `symlink`,
			substituteName: `\target.txt`,
			wantErr:        true,
		},
		{
			name:               "unparsed suffix is preserved",
			path:               `sub1\symlink\dir2\file.txt`,
			substituteName:     `..\target.txt`,
			unparsedPathLength: unparsed(`\dir2\file.txt`),
			want:               `target.txt\dir2\file.txt`,
		},
		{
			name:               "unparsed suffix with dot components is normalized",
			path:               `sub1\symlink\dir2\..\file.txt`,
			substituteName:     `target.txt`,
			unparsedPathLength: unparsed(`\dir2\..\file.txt`),
			want:               `sub1\target.txt\file.txt`,
		},
		{
			name:           "non-ASCII components are preserved",
			path:           `sub1\リンク\symlink`,
			substituteName: `..\ターゲット.txt`,
			want:           `sub1\ターゲット.txt`,
		},
		{
			name:           "names containing dots are preserved",
			path:           `sub1\file..txt\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\file..txt\target.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symErr := &wire.SymbolicLinkErrorResponse{
				UnparsedPathLength: tt.unparsedPathLength,
				Flags:              wire.SYMLINK_FLAG_RELATIVE,
				SubstituteName:     tt.substituteName,
				PrintName:          tt.substituteName,
			}
			buf := make([]byte, symErr.Size())
			symErr.Encode(buf)

			resolved, err := resolveTestSymlink(tt.path, buf)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
		})
	}
}

func TestCreateFileCleansRelativeSymlinkTarget(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc}

	createNames := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := NewTransport(serverConn)

		// The first CREATE resolves a relative symlink whose substitute name
		// still contains a ".." component.
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}
		req := wire.CreateRequestDecoder(reqBuf[64:])
		off, size := int(req.NameOffset()), int(req.NameLength())
		createNames <- utf16le.DecodeToString(reqBuf[off : off+size])

		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{
			CommandCode: wire.SMB2_CREATE,
			ErrorData: &wire.SymbolicLinkErrorResponse{
				Flags:          wire.SYMLINK_FLAG_RELATIVE,
				SubstituteName: `..\target.txt`,
				PrintName:      `..\target.txt`,
			},
		}, uint32(erref.STATUS_STOPPED_ON_SYMLINK))

		// The retried CREATE must carry the cleaned path.
		reqBuf, err = readMsg(dt)
		if err != nil {
			return
		}
		req = wire.CreateRequestDecoder(reqBuf[64:])
		off, size = int(req.NameOffset()), int(req.NameLength())
		createNames <- utf16le.DecodeToString(reqBuf[off : off+size])

		sendTestResponse(dt, reqBuf, &wire.CreateResponse{
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
			FileId:         &wire.FileId{},
			FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
		}, 0)

		// Service the CLOSE issued by the file cleanup.
		for {
			reqBuf, err = readMsg(dt)
			if err != nil {
				return
			}
			if wire.PacketCodec(reqBuf).Command() == wire.SMB2_CLOSE {
				sendTestResponse(dt, reqBuf, &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, 0)
				return
			}
		}
	}()

	f, err := fs.OpenFile(context.Background(), `sub1\sub2\symlink`, os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close(context.Background()))

	<-done

	require.Equal(t, `sub1\sub2\symlink`, <-createNames)
	require.Equal(t, `sub1\target.txt`, <-createNames)
}

func encodeSymlinkErrorResponse(unparsedPathLength uint16, relative bool, substituteName, printName string) []byte {
	flags := uint32(0)
	if relative {
		flags = wire.SYMLINK_FLAG_RELATIVE
	}
	symErr := &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: unparsedPathLength,
		Flags:              flags,
		SubstituteName:     substituteName,
		PrintName:          printName,
	}
	buf := make([]byte, symErr.Size())
	symErr.Encode(buf)
	return buf
}

func TestEvalSymlinkErrorRejectsOddLengths(t *testing.T) {
	t.Parallel()
	valid := encodeSymlinkErrorResponse(0, true, "target", "target")
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{name: "UnparsedPathLength", offset: 14},
		{name: "SubstituteNameLength", offset: 18},
		{name: "PrintNameLength", offset: 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(buf[tc.offset:tc.offset+2], 1)

			resolved, err := resolveTestSymlink(`dir\link\file`, buf)
			var invalid *InvalidResponseError
			require.ErrorAs(t, err, &invalid)
			require.Empty(t, resolved)
		})
	}
}

func TestResolveSymlinkResolvedNameLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		path        string
		unparsed    uint16
		substitute  string
		relative    bool
		want        string
		wantNameLen int
		wantErr     bool
	}{
		{
			name:        "relative resolved name at limit",
			path:        "d" + strings.Repeat("a", 32765),
			unparsed:    65530,
			substitute:  "t",
			relative:    true,
			want:        "t\\" + strings.Repeat("a", 32765),
			wantNameLen: 65534,
		},
		{
			name:       "relative resolved name over limit",
			path:       "d" + strings.Repeat("a", 32766),
			unparsed:   65532,
			substitute: strings.Repeat("t", 100),
			relative:   true,
			wantErr:    true,
		},
		{
			name:        "supplementary plane resolved name at limit",
			path:        "d" + strings.Repeat("\U0001F600", 16382) + "a",
			unparsed:    65530,
			substitute:  "t",
			relative:    true,
			want:        "t\\" + strings.Repeat("\U0001F600", 16382) + "a",
			wantNameLen: 65534,
		},
		{
			name:       "supplementary plane resolved name over limit",
			path:       "d" + strings.Repeat("\U0001F600", 16383) + "a",
			unparsed:   65534,
			substitute: "t",
			relative:   true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeSymlinkErrorResponse(tt.unparsed, tt.relative, tt.substitute, tt.substitute)
			resolved, err := resolveTestSymlink(tt.path, buf)
			if tt.wantErr {
				var ierr *InternalError
				require.ErrorAs(t, err, &ierr)
				require.Contains(t, ierr.Message, "exceeds uint16")
				require.Equal(t, "", resolved)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
			require.Equal(t, tt.wantNameLen, utf16le.EncodedStringLen(resolved))
		})
	}
}

func TestResolveSymlinkResolvedNameNormalizedWithinLimit(t *testing.T) {
	t.Parallel()
	// The raw substitution overflows the uint16 name bound, but eliminating the
	// "." and ".." components brings it back within the limit. [MS-SMB2]
	// 2.2.2.2.1.1 requires those components to be removed during symlink
	// processing, so the retry must succeed.
	comp := strings.Repeat("t", 250)
	target := strings.Repeat(comp+`\`, 129) + comp // 32629 chars, 65258 bytes
	suffix := strings.Repeat(`\..`, 130)           // 390 chars, 780 bytes; raw total > 65535 bytes
	path := "d" + suffix
	unparsed := uint16(utf16le.EncodedStringLen(suffix))

	buf := encodeSymlinkErrorResponse(unparsed, true, target, "")
	resolved, err := resolveTestSymlink(path, buf)
	require.NoError(t, err)
	require.Equal(t, "", resolved)
}

func TestResolveSymlinkRejectsInvalidAbsoluteTargets(t *testing.T) {
	t.Parallel()
	for _, target := range []string{`C:\dir`, `D:\dir`, `\\?\C:\dir`, `other\share\file`} {
		t.Run(target, func(t *testing.T) {
			buf := encodeSymlinkErrorResponse(0, false, target, target)
			resolved, err := resolveTestSymlink(`link`, buf)
			var invalid *InvalidResponseError
			require.ErrorAs(t, err, &invalid)
			require.Empty(t, resolved)
		})
	}
}

func TestResolveSymlinkReturnsCrossShareContinuation(t *testing.T) {
	t.Parallel()
	buf := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false, `\\other\share\dir`, `\\other\share\dir`)
	resolved, err := resolveTestSymlink(`link\file`, buf)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\server\share\link\file`, linkErr.Path)
	require.Equal(t, `\\other\share\dir\file`, linkErr.ResolvedPath)
}

func TestResolveSymlinkExtendedRemoteUNC(t *testing.T) {
	t.Parallel()
	data := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\?\UNC\SERVER\share\dir`, `\\?\UNC\SERVER\share\dir`)
	resolved, err := resolveTestSymlink(`link\file`, data)
	require.NoError(t, err)
	require.Equal(t, `dir\file`, resolved)

	data = encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\?\UNC\other\share\dir`, `\\?\UNC\other\share\dir`)
	resolved, err = resolveTestSymlink(`link\file`, data)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\server\share\link\file`, linkErr.Path)
	require.Equal(t, `\\other\share\dir`, linkErr.Target)
	require.Equal(t, `\\other\share\dir\file`, linkErr.ResolvedPath)
}

func TestResolveSymlinkNormalizesAbsoluteDotsAndSuffixBoundary(t *testing.T) {
	t.Parallel()
	data := encodeSymlinkErrorResponse(uint16(utf16le.EncodedStringLen(`\file`)), false,
		`\\server\share\dir\.\sub\..\base`, `\\server\share\dir\.\sub\..\base`)
	resolved, err := resolveTestSymlink(`link\file`, data)
	require.NoError(t, err)
	require.Equal(t, `dir\base\file`, resolved)

	data = encodeSymlinkErrorResponse(0, false,
		`\\server\share\..\..\file`, `\\server\share\..\..\file`)
	resolved, err = resolveTestSymlink(`link`, data)
	require.NoError(t, err)
	require.Equal(t, `file`, resolved)

	data = encodeSymlinkErrorResponse(0, false,
		`\\other\share\..\..\file`, `\\other\share\..\..\file`)
	resolved, err = resolveTestSymlink(`link`, data)
	var linkErr *CrossShareSymlinkError
	require.ErrorAs(t, err, &linkErr)
	require.Empty(t, resolved)
	require.Equal(t, `\\other\share\file`, linkErr.ResolvedPath)
}

func TestRejectsOverlongResolvedSymlinkPath(t *testing.T) {
	t.Parallel()
	for _, useBuilder := range []bool{false, true} {
		name := "OpenFile"
		if useBuilder {
			name = "requestBuilder"
		}
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.account.charge(8) // Leave credits available for CREATE retries.
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fs := &Share{treeConn: &treeConn{session: s, treeId: 1}}

			overlongName := "d" + strings.Repeat("a", 32766)
			creates := make(chan string, 3)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer close(creates)
				defer serverConn.Close()
				dt := NewTransport(serverConn)
				for count := 0; ; count++ {
					reqBuf, err := readMsg(dt)
					if err != nil || len(reqBuf) < 64 {
						return
					}
					if wire.PacketCodec(reqBuf).Command() == wire.SMB2_CLOSE {
						if wire.CloseRequestDecoder(reqBuf[64:]).IsInvalid() {
							return
						}
						sendTestResponse(dt, reqBuf, &wire.CloseResponse{
							CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
							LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
						}, 0)
						return
					}
					if wire.PacketCodec(reqBuf).Command() != wire.SMB2_CREATE || count >= 3 {
						return
					}
					req := wire.CreateRequestDecoder(reqBuf[64:])
					if req.IsInvalid() {
						return
					}
					off, size := int(req.NameOffset()), int(req.NameLength())
					if off > len(reqBuf) || size > len(reqBuf)-off {
						return
					}
					creates <- utf16le.DecodeToString(reqBuf[off : off+size])
					var closeReq []byte
					if useBuilder {
						next := uint64(wire.PacketCodec(reqBuf).NextCommand())
						if next < 64 || next > uint64(len(reqBuf)) || uint64(len(reqBuf))-next < 64 {
							return
						}
						closeReq = reqBuf[next:]
						if wire.PacketCodec(closeReq).Command() != wire.SMB2_CLOSE ||
							wire.CloseRequestDecoder(closeReq[64:]).IsInvalid() {
							return
						}
					}
					sendCreate := func(res wire.Packet, status uint32) {
						sendTestResponse(dt, reqBuf, res, status)
						if closeReq == nil {
							return
						}
						if status != 0 {
							sendTestResponse(dt, closeReq, &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}, status)
						} else {
							sendTestResponse(dt, closeReq, &wire.CloseResponse{
								CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
								LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
							}, 0)
						}
					}
					if count == 0 {
						sendCreate(&wire.ErrorResponse{
							CommandCode: wire.SMB2_CREATE,
							ErrorData: &wire.SymbolicLinkErrorResponse{
								UnparsedPathLength: 65532, Flags: wire.SYMLINK_FLAG_RELATIVE,
								SubstituteName: strings.Repeat("t", 100), PrintName: strings.Repeat("t", 100),
							},
						}, uint32(erref.STATUS_STOPPED_ON_SYMLINK))
						continue
					}
					// Only the short follow-up CREATE may follow the rejected link.
					sendCreate(&wire.CreateResponse{
						CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
						LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
						FileId: &wire.FileId{}, FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
					}, 0)
				}
			}()

			open := func(path string) error {
				if useBuilder {
					res, err := fs.request().create(path, wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).close().sendRecv(ctx)
					if res != nil {
						res.close()
					}
					return err
				}
				f, err := fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
				if err == nil {
					return f.Close(context.Background())
				}
				return err
			}
			var ierr *InternalError
			require.ErrorAs(t, open(overlongName), &ierr)
			require.Equal(t, "resolved symbolic link path exceeds uint16", ierr.Message)
			require.NoError(t, open("plain.txt"))
			clientConn.Close()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("symlink test server did not finish")
			}
			var names []string
			for name := range creates {
				names = append(names, name)
			}
			require.Equal(t, []string{overlongName, "plain.txt"}, names)
		})
	}
}

func TestReadFile_LargeFile(t *testing.T) {
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
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go c.runReceiver()

	const totalFileSize = 200 * 1024 // 200KB (> 2 * maxReadSize = 128KB)

	startFullFakeServer(serverConn, nil, nil, nil, func(req wire.CreateRequestDecoder, cres *wire.CreateResponse) {
		cres.EndofFile = totalFileSize
	})

	done := make(chan struct{})
	var data []byte
	var err error
	go func() {
		defer close(done)
		data, err = fs.ReadFile(context.Background(), "largefile.dat")
	}()

	select {
	case <-done:
		require.NoError(t, err)
		if len(data) != totalFileSize {
			t.Fatalf("BUG CONFIRMED: ReadFile truncated data! Expected %d bytes, got %d bytes", totalFileSize, len(data))
		}
		t.Logf("PASS: ReadFile read complete %d bytes", len(data))
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadFile timed out")
	}
}

func sendReadFileLengthResponse(dt Transport, req []byte, fileID *wire.FileId, status uint32, adjustment int) {
	p := wire.PacketCodec(req)
	readReqBuf := req
	for {
		readP := wire.PacketCodec(readReqBuf)
		if readP.Command() == wire.SMB2_READ {
			break
		}
		readReqBuf = readReqBuf[readP.NextCommand():]
	}
	readReq := wire.ReadRequestDecoder(wire.PacketCodec(readReqBuf).Body())
	data := make([]byte, int(readReq.Length())+adjustment)

	createRes := &wire.CreateResponse{
		FileId:         fileID,
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
		EndofFile:      int64(len(data)),
	}
	createBuf := make([]byte, createRes.Size())
	createRes.Encode(createBuf)
	createPad := (8 - (len(createBuf) % 8)) % 8
	createNext := uint32(len(createBuf) + createPad)
	createPadded := make([]byte, createNext)
	copy(createPadded, createBuf)
	createPacket := wire.PacketCodec(createPadded)
	createPacket.SetMessageId(p.MessageId())
	createPacket.SetSessionId(p.SessionId())
	createPacket.SetTreeId(p.TreeId())
	createPacket.SetStatus(uint32(erref.STATUS_SUCCESS))
	createPacket.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	createPacket.SetNextCommand(createNext)

	readRes := &wire.ReadResponse{Data: data}
	readBuf := make([]byte, readRes.Size())
	readRes.Encode(readBuf)
	readPacket := wire.PacketCodec(readBuf)
	readPacket.SetMessageId(p.MessageId() + 1)
	readPacket.SetSessionId(p.SessionId())
	readPacket.SetTreeId(p.TreeId())
	readPacket.SetStatus(status)
	readPacket.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	readPacket.SetCreditResponse(1)

	compound := append(createPadded, readBuf...)
	_, _ = dt.writev(compound)
}

func sendReadFileCloseResponse(dt Transport, req []byte) *wire.FileId {
	p := wire.PacketCodec(req)
	fileID := wire.CloseRequestDecoder(p.Body()).FileId().Decode()
	closeRes := &wire.CloseResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	closeBuf := make([]byte, closeRes.Size())
	closeRes.Encode(closeBuf)
	rp := wire.PacketCodec(closeBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(uint32(erref.STATUS_SUCCESS))
	rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	rp.SetCreditResponse(1)
	_, _ = dt.writev(closeBuf)
	return fileID
}

func requireReadFileLengthError(t *testing.T, data []byte, err error) {
	t.Helper()
	require.Nil(t, data)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "readfile", pathErr.Op)
	require.Equal(t, "test.txt", pathErr.Path)
	var invalidErr *InvalidResponseError
	require.ErrorAs(t, err, &invalidErr)
	require.Equal(t, "read length exceeds requested length", invalidErr.Message)
}

func TestReadFileReadLengthBoundary(t *testing.T) {
	t.Parallel()
	for _, adjustment := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(adjustment), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
			dt := NewTransport(serverConn)
			expectedFileID := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			closeReceived := make(chan *wire.FileId, 1)
			go func() {
				defer close(closeReceived)
				defer serverConn.Close()
				req, err := readMsg(dt)
				if err != nil {
					return
				}
				sendReadFileLengthResponse(dt, req, expectedFileID, uint32(erref.STATUS_SUCCESS), adjustment)
				closeReq, err := readMsg(dt)
				if err != nil {
					return
				}
				if wire.PacketCodec(closeReq).Command() == wire.SMB2_CLOSE {
					closeReceived <- sendReadFileCloseResponse(dt, closeReq)
				}
			}()
			data, err := fs.ReadFile(context.Background(), "test.txt")
			if adjustment > 0 {
				requireReadFileLengthError(t, data, err)
			} else {
				require.NoError(t, err)
				require.Len(t, data, maxSingleCreditPayloadSize+adjustment)
			}
			require.Equal(t, expectedFileID, <-closeReceived)
		})
	}
}

func TestReadFileRejectsOversizedOverflowReadWithoutFallback(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	dt := NewTransport(serverConn)
	expectedFileID := &wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	closeReceived := make(chan *wire.FileId, 1)
	extraCreate := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(closeReceived)
		defer serverConn.Close()
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendReadFileLengthResponse(dt, req, expectedFileID, uint32(erref.STATUS_BUFFER_OVERFLOW), 1)

		closeReq, err := readMsg(dt)
		if err != nil {
			return
		}
		if wire.PacketCodec(closeReq).Command() == wire.SMB2_CLOSE {
			closeReceived <- sendReadFileCloseResponse(dt, closeReq)
		}

		_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if nextReq, err := readMsg(dt); err == nil && wire.PacketCodec(nextReq).Command() == wire.SMB2_CREATE {
			extraCreate <- struct{}{}
			_ = serverConn.Close()
		}
	}()

	result := make(chan struct{})
	var data []byte
	var err error
	go func() {
		data, err = fs.ReadFile(context.Background(), "test.txt")
		close(result)
	}()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("ReadFile timed out")
	}
	requireReadFileLengthError(t, data, err)
	<-done
	require.Equal(t, expectedFileID, <-closeReceived)
	select {
	case <-extraCreate:
		t.Fatal("oversized overflow response must not trigger fallback CREATE")
	default:
	}
}

func TestCopyFile_ZeroBytes(t *testing.T) {
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
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go c.runReceiver()

	var sentCopyChunkReq bool

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt Transport) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			qres := &wire.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, qres.Size())
			qres.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.writev(resBuf)
			return true
		} else if ctlCode == wire.FSCTL_SRV_COPYCHUNK || ctlCode == wire.FSCTL_SRV_COPYCHUNK_WRITE {
			sentCopyChunkReq = true
			eres := &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC000000D) // STATUS_INVALID_PARAMETER
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.writev(resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[0:8], 0)  // AllocationSize = 0
		le.PutUint64(stdInfoBuf[8:16], 0) // EndOfFile = 0
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := &wire.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(context.Background(), srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.NoError(t, err)
	require.True(t, supported)
	require.Equal(t, int64(0), n)
	if sentCopyChunkReq {
		t.Fatal("BUG CONFIRMED: copyFile sent FSCTL_SRV_COPYCHUNK request with 0 chunks for 0-byte copy!")
	}
}

type copyChunkRecorder struct {
	mu     sync.Mutex
	chunks []wire.SrvCopychunk
}

func (r *copyChunkRecorder) snapshot() []wire.SrvCopychunk {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]wire.SrvCopychunk(nil), r.chunks...)
}

func newCopyFileTestShare(t *testing.T, endOfFile int64) (*Share, *copyChunkRecorder) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}
	recorder := &copyChunkRecorder{}

	go c.runReceiver()
	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt Transport) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			res := &wire.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.writev(resBuf)
			return true
		}
		if ctlCode != wire.FSCTL_SRV_COPYCHUNK {
			return false
		}

		inputCount := int(le.Uint32(reqData[28:32]))
		input := reqData[56 : 56+inputCount]
		chunkCount := le.Uint32(input[24:28])
		var total uint32
		chunks := make([]wire.SrvCopychunk, chunkCount)
		for i := range chunks {
			off := 32 + i*24
			chunks[i] = wire.SrvCopychunk{
				SourceOffset: int64(le.Uint64(input[off : off+8])),
				TargetOffset: int64(le.Uint64(input[off+8 : off+16])),
				Length:       le.Uint32(input[off+16 : off+20]),
			}
			total += chunks[i].Length
		}
		recorder.mu.Lock()
		recorder.chunks = append(recorder.chunks, chunks...)
		recorder.mu.Unlock()

		respBuf := make([]byte, 12)
		le.PutUint32(respBuf[0:4], chunkCount)
		le.PutUint32(respBuf[4:8], total)
		le.PutUint32(respBuf[8:12], total)
		res := &wire.IoctlResponse{Output: rawEncoder(respBuf)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		rp := wire.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetCreditResponse(1)
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		dt.writev(resBuf)
		return true
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], uint64(endOfFile))
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	return fs, recorder
}

func TestCopyFileRejectsInvalidOffsets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		readFrom  bool
		srcOffset int64
		dstOffset int64
	}{
		{name: "ReadFrom source", readFrom: true, srcOffset: -1},
		{name: "ReadFrom destination", readFrom: true, dstOffset: -1},
		{name: "WriteTo source", srcOffset: -1},
		{name: "WriteTo destination", dstOffset: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &Share{}
			src := &File{fs: fs, fd: &wire.FileId{}, name: "src.txt", offset: tt.srcOffset}
			dst := &File{fs: fs, fd: &wire.FileId{}, name: "dst.txt", offset: tt.dstOffset}

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
			} else {
				n, err = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
			}

			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, os.ErrInvalid)
			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "copy", linkErr.Op)
			require.Equal(t, int64(tt.srcOffset), src.offset)
			require.Equal(t, int64(tt.dstOffset), dst.offset)
		})
	}
}

func TestCopyFileRangeValidation(t *testing.T) {
	t.Parallel()
	const twoMiB = int64(2 * 1024 * 1024)

	tests := []struct {
		name      string
		readFrom  bool
		endOfFile int64
		dstOffset int64
		wantErr   bool
	}{
		{name: "ReadFrom reaches MaxInt64", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB},
		{name: "WriteTo reaches MaxInt64", endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB},
		{name: "ReadFrom exceeds MaxInt64", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - 1024*1024 + 1, wantErr: true},
		{name: "WriteTo exceeds MaxInt64", endOfFile: twoMiB, dstOffset: math.MaxInt64 - 1024*1024 + 1, wantErr: true},
		{name: "ReadFrom exceeds by one byte", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB + 1, wantErr: true},
		{name: "WriteTo exceeds by one byte", endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB + 1, wantErr: true},
		{name: "multiple batches exceed MaxInt64", readFrom: true, endOfFile: 17 * 1024 * 1024, dstOffset: math.MaxInt64 - 16*1024*1024 + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, recorder := newCopyFileTestShare(t, tt.endOfFile)
			src := &File{fs: fs, fd: &wire.FileId{Persistent: [8]byte{1}}, name: "src.txt"}
			dst := &File{fs: fs, fd: &wire.FileId{Persistent: [8]byte{2}}, name: "dst.txt", offset: tt.dstOffset, readAccess: true}

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
			} else {
				n, err = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
			}

			if tt.wantErr {
				require.Equal(t, int64(0), n)
				require.ErrorIs(t, err, os.ErrInvalid)
				var linkErr *os.LinkError
				require.ErrorAs(t, err, &linkErr)
				require.Equal(t, int64(0), src.offset)
				require.Equal(t, tt.dstOffset, dst.offset)
				require.Empty(t, recorder.snapshot())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.endOfFile, n)
			require.Equal(t, tt.endOfFile, src.offset)
			require.Equal(t, int64(math.MaxInt64), dst.offset)

			chunks := recorder.snapshot()
			require.Len(t, chunks, 2)
			for _, chunk := range chunks {
				require.GreaterOrEqual(t, chunk.SourceOffset, int64(0))
				require.GreaterOrEqual(t, chunk.TargetOffset, int64(0))
				require.LessOrEqual(t, chunk.SourceOffset, math.MaxInt64-int64(chunk.Length))
				require.LessOrEqual(t, chunk.TargetOffset, math.MaxInt64-int64(chunk.Length))
			}
			require.Equal(t, int64(0), chunks[0].SourceOffset)
			require.Equal(t, int64(math.MaxInt64)-twoMiB, chunks[0].TargetOffset)
			require.Equal(t, int64(1024*1024), chunks[1].SourceOffset)
			require.Equal(t, int64(math.MaxInt64)-1024*1024, chunks[1].TargetOffset)
		})
	}
}

func TestCopyFileUnsupportedFallsBackToNormalCopy(t *testing.T) {
	t.Parallel()
	const sourceByte = byte(0x5a)

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					src, serverConn := newTestFile(t)
					dst := &File{fs: src.fs, fd: &wire.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

					var mu sync.Mutex
					var ioctlCtlCodes []uint32
					var resumeKeyStatus uint32
					var readCount, writeCount int
					var written []byte
					done := make(chan struct{})
					t.Cleanup(func() {
						_ = serverConn.Close()
						<-done
					})

					go func() {
						defer close(done)
						defer serverConn.Close()
						dt := NewTransport(serverConn)
						for {
							req, err := readMsg(dt)
							if err != nil {
								return
							}
							if len(req) < 64 {
								return
							}
							switch wire.PacketCodec(req).Command() {
							case wire.SMB2_IOCTL:
								ioctlReq := wire.IoctlRequestDecoder(req[64:])
								if ioctlReq.IsInvalid() {
									return
								}
								ctlCode := ioctlReq.CtlCode()
								mu.Lock()
								ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
								if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
									resumeKeyStatus = uint32(status.status)
								}
								mu.Unlock()
								if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(status.status))
								} else {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_INVALID_PARAMETER))
								}
							case wire.SMB2_READ:
								mu.Lock()
								readCount++
								first := readCount == 1
								mu.Unlock()
								if first {
									sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{sourceByte}}, 0)
								} else {
									sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
								}
							case wire.SMB2_WRITE:
								writeReq := wire.WriteRequestDecoder(req[64:])
								if writeReq.IsInvalid() {
									return
								}
								dataOffset, dataLength := uint64(writeReq.DataOffset()), uint64(writeReq.Length())
								if dataOffset > uint64(len(req)) || dataLength > uint64(len(req))-dataOffset {
									return
								}
								data := append([]byte(nil), req[dataOffset:dataOffset+dataLength]...)
								mu.Lock()
								writeCount++
								written = append(written, data...)
								mu.Unlock()
								sendTestResponse(dt, req, &wire.WriteResponse{Count: writeReq.Length()}, 0)
							}
						}
					}()

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(1), n)
					require.Equal(t, int64(1), src.offset)
					require.Equal(t, int64(1), dst.offset)

					_ = serverConn.Close()
					<-done

					mu.Lock()
					defer mu.Unlock()
					require.Equal(t, []uint32{wire.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
					require.Equal(t, uint32(status.status), resumeKeyStatus)
					require.Greater(t, readCount, 0)
					require.Greater(t, writeCount, 0)
					require.Equal(t, []byte{sourceByte}, written)
				})
			}
		})
	}
}

func TestCopyFileResumeKeyAccessDeniedDoesNotFallBack(t *testing.T) {
	t.Parallel()
	src, serverConn := newTestFile(t)
	dst := &File{fs: src.fs, fd: &wire.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

	var mu sync.Mutex
	var ioctlCtlCodes []uint32
	var readCount, writeCount int
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = serverConn.Close()
		<-done
	})

	go func() {
		defer close(done)
		defer serverConn.Close()
		dt := NewTransport(serverConn)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if len(req) < 64 {
				return
			}
			switch wire.PacketCodec(req).Command() {
			case wire.SMB2_IOCTL:
				ioctlReq := wire.IoctlRequestDecoder(req[64:])
				if ioctlReq.IsInvalid() {
					return
				}
				ctlCode := ioctlReq.CtlCode()
				mu.Lock()
				ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
				mu.Unlock()
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_ACCESS_DENIED))
			case wire.SMB2_READ:
				mu.Lock()
				readCount++
				mu.Unlock()
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
			case wire.SMB2_WRITE:
				mu.Lock()
				writeCount++
				mu.Unlock()
				sendTestResponse(dt, req, &wire.WriteResponse{}, 0)
			}
		}
	}()

	n, err := dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
	require.Equal(t, int64(0), n)
	require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
	require.Equal(t, int64(0), src.offset)
	require.Equal(t, int64(0), dst.offset)

	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []uint32{wire.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
	require.Equal(t, 0, readCount)
	require.Equal(t, 0, writeCount)
}

func newCopyFailureTestFiles(t *testing.T, endOfFile int64, failAfter int, status erref.NtStatus) (*File, *File) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c := &conn{
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go c.runReceiver()

	copyCalls := 0
	startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt Transport) bool {
		req := wire.IoctlRequestDecoder(reqBuf[64:])
		switch req.CtlCode() {
		case wire.FSCTL_SRV_REQUEST_RESUME_KEY:
			sendTestResponse(dt, reqBuf, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_SRV_REQUEST_RESUME_KEY,
				Output:  rawEncoder(make([]byte, 32)),
			}, 0)
			return true
		case wire.FSCTL_SRV_COPYCHUNK:
			copyCalls++
			inputCount := int(req.InputCount())
			inputOffset := int(req.InputOffset())
			input := reqBuf[inputOffset : inputOffset+inputCount]
			chunkCount := le.Uint32(input[24:28])
			var total uint32
			for i := range chunkCount {
				off := 32 + i*24
				total += le.Uint32(input[off+16 : off+20])
			}

			if copyCalls == failAfter {
				// These values are server limits, not bytes transferred by a
				// failed request ([MS-SMB2] 3.2.5.14.3).
				limit := make([]byte, 12)
				le.PutUint32(limit[0:4], 1)
				le.PutUint32(limit[4:8], 1)
				le.PutUint32(limit[8:12], 1)
				sendTestResponse(dt, reqBuf, &wire.IoctlResponse{
					CtlCode: wire.FSCTL_SRV_COPYCHUNK,
					Output:  rawEncoder(limit),
				}, uint32(status))
				return true
			}

			response := make([]byte, 12)
			le.PutUint32(response[0:4], chunkCount)
			le.PutUint32(response[4:8], total)
			le.PutUint32(response[8:12], total)
			sendTestResponse(dt, reqBuf, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_SRV_COPYCHUNK,
				Output:  rawEncoder(response),
			}, 0)
			return true
		default:
			return false
		}
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], uint64(endOfFile))
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	src := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "src.txt")
	dst := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "dst.txt")
	dst.readAccess = true
	return src, dst
}

func TestCopyFileFailurePreservesStatusAndProgress(t *testing.T) {
	t.Parallel()
	const firstBatch = int64(16 * 1024 * 1024)

	tests := []struct {
		name      string
		readFrom  bool
		endOfFile int64
		failAfter int
		status    erref.NtStatus
		wantN     int64
	}{
		{name: "ReadFrom first disk full", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "WriteTo first disk full", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "ReadFrom after success disk full", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "WriteTo after success disk full", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "ReadFrom first invalid parameter", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "WriteTo first invalid parameter", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "ReadFrom after success invalid parameter", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
		{name: "WriteTo after success invalid parameter", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := newCopyFailureTestFiles(t, tt.endOfFile, tt.failAfter, tt.status)

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
			} else {
				n, err = src.WriteTo(context.Background(), dst.WithContext(context.Background()))
			}

			require.Equal(t, tt.wantN, n)
			require.ErrorIs(t, err, tt.status)
			var responseErr *ResponseError
			require.ErrorAs(t, err, &responseErr)
			require.Equal(t, uint32(tt.status), responseErr.Code)
			require.Empty(t, responseErr.data)
			require.Equal(t, tt.wantN, src.offset)
			require.Equal(t, tt.wantN, dst.offset)
		})
	}
}

// copyPermissionFile is the per-CREATE state tracked by copyPermissionServer.
type copyPermissionFile struct {
	id      wire.FileId
	access  uint32
	content []byte
}

func fileIdKey(id *wire.FileId) string {
	return string(id.Persistent[:]) + string(id.Volatile[:])
}

// copyPermissionConfig selects the behavior of the fake copy-permission server.
type copyPermissionConfig struct {
	sourceSize int64

	// rejectCopyStatus, when nonzero, rejects every server-side copy FSCTL.
	rejectCopyStatus erref.NtStatus
	// rejectWriteCtlStatus, when nonzero, rejects FSCTL_SRV_COPYCHUNK_WRITE.
	rejectWriteCtlStatus erref.NtStatus
	// failCopyRequest is the 1-based copy request to fail (0 disables).
	failCopyRequest int
	failCopyStatus  erref.NtStatus
}

// copyPermissionServer is a fake SMB2 server that enforces the access rights
// required by the server-side copy FSCTLs ([MS-SMB2] 2.2.31, 3.3.5.15.6) and
// records the control codes and buffered READ/WRITE requests it receives.
type copyPermissionServer struct {
	config copyPermissionConfig

	mu      sync.Mutex
	files   map[string]*copyPermissionFile
	source  *copyPermissionFile
	creates int

	copyCtlCodes  []uint32
	copyRequests  int
	readRequests  int
	writeRequests int
}

func newCopyPermissionPattern(n int64) []byte {
	const block = 64 * 1024
	pattern := make([]byte, block)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	b := make([]byte, n)
	for off := 0; off < len(b); off += block {
		copy(b[off:], pattern)
	}
	return b
}

func newCopyPermissionShare(t *testing.T, config copyPermissionConfig) (*Share, *copyPermissionServer) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(10*time.Second)))
	srv := &copyPermissionServer{
		config: config,
		files:  map[string]*copyPermissionFile{},
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(cleanup)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go srv.serve(serverConn)

	return fs, srv
}

func (s *copyPermissionServer) serve(serverConn net.Conn) {
	defer serverConn.Close()
	dt := NewTransport(serverConn)
	for {
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		if len(reqBuf) < 64 {
			return
		}
		body := reqBuf[64:]
		var invalid bool
		switch wire.PacketCodec(reqBuf).Command() {
		case wire.SMB2_CREATE:
			invalid = wire.CreateRequestDecoder(body).IsInvalid()
		case wire.SMB2_QUERY_INFO:
			invalid = wire.QueryInfoRequestDecoder(body).IsInvalid()
		case wire.SMB2_READ:
			invalid = wire.ReadRequestDecoder(body).IsInvalid()
		case wire.SMB2_WRITE:
			invalid = wire.WriteRequestDecoder(body).IsInvalid()
		case wire.SMB2_IOCTL:
			invalid = wire.IoctlRequestDecoder(body).IsInvalid()
		}
		if invalid {
			return
		}
		switch wire.PacketCodec(reqBuf).Command() {
		case wire.SMB2_TREE_CONNECT:
			sendTestResponse(dt, reqBuf, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_DISK}, 0)
		case wire.SMB2_TREE_DISCONNECT:
			sendTestResponse(dt, reqBuf, &wire.TreeDisconnectResponse{}, 0)
		case wire.SMB2_CREATE:
			s.handleCreate(dt, reqBuf)
		case wire.SMB2_CLOSE:
			sendTestResponse(dt, reqBuf, &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}, 0)
		case wire.SMB2_QUERY_INFO:
			s.handleQueryInfo(dt, reqBuf)
		case wire.SMB2_READ:
			s.handleRead(dt, reqBuf)
		case wire.SMB2_WRITE:
			s.handleWrite(dt, reqBuf)
		case wire.SMB2_IOCTL:
			s.handleIoctl(dt, reqBuf)
		}
	}
}

func (s *copyPermissionServer) handleCreate(dt Transport, reqBuf []byte) {
	req := wire.CreateRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.creates++
	idx := uint64(s.creates)
	id := wire.FileId{}
	le.PutUint64(id.Persistent[:], idx)
	le.PutUint64(id.Volatile[:], idx)
	f := &copyPermissionFile{id: id, access: req.DesiredAccess()}
	if s.source == nil {
		f.content = newCopyPermissionPattern(s.config.sourceSize)
		s.source = f
	}
	s.files[fileIdKey(&id)] = f
	s.mu.Unlock()

	sendTestResponse(dt, reqBuf, &wire.CreateResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
		FileId:         &id,
	}, 0)
}

func (s *copyPermissionServer) handleQueryInfo(dt Transport, reqBuf []byte) {
	req := wire.QueryInfoRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	f := s.files[fileIdKey(req.FileId().Decode())]
	s.mu.Unlock()

	var end int64
	if f != nil {
		end = int64(len(f.content))
	}

	stdInfoBuf := make([]byte, 24)
	le.PutUint64(stdInfoBuf[8:16], uint64(end))
	sendTestResponse(dt, reqBuf, &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}, 0)
}

func (s *copyPermissionServer) handleRead(dt Transport, reqBuf []byte) {
	req := wire.ReadRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.readRequests++
	f := s.files[fileIdKey(req.FileId().Decode())]
	var data []byte
	if f != nil {
		offset := int64(req.Offset())
		if offset >= 0 && offset < int64(len(f.content)) {
			end := min(offset+int64(req.Length()), int64(len(f.content)))
			data = append([]byte(nil), f.content[offset:end]...)
		}
	}
	s.mu.Unlock()

	if len(data) == 0 {
		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
		return
	}
	sendTestResponse(dt, reqBuf, &wire.ReadResponse{Data: data}, 0)
}

func (s *copyPermissionServer) handleWrite(dt Transport, reqBuf []byte) {
	req := wire.WriteRequestDecoder(reqBuf[64:])
	dataOffset, dataLength := uint64(req.DataOffset()), uint64(req.Length())
	if dataOffset > uint64(len(reqBuf)) || dataLength > uint64(len(reqBuf))-dataOffset ||
		req.Offset() > uint64(s.config.sourceSize) || dataLength > uint64(s.config.sourceSize)-req.Offset() {
		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_WRITE}, uint32(erref.STATUS_INVALID_PARAMETER))
		return
	}
	data := reqBuf[dataOffset : dataOffset+dataLength]

	s.mu.Lock()
	s.writeRequests++
	f := s.files[fileIdKey(req.FileId().Decode())]
	if f != nil {
		offset := int(req.Offset())
		end := offset + len(data)
		if end > len(f.content) {
			f.content = append(f.content, make([]byte, end-len(f.content))...)
		}
		copy(f.content[offset:], data)
	}
	s.mu.Unlock()

	sendTestResponse(dt, reqBuf, &wire.WriteResponse{Count: req.Length()}, 0)
}

func (s *copyPermissionServer) handleIoctl(dt Transport, reqBuf []byte) {
	req := wire.IoctlRequestDecoder(reqBuf[64:])

	switch req.CtlCode() {
	case wire.FSCTL_SRV_REQUEST_RESUME_KEY:
		s.mu.Lock()
		f := s.files[fileIdKey(req.FileId().Decode())]
		readable := f != nil && f.access&(wire.FILE_READ_DATA|wire.GENERIC_READ|wire.GENERIC_ALL) != 0
		s.mu.Unlock()
		if !readable {
			sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_ACCESS_DENIED))
			return
		}
		sendTestResponse(dt, reqBuf, &wire.IoctlResponse{Output: rawEncoder(make([]byte, 32))}, 0)
	case wire.FSCTL_SRV_COPYCHUNK, wire.FSCTL_SRV_COPYCHUNK_WRITE:
		s.handleCopyChunk(dt, reqBuf, req.CtlCode())
	default:
		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_NOT_SUPPORTED))
	}
}

func (s *copyPermissionServer) handleCopyChunk(dt Transport, reqBuf []byte, ctlCode uint32) {
	req := wire.IoctlRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.copyRequests++
	copyRequest := s.copyRequests
	s.copyCtlCodes = append(s.copyCtlCodes, ctlCode)
	dstFile := s.files[fileIdKey(req.FileId().Decode())]
	source := s.source
	s.mu.Unlock()

	reject := func(status erref.NtStatus) {
		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(status))
	}

	if s.config.rejectCopyStatus != 0 {
		reject(s.config.rejectCopyStatus)
		return
	}
	if ctlCode == wire.FSCTL_SRV_COPYCHUNK_WRITE && s.config.rejectWriteCtlStatus != 0 {
		reject(s.config.rejectWriteCtlStatus)
		return
	}
	if s.config.failCopyRequest != 0 && copyRequest == s.config.failCopyRequest {
		reject(s.config.failCopyStatus)
		return
	}

	// [MS-SMB2] 2.2.31: FSCTL_SRV_COPYCHUNK requires FILE_READ_DATA on the
	// destination handle; FSCTL_SRV_COPYCHUNK_WRITE only requires write access.
	if source == nil || source.access&(wire.FILE_READ_DATA|wire.GENERIC_READ|wire.GENERIC_ALL) == 0 ||
		dstFile == nil || dstFile.access&(wire.FILE_WRITE_DATA|wire.FILE_APPEND_DATA|wire.GENERIC_WRITE|wire.GENERIC_ALL) == 0 {
		reject(erref.STATUS_ACCESS_DENIED)
		return
	}
	if ctlCode == wire.FSCTL_SRV_COPYCHUNK {
		if dstFile.access&(wire.FILE_READ_DATA|wire.GENERIC_READ|wire.GENERIC_ALL) == 0 {
			reject(erref.STATUS_ACCESS_DENIED)
			return
		}
	}

	inputOffset := uint64(req.InputOffset())
	inputCount := uint64(req.InputCount())
	if inputCount < 32 || inputOffset > uint64(len(reqBuf)) || inputCount > uint64(len(reqBuf))-inputOffset {
		reject(erref.STATUS_INVALID_PARAMETER)
		return
	}
	input := reqBuf[inputOffset : inputOffset+inputCount]
	chunkCount := uint64(le.Uint32(input[24:28]))
	if chunkCount > uint64(len(input)-32)/24 {
		reject(erref.STATUS_INVALID_PARAMETER)
		return
	}

	s.mu.Lock()
	var total uint32
	for i := range chunkCount {
		off := 32 + i*24
		sourceOffset := int64(le.Uint64(input[off : off+8]))
		targetOffset := int64(le.Uint64(input[off+8 : off+16]))
		length := le.Uint32(input[off+16 : off+20])
		if sourceOffset < 0 || sourceOffset > int64(len(source.content)) || int64(length) > int64(len(source.content))-sourceOffset ||
			targetOffset < 0 || targetOffset > s.config.sourceSize || int64(length) > s.config.sourceSize-targetOffset {
			s.mu.Unlock()
			reject(erref.STATUS_INVALID_PARAMETER)
			return
		}
		end := targetOffset + int64(length)
		if end > int64(len(dstFile.content)) {
			dstFile.content = append(dstFile.content, make([]byte, end-int64(len(dstFile.content)))...)
		}
		copy(dstFile.content[targetOffset:], source.content[sourceOffset:sourceOffset+int64(length)])
		total += length
	}
	s.mu.Unlock()

	respBuf := make([]byte, 12)
	le.PutUint32(respBuf[0:4], uint32(chunkCount))
	// [MS-SMB2] 3.3.5.15.6 requires ChunkBytesWritten to be zero on success.
	le.PutUint32(respBuf[8:12], total)
	sendTestResponse(dt, reqBuf, &wire.IoctlResponse{Output: rawEncoder(respBuf)}, 0)
}

func (s *copyPermissionServer) content(id *wire.FileId) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.files[fileIdKey(id)]
	if f == nil {
		return nil
	}
	return append([]byte(nil), f.content...)
}

func (s *copyPermissionServer) sourceContent() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.source.content...)
}

func (s *copyPermissionServer) snapshot() (ctlCodes []uint32, reads, writes, copies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.copyCtlCodes...), s.readRequests, s.writeRequests, s.copyRequests
}

type copyPath struct {
	name string
	run  func(src, dst *File) (int64, error)
}

func copyPaths() []copyPath {
	return []copyPath{
		{name: "ReadFrom", run: func(src, dst *File) (int64, error) {
			return dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
		}},
		{name: "WriteTo", run: func(src, dst *File) (int64, error) {
			return src.WriteTo(context.Background(), dst.WithContext(context.Background()))
		}},
		{name: "io.Copy", run: func(src, dst *File) (int64, error) {
			return io.Copy(dst.WithContext(context.Background()), src.WithContext(context.Background()))
		}},
	}
}

func TestCopyFileWriteOnlyDestinationUsesWriteVariant(t *testing.T) {
	t.Parallel()
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{sourceSize: sourceSize})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileReadWriteDestinationUsesCopyChunk(t *testing.T) {
	t.Parallel()
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			// The server rejects FSCTL_SRV_COPYCHUNK_WRITE, proving a read/write
			// destination never relies on it.
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:           sourceSize,
				rejectWriteCtlStatus: erref.STATUS_NOT_SUPPORTED,
			})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileWriteVariantUnsupportedFallsBackToNormalCopy(t *testing.T) {
	t.Parallel()
	const sourceSize = 150 * 1024

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
						sourceSize:           sourceSize,
						rejectWriteCtlStatus: status.status,
					})

					src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
					require.NoError(t, err)
					defer src.Close(context.Background())

					dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
					require.NoError(t, err)
					defer dst.Close(context.Background())

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(sourceSize), n)
					require.Equal(t, int64(sourceSize), src.offset)
					require.Equal(t, int64(sourceSize), dst.offset)
					require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

					codes, reads, writes, copies := srv.snapshot()
					require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
					require.Equal(t, 1, copies)
					require.Greater(t, reads, 0)
					require.Greater(t, writes, 0)
				})
			}
		})
	}
}

func TestCopyFileAccessDeniedDoesNotFallBack(t *testing.T) {
	t.Parallel()
	const sourceSize = 150 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:       sourceSize,
				rejectCopyStatus: erref.STATUS_ACCESS_DENIED,
			})

			src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close(context.Background())

			dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close(context.Background())

			n, err := tc.run(src, dst)
			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
			require.Equal(t, int64(0), src.offset)
			require.Equal(t, int64(0), dst.offset)

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
			require.Empty(t, srv.content(dst.fd))
		})
	}
}

func TestCopyFileWriteVariantFailureAfterFirstBatchPreservesProgress(t *testing.T) {
	t.Parallel()
	const firstBatch = int64(16 * 1024 * 1024)
	const sourceSize = firstBatch + 1024*1024

	fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
		sourceSize:      sourceSize,
		failCopyRequest: 2,
		failCopyStatus:  erref.STATUS_NOT_SUPPORTED,
	})

	src, err := fs.OpenFile(context.Background(), "src.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer src.Close(context.Background())

	dst, err := fs.OpenFile(context.Background(), "dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	require.NoError(t, err)
	defer dst.Close(context.Background())

	n, err := dst.ReadFrom(context.Background(), src.WithContext(context.Background()))
	require.Equal(t, firstBatch, n)
	require.ErrorIs(t, err, erref.STATUS_NOT_SUPPORTED)
	require.Equal(t, firstBatch, src.offset)
	require.Equal(t, firstBatch, dst.offset)

	codes, reads, writes, copies := srv.snapshot()
	require.Equal(t, []uint32{wire.FSCTL_SRV_COPYCHUNK_WRITE, wire.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
	require.Equal(t, 2, copies)
	require.Equal(t, 0, reads)
	require.Equal(t, 0, writes)
	require.Equal(t, srv.sourceContent()[:firstBatch], srv.content(dst.fd))
}

func TestCopyFile_RejectsShortTotalBytesWritten(t *testing.T) {
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
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go c.runReceiver()

	const totalFileSize = 100

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt Transport) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			ires := &wire.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.writev(resBuf)
			return true
		} else if ctlCode == wire.FSCTL_SRV_COPYCHUNK {
			// Sum up the chunk lengths requested by the client.
			reqData := reqBuf[64:]
			inputCount := int(le.Uint32(reqData[28:32]))
			input := reqData[56 : 56+inputCount] // SrvCopychunkCopy
			reqTotal := uint64(0)
			chunks := le.Uint32(input[24:28])
			for i := range chunks {
				off := 32 + i*24
				reqTotal += uint64(le.Uint32(input[off+16 : off+20]))
			}

			// Respond with a SrvCopychunkResponse reporting one byte less than requested.
			respBuf := make([]byte, 12)
			le.PutUint32(respBuf[0:4], chunks)
			le.PutUint32(respBuf[4:8], uint32(reqTotal-1))  // ChunksBytesWritten
			le.PutUint32(respBuf[8:12], uint32(reqTotal-1)) // TotalBytesWritten
			ires := &wire.IoctlResponse{Output: rawEncoder(respBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.writev(resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], totalFileSize) // EndOfFile = 100
		qres := &wire.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := &wire.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(context.Background(), srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.True(t, supported)
	require.Error(t, err, "copyFile must fail when TotalBytesWritten is less than the requested bytes")

	var linkErr *os.LinkError
	require.True(t, errors.As(err, &linkErr))
	require.Equal(t, "copy", linkErr.Op)
	require.Equal(t, "src.txt", linkErr.Old)
	require.Equal(t, "dst.txt", linkErr.New)

	var invalidResp *InvalidResponseError
	require.True(t, errors.As(linkErr.Err, &invalidResp))
	require.Equal(t, "srv copy chunk wrote fewer bytes than requested", invalidResp.Message)

	require.Equal(t, int64(0), n)
}

func TestShareStatUsesCompoundCreateClose(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	var recordedCmds []wire.Command
	var createOptions uint32
	var createCount, closeCount int

	go func() {
		dt := NewTransport(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := wire.PacketCodec(currBuf)
			cmd := p.Command()
			recordedCmds = append(recordedCmds, cmd)

			var resBuf []byte
			switch cmd {
			case wire.SMB2_CREATE:
				createCount++
				req := wire.CreateRequestDecoder(currBuf[64:])
				createOptions = req.CreateOptions()
				cres := &wire.CreateResponse{
					CreationTime:   &wire.Filetime{LowDateTime: 0x11223344, HighDateTime: 0x01234567},
					LastAccessTime: &wire.Filetime{LowDateTime: 0x55667788, HighDateTime: 0x01234567},
					LastWriteTime:  &wire.Filetime{LowDateTime: 0x99aabbcc, HighDateTime: 0x01234567},
					ChangeTime:     &wire.Filetime{LowDateTime: 0xddeeff00, HighDateTime: 0x01234567},
					AllocationSize: 8192,
					EndofFile:      4096,
					FileAttributes: wire.FILE_ATTRIBUTE_ARCHIVE,
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case wire.SMB2_CLOSE:
				closeCount++
				clres := &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				resBuf = make([]byte, clres.Size())
				clres.Encode(resBuf)
			}

			if resBuf != nil {
				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
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
					wire.PacketCodec(padded).SetNextCommand(nextCmd)
					finalBuf = append(finalBuf, padded...)
				} else {
					finalBuf = append(finalBuf, rb...)
				}
			}
			_, _ = dt.writev(finalBuf)
		}
	}()

	fi, err := fs.Stat(context.Background(), "test.txt")
	require.NoError(t, err)
	require.NotNil(t, fi)

	require.Equal(t, "test.txt", fi.Name())
	require.Equal(t, int64(4096), fi.Size())
	require.False(t, fi.IsDir())

	fst, ok := fi.(*FileStat)
	require.True(t, ok)
	require.Equal(t, uint32(wire.FILE_ATTRIBUTE_ARCHIVE), fst.FileAttributes)
	require.Equal(t, int64(8192), fst.AllocationSize)

	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(0), createOptions, "Share.Stat must not set FILE_OPEN_REPARSE_POINT")
	require.Equal(t, 1, createCount)
	require.Equal(t, 1, closeCount)
}

func TestReadFileRejectsUnreasonableEndOfFile(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	createReady := make(chan struct{})
	go func() {
		<-createReady
		// Stop the fake server from supplying an effectively unlimited file.
		time.Sleep(10 * time.Millisecond)
		serverConn.Close()
	}()
	startFullFakeServer(serverConn, nil, nil, nil, func(req wire.CreateRequestDecoder, cres *wire.CreateResponse) {
		cres.EndofFile = int64(^uint64(0) >> 1) // max int64
		close(createReady)
	})

	var err error
	require.NotPanics(t, func() {
		_, err = fs.ReadFile(context.Background(), "test.txt")
	})
	require.Error(t, err)
}

func TestReadFile_EmptyFile(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	expectedFileId := &wire.FileId{
		Persistent: [8]byte{3, 4, 5, 6, 7, 8, 9, 10},
		Volatile:   [8]byte{11, 12, 13, 14, 15, 16, 17, 18},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + read (ReadFile)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: Read ErrorResponse STATUS_END_OF_FILE (empty file)
		errPkt1 := &wire.ErrorResponse{
			CommandCode: wire.SMB2_READ,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		wire.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
		wire.PacketCodec(resBuf1).SetSessionId(p.SessionId())
		wire.PacketCodec(resBuf1).SetTreeId(p.TreeId())
		wire.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_END_OF_FILE))
		wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(resBuf1).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.writev(compound)

		// Request 2: automatic close of the opened file handle
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeReq := wire.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}
	}()

	data, err := fs.ReadFile(context.Background(), "test.txt")
	require.NoError(t, err, "reading an empty file must not fail")
	require.NotNil(t, data, "reading an empty file must return a non-nil empty slice")
	require.Len(t, data, 0)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle")
}

func TestShare_ReadFile_StatusBufferOverflowFallback(t *testing.T) {
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
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}

	go c.runReceiver()

	dt := NewTransport(serverConn)
	fileId1 := &wire.FileId{Persistent: [8]byte{1, 1}, Volatile: [8]byte{2, 2}}
	fileId2 := &wire.FileId{Persistent: [8]byte{3, 3}, Volatile: [8]byte{4, 4}}

	done := make(chan struct{})
	go func() {
		defer close(done)

		// Request 1: compound CREATE + READ
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		p1 := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS (EndofFile = 12)
		cres1 := &wire.CreateResponse{
			FileId:         fileId1,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
			EndofFile:      12,
		}
		resBuf0 := make([]byte, cres1.Size())
		cres1.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p1.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p1.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p1.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: ReadResponse with STATUS_BUFFER_OVERFLOW and partial data "hello"
		partialData := []byte("hello")
		rres := &wire.ReadResponse{Data: partialData}
		resBuf1 := make([]byte, rres.Size())
		rres.Encode(resBuf1)
		wire.PacketCodec(resBuf1).SetMessageId(p1.MessageId() + 1)
		wire.PacketCodec(resBuf1).SetSessionId(p1.SessionId())
		wire.PacketCodec(resBuf1).SetTreeId(p1.TreeId())
		wire.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(resBuf1).SetCreditResponse(1)

		compound := append(padded0, resBuf1...)
		_, _ = dt.writev(compound)

		// Request 2: auto-close of fileId1 by tree_conn.sendRecv
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}

		// Request 3: fallback CREATE (single op, no compound)
		reqBuf3, err := readMsg(dt)
		if err != nil {
			return
		}
		p3 := wire.PacketCodec(reqBuf3)

		// CreateResponse SUCCESS with fileId2 (EndofFile = 12)
		cres2 := &wire.CreateResponse{
			FileId:         fileId2,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
			EndofFile:      12,
		}
		resBuf3 := make([]byte, cres2.Size())
		cres2.Encode(resBuf3)
		wire.PacketCodec(resBuf3).SetMessageId(p3.MessageId())
		wire.PacketCodec(resBuf3).SetSessionId(p3.SessionId())
		wire.PacketCodec(resBuf3).SetTreeId(p3.TreeId())
		wire.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(resBuf3).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(resBuf3).SetCreditResponse(1)
		_, _ = dt.writev(resBuf3)

		// Request 4: READ request at offset 5 for remaining 7 bytes (" world!")
		reqBuf4, err := readMsg(dt)
		if err != nil {
			return
		}
		p4 := wire.PacketCodec(reqBuf4)
		remainData := []byte(" world!")
		rres4 := &wire.ReadResponse{Data: remainData}
		resBuf4 := make([]byte, rres4.Size())
		rres4.Encode(resBuf4)
		rp4 := wire.PacketCodec(resBuf4)
		rp4.SetMessageId(p4.MessageId())
		rp4.SetSessionId(p4.SessionId())
		rp4.SetTreeId(p4.TreeId())
		rp4.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp4.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rp4.SetCreditResponse(1)
		_, _ = dt.writev(resBuf4)

		// Request 5: CLOSE of fileId2 by deferred file cleanup.
		reqBuf5, err := readMsg(dt)
		if err != nil {
			return
		}
		p5 := wire.PacketCodec(reqBuf5)
		closeRes2 := &wire.CloseResponse{
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}
		closeBuf2 := make([]byte, closeRes2.Size())
		closeRes2.Encode(closeBuf2)
		rp5 := wire.PacketCodec(closeBuf2)
		rp5.SetMessageId(p5.MessageId())
		rp5.SetSessionId(p5.SessionId())
		rp5.SetTreeId(p5.TreeId())
		rp5.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp5.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rp5.SetCreditResponse(1)
		_, _ = dt.writev(closeBuf2)
	}()

	data, err := fs.ReadFile(context.Background(), "test.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world!"), data)

	<-done
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
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc}

	// Initially, maxCredits = 1 -> capped to 1 * 64KB = 64KB
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))

	// Replenish to 4 credits (maxCreditBalance) -> capped to 4 * 64KB = 256KB
	c.account.charge(3)
	require.Equal(t, 256*1024, fs.maxReadSize(0))
	require.Equal(t, 256*1024, fs.maxWriteSize(0))
	require.Equal(t, 256*1024, fs.maxTransactSize(0))

	// If maxCreditBalance is large and credits are granted, scales up to winMaxPayloadSize (1MB)
	c.account.maxCreditBalance = 128
	c.account.charge(30)
	require.Equal(t, 1024*1024, fs.maxReadSize(0))
	require.Equal(t, 1024*1024, fs.maxWriteSize(0))
	require.Equal(t, 1024*1024, fs.maxTransactSize(0))
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
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc}

	// Replenish to maxCreditBalance so the cap is 4 * 64KB.
	c.account.charge(3)

	// A standalone request may use the whole credit cap.
	require.Equal(t, 256*1024, fs.maxReadSize(0))
	require.Equal(t, 256*1024, fs.maxWriteSize(0))
	require.Equal(t, 256*1024, fs.maxTransactSize(0))

	// A compound leaves room for its single-credit companions.
	require.Equal(t, 128*1024, fs.maxWriteSize(2))
	require.Equal(t, 128*1024, fs.maxTransactSize(2))
	require.Equal(t, 192*1024, fs.maxTransactSize(1))

	// Sizing never drops below a single credit.
	require.Equal(t, 64*1024, fs.maxTransactSize(8))
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
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc}

	// server advertises 32KB (< singleCreditMaxPayloadSize) -> respect it
	require.Equal(t, 32*1024, fs.maxReadSize(0))
	require.Equal(t, 32*1024, fs.maxWriteSize(0))
	require.Equal(t, 32*1024, fs.maxTransactSize(0))

	// non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))

	// without LARGE_MTU, server-advertised sizes are still respected
	c = &conn{
		account:         openAccount(4),
		capabilities:    0,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s = &session{conn: c}
	tc = &treeConn{session: s}
	fs = &Share{treeConn: tc}
	require.Equal(t, 32*1024, fs.maxReadSize(0))
	require.Equal(t, 32*1024, fs.maxWriteSize(0))
	require.Equal(t, 32*1024, fs.maxTransactSize(0))

	// without LARGE_MTU, non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))
}

func sendTestCompoundMidFailureResponse(dt Transport, req []byte, fileId *wire.FileId, status uint32) {
	createRes := &wire.CreateResponse{
		FileId:         fileId,
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)

	p := wire.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	wire.PacketCodec(padded1).SetMessageId(p.MessageId())
	wire.PacketCodec(padded1).SetSessionId(p.SessionId())
	wire.PacketCodec(padded1).SetTreeId(p.TreeId())
	wire.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	wire.PacketCodec(padded1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	wire.PacketCodec(padded1).SetNextCommand(next1)

	errPkt := &wire.ErrorResponse{
		CommandCode: wire.SMB2_SET_INFO,
	}
	resBuf2 := make([]byte, errPkt.Size())
	errPkt.Encode(resBuf2)
	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	wire.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	wire.PacketCodec(padded2).SetSessionId(p.SessionId())
	wire.PacketCodec(padded2).SetTreeId(p.TreeId())
	wire.PacketCodec(padded2).SetStatus(status)
	wire.PacketCodec(padded2).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(padded2).SetNextCommand(next2)

	closeErrPkt := &wire.ErrorResponse{
		CommandCode: wire.SMB2_CLOSE,
	}
	resBuf3 := make([]byte, closeErrPkt.Size())
	closeErrPkt.Encode(resBuf3)
	wire.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	wire.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	wire.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	wire.PacketCodec(resBuf3).SetStatus(status)
	wire.PacketCodec(resBuf3).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(resBuf3).SetCreditResponse(1)

	var compound []byte
	compound = append(compound, padded1...)
	compound = append(compound, padded2...)
	compound = append(compound, resBuf3...)

	_, _ = dt.writev(compound)
}

func TestCompoundMidFailureClosesServerHandle(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	expectedFileId := &wire.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + setInfo + close (Rename)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestCompoundMidFailureResponse(dt, reqBuf1, expectedFileId, uint32(erref.STATUS_ACCESS_DENIED))

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeReq := wire.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}
	}()

	err := fs.Rename(context.Background(), "old.txt", "new.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when compound fails mid-flight")
}

func TestReadFileCompoundFailureClosesServerHandle(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	expectedFileId := &wire.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryInfo + read (ReadFile)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryInfo ErrorResponse
		errPkt1 := &wire.ErrorResponse{
			CommandCode: wire.SMB2_QUERY_INFO,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		pad1 := (8 - (len(resBuf1) % 8)) % 8
		next1 := uint32(len(resBuf1) + pad1)
		padded1 := make([]byte, next1)
		copy(padded1, resBuf1)
		wire.PacketCodec(padded1).SetMessageId(p.MessageId() + 1)
		wire.PacketCodec(padded1).SetSessionId(p.SessionId())
		wire.PacketCodec(padded1).SetTreeId(p.TreeId())
		wire.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		wire.PacketCodec(padded1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(padded1).SetNextCommand(next1)

		// Op 2: Read ErrorResponse
		errPkt2 := &wire.ErrorResponse{
			CommandCode: wire.SMB2_READ,
		}
		resBuf2 := make([]byte, errPkt2.Size())
		errPkt2.Encode(resBuf2)
		wire.PacketCodec(resBuf2).SetMessageId(p.MessageId() + 2)
		wire.PacketCodec(resBuf2).SetSessionId(p.SessionId())
		wire.PacketCodec(resBuf2).SetTreeId(p.TreeId())
		wire.PacketCodec(resBuf2).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		wire.PacketCodec(resBuf2).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(resBuf2).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, padded1...)
		compound = append(compound, resBuf2...)
		_, _ = dt.writev(compound)

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeReq := wire.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}
	}()

	_, err := fs.ReadFile(context.Background(), "test.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when ReadFile fails mid-flight")
}

func TestReadDirCompoundFailureClosesServerHandle(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	expectedFileId := &wire.FileId{
		Persistent: [8]byte{2, 3, 4, 5, 6, 7, 8, 9},
		Volatile:   [8]byte{10, 11, 12, 13, 14, 15, 16, 17},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectory ErrorResponse
		errPkt1 := &wire.ErrorResponse{
			CommandCode: wire.SMB2_QUERY_DIRECTORY,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		wire.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
		wire.PacketCodec(resBuf1).SetSessionId(p.SessionId())
		wire.PacketCodec(resBuf1).SetTreeId(p.TreeId())
		wire.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		wire.PacketCodec(resBuf1).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.writev(compound)

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeReq := wire.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}
	}()

	_, err := fs.ReadDir(context.Background(), "some_dir")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle when ReadDir fails mid-flight")
}

func TestReadDir_EmptyDirectory(t *testing.T) {
	t.Parallel()
	// Some servers (e.g. Samba) report STATUS_NO_MORE_FILES or even
	// STATUS_NO_SUCH_FILE on the first QUERY_DIRECTORY of a compound
	// CREATE+QUERY_DIRECTORY when the directory has no entries.
	for _, status := range []erref.NtStatus{erref.STATUS_NO_MORE_FILES, erref.STATUS_NO_SUCH_FILE} {
		t.Run(status.Error(), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := NewTransport(serverConn)

			expectedFileId := &wire.FileId{
				Persistent: [8]byte{4, 5, 6, 7, 8, 9, 10, 11},
				Volatile:   [8]byte{12, 13, 14, 15, 16, 17, 18, 19},
			}

			var closeReceived atomic.Bool

			done := make(chan struct{})
			go func() {
				defer close(done)
				// Request 1: compound create + queryDir (ReadDir)
				reqBuf1, err := readMsg(dt)
				if err != nil {
					return
				}

				p := wire.PacketCodec(reqBuf1)

				// Op 0: CreateResponse SUCCESS
				createRes := &wire.CreateResponse{
					FileId:         expectedFileId,
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				resBuf0 := make([]byte, createRes.Size())
				createRes.Encode(resBuf0)
				pad0 := (8 - (len(resBuf0) % 8)) % 8
				next0 := uint32(len(resBuf0) + pad0)
				padded0 := make([]byte, next0)
				copy(padded0, resBuf0)
				wire.PacketCodec(padded0).SetMessageId(p.MessageId())
				wire.PacketCodec(padded0).SetSessionId(p.SessionId())
				wire.PacketCodec(padded0).SetTreeId(p.TreeId())
				wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
				wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				wire.PacketCodec(padded0).SetNextCommand(next0)

				// Op 1: QueryDirectory ErrorResponse
				errPkt1 := &wire.ErrorResponse{
					CommandCode: wire.SMB2_QUERY_DIRECTORY,
				}
				resBuf1 := make([]byte, errPkt1.Size())
				errPkt1.Encode(resBuf1)
				wire.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
				wire.PacketCodec(resBuf1).SetSessionId(p.SessionId())
				wire.PacketCodec(resBuf1).SetTreeId(p.TreeId())
				wire.PacketCodec(resBuf1).SetStatus(uint32(status))
				wire.PacketCodec(resBuf1).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
				wire.PacketCodec(resBuf1).SetCreditResponse(1)

				var compound []byte
				compound = append(compound, padded0...)
				compound = append(compound, resBuf1...)
				_, _ = dt.writev(compound)

				// Request 2: automatic fallback close request
				reqBuf2, err := readMsg(dt)
				if err != nil {
					return
				}
				p2 := wire.PacketCodec(reqBuf2)
				if p2.Command() == wire.SMB2_CLOSE {
					closeReq := wire.CloseRequestDecoder(p2.Body())
					if !closeReq.IsInvalid() {
						fd := closeReq.FileId().Decode()
						if *fd == *expectedFileId {
							closeReceived.Store(true)
						}
					}
					closeRes := &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}
					closeBuf := make([]byte, closeRes.Size())
					closeRes.Encode(closeBuf)
					rp := wire.PacketCodec(closeBuf)
					rp.SetMessageId(p2.MessageId())
					rp.SetSessionId(p2.SessionId())
					rp.SetTreeId(p2.TreeId())
					rp.SetStatus(uint32(erref.STATUS_SUCCESS))
					rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					rp.SetCreditResponse(1)
					_, _ = dt.writev(closeBuf)
				}
			}()

			fis, err := fs.ReadDir(context.Background(), "some_dir")
			require.NoError(t, err, "an empty directory must not fail")
			require.NotNil(t, fis, "an empty directory must return a non-nil slice")
			require.Len(t, fis, 0)

			<-done
			require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle")
		})
	}
}

// encodeFileIdBothDirEntry builds a FILE_ID_BOTH_DIR_INFORMATION entry
// (MS-FSCC 2.4.22) carrying a single file name.
func encodeFileIdBothDirEntry(name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
	entry := make([]byte, 104+len(nameBytes))
	le.PutUint64(entry[40:48], 1) // EndOfFile
	le.PutUint64(entry[48:56], 1) // AllocationSize
	le.PutUint32(entry[56:60], wire.FILE_ATTRIBUTE_NORMAL)
	le.PutUint32(entry[60:64], uint32(len(nameBytes))) // FileNameLength
	le.PutUint64(entry[96:104], 42)                    // FileId
	copy(entry[104:], nameBytes)
	return entry
}

// encodeQueryDirResponse builds a standalone SMB2 QUERY_DIRECTORY response
// packet carrying the given output buffer.
func encodeQueryDirResponse(msgId, sessionId uint64, treeId uint32, output []byte, status uint32, related bool) []byte {
	res := &wire.QueryDirectoryResponse{Output: rawEncoder(output)}
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	rp := wire.PacketCodec(resBuf)
	rp.SetMessageId(msgId)
	rp.SetSessionId(sessionId)
	rp.SetTreeId(treeId)
	rp.SetStatus(status)
	if related {
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	} else {
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	}
	rp.SetCreditResponse(1)
	return resBuf
}

func TestReadDirContinuesEnumerationWhenFirstResponseIsSmallerThanRequested(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	expectedFileId := &wire.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (Share.ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &wire.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		wire.PacketCodec(padded0).SetMessageId(p.MessageId())
		wire.PacketCodec(padded0).SetSessionId(p.SessionId())
		wire.PacketCodec(padded0).SetTreeId(p.TreeId())
		wire.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		wire.PacketCodec(padded0).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		wire.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectoryResponse with a single entry. The response is
		// far smaller than the requested OutputBufferLength (maxTransactSize),
		// but the server still has more entries to return.
		resBuf1 := encodeQueryDirResponse(p.MessageId()+1, p.SessionId(), p.TreeId(), encodeFileIdBothDirEntry("alpha.txt"), uint32(erref.STATUS_SUCCESS), true)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.writev(compound)

		// Request 2: follow-up queryDir issued by Readdir(-1); one more entry
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		resBuf2 := encodeQueryDirResponse(p2.MessageId(), p2.SessionId(), p2.TreeId(), encodeFileIdBothDirEntry("beta.txt"), uint32(erref.STATUS_SUCCESS), false)
		_, _ = dt.writev(resBuf2)

		// Request 3: follow-up queryDir; no more entries
		reqBuf3, err := readMsg(dt)
		if err != nil {
			return
		}
		p3 := wire.PacketCodec(reqBuf3)
		errPkt := &wire.ErrorResponse{
			CommandCode: wire.SMB2_QUERY_DIRECTORY,
		}
		errBuf := make([]byte, errPkt.Size())
		errPkt.Encode(errBuf)
		ep := wire.PacketCodec(errBuf)
		ep.SetMessageId(p3.MessageId())
		ep.SetSessionId(p3.SessionId())
		ep.SetTreeId(p3.TreeId())
		ep.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		ep.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		ep.SetCreditResponse(1)
		_, _ = dt.writev(errBuf)

		// Request 4: automatic close issued by ReadDir's deferred Close
		reqBuf4, err := readMsg(dt)
		if err != nil {
			return
		}
		p4 := wire.PacketCodec(reqBuf4)
		if p4.Command() == wire.SMB2_CLOSE {
			closeRes := &wire.CloseResponse{
				CreationTime:   &wire.Filetime{},
				LastAccessTime: &wire.Filetime{},
				LastWriteTime:  &wire.Filetime{},
				ChangeTime:     &wire.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := wire.PacketCodec(closeBuf)
			rp.SetMessageId(p4.MessageId())
			rp.SetSessionId(p4.SessionId())
			rp.SetTreeId(p4.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.writev(closeBuf)
		}
	}()

	fis, err := fs.ReadDir(context.Background(), "some_dir")
	require.NoError(t, err)

	names := make([]string, len(fis))
	for i, fi := range fis {
		names[i] = fi.Name()
	}
	require.Equal(t, []string{"alpha.txt", "beta.txt"}, names, "entries from subsequent query batches must not be dropped")

	<-done
}

func TestReadDirStopsAfterThreeDotOnlyPages(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)
	var queryCount int64 = 1 // The initial QUERY_DIRECTORY is compound with CREATE.
	done := make(chan struct{})
	go func() {
		defer close(done)

		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}
		p := wire.PacketCodec(reqBuf)

		createRes := &wire.CreateResponse{
			CreationTime:   &wire.Filetime{},
			LastAccessTime: &wire.Filetime{},
			LastWriteTime:  &wire.Filetime{},
			ChangeTime:     &wire.Filetime{},
			FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
		}
		createBuf := make([]byte, createRes.Size())
		createRes.Encode(createBuf)
		pad := (8 - (len(createBuf) % 8)) % 8
		paddedCreate := make([]byte, len(createBuf)+pad)
		copy(paddedCreate, createBuf)
		createPacket := wire.PacketCodec(paddedCreate)
		createPacket.SetMessageId(p.MessageId())
		createPacket.SetSessionId(p.SessionId())
		createPacket.SetTreeId(p.TreeId())
		createPacket.SetStatus(uint32(erref.STATUS_SUCCESS))
		createPacket.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		createPacket.SetNextCommand(uint32(len(paddedCreate)))

		queryBuf := encodeQueryDirResponse(
			p.MessageId()+1,
			p.SessionId(),
			p.TreeId(),
			encodeFileIdBothDirectoryInformations([]string{".", ".."}),
			uint32(erref.STATUS_SUCCESS),
			true,
		)
		_, _ = dt.writev(append(paddedCreate, queryBuf...))

		for {
			reqBuf, err = readMsg(dt)
			if err != nil {
				return
			}
			if wire.PacketCodec(reqBuf).Command() == wire.SMB2_CLOSE {
				sendTestResponse(dt, reqBuf, &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
				return
			}

			count := atomic.AddInt64(&queryCount, 1)
			if count <= 4 {
				sendTestResponse(dt, reqBuf, &wire.QueryDirectoryResponse{
					Output: rawEncoder(encodeFileIdBothDirectoryInformations([]string{".", ".."})),
				}, uint32(erref.STATUS_SUCCESS))
			} else {
				sendTestResponse(dt, reqBuf, &wire.ErrorResponse{
					CommandCode: wire.SMB2_QUERY_DIRECTORY,
				}, uint32(erref.STATUS_NO_MORE_FILES))
			}
		}
	}()

	_, err := fs.ReadDir(context.Background(), "testdir")
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "invalid response error: query directory returned only dot entries", invalid.Error())
	require.EqualValues(t, 4, atomic.LoadInt64(&queryCount))
	<-done
}

func TestReaddirContinuesPastSplitDotEntries(t *testing.T) {
	t.Parallel()
	dot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{"."})}
	dotdot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{".."})}
	visible := queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("visible.txt")}
	end := queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)}

	cases := []struct {
		name  string
		pages []queryDirectoryPage
		want  []string
	}{
		{
			name:  "single dot page then entry",
			pages: []queryDirectoryPage{dot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then entry",
			pages: []queryDirectoryPage{dot, dotdot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then end of enumeration",
			pages: []queryDirectoryPage{dot, dotdot, end},
			want:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "testdir")
			queryCount := startQueryDirectoryPages(t, serverConn, tc.pages...)

			fis, err := f.Readdir(context.Background(), -1)
			require.NoError(t, err)
			names := make([]string, len(fis))
			for i, fi := range fis {
				names[i] = fi.Name()
			}
			require.Equal(t, tc.want, names)
			require.EqualValues(t, len(tc.pages), atomic.LoadInt64(queryCount))
		})
	}
}

func TestShareChmodUsesCreateAttributes(t *testing.T) {
	t.Parallel()
	for _, status := range []erref.NtStatus{erref.STATUS_SUCCESS, erref.STATUS_ACCESS_DENIED} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := NewTransport(serverConn)
			fileID := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			const initialAttrs = wire.FILE_ATTRIBUTE_READONLY | wire.FILE_ATTRIBUTE_HIDDEN | wire.FILE_ATTRIBUTE_SYSTEM
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverConn.Close()
				create, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p := wire.PacketCodec(create)
				assert.Equal(t, wire.SMB2_CREATE, p.Command())
				assert.Zero(t, p.NextCommand(), "CREATE must not include QUERY_INFO")
				sendTestCreateAttributesResponse(dt, create, fileID, initialAttrs)

				set, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p = wire.PacketCodec(set)
				assert.Equal(t, wire.SMB2_SET_INFO, p.Command())
				assert.Zero(t, p.NextCommand())
				req := wire.SetInfoRequestDecoder(p.Body())
				assert.Equal(t, *fileID, *req.FileId().Decode())
				base := wire.FileBasicInformationDecoder(p[req.BufferOffset():])
				assert.Equal(t, uint32(wire.FILE_ATTRIBUTE_NORMAL|wire.FILE_ATTRIBUTE_HIDDEN|wire.FILE_ATTRIBUTE_SYSTEM), base.FileAttributes())
				if status == erref.STATUS_SUCCESS {
					sendTestResponse(dt, set, &wire.SetInfoResponse{}, uint32(status))
				} else {
					sendTestResponse(dt, set, &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, uint32(status))
				}

				closeReq, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p = wire.PacketCodec(closeReq)
				assert.Equal(t, wire.SMB2_CLOSE, p.Command())
				assert.Equal(t, *fileID, *wire.CloseRequestDecoder(p.Body()).FileId().Decode())
				sendTestCloseResponse(dt, closeReq)
			}()
			err := fs.Chmod(context.Background(), "file.txt", 0o644)
			<-done
			if status == erref.STATUS_SUCCESS {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, status)
			}
		})
	}
}

func TestStatfs_RegularFilePath(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, path string, sectorsPerAllocationUnit uint32, expectedBlockSize uint64) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   NewTransport(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()
		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc}

		go c.runReceiver()

		done := make(chan struct{})
		go func() {
			defer close(done)
			dt := NewTransport(serverConn)
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			// The fake server accepts the CREATE only when it does not force
			// FILE_DIRECTORY_FILE, mirroring how a real server rejects
			// opening a regular file as a directory with
			// STATUS_NOT_A_DIRECTORY.
			notADirectory := false
			curr := reqBuf
			for {
				p := wire.PacketCodec(curr)
				if p.Command() == wire.SMB2_CREATE &&
					wire.CreateRequestDecoder(curr[64:]).CreateOptions()&wire.FILE_DIRECTORY_FILE != 0 {
					notADirectory = true
					break
				}
				if p.NextCommand() == 0 {
					break
				}
				curr = curr[p.NextCommand():]
			}

			curr = reqBuf
			for {
				p := wire.PacketCodec(curr)
				msgId := p.MessageId()
				cmd := p.Command()

				var resBuf []byte
				switch {
				case notADirectory:
					resBuf = make([]byte, 64+8)
					le.PutUint16(resBuf[64:66], 9) // ErrorResponse StructureSize
					rp := wire.PacketCodec(resBuf)
					rp.SetProtocolId()
					rp.SetStructureSize()
					rp.SetCommand(cmd)
					rp.SetStatus(uint32(erref.STATUS_NOT_A_DIRECTORY))
				case cmd == wire.SMB2_CREATE:
					cres := &wire.CreateResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
						FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)
				case cmd == wire.SMB2_QUERY_INFO:
					// FileFsFullSizeInformation (32 bytes)
					info := make([]byte, 32)
					le.PutUint64(info[0:8], 1000)                       // TotalAllocationUnits
					le.PutUint64(info[8:16], 600)                       // CallerAvailableAllocationUnits
					le.PutUint64(info[16:24], 500)                      // ActualAvailableAllocationUnits
					le.PutUint32(info[24:28], sectorsPerAllocationUnit) // SectorsPerAllocationUnit
					le.PutUint32(info[28:32], 512)                      // BytesPerSector
					qres := &wire.QueryInfoResponse{Output: rawEncoder(info)}
					resBuf = make([]byte, qres.Size())
					qres.Encode(resBuf)
				default: // SMB2_CLOSE
					clres := &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(0x100)
				rp.SetTreeId(0x200)
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)

				if _, err := dt.writev(resBuf); err != nil {
					return
				}

				if p.NextCommand() == 0 {
					return
				}
				curr = curr[p.NextCommand():]
			}
		}()

		info, err := fs.Statfs(context.Background(), path)
		require.NoError(t, err)
		require.Equal(t, expectedBlockSize, info.BlockSize())
		require.Equal(t, uint64(sectorsPerAllocationUnit), info.FragmentSize())
		require.Equal(t, uint64(1000), info.TotalBlockCount())
		require.Equal(t, uint64(500), info.FreeBlockCount())
		require.Equal(t, uint64(600), info.AvailableBlockCount())
		require.Equal(t, uint64(1000)*expectedBlockSize, info.TotalBlockCount()*info.BlockSize())
		require.Equal(t, uint64(500)*expectedBlockSize, info.FreeBlockCount()*info.BlockSize())
		require.Equal(t, uint64(600)*expectedBlockSize, info.AvailableBlockCount()*info.BlockSize())
	}

	t.Run("regular file", func(t *testing.T) {
		run(t, "file.txt", 8, 4096)
	})

	t.Run("directory", func(t *testing.T) {
		run(t, "dir", 8, 4096)
	})

	t.Run("single-sector allocation unit", func(t *testing.T) {
		run(t, "file.txt", 1, 512)
	})

	t.Run("allocation unit exceeds 32 bits", func(t *testing.T) {
		run(t, "file.txt", 1<<23, 1<<32)
	})
}

func TestIoctlResponseSumExceedsMaxTransactSize(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	c.maxTransactSize = 65536
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fs := &Share{treeConn: &treeConn{session: c.session, treeId: 1}}
	require.Equal(t, 65536, fs.maxTransactSize(0))
	req := &wire.IoctlRequest{
		CtlCode:           wire.FSCTL_PIPE_TRANSCEIVE,
		Flags:             wire.SMB2_0_IOCTL_IS_FSCTL,
		Input:             rawEncoder([]byte{1}),
		MaxInputResponse:  65536,
		MaxOutputResponse: 1,
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := fs.ioctl(ctx, &wire.FileId{}, req)
		errCh <- err
	}()

	require.NoError(t, serverConn.SetDeadline(time.Now().Add(2*time.Second)))
	dt := NewTransport(serverConn)
	encoded, err := readMsg(dt)
	require.NoError(t, err)
	packet := wire.PacketCodec(encoded)
	require.Equal(t, wire.SMB2_IOCTL, packet.Command())
	require.Equal(t, uint16(2), packet.CreditCharge())
	wireReq := wire.IoctlRequestDecoder(packet.Body())
	require.Equal(t, uint32(1), wireReq.InputCount())
	require.Equal(t, uint32(65536), wireReq.MaxInputResponse())
	require.Equal(t, uint32(1), wireReq.MaxOutputResponse())
	require.Zero(t, wireReq.OutputCount())
	sendTestResponse(dt, encoded, &wire.IoctlResponse{
		CtlCode: req.CtlCode,
		Flags:   wire.SMB2_0_IOCTL_IS_FSCTL,
		Output:  rawEncoder([]byte{1}),
	}, 0)
	require.NoError(t, <-errCh)
}

// fakeServerFull processes SMB2 commands for comprehensive benchmarks, including compound request chains.
func fakeServerFull(t Transport, responseData []byte, dirEntries []byte, sessionId uint64) {
	dirQueryCount := 0

	for {
		rp, err := t.readPacket()
		if err != nil {
			return
		}
		reqBuf := rp.bytes()
		sz := len(reqBuf)

		off := 0
		var respBufs [][]byte

		for {
			p := wire.PacketCodec(reqBuf[off:sz])
			cmd := p.Command()
			msgId := p.MessageId()
			nextCmd := p.NextCommand()

			var singleResp []byte

			switch cmd {
			case wire.SMB2_CREATE:
				cres := &wire.CreateResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					OplockLevel:    wire.SMB2_OPLOCK_LEVEL_NONE,
					CreateAction:   1, // FILE_OPENED
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
					AllocationSize: int64(len(responseData)),
					EndofFile:      int64(len(responseData)),
					FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				singleResp = make([]byte, cres.Size())
				cres.Encode(singleResp)

			case wire.SMB2_CLOSE:
				clres := &wire.CloseResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				singleResp = make([]byte, clres.Size())
				clres.Encode(singleResp)

			case wire.SMB2_QUERY_DIRECTORY:
				dirQueryCount++
				if dirQueryCount%2 == 1 && dirEntries != nil {
					qdres := &wire.QueryDirectoryResponse{
						PacketHeader: wire.PacketHeader{
							Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
							SessionId: sessionId,
						},
						Output: rawEncoder(dirEntries),
					}
					singleResp = make([]byte, qdres.Size())
					qdres.Encode(singleResp)
				} else {
					eres := &wire.ErrorResponse{
						PacketHeader: wire.PacketHeader{
							Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
							SessionId: sessionId,
							Status:    0x80000006, // STATUS_NO_MORE_FILES
						},
						CommandCode: wire.SMB2_QUERY_DIRECTORY,
					}
					singleResp = make([]byte, eres.Size())
					eres.Encode(singleResp)
				}

			case wire.SMB2_QUERY_INFO:
				stdBuf := make([]byte, 104)
				binary.LittleEndian.PutUint64(stdBuf[40:48], uint64(len(responseData))) // AllocationSize
				binary.LittleEndian.PutUint64(stdBuf[48:56], uint64(len(responseData))) // EndOfFile
				binary.LittleEndian.PutUint32(stdBuf[56:60], 1)                         // NumberOfLinks
				binary.LittleEndian.PutUint32(stdBuf[64:68], uint32(wire.FILE_ATTRIBUTE_NORMAL))

				qires := &wire.QueryInfoResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Output: rawEncoder(stdBuf),
				}
				singleResp = make([]byte, qires.Size())
				qires.Encode(singleResp)

			case wire.SMB2_WRITE:
				wreq := wire.WriteRequestDecoder(reqBuf[off+64 : sz])
				wres := &wire.WriteResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Count: wreq.Length(),
				}
				singleResp = make([]byte, wres.Size())
				wres.Encode(singleResp)

			case wire.SMB2_READ:
				rreq := wire.ReadRequestDecoder(reqBuf[off+64 : sz])
				readLen := min(int(rreq.Length()), len(responseData))
				resp := &wire.ReadResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Data: responseData[:readLen],
				}
				singleResp = make([]byte, resp.Size())
				resp.Encode(singleResp)

			default:
				eres := &wire.ErrorResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
						Status:    0xC0000002, // STATUS_NOT_IMPLEMENTED
					},
				}
				singleResp = make([]byte, eres.Size())
				eres.Encode(singleResp)
			}

			rp := wire.PacketCodec(singleResp)
			rp.SetMessageId(msgId)
			rp.SetCreditResponse(p.CreditRequest())

			respBufs = append(respBufs, singleResp)

			if nextCmd == 0 {
				break
			}
			off += int(nextCmd)
		}

		var totalRespLen int
		for i, rb := range respBufs {
			if i < len(respBufs)-1 {
				padded := (len(rb) + 7) &^ 7
				totalRespLen += padded
			} else {
				totalRespLen += len(rb)
			}
		}

		compoundResp := make([]byte, totalRespLen)
		curr := 0
		for i, rb := range respBufs {
			copy(compoundResp[curr:], rb)
			if i < len(respBufs)-1 {
				padded := (len(rb) + 7) &^ 7
				wire.PacketCodec(compoundResp[curr:]).SetNextCommand(uint32(padded))
				curr += padded
			}
		}

		rp.close()
		if _, err := t.writev(compoundResp); err != nil {
			return
		}
	}
}

func BenchmarkReadFile(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: wire.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			tc := &treeConn{session: c.session}
			fs := &Share{treeConn: tc}

			responseData := make([]byte, sz.n)
			go fakeServerFull(NewTransport(serverConn), responseData, nil, 0)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				data, err := fs.ReadFile(context.Background(), "test.txt")
				if err != nil {
					b.Fatal(err)
				}
				if len(data) != sz.n {
					b.Fatalf("short read: %d != %d", len(data), sz.n)
				}
			}
		})
	}
}

func BenchmarkWriteFile(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: wire.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			tc := &treeConn{session: c.session}
			fs := &Share{treeConn: tc}

			go fakeServerFull(NewTransport(serverConn), nil, nil, 0)

			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				err := fs.WriteFile(context.Background(), "test.txt", buf, 0666)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStat(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	c.session = &session{
		conn:         c,
		sessionFlags: wire.SMB2_SESSION_FLAG_IS_GUEST,
	}
	c.enableSession()

	tc := &treeConn{session: c.session}
	fs := &Share{treeConn: tc}

	go fakeServerFull(NewTransport(serverConn), nil, nil, 0)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := fs.Stat(context.Background(), "test.txt")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// writeFileServerState records the CREATE arguments and the file content seen
// by the mock server so tests can verify what the client actually requested.
type writeFileServerState struct {
	mu       sync.Mutex
	content  []byte
	accesses []uint32
	attrs    []uint32
}

func (s *writeFileServerState) snapshot() (content []byte, accesses, attrs []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.content...), append([]uint32(nil), s.accesses...), append([]uint32(nil), s.attrs...)
}

// serveWriteFile answers CREATE/WRITE/CLOSE for both the compound fast path and
// the single-request large-data path. A CREATE that asks for DACL modification
// rights is denied, while GENERIC_WRITE and its constituent rights are allowed.
func serveWriteFile(t *testing.T, dt Transport, state *writeFileServerState) {
	t.Helper()

	for {
		req, err := readMsg(dt)
		if err != nil {
			return
		}

		var offsets []int
		for off := 0; ; {
			if len(req)-off < 64 {
				t.Error("truncated compound header")
				return
			}
			offsets = append(offsets, off)
			next := wire.PacketCodec(req[off:]).NextCommand()
			if next == 0 {
				break
			}
			if next < 64 || next%8 != 0 || uint64(next) > uint64(len(req)-off-64) {
				t.Error("invalid compound offset")
				return
			}
			off += int(next)
		}

		denied := false
		for i, off := range offsets {
			end := len(req)
			if i+1 < len(offsets) {
				end = offsets[i+1]
			}
			p := wire.PacketCodec(req[off:end])

			if denied {
				// A related compound still receives a response for every
				// operation after a failure ([MS-SMB2] 3.3.5.2.7.2), so the
				// client never waits for a response that will not come.
				sendTestResponse(dt, req[off:], &wire.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_INVALID_PARAMETER))
				continue
			}

			switch p.Command() {
			case wire.SMB2_CREATE:
				cr := wire.CreateRequestDecoder(p.Body())
				if cr.IsInvalid() {
					t.Error("invalid CREATE request")
					return
				}
				state.mu.Lock()
				state.accesses = append(state.accesses, cr.DesiredAccess())
				state.attrs = append(state.attrs, cr.FileAttributes())
				state.content = state.content[:0]
				state.mu.Unlock()

				// WRITE_DAC is the right to modify the DACL and is not part of
				// GENERIC_WRITE ([MS-SMB2] 2.2.13.1.1). A server that does not
				// grant it fails the open ([MS-SMB2] 3.3.5.9).
				if cr.DesiredAccess()&wire.WRITE_DAC != 0 {
					sendTestResponse(dt, req[off:], &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
					denied = true
				} else {
					sendTestResponse(dt, req[off:], &wire.CreateResponse{CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{}, LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{}, FileId: &wire.FileId{}}, 0)
				}
			case wire.SMB2_WRITE:
				wr := wire.WriteRequestDecoder(p.Body())
				if wr.IsInvalid() {
					t.Error("invalid WRITE request")
					return
				}
				start, length := uint64(wr.DataOffset()), uint64(wr.Length())
				if start < 112 || start > uint64(len(p)) || length > uint64(len(p))-start ||
					wr.Offset() > uint64(int(^uint(0)>>1))-length {
					t.Error("invalid WRITE bounds")
					return
				}
				data := p[start : start+length]
				state.mu.Lock()
				if end := int(wr.Offset()) + len(data); end > len(state.content) {
					state.content = append(state.content, make([]byte, end-len(state.content))...)
				}
				copy(state.content[int(wr.Offset()):], data)
				state.mu.Unlock()
				sendTestResponse(dt, req[off:], &wire.WriteResponse{Count: wr.Length()}, 0)
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req[off:], &wire.CloseResponse{CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{}, LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{}}, 0)
			default:
				t.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}
}

func TestWriteFileDesiredAccess(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	f.fs.conn.maxWriteSize = 65536

	state := &writeFileServerState{}
	go serveWriteFile(t, NewTransport(serverConn), state)

	share := f.fs

	limit := f.fs.maxWriteSize(2)

	fastPath := make([]byte, limit)
	for i := range fastPath {
		fastPath[i] = byte(i)
	}
	largePath := make([]byte, limit+1)
	for i := range largePath {
		largePath[i] = byte(i*7 + 1)
	}

	// Fast path: a single compound CREATE+WRITE+CLOSE.
	require.NoError(t, share.WriteFile(context.Background(), "test.txt", fastPath, 0600))
	content, accesses, _ := state.snapshot()
	require.Equal(t, fastPath, content)
	require.Equal(t, []uint32{wire.GENERIC_WRITE}, accesses)

	// Large-data path: OpenFile with GENERIC_WRITE followed by chunked writes.
	require.NoError(t, share.WriteFile(context.Background(), "test.txt", largePath, 0600))
	content, accesses, _ = state.snapshot()
	require.Equal(t, largePath, content)
	require.Equal(t, []uint32{wire.GENERIC_WRITE, wire.GENERIC_WRITE}, accesses)
}

func TestWriteFileFastPathFileAttributes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{"writable", 0600, wire.FILE_ATTRIBUTE_NORMAL},
		{"readonly", 0400, wire.FILE_ATTRIBUTE_NORMAL | wire.FILE_ATTRIBUTE_READONLY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, serverConn := newTestFile(t)
			f.fs.conn.maxWriteSize = 65536

			state := &writeFileServerState{}
			go serveWriteFile(t, NewTransport(serverConn), state)

			share := f.fs

			require.NoError(t, share.WriteFile(context.Background(), "test.txt", []byte("data"), tc.perm))
			_, accesses, attrs := state.snapshot()
			require.Equal(t, []uint32{wire.GENERIC_WRITE}, accesses)
			require.Equal(t, []uint32{tc.want}, attrs)
		})
	}
}

func TestWriteFileResponseCount(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 2, 65536} {
		for _, count := range []uint32{0, 1, uint32(length), uint32(length) + 1} {
			t.Run(fmt.Sprintf("length=%d/count=%d", length, count), func(t *testing.T) {
				f, server := newTestFile(t)
				f.fs.conn.maxWriteSize = 65536
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				share := f.fs
				serverDone := make(chan error, 1)
				go func() {
					dt := NewTransport(server)
					req, err := readMsg(dt)
					if err != nil {
						serverDone <- err
						return
					}
					for _, command := range []wire.Command{wire.SMB2_CREATE, wire.SMB2_WRITE, wire.SMB2_CLOSE} {
						p := wire.PacketCodec(req)
						if p.Command() != command {
							serverDone <- fmt.Errorf("command = %v, want %v", p.Command(), command)
							return
						}
						var res wire.Packet
						switch command {
						case wire.SMB2_CREATE:
							res = &wire.CreateResponse{CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{}, LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{}, FileId: &wire.FileId{}}
						case wire.SMB2_WRITE:
							if got := wire.WriteRequestDecoder(p.Body()).Length(); got != uint32(length) {
								serverDone <- fmt.Errorf("write length = %d", got)
								return
							}
							res = &wire.WriteResponse{Count: count}
						case wire.SMB2_CLOSE:
							res = &wire.CloseResponse{CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{}, LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{}}
						}
						sendTestResponse(dt, req, res, 0)
						if next := p.NextCommand(); next != 0 {
							req = req[next:]
						}
					}
					serverDone <- nil
				}()
				err := share.WriteFile(context.Background(), "test.txt", make([]byte, length), 0600)
				switch {
				case count > uint32(length):
					var invalid *InvalidResponseError
					require.ErrorAs(t, err, &invalid)
				case count < uint32(length):
					require.ErrorIs(t, err, io.ErrShortWrite)
				default:
					require.NoError(t, err)
				}
				if err != nil {
					var pathErr *os.PathError
					require.ErrorAs(t, err, &pathErr)
					require.Equal(t, "writefile", pathErr.Op)
					require.Equal(t, "test.txt", pathErr.Path)
				}
				select {
				case err := <-serverDone:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("server did not complete")
				}
			})
		}
	}
}

const pipelineChunk = 64 << 10

type pipelineRequest struct {
	packet []byte
	cmd    wire.Command
	msgID  uint64
	off    uint64
	length uint32
}

func setupPipelineFile(t *testing.T, credits uint16) (*File, net.Conn) {
	t.Helper()
	f, peer := newTestFile(t)
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c := f.fs.conn
	c.maxReadSize = pipelineChunk
	c.maxWriteSize = pipelineChunk
	f.fs.treeConn.shareType = wire.SMB2_SHARE_TYPE_DISK
	c.account.m.Lock()
	c.account.availableCredits = credits
	c.account.inFlightCredits = 0
	c.account.maxCredits = credits
	c.account.maxCreditBalance = credits
	c.account.m.Unlock()
	return f, peer
}

func collectPipelineRequest(t *testing.T, dt Transport) pipelineRequest {
	t.Helper()
	packet, err := readMsg(dt)
	if err != nil {
		t.Fatal(err)
	}
	p := wire.PacketCodec(packet)
	r := pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId()}
	switch r.cmd {
	case wire.SMB2_READ:
		req := wire.ReadRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	case wire.SMB2_WRITE:
		req := wire.WriteRequestDecoder(p.Body())
		r.off, r.length = req.Offset(), req.Length()
	}
	return r
}

func sendPipelineResponse(t Transport, req pipelineRequest, res wire.Packet, status erref.NtStatus) error {
	buf := pipelineResponseBytes(req, res, status)
	_, err := t.writev(buf)
	return err
}

func pipelineResponseBytes(req pipelineRequest, res wire.Packet, status erref.NtStatus) []byte {
	buf := make([]byte, res.Size())
	res.Encode(buf)
	p := wire.PacketCodec(req.packet)
	r := wire.PacketCodec(buf)
	r.SetMessageId(req.msgID)
	r.SetSessionId(p.SessionId())
	r.SetTreeId(p.TreeId())
	r.SetStatus(uint32(status))
	r.SetCreditResponse(1)
	r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	return buf
}

func pipelineReadData(off uint64, n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(off/pipelineChunk + 1)
	}
	return data
}

func pipelineReadResponse(t Transport, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &wire.ReadResponse{Data: pipelineReadData(req.off, n)}, erref.STATUS_SUCCESS)
}

func pipelineWriteResponse(t Transport, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &wire.WriteResponse{Count: uint32(n)}, erref.STATUS_SUCCESS)
}

func waitPipelineResult[T any](t *testing.T, ch <-chan pipelineResult[T]) pipelineResult[T] {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline operation timed out")
		return pipelineResult[T]{}
	}
}

type pipelineResult[T any] struct {
	n   int
	err error
	val T
}

func TestIOPipelineReadCollectsAndReorders(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := NewTransport(peer)
	buf := bytes.Repeat([]byte{0xa5}, 4*pipelineChunk)
	const baseOffset = int64(7*pipelineChunk + 13)
	done := make(chan pipelineResult[[]byte], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, baseOffset)
		done <- pipelineResult[[]byte]{n: n, err: err, val: buf}
	}()

	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
		if reqs[i].cmd != wire.SMB2_READ || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
			t.Fatalf("request %d = command %v offset %d length %d", i, reqs[i].cmd, reqs[i].off, reqs[i].length)
		}
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		if err := pipelineReadResponse(dt, reqs[i], pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
	for i := 0; i < len(buf); i += pipelineChunk {
		if !bytes.Equal(buf[i:i+pipelineChunk], pipelineReadData(uint64(baseOffset+int64(i)), pipelineChunk)) {
			t.Fatalf("read chunk at offset %d has wrong data", i)
		}
	}
}

func TestIOPipelineWriteCollectsAndReorders(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := NewTransport(peer)
	data := make([]byte, 4*pipelineChunk)
	const baseOffset = int64(9*pipelineChunk + 29)
	for i := range data {
		data[i] = byte(i/pipelineChunk + 1)
	}
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.WriteAt(context.Background(), data, baseOffset)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()

	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
		if reqs[i].cmd != wire.SMB2_WRITE || reqs[i].off != uint64(baseOffset+int64(i*pipelineChunk)) || reqs[i].length != pipelineChunk {
			t.Fatalf("request %d = command %v offset %d length %d", i, reqs[i].cmd, reqs[i].off, reqs[i].length)
		}
		body := wire.WriteRequestDecoder(wire.PacketCodec(reqs[i].packet).Body())
		start, end := int(body.DataOffset()), int(body.DataOffset())+int(body.Length())
		if !bytes.Equal(reqs[i].packet[start:end], data[i*pipelineChunk:(i+1)*pipelineChunk]) {
			t.Fatalf("write request %d has wrong payload", i)
		}
	}
	for i := len(reqs) - 1; i >= 0; i-- {
		if err := pipelineWriteResponse(dt, reqs[i], pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(data) {
		t.Fatalf("WriteAt = (%d, %v), want (%d, nil)", result.n, result.err, len(data))
	}
}

func TestIOPipelineMakesProgressWithOneCredit(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 1)
	dt := NewTransport(peer)
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	if first.off != 0 || first.length != pipelineChunk {
		t.Fatalf("first request = offset %d length %d", first.off, first.length)
	}
	if err := pipelineReadResponse(dt, first, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	second := collectPipelineRequest(t, dt)
	if second.off != pipelineChunk || second.length != pipelineChunk {
		t.Fatalf("second request = offset %d length %d", second.off, second.length)
	}
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineKeepsBoundedWindow(t *testing.T) {
	t.Parallel()
	for _, depth := range []uint{0, 1, 2, 6} {
		for _, write := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth=%d/write=%t", depth, write), func(t *testing.T) {
				testIOPipelineWindow(t, depth, write)
			})
		}
	}
}

func testIOPipelineWindow(t *testing.T, depth uint, write bool) {
	f, peer := setupPipelineFile(t, 8)
	f.fs.conn.ioPipelineDepth = depth
	if depth == 0 {
		depth = 4
	}
	dt := NewTransport(peer)
	respond := pipelineReadResponse
	if write {
		respond = pipelineWriteResponse
	}
	buf := make([]byte, 8*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		var n int
		var err error
		if write {
			n, err = f.WriteAt(context.Background(), buf, 0)
		} else {
			n, err = f.ReadAt(context.Background(), buf, 0)
		}
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	requests := make([]pipelineRequest, depth)
	for i := range requests {
		requests[i] = collectPipelineRequest(t, dt)
	}

	// A further request must wait until a response releases a pipeline slot.
	next := make(chan struct {
		req pipelineRequest
		err error
	}, 1)
	go func() {
		packet, err := readMsg(dt)
		if err != nil {
			next <- struct {
				req pipelineRequest
				err error
			}{err: err}
			return
		}
		p := wire.PacketCodec(packet)
		r := wire.ReadRequestDecoder(p.Body())
		offset, length := r.Offset(), r.Length()
		if write {
			w := wire.WriteRequestDecoder(p.Body())
			offset, length = w.Offset(), w.Length()
		}
		next <- struct {
			req pipelineRequest
			err error
		}{req: pipelineRequest{packet: packet, cmd: p.Command(), msgID: p.MessageId(), off: offset, length: length}}
	}()
	select {
	case got := <-next:
		t.Fatalf("received next request before any response: req=%+v err=%v", got.req, got.err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := respond(dt, requests[0], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	var nextRequest pipelineRequest
	select {
	case got := <-next:
		if got.err != nil {
			t.Fatal(got.err)
		}
		nextRequest = got.req
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not send a request after a slot was released")
	}
	if nextRequest.off != uint64(depth*pipelineChunk) || nextRequest.length != pipelineChunk {
		t.Fatalf("next request = offset %d length %d", nextRequest.off, nextRequest.length)
	}
	requests = append(requests, nextRequest)
	for _, req := range requests[1:] {
		if err := respond(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	for len(requests) < 8 {
		req := collectPipelineRequest(t, dt)
		requests = append(requests, req)
		if err := respond(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadErrorReportsContiguousPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := NewTransport(peer)
	buf := make([]byte, 4*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reqs := make([]pipelineRequest, 4)
	for i := range reqs {
		reqs[i] = collectPipelineRequest(t, dt)
	}
	if err := pipelineReadResponse(dt, reqs[3], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := sendPipelineResponse(dt, reqs[2], &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_ACCESS_DENIED); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, reqs[1], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, reqs[0], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != 2*pipelineChunk || !errors.Is(result.err, erref.STATUS_ACCESS_DENIED) {
		t.Fatalf("ReadAt = (%d, %v), want contiguous prefix %d and access denied", result.n, result.err, 2*pipelineChunk)
	}
}

func TestIOPipelineReadRefillsShortResponse(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := NewTransport(peer)
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	short := pipelineChunk / 2
	if err := pipelineReadResponse(dt, first, short); err != nil {
		t.Fatal(err)
	}
	refill := collectPipelineRequest(t, dt)
	if refill.off != uint64(short) || refill.length != uint32(pipelineChunk-short) {
		t.Fatalf("refill request = offset %d length %d", refill.off, refill.length)
	}
	if err := pipelineReadResponse(dt, refill, pipelineChunk-short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadRefillsBufferOverflow(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := NewTransport(peer)
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	short := pipelineChunk / 2
	if err := pipelineReadResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	if err := sendPipelineResponse(dt, first, &wire.ReadResponse{Data: pipelineReadData(0, short)}, erref.STATUS_BUFFER_OVERFLOW); err != nil {
		t.Fatal(err)
	}
	refill := collectPipelineRequest(t, dt)
	if refill.off != uint64(short) || refill.length != uint32(pipelineChunk-short) {
		t.Fatalf("overflow refill request = offset %d length %d", refill.off, refill.length)
	}
	if err := pipelineReadResponse(dt, refill, pipelineChunk-short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.err != nil || result.n != len(buf) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", result.n, result.err, len(buf))
	}
}

func TestIOPipelineReadEOFReportsPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := NewTransport(peer)
	buf := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(context.Background(), buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := sendPipelineResponse(dt, second, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_END_OF_FILE); err != nil {
		t.Fatal(err)
	}
	if err := pipelineReadResponse(dt, first, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != pipelineChunk || !errors.Is(result.err, io.EOF) {
		t.Fatalf("ReadAt = (%d, %v), want EOF after %d bytes", result.n, result.err, pipelineChunk)
	}
}

func TestIOPipelineWriteShortWriteReportsPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := NewTransport(peer)
	data := make([]byte, 2*pipelineChunk)
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.WriteAt(context.Background(), data, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	first := collectPipelineRequest(t, dt)
	second := collectPipelineRequest(t, dt)
	if err := pipelineWriteResponse(dt, second, pipelineChunk); err != nil {
		t.Fatal(err)
	}
	short := pipelineChunk / 2
	if err := pipelineWriteResponse(dt, first, short); err != nil {
		t.Fatal(err)
	}
	result := waitPipelineResult(t, done)
	if result.n != short || !errors.Is(result.err, io.ErrShortWrite) {
		t.Fatalf("WriteAt = (%d, %v), want short write after %d bytes", result.n, result.err, short)
	}
}

func TestIOPipelineCancellationDrainsDirectReads(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := NewTransport(peer)
	buf := bytes.Repeat([]byte{0xa5}, 4*pipelineChunk)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(ctx, buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reads := make([]pipelineRequest, 4)
	for i := range reads {
		reads[i] = collectPipelineRequest(t, dt)
	}
	cancel()
	wantCancel := make(map[uint64]bool, len(reads))
	for _, req := range reads {
		wantCancel[req.msgID] = true
	}
	for i := range reads {
		cancelReq := collectPipelineRequest(t, dt)
		if cancelReq.cmd != wire.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
			t.Fatalf("cancel %d = command %v message %d", i, cancelReq.cmd, cancelReq.msgID)
		}
		delete(wantCancel, cancelReq.msgID)
	}
	result := waitPipelineResult(t, done)
	if !errors.Is(result.err, context.Canceled) || result.n != 0 {
		t.Fatalf("ReadAt = (%d, %v), want cancellation", result.n, result.err)
	}
	// Replies are deliberately late relative to cancellation and operation
	// return. They must be drained without copying into the caller's buffer.
	for _, req := range reads {
		if err := pipelineReadResponse(dt, req, pipelineChunk); err != nil {
			t.Fatal(err)
		}
	}

	echoDone := make(chan error, 1)
	go func() { echoDone <- f.fs.session.echo(context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != wire.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &wire.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ECHO did not complete after canceled reads")
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatal("late direct READ response altered returned buffer")
	}
}

func TestIOPipelineCancellationWaitsForInFlightDirectRead(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 2)
	dt := NewTransport(peer)
	buf := bytes.Repeat([]byte{0xa5}, 2*pipelineChunk)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan pipelineResult[struct{}], 1)
	go func() {
		n, err := f.ReadAt(ctx, buf, 0)
		done <- pipelineResult[struct{}]{n: n, err: err}
	}()
	reads := []pipelineRequest{collectPipelineRequest(t, dt), collectPipelineRequest(t, dt)}

	// Feed only the response header and fixed READ body first. The transport
	// has selected the caller's direct buffer and is blocked while receiving
	// the payload when cancellation starts.
	response := pipelineResponseBytes(reads[0], &wire.ReadResponse{Data: pipelineReadData(0, pipelineChunk)}, erref.STATUS_SUCCESS)
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(response)))
	copy(frame[4:], response)
	if _, err := peer.Write(frame[:4+80]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr, ok := f.fs.conn.outstandingRequests.peek(reads[0].msgID)
		if ok && rr.directState.Load() == directStateReading {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("direct READ reception did not become in-flight")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
		t.Fatal("operation returned before in-flight direct reception completed")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := peer.Write(frame[4+80:]); err != nil {
		t.Fatal(err)
	}

	wantCancel := map[uint64]bool{reads[0].msgID: true, reads[1].msgID: true}
	for range reads {
		cancelReq := collectPipelineRequest(t, dt)
		if cancelReq.cmd != wire.SMB2_CANCEL || !wantCancel[cancelReq.msgID] {
			t.Fatalf("unexpected cancellation request: command %v message %d", cancelReq.cmd, cancelReq.msgID)
		}
		delete(wantCancel, cancelReq.msgID)
	}
	result := waitPipelineResult(t, done)
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("ReadAt error = %v, want context cancellation", result.err)
	}

	// Reinitialize the returned buffer and send the other late response. A
	// response still in flight must not write into caller memory after return.
	for i := range buf {
		buf[i] = 0xa5
	}
	if err := pipelineReadResponse(dt, reads[1], pipelineChunk); err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan error, 1)
	go func() { echoDone <- f.fs.session.echo(context.Background()) }()
	echoReq := collectPipelineRequest(t, dt)
	if echoReq.cmd != wire.SMB2_ECHO {
		t.Fatalf("unrelated request command = %v, want ECHO", echoReq.cmd)
	}
	if err := sendPipelineResponse(dt, echoReq, &wire.EchoResponse{}, erref.STATUS_SUCCESS); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ECHO did not complete after canceled reads")
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatal("late direct READ response altered returned buffer")
	}
}

type pipelineBenchResponse struct {
	packet  []byte
	readyAt time.Time
}

func startPipelineBenchServer(peer net.Conn, latency time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := NewTransport(peer)
		responses := make(chan pipelineBenchResponse, 32)
		var writers sync.WaitGroup
		writers.Add(1)
		go func() {
			defer writers.Done()
			for response := range responses {
				if wait := time.Until(response.readyAt); wait > 0 {
					time.Sleep(wait)
				}
				if _, err := dt.writev(response.packet); err != nil {
					return
				}
			}
		}()
		for {
			packet, err := readMsg(dt)
			if err != nil {
				close(responses)
				writers.Wait()
				return
			}
			p := wire.PacketCodec(packet)
			var response wire.Packet
			switch p.Command() {
			case wire.SMB2_READ:
				req := wire.ReadRequestDecoder(p.Body())
				response = &wire.ReadResponse{Data: pipelineReadData(req.Offset(), int(req.Length()))}
			case wire.SMB2_WRITE:
				req := wire.WriteRequestDecoder(p.Body())
				response = &wire.WriteResponse{Count: req.Length()}
			default:
				continue
			}
			buf := make([]byte, response.Size())
			response.Encode(buf)
			r := wire.PacketCodec(buf)
			r.SetMessageId(p.MessageId())
			r.SetSessionId(p.SessionId())
			r.SetTreeId(p.TreeId())
			r.SetCreditResponse(1)
			r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			responses <- pipelineBenchResponse{packet: buf, readyAt: time.Now().Add(latency)}
		}
	}()
	return done
}

func BenchmarkIOPipeline(b *testing.B) {
	for _, latency := range []struct {
		name  string
		delay time.Duration
	}{
		{name: "0ms", delay: 0},
		{name: "2ms", delay: 2 * time.Millisecond},
	} {
		for _, op := range []string{"Read", "Write"} {
			for _, mode := range []string{"Sequential", "Pipelined"} {
				b.Run(latency.name+"/"+op+"/"+mode, func(b *testing.B) {
					client, peer := net.Pipe()
					c, cleanup := newBenchConn(client)
					defer cleanup()
					defer peer.Close()
					c.session = &session{conn: c, sessionId: 0x100}
					c.enableSession()
					c.maxReadSize = pipelineChunk
					c.maxWriteSize = pipelineChunk
					c.account.m.Lock()
					c.account.availableCredits = 16
					c.account.inFlightCredits = 0
					c.account.maxCredits = 16
					c.account.maxCreditBalance = 16
					c.account.m.Unlock()
					f := newBenchFile(c)
					f.fs.treeConn.shareType = wire.SMB2_SHARE_TYPE_DISK
					serverDone := startPipelineBenchServer(peer, latency.delay)
					defer func() {
						_ = peer.Close()
						<-serverDone
					}()
					buf := make([]byte, 16*pipelineChunk)
					b.SetBytes(int64(len(buf)))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						var n int
						var err error
						if op == "Read" {
							if mode == "Sequential" {
								for n < len(buf) {
									var nn int
									nn, err = f.fs.readAtChunk(context.Background(), f.fd, buf[n:], int64(n))
									n += nn
									if err != nil {
										break
									}
								}
							} else {
								n, err = f.fs.readAt(context.Background(), f.fd, buf, 0)
							}
						} else if mode == "Sequential" {
							for n < len(buf) {
								var nn int
								nn, err = f.fs.writeAtChunk(context.Background(), f.fd, buf[n:], int64(n))
								n += nn
								if err != nil {
									break
								}
							}
						} else {
							n, err = f.fs.writeAt(context.Background(), f.fd, buf, 0)
						}
						if err != nil || n != len(buf) {
							b.Fatalf("%s %s = (%d, %v), want (%d, nil)", op, mode, n, err, len(buf))
						}
					}
				})
			}
		}
	}
}
