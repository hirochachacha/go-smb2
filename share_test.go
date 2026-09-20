package smb2

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestFileAttributesFromPerm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{name: "writable", perm: 0o666, want: wire.FILE_ATTRIBUTE_NORMAL},
		{name: "readonly", perm: 0o444, want: wire.FILE_ATTRIBUTE_NORMAL | wire.FILE_ATTRIBUTE_READONLY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileAttributesFromPerm(tt.perm); got != tt.want {
				t.Errorf("fileAttributesFromPerm(%#o) = %#x, want %#x", tt.perm, got, tt.want)
			}
		})
	}
}

func TestFileCopyToSelf(t *testing.T) {
	t.Parallel()
	f := &File{}

	if _, err := f.ReadFrom(context.Background(), &BoundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("ReadFrom self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
	if _, err := f.WriteTo(context.Background(), &BoundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("WriteTo self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
}

func TestFileCopyAcrossSharesSharingTreeConn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		op   func(src, dst *File)
	}{
		{"ReadFrom", func(src, dst *File) { _, _ = dst.ReadFrom(context.Background(), src.WithContext(context.Background())) }},
		{"WriteTo", func(src, dst *File) { _, _ = src.WriteTo(context.Background(), dst.WithContext(context.Background())) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()
			tcConn := &treeConn{session: c.session, treeId: 0x200}
			fs1 := &Share{treeConn: tcConn}
			fs2 := fs1

			var resumeKeyRequests atomic.Int32
			go func() {
				dt := NewTransport(serverConn)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					switch wire.PacketCodec(req).Command() {
					case wire.SMB2_IOCTL:
						reqData := req[64:]
						if wire.IoctlRequestDecoder(reqData).CtlCode() == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
							resumeKeyRequests.Add(1)
						}
						sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, 0xC0000001)
					case wire.SMB2_READ:
						readReq := wire.ReadRequestDecoder(req[64:])
						sendTestResponse(dt, req, &wire.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
					case wire.SMB2_WRITE:
						sendTestResponse(dt, req, &wire.WriteResponse{}, 0)
					}
				}
			}()

			srcFile := fs1.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "src.txt")
			dstFile := fs2.newFile(wire.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

			tc.op(srcFile, dstFile)

			require.Equal(t, int32(1), resumeKeyRequests.Load(),
				"copyFile (FSCTL_SRV_REQUEST_RESUME_KEY) must be attempted between files opened from different Share instances sharing the same treeConn")
		})
	}
}

func TestShareReadlinkUsesSingleCredit(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	var recordedCmds []wire.Command
	var ioctlCreditCharge uint16
	var maxOutputResponse uint32

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
				cres := &wire.CreateResponse{
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case wire.SMB2_IOCTL:
				ioctlCreditCharge = p.CreditCharge()
				req := wire.IoctlRequestDecoder(currBuf[64:])
				maxOutputResponse = req.MaxOutputResponse()

				reparse := &wire.SymbolicLinkReparseDataBuffer{
					Flags:          wire.SYMLINK_FLAG_RELATIVE,
					SubstituteName: "target.txt",
					PrintName:      "target.txt",
				}
				buf := make([]byte, reparse.Size())
				reparse.Encode(buf)

				ires := &wire.IoctlResponse{
					CtlCode: wire.FSCTL_GET_REPARSE_POINT,
					Output:  rawEncoder(buf),
				}
				resBuf = make([]byte, ires.Size())
				ires.Encode(resBuf)

			case wire.SMB2_CLOSE:
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

	target, err := fs.Readlink(context.Background(), "link.txt")
	require.NoError(t, err)
	require.Equal(t, "target.txt", target)

	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_IOCTL, wire.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(maxSingleCreditPayloadSize), maxOutputResponse)
	require.Equal(t, uint16(1), ioctlCreditCharge)
}

func TestShareReadlinkRejectsOddReparseNameLength(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	go func() {
		dt := NewTransport(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		p := wire.PacketCodec(reqBuf)
		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			curr := wire.PacketCodec(currBuf)
			var res wire.Packet
			switch curr.Command() {
			case wire.SMB2_CREATE:
				res = &wire.CreateResponse{
					FileId:         &wire.FileId{},
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
			case wire.SMB2_IOCTL:
				reparse := &wire.SymbolicLinkReparseDataBuffer{
					Flags:          wire.SYMLINK_FLAG_RELATIVE,
					SubstituteName: "target.txt",
					PrintName:      "target.txt",
				}
				data := make([]byte, reparse.Size())
				reparse.Encode(data)
				// Make only SubstituteNameLength odd while retaining the
				// otherwise valid reparse buffer.
				binary.LittleEndian.PutUint16(data[10:12], 1)
				res = &wire.IoctlResponse{
					CtlCode: wire.FSCTL_GET_REPARSE_POINT,
					Output:  rawEncoder(data),
				}
			case wire.SMB2_CLOSE:
				res = &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
			}

			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(curr.MessageId())
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			responseBufs = append(responseBufs, resBuf)

			if curr.NextCommand() == 0 {
				break
			}
			currBuf = currBuf[curr.NextCommand():]
		}

		var finalBuf []byte
		for i, rb := range responseBufs {
			if i < len(responseBufs)-1 {
				next := uint32(wire.Roundup(len(rb), 8))
				padded := make([]byte, next)
				copy(padded, rb)
				wire.PacketCodec(padded).SetNextCommand(next)
				finalBuf = append(finalBuf, padded...)
			} else {
				finalBuf = append(finalBuf, rb...)
			}
		}
		_, _ = dt.writev(finalBuf)
	}()

	target, err := fs.Readlink(context.Background(), "link.txt")
	require.Empty(t, target)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestRemoveAllRejectsInvalidDirectoryEntry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		entryName string
	}{
		{name: "path separator", entryName: `..\outside.txt`},
		{name: "empty name", entryName: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := NewTransport(serverConn)
			var createNames []string
			done := make(chan struct{})

			go func() {
				defer close(done)
				for request := 1; ; request++ {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					p := wire.PacketCodec(req)
					if p.Command() == wire.SMB2_CREATE {
						d := wire.CreateRequestDecoder(p.Body())
						if !d.IsInvalid() {
							body := p.Body()
							off := int(d.NameOffset()) - 64
							end := off + int(d.NameLength())
							if off >= 0 && end <= len(body) {
								createNames = append(createNames, utf16le.DecodeToString(body[off:end]))
							}
						}
					}

					switch request {
					case 1:
						// The initial delete fails because the directory is not empty.
						sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
					case 2:
						sendTestCreateAttributesResponse(dt, req, &wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
					case 3:
						sendTestResponse(dt, req, &wire.QueryDirectoryResponse{
							Output: rawEncoder(encodeFileIdBothDirectoryInformation(test.entryName)),
						}, uint32(erref.STATUS_SUCCESS))
					case 4:
						sendTestCloseResponse(dt, req)
					case 5:
						sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
						return
					}
				}
			}()

			err := fs.RemoveAll(context.Background(), "root")
			var invalidResponseErr *InvalidResponseError
			require.ErrorAs(t, err, &invalidResponseErr)
			<-done
			require.Equal(t, []string{"root", "root", "root"}, createNames)
		})
	}
}

func newTestShare(t *testing.T) (*Share, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc}
	return fs, serverConn
}

func sendTestCompoundErrorResponse(dt Transport, req []byte, status uint32) {
	p := wire.PacketCodec(req)
	baseMsgId := p.MessageId()

	var parts [][]byte
	for i := range 3 {
		errPkt := &wire.ErrorResponse{
			CommandCode: wire.SMB2_CREATE,
		}
		resBuf := make([]byte, errPkt.Size())
		errPkt.Encode(resBuf)
		rp := wire.PacketCodec(resBuf)
		rp.SetMessageId(baseMsgId + uint64(i))
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		if i == 0 {
			rp.SetStatus(status)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		} else {
			rp.SetStatus(uint32(erref.STATUS_INVALID_PARAMETER))
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
		}
		parts = append(parts, resBuf)
	}

	var compound []byte
	for i, part := range parts {
		if i < len(parts)-1 {
			pad := (8 - (len(part) % 8)) % 8
			next := uint32(len(part) + pad)
			padded := make([]byte, next)
			copy(padded, part)
			wire.PacketCodec(padded).SetNextCommand(next)
			compound = append(compound, padded...)
		} else {
			wire.PacketCodec(part).SetCreditResponse(1)
			compound = append(compound, part...)
		}
	}
	_, _ = dt.writev(compound)
}

func TestShare_Remove_NoFallbackOnNonAccessError(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			requestCount.Add(1)
			// Return STATUS_OBJECT_NAME_NOT_FOUND on the first request
			sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		}
	}()

	err := fs.Remove(context.Background(), "nonexistent.txt")
	require.Error(t, err)

	// Must NOT attempt fallback chmod; requestCount must be exactly 1
	require.Equal(t, int32(1), requestCount.Load(), "should not trigger chmod fallback on STATUS_OBJECT_NAME_NOT_FOUND")
}

func TestShareOpenFileRejectsNegativeCreateEndofFileAndKeepsConnection(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	dt := NewTransport(serverConn)

	commands := make(chan wire.Command, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(commands)
		for i := range 3 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			commands <- wire.PacketCodec(req).Command()

			switch i {
			case 0, 1:
				endofFile := int64(4096)
				if i == 0 {
					endofFile = -1
				}
				res := &wire.CreateResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
					EndofFile:      endofFile,
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			case 2:
				res := &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	file, err := fs.OpenFile(context.Background(), "negative.txt", os.O_WRONLY|os.O_APPEND, 0)
	var invalidResponseErr *InvalidResponseError
	require.Nil(t, file)
	require.ErrorAs(t, err, &invalidResponseErr)

	file, err = fs.OpenFile(context.Background(), "normal.txt", os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4096), file.offset)
	require.NoError(t, file.Close(context.Background()))

	<-done
	var gotCommands []wire.Command
	for command := range commands {
		gotCommands = append(gotCommands, command)
	}
	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_CREATE, wire.SMB2_CLOSE}, gotCommands)
}

func sendTestCompoundSuccessResponse(dt Transport, req []byte) {
	createRes := &wire.CreateResponse{
		FileId:         &wire.FileId{},
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	setInfoRes := &wire.SetInfoResponse{}
	closeRes := &wire.CloseResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)
	resBuf2 := make([]byte, setInfoRes.Size())
	setInfoRes.Encode(resBuf2)
	resBuf3 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf3)

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

	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	wire.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	wire.PacketCodec(padded2).SetSessionId(p.SessionId())
	wire.PacketCodec(padded2).SetTreeId(p.TreeId())
	wire.PacketCodec(padded2).SetStatus(uint32(erref.STATUS_SUCCESS))
	wire.PacketCodec(padded2).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(padded2).SetNextCommand(next2)

	wire.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	wire.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	wire.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	wire.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
	wire.PacketCodec(resBuf3).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(resBuf3).SetCreditResponse(1)

	compound := append(padded1, padded2...)
	compound = append(compound, resBuf3...)
	_, _ = dt.writev(compound)
}

func sendTestCloseResponse(dt Transport, req []byte) {
	res := &wire.CloseResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_FallbackOnCannotDelete(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			fileId := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, wire.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// Fourth request closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// Fifth request is retry remove (CREATE + SET_INFO + CLOSE compound)
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove(context.Background(), "readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load(), "should perform remove, create, set attributes, close, then retry remove")
}

func TestShare_Remove_FallbackOnAccessDenied(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			fileId := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_ACCESS_DENIED
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_ACCESS_DENIED))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, wire.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// Fourth request closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// Fifth request is retry remove
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove(context.Background(), "readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load(), "should perform remove, create, set attributes, close, then retry remove")
}

func TestShare_Remove_PropagatesChmodFallbackError(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod fallback CREATE,
				// which fails because the file is locked by another opener
				sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_SHARING_VIOLATION))
			}
		}
	}()

	err := fs.Remove(context.Background(), "locked.txt")
	require.Error(t, err)

	// Should not retry remove after chmod fallback failure
	require.Equal(t, int32(2), requestCount.Load(), "should stop after chmod fallback failure")

	var pe *os.PathError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "remove", pe.Op)
	require.Equal(t, "locked.txt", pe.Path)
	// Must report the chmod failure, not the initial STATUS_CANNOT_DELETE error
	require.ErrorIs(t, pe.Err, erref.STATUS_SHARING_VIOLATION, "should propagate chmod fallback error")
}

func sendTestCreateAttributesResponse(dt Transport, req []byte, fileId *wire.FileId, fileAttributes uint32) {
	sendTestResponse(dt, req, &wire.CreateResponse{
		FileId:         fileId,
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
		FileAttributes: fileAttributes,
	}, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_ReadonlyFallbackPreservesExistingAttributes(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)

	var (
		requestCount  atomic.Int32
		capturedAttrs atomic.Uint32
	)
	fileId := &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
	const initialAttrs = wire.FILE_ATTRIBUTE_READONLY | wire.FILE_ATTRIBUTE_HIDDEN | wire.FILE_ATTRIBUTE_SYSTEM

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// 1st request: remove fails with STATUS_CANNOT_DELETE
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// 2nd request: CREATE
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, initialAttrs)
			case 3:
				// 3rd request: SET_INFO (kept separate from CLOSE)
				p := wire.PacketCodec(reqBuf)
				if p.Command() == wire.SMB2_SET_INFO {
					d := wire.SetInfoRequestDecoder(p.Body())
					if !d.IsInvalid() && d.BufferLength() >= 40 {
						buf := p[d.BufferOffset() : d.BufferOffset()+uint16(d.BufferLength())]
						base := wire.FileBasicInformationDecoder(buf)
						if !base.IsInvalid() {
							capturedAttrs.Store(base.FileAttributes())
						}
					}
				}
				sendTestResponse(dt, reqBuf, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// 4th request: closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// 5th request: retry remove
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove(context.Background(), "hidden_readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load())
	// computeChmodAttrs clears readonly, preserves hidden/system, and sets NORMAL for non-directories
	expectedAttrs := uint32(wire.FILE_ATTRIBUTE_NORMAL | wire.FILE_ATTRIBUTE_HIDDEN | wire.FILE_ATTRIBUTE_SYSTEM)
	require.Equal(t, expectedAttrs, capturedAttrs.Load(), "fallback chmod must preserve existing attributes (hidden, system) while clearing readonly")
}

// renameObservation records the SET_INFO BufferLength and the per-command
// CreditCharge of the CREATE + SET_INFO + CLOSE compound that Rename sends.
type renameObservation struct {
	commands      []wire.Command
	creditCharges []uint16
	setInfoLength uint32
}

func (o renameObservation) totalCreditCharge() uint32 {
	var total uint32
	for _, charge := range o.creditCharges {
		total += uint32(charge)
	}
	return total
}

// longPathOfLength builds a relative path of exactly n ASCII characters from
// short components separated by backslashes, so no single component hits a
// server-side name limit.
func longPathOfLength(n int) string {
	const componentLen = 32

	var b strings.Builder
	b.Grow(n)
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('\\')
		}
		remaining := n - b.Len()
		b.WriteString(strings.Repeat("a", min(remaining, componentLen)))
	}
	return b.String()
}

// serveRenameCompound reads a single CREATE + SET_INFO + CLOSE compound request
// and replies with a successful response for each operation, reporting what it
// observed on the observed channel.
func serveRenameCompound(t *testing.T, serverConn net.Conn, observed chan<- renameObservation) {
	t.Helper()

	go func() {
		dt := NewTransport(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			observed <- renameObservation{}
			return
		}

		var obs renameObservation
		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := wire.PacketCodec(currBuf)
			obs.commands = append(obs.commands, p.Command())
			obs.creditCharges = append(obs.creditCharges, p.CreditCharge())
			nextCommand := p.NextCommand()

			var resBuf []byte
			switch p.Command() {
			case wire.SMB2_CREATE:
				res := &wire.CreateResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
					FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case wire.SMB2_SET_INFO:
				obs.setInfoLength = wire.SetInfoRequestDecoder(p.Body()).BufferLength()
				res := &wire.SetInfoResponse{}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case wire.SMB2_CLOSE:
				res := &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			}

			if resBuf != nil {
				rp := wire.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				flags := uint32(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				if len(responseBufs) > 0 {
					flags |= wire.SMB2_FLAGS_RELATED_OPERATIONS
				}
				rp.SetFlags(flags)
				responseBufs = append(responseBufs, resBuf)
			}

			if nextCommand == 0 {
				break
			}
			currBuf = currBuf[nextCommand:]
		}

		var compound []byte
		for i, rb := range responseBufs {
			if i < len(responseBufs)-1 {
				pad := (8 - (len(rb) % 8)) % 8
				next := uint32(len(rb) + pad)
				padded := make([]byte, next)
				copy(padded, rb)
				wire.PacketCodec(padded).SetNextCommand(next)
				compound = append(compound, padded...)
			} else {
				compound = append(compound, rb...)
			}
		}
		if len(compound) > 0 {
			if _, err := dt.writev(compound); err != nil {
				observed <- renameObservation{}
				return
			}
		}
		observed <- obs
	}()
}

// requireNoRequest asserts that the server receives nothing before the
// read deadline elapses.
func requireNoRequest(t *testing.T, serverConn net.Conn) {
	t.Helper()

	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	var buf [1]byte
	_, err := serverConn.Read(buf[:])
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout(), "expected read deadline, got %v", err)
}

// requireRenameRejectedLocally asserts that Rename fails with an os.LinkError
// wrapping os.ErrInvalid and that no request reaches the server.
func requireRenameRejectedLocally(t *testing.T, fs *Share, serverConn net.Conn, newpath string) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fs.Rename(context.Background(), "old.txt", newpath)
	}()

	select {
	case err := <-errCh:
		var linkErr *os.LinkError
		require.ErrorAs(t, err, &linkErr)
		require.ErrorIs(t, err, os.ErrInvalid)
		require.Equal(t, "rename", linkErr.Op)
		require.Equal(t, "old.txt", linkErr.Old)
		require.Equal(t, newpath, linkErr.New)
	case <-time.After(2 * time.Second):
		t.Fatal("Rename did not reject the oversized request locally")
	}

	requireNoRequest(t, serverConn)
}

func TestShareRenameRespectsMaxTransactSize(t *testing.T) {
	t.Parallel()
	const maxTransact = 65536

	t.Run("input at MaxTransactSize is sent", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = maxTransact
		require.Equal(t, maxTransact, fs.maxTransactSize(2))

		observed := make(chan renameObservation, 1)
		serveRenameCompound(t, serverConn, observed)

		newpath := longPathOfLength((maxTransact - 20) / 2)
		require.NoError(t, fs.Rename(context.Background(), "old.txt", newpath))

		obs := <-observed
		require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_SET_INFO, wire.SMB2_CLOSE}, obs.commands)
		require.Equal(t, uint32(maxTransact), obs.setInfoLength)
	})

	t.Run("input over MaxTransactSize is rejected before send", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = maxTransact

		newpath := longPathOfLength((maxTransact-20)/2 + 1)
		requireRenameRejectedLocally(t, fs, serverConn, newpath)
	})
}

func TestShareRenameRespectsReservedCreditBudget(t *testing.T) {
	t.Parallel()
	// A 65538-byte SET_INFO input (20-byte fixed part plus an encoded path)
	// needs a 2-credit CreditCharge, so the compound needs 4 credits in total
	// once the CREATE and CLOSE companions are accounted for.
	const setInfoSize = 65538
	newpath := longPathOfLength((setInfoSize - 20) / 2)

	t.Run("credit cap of three rejects locally", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = 1 << 20
		fs.conn.account.maxCreditBalance = 3
		require.Equal(t, maxSingleCreditPayloadSize, fs.maxTransactSize(2))

		requireRenameRejectedLocally(t, fs, serverConn, newpath)
	})

	t.Run("credit cap of four sends a four-credit compound", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = 1 << 20
		fs.conn.account.maxCreditBalance = 4
		require.Equal(t, 2*maxSingleCreditPayloadSize, fs.maxTransactSize(2))

		observed := make(chan renameObservation, 1)
		serveRenameCompound(t, serverConn, observed)

		require.NoError(t, fs.Rename(context.Background(), "old.txt", newpath))

		obs := <-observed
		require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_SET_INFO, wire.SMB2_CLOSE}, obs.commands)
		require.Equal(t, uint32(setInfoSize), obs.setInfoLength)
		require.Equal(t, []uint16{1, 2, 1}, obs.creditCharges)
		require.Equal(t, uint32(4), obs.totalCreditCharge())
	})
}

func TestLstatDoesNotRegisterFinalizer(t *testing.T) {
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

	var createCount, closeCount int64

	const (
		creationLow    = uint32(0x11223344)
		creationHigh   = uint32(0x01234567)
		accessLow      = uint32(0x55667788)
		accessHigh     = uint32(0x01234567)
		writeLow       = uint32(0x99aabbcc)
		writeHigh      = uint32(0x01234567)
		changeLow      = uint32(0xddeeff00)
		changeHigh     = uint32(0x01234567)
		allocationSize = int64(8192)
		endOfFile      = int64(4096)
		fileAttributes = uint32(0x20)
	)

	filetime := func(low, high uint32) time.Time {
		raw := make([]byte, 8)
		le.PutUint32(raw[0:4], low)
		le.PutUint32(raw[4:8], high)
		return wire.FiletimeDecoder(raw).Time()
	}

	// Fake server that counts CREATE and CLOSE requests so we can detect
	// a spurious CLOSE triggered by a runtime finalizer after GC.
	go func() {
		dt := NewTransport(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := wire.PacketCodec(currBuf)
				msgId := p.MessageId()

				var resBuf []byte
				switch p.Command() {
				case wire.SMB2_CREATE:
					atomic.AddInt64(&createCount, 1)
					cres := &wire.CreateResponse{
						CreationTime:   &wire.Filetime{LowDateTime: creationLow, HighDateTime: creationHigh},
						LastAccessTime: &wire.Filetime{LowDateTime: accessLow, HighDateTime: accessHigh},
						LastWriteTime:  &wire.Filetime{LowDateTime: writeLow, HighDateTime: writeHigh},
						ChangeTime:     &wire.Filetime{LowDateTime: changeLow, HighDateTime: changeHigh},
						AllocationSize: allocationSize,
						EndofFile:      endOfFile,
						FileAttributes: fileAttributes,
						FileId:         &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case wire.SMB2_CLOSE:
					atomic.AddInt64(&closeCount, 1)
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
					rp.SetMessageId(msgId)
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
		}
	}()

	fi, err := fs.Lstat(context.Background(), "test.txt")
	require.NoError(t, err)

	require.Equal(t, "test.txt", fi.Name())
	require.Equal(t, os.FileMode(0o666), fi.Mode())
	require.Equal(t, endOfFile, fi.Size())
	require.True(t, fi.ModTime().Equal(filetime(writeLow, writeHigh)))

	fst, ok := fi.(*FileStat)
	require.True(t, ok, "Lstat must return *FileStat")
	require.True(t, fst.CreationTime.Equal(filetime(creationLow, creationHigh)))
	require.True(t, fst.LastAccessTime.Equal(filetime(accessLow, accessHigh)))
	require.True(t, fst.LastWriteTime.Equal(filetime(writeLow, writeHigh)))
	require.True(t, fst.ChangeTime.Equal(filetime(changeLow, changeHigh)))
	require.Equal(t, endOfFile, fst.EndOfFile)
	require.Equal(t, allocationSize, fst.AllocationSize)
	require.Equal(t, fileAttributes, fst.FileAttributes)

	require.Equal(t, int64(1), atomic.LoadInt64(&createCount))
	require.Equal(t, int64(1), atomic.LoadInt64(&closeCount), "Lstat must send exactly one CLOSE (the compound close)")

	// The *File created by the old implementation becomes unreachable right
	// after Lstat returns, so its finalizer fires on GC and issues a spurious
	// CLOSE request. Force GC and make sure no extra CLOSE ever arrives.
	runtime.GC()
	runtime.GC()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := atomic.LoadInt64(&closeCount); n != 1 {
			t.Fatalf("Lstat registered a finalizer: %d CLOSE requests observed (want 1)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCreatePermissionsAndOptions(t *testing.T) {
	t.Parallel()
	t.Run("OpenFile_O_APPEND", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := NewTransport(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := wire.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "append.txt", os.O_WRONLY|os.O_APPEND, 0o666)
		require.Equal(t, uint32(wire.FILE_APPEND_DATA|wire.FILE_WRITE_EA|wire.FILE_WRITE_ATTRIBUTES|wire.READ_CONTROL|wire.SYNCHRONIZE), gotAccess)
		require.Zero(t, gotOptions)
	})

	t.Run("Truncate_Options", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := NewTransport(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := wire.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := wire.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &wire.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_ = f.fs.Truncate(context.Background(), "test.txt", 0)
		require.Equal(t, uint32(wire.FILE_WRITE_DATA), gotAccess)
		require.Equal(t, uint32(wire.FILE_NON_DIRECTORY_FILE), gotOptions)
		require.Zero(t, gotOptions&wire.FILE_SYNCHRONOUS_IO_NONALERT)
	})

	t.Run("ReadFile_GENERIC_READ", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := NewTransport(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := wire.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := wire.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &wire.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_, _ = f.fs.ReadFile(context.Background(), "test.txt")
		require.Equal(t, uint32(wire.GENERIC_READ), gotAccess)
		require.Equal(t, uint32(wire.FILE_NON_DIRECTORY_FILE), gotOptions)
	})

	t.Run("OpenFile_O_SYNC", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var gotOptions uint32
		go func() {
			dt := NewTransport(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := wire.CreateRequestDecoder(req[64:])
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "sync.txt", os.O_WRONLY|os.O_SYNC, 0o666)
		require.Equal(t, uint32(wire.FILE_WRITE_THROUGH), gotOptions)
	})

	t.Run("OpenFile_O_CREAT_O_EXCL", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotDisposition uint32
			gotOptions     uint32
		)
		go func() {
			dt := NewTransport(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := wire.CreateRequestDecoder(req[64:])
			gotDisposition = cr.CreateDisposition()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "excl.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		require.Equal(t, uint32(wire.FILE_CREATE), gotDisposition)
		require.Equal(t, uint32(wire.FILE_OPEN_REPARSE_POINT), gotOptions)
	})
}

func TestCanceledCreateReclaimsHandle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		compound     bool
		cancelAfter  int
		createStatus erref.NtStatus
		closeStatus  erref.NtStatus
		wantClose    int
	}{
		{name: "single success", wantClose: 1},
		{name: "single canceled", createStatus: erref.STATUS_CANCELLED},
		{name: "compound close succeeds", compound: true},
		{name: "compound close fails", compound: true, closeStatus: erref.STATUS_CANCELLED, wantClose: 1},
		{name: "create already received", compound: true, cancelAfter: 1, closeStatus: erref.STATUS_CANCELLED, wantClose: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fileID := &wire.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
			cancelSeen := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			closed := make(chan int, 1)
			go func() {
				defer serverConn.Close()
				dt := NewTransport(serverConn)
				req, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				for i := 0; ; i++ {
					p := wire.PacketCodec(req)
					if i == tc.cancelAfter {
						cancel()
						pkt, err := readMsg(dt)
						if err != nil {
							t.Error(err)
							return
						}
						if wire.PacketCodec(pkt).Command() != wire.SMB2_CANCEL {
							t.Error("expected CANCEL")
							return
						}
						close(cancelSeen)
						<-release
					}
					switch p.Command() {
					case wire.SMB2_CREATE:
						if tc.createStatus == erref.STATUS_SUCCESS {
							sendTestCreateAttributesResponse(dt, req, fileID, wire.FILE_ATTRIBUTE_NORMAL)
						} else {
							sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: p.Command()}, uint32(tc.createStatus))
						}
					case wire.SMB2_QUERY_INFO:
						sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 24))}, uint32(erref.STATUS_SUCCESS))
					case wire.SMB2_CLOSE:
						if tc.closeStatus == erref.STATUS_SUCCESS {
							sendTestCloseResponse(dt, req)
						} else {
							sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: p.Command()}, uint32(tc.closeStatus))
						}
					}
					if p.NextCommand() == 0 {
						break
					}
					req = req[p.NextCommand():]
				}
				closeCount := 0
				for {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return
					}
					p := wire.PacketCodec(req)
					switch p.Command() {
					case wire.SMB2_CANCEL:
					case wire.SMB2_CLOSE:
						closeCount++
						got := wire.CloseRequestDecoder(p.Body()).FileId().Decode()
						if *got != *fileID {
							t.Errorf("closed wrong handle: %v", got)
						}
						sendTestCloseResponse(dt, req)
					case wire.SMB2_FLUSH:
						sendTestResponse(dt, req, &wire.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
						closed <- closeCount
						return
					default:
						t.Errorf("unexpected command %v", p.Command())
						return
					}
				}
			}()
			result := make(chan error, 1)
			go func() {
				if tc.compound {
					res, err := fs.request().create("file", wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).
						queryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).close().sendRecv(ctx)
					res.close()
					result <- err
				} else {
					f, err := fs.Open(ctx, "file")
					if f != nil {
						_ = f.Close(context.Background())
					}
					result <- err
				}
			}()
			<-cancelSeen
			select {
			case err := <-result:
				t.Fatalf("returned before final CREATE response: %v", err)
			default:
			}
			close(release)
			require.ErrorIs(t, <-result, context.Canceled)
			// A separate request on the same connection must still succeed.
			res, err := fs.request().withFileId(fileID).flush().sendRecv(context.Background())
			require.NoError(t, err)
			res.close()
			require.Equal(t, tc.wantClose, <-closed)
		})
	}
}

func TestCreateSizeValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		operation  string
		size       int64
		allocation int64
		wantError  bool
	}{
		{name: "open rejects size", operation: "open", size: -1, wantError: true},
		{name: "append rejects allocation", operation: "append", size: 4096, allocation: -1, wantError: true},
		{name: "append rejects size", operation: "append", size: -1, wantError: true},
		{name: "stat rejects size", operation: "stat", size: -1, wantError: true},
		{name: "stat rejects allocation", operation: "stat", allocation: -1, wantError: true},
		{name: "lstat rejects size", operation: "lstat", size: -1, wantError: true},
		{name: "lstat rejects allocation", operation: "lstat", allocation: -1, wantError: true},
		{name: "stat accepts maximum int64", operation: "stat", size: 1<<63 - 1, allocation: 1<<63 - 1},
		{name: "readfile rejects size", operation: "readfile", size: -1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			fileID := &wire.FileId{Persistent: [8]byte{5}, Volatile: [8]byte{8}}
			closed := make(chan int, 1)
			go func() {
				defer serverConn.Close()
				dt := NewTransport(serverConn)
				closeCount := 0
				for {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return
					}
					for {
						p := wire.PacketCodec(req)
						switch p.Command() {
						case wire.SMB2_CREATE:
							sendTestResponse(dt, req, &wire.CreateResponse{
								FileId: fileID, EndofFile: test.size, AllocationSize: test.allocation,
								CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
								LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_READ:
							sendTestResponse(dt, req, &wire.ReadResponse{Data: []byte{1}}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_CLOSE:
							closeCount++
							sendTestCloseResponse(dt, req)
						case wire.SMB2_FLUSH:
							sendTestResponse(dt, req, &wire.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
							closed <- closeCount
							return
						default:
							t.Errorf("unexpected command: %v", p.Command())
							return
						}
						if p.NextCommand() == 0 {
							break
						}
						req = req[p.NextCommand():]
					}
				}
			}()
			var err error
			switch test.operation {
			case "open", "append":
				mode := os.O_RDONLY
				if test.operation == "append" {
					mode = os.O_WRONLY | os.O_APPEND
				}
				var f *File
				f, err = fs.OpenFile(context.Background(), "file", mode, 0)
				if err == nil {
					if test.operation == "append" {
						require.Equal(t, test.size, f.offset)
					}
					require.NoError(t, f.Close(context.Background()))
				}
			case "stat", "lstat":
				var info os.FileInfo
				if test.operation == "stat" {
					info, err = fs.Stat(context.Background(), "file")
				} else {
					info, err = fs.Lstat(context.Background(), "file")
				}
				if err == nil {
					require.Equal(t, test.size, info.Size())
					require.Equal(t, test.allocation, info.Sys().(*FileStat).AllocationSize)
				} else {
					require.Nil(t, info)
				}
			case "readfile":
				_, err = fs.ReadFile(context.Background(), "file")
			}
			if test.wantError {
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			} else {
				require.NoError(t, err)
			}
			// Probe the same connection to observe any extra cleanup requests.
			res, err := fs.request().withFileId(fileID).flush().sendRecv(context.Background())
			require.NoError(t, err)
			res.close()
			wantClose := 0
			if test.operation == "stat" || test.operation == "lstat" {
				wantClose = 1 // CLOSE was already part of the original compound.
			}
			require.Equal(t, wantClose, <-closed, "invalid CREATE must not trigger an extra CLOSE")
		})
	}
}

func TestShareRejectsDotComponentsBeforeSend(t *testing.T) {
	t.Parallel()
	// These paths retain a "." or ".." component after normPath, so they must
	// be rejected locally instead of being sent as a CREATE name.
	paths := []string{"..", `..\secret`, `dir\..\..\secret`, `a\.\b`, `a\..\b`}

	endpoints := []struct {
		name string
		op   string
		call func(fs *Share, path string) error
	}{
		{"OpenFile", "open", func(fs *Share, path string) error {
			_, err := fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
			return err
		}},
		{"RenameOld", "rename", func(fs *Share, path string) error {
			return fs.Rename(context.Background(), path, "new.txt")
		}},
		{"RenameNew", "rename", func(fs *Share, path string) error {
			return fs.Rename(context.Background(), "old.txt", path)
		}},
		{"GetSecurityDescriptor", "getSecurityDescriptor", func(fs *Share, path string) error {
			_, err := fs.GetSecurityDescriptor(context.Background(), path, 0)
			return err
		}},
		{"SetSecurityDescriptor", "setSecurityDescriptor", func(fs *Share, path string) error {
			return fs.SetSecurityDescriptor(context.Background(), path, nil)
		}},
	}

	for _, endpoint := range endpoints {
		for _, path := range paths {
			t.Run(endpoint.name+"/"+path, func(t *testing.T) {
				fs, serverConn := newTestShare(t)

				err := endpoint.call(fs, path)
				require.ErrorIs(t, err, os.ErrInvalid)

				switch e := err.(type) {
				case *os.LinkError:
					require.Equal(t, endpoint.op, e.Op)
				default:
					require.Equal(t, os.ErrInvalid, err)
				}

				requireNoRequest(t, serverConn)
			})
		}
	}
}

func TestRemoveAllRejectsNULDotDirectoryEntry(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := NewTransport(serverConn)
	var createNames []string
	done := make(chan struct{})

	go func() {
		defer close(done)
		for request := 1; ; request++ {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			p := wire.PacketCodec(req)
			if p.Command() == wire.SMB2_CREATE {
				d := wire.CreateRequestDecoder(p.Body())
				if !d.IsInvalid() {
					body := p.Body()
					off := int(d.NameOffset()) - 64
					end := off + int(d.NameLength())
					if off >= 0 && end <= len(body) {
						createNames = append(createNames, utf16le.DecodeToString(body[off:end]))
					}
				}
			}

			switch request {
			case 1:
				// The initial delete fails because the directory is not empty.
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
			case 2:
				sendTestCreateAttributesResponse(dt, req, &wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
			case 3:
				sendTestResponse(dt, req, &wire.QueryDirectoryResponse{
					Output: rawEncoder(encodeFileIdBothDirectoryInformationBytes(append(
						utf16le.EncodeStringToBytes(".."), 0, 0,
					))),
				}, uint32(erref.STATUS_SUCCESS))
			case 4:
				sendTestCloseResponse(dt, req)
			case 5:
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
				return
			}
		}
	}()

	err := fs.RemoveAll(context.Background(), "root")
	var invalidResponseErr *InvalidResponseError
	require.ErrorAs(t, err, &invalidResponseErr)
	<-done
	require.Equal(t, []string{"root", "root", "root"}, createNames)
}

// sendTestCreateCloseCompoundSuccess answers a CREATE+CLOSE compound (as sent
// by Share.Mkdir) with one success response per operation.
func sendTestCreateCloseCompoundSuccess(dt Transport, req []byte) {
	p := wire.PacketCodec(req)

	createRes := &wire.CreateResponse{
		FileId:         &wire.FileId{},
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)
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

	closeRes := &wire.CloseResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
	resBuf2 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf2)
	wire.PacketCodec(resBuf2).SetMessageId(p.MessageId() + 1)
	wire.PacketCodec(resBuf2).SetSessionId(p.SessionId())
	wire.PacketCodec(resBuf2).SetTreeId(p.TreeId())
	wire.PacketCodec(resBuf2).SetStatus(uint32(erref.STATUS_SUCCESS))
	wire.PacketCodec(resBuf2).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(resBuf2).SetCreditResponse(1)

	_, _ = dt.writev(append(padded1, resBuf2...))
}

func TestShareNormalizesSeparatorsBeforeSend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trailing slash", input: "dir/", want: "dir"},
		{name: "trailing backslash", input: `dir\`, want: "dir"},
		{name: "duplicate slashes", input: `a//b`, want: `a\b`},
		{name: "duplicate backslashes", input: `a\\b`, want: `a\b`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := NewTransport(serverConn)

			createNames := make(chan string, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				req, err := readMsg(dt)
				if err != nil {
					return
				}

				p := wire.PacketCodec(req)
				if p.Command() == wire.SMB2_CREATE {
					d := wire.CreateRequestDecoder(p.Body())
					if !d.IsInvalid() {
						body := p.Body()
						off := int(d.NameOffset()) - 64
						end := off + int(d.NameLength())
						if off >= 0 && end <= len(body) {
							createNames <- utf16le.DecodeToString(body[off:end])
						}
					}
				}
				sendTestCreateCloseCompoundSuccess(dt, req)
			}()

			require.NoError(t, fs.Mkdir(context.Background(), test.input, 0o755))
			<-done
			require.Equal(t, test.want, <-createNames)
		})
	}
}

func TestShareRemoveRejectsShareRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "dot", input: "."},
		{name: "dot backslash", input: `.\`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)

			err := fs.Remove(context.Background(), test.input)
			require.Equal(t, os.ErrInvalid, err)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestShareRenameRejectsShareRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		oldpath string
		newpath string
	}{
		{name: "empty old", oldpath: "", newpath: "new.txt"},
		{name: "dot old", oldpath: ".", newpath: "new.txt"},
		{name: "dot backslash old", oldpath: `.\`, newpath: "new.txt"},
		{name: "empty new", oldpath: "old.txt", newpath: ""},
		{name: "dot new", oldpath: "old.txt", newpath: "."},
		{name: "dot backslash new", oldpath: "old.txt", newpath: `.\`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)

			err := fs.Rename(context.Background(), test.oldpath, test.newpath)
			require.Equal(t, os.ErrInvalid, err)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestShareRemoveAllShareRoot(t *testing.T) {
	t.Parallel()
	t.Run("empty path is a no-op", func(t *testing.T) {
		fs, serverConn := newTestShare(t)

		require.NoError(t, fs.RemoveAll(context.Background(), ""))

		requireNoRequest(t, serverConn)
	})

	tests := []struct {
		name  string
		input string
	}{
		{name: "dot", input: "."},
		{name: "dot backslash", input: `.\`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)

			err := fs.RemoveAll(context.Background(), test.input)
			require.Equal(t, os.ErrInvalid, err)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestChmodHandleCleanup(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		cancelAt    wire.Command
		ownedFile   bool
		setStatus   erref.NtStatus
		closeStatus erref.NtStatus
		wantErr     error
	}{
		{name: "success"},
		{name: "cancel during set info", cancelAt: wire.SMB2_SET_INFO, wantErr: context.Canceled},
		{name: "cancel during close", cancelAt: wire.SMB2_CLOSE, wantErr: context.Canceled},
		{name: "set info denied", setStatus: erref.STATUS_ACCESS_DENIED, wantErr: erref.STATUS_ACCESS_DENIED},
		{name: "close denied", closeStatus: erref.STATUS_ACCESS_DENIED, wantErr: erref.STATUS_ACCESS_DENIED},
		{name: "preserve set info error", setStatus: erref.STATUS_ACCESS_DENIED, closeStatus: erref.STATUS_UNSUCCESSFUL, wantErr: erref.STATUS_ACCESS_DENIED},
		{name: "caller owned file", ownedFile: true},
		{name: "canceled caller owned file", ownedFile: true, cancelAt: wire.SMB2_SET_INFO, wantErr: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs, server := newTestShare(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fileID := &wire.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
			closed := make(chan int, 1)
			go func() {
				dt := NewTransport(server)
				var pending []byte
				closeCount := 0
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}
					p := wire.PacketCodec(req)
					switch p.Command() {
					case wire.SMB2_CREATE:
						sendTestCreateAttributesResponse(dt, req, fileID, wire.FILE_ATTRIBUTE_NORMAL)
					case wire.SMB2_QUERY_INFO:
						sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: &wire.FileBasicInformationEncoder{FileAttributes: wire.FILE_ATTRIBUTE_NORMAL}}, 0)
					case wire.SMB2_SET_INFO:
						if test.cancelAt == wire.SMB2_SET_INFO {
							// Keep SET_INFO outstanding until cleanup (or the next
							// operation for a caller-owned handle).
							pending = append([]byte(nil), req...)
							cancel()
						} else if test.setStatus != 0 {
							sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: p.Command()}, uint32(test.setStatus))
						} else {
							sendTestResponse(dt, req, &wire.SetInfoResponse{}, 0)
						}
					case wire.SMB2_CANCEL:
					case wire.SMB2_CLOSE, wire.SMB2_FLUSH:
						if pending != nil {
							sendTestResponse(dt, pending, &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, uint32(erref.STATUS_CANCELLED))
							pending = nil
						}
						if p.Command() == wire.SMB2_FLUSH {
							sendTestResponse(dt, req, &wire.FlushResponse{}, 0)
							closed <- closeCount
							return
						}
						closeCount++
						if got := wire.CloseRequestDecoder(p.Body()).FileId().Decode(); *got != *fileID {
							t.Errorf("closed wrong handle: %v", got)
						}
						if test.cancelAt == wire.SMB2_CLOSE {
							cancel()
						}
						if test.closeStatus != 0 {
							sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: p.Command()}, uint32(test.closeStatus))
						} else {
							sendTestCloseResponse(dt, req)
						}
					default:
						t.Errorf("unexpected command: %v", p.Command())
						return
					}
				}
			}()
			var err error
			if test.ownedFile {
				f := &File{fs: fs, fd: fileID, name: "file"}
				err = f.Chmod(ctx, 0o600)
			} else {
				err = fs.Chmod(ctx, "file", 0o600)
			}
			require.ErrorIs(t, err, test.wantErr)
			// A different handle on the shared connection must remain usable.
			barrier, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			require.NoError(t, fs.flush(barrier, &wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}))
			wantClose := 1
			if test.ownedFile {
				wantClose = 0
			}
			require.Equal(t, wantClose, <-closed)
			requests := fs.outstandingRequests
			requests.m.Lock()
			remaining := len(requests.requests)
			requests.m.Unlock()
			require.Zero(t, remaining)
		})
	}
}
