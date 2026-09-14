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
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

func TestFileAttributesFromPerm(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{name: "writable", perm: 0o666, want: smb2.FILE_ATTRIBUTE_NORMAL},
		{name: "readonly", perm: 0o444, want: smb2.FILE_ATTRIBUTE_NORMAL | smb2.FILE_ATTRIBUTE_READONLY},
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
	f := &File{}

	if _, err := f.ReadFrom(context.Background(), &BoundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("ReadFrom self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
	if _, err := f.WriteTo(context.Background(), &BoundFile{file: f, ctx: context.Background()}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("WriteTo self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
}

func TestFileCopyAcrossSharesSharingTreeConn(t *testing.T) {
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
				dt := direct(serverConn)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					switch smb2.PacketCodec(req).Command() {
					case smb2.SMB2_IOCTL:
						reqData := req[64:]
						if smb2.IoctlRequestDecoder(reqData).CtlCode() == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
							resumeKeyRequests.Add(1)
						}
						sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, 0xC0000001)
					case smb2.SMB2_READ:
						readReq := smb2.ReadRequestDecoder(req[64:])
						sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
					case smb2.SMB2_WRITE:
						sendTestResponse(dt, req, &smb2.WriteResponse{}, 0)
					}
				}
			}()

			srcFile := fs1.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "src.txt")
			dstFile := fs2.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

			tc.op(srcFile, dstFile)

			require.Equal(t, int32(1), resumeKeyRequests.Load(),
				"copyFile (FSCTL_SRV_REQUEST_RESUME_KEY) must be attempted between files opened from different Share instances sharing the same treeConn")
		})
	}
}

func TestShareReadlinkUsesSingleCredit(t *testing.T) {
	fs, serverConn := newTestShare(t)

	var recordedCmds []smb2.Command
	var ioctlCreditCharge uint16
	var maxOutputResponse uint32

	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := smb2.PacketCodec(currBuf)
			cmd := p.Command()
			recordedCmds = append(recordedCmds, cmd)

			var resBuf []byte
			switch cmd {
			case smb2.SMB2_CREATE:
				cres := &smb2.CreateResponse{
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case smb2.SMB2_IOCTL:
				ioctlCreditCharge = p.CreditCharge()
				req := smb2.IoctlRequestDecoder(currBuf[64:])
				maxOutputResponse = req.MaxOutputResponse()

				reparse := &smb2.SymbolicLinkReparseDataBuffer{
					Flags:          smb2.SYMLINK_FLAG_RELATIVE,
					SubstituteName: "target.txt",
					PrintName:      "target.txt",
				}
				buf := make([]byte, reparse.Size())
				reparse.Encode(buf)

				ires := &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_GET_REPARSE_POINT,
					Output:  rawEncoder(buf),
				}
				resBuf = make([]byte, ires.Size())
				ires.Encode(resBuf)

			case smb2.SMB2_CLOSE:
				clres := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, clres.Size())
				clres.Encode(resBuf)
			}

			if resBuf != nil {
				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
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
			_, _ = dt.Writev(finalBuf)
		}
	}()

	target, err := fs.Readlink(context.Background(), "link.txt")
	require.NoError(t, err)
	require.Equal(t, "target.txt", target)

	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_IOCTL, smb2.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(maxSingleCreditPayloadSize), maxOutputResponse)
	require.Equal(t, uint16(1), ioctlCreditCharge)
}

func TestShareReadlinkRejectsOddReparseNameLength(t *testing.T) {
	fs, serverConn := newTestShare(t)

	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		p := smb2.PacketCodec(reqBuf)
		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			curr := smb2.PacketCodec(currBuf)
			var res smb2.Packet
			switch curr.Command() {
			case smb2.SMB2_CREATE:
				res = &smb2.CreateResponse{
					FileId:         &smb2.FileId{},
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
			case smb2.SMB2_IOCTL:
				reparse := &smb2.SymbolicLinkReparseDataBuffer{
					SubstituteName: "target.txt",
					PrintName:      "target.txt",
				}
				data := make([]byte, reparse.Size())
				reparse.Encode(data)
				// Make only SubstituteNameLength odd while retaining the
				// otherwise valid reparse buffer.
				binary.LittleEndian.PutUint16(data[10:12], 1)
				res = &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_GET_REPARSE_POINT,
					Output:  rawEncoder(data),
				}
			case smb2.SMB2_CLOSE:
				res = &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
			}

			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(curr.MessageId())
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			responseBufs = append(responseBufs, resBuf)

			if curr.NextCommand() == 0 {
				break
			}
			currBuf = currBuf[curr.NextCommand():]
		}

		var finalBuf []byte
		for i, rb := range responseBufs {
			if i < len(responseBufs)-1 {
				next := uint32(smb2.Roundup(len(rb), 8))
				padded := make([]byte, next)
				copy(padded, rb)
				smb2.PacketCodec(padded).SetNextCommand(next)
				finalBuf = append(finalBuf, padded...)
			} else {
				finalBuf = append(finalBuf, rb...)
			}
		}
		_, _ = dt.Writev(finalBuf)
	}()

	target, err := fs.Readlink(context.Background(), "link.txt")
	require.Empty(t, target)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestRemoveAllRejectsInvalidDirectoryEntry(t *testing.T) {
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
			dt := direct(serverConn)
			var createNames []string
			done := make(chan struct{})

			go func() {
				defer close(done)
				for request := 1; ; request++ {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					p := smb2.PacketCodec(req)
					if p.Command() == smb2.SMB2_CREATE {
						d := smb2.CreateRequestDecoder(p.Body())
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
						sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY)
					case 3:
						sendTestResponse(dt, req, &smb2.QueryDirectoryResponse{
							Output: rawEncoder(encodeFileIdBothDirectoryInformation(test.entryName)),
						}, uint32(erref.STATUS_SUCCESS))
					case 4:
						sendTestCloseResponse(dt, req)
					case 5:
						sendTestCompoundSuccessResponse(dt, req)
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

func sendTestCompoundErrorResponse(dt transport, req []byte, status uint32) {
	p := smb2.PacketCodec(req)
	baseMsgId := p.MessageId()

	var parts [][]byte
	for i := range 3 {
		errPkt := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_CREATE,
		}
		resBuf := make([]byte, errPkt.Size())
		errPkt.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(baseMsgId + uint64(i))
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		if i == 0 {
			rp.SetStatus(status)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		} else {
			rp.SetStatus(uint32(erref.STATUS_INVALID_PARAMETER))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
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
			smb2.PacketCodec(padded).SetNextCommand(next)
			compound = append(compound, padded...)
		} else {
			smb2.PacketCodec(part).SetCreditResponse(1)
			compound = append(compound, part...)
		}
	}
	_, _ = dt.Writev(compound)
}

func TestShare_Remove_NoFallbackOnNonAccessError(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

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
	fs, serverConn := newTestShare(t)
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	dt := direct(serverConn)

	commands := make(chan smb2.Command, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(commands)
		for i := range 3 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			commands <- smb2.PacketCodec(req).Command()

			switch i {
			case 0, 1:
				endofFile := int64(4096)
				if i == 0 {
					endofFile = -1
				}
				res := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					EndofFile:      endofFile,
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			case 2:
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
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
	var gotCommands []smb2.Command
	for command := range commands {
		gotCommands = append(gotCommands, command)
	}
	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CREATE, smb2.SMB2_CLOSE}, gotCommands)
}

func sendTestCompoundSuccessResponse(dt transport, req []byte) {
	createRes := &smb2.CreateResponse{
		FileId:         &smb2.FileId{},
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	setInfoRes := &smb2.SetInfoResponse{}
	closeRes := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)
	resBuf2 := make([]byte, setInfoRes.Size())
	setInfoRes.Encode(resBuf2)
	resBuf3 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf3)

	p := smb2.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	smb2.PacketCodec(padded1).SetMessageId(p.MessageId())
	smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	smb2.PacketCodec(padded1).SetNextCommand(next1)

	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	smb2.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	smb2.PacketCodec(padded2).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded2).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded2).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(padded2).SetNextCommand(next2)

	smb2.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	smb2.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	smb2.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	smb2.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(resBuf3).SetCreditResponse(1)

	compound := append(padded1, padded2...)
	compound = append(compound, resBuf3...)
	_, _ = dt.Writev(compound)
}

func sendTestCloseResponse(dt transport, req []byte) {
	res := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_FallbackOnCannotDelete(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

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
			fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, smb2.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
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
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

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
			fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_ACCESS_DENIED
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_ACCESS_DENIED))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, smb2.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
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
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

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
				sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_SHARING_VIOLATION))
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

func sendTestCreateAttributesResponse(dt transport, req []byte, fileId *smb2.FileId, fileAttributes uint32) {
	sendTestResponse(dt, req, &smb2.CreateResponse{
		FileId:         fileId,
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
		FileAttributes: fileAttributes,
	}, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_ReadonlyFallbackPreservesExistingAttributes(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var (
		requestCount  atomic.Int32
		capturedAttrs atomic.Uint32
	)
	fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
	const initialAttrs = smb2.FILE_ATTRIBUTE_READONLY | smb2.FILE_ATTRIBUTE_HIDDEN | smb2.FILE_ATTRIBUTE_SYSTEM

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
				p := smb2.PacketCodec(reqBuf)
				if p.Command() == smb2.SMB2_SET_INFO {
					d := smb2.SetInfoRequestDecoder(p.Body())
					if !d.IsInvalid() && d.BufferLength() >= 40 {
						buf := p[d.BufferOffset() : d.BufferOffset()+uint16(d.BufferLength())]
						base := smb2.FileBasicInformationDecoder(buf)
						if !base.IsInvalid() {
							capturedAttrs.Store(base.FileAttributes())
						}
					}
				}
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
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
	expectedAttrs := uint32(smb2.FILE_ATTRIBUTE_NORMAL | smb2.FILE_ATTRIBUTE_HIDDEN | smb2.FILE_ATTRIBUTE_SYSTEM)
	require.Equal(t, expectedAttrs, capturedAttrs.Load(), "fallback chmod must preserve existing attributes (hidden, system) while clearing readonly")
}

// renameObservation records the SET_INFO BufferLength and the per-command
// CreditCharge of the CREATE + SET_INFO + CLOSE compound that Rename sends.
type renameObservation struct {
	commands      []smb2.Command
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
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			observed <- renameObservation{}
			return
		}

		var obs renameObservation
		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := smb2.PacketCodec(currBuf)
			obs.commands = append(obs.commands, p.Command())
			obs.creditCharges = append(obs.creditCharges, p.CreditCharge())
			nextCommand := p.NextCommand()

			var resBuf []byte
			switch p.Command() {
			case smb2.SMB2_CREATE:
				res := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case smb2.SMB2_SET_INFO:
				obs.setInfoLength = smb2.SetInfoRequestDecoder(p.Body()).BufferLength()
				res := &smb2.SetInfoResponse{}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case smb2.SMB2_CLOSE:
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			}

			if resBuf != nil {
				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				flags := uint32(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				if len(responseBufs) > 0 {
					flags |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
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
				smb2.PacketCodec(padded).SetNextCommand(next)
				compound = append(compound, padded...)
			} else {
				compound = append(compound, rb...)
			}
		}
		if len(compound) > 0 {
			if _, err := dt.Writev(compound); err != nil {
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
		require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_SET_INFO, smb2.SMB2_CLOSE}, obs.commands)
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
		require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_SET_INFO, smb2.SMB2_CLOSE}, obs.commands)
		require.Equal(t, uint32(setInfoSize), obs.setInfoLength)
		require.Equal(t, []uint16{1, 2, 1}, obs.creditCharges)
		require.Equal(t, uint32(4), obs.totalCreditCharge())
	})
}

func TestLstatDoesNotRegisterFinalizer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
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
		return smb2.FiletimeDecoder(raw).Time()
	}

	// Fake server that counts CREATE and CLOSE requests so we can detect
	// a spurious CLOSE triggered by a runtime finalizer after GC.
	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()

				var resBuf []byte
				switch p.Command() {
				case smb2.SMB2_CREATE:
					atomic.AddInt64(&createCount, 1)
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{LowDateTime: creationLow, HighDateTime: creationHigh},
						LastAccessTime: &smb2.Filetime{LowDateTime: accessLow, HighDateTime: accessHigh},
						LastWriteTime:  &smb2.Filetime{LowDateTime: writeLow, HighDateTime: writeHigh},
						ChangeTime:     &smb2.Filetime{LowDateTime: changeLow, HighDateTime: changeHigh},
						AllocationSize: allocationSize,
						EndofFile:      endOfFile,
						FileAttributes: fileAttributes,
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					atomic.AddInt64(&closeCount, 1)
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
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
				_, _ = dt.Writev(finalBuf)
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
	t.Run("OpenFile_O_APPEND", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "append.txt", os.O_WRONLY|os.O_APPEND, 0o666)
		require.Equal(t, uint32(smb2.FILE_APPEND_DATA|smb2.FILE_WRITE_EA|smb2.FILE_WRITE_ATTRIBUTES|smb2.READ_CONTROL|smb2.SYNCHRONIZE), gotAccess)
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
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := smb2.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_ = f.fs.Truncate(context.Background(), "test.txt", 0)
		require.Equal(t, uint32(smb2.FILE_WRITE_DATA), gotAccess)
		require.Equal(t, uint32(smb2.FILE_NON_DIRECTORY_FILE), gotOptions)
		require.Zero(t, gotOptions&smb2.FILE_SYNCHRONOUS_IO_NONALERT)
	})

	t.Run("ReadFile_GENERIC_READ", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := smb2.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_, _ = f.fs.ReadFile(context.Background(), "test.txt")
		require.Equal(t, uint32(smb2.GENERIC_READ), gotAccess)
		require.Equal(t, uint32(smb2.FILE_NON_DIRECTORY_FILE), gotOptions)
	})

	t.Run("OpenFile_O_SYNC", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var gotOptions uint32
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "sync.txt", os.O_WRONLY|os.O_SYNC, 0o666)
		require.Equal(t, uint32(smb2.FILE_WRITE_THROUGH), gotOptions)
	})

	t.Run("OpenFile_O_CREAT_O_EXCL", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotDisposition uint32
			gotOptions     uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotDisposition = cr.CreateDisposition()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile(context.Background(), "excl.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		require.Equal(t, uint32(smb2.FILE_CREATE), gotDisposition)
		require.Equal(t, uint32(smb2.FILE_OPEN_REPARSE_POINT), gotOptions)
	})
}

func TestCanceledCreateReclaimsHandle(t *testing.T) {
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
			fileID := &smb2.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
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
				dt := direct(serverConn)
				req, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				for i := 0; ; i++ {
					p := smb2.PacketCodec(req)
					if i == tc.cancelAfter {
						cancel()
						pkt, err := readMsg(dt)
						if err != nil {
							t.Error(err)
							return
						}
						if smb2.PacketCodec(pkt).Command() != smb2.SMB2_CANCEL {
							t.Error("expected CANCEL")
							return
						}
						close(cancelSeen)
						<-release
					}
					switch p.Command() {
					case smb2.SMB2_CREATE:
						if tc.createStatus == erref.STATUS_SUCCESS {
							sendTestCreateAttributesResponse(dt, req, fileID, smb2.FILE_ATTRIBUTE_NORMAL)
						} else {
							sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(tc.createStatus))
						}
					case smb2.SMB2_QUERY_INFO:
						sendTestResponse(dt, req, &smb2.QueryInfoResponse{Output: rawEncoder(make([]byte, 24))}, uint32(erref.STATUS_SUCCESS))
					case smb2.SMB2_CLOSE:
						if tc.closeStatus == erref.STATUS_SUCCESS {
							sendTestCloseResponse(dt, req)
						} else {
							sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(tc.closeStatus))
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
					p := smb2.PacketCodec(req)
					switch p.Command() {
					case smb2.SMB2_CANCEL:
					case smb2.SMB2_CLOSE:
						closeCount++
						got := smb2.CloseRequestDecoder(p.Body()).FileId().Decode()
						if *got != *fileID {
							t.Errorf("closed wrong handle: %v", got)
						}
						sendTestCloseResponse(dt, req)
					case smb2.SMB2_FLUSH:
						sendTestResponse(dt, req, &smb2.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
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
					res, err := fs.request().create("file", smb2.GENERIC_READ, smb2.FILE_OPEN, 0, 0).
						queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 0, 24).close().sendRecv(ctx)
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
			fileID := &smb2.FileId{Persistent: [8]byte{5}, Volatile: [8]byte{8}}
			closed := make(chan int, 1)
			go func() {
				defer serverConn.Close()
				dt := direct(serverConn)
				closeCount := 0
				for {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return
					}
					for {
						p := smb2.PacketCodec(req)
						switch p.Command() {
						case smb2.SMB2_CREATE:
							sendTestResponse(dt, req, &smb2.CreateResponse{
								FileId: fileID, EndofFile: test.size, AllocationSize: test.allocation,
								CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
								LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						case smb2.SMB2_READ:
							sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, uint32(erref.STATUS_SUCCESS))
						case smb2.SMB2_CLOSE:
							closeCount++
							sendTestCloseResponse(dt, req)
						case smb2.SMB2_FLUSH:
							sendTestResponse(dt, req, &smb2.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
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

func TestRemoveAllRejectsNULDotDirectoryEntry(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)
	var createNames []string
	done := make(chan struct{})

	go func() {
		defer close(done)
		for request := 1; ; request++ {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(req)
			if p.Command() == smb2.SMB2_CREATE {
				d := smb2.CreateRequestDecoder(p.Body())
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
				sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY)
			case 3:
				sendTestResponse(dt, req, &smb2.QueryDirectoryResponse{
					Output: rawEncoder(encodeFileIdBothDirectoryInformationBytes(append(
						utf16le.EncodeStringToBytes(".."), 0, 0,
					))),
				}, uint32(erref.STATUS_SUCCESS))
			case 4:
				sendTestCloseResponse(dt, req)
			case 5:
				sendTestCompoundSuccessResponse(dt, req)
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

func TestShareRemoveRejectsShareRoot(t *testing.T) {
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
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			require.Equal(t, "remove", pathErr.Op)
			require.Equal(t, "", pathErr.Path)
			require.ErrorIs(t, err, os.ErrInvalid)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestShareRenameRejectsShareRoot(t *testing.T) {
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
			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "rename", linkErr.Op)
			require.Equal(t, normPath(test.oldpath), linkErr.Old)
			require.Equal(t, normPath(test.newpath), linkErr.New)
			require.ErrorIs(t, err, os.ErrInvalid)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestShareRemoveAllShareRoot(t *testing.T) {
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
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			require.Equal(t, "removeall", pathErr.Op)
			require.Equal(t, test.input, pathErr.Path)
			require.ErrorIs(t, err, os.ErrInvalid)

			requireNoRequest(t, serverConn)
		})
	}
}

func TestShareRemoveDirectRejectsEmptyName(t *testing.T) {
	fs, serverConn := newTestShare(t)

	err := fs.removeDirect(context.Background(), "")
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "remove", pathErr.Op)
	require.Equal(t, "", pathErr.Path)
	require.ErrorIs(t, err, os.ErrInvalid)

	requireNoRequest(t, serverConn)
}
