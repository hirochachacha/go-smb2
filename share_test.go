package smb2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShareReadlinkUsesSingleCredit(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	var recordedCmds []wire.Command
	var ioctlCreditCharge uint16
	var maxOutputResponse uint32

	go func() {
		dt := serverConn
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
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, finalBuf)
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
		dt := serverConn
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
					FileId:         wire.FileId{},
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, finalBuf)
	}()

	target, err := fs.Readlink(context.Background(), "link.txt")
	require.Empty(t, target)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func newTestShare(t *testing.T, options ...testServerOptions) (*Share, net.Conn) {
	t.Helper()
	return newProtocolTestShare(t, options...)
}

func sendTestCompoundErrorResponse(dt net.Conn, req []byte, status uint32) {
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
	_, _ = testWritePacket(dt, compound)
}

func TestShare_Remove_NoFallbackOnNonAccessError(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

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
	dt := serverConn

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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
					EndofFile:      endofFile,
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			case 2:
				res := &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	file, err := fs.OpenFile(context.Background(), "negative.txt", os.O_WRONLY|os.O_APPEND, 0)
	var invalidResponseErr *protocol.InvalidResponseError
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

func sendTestCompoundSuccessResponse(dt net.Conn, req []byte) {
	createRes := &wire.CreateResponse{
		FileId:         wire.FileId{},
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}
	setInfoRes := &wire.SetInfoResponse{}
	closeRes := &wire.CloseResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
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
	_, _ = testWritePacket(dt, compound)
}

func sendTestCloseResponse(dt net.Conn, req []byte) {
	res := &wire.CloseResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}
	sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_FallbackOnCannotDelete(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

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
			fileId := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
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
	dt := serverConn

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
			fileId := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
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
	dt := serverConn

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

func sendTestCreateAttributesResponse(dt net.Conn, req []byte, fileId wire.FileId, fileAttributes uint32) {
	sendTestResponse(dt, req, &wire.CreateResponse{
		FileId:         fileId,
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
		FileAttributes: fileAttributes,
	}, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_ReadonlyFallbackPreservesExistingAttributes(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

	var (
		requestCount  atomic.Int32
		capturedAttrs atomic.Uint32
	)
	fileId := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
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
		dt := serverConn
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
			if _, err := testWritePacket(dt, compound); err != nil {
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
		fs, serverConn := newTestShare(t, testServerOptions{maxTransactSize: maxTransact})
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
		fs, serverConn := newTestShare(t, testServerOptions{maxTransactSize: maxTransact})

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
		fs, serverConn := newTestShare(t, testServerOptions{maxTransactSize: 1 << 20, credits: 3})
		require.Equal(t, maxSingleCreditPayloadSize, fs.maxTransactSize(2))

		requireRenameRejectedLocally(t, fs, serverConn, newpath)
	})

	t.Run("credit cap of four sends a four-credit compound", func(t *testing.T) {
		fs, serverConn := newTestShare(t, testServerOptions{maxTransactSize: 1 << 20, credits: 4})
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
			dt := serverConn
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
		require.Equal(t, uint32(wire.GENERIC_WRITE), gotAccess)
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
			dt := serverConn
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
			dt := serverConn
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
			dt := serverConn
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
			dt := serverConn
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
			fileID := wire.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
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
				dt := serverConn
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
						if got != fileID {
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
					res, err := fs.Request().WithFollowSymlinks(true).Create("file", wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).
						QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).Close().Do(ctx)
					res.Close()
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
			res, err := fs.Request().WithFollowSymlinks(true).WithFileID(fileID).Flush().Do(context.Background())
			require.NoError(t, err)
			res.Close()
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
			fileID := wire.FileId{Persistent: [8]byte{5}, Volatile: [8]byte{8}}
			closed := make(chan int, 1)
			go func() {
				defer serverConn.Close()
				dt := serverConn
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
								CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{},
								LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_QUERY_INFO:
							sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 8))}, uint32(erref.STATUS_SUCCESS))
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
				var invalid *protocol.InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			} else {
				require.NoError(t, err)
			}
			// Probe the same connection to observe any extra cleanup requests.
			res, err := fs.Request().WithFollowSymlinks(true).WithFileID(fileID).Flush().Do(context.Background())
			require.NoError(t, err)
			res.Close()
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

// sendTestCreateCloseCompoundSuccess answers a CREATE+CLOSE compound (as sent
// by Share.Mkdir) with one success response per operation.
func sendTestCreateCloseCompoundSuccess(dt net.Conn, req []byte) {
	p := wire.PacketCodec(req)

	createRes := &wire.CreateResponse{
		FileId:         wire.FileId{},
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
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
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}
	resBuf2 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf2)
	wire.PacketCodec(resBuf2).SetMessageId(p.MessageId() + 1)
	wire.PacketCodec(resBuf2).SetSessionId(p.SessionId())
	wire.PacketCodec(resBuf2).SetTreeId(p.TreeId())
	wire.PacketCodec(resBuf2).SetStatus(uint32(erref.STATUS_SUCCESS))
	wire.PacketCodec(resBuf2).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_RELATED_OPERATIONS)
	wire.PacketCodec(resBuf2).SetCreditResponse(1)

	_, _ = testWritePacket(dt, append(padded1, resBuf2...))
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
			dt := serverConn

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
			fileID := wire.FileId{Persistent: [8]byte{7}, Volatile: [8]byte{9}}
			closed := make(chan int, 1)
			go func() {
				dt := server
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
						if got := wire.CloseRequestDecoder(p.Body()).FileId().Decode(); got != fileID {
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
			require.NoError(t, fs.flush(barrier, wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}))
			wantClose := 1
			if test.ownedFile {
				wantClose = 0
			}
			require.Equal(t, wantClose, <-closed)
		})
	}
}

func TestShareStatUsesCompoundCreateQueryClose(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)

	var recordedCmds []wire.Command
	var createOptions uint32
	var createCount, closeCount int

	go func() {
		dt := serverConn
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
					CreationTime:   wire.Filetime{LowDateTime: 0x11223344, HighDateTime: 0x01234567},
					LastAccessTime: wire.Filetime{LowDateTime: 0x55667788, HighDateTime: 0x01234567},
					LastWriteTime:  wire.Filetime{LowDateTime: 0x99aabbcc, HighDateTime: 0x01234567},
					ChangeTime:     wire.Filetime{LowDateTime: 0xddeeff00, HighDateTime: 0x01234567},
					AllocationSize: 8192,
					EndofFile:      4096,
					FileAttributes: wire.FILE_ATTRIBUTE_ARCHIVE,
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case wire.SMB2_QUERY_INFO:
				output := make([]byte, 8)
				le.PutUint32(output[:4], wire.FILE_ATTRIBUTE_ARCHIVE)
				qres := &wire.QueryInfoResponse{Output: rawEncoder(output)}
				resBuf = make([]byte, qres.Size())
				qres.Encode(resBuf)

			case wire.SMB2_CLOSE:
				closeCount++
				clres := &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, finalBuf)
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

	require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_QUERY_INFO, wire.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(0), createOptions, "Share.Stat must not set FILE_OPEN_REPARSE_POINT")
	require.Equal(t, 1, createCount)
	require.Equal(t, 1, closeCount)
}

func TestChmodStillUsesFileBasicInformation(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t)
	dt := serverConn
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
	if _, ok := wire.TimeToFiletime(t); !ok {
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
			fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})

			var input []byte
			var ctlCode uint32
			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt net.Conn) bool {
				req := wire.IoctlRequestDecoder(reqBuf[64:])
				ctlCode = req.CtlCode()
				inputOffset := int(req.InputOffset()) - 64
				inputCount := int(req.InputCount())
				input = append([]byte(nil), reqBuf[64+inputOffset:64+inputOffset+inputCount]...)

				res := &wire.IoctlResponse{
					CtlCode: wire.FSCTL_SET_REPARSE_POINT,
					FileId:  wire.FileId{},
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
			fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})

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
			_, readErr := readMsg(serverConn)
			require.Error(t, readErr, "oversized symlink must not send CREATE, IOCTL, or CLOSE")
		})
	}
}

func TestSymlinkCreateCollisionDoesNotRemove(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})

	var receivedCommands []wire.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := serverConn
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
		_, _ = testWritePacket(st, allResp)

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

	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	// Should only have received the initial CREATE (compound start) and NOT a second CREATE (for Remove)
	require.Equal(t, []wire.Command{wire.SMB2_CREATE}, receivedCommands)
}

func TestSymlinkIoctlFailureDoesRemove(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})

	var receivedCommands []wire.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := serverConn
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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
			FileId: wire.FileId{
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
		_, _ = testWritePacket(st, allResp)

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
		_, _ = testWritePacket(st, closeResp)

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
		_, _ = testWritePacket(st, allRemResp)
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

	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	const fileSize = 512 * 1024
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go func() {
		dt := serverConn
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

				testWritePacket(dt, resBuf)

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

				testWritePacket(dt, resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	_, err := rand.Read(testPayload)
	req.NoError(err)

	dummyFd := wire.FileId{}
	wn, err := fs.writeAt(context.Background(), dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(context.Background(), dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestCreateFileCleansRelativeSymlinkTarget(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})

	createNames := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := serverConn

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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
			FileId:         wire.FileId{},
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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

func TestRejectsOverlongResolvedSymlinkPath(t *testing.T) {
	t.Parallel()
	for _, useBuilder := range []bool{false, true} {
		name := "OpenFile"
		if useBuilder {
			name = "requestBuilder"
		}
		t.Run(name, func(t *testing.T) {
			fs, serverConn := newProtocolTestShare(t, testServerOptions{sessionID: 0x1234, treeID: 1})
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			overlongName := "d" + strings.Repeat("a", 32766)
			creates := make(chan string, 3)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer close(creates)
				defer serverConn.Close()
				dt := serverConn
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
							CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{},
							LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{},
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
								CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{},
								LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{},
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
						CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{},
						LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{},
						FileId: wire.FileId{}, FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
					}, 0)
				}
			}()

			open := func(path string) error {
				if useBuilder {
					res, err := fs.Request().WithFollowSymlinks(true).Create(path, wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).Close().Do(ctx)
					if res != nil {
						res.Close()
					}
					return err
				}
				f, err := fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
				if err == nil {
					return f.Close(context.Background())
				}
				return err
			}
			require.ErrorContains(t, open(overlongName), "protocol: resolved symbolic link path exceeds uint16")
			require.NoError(t, open("plain.txt"))
			serverConn.Close()
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
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

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

func sendReadFileLengthResponse(dt net.Conn, req []byte, fileID wire.FileId, status uint32, adjustment int) {
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
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
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
	_, _ = testWritePacket(dt, compound)
}

func sendReadFileCloseResponse(dt net.Conn, req []byte) wire.FileId {
	p := wire.PacketCodec(req)
	fileID := wire.CloseRequestDecoder(p.Body()).FileId().Decode()
	closeRes := &wire.CloseResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
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
	_, _ = testWritePacket(dt, closeBuf)
	return fileID
}

func requireReadFileLengthError(t *testing.T, data []byte, err error) {
	t.Helper()
	require.Nil(t, data)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "readfile", pathErr.Op)
	require.Equal(t, "test.txt", pathErr.Path)
	var invalidErr *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalidErr)
	require.Equal(t, "read length exceeds requested length", invalidErr.Message)
}

func TestReadFileReadLengthBoundary(t *testing.T) {
	t.Parallel()
	for _, adjustment := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(adjustment), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
			dt := serverConn
			expectedFileID := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			closeReceived := make(chan wire.FileId, 1)
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
	dt := serverConn
	expectedFileID := wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	closeReceived := make(chan wire.FileId, 1)
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

	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})
	recorder := &copyChunkRecorder{}

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := wire.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == wire.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			res := &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			rp := wire.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, resBuf)
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
		res := &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(respBuf)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		rp := wire.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetCreditResponse(1)
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		testWritePacket(dt, resBuf)
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

func newCopyFailureTestFiles(t *testing.T, endOfFile int64, failAfter int, status erref.NtStatus) (*File, *File) {
	t.Helper()

	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	copyCalls := 0
	startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt net.Conn) bool {
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
					CtlCode: req.CtlCode(),
					Output:  rawEncoder(limit),
				}, uint32(status))
				return true
			}

			response := make([]byte, 12)
			le.PutUint32(response[0:4], chunkCount)
			le.PutUint32(response[4:8], total)
			le.PutUint32(response[8:12], total)
			sendTestResponse(dt, reqBuf, &wire.IoctlResponse{
				CtlCode: req.CtlCode(),
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

// copyPermissionFile is the per-CREATE state tracked by copyPermissionServer.
type copyPermissionFile struct {
	id      wire.FileId
	access  uint32
	content []byte
}

func fileIdKey(id wire.FileId) string {
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

	srv := &copyPermissionServer{
		config: config,
		files:  map[string]*copyPermissionFile{},
	}
	fs, serverConn := newProtocolTestShare(t)

	go srv.serve(serverConn)

	return fs, srv
}

func (s *copyPermissionServer) serve(serverConn net.Conn) {
	defer serverConn.Close()
	dt := serverConn
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
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
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

func (s *copyPermissionServer) handleCreate(dt net.Conn, reqBuf []byte) {
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
	s.files[fileIdKey(id)] = f
	s.mu.Unlock()

	sendTestResponse(dt, reqBuf, &wire.CreateResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
		FileId:         id,
	}, 0)
}

func (s *copyPermissionServer) handleQueryInfo(dt net.Conn, reqBuf []byte) {
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

func (s *copyPermissionServer) handleRead(dt net.Conn, reqBuf []byte) {
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

func (s *copyPermissionServer) handleWrite(dt net.Conn, reqBuf []byte) {
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

func (s *copyPermissionServer) handleIoctl(dt net.Conn, reqBuf []byte) {
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
		sendTestResponse(dt, reqBuf, &wire.IoctlResponse{CtlCode: req.CtlCode(), Output: rawEncoder(make([]byte, 32))}, 0)
	case wire.FSCTL_SRV_COPYCHUNK, wire.FSCTL_SRV_COPYCHUNK_WRITE:
		s.handleCopyChunk(dt, reqBuf, req.CtlCode())
	default:
		sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, uint32(erref.STATUS_NOT_SUPPORTED))
	}
}

func (s *copyPermissionServer) handleCopyChunk(dt net.Conn, reqBuf []byte, ctlCode uint32) {
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
	sendTestResponse(dt, reqBuf, &wire.IoctlResponse{CtlCode: ctlCode, Output: rawEncoder(respBuf)}, 0)
}

func (s *copyPermissionServer) content(id wire.FileId) []byte {
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
	dt := serverConn

	expectedFileId := wire.FileId{
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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, compound)

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
				if fd == expectedFileId {
					closeReceived.Store(true)
				}
			}
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, closeBuf)
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
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, credits: 100, singleCredit: true})

	dt := serverConn
	fileId1 := wire.FileId{Persistent: [8]byte{1, 1}, Volatile: [8]byte{2, 2}}
	fileId2 := wire.FileId{Persistent: [8]byte{3, 3}, Volatile: [8]byte{4, 4}}

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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, compound)

		// Request 2: auto-close of fileId1 by tree_conn.sendRecv
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := wire.PacketCodec(reqBuf2)
		if p2.Command() == wire.SMB2_CLOSE {
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, closeBuf)
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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, resBuf3)

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
		_, _ = testWritePacket(dt, resBuf4)

		// Request 5: CLOSE of fileId2 by deferred file cleanup.
		reqBuf5, err := readMsg(dt)
		if err != nil {
			return
		}
		p5 := wire.PacketCodec(reqBuf5)
		closeRes2 := &wire.CloseResponse{
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, closeBuf2)
	}()

	data, err := fs.ReadFile(context.Background(), "test.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world!"), data)

	<-done
}

func sendTestCompoundMidFailureResponse(dt net.Conn, req []byte, fileId wire.FileId, status uint32) {
	createRes := &wire.CreateResponse{
		FileId:         fileId,
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
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

	_, _ = testWritePacket(dt, compound)
}

func TestCompoundMidFailureClosesServerHandle(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn

	expectedFileId := wire.FileId{
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
				if fd == expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, closeBuf)
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
	dt := serverConn

	expectedFileId := wire.FileId{
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
			CreationTime:   wire.Filetime{},
			LastAccessTime: wire.Filetime{},
			LastWriteTime:  wire.Filetime{},
			ChangeTime:     wire.Filetime{},
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
		_, _ = testWritePacket(dt, compound)

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
				if fd == expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &wire.CloseResponse{
				CreationTime:   wire.Filetime{},
				LastAccessTime: wire.Filetime{},
				LastWriteTime:  wire.Filetime{},
				ChangeTime:     wire.Filetime{},
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
			_, _ = testWritePacket(dt, closeBuf)
		}
	}()

	_, err := fs.ReadFile(context.Background(), "test.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when ReadFile fails mid-flight")
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

func TestShareChmodUsesCreateAttributes(t *testing.T) {
	t.Parallel()
	for _, status := range []erref.NtStatus{erref.STATUS_SUCCESS, erref.STATUS_ACCESS_DENIED} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := serverConn
			fileID := wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
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
				assert.Equal(t, fileID, req.FileId().Decode())
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
				assert.Equal(t, fileID, wire.CloseRequestDecoder(p.Body()).FileId().Decode())
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

func TestIoctlResponseSumExceedsMaxTransactSize(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxTransactSize: 65536, treeID: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
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
		_, err := fs.ioctl(ctx, wire.FileId{}, req)
		errCh <- err
	}()

	require.NoError(t, serverConn.SetDeadline(time.Now().Add(2*time.Second)))
	dt := serverConn
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
func fakeServerFull(t net.Conn, responseData []byte, dirEntries []byte, sessionId uint64) {
	dirQueryCount := 0

	for {
		reqBuf, err := readMsg(t)
		if err != nil {
			return
		}
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
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
					AllocationSize: int64(len(responseData)),
					EndofFile:      int64(len(responseData)),
					FileAttributes: wire.FILE_ATTRIBUTE_NORMAL,
					FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				singleResp = make([]byte, cres.Size())
				cres.Encode(singleResp)

			case wire.SMB2_CLOSE:
				clres := &wire.CloseResponse{
					PacketHeader: wire.PacketHeader{
						Flags:     wire.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
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
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
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

		if _, err := testWritePacket(t, compoundResp); err != nil {
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
			fs, serverConn := newProtocolTestShare(b)

			responseData := make([]byte, sz.n)
			go fakeServerFull(serverConn, responseData, nil, 0x100)

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
			fs, serverConn := newProtocolTestShare(b)

			go fakeServerFull(serverConn, nil, nil, 0)

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
	fs, serverConn := newProtocolTestShare(b)

	go fakeServerFull(serverConn, nil, nil, 0)

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
func serveWriteFile(t *testing.T, dt net.Conn, state *writeFileServerState) {
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
					sendTestResponse(dt, req[off:], &wire.CreateResponse{CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{}, LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{}, FileId: wire.FileId{}}, 0)
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
				sendTestResponse(dt, req[off:], &wire.CloseResponse{CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{}, LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{}}, 0)
			default:
				t.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}
}

func TestWriteFileDesiredAccess(t *testing.T) {
	t.Parallel()
	f, serverConn := newTestFile(t, testServerOptions{maxWriteSize: 65536})

	state := &writeFileServerState{}
	go serveWriteFile(t, serverConn, state)

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
			f, serverConn := newTestFile(t, testServerOptions{maxWriteSize: 65536})

			state := &writeFileServerState{}
			go serveWriteFile(t, serverConn, state)

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
				f, server := newTestFile(t, testServerOptions{maxWriteSize: 65536})
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				share := f.fs
				serverDone := make(chan error, 1)
				go func() {
					dt := server
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
							res = &wire.CreateResponse{CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{}, LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{}, FileId: wire.FileId{}}
						case wire.SMB2_WRITE:
							if got := wire.WriteRequestDecoder(p.Body()).Length(); got != uint32(length) {
								serverDone <- fmt.Errorf("write length = %d", got)
								return
							}
							res = &wire.WriteResponse{Count: count}
						case wire.SMB2_CLOSE:
							res = &wire.CloseResponse{CreationTime: wire.Filetime{}, LastAccessTime: wire.Filetime{}, LastWriteTime: wire.Filetime{}, ChangeTime: wire.Filetime{}}
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
					var invalid *protocol.InvalidResponseError
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

func TestInvalidTreePayloadSize(t *testing.T) {
	// Reject an uninitialized tree before choosing either the sequential or
	// pipelined path; a zero-size sequential read must not loop without progress.
	fs := &Share{}
	for _, operation := range []struct {
		name string
		run  func() (int, error)
	}{
		{"read", func() (int, error) { return fs.readAt(context.Background(), wire.FileId{}, make([]byte, 1), 0) }},
		{"write", func() (int, error) { return fs.writeAt(context.Background(), wire.FileId{}, []byte{1}, 0) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			n, err := operation.run()
			require.Zero(t, n)
			require.ErrorIs(t, err, os.ErrInvalid)
		})
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

func setupPipelineFile(t testing.TB, credits uint16, options ...testServerOptions) (*File, net.Conn) {
	t.Helper()
	opts := testServerOptions{
		credits:         credits,
		maxReadSize:     pipelineChunk,
		maxWriteSize:    pipelineChunk,
		maxTransactSize: pipelineChunk,
	}
	if len(options) != 0 {
		opts.ioPipelineDepth = options[0].ioPipelineDepth
		opts.wrapClient = options[0].wrapClient
	}
	f, peer := newTestFile(t, opts)
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return f, peer
}

func collectPipelineRequest(t *testing.T, dt net.Conn) pipelineRequest {
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

func sendPipelineResponse(t net.Conn, req pipelineRequest, res wire.Packet, status erref.NtStatus) error {
	buf := pipelineResponseBytes(req, res, status)
	_, err := testWritePacket(t, buf)
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

func pipelineReadResponse(t net.Conn, req pipelineRequest, n int) error {
	return sendPipelineResponse(t, req, &wire.ReadResponse{Data: pipelineReadData(req.off, n)}, erref.STATUS_SUCCESS)
}

func pipelineWriteResponse(t net.Conn, req pipelineRequest, n int) error {
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
	dt := peer
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
	dt := peer
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
	dt := peer
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
	f, peer := setupPipelineFile(t, 8, testServerOptions{ioPipelineDepth: depth})
	if depth == 0 {
		depth = 4
	}
	dt := peer
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

func executePipelineEcho(f *File, ctx context.Context) error {
	res, err := f.fs.Request().Append(&wire.EchoRequest{}).Do(ctx)
	if res != nil {
		res.Close()
	}
	return err
}

// The test supplies the fixed READ header separately. A socket read into the
// entire chunk therefore starts only after the transport selects the direct
// destination; observing the header alone would race that selection.
type directReadSignalConn struct {
	net.Conn
	ready chan<- struct{}
	once  sync.Once
}

func (c *directReadSignalConn) Read(p []byte) (int, error) {
	if len(p) == pipelineChunk {
		c.once.Do(func() { close(c.ready) })
	}
	return c.Conn.Read(p)
}

func TestIOPipelineReadErrorReportsContiguousPrefix(t *testing.T) {
	t.Parallel()
	f, peer := setupPipelineFile(t, 4)
	dt := peer
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
	dt := peer
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
	dt := peer
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
	dt := peer
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
	dt := peer
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
	dt := peer
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
	go func() { echoDone <- executePipelineEcho(f, context.Background()) }()
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
	directReadReady := make(chan struct{})
	f, peer := setupPipelineFile(t, 2, testServerOptions{
		wrapClient: func(conn net.Conn) net.Conn {
			return &directReadSignalConn{Conn: conn, ready: directReadReady}
		},
	})
	dt := peer
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
	select {
	case <-directReadReady:
	case <-time.After(5 * time.Second):
		t.Fatal("direct READ reception did not become in-flight")
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
	go func() { echoDone <- executePipelineEcho(f, context.Background()) }()
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
		dt := peer
		responses := make(chan pipelineBenchResponse, 32)
		var writers sync.WaitGroup
		writers.Add(1)
		go func() {
			defer writers.Done()
			for response := range responses {
				if wait := time.Until(response.readyAt); wait > 0 {
					time.Sleep(wait)
				}
				if _, err := testWritePacket(dt, response.packet); err != nil {
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
					f, peer := newTestFile(b, testServerOptions{
						credits:         16,
						maxReadSize:     pipelineChunk,
						maxWriteSize:    pipelineChunk,
						maxTransactSize: pipelineChunk,
					})
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
			dt := serverConn
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
						sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
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
			var invalidResponseErr *protocol.InvalidResponseError
			require.ErrorAs(t, err, &invalidResponseErr)
			<-done
			require.Equal(t, []string{"root", "root", "root"}, createNames)
		})
	}
}

func TestRemoveAllRejectsNULDotDirectoryEntry(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
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
				sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
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
	var invalidResponseErr *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalidResponseErr)
	<-done
	require.Equal(t, []string{"root", "root", "root"}, createNames)
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

func TestRemoveAllFollowsParentSymlink(t *testing.T) {
	t.Parallel()
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			fs, server := newTestShare(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				dt := server
				read := func(command wire.Command, name string) []byte {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return nil
					}
					p := wire.PacketCodec(req)
					if p.Command() != command {
						t.Errorf("command = %v, want %v", p.Command(), command)
						return nil
					}
					if command == wire.SMB2_CREATE {
						cr := wire.CreateRequestDecoder(p.Body())
						start, size := int(cr.NameOffset()), int(cr.NameLength())
						if got := utf16le.DecodeToString(req[start : start+size]); got != name {
							t.Errorf("name = %q, want %q", got, name)
						}
						if cr.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT == 0 {
							t.Error("CREATE must open the final link itself")
						}
					}
					return req
				}
				stopped := func(req []byte, compound bool) {
					responses := []compoundResponse{{
						packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE, ErrorData: &wire.SymbolicLinkErrorResponse{
							UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\item`)),
							Flags:              wire.SYMLINK_FLAG_RELATIVE, SubstituteName: "target", PrintName: "target",
						}}, status: erref.STATUS_STOPPED_ON_SYMLINK,
					}}
					if compound {
						for _, cmd := range []wire.Command{wire.SMB2_SET_INFO, wire.SMB2_CLOSE} {
							responses = append(responses, compoundResponse{packet: &wire.ErrorResponse{CommandCode: cmd}, status: erref.STATUS_INVALID_HANDLE})
						}
					}
					if err := sendCompoundResponse(dt, req, responses); err != nil {
						t.Error(err)
					}
				}
				req := read(wire.SMB2_CREATE, `link\item`)
				if req == nil {
					return
				}
				stopped(req, true)
				req = read(wire.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				if !directory {
					sendTestCompoundSuccessResponse(dt, req)
					return
				}
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))

				// Opening a nonempty directory must also resolve the parent link.
				req = read(wire.SMB2_CREATE, `link\item`)
				if req == nil {
					return
				}
				stopped(req, false)
				req = read(wire.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				cr := wire.CreateRequestDecoder(wire.PacketCodec(req).Body())
				if cr.ShareAccess()&wire.FILE_SHARE_DELETE != 0 {
					t.Error("directory must remain pinned")
				}
				sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
				req = read(wire.SMB2_QUERY_DIRECTORY, "")
				if req == nil {
					return
				}
				// A child link is removed directly, never opened for enumeration.
				sendTestResponse(dt, req, &wire.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformation("child-link"))}, 0)
				req = read(wire.SMB2_QUERY_DIRECTORY, "")
				if req == nil {
					return
				}
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_NO_MORE_FILES))
				req = read(wire.SMB2_CREATE, `target\item\child-link`)
				if req == nil {
					return
				}
				sendTestCompoundSuccessResponse(dt, req)
				req = read(wire.SMB2_CLOSE, "")
				if req == nil {
					return
				}
				sendTestCloseResponse(dt, req)
				req = read(wire.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				sendTestCompoundSuccessResponse(dt, req)
			}()
			require.NoError(t, fs.RemoveAll(ctx, `link\item`))
			<-done
		})
	}
}

func TestRemoveAllDoesNotTraverseTargetSymlink(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := server
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		// If direct deletion fails, opening the target must not lead to
		// enumerating a link's contents, even if it is marked as a directory.
		sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_SHARING_VIOLATION))
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		cr := wire.CreateRequestDecoder(wire.PacketCodec(req).Body())
		if cr.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT == 0 {
			t.Error("CREATE followed the target link")
		}
		sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY|wire.FILE_ATTRIBUTE_REPARSE_POINT)
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		if got := wire.PacketCodec(req).Command(); got != wire.SMB2_CLOSE {
			t.Errorf("command = %v, want CLOSE without enumeration", got)
			return
		}
		sendTestCloseResponse(dt, req)
	}()
	require.ErrorIs(t, fs.RemoveAll(ctx, "link"), erref.STATUS_SHARING_VIOLATION)
	<-done
	requireNoRequest(t, server)
}

func TestRemoveAllReopensDirectory(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := server
		opens, removes, queries := 0, 0, 0
		for {
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CREATE:
				cr := wire.CreateRequestDecoder(p.Body())
				start, size := int(cr.NameOffset()), int(cr.NameLength())
				name := utf16le.DecodeToString(req[start : start+size])
				if cr.DesiredAccess()&wire.DELETE == 0 {
					opens++
					sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
				} else if name == `root\child` {
					sendTestCompoundSuccessResponse(dt, req)
				} else {
					removes++
					if removes < 3 {
						sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
					} else {
						if opens != 2 {
							t.Errorf("directory opens = %d, want 2", opens)
						}
						sendTestCompoundSuccessResponse(dt, req)
						return
					}
				}
			case wire.SMB2_QUERY_DIRECTORY:
				queries++
				if queries == 1 {
					sendTestResponse(dt, req, &wire.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformation("child"))}, 0)
				} else {
					sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_NO_MORE_FILES))
				}
			case wire.SMB2_CLOSE:
				sendTestCloseResponse(dt, req)
			default:
				t.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}()
	require.NoError(t, fs.RemoveAll(ctx, "root"))
	<-done
}

func TestRemoveAllFinalRemovalOverridesReadError(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := server
		for step := 0; step < 5; step++ {
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			switch step {
			case 0:
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
			case 1:
				sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_DIRECTORY)
			case 2:
				sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_ACCESS_DENIED))
			case 3:
				sendTestCloseResponse(dt, req)
			case 4:
				sendTestCompoundSuccessResponse(dt, req)
			}
		}
	}()
	require.NoError(t, fs.RemoveAll(ctx, "root"))
	<-done
}

func TestRemoveAllNonDirectory(t *testing.T) {
	t.Parallel()
	for _, parentIsFile := range []bool{false, true} {
		name := "target is file"
		if parentIsFile {
			name = "parent is file"
		}
		t.Run(name, func(t *testing.T) {
			fs, server := newTestShare(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				dt := server
				req, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_SHARING_VIOLATION))
				req, err = readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				if parentIsFile {
					sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_NOT_A_DIRECTORY))
					return
				}
				cr := wire.CreateRequestDecoder(wire.PacketCodec(req).Body())
				if cr.CreateOptions()&wire.FILE_DIRECTORY_FILE != 0 {
					t.Error("open must allow inspecting a non-directory target")
				}
				sendTestCreateAttributesResponse(dt, req, wire.FileId{}, wire.FILE_ATTRIBUTE_NORMAL)
				req, err = readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				sendTestCloseResponse(dt, req)
			}()
			err := fs.RemoveAll(ctx, `parent\target`)
			if parentIsFile {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, erref.STATUS_SHARING_VIOLATION)
			}
			<-done
		})
	}
}

func TestGlobRejectsExcessiveRecursion(t *testing.T) {
	t.Parallel()
	pattern := strings.Repeat(`*/`, 10000) + "file"

	matches, err := (&Share{}).WithContext(context.Background()).Glob(pattern)
	if err != path.ErrBadPattern {
		t.Fatalf("Glob returned error %v, want %v", err, path.ErrBadPattern)
	}
	if matches != nil {
		t.Fatalf("Glob returned matches %v, want nil", matches)
	}
}

// TestGlobKeepsMatchesAfterNoSuchFile verifies that Glob keeps matches from
// earlier directories when a later directory ends its enumeration with
// STATUS_NO_SUCH_FILE (no entry matches the search pattern).
func TestGlobKeepsMatchesAfterNoSuchFile(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, maxTransactSize: 64 * 1024, credits: 100})

	// Per-pattern query counters emulating:
	//   dir1 contains "ab1.ext" (and non-matching "zz.txt")
	//   dir2 contains no file matching "ab?.ext" -> readdir ends with STATUS_NO_SUCH_FILE
	queries := make(map[string]int)

	onQueryDir := func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		qreq := wire.QueryDirectoryRequestDecoder(reqBuf[64:])
		fno, fnl := qreq.FileNameOffset(), qreq.FileNameLength()
		pattern := utf16le.DecodeToString(reqBuf[int(fno) : int(fno)+int(fnl)])
		queries[pattern]++
		n := queries[pattern]

		writeEntry := func(name string) {
			entry := encodeFileIdBothDirectoryInformation(name)
			res := &wire.QueryDirectoryResponse{Output: rawEncoder(entry)}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
		}
		writeError := func(status uint32) {
			res := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(status)
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
		}

		switch pattern {
		case `dir*`:
			switch n {
			case 1:
				writeEntry("dir1")
			case 2:
				writeEntry("dir2")
			default:
				writeError(uint32(erref.STATUS_NO_MORE_FILES))
			}
		case `ab?.ext`:
			switch n {
			case 1: // dir1: one matching entry
				writeEntry("ab1.ext")
			case 2: // dir1: end of enumeration
				writeError(uint32(erref.STATUS_NO_MORE_FILES))
			default: // dir2: no matching entry
				writeError(uint32(erref.STATUS_NO_SUCH_FILE))
			}
		default:
			writeError(uint32(erref.STATUS_NO_MORE_FILES))
		}
		return true
	}

	onQueryInfo := func(msgId uint64, reqBuf []byte) []byte {
		// FileAllInformation with FILE_ATTRIBUTE_DIRECTORY
		info := make([]byte, 104)
		le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
		res := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		return buf
	}

	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	matches, err := fs.WithContext(context.Background()).Glob(`dir*/ab?.ext`)
	if err != nil {
		t.Fatalf("Glob returned error: %v", err)
	}

	expected := []string{`dir1/ab1.ext`}
	if !reflect.DeepEqual(matches, expected) {
		t.Errorf("Glob(`dir*\\ab?.ext`) = %v, want %v (matches from dir1 must survive STATUS_NO_SUCH_FILE from dir2)", matches, expected)
	}
}

// TestGlobKeepsPageEntriesBeforeNoSuchFile verifies that Glob keeps entries
// collected on the first page of a multi-page readdir when a subsequent page
// ends the enumeration with STATUS_NO_SUCH_FILE instead of
// STATUS_NO_MORE_FILES.
func TestGlobKeepsPageEntriesBeforeNoSuchFile(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t, testServerOptions{maxReadSize: 64 * 1024, maxWriteSize: 64 * 1024, maxTransactSize: 64 * 1024, credits: 100})

	// Per-pattern query counters emulating:
	//   dir1 contains "ab1.ext" on the first page and ends the second page with
	//   STATUS_NO_SUCH_FILE (a server may report end-of-enumeration this way)
	//   dir2 contains no file matching "ab?.ext" -> first readdir returns STATUS_NO_SUCH_FILE
	queries := make(map[string]int)

	onQueryDir := func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		qreq := wire.QueryDirectoryRequestDecoder(reqBuf[64:])
		fno, fnl := qreq.FileNameOffset(), qreq.FileNameLength()
		pattern := utf16le.DecodeToString(reqBuf[int(fno) : int(fno)+int(fnl)])
		queries[pattern]++
		n := queries[pattern]

		writeEntry := func(name string) {
			entry := encodeFileIdBothDirectoryInformation(name)
			res := &wire.QueryDirectoryResponse{Output: rawEncoder(entry)}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
		}
		writeError := func(status uint32) {
			res := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(status)
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
		}

		switch pattern {
		case `dir*`:
			switch n {
			case 1:
				writeEntry("dir1")
			case 2:
				writeEntry("dir2")
			default:
				writeError(uint32(erref.STATUS_NO_MORE_FILES))
			}
		case `ab?.ext`:
			switch n {
			case 1: // dir1: first page with one matching entry
				writeEntry("ab1.ext")
			case 2: // dir1: second page ends enumeration with STATUS_NO_SUCH_FILE
				writeError(uint32(erref.STATUS_NO_SUCH_FILE))
			default: // dir2: no matching entry
				writeError(uint32(erref.STATUS_NO_SUCH_FILE))
			}
		default:
			writeError(uint32(erref.STATUS_NO_MORE_FILES))
		}
		return true
	}

	onQueryInfo := func(msgId uint64, reqBuf []byte) []byte {
		// FileAllInformation with FILE_ATTRIBUTE_DIRECTORY
		info := make([]byte, 104)
		le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
		res := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		return buf
	}

	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	matches, err := fs.WithContext(context.Background()).Glob(`dir*/ab?.ext`)
	if err != nil {
		t.Fatalf("Glob returned error: %v", err)
	}

	expected := []string{`dir1/ab1.ext`}
	if !reflect.DeepEqual(matches, expected) {
		t.Errorf("Glob(`dir*\\ab?.ext`) = %v, want %v (first-page entries must survive STATUS_NO_SUCH_FILE on a later page)", matches, expected)
	}
}

func TestGlobContinuesPastDotOnlyPages(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformation("visible.txt"),
		},
		queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)},
	)

	matches, err := fs.WithContext(context.Background()).Glob("*")
	if err != nil {
		t.Fatalf("Glob returned error: %v", err)
	}
	if !reflect.DeepEqual(matches, []string{"visible.txt"}) {
		t.Fatalf("Glob returned %v, want [visible.txt]", matches)
	}
}

func TestGlobValidatesSearchPatternLength(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		pattern string
		want    string
	}{
		{
			name:    "65534 bytes",
			pattern: strings.Repeat("a", 32766) + "*",
			want:    strings.Repeat("a", 32766) + "*",
		},
		{
			name:    "non-BMP characters",
			pattern: strings.Repeat("😀", 16383) + "*",
			want:    strings.Repeat("😀", 16383) + "*",
		},
		{
			name:    "simplified character class",
			pattern: "[" + strings.Repeat("a", 65534) + "]*",
			want:    "?*",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs, server := newTestShare(t)
			received := make(chan struct {
				pattern string
				length  int
			}, 1)

			startFullFakeServer(server, func(msgId uint64, reqBuf []byte, dt net.Conn) bool {
				p := wire.PacketCodec(reqBuf)
				qreq := wire.QueryDirectoryRequestDecoder(reqBuf[64:])
				fno, fnl := qreq.FileNameOffset(), qreq.FileNameLength()
				encoded := reqBuf[int(fno) : int(fno)+int(fnl)]
				received <- struct {
					pattern string
					length  int
				}{
					pattern: utf16le.DecodeToString(encoded),
					length:  len(encoded),
				}

				res := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
				buf := make([]byte, res.Size())
				res.Encode(buf)
				rp := wire.PacketCodec(buf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
				rp.SetCreditResponse(1)
				rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				testWritePacket(dt, buf)
				return true
			}, nil, func(msgId uint64, reqBuf []byte) []byte {
				info := make([]byte, 104)
				le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
				res := &wire.QueryInfoResponse{Output: rawEncoder(info)}
				buf := make([]byte, res.Size())
				res.Encode(buf)
				return buf
			})

			matches, err := fs.WithContext(context.Background()).Glob(test.pattern)
			if err != nil {
				t.Fatalf("Glob returned error: %v", err)
			}
			if matches != nil {
				t.Fatalf("Glob returned matches %v, want nil", matches)
			}

			got := <-received
			wantLength := len(utf16le.EncodeStringToBytes(test.want))
			if got.pattern != test.want {
				t.Errorf("QUERY_DIRECTORY pattern length = %d, want pattern %q", len(got.pattern), test.want)
			}
			if got.length != wantLength {
				t.Errorf("FileNameLength = %d, want %d", got.length, wantLength)
			}
		})
	}
}

func TestGlobStopsAfterThreeDotOnlyPages(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	queryCount := startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
	)

	matches, err := fs.WithContext(context.Background()).Glob("*")
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Nil(t, matches)
	require.Equal(t, "glob", pathErr.Op)
	require.EqualError(t, pathErr.Err, "query directory returned only dot entries")
	require.EqualValues(t, 3, atomic.LoadInt64(queryCount))

	// Glob's directory error must not close the shared connection.
	_, err = fs.Stat(context.Background(), "other")
	require.NoError(t, err)
}

type (
	SecurityDescriptor  = security.Descriptor
	SecurityInformation = security.Information
	SID                 = security.SID
	ACL                 = security.ACL
	ACE                 = security.ACE
)

const (
	OWNER_SECURITY_INFORMATION = security.Owner
	GROUP_SECURITY_INFORMATION = security.Group
	DACL_SECURITY_INFORMATION  = security.DACL
	SACL_SECURITY_INFORMATION  = security.SACL

	ACCESS_ALLOWED = security.AccessAllowed
	ACCESS_DENIED  = security.AccessDenied
	SYSTEM_AUDIT   = security.SystemAudit

	SE_SELF_RELATIVE  uint16 = 0x8000
	SE_DACL_PRESENT   uint16 = 0x0004
	SE_SACL_PRESENT   uint16 = 0x0010
	SE_DACL_PROTECTED uint16 = 0x1000
	SE_SACL_PROTECTED uint16 = 0x2000
)

var decodeSecurityDescriptor = security.DecodeDescriptor

func testSID() *security.SID {
	return &security.SID{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 544}}
}

func encodeSecurityDescriptorForTest(t *testing.T, descriptor *security.Descriptor, _ ...security.Information) []byte {
	t.Helper()
	data, err := descriptor.Encode()
	if err != nil {
		t.Fatalf("descriptor.Encode() error = %v", err)
	}
	return data
}

func TestSecurityDescriptorRoundTripPreservesACLDetails(t *testing.T) {
	t.Parallel()
	raw := []byte{0x42, 0x07, 0x04, 0x00}
	descriptor := &SecurityDescriptor{
		Owner: testSID(),
		Group: testSID(),
		DACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: ACCESS_DENIED, Flags: 3, Mask: 0x10, SID: testSID()},
			{Type: 0x42, Flags: 7, Raw: raw},
		}},
		SACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: SYSTEM_AUDIT, Flags: 1, Mask: 0x20, SID: testSID()},
		}},
	}

	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wireBytes, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.DACL == nil || len(decoded.DACL.ACEs) != 2 || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
		t.Fatalf("DACL details were not preserved: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 1 || decoded.SACL.ACEs[0].SID == nil {
		t.Fatalf("SACL details were not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorDistinguishesNullAndEmptyACL(t *testing.T) {
	t.Parallel()
	descriptor := &SecurityDescriptor{
		DACL: security.NullACL,
		SACL: &ACL{Revision: 2},
	}
	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.DACL != security.NullACL {
		t.Fatalf("NULL DACL became an ACL: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 0 {
		t.Fatalf("empty SACL was not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorSetValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		descriptor *SecurityDescriptor
	}{
		{"no selected component", &SecurityDescriptor{}},
		{"invalid ACL", &SecurityDescriptor{DACL: &ACL{ACEs: []ACE{{}}}}},
		{"authority too wide", &SecurityDescriptor{Owner: &SID{Revision: 1, IdentifierAuthority: 1 << 48}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.descriptor.Encode(); err == nil {
				t.Fatal("invalid security descriptor was accepted")
			}
		})
	}
}

func TestSecurityDescriptorRejectsKnownACEInWrongACLEvenAsRaw(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		selection SecurityInformation
		acl       *ACL
	}{
		{
			name:      "audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: SYSTEM_AUDIT, Raw: []byte{byte(SYSTEM_AUDIT), 0, 4, 0}}}},
		},
		{
			name:      "object audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 4, ACEs: []ACE{{Type: 0x07, Raw: []byte{0x07, 0, 4, 0}}}},
		},
		{
			name:      "allow ACE in SACL",
			selection: SACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, Raw: []byte{byte(ACCESS_ALLOWED), 0, 4, 0}}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := &SecurityDescriptor{}
			if test.selection == DACL_SECURITY_INFORMATION {
				descriptor.DACL = test.acl
			} else {
				descriptor.SACL = test.acl
			}
			if _, err := descriptor.Encode(); err == nil {
				t.Fatal("known ACE was accepted in the wrong ACL")
			}
		})
	}
}

func TestSecurityDescriptorRejectsTruncatedAndOversizedACL(t *testing.T) {
	t.Parallel()
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{
		DACL: &ACL{Revision: 2},
	}, DACL_SECURITY_INFORMATION)
	for _, data := range [][]byte{
		valid[:19],
		func() []byte {
			data := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(data[16:20], uint32(len(data)-4))
			return data
		}(),
	} {
		if _, err := decodeSecurityDescriptor(data, DACL_SECURITY_INFORMATION); err == nil {
			t.Fatalf("malformed descriptor of length %d was accepted", len(data))
		}
	}

	bad := append([]byte(nil), valid...)
	// Keep the ACL offset but claim an ACL larger than the descriptor.
	daclOffset := binary.LittleEndian.Uint32(bad[16:20])
	binary.LittleEndian.PutUint16(bad[daclOffset+2:daclOffset+4], 0xffff)
	if _, err := decodeSecurityDescriptor(bad, DACL_SECURITY_INFORMATION); err == nil {
		t.Fatal("oversized ACL was accepted")
	}
}

func TestSecurityDescriptorSharedSIDAndAbsentACL(t *testing.T) {
	t.Parallel()
	// Owner and Group can reference the same SID, with neither ACL present.
	wireBytes := []byte{
		1, 0, 0, 0x80, 20, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0,
	}
	sd, err := decodeSecurityDescriptor(wireBytes, securityInformationComponents)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Owner == nil || sd.Group == nil || sd.Owner.SubAuthority[1] != 544 || sd.Group.SubAuthority[1] != 544 {
		t.Fatalf("shared SID decoded incorrectly: %#v", sd)
	}
	if sd.DACL != security.NullACL || sd.SACL != security.NullACL {
		t.Fatal("absent requested ACLs were not normalized to NULL ACLs")
	}
	clear(wireBytes)
	sd.Owner.SubAuthority[1] = 1
	if sd.Group.SubAuthority[1] != 544 {
		t.Fatal("decoded SIDs alias input or each other")
	}
}

func TestSecurityDescriptorPreservesMixedACERevisions(t *testing.T) {
	t.Parallel()
	// A non-object callback ACE is opaque to this API, including its condition.
	raw := []byte{9, 0, 24, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 7, 8, 9, 10}
	for _, revision := range []uint8{2, 4} {
		sd := &SecurityDescriptor{DACL: &ACL{Revision: revision, ACEs: []ACE{
			{Type: ACCESS_ALLOWED, SID: testSID(), Mask: 1}, {Type: 9, Raw: raw},
		}}}
		wireBytes := encodeSecurityDescriptorForTest(t, sd, DACL_SECURITY_INFORMATION)
		decoded, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.DACL.Revision != revision || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("ACE or ACL revision changed")
		}
		clear(wireBytes)
		if !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("raw ACE aliases receive buffer")
		}
	}
}

func TestSecurityDescriptorProtectionAndSelection(t *testing.T) {
	t.Parallel()
	sd := &SecurityDescriptor{
		DACL: &ACL{Protected: true},
	}
	wireBytes, err := sd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if sd.Information() != DACL_SECURITY_INFORMATION {
		t.Fatalf("selection = %#x, want DACL only", sd.Information())
	}
	if binary.LittleEndian.Uint16(wireBytes[2:4]) != SE_SELF_RELATIVE|SE_DACL_PRESENT|SE_DACL_PROTECTED {
		t.Fatal("DACL protection was not reflected in control")
	}
	if !bytes.Equal(wireBytes[4:16], make([]byte, 12)) || binary.LittleEndian.Uint32(wireBytes[16:20]) == 0 {
		t.Fatal("unselected components were transmitted")
	}
	sd.DACL.Protected = false
	wireBytes = encodeSecurityDescriptorForTest(t, sd)
	if binary.LittleEndian.Uint16(wireBytes[2:4])&SE_DACL_PROTECTED != 0 {
		t.Fatal("unprotect was ignored")
	}
}

func TestSecurityDescriptorMalformedComponentBounds(t *testing.T) {
	t.Parallel()
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{
		DACL: &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, SID: testSID()}}},
	}, DACL_SECURITY_INFORMATION)
	for _, mutate := range []func([]byte){
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 0xfffffffc) },
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 21) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[24:26], 0xffff) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[30:32], 0xffff) },
		func(w []byte) { w[37] = 16 },
		func(w []byte) { w[36] = 2 },
	} {
		wireBytes := append([]byte(nil), valid...)
		mutate(wireBytes)
		if _, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION); err == nil {
			t.Fatalf("malformed descriptor accepted: %x", wireBytes)
		}
	}
}

func TestSecurityDescriptorValidatesBeforeSending(t *testing.T) {
	t.Parallel()
	fs, _ := newTestShare(t, testServerOptions{maxTransactSize: 65536})
	// Both ACLs individually fit their uint16 AclSize; the combined descriptor
	// exceeds this connection's negotiated transaction size.
	raw := make([]byte, 40000)
	raw[0] = 0x42
	binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw)))
	acl := &ACL{Revision: 2, ACEs: []ACE{{Type: 0x42, Raw: raw}}}
	sd := &SecurityDescriptor{DACL: acl, SACL: acl}
	require.ErrorIs(t, fs.SetSecurityDescriptor(context.Background(), "test.txt", sd), os.ErrInvalid)
	require.ErrorIs(t, fs.SetSecurityDescriptor(context.Background(), "test.txt", nil), os.ErrInvalid)
	_, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", security.Information(0x80000000))
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = fs.GetSecurityDescriptor(context.Background(), "test.txt", 0)
	require.ErrorIs(t, err, os.ErrInvalid)
}

func TestShareSecurityDescriptor(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
	targetFileId := wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
	selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	descriptor := &SecurityDescriptor{
		Owner: testSID(),
		DACL:  &ACL{Revision: 2},
	}
	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 1. Compound CREATE + QUERY_INFO + CLOSE for GetSecurityDescriptor
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(p.Body())
				require.EqualValues(t, wire.READ_CONTROL, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_QUERY_INFO:
				query := wire.QueryInfoRequestDecoder(p.Body())
				require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
				sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := p.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}

		// 2. Compound CREATE + SET_INFO + CLOSE for SetSecurityDescriptor
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(p.Body())
				require.EqualValues(t, wire.WRITE_DAC|wire.WRITE_OWNER, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_SET_INFO:
				set := wire.SetInfoRequestDecoder(p.Body())
				require.EqualValues(t, selection, set.AdditionalInformation())
				sendTestResponse(dt, req, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := p.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}
	}()

	got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
	require.NoError(t, err)
	require.NotNil(t, got)

	err = fs.SetSecurityDescriptor(context.Background(), "test.txt", got)
	require.NoError(t, err)
	<-done
}

func TestGetSecurityDescriptorSACLOnly(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
	targetFileID := wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
	wireBytes := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{SACL: &ACL{Revision: 2}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			packet := wire.PacketCodec(req)
			switch packet.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(packet.Body())
				require.EqualValues(t, wire.ACCESS_SYSTEM_SECURITY, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileID,
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_QUERY_INFO:
				query := wire.QueryInfoRequestDecoder(packet.Body())
				require.EqualValues(t, SACL_SECURITY_INFORMATION, query.AdditionalInformation())
				sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   wire.Filetime{},
					LastAccessTime: wire.Filetime{},
					LastWriteTime:  wire.Filetime{},
					ChangeTime:     wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := packet.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}
	}()

	descriptor, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", SACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, descriptor.SACL)
	require.Nil(t, descriptor.Owner)
	require.Nil(t, descriptor.Group)
	require.Nil(t, descriptor.DACL)
	<-done
}

func TestGetSecurityDescriptor_BufferTooSmallRetry(t *testing.T) {
	t.Parallel()
	t.Run("SuccessAfterRetry", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		dt := serverConn
		targetFileId := wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
		selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		descriptor := &SecurityDescriptor{
			Owner: testSID(),
			DACL:  &ACL{Revision: 2},
		}
		wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

		const requiredLen = 70 * 1024 // larger than 64KB, fits within max limit

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Attempt 1: Initial query with 64KB buffer -> server fails with STATUS_BUFFER_TOO_SMALL
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
						FileId:         targetFileId,
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
					errData := make([]byte, 4)
					le.PutUint32(errData, uint32(requiredLen))
					errRes := &wire.ErrorResponse{
						CommandCode: wire.SMB2_QUERY_INFO,
						ErrorData:   rawEncoder(errData),
					}
					sendTestResponse(dt, req, errRes, uint32(erref.STATUS_BUFFER_TOO_SMALL))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}

			// Attempt 2: Retried query with requiredLen buffer -> server succeeds
			req, err = readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, requiredLen, query.OutputBufferLength())
					sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}
		}()

		got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, descriptor.Owner, got.Owner)
		require.NotNil(t, got.DACL)
		require.NotEqual(t, security.NullACL, got.DACL)
		<-done
	})

	t.Run("SuccessAtEffectiveLimit", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		dt := serverConn
		targetFileId := wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
		selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		descriptor := &SecurityDescriptor{
			Owner: testSID(),
			DACL:  &ACL{Revision: 2},
		}
		wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

		// Exactly the largest query buffer this connection may send: the retry
		// is still permitted because it does not exceed the effective limit.
		requiredLen := fs.maxTransactSize(2)
		require.Greater(t, requiredLen, maxSingleCreditPayloadSize)

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Attempt 1: initial query with 64KB buffer -> server fails with
			// STATUS_BUFFER_TOO_SMALL, reporting the effective limit.
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
						FileId:         targetFileId,
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
					errData := make([]byte, 4)
					le.PutUint32(errData, uint32(requiredLen))
					sendTestResponse(dt, req, &wire.ErrorResponse{
						CommandCode: wire.SMB2_QUERY_INFO,
						ErrorData:   rawEncoder(errData),
					}, uint32(erref.STATUS_BUFFER_TOO_SMALL))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}

			// Attempt 2: retried query at the effective limit -> server succeeds.
			req, err = readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, requiredLen, query.OutputBufferLength())
					sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   wire.Filetime{},
						LastAccessTime: wire.Filetime{},
						LastWriteTime:  wire.Filetime{},
						ChangeTime:     wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}
		}()

		got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, descriptor.Owner, got.Owner)
		require.NotNil(t, got.DACL)
		require.NotEqual(t, security.NullACL, got.DACL)
		<-done
	})
}

// TestGetSecurityDescriptor_BufferTooSmallOversizedRequired verifies that a
// server-reported required length above the connection's sendable limit is not
// retried. [MS-SMB2] 3.3.5.20 says the server SHOULD reject an
// OutputBufferLength greater than Connection.MaxTransactSize with
// STATUS_INVALID_PARAMETER, so the original response error must be preserved
// instead of exposing a local credit or internal error.
func TestGetSecurityDescriptor_BufferTooSmallOversizedRequired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		requiredLen uint32
		options     testServerOptions
	}{
		{
			name:        "exceeds negotiated max transact size",
			requiredLen: 256 * 1024,
			options:     testServerOptions{maxTransactSize: 128 * 1024},
		},
		{
			name:        "exceeds credit derived effective size",
			requiredLen: 70 * 1024,
			options:     testServerOptions{credits: 1, singleCredit: true},
		},
		{
			name:        "huge required length",
			requiredLen: 0x7FFF0000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fs, serverConn := newTestShare(t, test.options)
			dt := serverConn
			targetFileId := wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}

			var queryCount atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}
					for {
						p := wire.PacketCodec(req)
						switch p.Command() {
						case wire.SMB2_CREATE:
							sendTestResponse(dt, req, &wire.CreateResponse{
								FileId:         targetFileId,
								CreationTime:   wire.Filetime{},
								LastAccessTime: wire.Filetime{},
								LastWriteTime:  wire.Filetime{},
								ChangeTime:     wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_QUERY_INFO:
							queryCount.Add(1)
							errData := make([]byte, 4)
							le.PutUint32(errData, test.requiredLen)
							sendTestResponse(dt, req, &wire.ErrorResponse{
								CommandCode: wire.SMB2_QUERY_INFO,
								ErrorData:   rawEncoder(errData),
							}, uint32(erref.STATUS_BUFFER_TOO_SMALL))
						case wire.SMB2_CLOSE:
							sendTestResponse(dt, req, &wire.CloseResponse{
								CreationTime:   wire.Filetime{},
								LastAccessTime: wire.Filetime{},
								LastWriteTime:  wire.Filetime{},
								ChangeTime:     wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						}
						if next := p.NextCommand(); next != 0 {
							req = req[next:]
						} else {
							break
						}
					}
				}
			}()

			got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION)
			require.Nil(t, got)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			// The original response status must survive instead of being
			// replaced by a retry failure.
			require.ErrorIs(t, err, erref.STATUS_BUFFER_TOO_SMALL)

			// No retry may be sent; unblock and finish the pseudo server.
			require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			<-done
			require.EqualValues(t, 1, queryCount.Load())
		})
	}
}

func TestNilShareUnmount(t *testing.T) {
	if err := (*Share)(nil).Unmount(context.Background()); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Unmount = %v, want ErrInvalid", err)
	}
}
