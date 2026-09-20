package smb2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func notifyEventBytes(action ChangeAction, name string) []byte {
	encoded := utf16le.EncodeStringToBytes(name)
	record := make([]byte, (12+len(encoded)+3)&^3)
	le.PutUint32(record[4:8], uint32(action))
	le.PutUint32(record[8:12], uint32(len(encoded)))
	copy(record[12:], encoded)
	return record
}

type notifyOutcome struct {
	result ChangeResult
	err    error
}

func startNotify(f *File, ctx context.Context, filter ChangeFilter, recursive bool) <-chan notifyOutcome {
	done := make(chan notifyOutcome, 1)
	go func() {
		result, err := f.WaitForChange(ctx, filter, recursive)
		done <- notifyOutcome{result, err}
	}()
	return done
}

func finishNotify(t *testing.T, done <-chan notifyOutcome) (ChangeResult, error) {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome.result, outcome.err
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForChange did not complete")
		return ChangeResult{}, nil
	}
}

func TestFileWaitForChangeRequiresDirectoryAndValidFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilFile *File
	if _, err := nilFile.WaitForChange(ctx, ChangeFileName, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil File error = %v, want os.ErrInvalid", err)
	}

	f := &File{fd: &wire.FileId{}}
	if _, err := f.WaitForChange(ctx, ChangeFileName, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("regular File error = %v, want os.ErrInvalid", err)
	}
	f.isDir = true
	if _, err := f.WaitForChange(ctx, 0, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zero filter error = %v, want os.ErrInvalid", err)
	}
	if _, err := f.WaitForChange(ctx, ChangeFilter(1<<31), false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("unknown filter error = %v, want os.ErrInvalid", err)
	}
}

func TestFileWaitForChangeEmptyResponseRequiresRescan(t *testing.T) {
	t.Parallel()
	for _, status := range []uint32{uint32(erref.STATUS_SUCCESS), uint32(erref.STATUS_NOTIFY_ENUM_DIR)} {
		t.Run(fmt.Sprintf("status-%08x", status), func(t *testing.T) {
			require := require.New(t)
			f, serverConn := newTestFile(t)
			f.isDir = true
			go func() {
				dt := serverConn
				req, err := readMsg(dt)
				if err != nil {
					return
				}
				require.Equal(wire.SMB2_CHANGE_NOTIFY, wire.PacketCodec(req).Command())
				sendTestResponse(dt, req, &wire.ChangeNotifyResponse{}, status)
			}()

			result, err := f.WaitForChange(context.Background(), ChangeFileName, false)
			require.NoError(err)
			require.Empty(result.Events)
			require.True(result.RescanRequired)
		})
	}
}

func TestFileWaitForChangePreservesEventOrderAndNames(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	f, serverConn := newTestFile(t)
	f.isDir = true

	makeEvent := func(action uint32, name string) []byte {
		nameBytes := utf16le.EncodeStringToBytes(name)
		size := (12 + len(nameBytes) + 3) &^ 3
		b := make([]byte, size)
		le.PutUint32(b[4:8], action)
		le.PutUint32(b[8:12], uint32(len(nameBytes)))
		copy(b[12:], nameBytes)
		return b
	}
	oldName := makeEvent(wire.FILE_ACTION_RENAMED_OLD_NAME, "old.txt")
	newName := makeEvent(wire.FILE_ACTION_RENAMED_NEW_NAME, "new.txt")
	le.PutUint32(oldName[:4], uint32(len(oldName)))
	output := append(oldName, newName...)

	go func() {
		dt := serverConn
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		request := wire.ChangeNotifyRequestDecoder(wire.PacketCodec(req).Body())
		if request.IsInvalid() {
			return
		}
		sendTestResponse(dt, req, &wire.ChangeNotifyResponse{Output: rawEncoder(output)}, uint32(erref.STATUS_SUCCESS))
	}()

	result, err := f.WaitForChange(context.Background(), ChangeFileName, false)
	require.NoError(err)
	require.False(result.RescanRequired)
	require.Equal([]ChangeEvent{
		{Action: ChangeActionRenamedOldName, Name: "old.txt"},
		{Action: ChangeActionRenamedNewName, Name: "new.txt"},
	}, result.Events)
}

func TestFileWaitForChangeResponseValidation(t *testing.T) {
	t.Parallel()
	validThenEmpty := notifyEventBytes(ChangeActionAdded, "valid")
	le.PutUint32(validThenEmpty[:4], uint32(len(validThenEmpty)))
	validThenEmpty = append(validThenEmpty, notifyEventBytes(ChangeActionAdded, "")...)

	for _, test := range []struct {
		name       string
		output     []byte
		recursive  bool
		status     erref.NtStatus
		wantStatus bool
	}{
		{name: "empty name", output: notifyEventBytes(ChangeActionAdded, "")},
		{name: "embedded NUL", output: notifyEventBytes(ChangeActionAdded, "a\x00b")},
		{name: "trailing NUL", output: notifyEventBytes(ChangeActionAdded, "a\x00")},
		{name: "control character", output: notifyEventBytes(ChangeActionAdded, "a\x1fb")},
		{name: "invalid name after valid event", output: validThenEmpty},
		{name: "root slash", output: notifyEventBytes(ChangeActionAdded, "/root")},
		{name: "root backslash", output: notifyEventBytes(ChangeActionAdded, `\root`)},
		{name: "quote", output: notifyEventBytes(ChangeActionAdded, `a"b`)},
		{name: "stream name quote", output: notifyEventBytes(ChangeActionAdded, `file:st"ream`)},
		{name: "stream type quote", output: notifyEventBytes(ChangeActionAdded, `file:str:ty"pe`)},
		{name: "child slash", output: notifyEventBytes(ChangeActionAdded, "a/b")},
		{name: "child backslash", output: notifyEventBytes(ChangeActionAdded, `a\b`)},
		{name: "dotdot", output: notifyEventBytes(ChangeActionAdded, "..")},
		{name: "dotdot escape", output: notifyEventBytes(ChangeActionAdded, `..\target`)},
		{name: "recursive quote", output: notifyEventBytes(ChangeActionAdded, `a"b`), recursive: true},
		{name: "recursive dotdot", output: notifyEventBytes(ChangeActionAdded, ".."), recursive: true},
		{name: "recursive dotdot escape", output: notifyEventBytes(ChangeActionAdded, `..\target`), recursive: true},
		{name: "recursive stream name quote", output: notifyEventBytes(ChangeActionAdded, `file:st"ream`), recursive: true},
		{name: "recursive stream type quote", output: notifyEventBytes(ChangeActionAdded, `file:str:ty"pe`), recursive: true},
		{name: "truncated record", output: make([]byte, 11)},
		{name: "unknown action", output: notifyEventBytes(12, "a")},
		{name: "request limit", output: make([]byte, maxSingleCreditPayloadSize+1)},
		{name: "enum with events", status: erref.STATUS_NOTIFY_ENUM_DIR, output: notifyEventBytes(ChangeActionAdded, "a")},
		{name: "cleanup", status: erref.STATUS_NOTIFY_CLEANUP, wantStatus: true},
		{name: "access denied", status: erref.STATUS_ACCESS_DENIED, wantStatus: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
			f.isDir = true
			done := startNotify(f, context.Background(), ChangeFileName, test.recursive)
			dt := peer
			request, err := readMsg(dt)
			require.NoError(t, err)
			var response wire.Packet = &wire.ChangeNotifyResponse{Output: rawEncoder(test.output)}
			if test.wantStatus {
				response = &wire.ErrorResponse{CommandCode: wire.SMB2_CHANGE_NOTIFY}
			}
			sendTestResponse(dt, request, response, uint32(test.status))
			result, err := finishNotify(t, done)
			require.Empty(t, result.Events)
			require.False(t, result.RescanRequired)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			if test.wantStatus {
				var responseErr *protocol.ResponseError
				require.ErrorAs(t, err, &responseErr)
				require.Equal(t, uint32(test.status), responseErr.Code)
			} else {
				var invalid *protocol.InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			}
		})
	}
}

func TestFileWaitForChangeContract(t *testing.T) {
	t.Parallel()
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.isDir = true
	f.fd = &wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{7}}
	filter := ChangeFileName | ChangeDirName
	want := []ChangeEvent{{ChangeActionAdded, `child\same`}, {ChangeActionAdded, `child\same`}, {ChangeActionRenamedNewName, `child\new`}}
	var output []byte
	for i, event := range want {
		record := notifyEventBytes(event.Action, event.Name)
		if i < len(want)-1 {
			le.PutUint32(record[:4], uint32(len(record)))
		}
		output = append(output, record...)
	}
	dt := peer
	var first ChangeResult
	for i := range 2 {
		done := startNotify(f, context.Background(), filter, true)
		request, err := readMsg(dt)
		require.NoError(t, err)
		p := wire.PacketCodec(request)
		r := wire.ChangeNotifyRequestDecoder(p.Body())
		require.False(t, r.IsInvalid())
		require.Equal(t, f.fd, r.FileId().Decode())
		require.EqualValues(t, filter, r.CompletionFilter())
		require.EqualValues(t, wire.SMB2_WATCH_TREE, r.Flags())
		require.EqualValues(t, maxSingleCreditPayloadSize, r.OutputBufferLength())
		require.EqualValues(t, 1, p.CreditCharge())
		require.Zero(t, p.NextCommand())
		var response wire.Packet = &wire.ChangeNotifyResponse{}
		if i == 0 {
			response = &wire.ChangeNotifyResponse{Output: rawEncoder(output)}
		}
		sendTestResponse(dt, request, response, 0)
		result, err := finishNotify(t, done)
		require.NoError(t, err)
		if i == 0 {
			first = result
		}
	}
	require.Equal(t, want, first.Events) // Survives subsequent buffer reuse.
	f.closed.Store(true)
	_, err := f.WaitForChange(context.Background(), filter, true)
	require.ErrorIs(t, err, os.ErrClosed)
	var nilCtx context.Context
	require.Panics(t, func() { _, _ = f.WaitForChange(nilCtx, filter, true) })
}

func TestChangeNotifyCancellationPreservesSharedConnection(t *testing.T) {
	t.Parallel()
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprintf("async=%v", async), func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			f.isDir = true
			other := &File{fs: f.fs, fd: &wire.FileId{Volatile: [8]byte{2}}, name: "other", isDir: true}
			dt := peer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := startNotify(f, ctx, ChangeFileName, false)
			request, err := readMsg(dt)
			require.NoError(t, err)
			p := wire.PacketCodec(request)
			require.EqualValues(t, 65536, wire.ChangeNotifyRequestDecoder(p.Body()).OutputBufferLength())
			const asyncID = 0x12345678
			if async {
				pending := &wire.ErrorResponse{CommandCode: wire.SMB2_CHANGE_NOTIFY}
				buf := make([]byte, pending.Size())
				pending.Encode(buf)
				r := wire.PacketCodec(buf)
				r.SetMessageId(p.MessageId())
				r.SetSessionId(p.SessionId())
				r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND)
				r.SetAsyncId(asyncID)
				r.SetStatus(uint32(erref.STATUS_PENDING))
				r.SetCreditResponse(0)
				_, err := testWritePacket(dt, buf)
				require.NoError(t, err)
			}
			otherDone := startNotify(other, context.Background(), ChangeDirName, true)
			otherRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, other.fd, wire.ChangeNotifyRequestDecoder(wire.PacketCodec(otherRequest).Body()).FileId().Decode())
			cancel()
			cancelRequest, err := readMsg(dt)
			require.NoError(t, err)
			cp := wire.PacketCodec(cancelRequest)
			require.Equal(t, wire.SMB2_CANCEL, cp.Command())
			require.Equal(t, p.MessageId(), cp.MessageId())
			require.Zero(t, cp.CreditCharge())
			require.Zero(t, cp.CreditRequest())
			if async {
				require.NotZero(t, cp.Flags()&wire.SMB2_FLAGS_ASYNC_COMMAND)
				require.EqualValues(t, asyncID, cp.AsyncId())
			} else {
				require.Zero(t, cp.Flags()&wire.SMB2_FLAGS_ASYNC_COMMAND)
			}
			_, err = finishNotify(t, done)
			require.ErrorIs(t, err, context.Canceled)
			require.False(t, f.closed.Load())
			// ECHO completes while both notification responses are still pending.
			echoDone := make(chan error, 1)
			go func() { echoDone <- sendProtocolEcho(f.fs) }()
			echoRequest, err := readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echoRequest).Command())
			sendTestResponse(dt, echoRequest, &wire.EchoResponse{}, 0)
			select {
			case err := <-echoDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked ECHO")
			}
			final := &wire.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(ChangeActionAdded, "late"))}
			buf := make([]byte, final.Size())
			final.Encode(buf)
			fp := wire.PacketCodec(buf)
			fp.SetMessageId(p.MessageId())
			fp.SetSessionId(p.SessionId())
			fp.SetTreeId(p.TreeId())
			fp.SetCreditResponse(1)
			fp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			if async {
				fp.SetFlags(fp.Flags() | wire.SMB2_FLAGS_ASYNC_COMMAND)
				fp.SetAsyncId(asyncID)
			}
			_, err = testWritePacket(dt, buf)
			require.NoError(t, err)
			sendTestResponse(dt, otherRequest, &wire.ChangeNotifyResponse{Output: rawEncoder(notifyEventBytes(ChangeActionAdded, "other"))}, 0)
			result, err := finishNotify(t, otherDone)
			require.NoError(t, err)
			require.Equal(t, []ChangeEvent{{ChangeActionAdded, "other"}}, result.Events)
			// A request after both final notifications confirms that canceled
			// notification state and its credits were fully released.
			echoDone = make(chan error, 1)
			go func() { echoDone <- sendProtocolEcho(f.fs) }()
			echoRequest, err = readMsg(dt)
			require.NoError(t, err)
			require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(echoRequest).Command())
			sendTestResponse(dt, echoRequest, &wire.EchoResponse{}, 0)
			require.NoError(t, <-echoDone)
		})
	}
}

func TestChangeNotifyResponseRejectsMalformedEnum(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{nil, make([]byte, 7), {8, 0, 0, 0, 0, 0, 0, 0}, {9, 0, 72, 0, 1, 0, 0, 0}} {
		if !wire.ChangeNotifyResponseDecoder(body).IsInvalid() {
			t.Fatalf("malformed CHANGE_NOTIFY response %v was accepted", body)
		}
	}
}

func TestChangeNotifyCannotReadNextCompoundResponse(t *testing.T) {
	t.Parallel()
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.isDir = true
	dt := peer
	done := startNotify(f, context.Background(), ChangeFileName, false)
	notifyRequest, err := readMsg(dt)
	require.NoError(t, err)
	echoDone := make(chan error, 1)
	go func() { echoDone <- sendProtocolEcho(f.fs) }()
	echoRequest, err := readMsg(dt)
	require.NoError(t, err)
	makeResponse := func(request []byte, response wire.Packet) []byte {
		buf := make([]byte, response.Size())
		response.Encode(buf)
		p, r := wire.PacketCodec(request), wire.PacketCodec(buf)
		r.SetMessageId(p.MessageId())
		r.SetSessionId(p.SessionId())
		r.SetTreeId(p.TreeId())
		r.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		r.SetCreditResponse(1)
		return buf
	}
	first := makeResponse(notifyRequest, &wire.ChangeNotifyResponse{})
	wire.PacketCodec(first).SetNextCommand(uint32(len(first)))
	le.PutUint16(first[66:68], 80) // Points into the next SMB2 command.
	le.PutUint32(first[68:72], 16)
	second := makeResponse(echoRequest, &wire.EchoResponse{})
	_, err = testWritePacket(dt, append(first, second...))
	require.NoError(t, err)
	_, err = finishNotify(t, done)
	var invalid *protocol.InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	select {
	case err := <-echoDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ECHO response following malformed CHANGE_NOTIFY was lost")
	}
}
