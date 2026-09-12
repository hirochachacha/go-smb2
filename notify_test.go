package smb2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
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
	ctx := context.Background()
	var nilFile *File
	if _, err := nilFile.WaitForChange(ctx, ChangeFileName, false); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil File error = %v, want os.ErrInvalid", err)
	}

	f := &File{fd: &smb2.FileId{}}
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
	for _, status := range []uint32{uint32(erref.STATUS_SUCCESS), uint32(erref.STATUS_NOTIFY_ENUM_DIR)} {
		t.Run(fmt.Sprintf("status-%08x", status), func(t *testing.T) {
			require := require.New(t)
			f, serverConn := newTestFile(t)
			f.isDir = true
			go func() {
				dt := direct(serverConn)
				req, err := readMsg(dt)
				if err != nil {
					return
				}
				require.Equal(smb2.SMB2_CHANGE_NOTIFY, smb2.PacketCodec(req).Command())
				sendTestResponse(dt, req, &smb2.ChangeNotifyResponse{}, status)
			}()

			result, err := f.WaitForChange(context.Background(), ChangeFileName, false)
			require.NoError(err)
			require.Empty(result.Events)
			require.True(result.RescanRequired)
		})
	}
}

func TestFileWaitForChangePreservesEventOrderAndNames(t *testing.T) {
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
	oldName := makeEvent(smb2.FILE_ACTION_RENAMED_OLD_NAME, "old.txt")
	newName := makeEvent(smb2.FILE_ACTION_RENAMED_NEW_NAME, "new.txt")
	le.PutUint32(oldName[:4], uint32(len(oldName)))
	output := append(oldName, newName...)

	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		request := smb2.ChangeNotifyRequestDecoder(smb2.PacketCodec(req).Body())
		if request.IsInvalid() {
			return
		}
		sendTestResponse(dt, req, &smb2.ChangeNotifyResponse{Output: rawEncoder(output)}, uint32(erref.STATUS_SUCCESS))
	}()

	result, err := f.WaitForChange(context.Background(), ChangeFileName, false)
	require.NoError(err)
	require.False(result.RescanRequired)
	require.Equal([]ChangeEvent{
		{Action: ChangeActionRenamedOldName, Name: "old.txt"},
		{Action: ChangeActionRenamedNewName, Name: "new.txt"},
	}, result.Events)
}

func TestFileWaitForChangeRejectsConcurrentCall(t *testing.T) {
	require := require.New(t)
	f, serverConn := newTestFile(t)
	f.isDir = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		_, err := f.WaitForChange(ctx, ChangeFileName, false)
		firstDone <- err
	}()

	dt := direct(serverConn)
	request, err := readMsg(dt)
	require.NoError(err)
	_, err = f.WaitForChange(context.Background(), ChangeFileName, false)
	require.ErrorIs(err, os.ErrInvalid)

	cancel()
	cancelRequest, err := readMsg(dt)
	require.NoError(err)
	require.Equal(smb2.SMB2_CANCEL, smb2.PacketCodec(cancelRequest).Command())
	sendTestResponse(dt, request, &smb2.ChangeNotifyResponse{}, uint32(erref.STATUS_SUCCESS))
	select {
	case <-time.After(time.Second):
		t.Fatal("first CHANGE_NOTIFY did not return after cancellation")
	case err := <-firstDone:
		require.ErrorIs(err, context.Canceled)
	}
}

func TestFileWaitForChangeResponseValidation(t *testing.T) {
	for _, test := range []struct {
		name       string
		output     []byte
		recursive  bool
		status     erref.NtStatus
		wantStatus bool
	}{
		{name: "root slash", output: notifyEventBytes(ChangeActionAdded, "/root")},
		{name: "root backslash", output: notifyEventBytes(ChangeActionAdded, `\root`)},
		{name: "quote", output: notifyEventBytes(ChangeActionAdded, `a"b`)},
		{name: "child slash", output: notifyEventBytes(ChangeActionAdded, "a/b")},
		{name: "child backslash", output: notifyEventBytes(ChangeActionAdded, `a\b`)},
		{name: "recursive quote", output: notifyEventBytes(ChangeActionAdded, `a"b`), recursive: true},
		{name: "truncated record", output: make([]byte, 11)},
		{name: "unknown action", output: notifyEventBytes(12, "a")},
		{name: "request limit", output: make([]byte, 4097)},
		{name: "enum with events", status: erref.STATUS_NOTIFY_ENUM_DIR, output: notifyEventBytes(ChangeActionAdded, "a")},
		{name: "cleanup", status: erref.STATUS_NOTIFY_CLEANUP, wantStatus: true},
		{name: "access denied", status: erref.STATUS_ACCESS_DENIED, wantStatus: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, peer := newTestFile(t)
			require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
			f.isDir = true
			f.fs.conn.maxTransactSize = 4096
			done := startNotify(f, context.Background(), ChangeFileName, test.recursive)
			dt := direct(peer)
			request, err := readMsg(dt)
			require.NoError(t, err)
			var response smb2.Packet = &smb2.ChangeNotifyResponse{Output: rawEncoder(test.output)}
			if test.wantStatus {
				response = &smb2.ErrorResponse{CommandCode: smb2.SMB2_CHANGE_NOTIFY}
			}
			sendTestResponse(dt, request, response, uint32(test.status))
			result, err := finishNotify(t, done)
			require.Empty(t, result.Events)
			require.False(t, result.RescanRequired)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			if test.wantStatus {
				var responseErr *ResponseError
				require.ErrorAs(t, err, &responseErr)
				require.Equal(t, uint32(test.status), responseErr.Code)
			} else {
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
			}
		})
	}
}

func TestFileWaitForChangeContract(t *testing.T) {
	f, peer := newTestFile(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	f.isDir = true
	f.fd = &smb2.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{7}}
	f.fs.conn.maxTransactSize = 2048
	shareCtx, cancel := context.WithCancel(context.Background())
	cancel()
	f.fs.ctx = shareCtx // Only the explicit context governs WaitForChange.
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
	dt := direct(peer)
	var first ChangeResult
	for i := range 2 {
		done := startNotify(f, context.Background(), filter, true)
		request, err := readMsg(dt)
		require.NoError(t, err)
		p := smb2.PacketCodec(request)
		r := smb2.ChangeNotifyRequestDecoder(p.Body())
		require.False(t, r.IsInvalid())
		require.Equal(t, f.fd, r.FileId().Decode())
		require.EqualValues(t, filter, r.CompletionFilter())
		require.EqualValues(t, smb2.SMB2_WATCH_TREE, r.Flags())
		require.EqualValues(t, 2048, r.OutputBufferLength())
		require.EqualValues(t, 1, p.CreditCharge())
		require.Zero(t, p.NextCommand())
		var response smb2.Packet = &smb2.ChangeNotifyResponse{}
		if i == 0 {
			response = &smb2.ChangeNotifyResponse{Output: rawEncoder(output)}
		}
		sendTestResponse(dt, request, response, 0)
		result, err := finishNotify(t, done)
		require.NoError(t, err)
		if i == 0 {
			first = result
		}
		_, err = f.WaitForChange(context.Background(), ChangeFileName, true)
		require.ErrorIs(t, err, os.ErrInvalid)
		_, err = f.WaitForChange(context.Background(), filter, false)
		require.ErrorIs(t, err, os.ErrInvalid)
	}
	require.Equal(t, want, first.Events) // Survives subsequent buffer reuse.
	f.closed.Store(true)
	_, err := f.WaitForChange(context.Background(), filter, true)
	require.ErrorIs(t, err, os.ErrClosed)
	var nilCtx context.Context
	require.Panics(t, func() { _, _ = f.WaitForChange(nilCtx, filter, true) })
}
