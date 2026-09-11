package smb2

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func TestFileLockValidatesRangesAndEncodesRequest(t *testing.T) {
	f, serverConn := newTestFile(t)
	for _, test := range []struct {
		name   string
		lock   []LockRange
		unlock []ByteRange
	}{
		{name: "empty lock"},
		{name: "negative offset", lock: []LockRange{{Range: ByteRange{Offset: -1, Length: 1}}}},
		{name: "negative length", lock: []LockRange{{Range: ByteRange{Length: -1}}}},
		{name: "range overflow", lock: []LockRange{{Range: ByteRange{Offset: math.MaxInt64, Length: 2}}}},
		{name: "request too large", lock: make([]LockRange, (maxLockRequestSize-64-24)/24+1)},
		{name: "waiting multiple ranges", lock: []LockRange{{}, {}}},
		{name: "empty unlock", unlock: []ByteRange{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.unlock != nil {
				err = f.Unlock(context.Background(), test.unlock)
			} else {
				err = f.Lock(context.Background(), test.lock, false)
			}
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("error = %v, want os.ErrInvalid", err)
			}
		})
	}

	server := direct(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(server)
		if err != nil {
			t.Errorf("read lock request: %v", err)
			return
		}
		d := smb2.LockRequestDecoder(req[64:])
		if d.IsInvalid() || d.LockCount() != 1 {
			t.Errorf("invalid lock request: count=%d invalid=%v", d.LockCount(), d.IsInvalid())
			return
		}
		lock := smb2.LockElementDecoder(d.Locks())
		if lock.Offset() != 7 || lock.Length() != 0 || lock.Flags() != smb2.SMB2_LOCKFLAG_EXCLUSIVE_LOCK {
			t.Errorf("unexpected lock element: offset=%d length=%d flags=%#x", lock.Offset(), lock.Length(), lock.Flags())
		}
		sendTestResponse(server, req, &smb2.LockResponse{}, 0)
	}()

	if err := f.Lock(context.Background(), []LockRange{{Range: ByteRange{Offset: 7}, Exclusive: true}}, false); err != nil {
		t.Fatalf("Lock returned error: %v", err)
	}
	<-done
}

func TestFileLockReturnsRangeStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		status erref.NtStatus
		unlock bool
		wantOp string
	}{
		{name: "lock conflict", status: erref.STATUS_LOCK_NOT_GRANTED, wantOp: "lock"},
		{name: "unlock conflict", status: erref.STATUS_RANGE_NOT_LOCKED, unlock: true, wantOp: "unlock"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, serverConn := newTestFile(t)
			server := direct(serverConn)
			done := make(chan struct{})
			go func() {
				defer close(done)
				req, err := readMsg(server)
				if err != nil {
					t.Errorf("read %s request: %v", test.wantOp, err)
					return
				}
				if got := smb2.PacketCodec(req).Command(); got != smb2.SMB2_LOCK {
					t.Errorf("command = %v, want LOCK", got)
					return
				}
				sendTestResponse(server, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_LOCK}, uint32(test.status))
			}()

			var err error
			if test.unlock {
				err = f.Unlock(context.Background(), []ByteRange{{Offset: 7, Length: 1}})
			} else {
				err = f.Lock(context.Background(), []LockRange{{Range: ByteRange{Offset: 7, Length: 1}}}, true)
			}
			var responseErr *ResponseError
			if !errors.As(err, &responseErr) {
				t.Fatalf("error = %v, want ResponseError", err)
			}
			if responseErr.Code != uint32(test.status) {
				t.Fatalf("ResponseError.Code = %#x, want %#x", responseErr.Code, test.status)
			}
			<-done
		})
	}
}

func TestFileLockCancelSendsAsyncCancelAndKeepsConnectionUsable(t *testing.T) {
	for _, status := range []erref.NtStatus{erref.STATUS_SUCCESS, erref.STATUS_CANCELLED, erref.STATUS_LOCK_NOT_GRANTED} {
		t.Run(fmt.Sprintf("status_%x", uint32(status)), func(t *testing.T) {

			f, serverConn := newTestFile(t)
			other := f.fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "other.txt")
			server := direct(serverConn)

			ctx, cancel := context.WithCancel(context.Background())
			lockDone := make(chan error, 1)
			go func() {
				lockDone <- f.Lock(ctx, []LockRange{{Range: ByteRange{Offset: 4, Length: 8}}}, false)
			}()

			lockReq, err := readMsg(server)
			if err != nil {
				t.Fatalf("read LOCK request: %v", err)
			}
			lockPkt := smb2.PacketCodec(lockReq)
			if lockPkt.Command() != smb2.SMB2_LOCK {
				t.Fatalf("command = %v, want LOCK", lockPkt.Command())
			}

			pending := &smb2.LockResponse{}
			pendingBuf := make([]byte, pending.Size())
			pending.Encode(pendingBuf)
			pendingPkt := smb2.PacketCodec(pendingBuf)
			pendingPkt.SetMessageId(lockPkt.MessageId())
			pendingPkt.SetSessionId(lockPkt.SessionId())
			pendingPkt.SetTreeId(lockPkt.TreeId())
			pendingPkt.SetStatus(uint32(erref.STATUS_PENDING))
			pendingPkt.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
			pendingPkt.SetAsyncId(0xA55A)
			pendingPkt.SetCreditResponse(1)
			if _, err := server.Writev(pendingBuf); err != nil {
				t.Fatalf("send pending LOCK response: %v", err)
			}

			conn := f.fs.session.conn
			require.Eventually(t, func() bool {
				rr, ok := conn.outstandingRequests.peek(lockPkt.MessageId())
				return ok && rr.asyncId.Load() == 0xA55A
			}, time.Second, time.Millisecond, "PENDING response was not registered before cancellation")

			cancel()
			cancelReq, err := readMsg(server)
			if err != nil {
				t.Fatalf("read CANCEL request: %v", err)
			}
			cancelPkt := smb2.PacketCodec(cancelReq)
			if cancelPkt.Command() != smb2.SMB2_CANCEL || cancelPkt.MessageId() != lockPkt.MessageId() {
				t.Fatalf("CANCEL = command %v, message id %d; want LOCK id %d", cancelPkt.Command(), cancelPkt.MessageId(), lockPkt.MessageId())
			}
			if cancelPkt.Flags()&smb2.SMB2_FLAGS_ASYNC_COMMAND == 0 || cancelPkt.AsyncId() != 0xA55A {
				t.Fatalf("CANCEL async fields = flags %#x, id %#x", cancelPkt.Flags(), cancelPkt.AsyncId())
			}

			otherDone := make(chan error, 2)
			go func() { otherDone <- other.Sync() }()
			go func() { otherDone <- f.fs.session.echo(context.Background()) }()
			for i := 0; i < 2; i++ {
				req, err := readMsg(server)
				if err != nil {
					t.Fatalf("read concurrent request: %v", err)
				}
				switch smb2.PacketCodec(req).Command() {
				case smb2.SMB2_FLUSH:
					sendTestResponse(server, req, &smb2.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
				case smb2.SMB2_ECHO:
					sendTestResponse(server, req, &smb2.EchoResponse{}, uint32(erref.STATUS_SUCCESS))
				default:
					t.Fatalf("unexpected concurrent command: %v", smb2.PacketCodec(req).Command())
				}
			}
			for i := 0; i < 2; i++ {
				select {
				case err := <-otherDone:
					if err != nil {
						t.Fatalf("concurrent operation failed: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("concurrent operation did not complete while LOCK was canceled")
				}
			}

			select {
			case err := <-lockDone:
				t.Fatalf("LOCK completed before delayed final response: %v", err)
			default:
			}

			var final smb2.Packet = &smb2.LockResponse{}
			if status != erref.STATUS_SUCCESS {
				final = &smb2.ErrorResponse{CommandCode: smb2.SMB2_LOCK}
			}
			finalBuf := make([]byte, final.Size())
			final.Encode(finalBuf)
			finalPkt := smb2.PacketCodec(finalBuf)
			finalPkt.SetMessageId(lockPkt.MessageId())
			finalPkt.SetSessionId(lockPkt.SessionId())
			finalPkt.SetTreeId(lockPkt.TreeId())
			finalPkt.SetStatus(uint32(status))
			finalPkt.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_ASYNC_COMMAND)
			finalPkt.SetAsyncId(0xA55A)
			finalPkt.SetCreditResponse(1)
			if _, err := server.Writev(finalBuf); err != nil {
				t.Fatalf("send final LOCK response: %v", err)
			}
			select {
			case err := <-lockDone:
				switch status {
				case erref.STATUS_SUCCESS:
					require.NoError(t, err)
				case erref.STATUS_CANCELLED:
					require.ErrorIs(t, err, context.Canceled)
				default:
					var responseErr *ResponseError
					require.ErrorAs(t, err, &responseErr)
					require.Equal(t, uint32(status), responseErr.Code)
				}
			case <-time.After(time.Second):
				t.Fatal("LOCK did not complete after final response")
			}

			if !eventuallyNoInFlightCredits(conn, time.Second) {
				t.Fatal("delayed final LOCK response did not release its credits")
			}
		})
	}
}

func eventuallyNoInFlightCredits(conn *conn, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn.account.m.Lock()
		inFlight := conn.account.inFlightCredits
		conn.account.m.Unlock()
		if inFlight == 0 {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func TestFileLockMultipleRangesAndUnlock(t *testing.T) {
	f, serverConn := newTestFile(t)
	server := direct(serverConn)
	ranges := []ByteRange{{Offset: 7}, {Offset: math.MaxInt64, Length: 1}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, unlock := range []bool{false, true} {
			req, err := readMsg(server)
			if err != nil {
				t.Error(err)
				return
			}
			d := smb2.LockRequestDecoder(req[64:])
			if d.IsInvalid() || d.LockCount() != 2 {
				t.Error("invalid multi-range request")
				return
			}
			require.Equal(t, *f.fd, *d.FileId().Decode())
			for i, r := range ranges {
				element := smb2.LockElementDecoder(d.Locks()[24*i:])
				require.Equal(t, uint64(r.Offset), element.Offset())
				require.Equal(t, uint64(r.Length), element.Length())
				flags := uint32(smb2.SMB2_LOCKFLAG_SHARED_LOCK | smb2.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
				if i == 1 {
					flags = smb2.SMB2_LOCKFLAG_EXCLUSIVE_LOCK | smb2.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
				}
				if unlock {
					flags = smb2.SMB2_LOCKFLAG_UNLOCK
				}
				require.Equal(t, flags, element.Flags())
			}
			sendTestResponse(server, req, &smb2.LockResponse{}, 0)
		}
	}()
	require.NoError(t, f.Lock(context.Background(), []LockRange{{Range: ranges[0]}, {Range: ranges[1], Exclusive: true}}, true))
	require.NoError(t, f.Unlock(context.Background(), ranges))
	<-done
}

func TestFileLockCancellationWaitsForTransportFailure(t *testing.T) {
	f, serverConn := newTestFile(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.Lock(ctx, []LockRange{{}}, false) }()
	server := direct(serverConn)
	_, err := readMsg(server)
	require.NoError(t, err)
	cancel()
	req, err := readMsg(server)
	require.NoError(t, err)
	require.Equal(t, smb2.SMB2_CANCEL, smb2.PacketCodec(req).Command())
	require.NoError(t, serverConn.Close())
	select {
	case err := <-done:
		var transportErr *TransportError
		require.ErrorAs(t, err, &transportErr)
	case <-time.After(time.Second):
		t.Fatal("LOCK did not finish after transport failure")
	}
}
