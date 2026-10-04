package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/stretchr/testify/require"
)

func runClientCopy(method string, ctx context.Context, source, destination *File) (int64, error) {
	switch method {
	case "ReadFrom":
		return destination.ReadFrom(ctx, source.WithContext(ctx))
	case "WriteTo":
		return source.WriteTo(ctx, destination.WithContext(ctx))
	case "bound ReadFrom":
		return destination.WithContext(ctx).ReadFrom(source.WithContext(ctx))
	default:
		return source.WithContext(ctx).WriteTo(destination.WithContext(ctx))
	}
}

func TestClientCopyFailureRetiresAttributedSession(t *testing.T) {
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, tc := range []struct {
			name, mode, op, abort              string
			separate                           bool
			n, sourceOffset, destinationOffset int64
			reads, writes, resumes, copies     int
		}{
			{name: "shared aborted", mode: "recovery", op: "copy", abort: "source"},
			{name: "source aborted", mode: "recovery", op: "read", abort: "source", separate: true},
			{name: "destination aborted", mode: "recovery", op: "write", abort: "destination", separate: true, sourceOffset: 3, reads: 1},
			{name: "partial shared copy", mode: "copy-partial-unavailable", op: "copy", n: 16 << 20, sourceOffset: 16 << 20, destinationOffset: 16 << 20, resumes: 1, copies: 2},
			{name: "partial source", mode: "fallback-read-unavailable", op: "read", separate: true, n: 3, sourceOffset: 3, destinationOffset: 3, reads: 2, writes: 1},
			{name: "partial destination", mode: "fallback-write-unavailable", op: "write", separate: true, n: 3, sourceOffset: 6, destinationOffset: 3, reads: 2, writes: 2},
			{name: "peer EOF", mode: "fallback-transport-error", op: "read", n: 3, sourceOffset: 3, destinationOffset: 4, reads: 2, writes: 1},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					source, destination, fixture := newClientCopyPairOnClients(t, tc.mode, tc.separate)
					ctx := context.Background()
					failed, healthy := source, destination
					if tc.op == "write" {
						failed, healthy = destination, source
					}
					if tc.abort != "" {
						require.NoError(t, failed.session.Abort())
					}
					if tc.mode == "fallback-transport-error" {
						_, err := destination.Seek(ctx, 1, io.SeekStart)
						require.NoError(t, err)
					}
					n, err := runClientCopy(method, ctx, source, destination)
					require.Equal(t, tc.n, n)
					if tc.abort != "" || tc.mode == "fallback-transport-error" {
						var transport *protocol.TransportError
						require.ErrorAs(t, err, &transport)
						cause := net.ErrClosed
						if tc.mode == "fallback-transport-error" {
							cause = io.EOF
						}
						require.ErrorIs(t, err, cause)
					} else {
						require.ErrorIs(t, err, erref.STATUS_NETWORK_SESSION_EXPIRED)
					}
					if tc.op == "copy" {
						var link *os.LinkError
						require.ErrorAs(t, err, &link)
						require.Equal(t, "copy", link.Op)
						require.Equal(t, source.name, link.Old)
						require.Equal(t, destination.name, link.New)
					} else {
						var path *os.PathError
						require.ErrorAs(t, err, &path)
						require.Equal(t, tc.op, path.Op)
						require.Equal(t, failed.name, path.Path)
					}
					require.Equal(t, tc.reads, fixture.reads)
					require.Equal(t, tc.writes, fixture.writes)
					require.Equal(t, tc.resumes, fixture.resumes)
					require.Equal(t, tc.copies, fixture.copies, "copy must not be replayed")
					for _, endpoint := range []struct {
						file   *File
						offset int64
					}{{source, tc.sourceOffset}, {destination, tc.destinationOffset}} {
						offset, seekErr := endpoint.file.Seek(ctx, 0, io.SeekCurrent)
						require.NoError(t, seekErr)
						require.Equal(t, endpoint.offset, offset)
						require.False(t, endpoint.file.closed)
					}
					d := failed.session.client
					d.mu.Lock()
					cached := d.sessions[failed.session.key]
					d.mu.Unlock()
					require.Nil(t, cached, "a failed copy must not reopen the session itself")
					next, openErr := d.Open(ctx, `\\SERVER\SHARE\fresh`)
					require.NoError(t, openErr, "the next independent Open must reconnect immediately")
					require.NotSame(t, failed.session, next.session)
					defer next.Close(ctx)
					// Repeat an old-generation copy failure after publishing a replacement.
					if tc.op == "write" {
						_, seekErr := source.Seek(ctx, 0, io.SeekStart)
						require.NoError(t, seekErr)
					}
					_, lateErr := runClientCopy(method, ctx, source, destination)
					require.Error(t, lateErr)
					synctest.Wait()
					d.mu.Lock()
					current, oldUsers, newUsers := d.sessions[failed.session.key], failed.session.users, next.session.users
					staleShares := 0
					for _, share := range d.shares {
						if share.session == failed.session {
							staleShares++
						}
					}
					d.mu.Unlock()
					require.Same(t, next.session, current, "late errors must preserve the replacement")
					require.Zero(t, staleShares)
					wantOldUsers := 2
					if tc.separate {
						wantOldUsers = 1
						hd := healthy.session.client
						hd.mu.Lock()
						healthyCurrent, healthyUsers := hd.sessions[healthy.session.key], healthy.session.users
						hd.mu.Unlock()
						require.Same(t, healthy.session, healthyCurrent)
						require.Equal(t, 1, healthyUsers)
						buf := make([]byte, 3)
						count, readErr := healthy.ReadAt(ctx, buf, 0)
						require.NoError(t, readErr)
						require.Equal(t, 3, count)
						require.Equal(t, "abc", string(buf))
					}
					require.Equal(t, wantOldUsers, oldUsers)
					require.Equal(t, 1, newUsers)
				})
			})
		}
	}
}

func TestClientCopyCancellationKeepsSessions(t *testing.T) {
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, separate := range []bool{false, true} {
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
				t.Run(fmt.Sprintf("%s/%v/separate=%v", method, cause, separate), func(t *testing.T) {
					source, destination, fixture := newClientCopyPairOnClients(t, "recovery", separate)
					ctx, cancel := context.WithCancel(context.Background())
					if cause == context.DeadlineExceeded {
						cancel()
						ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
					}
					cancel()
					n, err := runClientCopy(method, ctx, source, destination)
					require.Zero(t, n)
					require.ErrorIs(t, err, cause)
					require.Zero(t, fixture.reads+fixture.writes+fixture.resumes+fixture.copies)
					for _, file := range []*File{source, destination} {
						d := file.session.client
						d.mu.Lock()
						current := d.sessions[file.session.key]
						d.mu.Unlock()
						require.Same(t, file.session, current)
					}
				})
			}
		}
	}
}

func TestClientCopyUnattributedErrorKeepsSessions(t *testing.T) {
	source, destination, _ := newClientCopyPairOnClients(t, "recovery", true)
	cause := &protocol.TransportError{Err: net.ErrClosed}
	for _, err := range []error{
		&os.LinkError{Op: "copy", Old: "file", New: "file", Err: cause},
		&os.LinkError{Op: "rename", Old: "file", New: "file", Err: cause},
		&os.PathError{Op: "stat", Path: "file", Err: cause},
	} {
		require.ErrorIs(t, copyError(err, source, destination), cause)
		for _, file := range []*File{source, destination} {
			d := file.session.client
			d.mu.Lock()
			current := d.sessions[file.session.key]
			d.mu.Unlock()
			require.Same(t, file.session, current)
		}
	}
}

func TestClientCopyInFlightCancellationKeepsSession(t *testing.T) {
	for _, method := range []string{"ReadFrom", "WriteTo", "bound ReadFrom", "bound WriteTo"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(method+"/"+cause.Error(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					source, destination, fixture := newClientCopyPair(t, "copy-cancel")
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					finished := make(chan error, 1)
					go func() {
						n, err := runClientCopy(method, ctx, source, destination)
						require.Zero(t, n)
						finished <- err
					}()
					synctest.Wait()
					require.Equal(t, 1, fixture.copies)
					require.NotEmpty(t, fixture.pendingCopy)
					if cause == context.Canceled {
						cancel()
					}
					require.ErrorIs(t, <-finished, cause)
					synctest.Wait()
					require.Empty(t, fixture.pendingCopy, "SMB CANCEL must complete the pending request")
					d := source.session.client
					next, err := d.Open(context.Background(), `\\server\share\healthy`)
					require.NoError(t, err)
					require.Same(t, source.session, next.session)
					require.NoError(t, next.Close(context.Background()))
					d.mu.Lock()
					users := source.session.users
					d.mu.Unlock()
					require.Equal(t, 2, users)
					require.False(t, source.closed)
					require.False(t, destination.closed)
				})
			})
		}
	}
}
