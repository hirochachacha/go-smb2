package client

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func assertSessionCount(t *testing.T, d *Client, want int) {
	t.Helper()
	synctest.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sessions) != want {
		t.Fatalf("cached sessions = %d, want %d", len(d.sessions), want)
	}
	if len(d.retired) != 0 {
		t.Fatalf("completed teardown retained %d sessions", len(d.retired))
	}
	if want == 0 && len(d.shares) != 0 {
		t.Fatalf("shares outlived session: %d", len(d.shares))
	}
}

func TestSessionIdleExpiryAndReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		ctx := context.Background()
		first, err := d.acquireShare(ctx, "server", "share")
		if err != nil {
			t.Fatal(err)
		}
		first.session.release()
		time.Sleep(40 * time.Second)
		reused, err := d.acquireShare(ctx, "SERVER", "SHARE")
		if err != nil {
			t.Fatal(err)
		}
		if reused != first {
			t.Fatal("cached share was not reused")
		}
		reused.session.release()
		time.Sleep(40 * time.Second)
		assertSessionCount(t, d, 1)
		time.Sleep(21 * time.Second)
		assertSessionCount(t, d, 0)
		select {
		case <-ep.closed:
		default:
			t.Fatal("expired transport remains open")
		}
		next, err := d.acquireShare(ctx, "server", "share")
		if err != nil {
			t.Fatal(err)
		}
		defer next.session.release()
		if next.session == first.session {
			t.Fatal("reused expired session")
		}
		ep.mu.Lock()
		defer ep.mu.Unlock()
		if ep.logoffs != 0 || ep.treeDisconnects != 0 {
			t.Fatalf("idle teardown sent LOGOFF/TREE_DISCONNECT: %d/%d", ep.logoffs, ep.treeDisconnects)
		}
		if ep.dials != 2 || ep.treeConnects != 2 {
			t.Fatalf("dials/mounts = %d/%d", ep.dials, ep.treeConnects)
		}
	})
}

func TestNonpositiveSessionIdleTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(timeout))
				defer d.Close()
				session, err := d.acquireSession(context.Background(), "server")
				if err != nil {
					t.Fatal(err)
				}
				session.release()
				time.Sleep(24 * time.Hour)
				assertSessionCount(t, d, 1)
			})
		})
	}
}

func TestOpenFilesPreventSessionIdleExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		ctx := context.Background()
		file, err := d.Open(ctx, `\\server\share\first`)
		if err != nil {
			t.Fatal(err)
		}
		other, err := d.WithContext(ctx).Open("server/share/second")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Minute)
		assertSessionCount(t, d, 1)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := file.Close(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Close = %v", err)
		}
		time.Sleep(2 * time.Minute)
		assertSessionCount(t, d, 1)
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Minute)
		assertSessionCount(t, d, 1)
		if err := file.WithContext(ctx).Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(ctx); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("second Close = %v", err)
		}
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestCanceledMountKeepsSessionUntilCreationCompletes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		gate := make(chan struct{})
		ep.blockTree, ep.treeGate = true, gate
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			share, err := d.acquireShare(ctx, "server", "share")
			if err == nil {
				share.session.release()
			}
			result <- err
		}()
		<-ep.treeStarted
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter = %v", err)
		}
		time.Sleep(2 * time.Minute)
		assertSessionCount(t, d, 1)
		close(gate)
		synctest.Wait()
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestExecutingOperationPreventsIdleExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		_, err := d.execute(context.Background(), `\\server\share\file`, func(ctx context.Context, route *resolvedRoute) (any, error) {
			time.Sleep(2 * time.Minute)
			assertSessionCount(t, d, 1)
			return nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestSessionWithoutSharesExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		// Server Stat establishes only a session, as do DFS-only connections.
		if _, err := d.WithContext(context.Background()).Stat("server"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestConcurrentFileCloseReleasesSessionOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		f, err := d.Open(context.Background(), `\\server\share\file`)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				if err := f.Close(context.Background()); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Errorf("Close: %v", err)
				}
			})
		}
		wg.Wait()
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestIdleRetirementCannotRemoveReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		first, err := d.acquireSession(context.Background(), "server")
		if err != nil {
			t.Fatal(err)
		}
		first.release()
		time.Sleep(30 * time.Second)
		d.invalidateSession("server", first)
		next, err := d.acquireSession(context.Background(), "server")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Minute)
		assertSessionCount(t, d, 1)
		next.release()
		time.Sleep(61 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestClientCloseJoinsIdleTeardown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		gate := make(chan struct{})
		ep.closeGate = gate
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Minute))
		defer d.Close()
		session, err := d.acquireSession(context.Background(), "server")
		if err != nil {
			t.Fatal(err)
		}
		session.release()
		time.Sleep(time.Minute)
		synctest.Wait()
		d.mu.Lock()
		cached, retiring := len(d.sessions), len(d.retired)
		d.mu.Unlock()
		if cached != 0 || retiring != 1 {
			t.Fatalf("cached/retiring = %d/%d", cached, retiring)
		}
		done := make(chan error, 1)
		go func() { done <- d.Close() }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("Close returned before teardown: %v", err)
		default:
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		assertSessionCount(t, d, 0)
	})
}

func TestIdleExpiryRacesWithAcquisition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ep := newClientTestEndpoint("server")
		d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(time.Second))
		defer d.Close()
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				for range 10 {
					share, err := d.acquireShare(context.Background(), "server", "share")
					if err != nil {
						t.Error(err)
						return
					}
					time.Sleep(time.Second)
					file, err := share.value.Open(context.Background(), "file")
					if err != nil {
						t.Error(err)
					} else if err := file.Close(context.Background()); err != nil {
						t.Error(err)
					}
					share.session.release()
					time.Sleep(time.Second)
				}
			})
		}
		wg.Wait()
		time.Sleep(2 * time.Second)
		assertSessionCount(t, d, 0)
	})
}

func TestSessionAbortInterruptsClose(t *testing.T) {
	ep := newClientTestEndpoint("server")
	ep.blockLogoff = true
	d := New(newClientTestDialer(&clientTestCredentials{}, ep))
	defer d.Close()
	session, err := d.acquireSession(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	defer session.release()
	closeDone := make(chan error, 1)
	go func() { closeDone <- session.Close() }()
	select {
	case <-ep.logoffStarted:
	case <-time.After(time.Second):
		t.Fatal("Close did not send LOGOFF")
	}
	abortDone := make(chan error, 1)
	go func() { abortDone <- session.Abort() }()
	select {
	case err := <-abortDone:
		if err != nil {
			t.Fatalf("Abort: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Abort waited for the LOGOFF deadline")
	}
	select {
	case err := <-closeDone:
		if err == nil {
			t.Fatal("Close did not report interrupted LOGOFF")
		}
	case <-time.After(time.Second):
		t.Fatal("Abort did not unblock Close")
	}
	if err := session.Abort(); err != nil {
		t.Fatalf("repeated Abort: %v", err)
	}
	if _, err := session.Mount(context.Background(), "share"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Mount after Abort: %v", err)
	}
}
