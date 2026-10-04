package smb2_test

import (
	"context"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

type cleanupTestSession struct{ order *[]string }

func (s cleanupTestSession) Close() error {
	*s.order = append(*s.order, "session")
	return nil
}

type cleanupTestShare struct {
	name    string
	order   *[]string
	ctx     context.Context
	wait    bool
	started chan struct{}
	release chan struct{}
}

func (s *cleanupTestShare) Unmount(ctx context.Context) error {
	s.ctx = ctx
	*s.order = append(*s.order, s.name)
	if s.started != nil {
		close(s.started)
	}
	if s.wait {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.release:
			return os.ErrPermission
		}
	}
	return os.ErrPermission
}

func TestIntegrationCleanupBoundsUnmount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var order []string
		share2 := &cleanupTestShare{name: "share2", order: &order, wait: true, started: make(chan struct{}), release: make(chan struct{})}
		share1 := &cleanupTestShare{name: "share1", order: &order}
		finished := make(chan struct{})
		t.Cleanup(func() {
			close(share2.release)
			<-finished
		})
		started := time.Now()
		go func() {
			closeTestSession(context.Background(), cleanupTestSession{&order}, share2, share1)
			close(finished)
		}()
		<-share2.started
		synctest.Wait()
		deadline, ok := share2.ctx.Deadline()
		require.True(t, ok, "Unmount must have its own bounded cleanup context")
		require.Equal(t, 5*time.Second, deadline.Sub(started))
		<-finished
		require.Equal(t, 5*time.Second, time.Since(started))
		require.Equal(t, []string{"share2", "share1", "session"}, order)
		require.ErrorIs(t, share2.ctx.Err(), context.DeadlineExceeded)
	})
}

func TestIntegrationCleanupDetachesExpiredSetupContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		setup, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
		defer cancel()
		require.ErrorIs(t, setup.Err(), context.DeadlineExceeded)
		var order []string
		share := &cleanupTestShare{name: "share1", order: &order}
		closeTestSession(setup, cleanupTestSession{&order}, share)
		require.Equal(t, []string{"share1", "session"}, order)
		deadline, ok := share.ctx.Deadline()
		require.True(t, ok)
		require.Equal(t, 5*time.Second, time.Until(deadline))
		require.ErrorIs(t, share.ctx.Err(), context.Canceled, "cleanup context must be canceled on return")
	})
}
