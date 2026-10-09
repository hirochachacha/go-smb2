package smb2

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Session represents one authenticated SMB session and its connections.
type Session struct {
	s                    *protocol.Session
	addr                 string
	disableAAPLExtension bool
	closeOnce            sync.Once
	closeErr             error
	closing              atomic.Bool
	ipcMu                sync.Mutex
	ipc                  *Share
	ipcMounting          chan struct{}
	credentials          Credentials
	transportDialer      TransportDialer
	bindMu               sync.Mutex
	bindings             map[*context.CancelFunc]struct{}
}

var errInvalidSession = errors.New("smb2: invalid session")

// BindChannel adds one manually selected connection to this SMB 3.x session.
// address is passed to the TransportDialer used by Dial. Authentication always
// uses the original Dial server name and a fresh initiator from its Credentials.
// Keep those credentials usable until all desired channels have been bound.
// Existing trees and files use the added connection automatically. A failed
// bind leaves existing connections intact; in-flight requests are never replayed.
// Sessions using GMAC signing return an error wrapping errors.ErrUnsupported
// before sending any SMB packet. The initial connection is never downgraded.
// No channels are created automatically.
func (c *Session) BindChannel(ctx context.Context, address string) error {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil || c.credentials == nil || c.transportDialer == nil {
		return errInvalidSession
	}
	if address == "" {
		return os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	c.bindMu.Lock()
	if c.closing.Load() {
		c.bindMu.Unlock()
		cancel()
		return net.ErrClosed
	}
	if c.bindings == nil {
		c.bindings = make(map[*context.CancelFunc]struct{})
	}
	c.bindings[&cancel] = struct{}{}
	c.bindMu.Unlock()
	defer func() {
		cancel()
		c.bindMu.Lock()
		delete(c.bindings, &cancel)
		c.bindMu.Unlock()
	}()
	initiator, err := c.credentials.NewInitiator(ctx, c.addr)
	if err != nil {
		return err
	}
	if initiator == nil {
		return errors.New("smb2: Credentials returned a nil Initiator")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transport, err := c.transportDialer.Dial(ctx, address)
	if err != nil {
		return err
	}
	if transport == nil {
		return errors.New("smb2: TransportDialer returned nil")
	}
	return c.s.BindChannel(ctx, initiator, transport)
}

func (c *Session) cancelBindings() {
	c.bindMu.Lock()
	c.closing.Store(true)
	for cancel := range c.bindings {
		(*cancel)()
	}
	c.bindMu.Unlock()
}

// Echo sends an echo request to the server.
func (c *Session) Echo(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	return c.s.Echo(ctx)
}

func (c *Session) serverName() string {
	serverName := c.addr
	if hostname, _, err := net.SplitHostPort(c.addr); err == nil {
		serverName = hostname
	}
	return serverName
}

// Mount connects to shareName on this session's server.
// After sending TREE_CONNECT, cancellation waits for the final response and
// disconnects any tree the server created. A server that does not complete
// the request can delay cancellation until the connection is closed.
func (c *Session) Mount(ctx context.Context, shareName string) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return nil, errInvalidSession
	}
	if !pathpkg.ValidShareName(shareName) {
		return nil, os.ErrInvalid
	}
	if c.closing.Load() {
		return nil, &os.PathError{Op: "mount", Path: shareName, Err: net.ErrClosed}
	}
	tc, err := c.s.TreeConnect(ctx, c.serverName(), shareName, 0)
	if err != nil {
		return nil, &os.PathError{Op: "mount", Path: pathpkg.JoinUNC(c.serverName(), shareName), Err: err}
	}
	fs := &Share{treeConn: tc}
	if tc.ShareType() == wire.SMB2_SHARE_TYPE_DISK && !c.disableAAPLExtension {
		err = fs.negotiateAAPL(ctx)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clientCleanupTimeout)
		defer cancel()
		_ = fs.Unmount(cleanupCtx)
		return nil, &os.PathError{Op: "mount", Path: pathpkg.JoinUNC(c.serverName(), shareName), Err: err}
	}
	return fs, nil
}

// Close logs off this session and closes its transports. It is idempotent and
// concurrent callers wait for the same shutdown to finish.
//
// Note: While [MS-SMB2] 3.2.4.23 specifies disconnecting each tree connect
// before sending SMB2 LOGOFF, [MS-SMB2] 3.3.5.7 dictates that the server must
// close all open files and tree connects on the session upon receiving LOGOFF.
// Furthermore, [MS-SMB2] 3.2.6.2 and 3.3.7.1 note that tearing down the
// connection implicitly tears down all associated sessions and tree connects on
// the server. Session.Close attempts a graceful LOGOFF first with a timeout,
// followed by closing the connection.
func (c *Session) Close() error {
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	c.closeOnce.Do(func() {
		c.cancelBindings()
		c.closeErr = c.s.Close()
	})
	return c.closeErr
}

// Abort closes the session's connections without sending LOGOFF or
// TREE_DISCONNECT, as permitted for idle connections by [MS-SMB2] 3.2.6.2.
// It also interrupts a concurrent Close waiting for LOGOFF to complete.
// Abort is idempotent and returns the connection shutdown error; a concurrent
// Close may separately report that its LOGOFF was interrupted.
func (c *Session) Abort() error {
	if c == nil || c.s == nil {
		return errInvalidSession
	}
	c.cancelBindings()
	// Tear down before joining Close so its LOGOFF cannot delay Abort.
	err := c.s.Abort()
	c.closeOnce.Do(func() { c.closeErr = err })
	return err
}

func (c *Session) getOrMountIPC(ctx context.Context) (*Share, error) {
	if c == nil || c.s == nil {
		return nil, errInvalidSession
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.ipcMu.Lock()
		if c.closing.Load() {
			c.ipcMu.Unlock()
			return nil, net.ErrClosed
		}
		if c.ipc != nil {
			fs := c.ipc
			c.ipcMu.Unlock()
			return fs, nil
		}
		if done := c.ipcMounting; done != nil {
			c.ipcMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		done := make(chan struct{})
		c.ipcMounting = done
		c.ipcMu.Unlock()

		fs, err := c.Mount(ctx, "IPC$")
		c.ipcMu.Lock()
		if err == nil && c.closing.Load() {
			// Session teardown owns any tree created during shutdown.
			err = net.ErrClosed
		}
		if err == nil {
			c.ipc = fs
		}
		c.ipcMounting = nil
		close(done)
		c.ipcMu.Unlock()
		if err != nil {
			return nil, err
		}
		return fs, nil
	}
}

// IPC returns the session-owned IPC$ share. Callers must not unmount it;
// Session.Close tears it down with the session.
func (c *Session) IPC(ctx context.Context) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	return c.getOrMountIPC(ctx)
}

// ListShareNames enumerates shares exported by this session's server.
func (c *Session) ListShareNames(ctx context.Context) ([]string, error) {
	if ctx == nil {
		panic("nil context")
	}
	return c.listShareNames(ctx, clientMaxShareResponseSize)
}

func (c *Session) listShareNames(ctx context.Context, maxShareResponseSize int) ([]string, error) {
	if c == nil || c.s == nil {
		return nil, errInvalidSession
	}
	ipc, err := c.IPC(ctx)
	if err != nil {
		return nil, err
	}
	return (&srvsvc{ipc: ipc}).listShareNames(ctx, c.serverName(), maxShareResponseSize)
}
