package smb2

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Session represents one authenticated SMB session and its connection.
type Session struct {
	s                    *protocol.Session
	addr                 string
	disableAAPLExtension bool
	closeOnce            sync.Once
	closeErr             error
	closing              atomic.Bool
	ipcMu                sync.Mutex
	ipc                  *Share
}

// Echo sends an echo request to the server.
func (c *Session) Echo(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return os.ErrInvalid
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
func (c *Session) Mount(ctx context.Context, shareName string) (*Share, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil || c.s == nil {
		return nil, os.ErrInvalid
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
		fs.negotiateAAPL(ctx)
	}
	if err := ctx.Err(); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fs.Unmount(cleanupCtx)
		return nil, &os.PathError{Op: "mount", Path: pathpkg.JoinUNC(c.serverName(), shareName), Err: err}
	}
	return fs, nil
}

// Close logs off this session and closes its transport. It is idempotent and
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
		return os.ErrInvalid
	}
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		c.closeErr = c.s.Close()
	})
	return c.closeErr
}

// Abort closes the session's connection without sending LOGOFF or
// TREE_DISCONNECT, as permitted for idle connections by [MS-SMB2] 3.2.6.2.
// It also interrupts a concurrent Close waiting for LOGOFF to complete.
// Abort is idempotent and returns the connection shutdown error; a concurrent
// Close may separately report that its LOGOFF was interrupted.
func (c *Session) Abort() error {
	if c == nil || c.s == nil {
		return os.ErrInvalid
	}
	c.closing.Store(true)
	// Tear down before joining Close so its LOGOFF cannot delay Abort.
	err := c.s.Abort()
	c.closeOnce.Do(func() { c.closeErr = err })
	return err
}

func (c *Session) getOrMountIPC(ctx context.Context) (*Share, error) {
	if c == nil || c.s == nil {
		return nil, os.ErrInvalid
	}
	if c.closing.Load() {
		return nil, net.ErrClosed
	}
	c.ipcMu.Lock()
	defer c.ipcMu.Unlock()
	if c.ipc != nil {
		return c.ipc, nil
	}
	fs, err := c.Mount(ctx, "IPC$")
	if err != nil {
		return nil, err
	}
	c.ipc = fs
	return fs, nil
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
	return c.listShareNames(ctx, clientMaxShareResponseSize)
}

func (c *Session) listShareNames(ctx context.Context, maxShareResponseSize int) ([]string, error) {
	if c == nil || c.s == nil {
		return nil, os.ErrInvalid
	}
	ipc, err := c.IPC(ctx)
	if err != nil {
		return nil, err
	}
	return (&srvsvc{ipc: ipc}).listShareNames(ctx, c.serverName(), maxShareResponseSize)
}
