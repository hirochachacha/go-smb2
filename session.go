package smb2

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Session represents one authenticated SMB session and its connection.
type Session struct {
	s         *protocol.Session
	addr      string
	closeOnce sync.Once
	closeErr  error
	closing   atomic.Bool
	ipcMu     sync.Mutex
	ipc       *Share
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
	return &Share{treeConn: tc}, nil
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

// ListShareNames enumerates shares exported by this session's server.
func (c *Session) ListShareNames(ctx context.Context) ([]string, error) {
	return c.listShareNames(ctx, clientMaxShareResponseSize)
}

func (c *Session) listShareNames(ctx context.Context, maxShareResponseSize int) ([]string, error) {
	if c == nil || c.s == nil {
		return nil, os.ErrInvalid
	}
	serverName := c.serverName()
	fs, err := c.getOrMountIPC(ctx)
	if err != nil {
		return nil, err
	}

	callId := rand.Uint32()

	bindReq := &msrpc.Bind{
		CallId: callId,
	}

	res, err := fs.Request().WithFollowSymlinks(true).
		Create("srvsvc", wire.GENERIC_READ|wire.GENERIC_WRITE, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL).
		Ioctl(wire.FSCTL_PIPE_TRANSCEIVE, bindReq, msrpc.DefaultMaxFragmentSize).
		Do(ctx)
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}
	defer res.Close()

	createRes, err := res.Create(0)
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}
	f := fs.newFile(createRes, "srvsvc")
	defer f.Close(ctx)

	ioctlRes, err := res.Ioctl(1)
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}
	output := ioctlRes.Output()

	if err := msrpc.ValidateBindAck(output, callId); err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}

	callId++

	shareReq := &msrpc.NetShareEnumAllRequest{
		CallId:     callId,
		ServerName: serverName,
		Level:      1, // level 1 seems to be portable
	}

	if err := shareReq.Validate(); err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}

	shareEnumReq := &wire.IoctlRequest{
		CtlCode:           wire.FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: msrpc.DefaultMaxFragmentSize,
		Flags:             wire.SMB2_0_IOCTL_IS_FSCTL,
		Input:             shareReq,
	}

	output, err = fs.ioctl(ctx, f.fd, shareEnumReq)
	if err != nil && !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}

	// RPC fragment flags determine completion, independently of SMB status.
	names, err := msrpc.ReadShareNames(output, callId, maxShareResponseSize, func(buffer []byte, minimum int) (int, error) {
		return fs.readAtChunkAtLeast(ctx, f.fd, buffer, minimum, 0)
	})
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}
	return names, nil
}

// GetDFSReferrals queries referrals using this session's IPC$ tree.
// A nil options value uses the standard referral request.
func (s *Session) GetDFSReferrals(ctx context.Context, path string, options *dfs.ReferralOptions) (*dfs.ReferralResponse, error) {
	if ctx == nil {
		panic("nil context")
	}
	if !pathpkg.ValidReferralPath(path) {
		return nil, os.ErrInvalid
	}
	fs, err := s.getOrMountIPC(ctx)
	if err != nil {
		return nil, err
	}
	ctlCode := uint32(wire.FSCTL_DFS_GET_REFERRALS)
	var req wire.Encoder
	if options != nil && options.SiteName != "" {
		ctlCode = wire.FSCTL_DFS_GET_REFERRALS_EX
		req = &dfsc.ReferralRequestEx{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
			SiteName:         options.SiteName,
		}
	} else {
		req = &dfsc.ReferralRequest{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
		}
	}
	for maxOutput := uint32(clientReferralInitialOutputSize); ; {
		res, err := fs.Request().WithFollowSymlinks(true).WithFileID(wire.RelatedFileId).
			Ioctl(ctlCode, req, maxOutput).Do(ctx)
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) && maxOutput < maxDFSReferralResponseSize {
				maxOutput = min(maxOutput*2, uint32(maxDFSReferralResponseSize))
				continue
			}
			return nil, err
		}
		out, err := res.Ioctl(0)
		if err != nil {
			res.Close()
			return nil, err
		}
		buf := append([]byte(nil), out.Output()...)
		res.Close()
		r, err := dfsc.ParseReferralResponse(buf, path)
		if err != nil {
			return nil, &os.PathError{Op: "getDFSReferrals", Path: path, Err: err}
		}
		return convertDFSReferral(r), nil
	}
}

func convertDFSReferral(r *dfsc.ReferralResponse) *dfs.ReferralResponse {
	nameList := r.IsNameList()
	prefix := ""
	suffix := ""
	if !nameList && len(r.Entries) > 0 {
		prefix, suffix = r.Prefix, r.Suffix
	}
	out := &dfs.ReferralResponse{PathConsumed: r.PathConsumed, HeaderFlags: r.ReferralHeaderFlags, Prefix: prefix, Entries: make([]dfs.ReferralEntry, len(r.Entries))}
	for i, e := range r.Entries {
		v := dfs.ReferralEntry{Version: e.Version, ServerType: e.ServerType, Flags: e.EntryFlags, TTL: time.Duration(e.TimeToLive) * time.Second, DFSPath: e.DFSPath, DFSAlternatePath: e.DFSAlternatePath, NetworkAddress: e.NetworkAddress, SpecialName: e.SpecialName, ExpandedNames: append([]string(nil), e.ExpandedNames...)}
		if !nameList && e.NetworkAddress != "" {
			v.TargetPath = pathpkg.ToPublicUNC(e.NetworkAddress)
			if suffix != "" {
				v.TargetPath = pathpkg.AppendReferralSuffix(v.TargetPath, suffix)
			}
		}
		out.Entries[i] = v
	}
	return out
}
