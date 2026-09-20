package smb2

import (
	"context"
	"errors"
	"math/rand"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

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
