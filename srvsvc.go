package smb2

import (
	"context"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

type srvsvc struct {
	ipc *Share
}

func (s *srvsvc) listShareNames(ctx context.Context, serverName string, maxShareResponseSize int) ([]string, error) {
	pipe, err := msrpc.OpenPipe(ctx, s.ipc, "srvsvc", msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION)
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}
	defer pipe.Close(ctx)

	output, callID, err := pipe.Call(ctx, func(callID uint32) (wire.Encoder, error) {
		request := &msrpc.NetShareEnumAllRequest{
			CallId:     callID,
			ServerName: serverName,
			Level:      1, // level 1 seems to be portable
		}
		if err := request.Validate(); err != nil {
			return nil, err
		}
		return request, nil
	})
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}

	// RPC fragment flags determine completion, independently of SMB status.
	names, err := msrpc.ReadShareNames(output, callID, maxShareResponseSize, func(buffer []byte, minimum int) (int, error) {
		return pipe.ReadAtLeast(ctx, buffer, minimum)
	})
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}
	return names, nil
}
