package smb2

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
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

	res, err := fs.request().
		create("srvsvc", smb2.GENERIC_READ|smb2.GENERIC_WRITE, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL).
		ioctl(smb2.FSCTL_PIPE_TRANSCEIVE, bindReq, msrpc.DefaultMaxFragmentSize).
		sendRecv(ctx)
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: "srvsvc", Err: err}
	}
	defer res.close()

	f := fs.newFile(res.data(0), "srvsvc")
	defer f.Close(ctx)

	output := smb2.IoctlResponseDecoder(res.data(1)).Output()

	bindAck := msrpc.BindAckDecoder(output)
	if bindAck.IsInvalid() || bindAck.CallId() != callId {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"broken bind ack response format"}}
	}
	// [MS-RPCE] 3.3.1.5.6 requires an accepted transfer syntax before calls.
	if !bindAck.AcceptsNDR() {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"bind ack did not accept NDR v2"}}
	}

	callId++

	shareReq := &msrpc.NetShareEnumAllRequest{
		CallId:     callId,
		ServerName: serverName,
		Level:      1, // level 1 seems to be portable
	}

	if shareReq.Size() > math.MaxUint16 {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InternalError{"server name exceeds max MSRPC fragment size"}}
	}

	shareEnumReq := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: msrpc.DefaultMaxFragmentSize,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             shareReq,
	}

	output, err = fs.ioctl(ctx, f.fd, shareEnumReq)
	if err != nil && !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
	}

	// STATUS_SUCCESS can carry only the first RPC response PDU; RPC fragment
	// flags, not the SMB status, determine completion [MS-RPCE 2.1.1.2].
	// STATUS_BUFFER_OVERFLOW describes only the FSCTL output buffer
	// [MS-FSCC 2.3.48].
	buf := make([]byte, msrpc.DefaultMaxFragmentSize)
	var (
		pdu []byte
		rem = output
	)
	firstFragment := true
	output = nil
	for {
		pdu, rem, err = fs.readRpcFrag(ctx, f.fd, rem, buf, callId)
		if err != nil {
			return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: err}
		}
		frag := msrpc.ResponseFragmentDecoder(pdu)
		if frag.IsInvalid() {
			return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
		}

		chunk := frag.Stub()
		if !firstFragment && len(chunk) == 0 {
			return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"empty net share enum response fragment"}}
		}
		if maxShareResponseSize >= 0 && len(chunk) > maxShareResponseSize-len(output) {
			return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"net share enum response exceeds maximum size"}}
		}
		output = append(output, chunk...)

		if frag.Header().PacketFlags()&msrpc.RPC_PACKET_FLAG_LAST != 0 {
			if len(rem) != 0 {
				return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
			}
			break
		}

		firstFragment = false
	}

	names, err := msrpc.NetShareEnumAllResponseDecoder(output).Sharenames()
	if err != nil {
		return nil, &os.PathError{Op: "listShareNames", Path: f.name, Err: &InvalidResponseError{fmt.Sprintf("broken net share enum response format: %v", err)}}
	}

	return names, nil
}
