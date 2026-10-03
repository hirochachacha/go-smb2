package client

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestClientWriteFileJoinedErrorsKeepOriginalUNC(t *testing.T) {
	for _, test := range []struct {
		name                       string
		writeFailure, closeFailure bool
	}{
		{name: "success"},
		{name: "write-only", writeFailure: true},
		{name: "close-only", closeFailure: true},
		{name: "both", writeFailure: true, closeFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			var writes, closes atomic.Int32
			ep.handleRequest = func(conn net.Conn, request []byte) bool {
				p := wire.PacketCodec(request)
				var response wire.Packet
				status := erref.STATUS_SUCCESS
				switch p.Command() {
				case wire.SMB2_WRITE:
					writes.Add(1)
					if test.writeFailure {
						status = erref.STATUS_ACCESS_DENIED
					} else {
						r := wire.WriteRequestDecoder(request[64:])
						require.False(t, r.IsInvalid())
						response = &wire.WriteResponse{Count: r.Length()}
					}
				case wire.SMB2_CLOSE:
					closes.Add(1)
					if test.closeFailure {
						status = erref.STATUS_UNSUCCESSFUL
					} else {
						response = &wire.CloseResponse{}
					}
				default:
					return false
				}
				if response == nil {
					response = &wire.ErrorResponse{CommandCode: p.Command()}
				}
				data := make([]byte, response.Size())
				response.Encode(data)
				out := wire.PacketCodec(data)
				out.SetMessageId(p.MessageId())
				out.SetSessionId(p.SessionId())
				out.SetTreeId(p.TreeId())
				out.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				out.SetCreditResponse(1)
				out.SetStatus(uint32(status))
				require.NoError(t, writeClientTestPacket(conn, data))
				return true
			}
			dialer := newClientTestDialer(&clientTestCredentials{}, ep)
			dialer.DisableAAPLExtension = true
			dialer.IOPipelineDepth = 1
			d := New(dialer)
			defer d.Close()
			const name = `\\server\share\dir\file`
			err := d.WriteFile(context.Background(), name, make([]byte, (64<<10)+1), 0600)
			require.Positive(t, closes.Load(), "cleanup CLOSE must run even after WRITE fails")
			if !test.writeFailure && !test.closeFailure {
				require.NoError(t, err)
				require.EqualValues(t, 2, writes.Load())
				return
			}
			var outer *os.PathError
			require.ErrorAs(t, err, &outer)
			require.Equal(t, "writefile", outer.Op)
			require.Equal(t, name, outer.Path)
			joined, ok := outer.Err.(interface{ Unwrap() []error })
			require.True(t, ok, "preserve the separate operation errors in the join")
			branches := joined.Unwrap()
			wantOps := []string{}
			if test.writeFailure {
				wantOps = append(wantOps, "write")
				require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
				require.ErrorIs(t, err, os.ErrPermission)
			}
			if test.closeFailure {
				wantOps = append(wantOps, "close")
				require.ErrorIs(t, err, erref.STATUS_UNSUCCESSFUL)
			}
			require.Len(t, branches, len(wantOps))
			for i, branch := range branches {
				var pathErr *os.PathError
				require.ErrorAs(t, branch, &pathErr)
				require.Equal(t, wantOps[i], pathErr.Op)
				require.Equal(t, name, pathErr.Path)
				_, nested := pathErr.Err.(*os.PathError)
				require.False(t, nested)
			}
			require.False(t, strings.Contains(err.Error(), `write dir\file:`), "diagnostics must not expose the resolved relative name")
			require.False(t, strings.Contains(err.Error(), `close dir\file:`))
			require.Equal(t, test.writeFailure, errors.Is(err, erref.STATUS_ACCESS_DENIED))
			require.Equal(t, test.closeFailure, errors.Is(err, erref.STATUS_UNSUCCESSFUL))
		})
	}
}

func TestWriteFileJoinErrorPreservesOtherErrors(t *testing.T) {
	opaque := errors.New("opaque error")
	otherPath := &os.PathError{Op: "stat", Path: "other", Err: os.ErrNotExist}
	for _, err := range []error{nil, os.ErrInvalid, opaque, otherPath, errors.Join(opaque, otherPath)} {
		require.True(t, writeFileJoinError(err, "UNC") == err, "unrelated errors must retain identity")
	}
	write := &os.PathError{Op: "write", Path: "file", Err: context.Canceled}
	got := writeFileJoinError(errors.Join(write, otherPath, opaque), "UNC")
	require.ErrorIs(t, got, context.Canceled)
	require.ErrorIs(t, got, os.ErrNotExist)
	require.ErrorIs(t, got, opaque)
	branches := got.(interface{ Unwrap() []error }).Unwrap()
	require.Len(t, branches, 3)
	require.Equal(t, "UNC", branches[0].(*os.PathError).Path)
	require.Same(t, otherPath, branches[1])
	require.Same(t, opaque, branches[2])
	require.Equal(t, "file", write.Path, "do not modify the original operation error")
}
