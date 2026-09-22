package protocol

import (
	"context"
	"errors"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestRequestedOutputLimits(t *testing.T) {
	for _, test := range []struct {
		name     string
		request  wire.Packet
		response wire.Packet
		status   erref.NtStatus
		invalid  bool
	}{
		{"ioctl success exceeds limit", &wire.IoctlRequest{MaxOutputResponse: 4}, &wire.IoctlResponse{FileId: wire.FileId{}, Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"ioctl warning exceeds limit", &wire.IoctlRequest{MaxOutputResponse: 4}, &wire.IoctlResponse{FileId: wire.FileId{}, Output: rawEncoder(make([]byte, 8))}, erref.STATUS_BUFFER_OVERFLOW, true},
		{"ioctl exact limit", &wire.IoctlRequest{MaxOutputResponse: 8}, &wire.IoctlResponse{FileId: wire.FileId{}, Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, false},
		{"ioctl error body", &wire.IoctlRequest{MaxOutputResponse: 4}, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, erref.STATUS_BUFFER_OVERFLOW, false},
		{"query info exceeds limit", &wire.QueryInfoRequest{OutputBufferLength: 4}, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"query info warning exceeds limit", &wire.QueryInfoRequest{OutputBufferLength: 4}, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_BUFFER_OVERFLOW, true},
		{"query info exact limit", &wire.QueryInfoRequest{OutputBufferLength: 8}, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, false},
		{"query info zero limit", &wire.QueryInfoRequest{}, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"query info error envelope", &wire.QueryInfoRequest{}, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_INFO}, erref.STATUS_BUFFER_OVERFLOW, false},
		{"query directory exceeds limit", &wire.QueryDirectoryRequest{OutputBufferLength: 4}, &wire.QueryDirectoryResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"query directory exact limit", &wire.QueryDirectoryRequest{OutputBufferLength: 8}, &wire.QueryDirectoryResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, false},
		{"query directory zero limit", &wire.QueryDirectoryRequest{}, &wire.QueryDirectoryResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"notify exceeds limit", &wire.ChangeNotifyRequest{OutputBufferLength: 4}, &wire.ChangeNotifyResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"notify enum has output", &wire.ChangeNotifyRequest{OutputBufferLength: 8}, &wire.ChangeNotifyResponse{Output: rawEncoder(make([]byte, 8))}, erref.STATUS_NOTIFY_ENUM_DIR, true},
		{"notify enum empty", &wire.ChangeNotifyRequest{OutputBufferLength: 8}, &wire.ChangeNotifyResponse{}, erref.STATUS_NOTIFY_ENUM_DIR, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := testAcceptedResponse(t, test.response)
			packet.codec().SetStatus(uint32(test.status))
			rr := &outstandingRequest{cmd: test.request.Command(), payloadRequest: describePayloadRequest(test.request)}
			response, err := acceptRequest(rr, packet, wire.SMB311)
			if response != nil {
				defer response.close()
			}
			var invalid *InvalidResponseError
			if errors.As(err, &invalid) != test.invalid {
				t.Fatalf("invalid=%v, error=%v", test.invalid, err)
			}
			if !test.invalid {
				if test.status == erref.STATUS_BUFFER_OVERFLOW {
					if _, ok := errors.AsType[*ResponseError](err); !ok {
						t.Fatalf("lost server status: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCopyRequestedTotalDoesNotWrap(t *testing.T) {
	request := &wire.IoctlRequest{CtlCode: wire.FSCTL_SRV_COPYCHUNK, Input: &wire.SrvCopychunkCopy{Chunks: []wire.SrvCopychunk{{Length: 0xffffffff}, {Length: 1}}}}
	packet := testAcceptedResponse(t, &wire.IoctlResponse{CtlCode: request.CtlCode, FileId: wire.FileId{}, Output: &wire.SrvCopychunkResponse{}})
	packet.payloadRequest = describePayloadRequest(request)
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	ioctl, err := response.Ioctl(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ioctl.SrvCopychunk(); err == nil {
		t.Fatal("accepted wrapped requested total")
	}
}

func TestQueryOutputLimitSnapshot(t *testing.T) {
	for _, req := range []wire.Packet{&wire.QueryInfoRequest{OutputBufferLength: 4}, &wire.QueryDirectoryRequest{OutputBufferLength: 4}} {
		snapshot := describePayloadRequest(req)
		switch r := req.(type) {
		case *wire.QueryInfoRequest:
			r.OutputBufferLength = 8
		case *wire.QueryDirectoryRequest:
			r.OutputBufferLength = 8
		}
		if snapshot.maxOutput != 4 {
			t.Fatalf("snapshot changed: %d", snapshot.maxOutput)
		}
	}
}

type customQueryInfo struct{ *wire.QueryInfoRequest }
type customQueryDirectory struct{ *wire.QueryDirectoryRequest }

func TestCustomQueryOutputLimits(t *testing.T) {
	for _, req := range []wire.Packet{&customQueryInfo{&wire.QueryInfoRequest{OutputBufferLength: 8}}, &customQueryDirectory{&wire.QueryDirectoryRequest{OutputBufferLength: 8}}} {
		c := &conn{outstandingRequests: newOutstandingRequests()}
		rrs, _, err := c.makeOutstandingRequest(context.Background(), false, []uint64{1}, req)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{8, 9} {
			var res wire.Packet = &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, size))}
			if req.Command() == wire.SMB2_QUERY_DIRECTORY {
				res = &wire.QueryDirectoryResponse{Output: rawEncoder(make([]byte, size))}
			}
			rp, err := acceptRequest(rrs[0], testAcceptedResponse(t, res), wire.SMB311)
			if rp != nil {
				rp.close()
			}
			if (err != nil) != (size > 8) {
				t.Fatalf("size %d: %v", size, err)
			}
		}
	}
}
