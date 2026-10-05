package protocol

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func testAcceptedResponse(t *testing.T, p wire.Packet) *recvPacket {
	t.Helper()
	buf := make([]byte, p.Size())
	p.Encode(buf)
	c := wire.PacketCodec(buf)
	c.SetStatus(uint32(erref.STATUS_SUCCESS))
	c.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	return &recvPacket{pkt: buf}
}

func TestAcceptRequestRejectsReadBeyondRequest(t *testing.T) {
	t.Parallel()
	response := testAcceptedResponse(t, &wire.ReadResponse{Data: make([]byte, 8)})
	rr := &outstandingRequest{
		cmd:             wire.SMB2_READ,
		expectedRead:    4,
		hasExpectedRead: true,
	}
	defer response.close()

	_, err := acceptRequest(rr, response, wire.SMB311)
	if err == nil {
		t.Fatal("acceptRequest accepted a READ response larger than requested")
	}
	if _, ok := err.(*InvalidResponseError); !ok {
		t.Fatalf("error type = %T, want *InvalidResponseError", err)
	}
}

func TestAcceptRequestRejectsWriteBeyondRequest(t *testing.T) {
	t.Parallel()
	response := testAcceptedResponse(t, &wire.WriteResponse{Count: 8})
	rr := &outstandingRequest{
		cmd:              wire.SMB2_WRITE,
		expectedWrite:    4,
		hasExpectedWrite: true,
	}
	defer response.close()

	_, err := acceptRequest(rr, response, wire.SMB311)
	if err == nil {
		t.Fatal("acceptRequest accepted a WRITE response larger than requested")
	}
	if _, ok := err.(*InvalidResponseError); !ok {
		t.Fatalf("error type = %T, want *InvalidResponseError", err)
	}
}

func TestAcceptRequestRejectsMalformedSuccessResponse(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 64+4)
	codec := wire.PacketCodec(buf)
	codec.SetCommand(wire.SMB2_FLUSH)
	codec.SetStatus(uint32(erref.STATUS_SUCCESS))
	codec.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	// The fixed body is intentionally truncated and has no valid structure size.
	rr := &outstandingRequest{cmd: wire.SMB2_FLUSH}
	rp := &recvPacket{pkt: buf}
	defer rp.close()

	_, err := acceptRequest(rr, rp, wire.SMB311)
	if err == nil {
		t.Fatal("acceptRequest accepted a malformed FLUSH response")
	}
	if _, ok := err.(*InvalidResponseError); !ok {
		t.Fatalf("error type = %T, want *InvalidResponseError", err)
	}
}

func TestAcceptRequestRejectsMalformedNegotiateResponse(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 64+4)
	codec := wire.PacketCodec(buf)
	codec.SetCommand(wire.SMB2_NEGOTIATE)
	codec.SetStatus(uint32(erref.STATUS_SUCCESS))
	codec.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	rr := &outstandingRequest{cmd: wire.SMB2_NEGOTIATE}
	rp := &recvPacket{pkt: buf}
	defer rp.close()

	_, err := acceptRequest(rr, rp, wire.SMB311)
	if err == nil {
		t.Fatal("acceptRequest accepted a malformed NEGOTIATE response")
	}
	var ire *InvalidResponseError
	if !errors.As(err, &ire) {
		t.Fatalf("error type = %T, want *InvalidResponseError", err)
	}
	if got, want := ire.Message, "broken negotiate response format"; got != want {
		t.Fatalf("error message = %q, want %q", got, want)
	}
}

func TestInvalidResponseErrorCommandContext(t *testing.T) {
	t.Parallel()
	message := "broken response format"

	unknown := &InvalidResponseError{Message: message}
	if got, want := unknown.Error(), "protocol: invalid response: "+message; got != want {
		t.Fatalf("unknown command error = %q, want %q", got, want)
	}

	negotiate := invalidResponse(wire.SMB2_NEGOTIATE, message)
	if negotiate.Command == nil {
		t.Fatal("NEGOTIATE command was lost")
	}
	if got, want := negotiate.Error(), "protocol: invalid SMB2_NEGOTIATE response: "+message; got != want {
		t.Fatalf("NEGOTIATE error = %q, want %q", got, want)
	}

	attached := withResponseCommand(unknown, wire.SMB2_READ)
	if attached == unknown {
		t.Fatal("withResponseCommand reused an unknown-command error")
	}
	if got, want := attached.Error(), "protocol: invalid SMB2_READ response: "+message; got != want {
		t.Fatalf("attached error = %q, want %q", got, want)
	}
	if unknown.Command != nil {
		t.Fatal("withResponseCommand mutated the original error")
	}

	known := invalidResponse(wire.SMB2_WRITE, message)
	if got := withResponseCommand(known, wire.SMB2_READ); got != known {
		t.Fatal("withResponseCommand replaced an already-scoped error")
	}
	wrapped := fmt.Errorf("wrapped: %w", unknown)
	if got := withResponseCommand(wrapped, wire.SMB2_READ); got != wrapped {
		t.Fatal("withResponseCommand changed a wrapped error")
	}
}

func TestAcceptResponseErrorsKeepExpectedCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		call func(*recvPacket) error
	}{
		{
			name: "accept",
			call: func(rp *recvPacket) error {
				_, err := accept(wire.SMB2_READ, rp, wire.SMB311)
				return err
			},
		},
		{
			name: "acceptRequest",
			call: func(rp *recvPacket) error {
				_, err := acceptRequest(&outstandingRequest{cmd: wire.SMB2_READ}, rp, wire.SMB311)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := encodedResponse(t, &wire.EchoResponse{})
			err := test.call(response)
			assertInvalidResponseCommand(t, err, wire.SMB2_READ,
				"protocol: invalid SMB2_READ response: expected command: SMB2_READ, got SMB2_ECHO")
		})
	}
}

func TestAcceptMalformedErrorResponseKeepsExpectedCommand(t *testing.T) {
	t.Parallel()
	response := encodedResponse(t, &wire.ErrorResponse{})
	response.pkt = response.pkt[:64+7]
	codec := response.codec()
	codec.SetCommand(wire.SMB2_READ)
	codec.SetStatus(uint32(erref.STATUS_INVALID_PARAMETER))

	_, err := accept(wire.SMB2_READ, response, wire.SMB311)
	assertInvalidResponseCommand(t, err, wire.SMB2_READ,
		"protocol: invalid SMB2_READ response: broken error response format")
}

func TestAcceptMalformedTypedPayloadKeepsExpectedCommand(t *testing.T) {
	t.Parallel()
	response := encodedResponse(t, &wire.EchoResponse{})
	response.pkt = response.pkt[:len(response.pkt)-1]

	_, err := accept(wire.SMB2_ECHO, response, wire.SMB311)
	assertInvalidResponseCommand(t, err, wire.SMB2_ECHO,
		"protocol: invalid SMB2_ECHO response: broken SMB2_ECHO response format")
}

func TestUnknownTransformErrorHasNoCommand(t *testing.T) {
	t.Parallel()
	_, _, err := decompressPacketForReceive(&conn{}, []byte("not a transform"), nil)
	var invalid *InvalidResponseError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v (%T), want *InvalidResponseError", err, err)
	}
	if invalid.Command != nil {
		t.Fatalf("transform error command = %s, want unknown", *invalid.Command)
	}
	if got, want := invalid.Error(), "protocol: invalid response: compression was not negotiated"; got != want {
		t.Fatalf("transform error = %q, want %q", got, want)
	}
}

func encodedResponse(t *testing.T, packet wire.Packet) *recvPacket {
	t.Helper()
	buf := make([]byte, packet.Size())
	packet.Encode(buf)
	return &recvPacket{pkt: buf}
}

func assertInvalidResponseCommand(t *testing.T, err error, command wire.Command, want string) {
	t.Helper()
	var invalid *InvalidResponseError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v (%T), want *InvalidResponseError", err, err)
	}
	if invalid.Command == nil {
		t.Fatal("invalid response command is nil")
	}
	if *invalid.Command != command {
		t.Fatalf("invalid response command = %s, want %s", *invalid.Command, command)
	}
	if got := invalid.Error(); got != want {
		t.Fatalf("invalid response error = %q, want %q", got, want)
	}
}

func TestRequestedOutputLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		request  wire.Packet
		response wire.Packet
		status   erref.NtStatus
		invalid  bool
	}{
		{"ioctl input exceeds limit", &wire.IoctlRequest{MaxInputResponse: 4}, &wire.IoctlResponse{FileId: wire.FileId{}, Input: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, true},
		{"ioctl input warning exceeds limit", &wire.IoctlRequest{MaxInputResponse: 4}, &wire.IoctlResponse{FileId: wire.FileId{}, Input: rawEncoder(make([]byte, 8))}, erref.STATUS_BUFFER_OVERFLOW, true},
		{"ioctl input exact limit", &wire.IoctlRequest{MaxInputResponse: 8}, &wire.IoctlResponse{FileId: wire.FileId{}, Input: rawEncoder(make([]byte, 8))}, erref.STATUS_SUCCESS, false},
		{"ioctl input zero limit", &wire.IoctlRequest{}, &wire.IoctlResponse{FileId: wire.FileId{}, Input: rawEncoder(make([]byte, 1))}, erref.STATUS_SUCCESS, true},
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
	t.Parallel()
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
	t.Parallel()
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

type customIoctl struct{ *wire.IoctlRequest }

func TestCustomIoctlResponseValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		code          uint32
		input, output int
		invalid       bool
	}{
		{"matching limits", wire.FSCTL_GET_REPARSE_POINT, 4, 8, false},
		{"wrong control code", wire.FSCTL_PIPE_TRANSCEIVE, 0, 0, true},
		{"oversized input", wire.FSCTL_GET_REPARSE_POINT, 5, 0, true},
		{"oversized output", wire.FSCTL_GET_REPARSE_POINT, 0, 9, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &customIoctl{&wire.IoctlRequest{CtlCode: wire.FSCTL_GET_REPARSE_POINT, MaxInputResponse: 4, MaxOutputResponse: 8}}
			c := &conn{outstandingRequests: newOutstandingRequests()}
			rrs, _, err := c.makeOutstandingRequest(context.Background(), false, []uint64{1}, req)
			if err != nil {
				t.Fatal(err)
			}
			req.CtlCode = wire.FSCTL_PIPE_TRANSCEIVE
			req.MaxInputResponse, req.MaxOutputResponse = 99, 99
			packet := testAcceptedResponse(t, &wire.IoctlResponse{CtlCode: tc.code, Input: rawEncoder(make([]byte, tc.input)), Output: rawEncoder(make([]byte, tc.output))})
			accepted, err := acceptRequest(rrs[0], packet, wire.SMB311)
			if accepted != nil {
				response := &Response{rpkts: []*recvPacket{accepted}}
				defer response.Close()
				_, err = response.Ioctl(0)
			}
			var invalid *InvalidResponseError
			if errors.As(err, &invalid) != tc.invalid {
				t.Fatalf("invalid=%v, error=%v", tc.invalid, err)
			}
		})
	}
}

type customQueryInfo struct{ *wire.QueryInfoRequest }

type customQueryDirectory struct{ *wire.QueryDirectoryRequest }

func TestCustomQueryOutputLimits(t *testing.T) {
	t.Parallel()
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
