package protocol

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestInvalidResponseErrorCommandContext(t *testing.T) {
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
	response := encodedResponse(t, &wire.EchoResponse{})
	response.pkt = response.pkt[:len(response.pkt)-1]

	_, err := accept(wire.SMB2_ECHO, response, wire.SMB311)
	assertInvalidResponseCommand(t, err, wire.SMB2_ECHO,
		"protocol: invalid SMB2_ECHO response: broken SMB2_ECHO response format")
}

func TestUnknownTransformErrorHasNoCommand(t *testing.T) {
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
