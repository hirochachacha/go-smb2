package protocol

import (
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
