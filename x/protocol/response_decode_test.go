package protocol

import (
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestResponseQueryInfoValidationBoundary(t *testing.T) {
	// A valid SMB envelope can contain an invalid information-class payload.
	response := &Response{rpkts: []*recvPacket{testAcceptedResponse(t, &wire.QueryInfoResponse{Output: rawEncoder{1}})}}
	defer response.Close()
	response.rpkts[0].payloadRequest = describePayloadRequest(&wire.QueryInfoRequest{InfoType: wire.SMB2_0_INFO_FILE, FileInfoClass: wire.FileStandardInformation})
	query, err := response.QueryInfo(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(query.Output()) != 1 {
		t.Fatal("lost query payload")
	}
	info := wire.FileStandardInformationDecoder(query.Output())
	if !info.IsInvalid() {
		t.Fatal("nested payload unexpectedly valid")
	}
	if _, err := query.FileStandardInformation(); err == nil {
		t.Fatal("typed accessor accepted malformed nested payload")
	}
	if _, err := response.Create(0); err == nil {
		t.Fatal("accepted wrong response command")
	}
}

func TestResponseTypedAccessRejectsUnavailablePackets(t *testing.T) {
	response := &Response{rpkts: []*recvPacket{testAcceptedResponse(t, &wire.WriteResponse{Count: 3})}}
	decoded, err := response.Write(0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Count() != 3 {
		t.Fatal("incorrect write count")
	}
	for _, index := range []int{-1, 1} {
		if _, err := response.Write(index); err == nil {
			t.Fatalf("accepted index %d", index)
		}
	}
	response.Close()
	if _, err := response.Write(0); err == nil {
		t.Fatal("accepted closed response")
	}
	var absent *Response
	if _, err := absent.Write(0); err == nil {
		t.Fatal("accepted nil response")
	}
}

func TestResponseTypedAccessRejectsMalformedEnvelope(t *testing.T) {
	packet := testAcceptedResponse(t, &wire.WriteResponse{Count: 3})
	packet.pkt = packet.pkt[:65]
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	if _, err := response.Write(0); err == nil {
		t.Fatal("accepted truncated WRITE")
	}
	packet.pkt = packet.pkt[:1]
	if _, err := response.Header(0); err == nil {
		t.Fatal("accepted truncated header")
	}
}

func TestResponseReadSeparatesDirectPayload(t *testing.T) {
	packet := testAcceptedResponse(t, &wire.ReadResponse{Data: []byte("read")})
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	read, err := response.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data()) != "read" {
		t.Fatal("incorrect read payload")
	}
	packet.ext = packet.pkt[80:]
	packet.pkt = packet.pkt[:80]
	if _, err := response.Read(0); err == nil {
		t.Fatal("returned contiguous decoder for direct READ")
	}
	if string(response.DirectData(0)) != "read" {
		t.Fatal("lost direct payload")
	}
}
