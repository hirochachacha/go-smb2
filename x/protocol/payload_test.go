package protocol

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestPayloadRequestSurvivesBuilderReuse(t *testing.T) {
	tree, peer := newTestTree(t)
	transport := NewTransport(peer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		request, err := readMsg(transport)
		if err != nil {
			return
		}
		sendTestResponse(transport, request, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 40))}, 0)
	}()
	request := tree.Request().WithFileID(&wire.FileId{}).QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 40)
	response, err := request.Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	<-done
	request.Get(0).(*wire.QueryInfoRequest).FileInfoClass = wire.FileBasicInformation
	query, err := response.QueryInfo(0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := query.FileStandardInformation()
	if err != nil {
		t.Fatal(err)
	}
	if info.EndOfFile() != 0 {
		t.Fatal("incorrect standard information")
	}
	if _, err := query.FileBasicInformation(); err == nil {
		t.Fatal("accepted a different request class")
	}
}

func TestDirectoryPayloadRejectsMalformedLaterEntry(t *testing.T) {
	// The first entry is valid; the truncated second entry must prevent any
	// partial results from being returned to the caller.
	output := make([]byte, 113)
	binary.LittleEndian.PutUint32(output[0:4], 112)
	binary.LittleEndian.PutUint32(output[60:64], 2)
	output[104] = 'a'
	packet := testAcceptedResponse(t, &wire.QueryDirectoryResponse{Output: rawEncoder(output)})
	packet.payloadRequest = describePayloadRequest(&wire.QueryDirectoryRequest{FileInfoClass: wire.FileIdBothDirectoryInformation})
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	directory, err := response.QueryDir(0)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := directory.FileIdBothDirectoryInformation()
	if err == nil || entries != nil {
		t.Fatal("accepted partial malformed directory listing")
	}
}

func TestIoctlPayloadChecksRequestAndResponseCodes(t *testing.T) {
	payload := &wire.SrvRequestResumeKeyResponse{}
	packet := testAcceptedResponse(t, &wire.IoctlResponse{CtlCode: wire.FSCTL_SRV_REQUEST_RESUME_KEY, FileId: &wire.FileId{}, Output: payload})
	packet.payloadRequest = describePayloadRequest(&wire.IoctlRequest{CtlCode: wire.FSCTL_SRV_REQUEST_RESUME_KEY})
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	ioctl, err := response.Ioctl(0)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ioctl.SrvRequestResumeKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key.ResumeKey()) != 24 {
		t.Fatal("incorrect resume key")
	}
	if _, err := ioctl.SrvCopychunk(); err == nil {
		t.Fatal("accepted incorrect payload type")
	}
	packet.payloadRequest.ctlCode = wire.FSCTL_SRV_COPYCHUNK
	if _, err := response.Ioctl(0); err == nil {
		t.Fatal("accepted mismatched control code")
	}
}

func TestUnknownPayloadRemainsRaw(t *testing.T) {
	packet := testAcceptedResponse(t, &wire.QueryInfoResponse{Output: rawEncoder{1}})
	packet.payloadRequest = describePayloadRequest(&wire.QueryInfoRequest{InfoType: 255, FileInfoClass: 255})
	response := &Response{rpkts: []*recvPacket{packet}}
	defer response.Close()
	query, err := response.QueryInfo(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(query.RawOutput()) != 1 {
		t.Fatal("raw output unavailable")
	}
	if _, err := query.FileStandardInformation(); err == nil {
		t.Fatal("typed accessor accepted unknown class")
	}
}
