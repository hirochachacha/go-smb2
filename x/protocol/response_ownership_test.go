package protocol

import "testing"

func TestClosedResponseCopyDoesNotCloseLaterResponse(t *testing.T) {
	first := &Response{rpkts: []*recvPacket{allocRecvPacket(64)}}
	copyOfFirst := *first
	first.Close()

	later := &Response{rpkts: []*recvPacket{allocRecvPacket(64)}}
	defer later.Close()
	copyOfFirst.Close()
	if len(later.Bytes(0)) != 64 {
		t.Fatal("closing a copy of an old response closed a later response")
	}
}
