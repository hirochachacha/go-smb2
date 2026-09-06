package msrpc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNDR_PrimitivesAndAlignment(t *testing.T) {
	enc := NewEncoder()
	enc.WriteUint8(0x42)
	enc.WriteUint16(0x1234)
	enc.WriteUint8(0x55)
	enc.WriteUint32(0xabcdef01)
	enc.WriteConformantVaryingString("hello")

	dec := NewDecoder(enc.Bytes())
	u8, err := dec.ReadUint8()
	if err != nil || u8 != 0x42 {
		t.Fatalf("unexpected u8: %x, err: %v", u8, err)
	}
	u16, err := dec.ReadUint16()
	if err != nil || u16 != 0x1234 {
		t.Fatalf("unexpected u16: %x, err: %v", u16, err)
	}
	u8_2, err := dec.ReadUint8()
	if err != nil || u8_2 != 0x55 {
		t.Fatalf("unexpected u8_2: %x, err: %v", u8_2, err)
	}
	u32, err := dec.ReadUint32()
	if err != nil || u32 != 0xabcdef01 {
		t.Fatalf("unexpected u32: %x, err: %v", u32, err)
	}
	str, err := dec.ReadConformantVaryingString()
	if err != nil || str != "hello" {
		t.Fatalf("unexpected string: %q, err: %v", str, err)
	}
}

func TestBind_Encode(t *testing.T) {
	req := &Bind{CallId: 100}
	if req.Size() != 72 {
		t.Fatalf("expected size 72, got %d", req.Size())
	}

	buf := make([]byte, req.Size())
	req.Encode(buf)

	if buf[0] != RPC_VERSION || buf[1] != RPC_VERSION_MINOR {
		t.Fatalf("invalid rpc version")
	}
	if buf[2] != RPC_TYPE_BIND {
		t.Fatalf("invalid packet type: %d", buf[2])
	}
	if le.Uint16(buf[8:10]) != 72 {
		t.Fatalf("invalid frag length: %d", le.Uint16(buf[8:10]))
	}
	if le.Uint32(buf[12:16]) != 100 {
		t.Fatalf("invalid call id: %d", le.Uint32(buf[12:16]))
	}

	// Verify srvsvc UUID
	var expectedSrvSvc [16]byte
	hex.Decode(expectedSrvSvc[:], SRVSVC_UUID)
	if !bytes.Equal(buf[32:48], expectedSrvSvc[:]) {
		t.Fatalf("srvsvc UUID mismatch")
	}

	// Verify NDR UUID
	var expectedNDR [16]byte
	hex.Decode(expectedNDR[:], NDR_UUID)
	if !bytes.Equal(buf[52:68], expectedNDR[:]) {
		t.Fatalf("NDR UUID mismatch")
	}
}

func TestBindAck_Decoder(t *testing.T) {
	validAck := make([]byte, 24)
	encodeCommonHeader(validAck, RPC_TYPE_BIND_ACK, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, 24, 0, 42)

	dec := BindAckDecoder(validAck)
	if dec.IsInvalid() {
		t.Fatalf("expected valid bind ack")
	}
	if dec.CallId() != 42 {
		t.Fatalf("expected call id 42, got %d", dec.CallId())
	}

	// Invalid short
	if !BindAckDecoder(validAck[:20]).IsInvalid() {
		t.Fatalf("expected short buffer to be invalid")
	}
	// Invalid packet type
	validAck[2] = RPC_TYPE_RESPONSE
	if !BindAckDecoder(validAck).IsInvalid() {
		t.Fatalf("expected wrong packet type to be invalid")
	}
}

func TestNetShareEnumAllRequest_Encode(t *testing.T) {
	req := &NetShareEnumAllRequest{
		CallId:     1,
		ServerName: "myserver",
		Level:      1,
	}

	buf := make([]byte, req.Size())
	req.Encode(buf)

	if buf[0] != RPC_VERSION || buf[1] != RPC_VERSION_MINOR {
		t.Fatalf("invalid rpc version")
	}
	if buf[2] != RPC_TYPE_REQUEST {
		t.Fatalf("invalid packet type: %d", buf[2])
	}
	if le.Uint32(buf[12:16]) != 1 {
		t.Fatalf("invalid call id")
	}
	if le.Uint16(buf[22:24]) != OP_NET_SHARE_ENUM {
		t.Fatalf("invalid opnum: %d", le.Uint16(buf[22:24]))
	}

	// Stub starts at offset 24
	stub := buf[24:]
	dec := NewDecoder(stub)
	refID, err := dec.ReadUint32()
	if err != nil || refID == 0 {
		t.Fatalf("invalid referent id for server unc")
	}
	serverName, err := dec.ReadConformantVaryingString()
	if err != nil || serverName != "myserver" {
		t.Fatalf("unexpected server unc string: %q, err: %v", serverName, err)
	}

	level, err := dec.ReadUint32()
	if err != nil || level != 1 {
		t.Fatalf("unexpected level: %d", level)
	}
}

func TestNetShareEnumAllResponse_Level1(t *testing.T) {
	// Build a valid MS-SRVS NetrShareEnum Level 1 response stub
	enc := NewEncoder()
	// InfoStruct: Level (1), switch_is(Level) (1), ctr pointer (0x20004)
	enc.WriteUint32(1)
	enc.WriteUint32(1)
	enc.WriteUint32(0x20004)

	// Container: EntriesRead = 2, Buffer pointer (0x20008)
	enc.WriteUint32(2)
	enc.WriteUint32(0x20008)

	// Array MaxCount = 2
	enc.WriteUint32(2)

	// Inline entries (2 entries):
	// Entry 0: name ptr = 0x2000c, type = 0, remark ptr = 0x20010
	enc.WriteUint32(0x2000c)
	enc.WriteUint32(0)
	enc.WriteUint32(0x20010)
	// Entry 1: name ptr = 0x20014, type = 0x80000000, remark ptr = 0 (NULL)
	enc.WriteUint32(0x20014)
	enc.WriteUint32(0x80000000)
	enc.WriteUint32(0)

	// Deferred strings:
	// Entry 0 name: "IPC$"
	enc.WriteConformantVaryingString("IPC$")
	// Entry 0 remark: "Remote IPC"
	enc.WriteConformantVaryingString("Remote IPC")
	// Entry 1 name: "share1"
	enc.WriteConformantVaryingString("share1")

	// Trailing parameters:
	enc.WriteUint32(2) // TotalEntries
	enc.WriteUint32(0) // ResumeHandle (NULL)
	enc.WriteUint32(0) // ReturnStatus (NERR_Success)

	stub := enc.Bytes()
	totalLen := HeaderSize + len(stub)

	pdu := make([]byte, totalLen)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(totalLen), 0, 77)
	copy(pdu[HeaderSize:], stub)

	resp := NetShareEnumAllResponseDecoder(pdu)
	if resp.IsInvalid() {
		t.Fatalf("expected valid response")
	}
	if resp.CallId() != 77 {
		t.Fatalf("expected call id 77, got %d", resp.CallId())
	}

	infos, err := resp.ShareInfos()
	if err != nil {
		t.Fatalf("expected complete response, got err: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(infos))
	}
	if infos[0].Name != "IPC$" || infos[0].Comment != "Remote IPC" || infos[0].Type != 0 {
		t.Fatalf("unexpected share[0]: %+v", infos[0])
	}
	if infos[1].Name != "share1" || infos[1].Comment != "" || infos[1].Type != 0x80000000 {
		t.Fatalf("unexpected share[1]: %+v", infos[1])
	}

	names, err := resp.Sharenames()
	if err != nil {
		t.Fatalf("expected complete response, got err: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "IPC$" || names[1] != "share1" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestNetShareEnumAllResponse_Level1_NullNamePtr(t *testing.T) {
	// Build a Level 1 response where an entry has a NULL netname pointer
	enc := NewEncoder()
	// InfoStruct: Level (1), switch_is(Level) (1), ctr pointer (0x20004)
	enc.WriteUint32(1)
	enc.WriteUint32(1)
	enc.WriteUint32(0x20004)

	// Container: EntriesRead = 2, Buffer pointer (0x20008)
	enc.WriteUint32(2)
	enc.WriteUint32(0x20008)

	// Array MaxCount = 2
	enc.WriteUint32(2)

	// Inline entries (2 entries):
	// Entry 0: name ptr = 0x2000c, type = 0, remark ptr = 0x20010
	enc.WriteUint32(0x2000c)
	enc.WriteUint32(0)
	enc.WriteUint32(0x20010)
	// Entry 1: name ptr = 0 (NULL), type = 1, remark ptr = 0x20014
	enc.WriteUint32(0)
	enc.WriteUint32(1)
	enc.WriteUint32(0x20014)

	// Deferred strings:
	// Entry 0 name: "IPC$"
	enc.WriteConformantVaryingString("IPC$")
	// Entry 0 remark: "Remote IPC"
	enc.WriteConformantVaryingString("Remote IPC")
	// Entry 1 name: NULL pointer, no string data
	// Entry 1 remark: "comment"
	enc.WriteConformantVaryingString("comment")

	// Trailing parameters:
	enc.WriteUint32(2) // TotalEntries
	enc.WriteUint32(0) // ResumeHandle (NULL)
	enc.WriteUint32(0) // ReturnStatus (NERR_Success)

	stub := enc.Bytes()
	totalLen := HeaderSize + len(stub)

	pdu := make([]byte, totalLen)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(totalLen), 0, 99)
	copy(pdu[HeaderSize:], stub)

	resp := NetShareEnumAllResponseDecoder(pdu)
	if resp.IsInvalid() {
		t.Fatalf("expected valid response")
	}

	infos, err := resp.ShareInfos()
	if err != nil {
		t.Fatalf("expected complete response, got err: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(infos))
	}
	if infos[0].Name != "IPC$" || infos[0].Comment != "Remote IPC" || infos[0].Type != 0 {
		t.Fatalf("unexpected share[0]: %+v", infos[0])
	}
	// NULL netname pointer must be decoded as an empty name without
	// consuming the bytes of the following remark string.
	if infos[1].Name != "" || infos[1].Comment != "comment" || infos[1].Type != 1 {
		t.Fatalf("unexpected share[1]: %+v", infos[1])
	}
}

func TestNetShareEnumAllResponse_Level0(t *testing.T) {
	enc := NewEncoder()
	enc.WriteUint32(0) // Level 0
	enc.WriteUint32(0) // switch
	enc.WriteUint32(0x20004)
	enc.WriteUint32(1) // EntriesRead = 1
	enc.WriteUint32(0x20008)
	enc.WriteUint32(1) // Array MaxCount = 1

	// Inline: name ptr = 0x2000c
	enc.WriteUint32(0x2000c)

	// Deferred string
	enc.WriteConformantVaryingString("PUBLIC")

	stub := enc.Bytes()
	totalLen := HeaderSize + len(stub)

	pdu := make([]byte, totalLen)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(totalLen), 0, 88)
	copy(pdu[HeaderSize:], stub)

	resp := NetShareEnumAllResponseDecoder(pdu)
	if resp.IsInvalid() {
		t.Fatalf("expected valid response")
	}

	names, err := resp.Sharenames()
	if err != nil {
		t.Fatalf("expected valid response, got err: %v", err)
	}
	if len(names) != 1 || names[0] != "PUBLIC" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestNetShareEnumAllResponse_TruncatedAndInvalid(t *testing.T) {
	// PDU shorter than header
	shortPDU := make([]byte, 10)
	if !NetShareEnumAllResponseDecoder(shortPDU).IsInvalid() {
		t.Fatalf("expected short pdu to be invalid")
	}

	// PDU with truncated string data
	enc := NewEncoder()
	enc.WriteUint32(1) // Level 1
	enc.WriteUint32(1)
	enc.WriteUint32(0x20004)
	enc.WriteUint32(1) // 1 entry
	enc.WriteUint32(0x20008)
	enc.WriteUint32(1)
	enc.WriteUint32(0x2000c) // name ptr
	enc.WriteUint32(0)       // type
	enc.WriteUint32(0)       // remark ptr
	// string header but truncated body
	enc.WriteUint32(10) // max count
	enc.WriteUint32(0)  // offset
	enc.WriteUint32(10) // actual count (requires 20 bytes body)
	// only write 4 bytes instead of 20
	enc.WriteBytes([]byte{0x41, 0x00, 0x42, 0x00})

	stub := enc.Bytes()
	totalLen := HeaderSize + len(stub)
	pdu := make([]byte, totalLen)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(totalLen), 0, 1)
	copy(pdu[HeaderSize:], stub)

	resp := NetShareEnumAllResponseDecoder(pdu)
	if resp.IsInvalid() {
		t.Fatalf("pdu header itself should be valid")
	}
	if _, err := resp.Sharenames(); err == nil {
		t.Fatalf("expected truncated string body to return error")
	}
}
