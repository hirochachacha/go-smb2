package msrpc

import (
	"bytes"
	"encoding/hex"
	"errors"
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

func TestNDR_OverflowSafety(t *testing.T) {
	dec := NewDecoder(make([]byte, 16))
	_, _ = dec.ReadUint8() // off becomes 1

	// ReadBytes with math.MaxInt must not panic
	const maxInt = int(^uint(0) >> 1)
	_, err := dec.ReadBytes(maxInt)
	if err == nil {
		t.Fatal("expected error for ReadBytes(MaxInt), got nil")
	}

	// Negative length
	_, err = dec.ReadBytes(-1)
	if err == nil {
		t.Fatal("expected error for ReadBytes(-1), got nil")
	}

	// Align with large value
	err = dec.Align(maxInt)
	if err == nil {
		t.Fatal("expected error for Align(MaxInt), got nil")
	}
}

func TestBind_Encode(t *testing.T) {
	req := &Bind{CallId: 100, AbstractSyntax: SRVSVC_UUID, Version: SRVSVC_VERSION}
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
	if !bytes.Equal(buf[32:48], SRVSVC_UUID[:]) {
		t.Fatalf("srvsvc UUID mismatch")
	}

	// Verify NDR UUID
	if !bytes.Equal(buf[52:68], NDR_UUID[:]) {
		t.Fatalf("NDR UUID mismatch")
	}
}

func TestBindLSARPC(t *testing.T) {
	req := &Bind{CallId: 1, AbstractSyntax: LSARPC_UUID, Version: LSARPC_VERSION}
	buf := make([]byte, req.Size())
	req.Encode(buf)
	if !bytes.Equal(buf[32:48], LSARPC_UUID[:]) || le.Uint16(buf[48:50]) != 0 {
		t.Fatalf("LSARPC abstract syntax = %x", buf[32:52])
	}
}

func TestReadStubReturnsRPCFault(t *testing.T) {
	packet, err := hex.DecodeString("05000303100000002400000001000000040000000000000000000000000000000700001c")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadStub(packet, 1, 1024, nil)
	var fault *FaultError
	if !errors.As(err, &fault) || fault.Status != 0x1c000007 {
		t.Fatalf("fault = %v, want 0x1c000007", err)
	}
}

func TestBindAck_Decoder(t *testing.T) {
	// Independent wire fixture: empty sec_addr, one NDR v2 acceptance.
	validAck, err := hex.DecodeString("05000c0310000000380000002a000000b810b81000000000000000000100000000000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}
	if got := BindAckDecoder(validAck).CallId(); got != 42 {
		t.Fatalf("expected call id 42, got %d", got)
	}

	for _, tt := range []struct {
		name    string
		modify  func([]byte) []byte
		invalid bool
		accepts bool
	}{
		{name: "acceptance", accepts: true},
		{name: "wrong version", modify: func(b []byte) []byte { b[0]++; return b }, invalid: true},
		{name: "wrong minor version", modify: func(b []byte) []byte { b[1]++; return b }, invalid: true},
		{name: "wrong packet type", modify: func(b []byte) []byte { b[2] = RPC_TYPE_RESPONSE; return b }, invalid: true},
		{name: "big endian", modify: func(b []byte) []byte { b[4] = 0; return b }, invalid: true},
		{name: "missing first", modify: func(b []byte) []byte { b[3] = RPC_PACKET_FLAG_LAST; return b }, invalid: true},
		{name: "missing last", modify: func(b []byte) []byte { b[3] = RPC_PACKET_FLAG_FIRST; return b }, invalid: true},
		{name: "authentication", modify: func(b []byte) []byte { b[10] = 1; return b }, invalid: true},
		{name: "short fragment length", modify: func(b []byte) []byte { b[8]--; return b }, invalid: true},
		{name: "long fragment length", modify: func(b []byte) []byte { b[8]++; return b }, invalid: true},
		{name: "secondary address out of bounds", modify: func(b []byte) []byte { le.PutUint16(b[24:26], 0xffff); return b }, invalid: true},
		{name: "missing padding", modify: func(b []byte) []byte { b[8] = 27; b[24] = 1; return b[:27] }, invalid: true},
		{name: "trailing byte", modify: func(b []byte) []byte { b[8]++; return append(b, 0) }, invalid: true},
		{name: "incomplete results", modify: func(b []byte) []byte { b[28] = 2; return b }, invalid: true},
		{name: "maximum result count", modify: func(b []byte) []byte { b[28] = 255; return b }, invalid: true},
		{name: "zero results", modify: func(b []byte) []byte { b[28] = 0; b[8] = 32; return b[:32] }},
		{name: "two results", modify: func(b []byte) []byte { b[28] = 2; b[8] = 80; return append(b, b[32:56]...) }},
		{name: "user rejection", modify: func(b []byte) []byte { b[32] = 1; return b }},
		{name: "provider rejection", modify: func(b []byte) []byte { b[32] = 2; b[34] = 2; return b }},
		{name: "result high byte", modify: func(b []byte) []byte { b[33] = 1; return b }},
		{name: "different UUID", modify: func(b []byte) []byte { b[36]++; return b }},
		{name: "different version", modify: func(b []byte) []byte { b[52]++; return b }},
		{name: "version high byte", modify: func(b []byte) []byte { b[55] = 1; return b }},
		{name: "nonzero padding and reserved fields", modify: func(b []byte) []byte {
			b[26] = 0xff
			b[27] = 0xff
			b[29] = 1
			b[30] = 2
			b[31] = 3
			return b
		}, accepts: true},
		{name: "secondary address and alignment", modify: func(b []byte) []byte {
			ack := make([]byte, 60)
			copy(ack, b[:26])
			copy(ack[26:32], []byte{'1', '3', '5', 0, 0xaa, 0xbb})
			copy(ack[32:], b[28:])
			ack[24] = 4
			ack[8] = byte(len(ack))
			return ack
		}, accepts: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ack := append([]byte(nil), validAck...)
			if tt.modify != nil {
				ack = tt.modify(ack)
			}
			dec := BindAckDecoder(ack)
			if got := dec.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
			if got := dec.AcceptsNDR(); got != tt.accepts {
				t.Errorf("AcceptsNDR() = %v, want %v", got, tt.accepts)
			}
		})
	}

	// Every truncation must fail safely, including a matching fragment length.
	for length := range validAck {
		ack := append([]byte(nil), validAck[:length]...)
		if length >= 10 {
			le.PutUint16(ack[8:10], uint16(length))
		}
		dec := BindAckDecoder(ack)
		if !dec.IsInvalid() || dec.AcceptsNDR() {
			t.Errorf("accepted truncated bind ack of length %d", length)
		}
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

func TestNetShareEnumAllRequest_Encode_OversizedPanics(t *testing.T) {
	// ServerName with 33000 characters produces stub > 65535 bytes
	oversizedName := string(make([]byte, 33000))
	req := &NetShareEnumAllRequest{
		CallId:     1,
		ServerName: oversizedName,
		Level:      1,
	}

	buf := make([]byte, req.Size())
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected Encode to panic on oversized fragment length, but it did not")
		}
	}()
	req.Encode(buf)
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

	resp := NetShareEnumAllResponseDecoder(pdu[HeaderSize:])
	if ResponseFragmentDecoder(pdu).IsInvalid() {
		t.Fatalf("expected valid response")
	}
	if ResponseFragmentDecoder(pdu).Header().CallId() != 77 {
		t.Fatalf("expected call id 77, got %d", ResponseFragmentDecoder(pdu).Header().CallId())
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

	resp := NetShareEnumAllResponseDecoder(pdu[HeaderSize:])
	if ResponseFragmentDecoder(pdu).IsInvalid() {
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

func TestNetShareEnumAllResponse_Level1StringTermination(t *testing.T) {
	tests := []struct {
		name      string
		namePtr   uint32
		nameCount uint32
		nameBody  []byte
		wantName  string
		wantErr   bool
	}{
		{
			name:      "missing name terminator",
			namePtr:   0x2000c,
			nameCount: 1,
			nameBody:  []byte{0x41, 0x00},
			wantErr:   true,
		},
		{
			name:      "zero length non-NULL name",
			namePtr:   0x2000c,
			nameCount: 0,
			wantErr:   true,
		},
		{
			name:      "empty terminated name",
			namePtr:   0x2000c,
			nameCount: 1,
			nameBody:  []byte{0, 0},
			wantName:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncoder()
			enc.WriteUint32(1)       // Level
			enc.WriteUint32(1)       // switch
			enc.WriteUint32(0x20004) // container pointer
			enc.WriteUint32(1)       // EntriesRead
			enc.WriteUint32(0x20008) // Buffer
			enc.WriteUint32(1)       // Array MaxCount
			enc.WriteUint32(tt.namePtr)
			enc.WriteUint32(0)            // Type
			enc.WriteUint32(0)            // Comment pointer (NULL)
			enc.WriteUint32(tt.nameCount) // MaxCount
			enc.WriteUint32(0)            // Offset
			enc.WriteUint32(tt.nameCount) // ActualCount
			enc.WriteBytes(tt.nameBody)
			enc.WriteUint32(1) // TotalEntries
			enc.WriteUint32(0) // ResumeHandle (NULL)
			enc.WriteUint32(0) // ReturnStatus (NERR_Success)

			infos, err := NetShareEnumAllResponseDecoder(enc.Bytes()).ShareInfos()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ShareInfos() error = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(infos) != 1 || infos[0].Name != tt.wantName {
				t.Fatalf("unexpected infos: %+v", infos)
			}
		})
	}
}

func TestNetShareEnumAllResponse_Level1CommentRequiresTerminator(t *testing.T) {
	enc := NewEncoder()
	enc.WriteUint32(1)       // Level
	enc.WriteUint32(1)       // switch
	enc.WriteUint32(0x20004) // container pointer
	enc.WriteUint32(1)       // EntriesRead
	enc.WriteUint32(0x20008) // Buffer
	enc.WriteUint32(1)       // Array MaxCount
	enc.WriteUint32(0x2000c) // Name pointer
	enc.WriteUint32(0)       // Type
	enc.WriteUint32(0x20010) // Comment pointer
	enc.WriteConformantVaryingString("share")
	enc.WriteUint32(1) // Comment MaxCount
	enc.WriteUint32(0) // Comment Offset
	enc.WriteUint32(1) // Comment ActualCount
	enc.WriteUint16('A')
	enc.WriteUint32(1) // TotalEntries
	enc.WriteUint32(0) // ResumeHandle (NULL)
	enc.WriteUint32(0) // ReturnStatus (NERR_Success)

	if _, err := NetShareEnumAllResponseDecoder(enc.Bytes()).ShareInfos(); err == nil {
		t.Fatal("expected unterminated comment to be rejected")
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

	// Trailing parameters.
	enc.WriteUint32(1) // TotalEntries
	enc.WriteUint32(0) // ResumeHandle (NULL)
	enc.WriteUint32(0) // ReturnStatus (NERR_Success)

	stub := enc.Bytes()
	totalLen := HeaderSize + len(stub)

	pdu := make([]byte, totalLen)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(totalLen), 0, 88)
	copy(pdu[HeaderSize:], stub)

	resp := NetShareEnumAllResponseDecoder(pdu[HeaderSize:])
	if ResponseFragmentDecoder(pdu).IsInvalid() {
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

func TestNetShareEnumAllResponse_Level0_NullNamePointers(t *testing.T) {
	enc := NewEncoder()
	enc.WriteUint32(0) // Level
	enc.WriteUint32(0) // switch
	enc.WriteUint32(0x20004)
	enc.WriteUint32(2)       // EntriesRead
	enc.WriteUint32(0x20008) // Buffer
	enc.WriteUint32(2)       // Array MaxCount
	enc.WriteUint32(0)       // Entry 0 name pointer (NULL)
	enc.WriteUint32(0x2000c) // Entry 1 name pointer
	enc.WriteConformantVaryingString("PUBLIC")
	enc.WriteUint32(2) // TotalEntries
	enc.WriteUint32(0) // ResumeHandle (NULL)
	enc.WriteUint32(0) // ReturnStatus (NERR_Success)

	pdu := make([]byte, HeaderSize+enc.Len())
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(len(pdu)), 0, 1)
	copy(pdu[HeaderSize:], enc.Bytes())

	names, err := NetShareEnumAllResponseDecoder(pdu[HeaderSize:]).Sharenames()
	if err != nil {
		t.Fatalf("expected valid response, got err: %v", err)
	}
	if len(names) != 2 || names[0] != "" || names[1] != "PUBLIC" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestNetShareEnumAllResponse_Level0_NullNamePointerRejectsReferent(t *testing.T) {
	enc := NewEncoder()
	enc.WriteUint32(0) // Level
	enc.WriteUint32(0) // switch
	enc.WriteUint32(0x20004)
	enc.WriteUint32(1)                         // EntriesRead
	enc.WriteUint32(0x20008)                   // Buffer
	enc.WriteUint32(1)                         // Array MaxCount
	enc.WriteUint32(0)                         // name pointer (NULL)
	enc.WriteConformantVaryingString("PUBLIC") // invalid referent for NULL pointer
	enc.WriteUint32(1)                         // TotalEntries
	enc.WriteUint32(0)                         // ResumeHandle (NULL)
	enc.WriteUint32(0)                         // ReturnStatus (NERR_Success)

	pdu := make([]byte, HeaderSize+enc.Len())
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(len(pdu)), 0, 1)
	copy(pdu[HeaderSize:], enc.Bytes())

	if _, err := NetShareEnumAllResponseDecoder(pdu[HeaderSize:]).Sharenames(); err == nil {
		t.Fatal("expected referent data for a NULL name pointer to be rejected")
	}
}

func TestNetShareEnumAllResponse_RequiresCompleteResponse(t *testing.T) {
	tests := []struct {
		name    string
		build   func(*Encoder)
		wantErr bool
	}{
		{
			name: "missing trailing parameters for empty response",
			build: func(enc *Encoder) {
				enc.WriteUint32(1)       // Level
				enc.WriteUint32(1)       // switch
				enc.WriteUint32(0x20004) // container pointer
				enc.WriteUint32(0)       // EntriesRead
				enc.WriteUint32(0)       // Buffer (NULL)
				enc.WriteUint32(0)       // incomplete trailing parameters
			},
			wantErr: true,
		},
		{
			name: "invalid level for empty response",
			build: func(enc *Encoder) {
				enc.WriteUint32(3) // unsupported Level
				enc.WriteUint32(3) // switch
				enc.WriteUint32(0x20004)
				enc.WriteUint32(0)
				enc.WriteUint32(0)
				enc.WriteUint32(0) // TotalEntries
				enc.WriteUint32(0) // ResumeHandle (NULL)
				enc.WriteUint32(0) // ReturnStatus
			},
			wantErr: true,
		},
		{
			name: "mismatched switch for empty response",
			build: func(enc *Encoder) {
				enc.WriteUint32(1) // Level
				enc.WriteUint32(0) // mismatched switch
				enc.WriteUint32(0x20004)
				enc.WriteUint32(0)
				enc.WriteUint32(0)
				enc.WriteUint32(0) // TotalEntries
				enc.WriteUint32(0) // ResumeHandle (NULL)
				enc.WriteUint32(0) // ReturnStatus
			},
			wantErr: true,
		},
		{
			name: "array max count differs from entries read",
			build: func(enc *Encoder) {
				enc.WriteUint32(0) // Level
				enc.WriteUint32(0) // switch
				enc.WriteUint32(0x20004)
				enc.WriteUint32(1)       // EntriesRead
				enc.WriteUint32(0x20008) // Buffer
				enc.WriteUint32(2)       // Array MaxCount
				enc.WriteUint32(0x2000c) // name pointer
				enc.WriteConformantVaryingString("PUBLIC")
				enc.WriteUint32(1) // TotalEntries
				enc.WriteUint32(0) // ResumeHandle (NULL)
				enc.WriteUint32(0) // ReturnStatus
			},
			wantErr: true,
		},
		{
			name: "failure return status",
			build: func(enc *Encoder) {
				enc.WriteUint32(1) // Level
				enc.WriteUint32(1) // switch
				enc.WriteUint32(0x20004)
				enc.WriteUint32(0)    // EntriesRead
				enc.WriteUint32(0)    // Buffer (NULL)
				enc.WriteUint32(0)    // TotalEntries
				enc.WriteUint32(0)    // ResumeHandle (NULL)
				enc.WriteUint32(0xEA) // ERROR_MORE_DATA
			},
			wantErr: true,
		},
		{
			name: "null buffer and resume handle",
			build: func(enc *Encoder) {
				enc.WriteUint32(1) // Level
				enc.WriteUint32(1) // switch
				enc.WriteUint32(0x20004)
				enc.WriteUint32(0) // EntriesRead
				enc.WriteUint32(0) // Buffer (NULL)
				enc.WriteUint32(0) // TotalEntries
				enc.WriteUint32(0) // ResumeHandle (NULL)
				enc.WriteUint32(0) // ReturnStatus
			},
			wantErr: false,
		},
		{
			name: "non-nil empty buffer",
			build: func(enc *Encoder) {
				enc.WriteUint32(1)       // Level
				enc.WriteUint32(1)       // switch
				enc.WriteUint32(0x20004) // container pointer
				enc.WriteUint32(0)       // EntriesRead
				enc.WriteUint32(0x20008) // Buffer
				enc.WriteUint32(0)       // Array MaxCount
				enc.WriteUint32(0)       // TotalEntries
				enc.WriteUint32(0)       // ResumeHandle (NULL)
				enc.WriteUint32(0)       // ReturnStatus
			},
			wantErr: false,
		},
		{
			name: "non-nil empty buffer with mismatched max count",
			build: func(enc *Encoder) {
				enc.WriteUint32(1)       // Level
				enc.WriteUint32(1)       // switch
				enc.WriteUint32(0x20004) // container pointer
				enc.WriteUint32(0)       // EntriesRead
				enc.WriteUint32(0x20008) // Buffer
				enc.WriteUint32(1)       // Array MaxCount
				enc.WriteUint32(0)       // TotalEntries
				enc.WriteUint32(0)       // ResumeHandle (NULL)
				enc.WriteUint32(0)       // ReturnStatus
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncoder()
			tt.build(enc)
			pdu := make([]byte, HeaderSize+enc.Len())
			encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, uint16(len(pdu)), 0, 1)
			copy(pdu[HeaderSize:], enc.Bytes())

			_, err := NetShareEnumAllResponseDecoder(pdu[HeaderSize:]).ShareInfos()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ShareInfos() error = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

func TestResponseFragmentBoundaries(t *testing.T) {
	const fragmentLength = HeaderSize + 8
	pdu := make([]byte, fragmentLength+1)
	encodeCommonHeader(pdu, RPC_TYPE_RESPONSE, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, fragmentLength, 0, 77)
	for length := 0; length <= len(pdu); length++ {
		header := ResponseHeaderDecoder(pdu[:length])
		if header.IsInvalid() != (length < HeaderSize) {
			t.Fatalf("header validity for length %d", length)
		}
		fragment := ResponseFragmentDecoder(pdu[:length])
		if fragment.IsInvalid() != (length != fragmentLength) {
			t.Fatalf("fragment validity for length %d", length)
		}
	}
	fragment := ResponseFragmentDecoder(pdu[:fragmentLength])
	if fragment.Header().CallId() != 77 || !bytes.Equal(fragment.Stub(), pdu[HeaderSize:fragmentLength]) {
		t.Fatal("fragment header or stub was not preserved")
	}
	for _, declared := range []uint16{HeaderSize - 1, DefaultMaxFragmentSize + 1} {
		le.PutUint16(pdu[8:10], declared)
		if !ResponseHeaderDecoder(pdu).IsInvalid() {
			t.Fatalf("accepted invalid declared length %d", declared)
		}
	}
	le.PutUint16(pdu[8:10], fragmentLength)
	pdu[2] = RPC_TYPE_REQUEST
	if !ResponseHeaderDecoder(pdu).IsInvalid() || !ResponseFragmentDecoder(pdu[:fragmentLength]).IsInvalid() {
		t.Fatal("accepted a request as a response")
	}
	pdu[2] = RPC_TYPE_RESPONSE
	le.PutUint16(pdu[10:12], 1)
	if !ResponseHeaderDecoder(pdu).IsInvalid() || !ResponseFragmentDecoder(pdu[:fragmentLength]).IsInvalid() {
		t.Fatal("accepted authenticated response")
	}
}

func TestNetShareEnumAllResponse_TruncatedAndInvalid(t *testing.T) {
	for length := range 24 {
		if _, err := NetShareEnumAllResponseDecoder(make([]byte, length)).ShareInfos(); err == nil {
			t.Fatalf("accepted incomplete response stub of length %d", length)
		}
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

	resp := NetShareEnumAllResponseDecoder(pdu[HeaderSize:])
	if ResponseFragmentDecoder(pdu).IsInvalid() {
		t.Fatalf("pdu header itself should be valid")
	}
	if _, err := resp.Sharenames(); err == nil {
		t.Fatalf("expected truncated string body to return error")
	}
}

func TestConformantVaryingStringTruncation(t *testing.T) {
	enc := NewEncoder()
	enc.WriteConformantVaryingString("AB")
	for n := range 18 {
		if _, err := NewDecoder(enc.Bytes()[:n]).ReadConformantVaryingString(); err == nil {
			t.Fatalf("accepted string truncated to %d bytes", n)
		}
	}
}
