package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCompressionCodec(t *testing.T) {
	pkt := make([]byte, 24)
	copy(pkt[:4], []byte{0xfc, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint32(pkt[4:8], 0x11223344)
	binary.LittleEndian.PutUint16(pkt[8:10], SMB2_COMPRESSION_ALGORITHM_LZ4)
	binary.LittleEndian.PutUint16(pkt[10:12], SMB2_COMPRESSION_FLAG_NONE)
	binary.LittleEndian.PutUint32(pkt[12:16], 0x00000008)

	c := CompressionCodec(pkt)
	if c.IsInvalid() {
		t.Fatal("known compression header rejected")
	}
	if got := c.OriginalCompressedSegmentSize(); got != 0x11223344 {
		t.Fatalf("OriginalCompressedSegmentSize = %#x", got)
	}
	if got := c.CompressionAlgorithm(); got != SMB2_COMPRESSION_ALGORITHM_LZ4 {
		t.Fatalf("CompressionAlgorithm = %#x", got)
	}
	if got := c.Flags(); got != SMB2_COMPRESSION_FLAG_NONE {
		t.Fatalf("Flags = %#x", got)
	}
	if got := c.Offset(); got != 0x00000008 {
		t.Fatalf("Offset = %#x", got)
	}

	for n := range pkt {
		if !CompressionCodec(pkt[:n]).IsInvalid() {
			t.Fatalf("truncated compression header of length %d accepted", n)
		}
	}
}

func TestCompressionContextDataDecoder(t *testing.T) {
	encoded := make([]byte, (&CompressionContext{
		CompressionAlgorithms: []uint16{SMB2_COMPRESSION_ALGORITHM_LZ4},
		Flags:                 SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE,
	}).Size())
	(&CompressionContext{
		CompressionAlgorithms: []uint16{SMB2_COMPRESSION_ALGORITHM_LZ4},
		Flags:                 SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE,
	}).Encode(encoded)
	want := []byte{
		0x03, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
	}
	// The context is padded to an 8-byte boundary by the enclosing request,
	// not by the context encoder itself.
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded compression context = %x, want %x", encoded, want)
	}

	data := make([]byte, 12)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.LittleEndian.PutUint32(data[4:8], SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE)
	binary.LittleEndian.PutUint16(data[8:10], SMB2_COMPRESSION_ALGORITHM_LZ4)
	binary.LittleEndian.PutUint16(data[10:12], SMB2_COMPRESSION_ALGORITHM_NONE)

	d := CompressionContextDataDecoder(data)
	if d.IsInvalid() {
		t.Fatal("known compression context rejected")
	}
	if got := d.CompressionAlgorithms(); len(got) != 2 || got[0] != SMB2_COMPRESSION_ALGORITHM_LZ4 || got[1] != SMB2_COMPRESSION_ALGORITHM_NONE {
		t.Fatalf("CompressionAlgorithms = %#v", got)
	}

	for n := range data {
		if !CompressionContextDataDecoder(data[:n]).IsInvalid() {
			t.Fatalf("truncated compression context of length %d accepted", n)
		}
	}
}

type mockEncoder struct {
	data []byte
}

func (e *mockEncoder) Encode(dst []byte) {
	copy(dst, e.data)
}

func (e *mockEncoder) Size() int {
	return len(e.data)
}

func testHeaderSettersAndCodec(
	t *testing.T,
	pkt Packet,
	expectedCmd Command, expectedCreditCharge uint16,
	msgId, sessionId uint64,
	treeId, nextCmd uint32,
	creditReq uint16,
	flags uint32,
) {
	pkt.SetMessageId(msgId)
	pkt.SetSessionId(sessionId)
	pkt.SetTreeId(treeId)
	pkt.SetNextCommand(nextCmd)
	pkt.SetCreditRequestResponse(creditReq)
	pkt.SetFlags(flags)

	if pkt.Command() != expectedCmd {
		t.Fatalf("Command mismatch: expected %d, got %d", expectedCmd, pkt.Command())
	}
	if pkt.CreditCharge() != expectedCreditCharge {
		t.Fatalf("CreditCharge mismatch: expected %d, got %d", expectedCreditCharge, pkt.CreditCharge())
	}

	buf := make([]byte, pkt.Size())
	pkt.Encode(buf)

	p := PacketCodec(buf)
	if p.Command() != expectedCmd {
		t.Fatalf("Header Command mismatch: expected %d, got %d", expectedCmd, p.Command())
	}
	if p.CreditCharge() != expectedCreditCharge {
		t.Fatalf("Header CreditCharge mismatch: expected %d, got %d", expectedCreditCharge, p.CreditCharge())
	}
	if p.MessageId() != msgId {
		t.Fatalf("Header MessageId mismatch: expected %d, got %d", msgId, p.MessageId())
	}
	if p.SessionId() != sessionId {
		t.Fatalf("Header SessionId mismatch: expected %d, got %d", sessionId, p.SessionId())
	}
	if p.TreeId() != treeId {
		t.Fatalf("Header TreeId mismatch: expected %d, got %d", treeId, p.TreeId())
	}
	if p.NextCommand() != nextCmd {
		t.Fatalf("Header NextCommand mismatch: expected %d, got %d", nextCmd, p.NextCommand())
	}
	if p.CreditRequest() != creditReq {
		t.Fatalf("Header CreditRequest mismatch: expected %d, got %d", creditReq, p.CreditRequest())
	}
	if p.Flags() != flags {
		t.Fatalf("Header Flags mismatch: expected %d, got %d", flags, p.Flags())
	}
}

func FuzzPacket(f *testing.F) {
	for i := range uint8(32) {
		f.Add(i, uint64(100), uint64(200), uint32(300), uint32(0), uint16(1), uint32(0), uint16(1), uint32(10), uint32(20), uint32(30), uint32(40), uint64(50), uint64(60), []byte("fuzz_payload"))
	}

	f.Fuzz(func(
		t *testing.T,
		packetType uint8,
		msgId, sessionId uint64,
		treeId, nextCmd uint32,
		creditReq uint16,
		flags uint32,
		creditCharge uint16,
		arg1, arg2, arg3, arg4 uint32,
		arg5, arg6 uint64,
		payload []byte,
	) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], arg5)
		binary.LittleEndian.PutUint64(volatile[:], arg6)

		var mockEnc Encoder
		if len(payload) > 0 {
			mockEnc = &mockEncoder{data: payload}
		}

		switch packetType % 32 {
		// --------------------------------------------------------------------
		// Request Packets (0 - 15)
		// --------------------------------------------------------------------
		case 0: // NegotiateRequest
			req := &NegotiateRequest{}
			testHeaderSettersAndCodec(t, req, SMB2_NEGOTIATE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 1: // SessionSetupRequest
			req := &SessionSetupRequest{
				Flags:             uint8(arg1),
				SecurityMode:      uint8(arg2),
				Capabilities:      arg3,
				Channel:           arg4,
				PreviousSessionId: arg5,
				SecurityBuffer:    payload,
			}
			testHeaderSettersAndCodec(t, req, SMB2_SESSION_SETUP, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := SessionSetupRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Flags() != uint8(arg1) || d.SecurityMode() != uint8(arg2) {
					t.Fatal("SessionSetupRequestDecoder mismatch")
				}
			}

		case 2: // LogoffRequest
			req := &LogoffRequest{}
			testHeaderSettersAndCodec(t, req, SMB2_LOGOFF, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 3: // EchoRequest
			req := &EchoRequest{}
			testHeaderSettersAndCodec(t, req, SMB2_ECHO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 4: // TreeConnectRequest
			req := &TreeConnectRequest{
				Flags: uint16(arg1),
				Path:  string(payload),
			}
			testHeaderSettersAndCodec(t, req, SMB2_TREE_CONNECT, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := TreeConnectRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Flags() != uint16(arg1) {
					t.Fatal("TreeConnectRequestDecoder mismatch")
				}
			}

		case 5: // TreeDisconnectRequest
			req := &TreeDisconnectRequest{}
			testHeaderSettersAndCodec(t, req, SMB2_TREE_DISCONNECT, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 6: // CreateRequest
			req := &CreateRequest{
				SecurityFlags:        uint8(arg1),
				RequestedOplockLevel: uint8(arg2),
				ImpersonationLevel:   arg3,
				SmbCreateFlags:       arg5,
				DesiredAccess:        arg4,
				FileAttributes:       arg1,
				ShareAccess:          arg2,
				CreateDisposition:    arg3,
				CreateOptions:        arg4,
				Name:                 string(payload),
			}
			testHeaderSettersAndCodec(t, req, SMB2_CREATE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := CreateRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.SecurityFlags() != uint8(arg1) || d.RequestedOplockLevel() != uint8(arg2) {
					t.Fatal("CreateRequestDecoder mismatch")
				}
			}

		case 7: // CloseRequest
			req := &CloseRequest{
				Flags:  uint16(arg1),
				FileId: &FileId{Persistent: persistent, Volatile: volatile},
			}
			testHeaderSettersAndCodec(t, req, SMB2_CLOSE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := CloseRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Flags() != uint16(arg1) {
					t.Fatal("CloseRequestDecoder mismatch")
				}
			}

		case 8: // FlushRequest
			req := &FlushRequest{
				FileId: &FileId{Persistent: persistent, Volatile: volatile},
			}
			testHeaderSettersAndCodec(t, req, SMB2_FLUSH, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := FlushRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if !bytes.Equal(d.FileId().Persistent(), persistent[:]) {
					t.Fatal("FlushRequestDecoder mismatch")
				}
			}

		case 9: // ReadRequest
			req := &ReadRequest{
				Padding:        uint8(arg1),
				Flags:          uint8(arg2),
				Length:         arg3,
				Offset:         arg5,
				FileId:         &FileId{Persistent: persistent, Volatile: volatile},
				MinimumCount:   arg4,
				Channel:        arg1,
				RemainingBytes: arg2,
			}
			expCharge := creditCharge
			if expCharge == 0 {
				expCharge = 1
			}
			req.SetCreditCharge(creditCharge)
			testHeaderSettersAndCodec(t, req, SMB2_READ, expCharge, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := ReadRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Padding() != uint8(arg1) || d.Flags() != uint8(arg2) || d.Length() != arg3 || d.Offset() != arg5 {
					t.Fatal("ReadRequestDecoder mismatch")
				}
			}

		case 10: // WriteRequest
			req := &WriteRequest{
				Flags:          arg1,
				Channel:        arg2,
				RemainingBytes: arg3,
				Offset:         arg5,
				Data:           payload,
				FileId:         &FileId{Persistent: persistent, Volatile: volatile},
			}
			expCharge := creditCharge
			if expCharge == 0 {
				expCharge = 1
			}
			req.SetCreditCharge(creditCharge)
			testHeaderSettersAndCodec(t, req, SMB2_WRITE, expCharge, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := WriteRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Flags() != arg1 || d.Channel() != arg2 || d.RemainingBytes() != arg3 || d.Offset() != arg5 {
					t.Fatal("WriteRequestDecoder mismatch")
				}
			}

		case 11: // CancelRequest
			req := &CancelRequest{}
			testHeaderSettersAndCodec(t, req, SMB2_CANCEL, 0, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := CancelRequestDecoder(pkt[64:])
			if d.IsInvalid() {
				t.Fatal("CancelRequestDecoder reported invalid")
			}

		case 12: // IoctlRequest
			req := &IoctlRequest{
				CtlCode:           arg1,
				FileId:            &FileId{Persistent: persistent, Volatile: volatile},
				OutputOffset:      arg2,
				OutputCount:       arg3,
				MaxInputResponse:  arg4,
				MaxOutputResponse: arg1,
				Flags:             arg2,
				Input:             mockEnc,
			}
			expCharge := creditCharge
			if expCharge == 0 {
				expCharge = 1
			}
			req.SetCreditCharge(creditCharge)
			testHeaderSettersAndCodec(t, req, SMB2_IOCTL, expCharge, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := IoctlRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.CtlCode() != arg1 || d.Flags() != arg2 {
					t.Fatal("IoctlRequestDecoder mismatch")
				}
			}

		case 13: // QueryDirectoryRequest
			req := &QueryDirectoryRequest{
				FileInfoClass:      uint8(arg1),
				Flags:              uint8(arg2),
				FileIndex:          arg3,
				FileId:             &FileId{Persistent: persistent, Volatile: volatile},
				OutputBufferLength: arg4,
				FileName:           string(payload),
			}
			expCharge := creditCharge
			if expCharge == 0 {
				expCharge = 1
			}
			req.SetCreditCharge(creditCharge)
			testHeaderSettersAndCodec(t, req, SMB2_QUERY_DIRECTORY, expCharge, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := QueryDirectoryRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.FileInfoClass() != uint8(arg1) || d.Flags() != uint8(arg2) {
					t.Fatal("QueryDirectoryRequestDecoder mismatch")
				}
			}

		case 14: // QueryInfoRequest
			req := &QueryInfoRequest{
				InfoType:              uint8(arg1),
				FileInfoClass:         uint8(arg2),
				OutputBufferLength:    arg3,
				AdditionalInformation: arg4,
				Flags:                 arg1,
				FileId:                &FileId{Persistent: persistent, Volatile: volatile},
				Input:                 mockEnc,
			}
			testHeaderSettersAndCodec(t, req, SMB2_QUERY_INFO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := QueryInfoRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.InfoType() != uint8(arg1) || d.FileInfoClass() != uint8(arg2) {
					t.Fatal("QueryInfoRequestDecoder mismatch")
				}
			}

		case 15: // SetInfoRequest
			req := &SetInfoRequest{
				InfoType:              uint8(arg1),
				FileInfoClass:         uint8(arg2),
				AdditionalInformation: arg3,
				FileId:                &FileId{Persistent: persistent, Volatile: volatile},
				Input:                 mockEnc,
			}
			testHeaderSettersAndCodec(t, req, SMB2_SET_INFO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, req.Size())
			req.Encode(pkt)
			d := SetInfoRequestDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.InfoType() != uint8(arg1) || d.FileInfoClass() != uint8(arg2) {
					t.Fatal("SetInfoRequestDecoder mismatch")
				}
			}

		// --------------------------------------------------------------------
		// Response Packets (16 - 31)
		// --------------------------------------------------------------------
		case 16: // ErrorResponse
			resp := &ErrorResponse{
				CommandCode: SMB2_READ,
				ErrorData:   mockEnc,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_READ, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 17: // NegotiateResponse
			resp := &NegotiateResponse{
				SecurityMode:    uint16(arg1),
				DialectRevision: uint16(arg2),
				Capabilities:    arg3,
				MaxTransactSize: arg4,
				MaxReadSize:     uint32(arg5),
				MaxWriteSize:    uint32(arg6),
				SystemTime:      &Filetime{LowDateTime: 10, HighDateTime: 20},
				ServerStartTime: &Filetime{LowDateTime: 30, HighDateTime: 40},
				SecurityBuffer:  payload,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_NEGOTIATE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 18: // SessionSetupResponse
			resp := &SessionSetupResponse{
				SessionFlags:   uint16(arg1),
				SecurityBuffer: payload,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_SESSION_SETUP, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := SessionSetupResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.SessionFlags() != uint16(arg1) {
					t.Fatal("SessionSetupResponseDecoder mismatch")
				}
			}

		case 19: // LogoffResponse
			resp := &LogoffResponse{}
			testHeaderSettersAndCodec(t, resp, SMB2_LOGOFF, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 20: // EchoResponse
			resp := &EchoResponse{}
			testHeaderSettersAndCodec(t, resp, SMB2_ECHO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 21: // TreeConnectResponse
			resp := &TreeConnectResponse{
				ShareType:     uint8(arg1),
				ShareFlags:    arg2,
				Capabilities:  arg3,
				MaximalAccess: arg4,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_TREE_CONNECT, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := TreeConnectResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.ShareType() != uint8(arg1) || d.ShareFlags() != arg2 {
					t.Fatal("TreeConnectResponseDecoder mismatch")
				}
			}

		case 22: // TreeDisconnectResponse
			resp := &TreeDisconnectResponse{}
			testHeaderSettersAndCodec(t, resp, SMB2_TREE_DISCONNECT, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 23: // CreateResponse
			resp := &CreateResponse{
				OplockLevel:    uint8(arg1),
				Flags:          uint8(arg2),
				CreateAction:   arg3,
				CreationTime:   &Filetime{LowDateTime: 10, HighDateTime: 20},
				LastAccessTime: &Filetime{LowDateTime: 30, HighDateTime: 40},
				LastWriteTime:  &Filetime{LowDateTime: 50, HighDateTime: 60},
				ChangeTime:     &Filetime{LowDateTime: 70, HighDateTime: 80},
				AllocationSize: int64(arg5),
				EndofFile:      int64(arg6),
				FileAttributes: arg4,
				FileId:         &FileId{Persistent: persistent, Volatile: volatile},
			}
			testHeaderSettersAndCodec(t, resp, SMB2_CREATE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := CreateResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.OplockLevel() != uint8(arg1) || d.Flags() != uint8(arg2) {
					t.Fatal("CreateResponseDecoder mismatch")
				}
			}

		case 24: // CloseResponse
			resp := &CloseResponse{
				Flags:          uint16(arg1),
				CreationTime:   &Filetime{LowDateTime: 10, HighDateTime: 20},
				LastAccessTime: &Filetime{LowDateTime: 30, HighDateTime: 40},
				LastWriteTime:  &Filetime{LowDateTime: 50, HighDateTime: 60},
				ChangeTime:     &Filetime{LowDateTime: 70, HighDateTime: 80},
				AllocationSize: int64(arg5),
				EndofFile:      int64(arg6),
				FileAttributes: arg2,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_CLOSE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := CloseResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Flags() != uint16(arg1) {
					t.Fatal("CloseResponseDecoder mismatch")
				}
			}

		case 25: // FlushResponse
			resp := &FlushResponse{}
			testHeaderSettersAndCodec(t, resp, SMB2_FLUSH, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)

		case 26: // ReadResponse
			resp := &ReadResponse{
				Data:          payload,
				DataRemaining: arg1,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_READ, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := ReadResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.DataRemaining() != arg1 {
					t.Fatal("ReadResponseDecoder mismatch")
				}
			}

		case 27: // WriteResponse
			resp := &WriteResponse{
				Count:     arg1,
				Remaining: arg2,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_WRITE, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := WriteResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.Count() != arg1 || d.Remaining() != arg2 {
					t.Fatal("WriteResponseDecoder mismatch")
				}
			}

		case 28: // IoctlResponse
			resp := &IoctlResponse{
				CtlCode: arg1,
				FileId:  &FileId{Persistent: persistent, Volatile: volatile},
				Flags:   arg2,
				Input:   mockEnc,
				Output:  mockEnc,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_IOCTL, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := IoctlResponseDecoder(pkt[64:])
			if !d.IsInvalid() {
				if d.CtlCode() != arg1 || d.Flags() != arg2 {
					t.Fatal("IoctlResponseDecoder mismatch")
				}
			}

		case 29: // QueryDirectoryResponse
			resp := &QueryDirectoryResponse{
				Output: mockEnc,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_QUERY_DIRECTORY, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := QueryDirectoryResponseDecoder(pkt[64:])
			if d.IsInvalid() && len(payload) > 0 {
				t.Fatal("QueryDirectoryResponseDecoder reported invalid")
			}

		case 30: // QueryInfoResponse
			resp := &QueryInfoResponse{
				Output: mockEnc,
			}
			testHeaderSettersAndCodec(t, resp, SMB2_QUERY_INFO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
			pkt := make([]byte, resp.Size())
			resp.Encode(pkt)
			d := QueryInfoResponseDecoder(pkt[64:])
			if d.IsInvalid() && len(payload) > 0 {
				t.Fatal("QueryInfoResponseDecoder reported invalid")
			}

		case 31: // SetInfoResponse
			resp := &SetInfoResponse{}
			testHeaderSettersAndCodec(t, resp, SMB2_SET_INFO, 1, msgId, sessionId, treeId, nextCmd, creditReq, flags)
		}
	})
}
