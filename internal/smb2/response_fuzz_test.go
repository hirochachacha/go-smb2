package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type mockEncoder struct {
	data []byte
}

func (e *mockEncoder) Encode(dst []byte) {
	copy(dst, e.data)
}

func (e *mockEncoder) Size() int {
	return len(e.data)
}

func FuzzReadResponse(f *testing.F) {
	f.Add([]byte("hello world"), uint32(0))
	f.Add([]byte(""), uint32(100))

	f.Fuzz(func(t *testing.T, data []byte, dataRemaining uint32) {
		resp := &ReadResponse{
			Data:          data,
			DataRemaining: dataRemaining,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := ReadResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded ReadResponse")
		}

		if !bytes.Equal(d.Data(), data) {
			t.Fatalf("Data mismatch: expected %q, got %q", data, d.Data())
		}
		if d.DataRemaining() != dataRemaining {
			t.Fatalf("DataRemaining mismatch: expected %d, got %d", dataRemaining, d.DataRemaining())
		}
	})
}

func FuzzWriteResponse(f *testing.F) {
	f.Add(uint32(4096), uint32(0))
	f.Add(uint32(0), uint32(100))

	f.Fuzz(func(t *testing.T, count, remaining uint32) {
		resp := &WriteResponse{
			Count:     count,
			Remaining: remaining,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := WriteResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded WriteResponse")
		}

		if d.Count() != count {
			t.Fatalf("Count mismatch: expected %d, got %d", count, d.Count())
		}
		if d.Remaining() != remaining {
			t.Fatalf("Remaining mismatch: expected %d, got %d", remaining, d.Remaining())
		}
	})
}

func FuzzSessionSetupResponse(f *testing.F) {
	f.Add(uint16(1), []byte("token"))
	f.Add(uint16(0), []byte(""))

	f.Fuzz(func(t *testing.T, flags uint16, secBuf []byte) {
		resp := &SessionSetupResponse{
			SessionFlags:   flags,
			SecurityBuffer: secBuf,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := SessionSetupResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded SessionSetupResponse")
		}

		if d.SessionFlags() != flags {
			t.Fatalf("SessionFlags mismatch: expected %d, got %d", flags, d.SessionFlags())
		}
		if !bytes.Equal(d.SecurityBuffer(), secBuf) {
			t.Fatalf("SecurityBuffer mismatch: expected %q, got %q", secBuf, d.SecurityBuffer())
		}
	})
}

func FuzzTreeConnectResponse(f *testing.F) {
	f.Add(uint8(1), uint32(2), uint32(3), uint32(0x001F01FF))

	f.Fuzz(func(t *testing.T, shareType uint8, shareFlags, caps, maxAccess uint32) {
		resp := &TreeConnectResponse{
			ShareType:     shareType,
			ShareFlags:    shareFlags,
			Capabilities:  caps,
			MaximalAccess: maxAccess,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := TreeConnectResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded TreeConnectResponse")
		}

		if d.ShareType() != shareType {
			t.Fatalf("ShareType mismatch: expected %d, got %d", shareType, d.ShareType())
		}
		if d.ShareFlags() != shareFlags {
			t.Fatalf("ShareFlags mismatch: expected %d, got %d", shareFlags, d.ShareFlags())
		}
		if d.Capabilities() != caps {
			t.Fatalf("Capabilities mismatch: expected %d, got %d", caps, d.Capabilities())
		}
		if d.MaximalAccess() != maxAccess {
			t.Fatalf("MaximalAccess mismatch: expected 0x%X, got 0x%X", maxAccess, d.MaximalAccess())
		}
	})
}

func FuzzCreateResponse(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(3), int64(1024), int64(512), uint32(32), uint64(100), uint64(200))

	f.Fuzz(func(t *testing.T, oplock, flags uint8, action uint32, allocSize, eof int64, attr uint32, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		resp := &CreateResponse{
			OplockLevel:    oplock,
			Flags:          flags,
			CreateAction:   action,
			CreationTime:   &Filetime{LowDateTime: 10, HighDateTime: 20},
			LastAccessTime: &Filetime{LowDateTime: 30, HighDateTime: 40},
			LastWriteTime:  &Filetime{LowDateTime: 50, HighDateTime: 60},
			ChangeTime:     &Filetime{LowDateTime: 70, HighDateTime: 80},
			AllocationSize: allocSize,
			EndofFile:      eof,
			FileAttributes: attr,
			FileId:         &FileId{Persistent: persistent, Volatile: volatile},
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := CreateResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded CreateResponse")
		}

		if d.OplockLevel() != oplock {
			t.Fatalf("OplockLevel mismatch: expected %d, got %d", oplock, d.OplockLevel())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.CreateAction() != action {
			t.Fatalf("CreateAction mismatch: expected %d, got %d", action, d.CreateAction())
		}
		if d.AllocationSize() != allocSize {
			t.Fatalf("AllocationSize mismatch: expected %d, got %d", allocSize, d.AllocationSize())
		}
		if d.EndofFile() != eof {
			t.Fatalf("EndofFile mismatch: expected %d, got %d", eof, d.EndofFile())
		}
		if d.FileAttributes() != attr {
			t.Fatalf("FileAttributes mismatch: expected %d, got %d", attr, d.FileAttributes())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzCloseResponse(f *testing.F) {
	f.Add(uint16(1), int64(2048), int64(1024), uint32(16))

	f.Fuzz(func(t *testing.T, flags uint16, allocSize, eof int64, attr uint32) {
		resp := &CloseResponse{
			Flags:          flags,
			CreationTime:   &Filetime{LowDateTime: 10, HighDateTime: 20},
			LastAccessTime: &Filetime{LowDateTime: 30, HighDateTime: 40},
			LastWriteTime:  &Filetime{LowDateTime: 50, HighDateTime: 60},
			ChangeTime:     &Filetime{LowDateTime: 70, HighDateTime: 80},
			AllocationSize: allocSize,
			EndofFile:      eof,
			FileAttributes: attr,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := CloseResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded CloseResponse")
		}

		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.AllocationSize() != allocSize {
			t.Fatalf("AllocationSize mismatch: expected %d, got %d", allocSize, d.AllocationSize())
		}
		if d.EndofFile() != eof {
			t.Fatalf("EndofFile mismatch: expected %d, got %d", eof, d.EndofFile())
		}
		if d.FileAttributes() != attr {
			t.Fatalf("FileAttributes mismatch: expected %d, got %d", attr, d.FileAttributes())
		}
	})
}

func FuzzIoctlResponse(f *testing.F) {
	f.Add(uint32(0x0011C017), uint32(0), []byte("input"), []byte("output"))
	f.Add(uint32(0), uint32(1), []byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, ctlCode, flags uint32, inputData, outputData []byte) {
		var inputEnc, outputEnc Encoder
		if len(inputData) > 0 {
			inputEnc = &mockEncoder{data: inputData}
		}
		if len(outputData) > 0 {
			outputEnc = &mockEncoder{data: outputData}
		}

		resp := &IoctlResponse{
			CtlCode: ctlCode,
			FileId:  &FileId{},
			Flags:   flags,
			Input:   inputEnc,
			Output:  outputEnc,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := IoctlResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded IoctlResponse")
		}

		if d.CtlCode() != ctlCode {
			t.Fatalf("CtlCode mismatch: expected 0x%X, got 0x%X", ctlCode, d.CtlCode())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if len(inputData) > 0 && !bytes.Equal(d.Input(), inputData) {
			t.Fatalf("Input mismatch: expected %q, got %q", inputData, d.Input())
		}
		if len(outputData) > 0 && !bytes.Equal(d.Output(), outputData) {
			t.Fatalf("Output mismatch: expected %q, got %q", outputData, d.Output())
		}
	})
}

func FuzzQueryDirectoryResponse(f *testing.F) {
	f.Add([]byte("dir_info_data"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, outData []byte) {
		var outEnc Encoder
		if len(outData) > 0 {
			outEnc = &mockEncoder{data: outData}
		}

		resp := &QueryDirectoryResponse{
			Output: outEnc,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := QueryDirectoryResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded QueryDirectoryResponse")
		}

		if len(outData) > 0 && !bytes.Equal(d.OutputBuffer(), outData) {
			t.Fatalf("OutputBuffer mismatch: expected %q, got %q", outData, d.OutputBuffer())
		}
	})
}

func FuzzQueryInfoResponse(f *testing.F) {
	f.Add([]byte("query_info_data"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, outData []byte) {
		var outEnc Encoder
		if len(outData) > 0 {
			outEnc = &mockEncoder{data: outData}
		}

		resp := &QueryInfoResponse{
			Output: outEnc,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := QueryInfoResponseDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded QueryInfoResponse")
		}

		if len(outData) > 0 && !bytes.Equal(d.OutputBuffer(), outData) {
			t.Fatalf("OutputBuffer mismatch: expected %q, got %q", outData, d.OutputBuffer())
		}
	})
}

func FuzzSymbolicLinkErrorResponse(f *testing.F) {
	f.Add(uint16(0), uint32(0), "substitute", "print")

	f.Fuzz(func(t *testing.T, unparsedPathLen uint16, flags uint32, subName, printName string) {
		resp := &SymbolicLinkErrorResponse{
			UnparsedPathLength: unparsedPathLen,
			Flags:              flags,
			SubstituteName:     subName,
			PrintName:          printName,
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)

		d := SymbolicLinkErrorResponseDecoder(pkt)
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded SymbolicLinkErrorResponse")
		}

		if d.SubstituteName() != subName {
			t.Fatalf("SubstituteName mismatch: expected %q, got %q", subName, d.SubstituteName())
		}
		if d.PrintName() != printName {
			t.Fatalf("PrintName mismatch: expected %q, got %q", printName, d.PrintName())
		}
	})
}
