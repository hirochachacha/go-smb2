package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzReadRequest(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint32(1024), uint64(0), uint32(1), uint32(0), uint32(0), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, padding, flags uint8, length uint32, offset uint64, minCount, channel, remaining uint32, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		req := &ReadRequest{
			Padding:        padding,
			Flags:          flags,
			Length:         length,
			Offset:         offset,
			FileId:         &FileId{Persistent: persistent, Volatile: volatile},
			MinimumCount:   minCount,
			Channel:        channel,
			RemainingBytes: remaining,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := ReadRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded ReadRequest")
		}

		if d.Padding() != padding {
			t.Fatalf("Padding mismatch: expected %d, got %d", padding, d.Padding())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.Length() != length {
			t.Fatalf("Length mismatch: expected %d, got %d", length, d.Length())
		}
		if d.Offset() != offset {
			t.Fatalf("Offset mismatch: expected %d, got %d", offset, d.Offset())
		}
		if d.MinimumCount() != minCount {
			t.Fatalf("MinimumCount mismatch: expected %d, got %d", minCount, d.MinimumCount())
		}
		if d.Channel() != channel {
			t.Fatalf("Channel mismatch: expected %d, got %d", channel, d.Channel())
		}
		if d.RemainingBytes() != remaining {
			t.Fatalf("RemainingBytes mismatch: expected %d, got %d", remaining, d.RemainingBytes())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzWriteRequest(f *testing.F) {
	f.Add(uint32(0), uint32(0), uint32(0), uint64(0), []byte("write_data"), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, flags, channel, remaining uint32, offset uint64, data []byte, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		req := &WriteRequest{
			Flags:          flags,
			Channel:        channel,
			RemainingBytes: remaining,
			Offset:         offset,
			Data:           data,
			FileId:         &FileId{Persistent: persistent, Volatile: volatile},
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := WriteRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded WriteRequest")
		}

		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.Channel() != channel {
			t.Fatalf("Channel mismatch: expected %d, got %d", channel, d.Channel())
		}
		if d.RemainingBytes() != remaining {
			t.Fatalf("RemainingBytes mismatch: expected %d, got %d", remaining, d.RemainingBytes())
		}
		if d.Offset() != offset {
			t.Fatalf("Offset mismatch: expected %d, got %d", offset, d.Offset())
		}
		if d.Length() != uint32(len(data)) {
			t.Fatalf("Length mismatch: expected %d, got %d", len(data), d.Length())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzSessionSetupRequest(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(3), uint32(4), uint64(5), []byte("sec_buffer"))

	f.Fuzz(func(t *testing.T, flags, secMode uint8, caps, channel uint32, prevSessionId uint64, secBuf []byte) {
		req := &SessionSetupRequest{
			Flags:             flags,
			SecurityMode:      secMode,
			Capabilities:      caps,
			Channel:           channel,
			PreviousSessionId: prevSessionId,
			SecurityBuffer:    secBuf,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := SessionSetupRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded SessionSetupRequest")
		}

		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.SecurityMode() != secMode {
			t.Fatalf("SecurityMode mismatch: expected %d, got %d", secMode, d.SecurityMode())
		}
		if d.Capabilities() != caps {
			t.Fatalf("Capabilities mismatch: expected %d, got %d", caps, d.Capabilities())
		}
		if d.Channel() != channel {
			t.Fatalf("Channel mismatch: expected %d, got %d", channel, d.Channel())
		}
		if d.PreviousSessionId() != prevSessionId {
			t.Fatalf("PreviousSessionId mismatch: expected %d, got %d", prevSessionId, d.PreviousSessionId())
		}
		if !bytes.Equal(d.SecurityBuffer(), secBuf) {
			t.Fatalf("SecurityBuffer mismatch: expected %q, got %q", secBuf, d.SecurityBuffer())
		}
	})
}

func FuzzTreeConnectRequest(f *testing.F) {
	f.Add(uint16(0), `\\server\share`)

	f.Fuzz(func(t *testing.T, flags uint16, path string) {
		req := &TreeConnectRequest{
			Flags: flags,
			Path:  path,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := TreeConnectRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded TreeConnectRequest")
		}

		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.Path() != path {
			t.Fatalf("Path mismatch: expected %q, got %q", path, d.Path())
		}
	})
}

func FuzzCreateRequest(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(3), uint64(4), uint32(5), uint32(6), uint32(7), uint32(8), uint32(9), "test.txt")

	f.Fuzz(func(t *testing.T, secFlags, oplock uint8, impersonation uint32, createFlags uint64, access, attr, shareAccess, disposition, options uint32, name string) {
		req := &CreateRequest{
			SecurityFlags:        secFlags,
			RequestedOplockLevel: oplock,
			ImpersonationLevel:   impersonation,
			SmbCreateFlags:       createFlags,
			DesiredAccess:        access,
			FileAttributes:       attr,
			ShareAccess:          shareAccess,
			CreateDisposition:    disposition,
			CreateOptions:        options,
			Name:                 name,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := CreateRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded CreateRequest")
		}

		if d.SecurityFlags() != secFlags {
			t.Fatalf("SecurityFlags mismatch: expected %d, got %d", secFlags, d.SecurityFlags())
		}
		if d.RequestedOplockLevel() != oplock {
			t.Fatalf("RequestedOplockLevel mismatch: expected %d, got %d", oplock, d.RequestedOplockLevel())
		}
		if d.ImpersonationLevel() != impersonation {
			t.Fatalf("ImpersonationLevel mismatch: expected %d, got %d", impersonation, d.ImpersonationLevel())
		}
		if d.SmbCreateFlags() != createFlags {
			t.Fatalf("SmbCreateFlags mismatch: expected %d, got %d", createFlags, d.SmbCreateFlags())
		}
		if d.DesiredAccess() != access {
			t.Fatalf("DesiredAccess mismatch: expected %d, got %d", access, d.DesiredAccess())
		}
		if d.FileAttributes() != attr {
			t.Fatalf("FileAttributes mismatch: expected %d, got %d", attr, d.FileAttributes())
		}
		if d.ShareAccess() != shareAccess {
			t.Fatalf("ShareAccess mismatch: expected %d, got %d", shareAccess, d.ShareAccess())
		}
		if d.CreateDisposition() != disposition {
			t.Fatalf("CreateDisposition mismatch: expected %d, got %d", disposition, d.CreateDisposition())
		}
		if d.CreateOptions() != options {
			t.Fatalf("CreateOptions mismatch: expected %d, got %d", options, d.CreateOptions())
		}
	})
}

func FuzzCloseRequest(f *testing.F) {
	f.Add(uint16(1), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, flags uint16, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		req := &CloseRequest{
			Flags:  flags,
			FileId: &FileId{Persistent: persistent, Volatile: volatile},
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := CloseRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded CloseRequest")
		}

		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzIoctlRequest(f *testing.F) {
	f.Add(uint32(0x0011C017), uint32(1024), uint32(0), uint32(512), uint32(2048), uint32(0), []byte("ioctl_req_input"), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, ctlCode, maxInputResp, outputOffset, outputCount, maxOutputResp, flags uint32, inputData []byte, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		var inputEnc Encoder
		if len(inputData) > 0 {
			inputEnc = &mockEncoder{data: inputData}
		}

		req := &IoctlRequest{
			CtlCode:           ctlCode,
			FileId:            &FileId{Persistent: persistent, Volatile: volatile},
			OutputOffset:      outputOffset,
			OutputCount:       outputCount,
			MaxInputResponse:  maxInputResp,
			MaxOutputResponse: maxOutputResp,
			Flags:             flags,
			Input:             inputEnc,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := IoctlRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded IoctlRequest")
		}

		if d.CtlCode() != ctlCode {
			t.Fatalf("CtlCode mismatch: expected 0x%X, got 0x%X", ctlCode, d.CtlCode())
		}
		if d.MaxInputResponse() != maxInputResp {
			t.Fatalf("MaxInputResponse mismatch: expected %d, got %d", maxInputResp, d.MaxInputResponse())
		}
		if d.OutputOffset() != outputOffset {
			t.Fatalf("OutputOffset mismatch: expected %d, got %d", outputOffset, d.OutputOffset())
		}
		if d.OutputCount() != outputCount {
			t.Fatalf("OutputCount mismatch: expected %d, got %d", outputCount, d.OutputCount())
		}
		if d.MaxOutputResponse() != maxOutputResp {
			t.Fatalf("MaxOutputResponse mismatch: expected %d, got %d", maxOutputResp, d.MaxOutputResponse())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzQueryDirectoryRequest(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(3), uint32(4096), "file.txt", uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, fileInfoClass, flags uint8, fileIndex, outputBufferLen uint32, name string, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		req := &QueryDirectoryRequest{
			FileInfoClass:      fileInfoClass,
			Flags:              flags,
			FileIndex:          fileIndex,
			FileId:             &FileId{Persistent: persistent, Volatile: volatile},
			OutputBufferLength: outputBufferLen,
			FileName:           name,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := QueryDirectoryRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded QueryDirectoryRequest")
		}

		if d.FileInfoClass() != fileInfoClass {
			t.Fatalf("FileInfoClass mismatch: expected %d, got %d", fileInfoClass, d.FileInfoClass())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if d.FileIndex() != fileIndex {
			t.Fatalf("FileIndex mismatch: expected %d, got %d", fileIndex, d.FileIndex())
		}
		if d.OutputBufferLength() != outputBufferLen {
			t.Fatalf("OutputBufferLength mismatch: expected %d, got %d", outputBufferLen, d.OutputBufferLength())
		}
		if d.FileName() != name {
			t.Fatalf("FileName mismatch: expected %q, got %q", name, d.FileName())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzQueryInfoRequest(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(1024), uint32(3), uint32(4), []byte("input_buf"), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, infoType, fileInfoClass uint8, outputBufferLen, addInfo, flags uint32, inputData []byte, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		var inputEnc Encoder
		if len(inputData) > 0 {
			inputEnc = &mockEncoder{data: inputData}
		}

		req := &QueryInfoRequest{
			InfoType:              infoType,
			FileInfoClass:         fileInfoClass,
			OutputBufferLength:    outputBufferLen,
			AdditionalInformation: addInfo,
			Flags:                 flags,
			FileId:                &FileId{Persistent: persistent, Volatile: volatile},
			Input:                 inputEnc,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := QueryInfoRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded QueryInfoRequest")
		}

		if d.InfoType() != infoType {
			t.Fatalf("InfoType mismatch: expected %d, got %d", infoType, d.InfoType())
		}
		if d.FileInfoClass() != fileInfoClass {
			t.Fatalf("FileInfoClass mismatch: expected %d, got %d", fileInfoClass, d.FileInfoClass())
		}
		if d.OutputBufferLength() != outputBufferLen {
			t.Fatalf("OutputBufferLength mismatch: expected %d, got %d", outputBufferLen, d.OutputBufferLength())
		}
		if d.AdditionalInformation() != addInfo {
			t.Fatalf("AdditionalInformation mismatch: expected %d, got %d", addInfo, d.AdditionalInformation())
		}
		if d.Flags() != flags {
			t.Fatalf("Flags mismatch: expected %d, got %d", flags, d.Flags())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}

func FuzzSetInfoRequest(f *testing.F) {
	f.Add(uint8(1), uint8(2), uint32(3), []byte("set_info_input"), uint64(10), uint64(20))

	f.Fuzz(func(t *testing.T, infoType, fileInfoClass uint8, addInfo uint32, inputData []byte, pId, vId uint64) {
		var persistent, volatile [8]byte
		binary.LittleEndian.PutUint64(persistent[:], pId)
		binary.LittleEndian.PutUint64(volatile[:], vId)

		var inputEnc Encoder
		if len(inputData) > 0 {
			inputEnc = &mockEncoder{data: inputData}
		}

		req := &SetInfoRequest{
			InfoType:              infoType,
			FileInfoClass:         fileInfoClass,
			AdditionalInformation: addInfo,
			FileId:                &FileId{Persistent: persistent, Volatile: volatile},
			Input:                 inputEnc,
		}

		pkt := make([]byte, req.Size())
		req.Encode(pkt)

		d := SetInfoRequestDecoder(pkt[64:])
		if d.IsInvalid() {
			t.Fatal("IsInvalid reported true for valid encoded SetInfoRequest")
		}

		if d.InfoType() != infoType {
			t.Fatalf("InfoType mismatch: expected %d, got %d", infoType, d.InfoType())
		}
		if d.FileInfoClass() != fileInfoClass {
			t.Fatalf("FileInfoClass mismatch: expected %d, got %d", fileInfoClass, d.FileInfoClass())
		}
		if d.AdditionalInformation() != addInfo {
			t.Fatalf("AdditionalInformation mismatch: expected %d, got %d", addInfo, d.AdditionalInformation())
		}
		if !bytes.Equal(d.FileId().Persistent(), persistent[:]) || !bytes.Equal(d.FileId().Volatile(), volatile[:]) {
			t.Fatalf("FileId mismatch")
		}
	})
}
