package smb2

// ----------------------------------------------------------------------------
// SMB2 FILEID
//

type FileIdDecoder []byte

func (fd FileIdDecoder) Persistent() []byte {
	return fd[:8]
}

func (fd FileIdDecoder) Volatile() []byte {
	return fd[8:16]
}

func (fd FileIdDecoder) Decode() *FileId {
	var ret FileId
	copy(ret.Persistent[:], fd[:8])
	copy(ret.Volatile[:], fd[8:16])
	return &ret
}

// ----------------------------------------------------------------------------
// SMB2 Error Response
//

type ErrorResponseDecoder []byte

func (res ErrorResponseDecoder) IsInvalid() bool {
	if len(res) < 8 {
		return true
	}

	if res.StructureSize() != 9 {
		return true
	}

	if uint32(len(res)) < 8+res.ByteCount() {
		return true
	}

	return false
}

func (res ErrorResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res ErrorResponseDecoder) ErrorContextCount() uint8 {
	return res[2]
}

func (res ErrorResponseDecoder) ByteCount() uint32 {
	return le.Uint32(res[4:8])
}

func (res ErrorResponseDecoder) ErrorData() []byte {
	return res[8 : 8+res.ByteCount()]
}

type ErrorContextResponseDecoder []byte

func (ctx ErrorContextResponseDecoder) IsInvalid() bool {
	if len(ctx) < 8 {
		return true
	}

	if uint32(len(ctx)) < 8+ctx.ErrorDataLength() {
		return true
	}

	return false
}

func (ctx ErrorContextResponseDecoder) ErrorDataLength() uint32 {
	return le.Uint32(ctx[:4])
}

func (ctx ErrorContextResponseDecoder) ErrorId() uint32 {
	return le.Uint32(ctx[4:8])
}

func (ctx ErrorContextResponseDecoder) ErrorContextData() []byte {
	return ctx[8 : 8+ctx.ErrorDataLength()]
}

func (ctx ErrorContextResponseDecoder) Next() []byte {
	return ctx[8+ctx.ErrorDataLength():]
}

type SmallBufferErrorResponseDecoder []byte

func (res SmallBufferErrorResponseDecoder) IsInvalid() bool {
	return len(res) != 4
}

func (res SmallBufferErrorResponseDecoder) RequiredBufferLength() uint32 {
	return le.Uint32(res)
}

type SymbolicLinkErrorResponseDecoder []byte

func (res SymbolicLinkErrorResponseDecoder) IsInvalid() bool {
	if len(res) < 28 {
		return true
	}

	if res.SymLinkErrorTag() != 0x4c4d5953 {
		return true
	}

	if res.ReparseTag() != 0xa000000c {
		return true
	}

	tlen := int(res.SymLinkLength())
	rlen := int(res.ReparseDataLength())
	soff := int(res.SubstituteNameOffset())
	slen := int(res.SubstituteNameLength())
	poff := int(res.PrintNameOffset())
	plen := int(res.PrintNameLength())

	if len(res) < tlen {
		return true
	}

	if len(res) < 16+rlen {
		return true
	}

	if len(res) < 28+soff+slen {
		return true
	}

	if len(res) < 28+poff+plen {
		return true
	}

	return false
}

func (res SymbolicLinkErrorResponseDecoder) SymLinkLength() uint32 {
	return le.Uint32(res[:4])
}

func (res SymbolicLinkErrorResponseDecoder) SymLinkErrorTag() uint32 {
	return le.Uint32(res[:8])
}

func (res SymbolicLinkErrorResponseDecoder) ReparseTag() uint32 {
	return le.Uint32(res[8:12])
}

func (res SymbolicLinkErrorResponseDecoder) ReparseDataLength() uint16 {
	return le.Uint16(res[12:14])
}

func (res SymbolicLinkErrorResponseDecoder) UnparsedPathLength() uint16 {
	return le.Uint16(res[14:16])
}

func (res SymbolicLinkErrorResponseDecoder) SubstituteNameOffset() uint16 {
	return le.Uint16(res[16:18])
}

func (res SymbolicLinkErrorResponseDecoder) SubstituteNameLength() uint16 {
	return le.Uint16(res[18:20])
}

func (res SymbolicLinkErrorResponseDecoder) PrintNameOffset() uint16 {
	return le.Uint16(res[20:22])
}

func (res SymbolicLinkErrorResponseDecoder) PrintNameLength() uint16 {
	return le.Uint16(res[22:24])
}

func (res SymbolicLinkErrorResponseDecoder) Flags() uint32 {
	return le.Uint32(res[24:28])
}

func (res SymbolicLinkErrorResponseDecoder) PathBuffer() []byte {
	return res[28:]
}

func (res SymbolicLinkErrorResponseDecoder) SubstituteName() []uint16 {
	off := res.SubstituteNameOffset()
	len := res.SubstituteNameLength()
	return BytesToUTF16(res.PathBuffer()[off : off+len])
}

func (res SymbolicLinkErrorResponseDecoder) PrintName() []uint16 {
	off := res.PrintNameOffset()
	len := res.PrintNameLength()
	return BytesToUTF16(res.PathBuffer()[off : off+len])
}

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Response
//

type NegotiateResponseDecoder []byte

func (res NegotiateResponseDecoder) IsInvalid() bool {
	if len(res) < 64 {
		return true
	}

	if res.StructureSize() != 65 {
		return true
	}

	if len(res) < int(res.SecurityBufferOffset()+res.SecurityBufferLength())-64 {
		return true
	}

	if len(res) < int(res.NegotiateContextOffset())-64 {
		return true
	}

	return false
}

func (res NegotiateResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res NegotiateResponseDecoder) SecurityMode() uint16 {
	return le.Uint16(res[2:4])
}

func (res NegotiateResponseDecoder) DialectRevision() uint16 {
	return le.Uint16(res[4:6])
}

func (res NegotiateResponseDecoder) ServerGuid() []byte {
	return res[8:24]
}

func (res NegotiateResponseDecoder) Capabilities() uint32 {
	return le.Uint32(res[24:28])
}

func (res NegotiateResponseDecoder) MaxTransactSize() uint32 {
	return le.Uint32(res[28:32])
}

func (res NegotiateResponseDecoder) MaxReadSize() uint32 {
	return le.Uint32(res[32:36])
}

func (res NegotiateResponseDecoder) MaxWriteSize() uint32 {
	return le.Uint32(res[36:40])
}

func (res NegotiateResponseDecoder) SystemTime() FiletimeDecoder {
	return FiletimeDecoder(res[40:48])
}

func (res NegotiateResponseDecoder) ServerStartTime() FiletimeDecoder {
	return FiletimeDecoder(res[48:56])
}

func (res NegotiateResponseDecoder) SecurityBufferOffset() uint16 {
	return le.Uint16(res[56:58])
}

func (res NegotiateResponseDecoder) SecurityBufferLength() uint16 {
	return le.Uint16(res[58:60])
}

// func (res NegotiateResponseDecoder) Buffer() []byte {
// return res[64:]
// }

func (res NegotiateResponseDecoder) SecurityBuffer() []byte {
	off := res.SecurityBufferOffset()
	if off < 64+64 {
		return nil
	}
	off -= 64
	len := res.SecurityBufferLength()
	return res[off : off+len]
}

// From SMB311

func (res NegotiateResponseDecoder) NegotiateContextCount() uint16 {
	return le.Uint16(res[6:8])
}

func (res NegotiateResponseDecoder) NegotiateContextOffset() uint32 {
	return le.Uint32(res[60:64])
}

func (res NegotiateResponseDecoder) NegotiateContextList() []byte {
	off := res.NegotiateContextOffset()
	if off < 64 {
		return nil
	}
	return res[off-64:]
}

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Context
//

// From SMB311

type NegotiateContextDecoder []byte

func (ctx NegotiateContextDecoder) IsInvalid() bool {
	if len(ctx) < 8 {
		return true
	}

	if len(ctx) < 8+int(ctx.DataLength()) {
		return true
	}

	return false
}

func (ctx NegotiateContextDecoder) ContextType() uint16 {
	return le.Uint16(ctx[:2])
}

func (ctx NegotiateContextDecoder) DataLength() uint16 {
	return le.Uint16(ctx[2:4])
}

func (ctx NegotiateContextDecoder) Data() []byte {
	len := ctx.DataLength()
	return ctx[8 : 8+len]
}

func (ctx NegotiateContextDecoder) Next() int {
	return Roundup(8+int(ctx.DataLength()), 8)
}

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Contexts
//

// From SMB311

type HashContextDataDecoder []byte

func (h HashContextDataDecoder) IsInvalid() bool {
	if len(h) < 4 {
		return true
	}

	if len(h) < 4+int(h.HashAlgorithmCount())*2+int(h.SaltLength()) {
		return true
	}

	return false
}

func (h HashContextDataDecoder) HashAlgorithmCount() uint16 {
	return le.Uint16(h[:2])
}

func (h HashContextDataDecoder) SaltLength() uint16 {
	return le.Uint16(h[2:4])
}

func (h HashContextDataDecoder) HashAlgorithms() []uint16 {
	bs := h[4:]
	algs := make([]uint16, h.HashAlgorithmCount())
	for i := range algs {
		algs[i] = le.Uint16(bs[2*i : 2*i+2])
	}
	return algs
}

func (h HashContextDataDecoder) Salt() []byte {
	off := 4 + h.HashAlgorithmCount()*2
	len := h.SaltLength()
	return h[off : off+len]
}

type CipherContextDataDecoder []byte

func (c CipherContextDataDecoder) IsInvalid() bool {
	if len(c) < 2 {
		return true
	}

	if len(c) < 2+int(c.CipherCount())*2 {
		return true
	}

	return false
}

func (c CipherContextDataDecoder) CipherCount() uint16 {
	return le.Uint16(c[:2])
}

func (c CipherContextDataDecoder) Ciphers() []uint16 {
	bs := c[2:]
	cs := make([]uint16, c.CipherCount())
	for i := range cs {
		cs[i] = le.Uint16(bs[2*i : 2*i+2])
	}
	return cs
}

// ----------------------------------------------------------------------------
// SMB2 SESSION_SETUP Response
//

type SessionSetupResponseDecoder []byte

func (res SessionSetupResponseDecoder) IsInvalid() bool {
	if len(res) < 8 {
		return true
	}

	if res.StructureSize() != 9 {
		return true
	}

	if len(res) < int(res.SecurityBufferOffset()+res.SecurityBufferLength())-64 {
		return true
	}

	return false
}

func (res SessionSetupResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res SessionSetupResponseDecoder) SessionFlags() uint16 {
	return le.Uint16(res[2:4])
}

func (res SessionSetupResponseDecoder) SecurityBufferOffset() uint16 {
	return le.Uint16(res[4:6])
}

func (res SessionSetupResponseDecoder) SecurityBufferLength() uint16 {
	return le.Uint16(res[6:8])
}

// func (req SessionSetupResponseDecoder) Buffer() []byte {
// return req[8:]
// }

func (res SessionSetupResponseDecoder) SecurityBuffer() []byte {
	off := res.SecurityBufferOffset()
	if off < 8+64 {
		return nil
	}
	off -= 64
	len := res.SecurityBufferLength()
	return res[off : off+len]
}

// ----------------------------------------------------------------------------
// SMB2 LOGOFF Response
//

type LogoffResponseDecoder []byte

func (res LogoffResponseDecoder) IsInvalid() bool {
	if len(res) < 4 {
		return true
	}

	if res.StructureSize() != 4 {
		return true
	}

	return false
}

func (res LogoffResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

// ----------------------------------------------------------------------------
// SMB2 TREE_CONNECT Response
//

type TreeConnectResponseDecoder []byte

func (res TreeConnectResponseDecoder) IsInvalid() bool {
	if len(res) < 16 {
		return true
	}

	if res.StructureSize() != 16 {
		return true
	}

	return false
}

func (res TreeConnectResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res TreeConnectResponseDecoder) ShareType() uint8 {
	return res[2]
}

func (res TreeConnectResponseDecoder) ShareFlags() uint32 {
	return le.Uint32(res[4:8])
}

func (res TreeConnectResponseDecoder) Capabilities() uint32 {
	return le.Uint32(res[8:12])
}

func (res TreeConnectResponseDecoder) MaximalAccess() uint32 {
	return le.Uint32(res[12:16])
}

// ----------------------------------------------------------------------------
// SMB2 TREE_DISCONNECT Response
//

type TreeDisconnectResponseDecoder []byte

func (res TreeDisconnectResponseDecoder) IsInvalid() bool {
	if len(res) < 4 {
		return true
	}

	if res.StructureSize() != 4 {
		return true
	}

	return false
}

func (res TreeDisconnectResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

// ----------------------------------------------------------------------------
// SMB2 CREATE Response
//

type CreateResponseDecoder []byte

func (res CreateResponseDecoder) IsInvalid() bool {
	if len(res) < 88 {
		return true
	}

	if res.StructureSize() != 89 {
		return true
	}

	if len(res) < int(res.CreateContextsOffset()+res.CreateContextsLength())-64 {
		return true
	}

	return false
}

func (res CreateResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res CreateResponseDecoder) OplockLevel() uint8 {
	return res[2]
}

func (res CreateResponseDecoder) Flags() uint8 {
	return res[3]
}

func (res CreateResponseDecoder) CreateAction() uint32 {
	return le.Uint32(res[4:8])
}

func (res CreateResponseDecoder) CreationTime() FiletimeDecoder {
	return FiletimeDecoder(res[8:16])
}

func (res CreateResponseDecoder) LastAccessTime() FiletimeDecoder {
	return FiletimeDecoder(res[16:24])
}

func (res CreateResponseDecoder) LastWriteTime() FiletimeDecoder {
	return FiletimeDecoder(res[24:32])
}

func (res CreateResponseDecoder) ChangeTime() FiletimeDecoder {
	return FiletimeDecoder(res[32:40])
}

func (res CreateResponseDecoder) AllocationSize() int64 {
	return int64(le.Uint64(res[40:48]))
}

func (res CreateResponseDecoder) EndofFile() int64 {
	return int64(le.Uint64(res[48:56]))
}

func (res CreateResponseDecoder) FileAttributes() uint32 {
	return le.Uint32(res[56:60])
}

func (res CreateResponseDecoder) FileId() FileIdDecoder {
	return FileIdDecoder(res[64:80])
}

func (res CreateResponseDecoder) CreateContextsOffset() uint32 {
	return le.Uint32(res[80:84])
}

func (res CreateResponseDecoder) CreateContextsLength() uint32 {
	return le.Uint32(res[84:88])
}

// func (res CreateResponseDecoder) Buffer() []byte {
// return res[88:]
// }

func (res CreateResponseDecoder) CreateContexts() []byte {
	off := res.CreateContextsOffset()
	if off < 88+64 {
		return nil
	}
	off -= 64
	len := res.CreateContextsLength()
	return res[off : off+len]
}

// ----------------------------------------------------------------------------
// SMB2 CLOSE Response
//

type CloseResponseDecoder []byte

func (res CloseResponseDecoder) IsInvalid() bool {
	if len(res) < 60 {
		return true
	}

	if res.StructureSize() != 60 {
		return true
	}

	return false
}

func (res CloseResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res CloseResponseDecoder) Flags() uint16 {
	return le.Uint16(res[2:4])
}

func (res CloseResponseDecoder) CreationTime() FiletimeDecoder {
	return FiletimeDecoder(res[8:16])
}

func (res CloseResponseDecoder) LastAccessTime() FiletimeDecoder {
	return FiletimeDecoder(res[16:24])
}

func (res CloseResponseDecoder) LastWriteTime() FiletimeDecoder {
	return FiletimeDecoder(res[24:32])
}

func (res CloseResponseDecoder) ChangeTime() FiletimeDecoder {
	return FiletimeDecoder(res[32:40])
}

func (res CloseResponseDecoder) AllocationSize() int64 {
	return int64(le.Uint64(res[40:48]))
}

func (res CloseResponseDecoder) EndofFile() int64 {
	return int64(le.Uint64(res[48:56]))
}

func (res CloseResponseDecoder) FileAttributes() uint32 {
	return le.Uint32(res[56:60])
}

// ----------------------------------------------------------------------------
// SMB2 FLUSH Response
//

type FlushResponseDecoder []byte

func (res FlushResponseDecoder) IsInvalid() bool {
	if len(res) < 4 {
		return true
	}

	if res.StructureSize() != 4 {
		return true
	}

	return false
}

func (res FlushResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

// ----------------------------------------------------------------------------
// SMB2 READ Response
//

type ReadResponseDecoder []byte

func (res ReadResponseDecoder) IsInvalid() bool {
	if len(res) < 16 {
		return true
	}

	if res.StructureSize() != 17 {
		return true
	}

	if len(res) < int(uint32(res.DataOffset())+res.DataLength())-64 {
		return true
	}

	return false
}

func (res ReadResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res ReadResponseDecoder) DataOffset() uint8 {
	return res[2]
}

func (res ReadResponseDecoder) DataLength() uint32 {
	return le.Uint32(res[4:8])
}

func (res ReadResponseDecoder) DataRemaining() uint32 {
	return le.Uint32(res[8:12])
}

// func (res ReadResponseDecoder) Buffer() []byte {
// return res[16:]
// }

func (res ReadResponseDecoder) Data() []byte {
	off := res.DataOffset()
	if off < 16+64 {
		return nil
	}
	off -= 64
	len := res.DataLength()
	return res[off : uint32(off)+len]
}

// ----------------------------------------------------------------------------
// SMB2 WRITE Response
//

type WriteResponseDecoder []byte

func (res WriteResponseDecoder) IsInvalid() bool {
	if len(res) < 16 {
		return true
	}

	if res.StructureSize() != 17 {
		return true
	}

	return false
}

func (res WriteResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res WriteResponseDecoder) Count() uint32 {
	return le.Uint32(res[4:8])
}

func (res WriteResponseDecoder) Remaining() uint32 {
	return le.Uint32(res[8:12])
}

func (res WriteResponseDecoder) WriteChannelInfoOffset() uint16 {
	return le.Uint16(res[12:14])
}

func (res WriteResponseDecoder) WriteChannelInfoLength() uint16 {
	return le.Uint16(res[14:16])
}

// ----------------------------------------------------------------------------
// SMB2 OPLOCK_BREAK Notification and Response
//

// ----------------------------------------------------------------------------
// SMB2 LOCK Response
//

// ----------------------------------------------------------------------------
// SMB2 ECHO Response
//

// ----------------------------------------------------------------------------
// SMB2 IOCTL Response
//

type IoctlResponseDecoder []byte

func (res IoctlResponseDecoder) IsInvalid() bool {
	if len(res) < 48 {
		return true
	}

	if res.StructureSize() != 49 {
		return true
	}

	if len(res) < int(res.InputOffset()+res.InputCount())-64 {
		return true
	}

	if len(res) < int(res.OutputOffset()+res.OutputCount())-64 {
		return true
	}

	return false
}

func (res IoctlResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res IoctlResponseDecoder) CtlCode() uint32 {
	return le.Uint32(res[4:8])
}

func (res IoctlResponseDecoder) FileId() FileIdDecoder {
	return FileIdDecoder(res[8:24])
}

func (res IoctlResponseDecoder) InputOffset() uint32 {
	return le.Uint32(res[24:28])
}

func (res IoctlResponseDecoder) InputCount() uint32 {
	return le.Uint32(res[28:32])
}

func (res IoctlResponseDecoder) OutputOffset() uint32 {
	return le.Uint32(res[32:36])
}

func (res IoctlResponseDecoder) OutputCount() uint32 {
	return le.Uint32(res[36:40])
}

func (res IoctlResponseDecoder) Flags() uint32 {
	return le.Uint32(res[40:44])
}

// func (res IoctlResponseDecoder) Buffer() []byte {
// return res[48:]
// }

func (res IoctlResponseDecoder) Input() []byte {
	off := res.InputOffset()
	if off < 64+48 {
		return nil
	}
	off -= 64
	len := res.InputCount()
	return res[off : off+len]
}

func (res IoctlResponseDecoder) Output() []byte {
	off := res.OutputOffset()
	if off < 64+48 {
		return nil
	}
	off -= 64
	len := res.OutputCount()
	return res[off : off+len]
}

// ----------------------------------------------------------------------------
// SMB2 QUERY_DIRECTORY Response
//

type QueryDirectoryResponseDecoder []byte

func (res QueryDirectoryResponseDecoder) IsInvalid() bool {
	if len(res) < 8 {
		return true
	}

	if res.StructureSize() != 9 {
		return true
	}

	if len(res) < int(uint32(res.OutputBufferOffset())+res.OutputBufferLength())-64 {
		return true
	}

	return false
}

func (res QueryDirectoryResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res QueryDirectoryResponseDecoder) OutputBufferOffset() uint16 {
	return le.Uint16(res[2:4])
}

func (res QueryDirectoryResponseDecoder) OutputBufferLength() uint32 {
	return le.Uint32(res[4:8])
}

// func (res QueryDirectoryResponseDecoder) Buffer() []byte {
// return res[8:]
// }

func (res QueryDirectoryResponseDecoder) OutputBuffer() []byte {
	off := res.OutputBufferOffset()
	if off < 64+8 {
		return nil
	}
	off -= 64
	len := res.OutputBufferLength()
	return res[off : uint32(off)+len]
}

// ----------------------------------------------------------------------------
// SMB2 CHANGE_NOTIFY Response
//

// ----------------------------------------------------------------------------
// SMB2 QUERY_INFO Response
//

type QueryInfoResponseDecoder []byte

func (res QueryInfoResponseDecoder) IsInvalid() bool {
	if len(res) < 8 {
		return true
	}

	if res.StructureSize() != 9 {
		return true
	}

	if len(res) < int(uint32(res.OutputBufferOffset())+res.OutputBufferLength())-64 {
		return true
	}

	return false
}

func (res QueryInfoResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}

func (res QueryInfoResponseDecoder) OutputBufferOffset() uint16 {
	return le.Uint16(res[2:4])
}

func (res QueryInfoResponseDecoder) OutputBufferLength() uint32 {
	return le.Uint32(res[4:8])
}

// func (res QueryInfoResponseDecoder) Buffer() []byte {
// return res[8:]
// }

func (res QueryInfoResponseDecoder) OutputBuffer() []byte {
	off := res.OutputBufferOffset()
	if off < 64+8 {
		return nil
	}
	off -= 64
	len := res.OutputBufferLength()
	return res[off : uint32(off)+len]
}

// ----------------------------------------------------------------------------
// SMB2 SET_INFO Response
//

type SetInfoResponseDecoder []byte

func (res SetInfoResponseDecoder) IsInvalid() bool {
	if len(res) < 2 {
		return true
	}

	if res.StructureSize() != 2 {
		return true
	}

	return false
}

func (res SetInfoResponseDecoder) StructureSize() uint16 {
	return le.Uint16(res[:2])
}
