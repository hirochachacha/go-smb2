package smb2

var zero [16]byte

// ----------------------------------------------------------------------------
// SMB2 FILEID
//

type FileId struct {
	Persistent [8]byte
	Volatile   [8]byte
}

func (fd *FileId) IsZero() bool {
	if fd == nil {
		return true
	}

	for _, b := range fd.Persistent[:] {
		if b != 0 {
			return false
		}
	}
	for _, b := range fd.Volatile[:] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (fd *FileId) Size() int {
	return 16
}

func (fd *FileId) Encode(p []byte) {
	if fd == nil {
		copy(p[:16], zero[:])
	} else {
		copy(p[:8], fd.Persistent[:])
		copy(p[8:16], fd.Volatile[:])
	}
}

// ----------------------------------------------------------------------------
// SMB2 Packet Header
//

type PacketHeader struct {
	CreditCharge    uint16
	ChannelSequence uint16
	Status          uint32
	CreditRequest   uint16
	Flags           uint32
	MessageId       uint64
	AsyncId         uint64
	TreeId          uint32
	SessionId       uint64
	Signature       []byte
}

func (hdr *PacketHeader) encodeHeader(pkt []byte, cmd uint16) {
	p := PacketCodec(pkt)

	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCreditCharge(hdr.CreditCharge)

	switch {
	case hdr.ChannelSequence != 0:
		p.SetChannelSequence(hdr.ChannelSequence)
	case hdr.Status != 0:
		p.SetStatus(hdr.Status)
	}

	p.SetCommand(cmd)

	p.SetCreditRequest(hdr.CreditRequest)
	p.SetFlags(hdr.Flags)
	p.SetMessageId(hdr.MessageId)

	switch {
	case hdr.TreeId != 0:
		p.SetTreeId(hdr.TreeId)
	case hdr.AsyncId != 0:
		p.SetAsyncId(hdr.AsyncId)
	}

	p.SetSessionId(hdr.SessionId)
	p.SetSignature(hdr.Signature)
}

// ----------------------------------------------------------------------------
// SMB2 Request Packet Interface
//

type Packet interface {
	Encoder

	Header() *PacketHeader
}

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Request Packet
//

type NegotiateRequest struct {
	PacketHeader

	SecurityMode   uint16
	Capabilities   uint32
	ClientGuid     [16]byte
	Dialects       []uint16
	HashAlgorithms []uint16
	HashSalt       []byte
	Ciphers        []uint16
}

func (c *NegotiateRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *NegotiateRequest) Size() int {
	size := 36 + len(c.Dialects)*2

	if len(c.HashAlgorithms) > 0 {
		size = Roundup(size, 8)

		size += 8 + 4 + len(c.HashAlgorithms)*2 + len(c.HashSalt)
	}

	if len(c.Ciphers) > 0 {
		size = Roundup(size, 8)

		size += 8 + 2 + len(c.Ciphers)*2
	}

	return 64 + size
}

func (c *NegotiateRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_NEGOTIATE)

	req := pkt[64:]
	le.PutUint16(req[:2], 36) // StructureSize
	le.PutUint16(req[4:6], c.SecurityMode)
	le.PutUint32(req[8:12], c.Capabilities)
	copy(req[12:28], c.ClientGuid[:])

	{
		bs := req[36:]
		for i, d := range c.Dialects {
			le.PutUint16(bs[2*i:2*i+2], d)
		}
		le.PutUint16(req[2:4], uint16(len(c.Dialects)))
	}

	count := 0
	off := 36 + len(c.Dialects)*2

	if len(c.HashAlgorithms) > 0 {
		off = Roundup(off, 8)

		le.PutUint32(req[28:32], uint32(off+64)) // NegotiateContextOffset

		ctx := req[off:]
		le.PutUint16(ctx[:2], SMB2_PREAUTH_INTEGRITY_CAPABILITIES)                // ContextType
		le.PutUint16(ctx[2:4], uint16(4+len(c.HashAlgorithms)*2+len(c.HashSalt))) // DataLength

		{
			d := NegotiateContextDecoder(ctx).Data()

			// HashAlgorithms
			{
				bs := d[4:]
				for i, alg := range c.HashAlgorithms {
					le.PutUint16(bs[2*i:2*i+2], alg)
				}
				le.PutUint16(d[:2], uint16(len(c.HashAlgorithms)))
			}

			// HashSalt
			{
				off := 4 + len(c.HashAlgorithms)*2
				copy(d[off:], c.HashSalt)
				le.PutUint16(d[2:4], uint16(len(c.HashSalt)))
			}
		}

		off += 8 + 4 + len(c.HashAlgorithms)*2 + len(c.HashSalt)

		count++
	}

	if len(c.Ciphers) > 0 {
		off = Roundup(off, 8)

		if count == 0 {
			le.PutUint32(req[28:32], uint32(off+64)) // NegotiateContextOffset
		}

		ctx := req[off:]
		le.PutUint16(ctx[:2], SMB2_ENCRYPTION_CAPABILITIES) // ContextType
		le.PutUint16(ctx[2:4], uint16(2+len(c.Ciphers)*2))  // DataLength

		{
			d := NegotiateContextDecoder(ctx).Data()

			{ // Ciphers
				bs := d[2:]
				for i, c := range c.Ciphers {
					le.PutUint16(bs[2*i:2*i+2], c)
				}
				le.PutUint16(d[:2], uint16(len(c.Ciphers))) // CipherCount
			}
		}

		off += 8 + 2 + len(c.Ciphers)*2

		count++
	}

	if count > 0 {
		le.PutUint16(req[32:34], uint16(count)) // NegotiateContextCount
	}
}

// ----------------------------------------------------------------------------
// SMB2 SESSION_SETUP Request Packet
//

type SessionSetupRequest struct {
	PacketHeader

	Flags             uint8
	SecurityMode      uint8
	Capabilities      uint32
	Channel           uint32
	SecurityBuffer    []byte
	PreviousSessionId uint64
}

func (c *SessionSetupRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *SessionSetupRequest) Size() int {
	return 64 + 24 + len(c.SecurityBuffer)
}

func (c *SessionSetupRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_SESSION_SETUP)

	req := pkt[64:]
	le.PutUint16(req[:2], 25)
	req[2] = c.Flags
	req[3] = c.SecurityMode
	le.PutUint32(req[4:8], c.Capabilities)
	le.PutUint32(req[8:12], c.Channel)
	le.PutUint64(req[16:24], c.PreviousSessionId)

	// SecurityBuffer
	{
		copy(req[24:], c.SecurityBuffer)
		le.PutUint16(req[12:14], 64+24)                         // SecurityBufferOffset
		le.PutUint16(req[14:16], uint16(len(c.SecurityBuffer))) // SecurityBufferLength
	}
}

// ----------------------------------------------------------------------------
// SMB2 LOGOFF Request Packet
//

type LogoffRequest struct {
	PacketHeader
}

func (c *LogoffRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *LogoffRequest) Size() int {
	return 64 + 4
}

func (c *LogoffRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_LOGOFF)

	req := pkt[64:]
	le.PutUint16(req[:2], 4) // StructureSize
}

// ----------------------------------------------------------------------------
// SMB2 TREE_CONNECT Request Packet
//

type TreeConnectRequest struct {
	PacketHeader

	Flags uint16
	Path  []uint16
}

func (c *TreeConnectRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *TreeConnectRequest) Size() int {
	if len(c.Path) == 0 {
		return 64 + 8 + 1
	}

	return 64 + 8 + len(c.Path)*2
}

func (c *TreeConnectRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_TREE_CONNECT)

	req := pkt[64:]
	le.PutUint16(req[:2], 9) // StructureSize
	le.PutUint16(req[2:4], c.Flags)

	// Path
	{
		PutUTF16(req[8:], c.Path)

		le.PutUint16(req[4:6], 8+64)                  // PathOffset
		le.PutUint16(req[6:8], uint16(len(c.Path)*2)) // PathLength
	}
}

// ----------------------------------------------------------------------------
// SMB2 TREE_DISCONNECT Request Packet
//

type TreeDisconnectRequest struct {
	PacketHeader
}

func (c *TreeDisconnectRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *TreeDisconnectRequest) Size() int {
	return 64 + 4
}

func (c *TreeDisconnectRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_TREE_DISCONNECT)

	req := pkt[64:]
	le.PutUint16(req[:2], 4) // StructureSize
}

// ----------------------------------------------------------------------------
// SMB2 CREATE Request Packet
//

type CreateRequest struct {
	PacketHeader

	SecurityFlags        uint8
	RequestedOplockLevel uint8
	ImpersonationLevel   uint32
	SmbCreateFlags       uint64
	DesiredAccess        uint32
	FileAttributes       uint32
	ShareAccess          uint32
	CreateDisposition    uint32
	CreateOptions        uint32
	Name                 []uint16

	Contexts []Encoder
}

func (c *CreateRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *CreateRequest) Size() int {
	if len(c.Name) == 0 && len(c.Contexts) == 0 {
		return 64 + 56 + 1
	}

	size := 64 + 56 + len(c.Name)*2

	for _, ctx := range c.Contexts {
		size = Roundup(size, 8)
		size += ctx.Size()
	}

	return size
}

func (c *CreateRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_CREATE)

	req := pkt[64:]
	le.PutUint16(req[:2], 57) // StructureSize
	req[2] = c.SecurityFlags
	req[3] = c.RequestedOplockLevel
	le.PutUint32(req[4:8], c.ImpersonationLevel)
	le.PutUint64(req[8:16], c.SmbCreateFlags)
	le.PutUint32(req[24:28], c.DesiredAccess)
	le.PutUint32(req[28:32], c.FileAttributes)
	le.PutUint32(req[32:36], c.ShareAccess)
	le.PutUint32(req[36:40], c.CreateDisposition)
	le.PutUint32(req[40:44], c.CreateOptions)

	// Name
	{
		PutUTF16(req[56:], c.Name)

		le.PutUint16(req[44:46], 56+64)
		le.PutUint16(req[46:48], uint16(len(c.Name)*2))
	}

	off := 56 + len(c.Name)*2

	if len(c.Contexts) > 0 {
		off = Roundup(off, 8)

		le.PutUint32(req[48:52], uint32(64+off)) // CreateContextsOffset

		ctx := req[off:]

		c.Contexts[0].Encode(ctx)

		next := c.Contexts[0].Size()

		for _, c := range c.Contexts[1:] {
			next = Roundup(next, 8)

			le.PutUint32(ctx[:4], uint32(next)) // Next

			off += next

			ctx = req[off:]

			c.Encode(ctx)

			next = c.Size()
		}

		off += next

		le.PutUint32(req[52:56], uint32(off-(56+len(c.Name)*2))) // CreateContextsLength
	}
}

// ----------------------------------------------------------------------------
// SMB2 CLOSE Request Packet
//

type CloseRequest struct {
	PacketHeader

	Flags  uint16
	FileId *FileId
}

func (c *CloseRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *CloseRequest) Size() int {
	return 64 + 24
}

func (c *CloseRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_CLOSE)

	req := pkt[64:]
	le.PutUint16(req[:2], 24) // StructureSize
	le.PutUint16(req[2:4], c.Flags)
	c.FileId.Encode(req[8:24])
}

// ----------------------------------------------------------------------------
// SMB2 FLUSH Request Packet
//

type FlushRequest struct {
	PacketHeader

	FileId *FileId
}

func (c *FlushRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *FlushRequest) Size() int {
	return 64 + 24
}

func (c *FlushRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_FLUSH)

	req := pkt[64:]
	le.PutUint16(req[:2], 24) // StructureSize
	c.FileId.Encode(req[8:24])
}

// ----------------------------------------------------------------------------
// SMB2 READ Request Packet
//

type ReadRequest struct {
	PacketHeader

	Padding         uint8
	Flags           uint8
	Length          uint32
	Offset          uint64
	FileId          *FileId
	MinimumCount    uint32
	Channel         uint32
	RemainingBytes  uint32
	ReadChannelInfo []Encoder
}

func (c *ReadRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *ReadRequest) Size() int {
	if len(c.ReadChannelInfo) == 0 {
		return 64 + 48 + 1
	}

	size := 64 + 48
	for _, r := range c.ReadChannelInfo {
		size += r.Size()
	}
	return size
}

func (c *ReadRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_READ)

	req := pkt[64:]
	le.PutUint16(req[:2], 49)
	req[2] = c.Padding
	req[3] = c.Flags
	le.PutUint32(req[4:8], c.Length)
	le.PutUint64(req[8:16], c.Offset)
	c.FileId.Encode(req[16:32])
	le.PutUint32(req[32:36], c.MinimumCount)
	le.PutUint32(req[36:40], c.Channel)
	le.PutUint32(req[40:44], c.RemainingBytes)

	off := 48

	if len(c.ReadChannelInfo) > 0 {
		le.PutUint16(req[44:46], uint16(64+off)) // ReadChannelInfoOffset

		r := c.ReadChannelInfo[0]

		r.Encode(req[off:])

		off += r.Size()

		for _, r := range c.ReadChannelInfo[1:] {
			r.Encode(req[off:])

			off += r.Size()
		}

		le.PutUint16(req[46:48], uint16(off-48)) // ReadChannelInfoLength
	}
}

// ----------------------------------------------------------------------------
// SMB2 WRITE Request Packet
//

type WriteRequest struct {
	PacketHeader

	FileId           *FileId
	Flags            uint32
	Channel          uint32
	RemainingBytes   uint32
	Offset           uint64
	WriteChannelInfo []Encoder
	Data             []byte
}

func (c *WriteRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *WriteRequest) Size() int {
	if len(c.Data) == 0 && len(c.WriteChannelInfo) == 0 {
		return 64 + 48 + 1
	}

	off := 64 + 48

	for _, w := range c.WriteChannelInfo {
		off += w.Size()
	}

	off += len(c.Data)

	return off
}

func (c *WriteRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_WRITE)

	req := pkt[64:]
	le.PutUint16(req[:2], 49) // StructureSize
	le.PutUint64(req[8:16], c.Offset)
	c.FileId.Encode(req[16:32])
	le.PutUint32(req[32:36], c.Channel)
	le.PutUint32(req[36:40], c.RemainingBytes)
	le.PutUint32(req[44:48], c.Flags)

	off := 48

	if len(c.WriteChannelInfo) > 0 {
		le.PutUint16(req[40:42], uint16(64+off)) // WriteChannelInfoOffset

		w := c.WriteChannelInfo[0]

		w.Encode(req[off:])

		off += w.Size()

		for _, w := range c.WriteChannelInfo[1:] {
			w.Encode(req[off:])

			off += w.Size()
		}

		le.PutUint16(req[42:44], uint16(off-48)) // ReadChannelInfoLength
	}

	le.PutUint16(req[2:4], uint16(64+off)) // DataOffset

	copy(req[off:], c.Data)

	le.PutUint32(req[4:8], uint32(len(c.Data))) // Length
}

// ----------------------------------------------------------------------------
// SMB2 OPLOCK_BREAK Acknowledgement
//

// ----------------------------------------------------------------------------
// SMB2 LOCK Request Packet
//

// ----------------------------------------------------------------------------
// SMB2 ECHO Request Packet
//

// ----------------------------------------------------------------------------
// SMB2 CANCEL Request Packet
//

type CancelRequest struct {
	PacketHeader
}

func (c *CancelRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *CancelRequest) Size() int {
	return 64 + 4
}

func (c *CancelRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_CANCEL)

	req := pkt[64:]
	le.PutUint16(req[:2], 4) // StructureSize
}

// ----------------------------------------------------------------------------
// SMB2 IOCTL Request Packet
//

type IoctlRequest struct {
	PacketHeader

	CtlCode           uint32
	FileId            *FileId
	OutputOffset      uint32
	OutputCount       uint32
	MaxInputResponse  uint32
	MaxOutputResponse uint32
	Flags             uint32
	Input             Encoder
}

func (c *IoctlRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *IoctlRequest) Size() int {
	if c.Input == nil {
		return 64 + 56 + 1
	}

	return 64 + 56 + c.Input.Size()
}

func (c *IoctlRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_IOCTL)

	req := pkt[64:]
	le.PutUint16(req[:2], 57) // StructureSize
	le.PutUint32(req[4:8], c.CtlCode)
	c.FileId.Encode(req[8:24])
	le.PutUint32(req[32:36], c.MaxInputResponse)
	le.PutUint32(req[36:40], c.OutputOffset)
	le.PutUint32(req[40:44], c.OutputCount)
	le.PutUint32(req[44:48], c.MaxOutputResponse)
	le.PutUint32(req[48:52], c.Flags)

	if c.Input != nil {
		off := 56

		le.PutUint32(req[24:28], uint32(off+64)) // InputOffset

		c.Input.Encode(req[off:])

		le.PutUint32(req[28:32], uint32(c.Input.Size())) // InputCount
	}
}

// ----------------------------------------------------------------------------
// SMB2 QUERY_DIRECTORY Request Packet
//

type QueryDirectoryRequest struct {
	PacketHeader

	FileInfoClass      uint8
	Flags              uint8
	FileIndex          uint32
	FileId             *FileId
	OutputBufferLength uint32
	FileName           []uint16
}

func (c *QueryDirectoryRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *QueryDirectoryRequest) Size() int {
	if len(c.FileName) == 0 {
		return 64 + 32 + 1
	}

	return 64 + 32 + len(c.FileName)*2
}

func (c *QueryDirectoryRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_QUERY_DIRECTORY)

	req := pkt[64:]
	le.PutUint16(req[:2], 33) // StructureSize
	req[2] = c.FileInfoClass
	req[3] = c.Flags
	le.PutUint32(req[4:8], c.FileIndex)
	c.FileId.Encode(req[8:24])
	le.PutUint32(req[28:32], c.OutputBufferLength)

	off := 32

	le.PutUint16(req[24:26], uint16(off+64)) // FileNameOffset

	PutUTF16(req[off:], c.FileName)

	le.PutUint16(req[26:28], uint16(len(c.FileName)*2)) // FileNameLength
}

// ----------------------------------------------------------------------------
// SMB2 CHANGE_NOTIFY Request Packet
//

// ----------------------------------------------------------------------------
// SMB2 QUERY_INFO Request Packet
//

type QueryInfoRequest struct {
	PacketHeader

	InfoType              uint8
	FileInfoClass         uint8
	OutputBufferLength    uint32
	AdditionalInformation uint32
	Flags                 uint32
	FileId                *FileId
	Input                 Encoder
}

func (c *QueryInfoRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *QueryInfoRequest) Size() int {
	if c.Input == nil {
		return 64 + 40 + 1
	}

	return 64 + 40 + c.Input.Size()
}

func (c *QueryInfoRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_QUERY_INFO)

	req := pkt[64:]
	le.PutUint16(req[:2], 41) // StructureSize
	req[2] = c.InfoType
	req[3] = c.FileInfoClass
	le.PutUint32(req[4:8], c.OutputBufferLength)
	le.PutUint32(req[16:20], c.AdditionalInformation)
	le.PutUint32(req[20:24], c.Flags)
	c.FileId.Encode(req[24:40])

	off := 40

	if c.Input != nil {
		le.PutUint16(req[8:10], uint16(off+64)) // InputBufferOffset

		c.Input.Encode(req[off:])

		le.PutUint32(req[12:16], uint32(c.Input.Size())) // InputBufferLength
	}
}

// ----------------------------------------------------------------------------
// SMB2 SET_INFO Request Packet
//

type SetInfoRequest struct {
	PacketHeader

	InfoType              uint8
	FileInfoClass         uint8
	AdditionalInformation uint32
	FileId                *FileId
	Input                 Encoder
}

func (c *SetInfoRequest) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *SetInfoRequest) Size() int {
	if c.Input == nil {
		return 64 + 32 + 1
	}

	return 64 + 32 + c.Input.Size()
}

func (c *SetInfoRequest) Encode(pkt []byte) {
	c.encodeHeader(pkt, SMB2_SET_INFO)

	req := pkt[64:]
	le.PutUint16(req[:2], 33) // StructureSize
	req[2] = c.InfoType
	req[3] = c.FileInfoClass
	le.PutUint32(req[12:16], c.AdditionalInformation)
	c.FileId.Encode(req[16:32])

	off := 32

	if c.Input != nil {
		le.PutUint16(req[8:10], uint16(off+64)) // BufferOffset

		c.Input.Encode(req[off:])

		le.PutUint32(req[4:8], uint32(c.Input.Size())) // BufferLength
	}
}
