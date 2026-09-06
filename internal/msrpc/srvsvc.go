package msrpc

import (
	"errors"
)


// NetShareEnumAllRequest represents an MS-SRVS NetrShareEnum request (Opnum 15).
type NetShareEnumAllRequest struct {
	CallId     uint32
	ServerName string
	Level      uint32
}

func (r *NetShareEnumAllRequest) Size() int {
	// PDU Header: 24 bytes
	// ServerName: 4 (ptr) + 12 (str header) + 2 * (len+1) + align
	// InfoStruct: 4 (Level) + 4 (switch Level) + 4 (ctr ptr) + 4 (EntriesRead) + 4 (Buffer ptr) + 4 (max buffer)
	// ResumeHandle: 4 (null ptr)
	enc := NewEncoder()
	r.encodeStub(enc)
	return HeaderSize + enc.Len()
}

func (r *NetShareEnumAllRequest) encodeStub(enc *Encoder) {
	// ServerName: [in, string, unique] SRVSVC_HANDLE ServerName
	enc.WriteUint32(0x00020000) // Referent ID
	enc.WriteConformantVaryingString(r.ServerName)

	// InfoStruct: [in, out] LPSHARE_ENUM_STRUCT InfoStruct
	// SHARE_ENUM_STRUCT: Level + switch_is(Level) SHARE_ENUM_UNION
	enc.WriteUint32(r.Level) // Level
	// Union: discriminant + arm
	enc.WriteUint32(r.Level)    // discriminant
	enc.WriteUint32(0x00020004) // Referent ID to SHARE_INFO_X_CONTAINER
	// Container: EntriesRead = 0, Buffer = NULL
	enc.WriteUint32(0) // EntriesRead
	enc.WriteUint32(0) // Buffer (NULL pointer)

	// PreferedMaximumLength: [in] DWORD PreferedMaximumLength (MAX_PREFERRED_LENGTH = 0xFFFFFFFF)
	enc.WriteUint32(0xFFFFFFFF)

	// ResumeHandle: [in, out, unique] DWORD* ResumeHandle (NULL pointer = 0)
	enc.WriteUint32(0)
}

func (r *NetShareEnumAllRequest) Encode(b []byte) {
	enc := NewEncoder()
	r.encodeStub(enc)
	stub := enc.Bytes()

	totalLen := uint16(HeaderSize + len(stub))

	// Common header (16 bytes)
	encodeCommonHeader(b, RPC_TYPE_REQUEST, RPC_PACKET_FLAG_FIRST|RPC_PACKET_FLAG_LAST, totalLen, 0, r.CallId)

	// Request header (8 bytes)
	le.PutUint32(b[16:20], uint32(len(stub))) // alloc_hint
	le.PutUint16(b[20:22], 0)                 // context_id
	le.PutUint16(b[22:24], OP_NET_SHARE_ENUM) // opnum

	// Stub data
	copy(b[HeaderSize:], stub)
}

// NetShareEnumAllResponseDecoder decodes an MS-SRVS NetrShareEnum response PDU.
type NetShareEnumAllResponseDecoder []byte

func (c NetShareEnumAllResponseDecoder) IsInvalid() bool {
	hdr := CommonHeaderDecoder(c)
	if hdr.IsInvalidCommon(HeaderSize) {
		return true
	}
	if hdr.PacketType() != RPC_TYPE_RESPONSE {
		return true
	}
	fragLength := hdr.FragLength()
	if fragLength < HeaderSize || fragLength > DefaultMaxFragmentSize {
		return true
	}
	return false
}

func (c NetShareEnumAllResponseDecoder) Version() uint8 {
	return CommonHeaderDecoder(c).Version()
}

func (c NetShareEnumAllResponseDecoder) VersionMinor() uint8 {
	return CommonHeaderDecoder(c).VersionMinor()
}

func (c NetShareEnumAllResponseDecoder) PacketType() uint8 {
	return CommonHeaderDecoder(c).PacketType()
}

func (c NetShareEnumAllResponseDecoder) PacketFlags() uint8 {
	return CommonHeaderDecoder(c).PacketFlags()
}

func (c NetShareEnumAllResponseDecoder) DataRepresentation() []byte {
	return CommonHeaderDecoder(c).DataRepresentation()
}

func (c NetShareEnumAllResponseDecoder) FragLength() uint16 {
	return CommonHeaderDecoder(c).FragLength()
}

func (c NetShareEnumAllResponseDecoder) AuthLength() uint16 {
	return CommonHeaderDecoder(c).AuthLength()
}

func (c NetShareEnumAllResponseDecoder) CallId() uint32 {
	return CommonHeaderDecoder(c).CallId()
}

func (c NetShareEnumAllResponseDecoder) AllocHint() uint32 {
	if len(c) < 20 {
		return 0
	}
	return le.Uint32(c[16:20])
}

func (c NetShareEnumAllResponseDecoder) ContextId() uint16 {
	if len(c) < 22 {
		return 0
	}
	return le.Uint16(c[20:22])
}

func (c NetShareEnumAllResponseDecoder) CancelCount() uint8 {
	if len(c) < 23 {
		return 0
	}
	return c[22]
}

func (c NetShareEnumAllResponseDecoder) Buffer() []byte {
	if len(c) < HeaderSize {
		return nil
	}
	return c[HeaderSize:]
}

// ShareInfo represents information about a shared resource.
type ShareInfo struct {
	Name    string
	Type    uint32
	Comment string
}

func (c NetShareEnumAllResponseDecoder) ShareInfos() ([]ShareInfo, error) {
	if len(c) < HeaderSize+24 {
		return nil, errBufferTooSmall
	}

	stub := c[HeaderSize:]
	dec := NewDecoder(stub)

	level, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}

	// switch_is(Level)
	if _, err := dec.ReadUint32(); err != nil {
		return nil, err
	}

	// container pointer
	if _, err := dec.ReadUint32(); err != nil {
		return nil, err
	}

	// EntriesRead
	entriesRead, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	if entriesRead > 65536 {
		return nil, errInvalidCount
	}

	count := int(entriesRead)
	if count == 0 {
		return []ShareInfo{}, nil
	}

	// buffer pointer
	if _, err := dec.ReadUint32(); err != nil {
		return nil, err
	}

	// array max count
	if _, err := dec.ReadUint32(); err != nil {
		return nil, err
	}

	infos := make([]ShareInfo, count)

	switch level {
	case 0:
		for i := 0; i < count; i++ {
			if _, err := dec.ReadUint32(); err != nil {
				return nil, err
			}
		}

		for i := 0; i < count; i++ {
			name, err := dec.ReadConformantVaryingString()
			if err != nil {
				return nil, err
			}
			infos[i].Name = name
		}
	case 1:
		type inline1 struct {
			namePtr   uint32
			typ       uint32
			remarkPtr uint32
		}
		items := make([]inline1, count)
		for i := 0; i < count; i++ {
			namePtr, err := dec.ReadUint32()
			if err != nil {
				return nil, err
			}
			typ, err := dec.ReadUint32()
			if err != nil {
				return nil, err
			}
			remarkPtr, err := dec.ReadUint32()
			if err != nil {
				return nil, err
			}
			items[i] = inline1{namePtr: namePtr, typ: typ, remarkPtr: remarkPtr}
		}

		for i := 0; i < count; i++ {
			name, err := dec.ReadConformantVaryingString()
			if err != nil {
				return nil, err
			}
			infos[i].Name = name
			infos[i].Type = items[i].typ

			if items[i].remarkPtr != 0 {
				remark, err := dec.ReadConformantVaryingString()
				if err != nil {
					return nil, err
				}
				infos[i].Comment = remark
			}
		}
	default:
		return nil, errors.New("msrpc: unsupported share info level")
	}

	return infos, nil
}

// Sharenames returns the list of share names.
func (c NetShareEnumAllResponseDecoder) Sharenames() ([]string, error) {
	infos, err := c.ShareInfos()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(infos))
	for i, info := range infos {
		names[i] = info.Name
	}
	return names, nil
}

