package msrpc

import (
	"fmt"
	"io/fs"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/security"
)

const policyLookupNames = 0x00000800

// PolicyHandle is an LSAPR_HANDLE context handle.
type PolicyHandle [20]byte

func NewLsarCall(callID uint32, opnum uint16, stub []byte) (*Call, error) {
	if len(stub) > DefaultMaxFragmentSize-HeaderSize {
		return nil, fmt.Errorf("LSARPC request exceeds one RPC fragment: %w", fs.ErrInvalid)
	}
	return &Call{CallId: callID, Opnum: opnum, Stub: stub}, nil
}

func OpenPolicy2Stub() []byte {
	enc := NewEncoder()
	enc.WriteUint32(0) // SystemName: NULL
	enc.WriteUint32(0) // ObjectAttributes.Length
	enc.WriteUint32(0) // RootDirectory: NULL
	enc.WriteUint32(0) // ObjectName: NULL
	enc.WriteUint32(0) // Attributes
	enc.WriteUint32(0) // SecurityDescriptor: NULL
	enc.WriteUint32(0) // SecurityQualityOfService: NULL
	enc.WriteUint32(policyLookupNames)
	return enc.Bytes()
}

func ClosePolicyStub(handle PolicyHandle) []byte {
	return handle[:]
}

func lookupNamesStub(handle PolicyHandle, names []string) ([]byte, error) {
	if len(names) == 0 || len(names) > 1000 {
		return nil, fs.ErrInvalid
	}
	enc := NewEncoder()
	enc.WriteBytes(handle[:])
	enc.WriteUint32(uint32(len(names)))
	enc.WriteUint32(uint32(len(names))) // conformant Names array
	for i, name := range names {
		n := utf16le.EncodedStringLen(name)
		if n > 0xfffe {
			return nil, fs.ErrInvalid
		}
		enc.WriteUint16(uint16(n))
		enc.WriteUint16(uint16(n))
		if n == 0 {
			enc.WriteUint32(0)
		} else {
			enc.WriteUint32(uint32(0x20000 + 4*i))
		}
	}
	if enc.Len() > DefaultMaxFragmentSize-HeaderSize {
		return nil, fs.ErrInvalid
	}
	for _, name := range names {
		n := utf16le.EncodedStringLen(name)
		if n == 0 {
			continue
		}
		if n > DefaultMaxFragmentSize-HeaderSize-enc.Len()-28 {
			return nil, fs.ErrInvalid
		}
		enc.WriteUint32(uint32(n / 2)) // MaxCount
		enc.WriteUint32(0)             // Offset
		enc.WriteUint32(uint32(n / 2)) // ActualCount
		enc.WriteBytes(utf16le.EncodeStringToBytes(name))
		enc.Align(4)
	}
	enc.WriteUint32(0) // TranslatedSids.Entries
	enc.WriteUint32(0) // TranslatedSids.Sids: NULL
	enc.WriteUint32(1) // LsapLookupWksta
	enc.WriteUint32(0) // MappedCount
	if enc.Len() > DefaultMaxFragmentSize-HeaderSize {
		return nil, fs.ErrInvalid
	}
	return enc.Bytes(), nil
}

func LookupNames3Stub(handle PolicyHandle, names []string) ([]byte, error) {
	stub, err := lookupNamesStub(handle, names)
	if err != nil {
		return nil, err
	}
	if len(stub) > DefaultMaxFragmentSize-HeaderSize-8 {
		return nil, fs.ErrInvalid
	}
	enc := NewEncoder()
	enc.WriteBytes(stub)
	enc.WriteUint32(0) // LookupOptions: search all scopes
	enc.WriteUint32(2) // ClientRevision: understands DNS domain names
	return enc.Bytes(), nil
}

func GetUserNameStub() []byte {
	enc := NewEncoder()
	enc.WriteUint32(0)       // SystemName: NULL
	enc.WriteUint32(0)       // UserName: NULL on input
	enc.WriteUint32(0x20000) // DomainName: non-NULL pointer
	enc.WriteUint32(0)       // DomainName: NULL on input
	return enc.Bytes()
}

func LookupSidsStub(handle PolicyHandle, sids []*security.SID) ([]byte, error) {
	if len(sids) == 0 || len(sids) > 20480 {
		return nil, fs.ErrInvalid
	}
	enc := NewEncoder()
	enc.WriteBytes(handle[:])
	enc.WriteUint32(uint32(len(sids)))
	enc.WriteUint32(0x20000)           // SidInfo array pointer
	enc.WriteUint32(uint32(len(sids))) // conformant array
	for i, sid := range sids {
		if sid == nil || sid.Revision != 1 || sid.IdentifierAuthority > 0xffffffffffff || len(sid.SubAuthority) > 15 {
			return nil, fs.ErrInvalid
		}
		enc.WriteUint32(uint32(0x20004 + 4*i))
	}
	if enc.Len() > DefaultMaxFragmentSize-HeaderSize {
		return nil, fs.ErrInvalid
	}
	for _, sid := range sids {
		if sid.Size() > DefaultMaxFragmentSize-HeaderSize-enc.Len()-20 {
			return nil, fs.ErrInvalid
		}
		enc.WriteUint32(uint32(len(sid.SubAuthority))) // conformant RPC_SID
		buf := make([]byte, sid.Size())
		sid.Encode(buf)
		enc.WriteBytes(buf)
	}
	enc.WriteUint32(0) // TranslatedNames.Entries
	enc.WriteUint32(0) // TranslatedNames.Names: NULL
	enc.WriteUint32(1) // LsapLookupWksta
	enc.WriteUint32(0) // MappedCount
	if enc.Len() > DefaultMaxFragmentSize-HeaderSize {
		return nil, fs.ErrInvalid
	}
	return enc.Bytes(), nil
}
