package msrpc

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/security"
)

type TranslatedSID struct {
	Use    uint32
	SID    *security.SID
	Domain string
}

type TranslatedName struct {
	Use    uint32
	Name   string
	Domain string
}

type referencedDomain struct {
	name string
	sid  *security.SID
}

type rpcStringHeader struct {
	length  uint16
	maximum uint16
	pointer uint32
}

func ReadOpenPolicy2Response(stub []byte) (PolicyHandle, error) {
	var handle PolicyHandle
	if len(stub) < 4 {
		return handle, &InvalidResponseError{"short LsarOpenPolicy2 response"}
	}
	status := erref.NtStatus(le.Uint32(stub[len(stub)-4:]))
	if status != 0 {
		return handle, status
	}
	if len(stub) != len(handle)+4 {
		return handle, &InvalidResponseError{"invalid LsarOpenPolicy2 response length"}
	}
	copy(handle[:], stub[:len(handle)])
	if handle == (PolicyHandle{}) {
		return handle, &InvalidResponseError{"LsarOpenPolicy2 returned a null handle"}
	}
	return handle, nil
}

func ReadClosePolicyResponse(stub []byte) error {
	if len(stub) < 4 {
		return &InvalidResponseError{"short LsarClose response"}
	}
	status := erref.NtStatus(le.Uint32(stub[len(stub)-4:]))
	if status != 0 {
		return status
	}
	if len(stub) != 24 {
		return &InvalidResponseError{"invalid LsarClose response length"}
	}
	if PolicyHandle(stub[:20]) != (PolicyHandle{}) {
		return &InvalidResponseError{"LsarClose returned a non-null handle"}
	}
	return nil
}

func ReadGetUserNameResponse(stub []byte) (string, string, error) {
	if len(stub) < 4 {
		return "", "", &InvalidResponseError{"short LsarGetUserName response"}
	}
	status := erref.NtStatus(le.Uint32(stub[len(stub)-4:]))
	if status != 0 {
		return "", "", status
	}
	dec := NewDecoder(stub)
	userPointer, err := dec.ReadUint32()
	if err != nil || userPointer == 0 {
		return "", "", &InvalidResponseError{"missing user name"}
	}
	userHeader, err := readRPCStringHeader(dec)
	if err != nil {
		return "", "", &InvalidResponseError{fmt.Sprintf("invalid user name: %v", err)}
	}
	userName, err := readRPCString(dec, userHeader)
	if err != nil || userName == "" {
		return "", "", &InvalidResponseError{fmt.Sprintf("invalid user name: %v", err)}
	}
	domainPointer, err := dec.ReadUint32()
	if err != nil {
		return "", "", &InvalidResponseError{"missing domain name pointer"}
	}
	var domainName string
	if domainPointer != 0 {
		innerPointer, err := dec.ReadUint32()
		if err != nil {
			return "", "", &InvalidResponseError{"missing domain name"}
		}
		if innerPointer != 0 {
			domainHeader, err := readRPCStringHeader(dec)
			if err != nil {
				return "", "", &InvalidResponseError{fmt.Sprintf("invalid domain name: %v", err)}
			}
			domainName, err = readRPCString(dec, domainHeader)
			if err != nil {
				return "", "", &InvalidResponseError{fmt.Sprintf("invalid domain name: %v", err)}
			}
		}
	}
	if _, err := dec.ReadUint32(); err != nil || dec.Remaining() != 0 {
		return "", "", &InvalidResponseError{"invalid LsarGetUserName response tail"}
	}
	return userName, domainName, nil
}

func readRPCStringHeader(dec *Decoder) (rpcStringHeader, error) {
	length, err := dec.ReadUint16()
	if err != nil {
		return rpcStringHeader{}, err
	}
	maximum, err := dec.ReadUint16()
	if err != nil {
		return rpcStringHeader{}, err
	}
	pointer, err := dec.ReadUint32()
	if err != nil {
		return rpcStringHeader{}, err
	}
	if length%2 != 0 || maximum%2 != 0 || length > maximum || (length != 0 && pointer == 0) {
		return rpcStringHeader{}, errors.New("invalid RPC_UNICODE_STRING header")
	}
	return rpcStringHeader{length, maximum, pointer}, nil
}

func readRPCString(dec *Decoder, header rpcStringHeader) (string, error) {
	if header.pointer == 0 {
		return "", nil
	}
	maximum, err := dec.ReadUint32()
	if err != nil {
		return "", err
	}
	offset, err := dec.ReadUint32()
	if err != nil {
		return "", err
	}
	actual, err := dec.ReadUint32()
	if err != nil {
		return "", err
	}
	if maximum != uint32(header.maximum)/2 || offset != 0 || actual != uint32(header.length)/2 {
		return "", errors.New("invalid RPC_UNICODE_STRING array bounds")
	}
	raw, err := dec.ReadBytes(int(actual) * 2)
	if err != nil {
		return "", err
	}
	for i := 0; i < len(raw); i += 2 {
		u := binary.LittleEndian.Uint16(raw[i : i+2])
		if u == 0 {
			return "", errors.New("embedded null in RPC_UNICODE_STRING")
		}
		if 0xd800 <= u && u <= 0xdbff {
			if i+4 > len(raw) || binary.LittleEndian.Uint16(raw[i+2:i+4]) < 0xdc00 || binary.LittleEndian.Uint16(raw[i+2:i+4]) > 0xdfff {
				return "", errors.New("invalid UTF-16 surrogate pair")
			}
			i += 2
		} else if 0xdc00 <= u && u <= 0xdfff {
			return "", errors.New("unpaired UTF-16 surrogate")
		}
	}
	if err := dec.Align(4); err != nil {
		return "", err
	}
	return utf16le.DecodeToString(raw), nil
}

func readRPCSID(dec *Decoder) (*security.SID, error) {
	count, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	if count > 15 {
		return nil, errors.New("RPC_SID subauthority count exceeds 15")
	}
	fixed, err := dec.ReadBytes(8)
	if err != nil {
		return nil, err
	}
	if fixed[0] != 1 || uint32(fixed[1]) != count {
		return nil, errors.New("invalid RPC_SID revision or count")
	}
	sid := &security.SID{Revision: 1, SubAuthority: make([]uint32, count)}
	for _, b := range fixed[2:8] {
		sid.IdentifierAuthority = sid.IdentifierAuthority<<8 | uint64(b)
	}
	for i := range sid.SubAuthority {
		value, err := dec.ReadUint32()
		if err != nil {
			return nil, err
		}
		sid.SubAuthority[i] = value
	}
	return sid, nil
}

func readReferencedDomains(dec *Decoder) ([]referencedDomain, error) {
	pointer, err := dec.ReadUint32()
	if err != nil || pointer == 0 {
		return nil, err
	}
	entries, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	arrayPointer, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadUint32(); err != nil { // MaxEntries is unspecified.
		return nil, err
	}
	if entries > 1000 || (entries > 0 && arrayPointer == 0) {
		return nil, errors.New("invalid referenced domain count")
	}
	if arrayPointer == 0 {
		return nil, nil
	}
	arrayCount, err := dec.ReadUint32()
	if err != nil || arrayCount != entries {
		return nil, errors.New("referenced domain array count mismatch")
	}
	type domainHeader struct {
		name       rpcStringHeader
		sidPointer uint32
	}
	headers := make([]domainHeader, entries)
	for i := range headers {
		name, err := readRPCStringHeader(dec)
		if err != nil {
			return nil, err
		}
		sidPointer, err := dec.ReadUint32()
		if err != nil || sidPointer == 0 {
			return nil, errors.New("referenced domain has no SID")
		}
		headers[i] = domainHeader{name, sidPointer}
	}
	domains := make([]referencedDomain, entries)
	for i, header := range headers {
		name, err := readRPCString(dec, header.name)
		if err != nil {
			return nil, err
		}
		sid, err := readRPCSID(dec)
		if err != nil {
			return nil, err
		}
		domains[i] = referencedDomain{name, sid}
	}
	return domains, nil
}

func readLookupStatus(dec *Decoder, mapped, entries uint32) error {
	count, err := dec.ReadUint32()
	if err != nil {
		return err
	}
	statusValue, err := dec.ReadUint32()
	if err != nil || dec.Remaining() != 0 {
		return errors.New("invalid LSARPC lookup response tail")
	}
	if count != mapped || count > entries {
		return errors.New("LSARPC mapped count mismatch")
	}
	status := erref.NtStatus(statusValue)
	if status != 0 && status != erref.STATUS_SOME_NOT_MAPPED && status != erref.STATUS_NONE_MAPPED {
		return status
	}
	return nil
}

func ReadLookupNames3Response(stub []byte, expected int) ([]TranslatedSID, error) {
	if expected < 0 || expected > 1000 {
		return nil, &InvalidResponseError{"invalid expected translated SID count"}
	}
	if len(stub) < 4 {
		return nil, &InvalidResponseError{"short LsarLookupNames3 response"}
	}
	status := erref.NtStatus(le.Uint32(stub[len(stub)-4:]))
	if status != 0 && status != erref.STATUS_SOME_NOT_MAPPED && status != erref.STATUS_NONE_MAPPED {
		return nil, status
	}
	dec := NewDecoder(stub)
	domains, err := readReferencedDomains(dec)
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("invalid referenced domains: %v", err)}
	}
	entries, err := dec.ReadUint32()
	if err != nil {
		return nil, &InvalidResponseError{"short translated SID count"}
	}
	if entries != uint32(expected) {
		return nil, &InvalidResponseError{fmt.Sprintf("translated SID count mismatch: got %d, want %d", entries, expected)}
	}
	arrayPointer, err := dec.ReadUint32()
	if err != nil || (entries > 0 && arrayPointer == 0) {
		return nil, &InvalidResponseError{"missing translated SID array"}
	}
	arrayCount, err := dec.ReadUint32()
	if err != nil || arrayCount != entries {
		return nil, &InvalidResponseError{"translated SID array count mismatch"}
	}
	type sidHeader struct {
		use     uint32
		pointer uint32
		index   int32
	}
	headers := make([]sidHeader, entries)
	for i := range headers {
		use, err := dec.ReadUint32()
		if err != nil || use < 1 || use > 10 {
			return nil, &InvalidResponseError{fmt.Sprintf("invalid translated SID type at entry %d", i)}
		}
		pointer, err := dec.ReadUint32()
		if err != nil {
			return nil, &InvalidResponseError{"short translated SID pointer"}
		}
		indexValue, err := dec.ReadUint32()
		if err != nil {
			return nil, &InvalidResponseError{"short translated SID domain index"}
		}
		index := int32(indexValue)
		if index < -1 || (index >= 0 && int(index) >= len(domains)) {
			return nil, &InvalidResponseError{"invalid translated SID domain index"}
		}
		if _, err := dec.ReadUint32(); err != nil { // Flags
			return nil, &InvalidResponseError{"short translated SID flags"}
		}
		if use != 7 && use != 8 && pointer == 0 {
			return nil, &InvalidResponseError{"mapped SID has no value"}
		}
		headers[i] = sidHeader{use, pointer, index}
	}
	results := make([]TranslatedSID, entries)
	var mapped uint32
	for i, header := range headers {
		results[i].Use = header.use
		if header.index >= 0 {
			results[i].Domain = domains[header.index].name
		}
		if header.pointer != 0 {
			sid, err := readRPCSID(dec)
			if err != nil {
				return nil, &InvalidResponseError{fmt.Sprintf("invalid translated SID: %v", err)}
			}
			results[i].SID = sid
		}
		if header.use != 7 && header.use != 8 {
			mapped++
		}
	}
	if err := readLookupStatus(dec, mapped, entries); err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("invalid LsarLookupNames3 status: %v", err)}
	}
	return results, nil
}

func ReadLookupSidsResponse(stub []byte, expected int) ([]TranslatedName, error) {
	if expected < 0 || expected > 20480 {
		return nil, &InvalidResponseError{"invalid expected translated name count"}
	}
	if len(stub) < 4 {
		return nil, &InvalidResponseError{"short LsarLookupSids response"}
	}
	status := erref.NtStatus(le.Uint32(stub[len(stub)-4:]))
	if status != 0 && status != erref.STATUS_SOME_NOT_MAPPED && status != erref.STATUS_NONE_MAPPED {
		return nil, status
	}
	dec := NewDecoder(stub)
	domains, err := readReferencedDomains(dec)
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("invalid referenced domains: %v", err)}
	}
	entries, err := dec.ReadUint32()
	if err != nil || entries != uint32(expected) {
		return nil, &InvalidResponseError{"translated name count mismatch"}
	}
	arrayPointer, err := dec.ReadUint32()
	if err != nil || (entries > 0 && arrayPointer == 0) {
		return nil, &InvalidResponseError{"missing translated name array"}
	}
	arrayCount, err := dec.ReadUint32()
	if err != nil || arrayCount != entries {
		return nil, &InvalidResponseError{"translated name array count mismatch"}
	}
	type nameHeader struct {
		use   uint32
		name  rpcStringHeader
		index int32
	}
	headers := make([]nameHeader, entries)
	for i := range headers {
		use, err := dec.ReadUint32()
		if err != nil || use < 1 || use > 10 {
			return nil, &InvalidResponseError{"invalid translated name type"}
		}
		name, err := readRPCStringHeader(dec)
		if err != nil {
			return nil, &InvalidResponseError{fmt.Sprintf("invalid translated name: %v", err)}
		}
		indexValue, err := dec.ReadUint32()
		if err != nil {
			return nil, &InvalidResponseError{"short translated name domain index"}
		}
		index := int32(indexValue)
		if index < -1 || (index >= 0 && int(index) >= len(domains)) {
			return nil, &InvalidResponseError{"invalid translated name domain index"}
		}
		headers[i] = nameHeader{use, name, index}
	}
	results := make([]TranslatedName, entries)
	var mapped uint32
	for i, header := range headers {
		name, err := readRPCString(dec, header.name)
		if err != nil {
			return nil, &InvalidResponseError{fmt.Sprintf("invalid translated name: %v", err)}
		}
		results[i] = TranslatedName{Use: header.use, Name: name}
		if header.index >= 0 {
			results[i].Domain = domains[header.index].name
		}
		if header.use != 7 && header.use != 8 {
			mapped++
		}
	}
	if err := readLookupStatus(dec, mapped, entries); err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("invalid LsarLookupSids status: %v", err)}
	}
	return results, nil
}
