package smb2

import (
	"errors"
	"fmt"
	"os"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// SecurityInformation selects security descriptor components for QUERY_INFO
// and SET_INFO. The values are defined by [MS-DTYP] section 2.4.7.
type SecurityInformation uint32

const (
	OWNER_SECURITY_INFORMATION SecurityInformation = 0x00000001
	GROUP_SECURITY_INFORMATION SecurityInformation = 0x00000002
	DACL_SECURITY_INFORMATION  SecurityInformation = 0x00000004
	SACL_SECURITY_INFORMATION  SecurityInformation = 0x00000008

	UNPROTECTED_SACL_SECURITY_INFORMATION SecurityInformation = 0x10000000
	UNPROTECTED_DACL_SECURITY_INFORMATION SecurityInformation = 0x20000000
	PROTECTED_SACL_SECURITY_INFORMATION   SecurityInformation = 0x40000000
	PROTECTED_DACL_SECURITY_INFORMATION   SecurityInformation = 0x80000000
)

// Security descriptor control bits are defined by [MS-DTYP] section 2.4.6.
const (
	SE_SELF_RELATIVE    uint16 = 0x8000
	SE_RM_CONTROL_VALID uint16 = 0x4000
	SE_DACL_PRESENT     uint16 = 0x0004
	SE_SACL_PRESENT     uint16 = 0x0010
	SE_DACL_PROTECTED   uint16 = 0x1000
	SE_SACL_PROTECTED   uint16 = 0x2000
)

// ACE types supported structurally by this package. Other ACE types are
// preserved as ACE.Raw, including their complete four-byte header.
const (
	ACCESS_ALLOWED uint8 = iota
	ACCESS_DENIED
	SYSTEM_AUDIT
)

// SID is a Windows security identifier. IdentifierAuthority is the six-byte
// value from the wire representation and must fit in 48 bits.
type SID struct {
	Revision            uint8
	IdentifierAuthority uint64
	SubAuthorities      []uint32
}

// ACL is an ordered access control list. A nil ACL in a security descriptor
// is distinct from an empty ACL: the former is a NULL ACL when its PRESENT
// control bit is set, while the latter has an ACL header with zero ACEs.
type ACL struct {
	Revision uint8
	ACEs     []ACE
}

// ACE is either one of the three structurally supported ACE types, or an
// unknown ACE represented by its complete raw bytes. Structured ACEs must not
// set Raw; unknown ACEs must not set Mask or SID.
type ACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   *SID
	Raw   []byte
}

// SecurityDescriptor contains the selected Windows security attributes.
// Control and ResourceManagerControl are retained as received. The wire
// encoder always emits the self-relative form required by [MS-DTYP] 2.4.6.
type SecurityDescriptor struct {
	Control                uint16
	ResourceManagerControl uint8
	Owner                  *SID
	Group                  *SID
	DACL                   *ACL
	SACL                   *ACL
}

const (
	securityInformationComponents = OWNER_SECURITY_INFORMATION |
		GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION |
		SACL_SECURITY_INFORMATION
	securityInformationProtection = UNPROTECTED_SACL_SECURITY_INFORMATION |
		UNPROTECTED_DACL_SECURITY_INFORMATION |
		PROTECTED_SACL_SECURITY_INFORMATION |
		PROTECTED_DACL_SECURITY_INFORMATION
)

func validateSecurityQuery(selection SecurityInformation) error {
	if selection == 0 || selection&^securityInformationComponents != 0 {
		return os.ErrInvalid
	}
	return nil
}

func validateSecuritySet(selection SecurityInformation) error {
	if selection == 0 || selection&^(securityInformationComponents|securityInformationProtection) != 0 {
		return os.ErrInvalid
	}
	if selection&PROTECTED_DACL_SECURITY_INFORMATION != 0 && selection&UNPROTECTED_DACL_SECURITY_INFORMATION != 0 {
		return os.ErrInvalid
	}
	if selection&PROTECTED_SACL_SECURITY_INFORMATION != 0 && selection&UNPROTECTED_SACL_SECURITY_INFORMATION != 0 {
		return os.ErrInvalid
	}
	if selection&(PROTECTED_DACL_SECURITY_INFORMATION|UNPROTECTED_DACL_SECURITY_INFORMATION) != 0 && selection&DACL_SECURITY_INFORMATION == 0 {
		return os.ErrInvalid
	}
	if selection&(PROTECTED_SACL_SECURITY_INFORMATION|UNPROTECTED_SACL_SECURITY_INFORMATION) != 0 && selection&SACL_SECURITY_INFORMATION == 0 {
		return os.ErrInvalid
	}
	return nil
}

func (sd *SecurityDescriptor) internal(selection SecurityInformation) (*smb2.SecurityDescriptor, error) {
	if sd == nil {
		return nil, os.ErrInvalid
	}
	if err := validateSecuritySet(selection); err != nil {
		return nil, err
	}

	result := &smb2.SecurityDescriptor{
		Control:                sd.Control,
		ResourceManagerControl: sd.ResourceManagerControl,
	}
	if selection&OWNER_SECURITY_INFORMATION != 0 {
		if sd.Owner == nil {
			return nil, os.ErrInvalid
		}
		result.Owner = sidToInternal(sd.Owner)
	}
	if selection&GROUP_SECURITY_INFORMATION != 0 {
		if sd.Group == nil {
			return nil, os.ErrInvalid
		}
		result.Group = sidToInternal(sd.Group)
	}
	if selection&DACL_SECURITY_INFORMATION != 0 {
		if sd.Control&SE_DACL_PRESENT == 0 {
			return nil, os.ErrInvalid
		}
		var err error
		result.DACL, err = aclToInternal(sd.DACL, false)
		if err != nil {
			return nil, err
		}
	} else {
		result.Control &^= SE_DACL_PRESENT | SE_DACL_PROTECTED
	}
	if selection&PROTECTED_DACL_SECURITY_INFORMATION != 0 {
		result.Control |= SE_DACL_PROTECTED
	}
	if selection&UNPROTECTED_DACL_SECURITY_INFORMATION != 0 {
		result.Control &^= SE_DACL_PROTECTED
	}
	if selection&SACL_SECURITY_INFORMATION != 0 {
		if sd.Control&SE_SACL_PRESENT == 0 {
			return nil, os.ErrInvalid
		}
		var err error
		result.SACL, err = aclToInternal(sd.SACL, true)
		if err != nil {
			return nil, err
		}
	} else {
		result.Control &^= SE_SACL_PRESENT | SE_SACL_PROTECTED
	}
	if selection&PROTECTED_SACL_SECURITY_INFORMATION != 0 {
		result.Control |= SE_SACL_PROTECTED
	}
	if selection&UNPROTECTED_SACL_SECURITY_INFORMATION != 0 {
		result.Control &^= SE_SACL_PROTECTED
	}
	if result.Size() == 0 {
		return nil, os.ErrInvalid
	}
	return result, nil
}

func sidToInternal(sid *SID) *smb2.Sid {
	if sid == nil {
		return nil
	}
	return &smb2.Sid{
		Revision:            sid.Revision,
		IdentifierAuthority: sid.IdentifierAuthority,
		SubAuthority:        append([]uint32(nil), sid.SubAuthorities...),
	}
}

func sidFromInternal(sid *smb2.Sid) *SID {
	if sid == nil {
		return nil
	}
	return &SID{
		Revision:            sid.Revision,
		IdentifierAuthority: sid.IdentifierAuthority,
		SubAuthorities:      append([]uint32(nil), sid.SubAuthority...),
	}
}

func aclToInternal(acl *ACL, sacl bool) (*smb2.ACL, error) {
	if acl == nil {
		return nil, nil
	}
	result := &smb2.ACL{Revision: acl.Revision, ACEs: make([]smb2.ACE, len(acl.ACEs))}
	for i, ace := range acl.ACEs {
		result.ACEs[i] = smb2.ACE{
			Type:  ace.Type,
			Flags: ace.Flags,
			Mask:  ace.Mask,
			SID:   sidToInternal(ace.SID),
			Raw:   cloneBytes(ace.Raw),
		}
	}
	if _, err := result.Validate(sacl); err != nil {
		return nil, os.ErrInvalid
	}
	return result, nil
}

func securityDescriptorFromInternal(sd *smb2.SecurityDescriptor) *SecurityDescriptor {
	if sd == nil {
		return nil
	}
	result := &SecurityDescriptor{
		Control:                sd.Control,
		ResourceManagerControl: sd.ResourceManagerControl,
		Owner:                  sidFromInternal(sd.Owner),
		Group:                  sidFromInternal(sd.Group),
	}
	result.DACL = aclFromInternal(sd.DACL)
	result.SACL = aclFromInternal(sd.SACL)
	return result
}

func aclFromInternal(acl *smb2.ACL) *ACL {
	if acl == nil {
		return nil
	}
	result := &ACL{Revision: acl.Revision, ACEs: make([]ACE, len(acl.ACEs))}
	for i, ace := range acl.ACEs {
		result.ACEs[i] = ACE{
			Type:  ace.Type,
			Flags: ace.Flags,
			Mask:  ace.Mask,
			SID:   sidFromInternal(ace.SID),
			Raw:   cloneBytes(ace.Raw),
		}
	}
	return result
}

func cloneBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}

func decodeSecurityDescriptor(data []byte, selection SecurityInformation) (*SecurityDescriptor, error) {
	if err := validateSecurityQuery(selection); err != nil {
		return nil, err
	}
	sd, err := smb2.DecodeSecurityDescriptor(data)
	if err != nil {
		return nil, err
	}
	if selection&OWNER_SECURITY_INFORMATION != 0 && sd.Owner == nil {
		return nil, errors.New("security descriptor omits requested owner")
	}
	if selection&GROUP_SECURITY_INFORMATION != 0 && sd.Group == nil {
		return nil, errors.New("security descriptor omits requested group")
	}
	// An absent ACL (PRESENT clear) is a valid security descriptor state,
	// distinct from a NULL ACL and an empty ACL, even when that ACL is queried.
	return securityDescriptorFromInternal(sd), nil
}

// GetSecurityDescriptor returns the selected owner, group, DACL, and/or SACL
// from the object's Windows security descriptor at the specified path.
// SACL queries additionally require ACCESS_SYSTEM_SECURITY and the server-side privilege.
func (fs *Share) GetSecurityDescriptor(name string, selection SecurityInformation) (*SecurityDescriptor, error) {
	name = normPath(name)
	if err := validatePath("getSecurityDescriptor", name, false); err != nil {
		return nil, err
	}
	if err := validateSecurityQuery(selection); err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}

	maxOutput := fs.maxTransactSizeReserving(maxCompoundCreditOverhead)
	if maxOutput <= 0 {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InternalError{"invalid maximum transaction size"}}
	}

	var access uint32 = smb2.READ_CONTROL
	if selection&SACL_SECURITY_INFORMATION != 0 {
		access |= smb2.ACCESS_SYSTEM_SECURITY
	}

	res, err := fs.request().
		create(name, access, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL).
		queryInfo(smb2.SMB2_0_INFO_SECURITY, 0, uint32(selection), uint32(maxOutput)).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}
	defer res.close()

	queryRes := smb2.QueryInfoResponseDecoder(res.data(1))
	if queryRes.IsInvalid() {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InvalidResponseError{"broken security query response format"}}
	}
	if uint64(queryRes.OutputBufferLength()) > uint64(maxOutput) {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InvalidResponseError{"security query response exceeds requested length"}}
	}
	sd, err := decodeSecurityDescriptor(queryRes.OutputBuffer(), selection)
	if err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InvalidResponseError{fmt.Sprintf("broken security descriptor: %v", err)}}
	}
	return sd, nil
}

// SetSecurityDescriptor applies the selected owner, group, DACL, and/or SACL
// to the object's Windows security descriptor at the specified path.
// Setting DACL requires WRITE_DAC, owner/group requires WRITE_OWNER, and
// SACL requires ACCESS_SYSTEM_SECURITY plus server privilege.
func (fs *Share) SetSecurityDescriptor(name string, selection SecurityInformation, descriptor *SecurityDescriptor) error {
	name = normPath(name)
	if err := validatePath("setSecurityDescriptor", name, false); err != nil {
		return err
	}
	if err := validateSecuritySet(selection); err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	input, err := descriptor.internal(selection)
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	if input.Size() == 0 || input.Size() > fs.maxTransactSize() {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: os.ErrInvalid}
	}

	var access uint32
	if selection&DACL_SECURITY_INFORMATION != 0 {
		access |= smb2.WRITE_DAC
	}
	if selection&(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION) != 0 {
		access |= smb2.WRITE_OWNER
	}
	if selection&SACL_SECURITY_INFORMATION != 0 {
		access |= smb2.ACCESS_SYSTEM_SECURITY
	}

	res, err := fs.request().
		create(name, access, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.SMB2_0_INFO_SECURITY, 0, uint32(selection), input).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	res.close()
	return nil
}
