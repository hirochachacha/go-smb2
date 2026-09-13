package smb2

import (
	"context"
	"fmt"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/security"
)

const (
	securityDescriptorDACLPresent   uint16 = 0x0004
	securityDescriptorSACLPresent   uint16 = 0x0010
	securityDescriptorDACLProtected uint16 = 0x1000
	securityDescriptorSACLProtected uint16 = 0x2000
)

const (
	securityInformationComponents = security.Owner |
		security.Group |
		security.DACL |
		security.SACL
)

func validateSecurityQuery(selection security.Information) error {
	if selection == 0 || selection&^securityInformationComponents != 0 {
		return os.ErrInvalid
	}
	return nil
}

func securityDescriptorToInternal(sd *security.Descriptor) (*smb2.SecurityDescriptor, security.Information, error) {
	if sd == nil {
		return nil, 0, os.ErrInvalid
	}

	result := &smb2.SecurityDescriptor{}
	var selection security.Information
	if sd.Owner != nil {
		selection |= security.Owner
		result.Owner = sidToInternal(sd.Owner)
	}
	if sd.Group != nil {
		selection |= security.Group
		result.Group = sidToInternal(sd.Group)
	}
	if sd.DACL != nil {
		selection |= security.DACL
		result.Control |= securityDescriptorDACLPresent
		var err error
		result.DACL, err = aclToInternal(sd.DACL, false)
		if err != nil {
			return nil, 0, err
		}
		if sd.DACL.Protected {
			result.Control |= securityDescriptorDACLProtected
		}
	}
	if sd.SACL != nil {
		selection |= security.SACL
		result.Control |= securityDescriptorSACLPresent
		var err error
		result.SACL, err = aclToInternal(sd.SACL, true)
		if err != nil {
			return nil, 0, err
		}
		if sd.SACL.Protected {
			result.Control |= securityDescriptorSACLProtected
		}
	}
	if selection == 0 || result.Size() == 0 {
		return nil, 0, os.ErrInvalid
	}
	return result, selection, nil
}

func sidToInternal(sid *security.SID) *smb2.Sid {
	if sid == nil {
		return nil
	}
	return &smb2.Sid{
		Revision:            sid.Revision,
		IdentifierAuthority: sid.IdentifierAuthority,
		SubAuthority:        append([]uint32(nil), sid.SubAuthority...),
	}
}

func sidFromInternal(sid *smb2.Sid) *security.SID {
	if sid == nil {
		return nil
	}
	return &security.SID{
		Revision:            sid.Revision,
		IdentifierAuthority: sid.IdentifierAuthority,
		SubAuthority:        append([]uint32(nil), sid.SubAuthority...),
	}
}

func aclToInternal(acl *security.ACL, sacl bool) (*smb2.ACL, error) {
	if acl == nil {
		return nil, nil
	}
	if acl == security.NullACL {
		return nil, nil
	}
	revision := acl.Revision
	if revision == 0 {
		revision = 2
	}
	result := &smb2.ACL{Revision: revision, ACEs: make([]smb2.ACE, len(acl.ACEs))}
	for i, ace := range acl.ACEs {
		result.ACEs[i] = smb2.ACE{
			Type:  uint8(ace.Type),
			Flags: uint8(ace.Flags),
			Mask:  uint32(ace.Mask),
			SID:   sidToInternal(ace.SID),
			Raw:   cloneBytes(ace.Raw),
		}
	}
	if _, err := result.Validate(sacl); err != nil {
		return nil, os.ErrInvalid
	}
	return result, nil
}

func securityDescriptorFromInternal(sd *smb2.SecurityDescriptor, selection security.Information) *security.Descriptor {
	if sd == nil {
		return nil
	}
	result := &security.Descriptor{}
	if selection&security.Owner != 0 {
		result.Owner = sidFromInternal(sd.Owner)
	}
	if selection&security.Group != 0 {
		result.Group = sidFromInternal(sd.Group)
	}
	if selection&security.DACL != 0 {
		result.DACL = aclFromInternal(sd.DACL)
		if result.DACL == nil {
			result.DACL = security.NullACL
		} else {
			result.DACL.Protected = sd.Control&securityDescriptorDACLProtected != 0
		}
	}
	if selection&security.SACL != 0 {
		result.SACL = aclFromInternal(sd.SACL)
		if result.SACL == nil {
			result.SACL = security.NullACL
		} else {
			result.SACL.Protected = sd.Control&securityDescriptorSACLProtected != 0
		}
	}
	return result
}

func aclFromInternal(acl *smb2.ACL) *security.ACL {
	if acl == nil {
		return nil
	}
	result := &security.ACL{Revision: acl.Revision, ACEs: make([]security.ACE, len(acl.ACEs))}
	for i, ace := range acl.ACEs {
		result.ACEs[i] = security.ACE{
			Type:  security.ACEType(ace.Type),
			Flags: security.ACEFlags(ace.Flags),
			Mask:  security.AccessMask(ace.Mask),
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

func decodeSecurityDescriptor(data []byte, selection security.Information) (*security.Descriptor, error) {
	if err := validateSecurityQuery(selection); err != nil {
		return nil, err
	}
	sd, err := smb2.DecodeSecurityDescriptor(data)
	if err != nil {
		return nil, err
	}
	// The public model intentionally normalizes an absent requested ACL and a
	// NULL ACL to security.NullACL. Both grant unrestricted access, while an
	// empty ACL denies all access. Unrequested ACLs remain nil.
	return securityDescriptorFromInternal(sd, selection), nil
}

// GetSecurityDescriptor returns the selected owner, group, DACL, and/or SACL
// from the object's Windows security descriptor at the specified path.
// Unrequested fields are nil. A requested absent or NULL ACL is returned as
// security.NullACL, while a regular ACL with no ACEs is empty.
// SACL queries additionally require ACCESS_SYSTEM_SECURITY and the server-side privilege.
func (fs *Share) GetSecurityDescriptor(ctx context.Context, name string, selection security.Information) (*security.Descriptor, error) {
	name = normPath(name)
	if err := validatePath("getSecurityDescriptor", name, false); err != nil {
		return nil, err
	}
	if err := validateSecurityQuery(selection); err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}

	var access uint32
	if selection&(security.Owner|security.Group|security.DACL) != 0 {
		access |= smb2.READ_CONTROL
	}
	if selection&security.SACL != 0 {
		access |= smb2.ACCESS_SYSTEM_SECURITY
	}

	req := fs.request().
		create(name, access, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL).
		queryInfo(smb2.SMB2_0_INFO_SECURITY, 0, uint32(selection), maxSingleCreditPayloadSize).
		close()

	res, err := req.sendRecv(ctx)
	if err != nil {
		if required, ok := requireBufferLength(err, 1); ok && required > maxSingleCreditPayloadSize {
			req.get(1).(*smb2.QueryInfoRequest).OutputBufferLength = uint32(required)
			res, err = req.sendRecv(ctx)
		}
		if err != nil {
			return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
		}
	}
	defer res.close()

	queryRes := smb2.QueryInfoResponseDecoder(res.data(1))
	if queryRes.IsInvalid() {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InvalidResponseError{"broken security query response format"}}
	}
	sd, err := decodeSecurityDescriptor(queryRes.OutputBuffer(), selection)
	if err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: &InvalidResponseError{fmt.Sprintf("broken security descriptor: %v", err)}}
	}
	return sd, nil
}

// SetSecurityDescriptor applies each non-nil owner, group, DACL, and/or SACL
// to the object's Windows security descriptor at the specified path. Nil fields
// are left unchanged.
// Setting DACL requires WRITE_DAC, owner/group requires WRITE_OWNER, and
// SACL requires ACCESS_SYSTEM_SECURITY plus server privilege.
func (fs *Share) SetSecurityDescriptor(ctx context.Context, name string, descriptor *security.Descriptor) error {
	name = normPath(name)
	if err := validatePath("setSecurityDescriptor", name, false); err != nil {
		return err
	}
	input, selection, err := securityDescriptorToInternal(descriptor)
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	if input.Size() == 0 || input.Size() > fs.maxTransactSize(2) {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: os.ErrInvalid}
	}

	var access uint32
	if selection&security.DACL != 0 {
		access |= smb2.WRITE_DAC
	}
	if selection&(security.Owner|security.Group) != 0 {
		access |= smb2.WRITE_OWNER
	}
	if selection&security.SACL != 0 {
		access |= smb2.ACCESS_SYSTEM_SECURITY
	}

	res, err := fs.request().
		create(name, access, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.SMB2_0_INFO_SECURITY, 0, uint32(selection), input).
		close().
		sendRecv(ctx)
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	res.close()
	return nil
}
