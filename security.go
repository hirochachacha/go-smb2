package smb2

import (
	"context"
	"os"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

type rawEncoder []byte

func (b rawEncoder) Size() int       { return len(b) }
func (b rawEncoder) Encode(p []byte) { copy(p, b) }

const securityInformationComponents = security.Owner |
	security.Group |
	security.DACL |
	security.SACL

func validateSecurityQuery(selection security.Information) error {
	if selection == 0 || selection&^securityInformationComponents != 0 {
		return os.ErrInvalid
	}
	return nil
}

// GetSecurityDescriptor returns the selected owner, group, DACL, and/or SACL
// from the object's Windows security descriptor at the specified path.
// Unrequested fields are nil. A requested absent or NULL ACL is returned as
// security.NullACL, while a regular ACL with no ACEs is empty.
// SACL queries additionally require ACCESS_SYSTEM_SECURITY and the server-side privilege.
func (fs *Share) GetSecurityDescriptor(ctx context.Context, name string, selection security.Information) (*security.Descriptor, error) {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return nil, err
	}
	if err := validateSecurityQuery(selection); err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}

	var access uint32
	if selection&(security.Owner|security.Group|security.DACL) != 0 {
		access |= wire.READ_CONTROL
	}
	if selection&security.SACL != 0 {
		access |= wire.ACCESS_SYSTEM_SECURITY
	}

	req := fs.Request().WithFollowSymlinks(true).
		Create(name, access, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL).
		QueryInfo(wire.SMB2_0_INFO_SECURITY, 0, uint32(selection), maxSingleCreditPayloadSize).
		Close()

	res, err := req.Do(ctx)
	if err != nil {
		// [MS-SMB2] 3.3.5.20: a server SHOULD reject a QUERY_INFO whose
		// OutputBufferLength exceeds Connection.MaxTransactSize with
		// STATUS_INVALID_PARAMETER. Do not retry with a length this connection
		// cannot send; keep the original server error instead.
		if required, ok := protocol.RequiredBufferLength(err, 1); ok &&
			required > maxSingleCreditPayloadSize &&
			required <= fs.maxTransactSize(2) {
			req.Get(1).(*wire.QueryInfoRequest).OutputBufferLength = uint32(required)
			res, err = req.Do(ctx)
		}
		if err != nil {
			return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
		}
	}
	defer res.Close()

	queryRes, err := res.QueryInfo(1)
	if err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}
	sd, err := queryRes.SecurityDescriptor()
	if err != nil {
		return nil, &os.PathError{Op: "getSecurityDescriptor", Path: name, Err: err}
	}
	return sd, nil
}

// SetSecurityDescriptor applies each non-nil owner, group, DACL, and/or SACL
// to the object's Windows security descriptor at the specified path. Nil fields
// are left unchanged.
// Setting DACL requires WRITE_DAC, owner/group requires WRITE_OWNER, and
// SACL requires ACCESS_SYSTEM_SECURITY plus server privilege.
func (fs *Share) SetSecurityDescriptor(ctx context.Context, name string, descriptor *security.Descriptor) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}
	if descriptor == nil {
		return os.ErrInvalid
	}
	input, err := descriptor.Encode()
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	selection := descriptor.Information()
	if selection == 0 || len(input) == 0 || len(input) > fs.maxTransactSize(2) {
		return os.ErrInvalid
	}

	var access uint32
	if selection&security.DACL != 0 {
		access |= wire.WRITE_DAC
	}
	if selection&(security.Owner|security.Group) != 0 {
		access |= wire.WRITE_OWNER
	}
	if selection&security.SACL != 0 {
		access |= wire.ACCESS_SYSTEM_SECURITY
	}

	res, err := fs.Request().WithFollowSymlinks(true).
		Create(name, access, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL).
		SetInfo(wire.SMB2_0_INFO_SECURITY, 0, uint32(selection), rawEncoder(input)).
		Close().
		Do(ctx)
	if err != nil {
		return &os.PathError{Op: "setSecurityDescriptor", Path: name, Err: err}
	}
	res.Close()
	return nil
}
