package security

import "github.com/hirochachacha/go-smb2/v2/internal/smb2"

// Information selects the parts of a security descriptor to query.
//
// The values are defined by [MS-DTYP] section 2.4.7.
type Information uint32

const (
	Owner Information = smb2.OWNER_SECURITY_INFORMATION
	Group Information = smb2.GROUP_SECURITY_INFORMATION
	DACL  Information = smb2.DACL_SECURITY_INFORMATION
	SACL  Information = smb2.SACL_SECURITY_INFORMATION
)

// Descriptor contains the security descriptor components exposed by the
// high-level API. Wire-only control and offset fields remain internal.
type Descriptor struct {
	Owner *SID
	Group *SID
	DACL  *ACL
	SACL  *ACL
}

// SID is a Windows security identifier.
type SID = smb2.Sid

// ACL is an ordered access control list. Use NullACL for a NULL ACL; a regular
// &ACL{} represents an empty ACL.
type ACL = smb2.ACL

// ACE is an access control entry. Unknown ACEs are preserved in Raw.
type ACE = smb2.ACE

// ACEType identifies the layout and purpose of an ACE.
type ACEType = uint8

const (
	AccessAllowed ACEType = 0x00
	AccessDenied  ACEType = 0x01
	SystemAudit   ACEType = 0x02
)

// ACEFlags controls inheritance and auditing for an ACE.
type ACEFlags = uint8

const (
	ObjectInherit      ACEFlags = 0x01
	ContainerInherit   ACEFlags = 0x02
	NoPropagateInherit ACEFlags = 0x04
	InheritOnly        ACEFlags = 0x08
	Inherited          ACEFlags = 0x10
	SuccessfulAccess   ACEFlags = 0x40
	FailedAccess       ACEFlags = 0x80
)

// AccessMask specifies access rights granted, denied, or audited by an ACE.
type AccessMask = uint32

// File and directory access rights defined by [MS-SMB2] section 2.2.13.1.
const (
	FileReadData        AccessMask = smb2.FILE_READ_DATA
	FileWriteData       AccessMask = smb2.FILE_WRITE_DATA
	FileAppendData      AccessMask = smb2.FILE_APPEND_DATA
	FileReadEA          AccessMask = smb2.FILE_READ_EA
	FileWriteEA         AccessMask = smb2.FILE_WRITE_EA
	FileExecute         AccessMask = smb2.FILE_EXECUTE
	FileDeleteChild     AccessMask = smb2.FILE_DELETE_CHILD
	FileReadAttributes  AccessMask = smb2.FILE_READ_ATTRIBUTES
	FileWriteAttributes AccessMask = smb2.FILE_WRITE_ATTRIBUTES

	FileListDirectory   AccessMask = smb2.FILE_LIST_DIRECTORY
	FileAddFile         AccessMask = smb2.FILE_ADD_FILE
	FileAddSubdirectory AccessMask = smb2.FILE_ADD_SUBDIRECTORY
	FileTraverse        AccessMask = smb2.FILE_TRAVERSE
)

// Standard and generic access rights defined by [MS-DTYP] section 2.4.3.
const (
	Delete               AccessMask = smb2.DELETE
	ReadControl          AccessMask = smb2.READ_CONTROL
	WriteDACL            AccessMask = smb2.WRITE_DAC
	WriteOwner           AccessMask = smb2.WRITE_OWNER
	Synchronize          AccessMask = smb2.SYNCHRONIZE
	AccessSystemSecurity AccessMask = smb2.ACCESS_SYSTEM_SECURITY
	GenericAll           AccessMask = smb2.GENERIC_ALL
	GenericExecute       AccessMask = smb2.GENERIC_EXECUTE
	GenericWrite         AccessMask = smb2.GENERIC_WRITE
	GenericRead          AccessMask = smb2.GENERIC_READ
)

// Common composite access masks for files.
const (
	FileAllAccess      AccessMask = 0x001f01ff
	FileGenericRead    AccessMask = 0x00120089
	FileGenericWrite   AccessMask = 0x00120116
	FileGenericExecute AccessMask = 0x001200a0
)

// NullACL is a convenient value for selecting a NULL ACL when setting a
// descriptor and is also returned for a requested NULL or absent ACL. Treat it
// as read-only; a regular &ACL{} represents an empty ACL.
var NullACL = smb2.NullACL
