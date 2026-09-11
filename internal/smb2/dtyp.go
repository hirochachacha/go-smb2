// ref: MS-DTYP

package smb2

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// FILETIME is an unsigned count of 100-nanosecond intervals, so split the
// value before converting it to time.Unix ([MS-DTYP] 2.3.3).
func filetimeToTime(ticks uint64) time.Time {
	return time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100)
}

func (ft *Filetime) Size() int {
	return 8
}

func (ft *Filetime) Encode(p []byte) {
	le.PutUint32(p[:4], ft.LowDateTime)
	le.PutUint32(p[4:8], ft.HighDateTime)
}

func (ft *Filetime) Time() time.Time {
	if ft == nil {
		return time.Time{}
	}
	return filetimeToTime(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
}

func TimeToFiletime(t time.Time) *Filetime {
	if t.IsZero() {
		return nil
	}

	const unixToFiletimeSeconds = int64(11644473600)
	const maxFiletimeSeconds = int64(^uint64(0) / 10000000)
	seconds := t.Unix()
	if seconds < -unixToFiletimeSeconds || seconds > maxFiletimeSeconds-unixToFiletimeSeconds {
		return nil
	}

	filetimeSeconds := uint64(seconds + unixToFiletimeSeconds)
	nanoseconds := uint64(t.Nanosecond() / 100)
	if filetimeSeconds > (^uint64(0)-nanoseconds)/10000000 {
		return nil
	}

	filetime := filetimeSeconds*10000000 + nanoseconds
	return &Filetime{
		LowDateTime:  uint32(filetime),
		HighDateTime: uint32(filetime >> 32),
	}
}

type FiletimeDecoder []byte

func (ft FiletimeDecoder) LowDateTime() uint32 {
	return le.Uint32(ft[:4])
}

func (ft FiletimeDecoder) HighDateTime() uint32 {
	return le.Uint32(ft[4:8])
}

func (ft FiletimeDecoder) Time() time.Time {
	return filetimeToTime(uint64(ft.HighDateTime())<<32 | uint64(ft.LowDateTime()))
}

func (ft FiletimeDecoder) Decode() *Filetime {
	return &Filetime{
		LowDateTime:  ft.LowDateTime(),
		HighDateTime: ft.HighDateTime(),
	}
}

type Sid struct {
	Revision            uint8
	IdentifierAuthority uint64
	SubAuthority        []uint32
}

func (sid *Sid) String() string {
	list := make([]string, 0, 3+len(sid.SubAuthority))
	list = append(list, "S")
	list = append(list, strconv.Itoa(int(sid.Revision)))
	if sid.IdentifierAuthority < uint64(1<<32) {
		list = append(list, strconv.FormatUint(sid.IdentifierAuthority, 10))
	} else {
		list = append(list, "0x"+strconv.FormatUint(sid.IdentifierAuthority, 16))
	}
	for _, a := range sid.SubAuthority {
		list = append(list, strconv.FormatUint(uint64(a), 10))
	}
	return strings.Join(list, "-")
}

func (sid *Sid) Size() int {
	if sid == nil {
		return 0
	}
	return 8 + len(sid.SubAuthority)*4
}

func (sid *Sid) Encode(p []byte) {
	if sid == nil || len(p) < sid.Size() {
		return
	}
	p[0] = sid.Revision
	p[1] = uint8(len(sid.SubAuthority))
	for j := 0; j < 6; j++ {
		p[2+j] = byte(sid.IdentifierAuthority >> uint64(8*(5-j)))
	}
	off := 8
	for _, u := range sid.SubAuthority {
		le.PutUint32(p[off:off+4], u)
		off += 4
	}
}

type SidDecoder []byte

func (c SidDecoder) IsInvalid() bool {
	if len(c) < 8 {
		return true
	}

	if c.Revision() != 1 || c.SubAuthorityCount() > 15 {
		return true
	}

	if uint64(len(c)) < 8+4*uint64(c.SubAuthorityCount()) {
		return true
	}

	return false
}

func (c SidDecoder) Revision() uint8 {
	if len(c) < 1 {
		return 0
	}
	return c[0]
}

func (c SidDecoder) SubAuthorityCount() uint8 {
	if len(c) < 2 {
		return 0
	}
	return c[1]
}

func (c SidDecoder) IdentifierAuthority() uint64 {
	if len(c) < 8 {
		return 0
	}
	var u uint64
	for j := 0; j < 6; j++ {
		u += uint64(c[7-j]) << uint64(8*j)
	}
	return u
}

func (c SidDecoder) SubAuthority() []uint32 {
	if c.IsInvalid() {
		return nil
	}
	count := c.SubAuthorityCount()
	as := make([]uint32, count)
	off := 8
	for i := uint8(0); i < count; i++ {
		as[i] = le.Uint32(c[off : off+4])
		off += 4
	}
	return as
}

func (c SidDecoder) Decode() *Sid {
	if c.IsInvalid() {
		return nil
	}
	return &Sid{
		Revision:            c.Revision(),
		IdentifierAuthority: c.IdentifierAuthority(),
		SubAuthority:        c.SubAuthority(),
	}
}

const (
	securityDescriptorRevision            = 1
	securityDescriptorSelfRelative uint16 = 0x8000
	securityDescriptorDACLPresent  uint16 = 0x0004
	securityDescriptorSACLPresent  uint16 = 0x0010

	accessAllowedACEType = 0x00
	accessDeniedACEType  = 0x01
	systemAuditACEType   = 0x02
	aclRevision          = 0x02
	aclRevisionDS        = 0x04
)

// SecurityDescriptor is the self-relative SECURITY_DESCRIPTOR wire model.
// Its layout follows [MS-DTYP] sections 2.4.4 through 2.4.6.
type SecurityDescriptor struct {
	Control                uint16
	ResourceManagerControl uint8
	Owner                  *Sid
	Group                  *Sid
	DACL                   *ACL
	SACL                   *ACL
}

type ACL struct {
	Revision uint8
	ACEs     []ACE
}

type ACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   *Sid
	Raw   []byte
}

func (sd *SecurityDescriptor) size() (int, error) {
	if sd == nil {
		return 0, fmt.Errorf("nil security descriptor")
	}

	if err := validateSID(sd.Owner); err != nil {
		return 0, fmt.Errorf("owner: %w", err)
	}
	if err := validateSID(sd.Group); err != nil {
		return 0, fmt.Errorf("group: %w", err)
	}

	saclSize, err := validateACL(sd.SACL, true)
	if err != nil {
		return 0, fmt.Errorf("sacl: %w", err)
	}
	daclSize, err := validateACL(sd.DACL, false)
	if err != nil {
		return 0, fmt.Errorf("dacl: %w", err)
	}

	size := 20
	for _, n := range []int{sd.Owner.Size(), sd.Group.Size(), saclSize, daclSize} {
		if n == 0 {
			continue
		}
		size = roundup4(size)
		if uint64(size)+uint64(n) > uint64(^uint32(0)) {
			return 0, fmt.Errorf("security descriptor is too large")
		}
		size += n
	}
	if uint64(size) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("security descriptor is too large")
	}
	return size, nil
}

func (sd *SecurityDescriptor) Size() int {
	size, err := sd.size()
	if err != nil {
		return 0
	}
	return size
}

func (sd *SecurityDescriptor) Encode(p []byte) {
	size, err := sd.size()
	if err != nil || len(p) < size {
		return
	}

	ownerOffset, groupOffset, saclOffset, daclOffset := 0, 0, 0, 0
	off := 20
	if sd.Owner != nil {
		off = roundup4(off)
		ownerOffset = off
		sd.Owner.Encode(p[off:])
		off += sd.Owner.Size()
	}
	if sd.Group != nil {
		off = roundup4(off)
		groupOffset = off
		sd.Group.Encode(p[off:])
		off += sd.Group.Size()
	}
	if sd.SACL != nil {
		off = roundup4(off)
		saclOffset = off
		sd.SACL.encode(p[off:], true)
		saclSize, _ := validateACL(sd.SACL, true)
		off += saclSize
	}
	if sd.DACL != nil {
		off = roundup4(off)
		daclOffset = off
		sd.DACL.encode(p[off:], false)
	}

	p[0] = securityDescriptorRevision
	p[1] = sd.ResourceManagerControl
	le.PutUint16(p[2:4], sd.Control|securityDescriptorSelfRelative)
	le.PutUint32(p[4:8], uint32(ownerOffset))
	le.PutUint32(p[8:12], uint32(groupOffset))
	le.PutUint32(p[12:16], uint32(saclOffset))
	le.PutUint32(p[16:20], uint32(daclOffset))
}

func (acl *ACL) Size() int {
	size, err := validateACL(acl, false)
	if err != nil {
		return 0
	}
	return size
}

func (acl *ACL) encode(p []byte, sacl bool) {
	size, err := validateACL(acl, sacl)
	if err != nil {
		size = 0
	}
	if size == 0 || len(p) < size {
		return
	}
	// The ACL header has AclRevision/Sbz1/AclSize, then AceCount/Sbz2.
	p[0] = acl.Revision
	p[1] = 0
	le.PutUint16(p[2:4], uint16(size))
	le.PutUint16(p[4:6], uint16(len(acl.ACEs)))
	le.PutUint16(p[6:8], 0)
	off := 8
	for i := range acl.ACEs {
		acl.ACEs[i].encode(p[off:])
		off += acl.ACEs[i].size()
	}
}

func (acl *ACL) Validate(sacl bool) (int, error) {
	return validateACL(acl, sacl)
}

func (ace *ACE) size() int {
	if ace == nil {
		return 0
	}
	if ace.Raw != nil {
		return len(ace.Raw)
	}
	if ace.SID == nil {
		return 0
	}
	return 8 + ace.SID.Size()
}

func (ace *ACE) encode(p []byte) {
	if ace == nil {
		return
	}
	if ace.Raw != nil {
		copy(p, ace.Raw)
		return
	}
	p[0] = ace.Type
	p[1] = ace.Flags
	le.PutUint16(p[2:4], uint16(ace.size()))
	le.PutUint32(p[4:8], ace.Mask)
	ace.SID.Encode(p[8:])
}

func validateSID(sid *Sid) error {
	if sid == nil {
		return nil
	}
	if sid.Revision != 1 || len(sid.SubAuthority) > 15 || sid.IdentifierAuthority > 0xffffffffffff {
		return fmt.Errorf("invalid SID")
	}
	return nil
}

func validateACL(acl *ACL, sacl bool) (int, error) {
	if acl == nil {
		return 0, nil
	}
	if acl.Revision != aclRevision && acl.Revision != aclRevisionDS {
		return 0, fmt.Errorf("invalid ACL revision")
	}
	if len(acl.ACEs) > 0xffff {
		return 0, fmt.Errorf("too many ACEs")
	}

	size := 8
	for i := range acl.ACEs {
		ace := &acl.ACEs[i]
		aceSize, err := validateACE(ace, acl.Revision, sacl)
		if err != nil {
			return 0, fmt.Errorf("ACE %d: %w", i, err)
		}
		if aceSize > 0xffff-size {
			return 0, fmt.Errorf("ACL is too large")
		}
		size += aceSize
	}
	return size, nil
}

func validateACE(ace *ACE, revision uint8, sacl bool) (int, error) {
	if ace == nil {
		return 0, fmt.Errorf("nil ACE")
	}
	if !aceAllowedByRevision(ace.Type, revision) {
		return 0, fmt.Errorf("ACE type is invalid for ACL revision")
	}
	if aceIsDACLOnly(ace.Type) && sacl {
		return 0, fmt.Errorf("DACL ACE type is invalid for SACL")
	}
	if aceIsSACLOnly(ace.Type) && !sacl {
		return 0, fmt.Errorf("SACL ACE type is invalid for DACL")
	}
	switch ace.Type {
	case accessAllowedACEType, accessDeniedACEType, systemAuditACEType:
		if ace.Raw != nil || ace.SID == nil {
			return 0, fmt.Errorf("structured ACE has invalid raw or SID fields")
		}
		if err := validateSID(ace.SID); err != nil {
			return 0, err
		}
		size := 8 + ace.SID.Size()
		if size > 0xffff || size&3 != 0 {
			return 0, fmt.Errorf("invalid ACE size")
		}
		return size, nil
	default:
		if len(ace.Raw) < 4 || len(ace.Raw) > 0xffff || len(ace.Raw)&3 != 0 {
			return 0, fmt.Errorf("invalid raw ACE size")
		}
		if ace.Raw[0] != ace.Type || ace.Raw[1] != ace.Flags || le.Uint16(ace.Raw[2:4]) != uint16(len(ace.Raw)) {
			return 0, fmt.Errorf("raw ACE header does not match fields")
		}
		if ace.Mask != 0 || ace.SID != nil {
			return 0, fmt.Errorf("raw ACE has structured fields")
		}
		return len(ace.Raw), nil
	}
}

// Object-specific ACEs require ACL_REVISION_DS. Other ACEs may occur in
// either supported revision, including alongside object-specific ACEs.
// See RtlAddAce and AddConditionalAce in the Microsoft Windows API docs.
// Unknown ACEs retain their opaque bytes as required by the public API.
func aceAllowedByRevision(aceType, revision uint8) bool {
	switch aceType {
	case 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0f, 0x10:
		return revision == aclRevisionDS
	default:
		return true
	}
}

func aceIsDACLOnly(aceType uint8) bool {
	switch aceType {
	case 0x00, 0x01, 0x05, 0x06, 0x09, 0x0a, 0x0b, 0x0c:
		return true
	default:
		return false
	}
}

func aceIsSACLOnly(aceType uint8) bool {
	switch aceType {
	case 0x02, 0x07, 0x0d, 0x0f, 0x11, 0x12, 0x13:
		return true
	default:
		return false
	}
}

func roundup4(n int) int {
	return (n + 3) &^ 3
}

// DecodeSecurityDescriptor validates and copies a self-relative descriptor.
func DecodeSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 || data[0] != securityDescriptorRevision {
		return nil, fmt.Errorf("invalid security descriptor header")
	}
	control := le.Uint16(data[2:4])
	if control&securityDescriptorSelfRelative == 0 {
		return nil, fmt.Errorf("security descriptor is not self-relative")
	}

	sd := &SecurityDescriptor{
		Control:                control,
		ResourceManagerControl: data[1],
	}
	owner, err := decodeSIDAt(data, le.Uint32(data[4:8]))
	if err != nil {
		return nil, fmt.Errorf("owner: %w", err)
	}
	group, err := decodeSIDAt(data, le.Uint32(data[8:12]))
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	sacl, err := decodeACLAt(data, le.Uint32(data[12:16]), control&securityDescriptorSACLPresent != 0, true)
	if err != nil {
		return nil, fmt.Errorf("sacl: %w", err)
	}
	dacl, err := decodeACLAt(data, le.Uint32(data[16:20]), control&securityDescriptorDACLPresent != 0, false)
	if err != nil {
		return nil, fmt.Errorf("dacl: %w", err)
	}
	sd.Owner, sd.Group, sd.SACL, sd.DACL = owner, group, sacl, dacl
	return sd, nil
}

func decodeSIDAt(data []byte, offset uint32) (*Sid, error) {
	if offset == 0 {
		return nil, nil
	}
	if offset < 20 || offset&3 != 0 || uint64(offset)+8 > uint64(len(data)) {
		return nil, fmt.Errorf("invalid SID offset")
	}
	sidData := data[offset:]
	sid := SidDecoder(sidData)
	if sid.IsInvalid() {
		return nil, fmt.Errorf("invalid SID")
	}
	return sid.Decode(), nil
}

func decodeACLAt(data []byte, offset uint32, present, sacl bool) (*ACL, error) {
	if offset == 0 {
		return nil, nil
	}
	if !present || offset < 20 || offset&3 != 0 || uint64(offset)+8 > uint64(len(data)) {
		return nil, fmt.Errorf("invalid ACL offset")
	}
	aclData := data[offset:]
	aclSize := uint64(le.Uint16(aclData[2:4]))
	if aclSize < 8 || aclSize > uint64(len(aclData)) {
		return nil, fmt.Errorf("invalid ACL size")
	}
	aclData = aclData[:aclSize]
	if aclData[0] != aclRevision && aclData[0] != aclRevisionDS || aclData[1] != 0 || le.Uint16(aclData[6:8]) != 0 {
		return nil, fmt.Errorf("invalid ACL header")
	}
	count := uint64(le.Uint16(aclData[4:6]))
	if count > (aclSize-8)/4 {
		return nil, fmt.Errorf("ACE count exceeds ACL size")
	}
	acl := &ACL{Revision: aclData[0], ACEs: make([]ACE, 0, count)}
	off := uint64(8)
	for i := uint64(0); i < count; i++ {
		if off+4 > aclSize {
			return nil, fmt.Errorf("truncated ACE header")
		}
		aceSize := uint64(le.Uint16(aclData[off+2 : off+4]))
		if aceSize < 4 || aceSize&3 != 0 || off+aceSize > aclSize {
			return nil, fmt.Errorf("invalid ACE size")
		}
		aceData := aclData[off : off+aceSize]
		ace := ACE{Type: aceData[0], Flags: aceData[1]}
		switch ace.Type {
		case accessAllowedACEType, accessDeniedACEType, systemAuditACEType:
			if aceSize < 8 {
				return nil, fmt.Errorf("truncated structured ACE")
			}
			ace.Mask = le.Uint32(aceData[4:8])
			sid := SidDecoder(aceData[8:])
			if sid.IsInvalid() || 8+4*uint64(sid.SubAuthorityCount()) != aceSize-8 {
				return nil, fmt.Errorf("invalid structured ACE SID")
			}
			ace.SID = sid.Decode()
		default:
			ace.Raw = append([]byte(nil), aceData...)
		}
		acl.ACEs = append(acl.ACEs, ace)
		off += aceSize
	}
	if off != aclSize {
		return nil, fmt.Errorf("ACL contains unparsed data")
	}
	if _, err := validateACL(acl, sacl); err != nil {
		return nil, err
	}
	return acl, nil
}
