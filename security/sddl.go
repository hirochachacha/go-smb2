package security

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// String returns the SDDL representation of the security descriptor.
func (d *Descriptor) String() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	d.writeSDDL(&b)
	return b.String()
}

func (d *Descriptor) writeSDDL(b *strings.Builder) {
	if d.Owner != nil {
		b.WriteString("O:")
		writeSDDLSID(b, d.Owner)
	}
	if d.Group != nil {
		b.WriteString("G:")
		writeSDDLSID(b, d.Group)
	}
	if d.DACL != nil && d.DACL != NullACL {
		b.WriteString("D:")
		d.DACL.writeSDDL(b)
	}
	if d.SACL != nil && d.SACL != NullACL {
		b.WriteString("S:")
		d.SACL.writeSDDL(b)
	}
}

// String returns the SDDL representation of the ACL.
func (acl *ACL) String() string {
	if acl == nil || acl == NullACL {
		return ""
	}
	var b strings.Builder
	acl.writeSDDL(&b)
	return b.String()
}

func (acl *ACL) writeSDDL(b *strings.Builder) {
	if acl.Protected {
		b.WriteByte('P')
	}
	for i := range acl.ACEs {
		acl.ACEs[i].writeSDDL(b)
	}
}

// String returns the SDDL representation of the ACE.
func (ace *ACE) String() string {
	if ace == nil || ace.Raw != nil {
		return ""
	}
	var b strings.Builder
	ace.writeSDDL(&b)
	return b.String()
}

func (ace *ACE) writeSDDL(b *strings.Builder) {
	if ace == nil || ace.Raw != nil {
		return
	}
	b.WriteByte('(')
	writeSDDLType(b, ace.Type)
	b.WriteByte(';')
	writeSDDLFlags(b, ace.Flags)
	b.WriteByte(';')
	writeSDDLRights(b, ace.Mask)
	b.WriteString(";;;")
	writeSDDLSID(b, ace.SID)
	b.WriteByte(')')
}

func writeSDDLType(b *strings.Builder, t ACEType) {
	switch t {
	case AccessAllowed:
		b.WriteByte('A')
	case AccessDenied:
		b.WriteByte('D')
	case SystemAudit:
		b.WriteString("AU")
	case 0x05:
		b.WriteString("OA")
	case 0x06:
		b.WriteString("OD")
	case 0x07:
		b.WriteString("OU")
	case 0x09:
		b.WriteString("XA")
	case 0x0a:
		b.WriteString("XD")
	case 0x0b:
		b.WriteString("XU")
	case 0x0d:
		b.WriteString("ZA")
	case 0x11:
		b.WriteString("ML")
	case 0x12:
		b.WriteString("SP")
	default:
		fmt.Fprintf(b, "0x%x", byte(t))
	}
}


func writeSDDLFlags(b *strings.Builder, flags ACEFlags) {
	if flags&ContainerInherit != 0 {
		b.WriteString("CI")
	}
	if flags&ObjectInherit != 0 {
		b.WriteString("OI")
	}
	if flags&NoPropagateInherit != 0 {
		b.WriteString("NP")
	}
	if flags&InheritOnly != 0 {
		b.WriteString("IO")
	}
	if flags&Inherited != 0 {
		b.WriteString("ID")
	}
	if flags&SuccessfulAccess != 0 {
		b.WriteString("SA")
	}
	if flags&FailedAccess != 0 {
		b.WriteString("FA")
	}
}

func writeSDDLRights(b *strings.Builder, mask AccessMask) {
	switch mask {
	case FileAllAccess:
		b.WriteString("FA")
		return
	case FileGenericRead:
		b.WriteString("FR")
		return
	case FileGenericWrite:
		b.WriteString("FW")
		return
	case FileGenericExecute:
		b.WriteString("FX")
		return
	}

	const knownRightsMask = GenericRead | GenericWrite | GenericExecute | GenericAll |
		WriteOwner | WriteDACL | ReadControl | Delete

	if mask != 0 && (mask&^knownRightsMask) == 0 {
		if mask&GenericRead != 0 {
			b.WriteString("GR")
		}
		if mask&GenericWrite != 0 {
			b.WriteString("GW")
		}
		if mask&GenericExecute != 0 {
			b.WriteString("GX")
		}
		if mask&GenericAll != 0 {
			b.WriteString("GA")
		}
		if mask&WriteOwner != 0 {
			b.WriteString("WO")
		}
		if mask&WriteDACL != 0 {
			b.WriteString("WD")
		}
		if mask&ReadControl != 0 {
			b.WriteString("RC")
		}
		if mask&Delete != 0 {
			b.WriteString("SD")
		}
		return
	}

	fmt.Fprintf(b, "0x%x", uint32(mask))
}

func writeSDDLSID(b *strings.Builder, sid *SID) {
	if sid == nil {
		return
	}
	b.WriteString(sddlSID(sid))
}

func sddlSID(sid *SID) string {
	if sid == nil {
		return ""
	}
	if sid.Revision == 1 {
		switch sid.IdentifierAuthority {
		case 1:
			if len(sid.SubAuthority) == 1 && sid.SubAuthority[0] == 0 {
				return "WD" // S-1-1-0
			}
		case 3:
			if len(sid.SubAuthority) == 1 {
				switch sid.SubAuthority[0] {
				case 0:
					return "CO" // S-1-3-0
				case 1:
					return "CG" // S-1-3-1
				case 4:
					return "OW" // S-1-3-4
				}
			}
		case 5:
			if len(sid.SubAuthority) == 1 {
				switch sid.SubAuthority[0] {
				case 2:
					return "NU" // S-1-5-2
				case 4:
					return "IU" // S-1-5-4
				case 6:
					return "SU" // S-1-5-6
				case 7:
					return "AN" // S-1-5-7
				case 9:
					return "ED" // S-1-5-9
				case 10:
					return "PS" // S-1-5-10
				case 11:
					return "AU" // S-1-5-11
				case 12:
					return "RC" // S-1-5-12
				case 18:
					return "SY" // S-1-5-18
				case 19:
					return "LS" // S-1-5-19
				case 20:
					return "NS" // S-1-5-20
				case 33:
					return "WR" // S-1-5-33
				}
			} else if len(sid.SubAuthority) == 2 && sid.SubAuthority[0] == 32 {
				switch sid.SubAuthority[1] {
				case 544:
					return "BA" // S-1-5-32-544
				case 545:
					return "BU" // S-1-5-32-545
				case 546:
					return "BG" // S-1-5-32-546
				case 547:
					return "PU" // S-1-5-32-547
				case 548:
					return "AO" // S-1-5-32-548
				case 549:
					return "SO" // S-1-5-32-549
				case 550:
					return "PO" // S-1-5-32-550
				case 551:
					return "BO" // S-1-5-32-551
				case 552:
					return "RE" // S-1-5-32-552
				case 553:
					return "RS" // S-1-5-32-553
				case 554:
					return "RU" // S-1-5-32-554
				case 555:
					return "RD" // S-1-5-32-555
				case 556:
					return "NO" // S-1-5-32-556
				case 558:
					return "MU" // S-1-5-32-558
				case 559:
					return "LU" // S-1-5-32-559
				case 568:
					return "IS" // S-1-5-32-568
				case 569:
					return "CY" // S-1-5-32-569
				case 573:
					return "ER" // S-1-5-32-573
				case 574:
					return "CD" // S-1-5-32-574
				case 575:
					return "RA" // S-1-5-32-575
				case 576:
					return "ES" // S-1-5-32-576
				case 577:
					return "MS" // S-1-5-32-577
				case 578:
					return "HA" // S-1-5-32-578
				case 579:
					return "AA" // S-1-5-32-579
				case 580:
					return "RM" // S-1-5-32-580
				}
			} else if len(sid.SubAuthority) == 6 && sid.SubAuthority[0] == 84 &&
				sid.SubAuthority[1] == 0 && sid.SubAuthority[2] == 0 &&
				sid.SubAuthority[3] == 0 && sid.SubAuthority[4] == 0 &&
				sid.SubAuthority[5] == 0 {
				return "UD" // S-1-5-84-0-0-0-0-0
			}
		case 15:
			if len(sid.SubAuthority) == 2 && sid.SubAuthority[0] == 2 && sid.SubAuthority[1] == 1 {
				return "AC" // S-1-15-2-1
			}
		case 16:
			if len(sid.SubAuthority) == 1 {
				switch sid.SubAuthority[0] {
				case 4096:
					return "LW" // S-1-16-4096
				case 8192:
					return "ME" // S-1-16-8192
				case 8448:
					return "MP" // S-1-16-8448
				case 12288:
					return "HI" // S-1-16-12288
				case 16384:
					return "SI" // S-1-16-16384
				}
			}
		}
	}
	return sid.String()
}

var tokenToSID = map[string]*SID{
	"WD": {Revision: 1, IdentifierAuthority: 1, SubAuthority: []uint32{0}},
	"CO": {Revision: 1, IdentifierAuthority: 3, SubAuthority: []uint32{0}},
	"CG": {Revision: 1, IdentifierAuthority: 3, SubAuthority: []uint32{1}},
	"OW": {Revision: 1, IdentifierAuthority: 3, SubAuthority: []uint32{4}},
	"NU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{2}},
	"IU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{4}},
	"SU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{6}},
	"AN": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{7}},
	"ED": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{9}},
	"PS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{10}},
	"AU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{11}},
	"RC": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{12}},
	"SY": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}},
	"LS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{19}},
	"NS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{20}},
	"WR": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{33}},
	"UD": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{84, 0, 0, 0, 0, 0}},
	"BA": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 544}},

	"BU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 545}},
	"BG": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 546}},
	"PU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 547}},
	"AO": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 548}},
	"SO": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 549}},
	"PO": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 550}},
	"BO": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 551}},
	"RE": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 552}},
	"RS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 553}},
	"RU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 554}},
	"RD": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 555}},
	"NO": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 556}},
	"MU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 558}},
	"LU": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 559}},
	"IS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 568}},
	"CY": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 569}},
	"ER": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 573}},
	"CD": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 574}},
	"RA": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 575}},
	"ES": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 576}},
	"MS": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 577}},
	"HA": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 578}},
	"AA": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 579}},
	"RM": {Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 580}},
	"AC": {Revision: 1, IdentifierAuthority: 15, SubAuthority: []uint32{2, 1}},
	"LW": {Revision: 1, IdentifierAuthority: 16, SubAuthority: []uint32{4096}},
	"ME": {Revision: 1, IdentifierAuthority: 16, SubAuthority: []uint32{8192}},
	"MP": {Revision: 1, IdentifierAuthority: 16, SubAuthority: []uint32{8448}},
	"HI": {Revision: 1, IdentifierAuthority: 16, SubAuthority: []uint32{12288}},
	"SI": {Revision: 1, IdentifierAuthority: 16, SubAuthority: []uint32{16384}},
}

func parseSIDString(s string) (*SID, error) {
	if sid, ok := tokenToSID[s]; ok {
		subs := make([]uint32, len(sid.SubAuthority))
		copy(subs, sid.SubAuthority)
		return &SID{
			Revision:            sid.Revision,
			IdentifierAuthority: sid.IdentifierAuthority,
			SubAuthority:        subs,
		}, nil
	}
	return ParseSID(s)
}

// ParseDescriptor parses an SDDL string into a Descriptor.
func ParseDescriptor(sddl string) (*Descriptor, error) {
	sddl = strings.TrimSpace(sddl)
	if sddl == "" {
		return &Descriptor{}, nil
	}

	type section struct {
		tag string
		val string
	}

	var sections []section
	inParen := false
	start := 0
	currentTag := ""

	i := 0
	for i < len(sddl) {
		switch sddl[i] {
		case '(':
			inParen = true
			i++
		case ')':
			inParen = false
			i++
		default:
			if !inParen && i+1 < len(sddl) && sddl[i+1] == ':' {
				tag := sddl[i : i+1]
				if tag == "O" || tag == "G" || tag == "D" || tag == "S" {
					if currentTag != "" {
						sections = append(sections, section{tag: currentTag, val: sddl[start:i]})
					} else if i > 0 && strings.TrimSpace(sddl[:i]) != "" {
						return nil, fmt.Errorf("unexpected content before first tag: %q", sddl[:i])
					}
					currentTag = tag
					start = i + 2
					i += 2
					continue
				}
			}
			i++
		}
	}
	if inParen {
		return nil, errors.New("unmatched parenthesis in SDDL")
	}
	if currentTag != "" {
		sections = append(sections, section{tag: currentTag, val: sddl[start:]})
	} else {
		return nil, fmt.Errorf("invalid SDDL string: %q", sddl)
	}

	d := &Descriptor{}
	for _, sec := range sections {
		switch sec.tag {
		case "O":
			if d.Owner != nil {
				return nil, errors.New("duplicate owner in SDDL")
			}
			owner, err := parseSIDString(sec.val)
			if err != nil {
				return nil, fmt.Errorf("invalid owner SID: %w", err)
			}
			d.Owner = owner
		case "G":
			if d.Group != nil {
				return nil, errors.New("duplicate group in SDDL")
			}
			group, err := parseSIDString(sec.val)
			if err != nil {
				return nil, fmt.Errorf("invalid group SID: %w", err)
			}
			d.Group = group
		case "D":
			if d.DACL != nil {
				return nil, errors.New("duplicate DACL in SDDL")
			}
			dacl, err := parseSDDLACL(sec.val)
			if err != nil {
				return nil, fmt.Errorf("invalid DACL: %w", err)
			}
			d.DACL = dacl
		case "S":
			if d.SACL != nil {
				return nil, errors.New("duplicate SACL in SDDL")
			}
			sacl, err := parseSDDLACL(sec.val)
			if err != nil {
				return nil, fmt.Errorf("invalid SACL: %w", err)
			}
			d.SACL = sacl
		}
	}

	return d, nil
}

// MustDescriptor parses an SDDL string into a Descriptor, panicking on error.
func MustDescriptor(s string) *Descriptor {
	d, err := ParseDescriptor(s)
	if err != nil {
		panic(err)
	}
	return d
}

func parseSDDLACL(s string) (*ACL, error) {
	acl := &ACL{Revision: aclRevision}
	parenIdx := strings.IndexByte(s, '(')
	flagsPart := s
	acesPart := ""
	if parenIdx >= 0 {
		flagsPart = s[:parenIdx]
		acesPart = s[parenIdx:]
	}

	for len(flagsPart) > 0 {
		if strings.HasPrefix(flagsPart, "P") {
			acl.Protected = true
			flagsPart = flagsPart[1:]
		} else if strings.HasPrefix(flagsPart, "AR") {
			flagsPart = flagsPart[2:]
		} else if strings.HasPrefix(flagsPart, "AI") {
			flagsPart = flagsPart[2:]
		} else {
			return nil, fmt.Errorf("unrecognized ACL flag: %q", flagsPart)
		}
	}

	for len(acesPart) > 0 {
		if acesPart[0] != '(' {
			return nil, fmt.Errorf("expected '(' at start of ACE: %q", acesPart)
		}
		end := strings.IndexByte(acesPart, ')')
		if end < 0 {
			return nil, errors.New("unclosed '(' in ACE")
		}
		aceStr := acesPart[1:end]
		ace, err := parseSDDLACE(aceStr)
		if err != nil {
			return nil, err
		}
		acl.ACEs = append(acl.ACEs, *ace)
		acesPart = acesPart[end+1:]
	}

	return acl, nil
}

func parseSDDLACE(s string) (*ACE, error) {
	parts := strings.Split(s, ";")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid ACE format: expected 6 fields, got %d", len(parts))
	}

	// [MS-DTYP] section 2.5.1.1 defines fields 4 and 5 as object GUIDs,
	// while section 2.4.4.3 defines the corresponding object ACE GUIDs and
	// presence flags; ACE has no representation for them, so reject them
	// rather than silently discarding them.
	if parts[3] != "" || parts[4] != "" {
		return nil, errors.New("unsupported object GUID fields in ACE")
	}

	aceType, err := parseSDDLType(parts[0])
	if err != nil {
		return nil, err
	}
	// [MS-DTYP] section 2.4.4.3 defines object ACEs with GUID-bearing
	// layouts that this SDDL parser cannot represent.
	switch aceType {
	case 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0f, 0x10:
		return nil, fmt.Errorf("unsupported ACE type: %q (0x%02x)", parts[0], byte(aceType))
	}

	flags, err := parseSDDLFlags(parts[1])
	if err != nil {
		return nil, err
	}

	mask, err := parseSDDLRights(parts[2])
	if err != nil {
		return nil, err
	}

	if parts[5] == "" {
		return nil, errors.New("missing SID in ACE")
	}
	sid, err := parseSIDString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid SID in ACE: %w", err)
	}

	return &ACE{
		Type:  aceType,
		Flags: flags,
		Mask:  mask,
		SID:   sid,
	}, nil
}

func parseSDDLType(s string) (ACEType, error) {
	switch s {
	case "A":
		return AccessAllowed, nil
	case "D":
		return AccessDenied, nil
	case "AU":
		return SystemAudit, nil
	case "OA":
		return 0x05, nil
	case "OD":
		return 0x06, nil
	case "OU":
		return 0x07, nil
	case "XA":
		return 0x09, nil
	case "XD":
		return 0x0a, nil
	case "XU":
		return 0x0b, nil
	case "ZA":
		return 0x0d, nil
	case "ML":
		return 0x11, nil
	case "SP":
		return 0x12, nil
	default:
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			v, err := strconv.ParseUint(s[2:], 16, 8)
			if err != nil {
				return 0, fmt.Errorf("invalid ACE type: %q", s)
			}
			return ACEType(v), nil
		}
		return 0, fmt.Errorf("unsupported ACE type: %q", s)
	}
}

func parseSDDLFlags(s string) (ACEFlags, error) {
	var flags ACEFlags
	for len(s) > 0 {
		if len(s) < 2 {
			return 0, fmt.Errorf("invalid ACE flags: %q", s)
		}
		token := s[:2]
		s = s[2:]
		switch token {
		case "CI":
			flags |= ContainerInherit
		case "OI":
			flags |= ObjectInherit
		case "NP":
			flags |= NoPropagateInherit
		case "IO":
			flags |= InheritOnly
		case "ID":
			flags |= Inherited
		case "SA":
			flags |= SuccessfulAccess
		case "FA":
			flags |= FailedAccess
		default:
			return 0, fmt.Errorf("unknown ACE flag: %q", token)
		}
	}
	return flags, nil
}

func parseSDDLRights(s string) (AccessMask, error) {
	if s == "" {
		return 0, nil
	}
	switch s {
	case "FA":
		return FileAllAccess, nil
	case "FR":
		return FileGenericRead, nil
	case "FW":
		return FileGenericWrite, nil
	case "FX":
		return FileGenericExecute, nil
	case "KA":
		return 0x000f003f, nil
	case "KR":
		return 0x00020019, nil
	case "KW":
		return 0x00020006, nil
	case "KX":
		return 0x00020019, nil
	}

	if s[0] >= '0' && s[0] <= '9' {
		v, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid numeric rights value: %q", s)
		}
		return AccessMask(v), nil
	}


	var mask AccessMask
	rem := s
	for len(rem) > 0 {
		if len(rem) < 2 {
			return 0, fmt.Errorf("invalid rights string: %q", s)
		}
		token := rem[:2]
		rem = rem[2:]
		switch token {
		case "GA":
			mask |= GenericAll
		case "GR":
			mask |= GenericRead
		case "GW":
			mask |= GenericWrite
		case "GX":
			mask |= GenericExecute
		case "RC":
			mask |= ReadControl
		case "SD":
			mask |= Delete
		case "WD":
			mask |= WriteDACL
		case "WO":
			mask |= WriteOwner
		case "CC":
			mask |= FileReadData
		case "DC":
			mask |= FileWriteData
		case "LC":
			mask |= FileAppendData
		case "SW":
			mask |= FileReadEA
		case "RP":
			mask |= FileWriteEA
		case "WP":
			mask |= FileExecute
		case "DT":
			mask |= FileDeleteChild
		case "LO":
			mask |= FileReadAttributes
		case "CR":
			mask |= FileWriteAttributes
		default:
			return 0, fmt.Errorf("unknown rights token: %q", token)
		}
	}
	return mask, nil
}
