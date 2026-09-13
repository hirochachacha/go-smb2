package security

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	maxSubAuthorities = 15
)

// ParseSID parses the SID string format defined by [MS-DTYP] section 2.4.2.1.
func ParseSID(s string) (*SID, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 4 || parts[0] != "S" || parts[1] != "1" {
		return nil, fmt.Errorf("invalid SID %q", s)
	}
	if len(parts)-3 > maxSubAuthorities {
		return nil, fmt.Errorf("invalid SID %q: too many subauthorities", s)
	}

	authority, err := parseIdentifierAuthority(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid SID %q: %w", s, err)
	}

	subAuthorities := make([]uint32, len(parts)-3)
	for i, part := range parts[3:] {
		value, err := parseDecimal(part, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID %q: subauthority %d: %w", s, i, err)
		}
		subAuthorities[i] = uint32(value)
	}

	return &SID{
		Revision:            1,
		IdentifierAuthority: authority,
		SubAuthority:        subAuthorities,
	}, nil
}

func parseIdentifierAuthority(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if len(s) != 14 {
			return 0, fmt.Errorf("identifier authority must contain 12 hexadecimal digits")
		}
		value, err := strconv.ParseUint(s[2:], 16, 48)
		if err != nil {
			return 0, fmt.Errorf("invalid identifier authority")
		}
		if value < 1<<32 {
			return 0, fmt.Errorf("identifier authority below 2^32 must be decimal")
		}
		return value, nil
	}

	value, err := parseDecimal(s, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid identifier authority")
	}
	return value, nil
}

func parseDecimal(s string, bitSize int) (uint64, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("invalid decimal number")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid decimal number")
		}
	}
	value, err := strconv.ParseUint(s, 10, bitSize)
	if err != nil {
		return 0, fmt.Errorf("decimal number is out of range")
	}
	return value, nil
}

// MustSID is like ParseSID but panics if s is not a valid SID.
func MustSID(s string) *SID {
	sid, err := ParseSID(s)
	if err != nil {
		panic(err)
	}
	return sid
}
