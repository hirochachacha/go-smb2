package security

import (
	"encoding/binary"
	"fmt"
)

// validateRawACEBody checks known layouts retained as raw bytes on decode.
// Encoding raw bytes deliberately does not impose these checks on callers.
func validateRawACEBody(ace []byte) error {
	sidOffset := 8 // Header and Mask.
	switch ACEType(ace[0]) {
	case 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0f:
		// [MS-DTYP] 2.4.4.3: Flags controls the two optional GUIDs.
		if len(ace) < 12 {
			return fmt.Errorf("truncated object ACE")
		}
		flags := binary.LittleEndian.Uint32(ace[8:12])
		if flags & ^uint32(3) != 0 {
			return fmt.Errorf("invalid object ACE flags")
		}
		sidOffset = 12
		if flags&1 != 0 {
			sidOffset += 16
		}
		if flags&2 != 0 {
			sidOffset += 16
		}
	case 0x09, 0x0a, 0x0d, 0x12:
		// Callback ACEs have a SID followed by opaque application data.
	default:
		// Unknown and reserved types have no layout defined here.
		return nil
	}
	if len(ace) < sidOffset {
		return fmt.Errorf("truncated ACE fields")
	}
	sid, err := decodeSID(ace[sidOffset:])
	if err != nil {
		return fmt.Errorf("invalid raw ACE SID: %w", err)
	}
	if ACEType(ace[0]) == 0x12 {
		// [MS-DTYP] 2.4.4.15 requires a zero mask and the Everyone SID.
		if binary.LittleEndian.Uint32(ace[4:8]) != 0 || sid.IdentifierAuthority != 1 || len(sid.SubAuthority) != 1 || sid.SubAuthority[0] != 0 {
			return fmt.Errorf("invalid resource attribute ACE")
		}
		return validateResourceClaim(ace[sidOffset+sid.Size():])
	}
	// ACE_HEADER permits AceSize to exceed the sum of its fields. Keep
	// trailing bytes, including callback application data, in Raw.
	return nil
}
