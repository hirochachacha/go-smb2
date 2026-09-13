package security

import "testing"

func TestACLNullAndEmptyRepresentationsAreDistinct(t *testing.T) {
	if NullACL == nil {
		t.Fatal("NullACL is nil")
	}
	descriptor := &Descriptor{
		DACL: NullACL,
		SACL: &ACL{ACEs: []ACE{}},
	}

	if descriptor.DACL != NullACL {
		t.Fatal("DACL does not represent a NULL ACL")
	}
	if descriptor.SACL == nil || descriptor.SACL == NullACL || len(descriptor.SACL.ACEs) != 0 {
		t.Fatal("SACL does not represent an empty ACL")
	}
	if (&Descriptor{}).DACL != nil {
		t.Fatal("an unselected ACL does not have the nil representation")
	}
}
