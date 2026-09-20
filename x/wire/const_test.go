package wire

import "testing"

// TestDesiredAccessDirectoryConstants verifies directory DesiredAccess values
// defined in [MS-SMB2] 2.2.13.1.1 / MS-DTYP 2.4.4:
//
//	FILE_LIST_DIRECTORY   0x00000001
//	FILE_ADD_FILE         0x00000002
//	FILE_ADD_SUBDIRECTORY 0x00000004
//	FILE_TRAVERSE         0x00000020
func TestDesiredAccessDirectoryConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"FILE_LIST_DIRECTORY", FILE_LIST_DIRECTORY, 0x00000001},
		{"FILE_ADD_FILE", FILE_ADD_FILE, 0x00000002},
		{"FILE_ADD_SUBDIRECTORY", FILE_ADD_SUBDIRECTORY, 0x00000004},
		{"FILE_TRAVERSE", FILE_TRAVERSE, 0x00000020},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %#x, want %#x", tt.name, tt.got, tt.want)
		}
	}
}

func TestCipherConstants(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"AES128CCM", AES128CCM, 0x0001},
		{"AES128GCM", AES128GCM, 0x0002},
		{"AES256CCM", AES256CCM, 0x0003},
		{"AES256GCM", AES256GCM, 0x0004},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %#x, want %#x", tt.name, tt.got, tt.want)
		}
	}
}
