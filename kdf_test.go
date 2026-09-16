package smb2

import (
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		keySize  int
		expected string
	}{
		{name: "128-bit", keySize: 16, expected: "ca3928a6664e3cfdc87eef2dff7c78ac"},
		{name: "256-bit", keySize: 32, expected: "bed7d5efc7ecf05d3df490baff03a3e43c8ed2f1976fed76ee4bbe50a3b11035"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected, err := hex.DecodeString(test.expected)
			if err != nil {
				t.Fatal(err)
			}
			actual := kdf([]byte("foo"), []byte("bar"), []byte("baz"), test.keySize)
			if string(actual) != string(expected) {
				t.Fatalf("kdf() = %x, want %x", actual, expected)
			}
		})
	}
}
