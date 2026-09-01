package utf16le

import (
	"bytes"
	"testing"
)

func TestUTF16LE(t *testing.T) {
	testCases := []string{
		"",
		"a",
		"hello world",
		"日本語テスト",
		"😀😃😄😁",
		"mixed 日本語 and english 😀",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			encodedBytes := EncodeStringToBytes(tc)
			expectedLen := EncodedStringLen(tc)
			if len(encodedBytes) != expectedLen {
				t.Errorf("EncodedStringLen mismatch for %q: got %d, want %d", tc, len(encodedBytes), expectedLen)
			}

			dst := make([]byte, expectedLen)
			n := EncodeString(dst, tc)
			if n != expectedLen {
				t.Errorf("EncodeString length mismatch for %q: got %d, want %d", tc, n, expectedLen)
			}
			if !bytes.Equal(dst, encodedBytes) {
				t.Errorf("EncodeString mismatch for %q", tc)
			}

			decoded := DecodeToString(encodedBytes)
			if decoded != tc {
				t.Errorf("DecodeToString mismatch: got %q, want %q", decoded, tc)
			}

			if len(encodedBytes) > 0 {
				// With trailing null byte (common in SMB2 strings)
				nullTerminated := append(append([]byte(nil), encodedBytes...), 0, 0)
				decodedNull := DecodeToString(nullTerminated)
				if decodedNull != tc {
					t.Errorf("DecodeToString with null terminator mismatch: got %q, want %q", decodedNull, tc)
				}
			}
		})
	}
}

func BenchmarkEncodeString(b *testing.B) {
	s := "share/subfolder/test_file_name_12345.txt"
	dst := make([]byte, EncodedStringLen(s))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EncodeString(dst, s)
	}
}

func BenchmarkDecodeToString(b *testing.B) {
	s := "share/subfolder/test_file_name_12345.txt"
	bs := EncodeStringToBytes(s)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DecodeToString(bs)
	}
}
