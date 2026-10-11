package utf16le

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestUTF16LE(t *testing.T) {
	t.Parallel()
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

func TestDecodeToStringMatchesUTF16Decode(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("日本語😀a", 40)
	for _, units := range [][]uint16{
		{0xd800},
		{0xdc00, 'a'},
		{0xd800, 'a', 0xdbff},
		{0xd83d, 0xde00, 0xd83d},
		{'a', 0},
		{'a', 0, 0},
		{0, 'a'},
		utf16.Encode([]rune(long)),
		append(utf16.Encode([]rune(long)), 0xd800, 0),
	} {
		raw := make([]byte, 0, 2*len(units)+1)
		for _, u := range units {
			raw = binary.LittleEndian.AppendUint16(raw, u)
		}
		want := units
		if len(want) > 0 && want[len(want)-1] == 0 {
			want = want[:len(want)-1]
		}
		if got, want := DecodeToString(raw), string(utf16.Decode(want)); got != want {
			t.Errorf("DecodeToString(%x) = %q, want %q", raw, got, want)
		}
		// A trailing odd byte is not a code unit.
		if got, want := DecodeToString(append(raw, 'x')), string(utf16.Decode(want)); got != want {
			t.Errorf("DecodeToString(%x + odd byte) = %q, want %q", raw, got, want)
		}
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
