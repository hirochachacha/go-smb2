package smb2

import (
	"encoding/binary"
	"unicode/utf16"
)

var (
	le = binary.LittleEndian
)

func Roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func UTF16FromString(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

func UTF16ToString(s []uint16) string {
	return string(utf16.Decode(s))
}

func BytesToUTF16(bs []byte) []uint16 {
	if len(bs) == 0 {
		return nil
	}

	ws := make([]uint16, len(bs)/2)
	for i := range ws {
		ws[i] = le.Uint16(bs[2*i : 2*i+2])
	}
	return ws
}

func PutUTF16(bs []byte, ws []uint16) {
	for i, w := range ws {
		le.PutUint16(bs[2*i:2*i+2], w)
	}
}
