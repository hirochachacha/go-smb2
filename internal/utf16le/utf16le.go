package utf16le

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	le = binary.LittleEndian
)

func EncodedStringLen(s string) int {
	l := 0
	for _, r := range s {
		if 0x10000 <= r && r <= '\U0010FFFF' {
			l += 4
		} else {
			l += 2
		}
	}
	return l
}

func EncodeString(dst []byte, src string) int {
	n := 0
	for _, r := range src {
		if r <= 0xffff {
			le.PutUint16(dst[n:], uint16(r))
			n += 2
		} else {
			r1, r2 := utf16.EncodeRune(r)
			le.PutUint16(dst[n:], uint16(r1))
			le.PutUint16(dst[n+2:], uint16(r2))
			n += 4
		}
	}
	return n
}

func EncodeStringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	bs := make([]byte, EncodedStringLen(s))
	EncodeString(bs, s)
	return bs
}

func DecodeToString(bs []byte) string {
	n := len(bs) / 2
	if n == 0 {
		return ""
	}
	if le.Uint16(bs[2*(n-1):2*n]) == 0 {
		n--
	}
	if n == 0 {
		return ""
	}

	// Decode into a stack buffer so typical names cost only the string
	// allocation; append moves longer names to the heap.
	var stack [256]byte
	buf := stack[:0]
	for i := 0; i < n; i++ {
		u := le.Uint16(bs[2*i : 2*i+2])
		switch {
		case u < utf8.RuneSelf:
			buf = append(buf, byte(u))
		case u < 0xd800 || u >= 0xe000:
			buf = utf8.AppendRune(buf, rune(u))
		case u <= 0xdbff && i+1 < n && isLowSurrogate(le.Uint16(bs[2*(i+1):2*(i+2)])):
			buf = utf8.AppendRune(buf, utf16.DecodeRune(rune(u), rune(le.Uint16(bs[2*(i+1):2*(i+2)]))))
			i++
		default:
			buf = utf8.AppendRune(buf, utf8.RuneError)
		}
	}
	return string(buf)
}

func isLowSurrogate(u uint16) bool { return u >= 0xdc00 && u <= 0xdfff }
