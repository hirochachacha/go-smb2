// ref: NIST SP 800-108 5.1

package smb2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// KDF in Counter Mode with h = 256 and r = 32.
func kdf(ki, label, context []byte, keySize int) []byte {
	h := hmac.New(sha256.New, ki)
	var outputBits [4]byte
	binary.BigEndian.PutUint32(outputBits[:], uint32(keySize*8))

	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(context)
	h.Write(outputBits[:])

	return h.Sum(nil)[:keySize]
}
