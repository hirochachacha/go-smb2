package ccm

import (
	"crypto/aes"
	"fmt"
	"testing"
)

func BenchmarkSeal(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	aead, err := NewCCMWithNonceAndTagSizes(block, 11, 16)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{4096, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size+16)
			nonce := make([]byte, 11)
			associatedData := make([]byte, 52)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				aead.Seal(ciphertext[:0], nonce, plaintext, associatedData)
			}
		})
	}
}
