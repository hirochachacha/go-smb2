package cmac

import (
	"crypto/aes"
	"fmt"
	"testing"
)

func BenchmarkWrite(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	mac := New(block)
	for _, size := range []int{4096, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			message := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				mac.Reset()
				mac.Write(message)
				mac.Sum(nil)
			}
		})
	}
}
