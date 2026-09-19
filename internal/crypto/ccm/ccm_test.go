package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"testing"
)

// run examples defined in Appendix C.
func Test(t *testing.T) {
	C4A := make([]byte, 524288/8)
	for i := range C4A {
		C4A[i] = byte(i)
	}

	examples := []struct {
		Key        []byte
		Nonce      []byte
		Data       []byte
		PlainText  []byte
		CipherText []byte
		TagLen     int
	}{
		{ // C.1
			[]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
			[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
			[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			[]byte{0x20, 0x21, 0x22, 0x23},
			[]byte{0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d},
			4,
		},
		{ // C.2
			[]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
			[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
			[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			[]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
			[]byte{0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d, 0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd},
			6,
		},
		{ // C.3
			[]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
			[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b},
			[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
			[]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},

			[]byte{0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5, 0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51},
			8,
		},
		{ // C.4
			[]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
			[]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c},
			C4A,
			[]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f},

			[]byte{0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37, 0x6a, 0x68, 0xc2, 0x96, 0x7e, 0x4d, 0xab, 0x61, 0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4, 0x84, 0x82, 0x85, 0x29, 0x46, 0x3c, 0xcf, 0x72, 0xb4, 0xac, 0x6b, 0xec, 0x93, 0xe8, 0x59, 0x8e, 0x7f, 0x0d, 0xad, 0xbc, 0xea, 0x5b},
			14,
		},
	}

	for _, ex := range examples {
		c, err := aes.NewCipher(ex.Key)
		if err != nil {
			t.Fatal(err)
		}

		ccm, err := NewCCMWithNonceAndTagSizes(c, len(ex.Nonce), ex.TagLen)
		if err != nil {
			t.Fatal(err)
		}

		CipherText := ccm.Seal(nil, ex.Nonce, ex.PlainText, ex.Data)

		if !bytes.Equal(ex.CipherText, CipherText) {
			t.Errorf("Seal() = %x, want %x", CipherText, ex.CipherText)
		}

		prefix := []byte("transform header")
		buf := make([]byte, len(prefix)+len(ex.PlainText)+16)
		copy(buf, prefix)
		copy(buf[len(prefix):], ex.PlainText)
		sealed := ccm.Seal(buf[:len(prefix)], ex.Nonce, buf[len(prefix):len(prefix)+len(ex.PlainText)], ex.Data)
		expected := append(append([]byte(nil), prefix...), ex.CipherText...)
		if !bytes.Equal(sealed, expected) {
			t.Errorf("in-place Seal() = %x, want %x", sealed, expected)
		}

		PlainText, err := ccm.Open(nil, ex.Nonce, ex.CipherText, ex.Data)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(ex.PlainText, PlainText) {
			t.Errorf("Open() = %x, want %x", PlainText, ex.PlainText)
		}
	}
}

func TestSealAssociatedDataLengthBoundaries(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 11)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	// Associated data is AD[i] = byte(i); 65280 is the largest length tested.
	data := make([]byte, 65280)
	for i := range data {
		data[i] = byte(i)
	}

	// Expected tags were generated with an independent CCM implementation
	// (Node.js crypto backed by OpenSSL) to check the associated data length
	// encoding boundaries defined in RFC 3610 2.2 (NIST SP 800-38C A.2.2).
	vectors := []struct {
		dataLen int
		tag     string
	}{
		{32639, "c75d17b48883247088b0fcc9f2967b49"},
		{32640, "e10e8494ed58cdf7c8cd7bc160de2e69"},
		{40000, "aab5da56a330553313197f0f9e5392a3"},
		{65279, "cd721070f0ec5552c2bcba5a42be1501"},
		{65280, "79473a20ee4736eb47aa9e1075a52f74"},
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		want, err := hex.DecodeString(v.tag)
		if err != nil {
			t.Fatal(err)
		}

		sealed := ccm.Seal(nil, nonce, nil, data[:v.dataLen])
		if !bytes.Equal(sealed, want) {
			t.Errorf("Seal() with %d bytes of associated data = %x, want %x", v.dataLen, sealed, want)
		}

		if _, err := ccm.Open(nil, nonce, want, data[:v.dataLen]); err != nil {
			t.Errorf("Open() with %d bytes of associated data failed: %v", v.dataLen, err)
		}
	}
}

func TestEmptyPlaintext(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	ccm, err := NewCCMWithNonceAndTagSizes(c, 12, 8)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, ccm.NonceSize())
	for _, data := range [][]byte{nil, []byte("additional data")} {
		ciphertext := ccm.Seal(nil, nonce, nil, data)
		plaintext, err := ccm.Open(nil, nonce, ciphertext, data)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if len(plaintext) != 0 {
			t.Errorf("Open() plaintext length = %d, want 0", len(plaintext))
		}
	}
}

func TestOpenShortCiphertext(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	ccm, err := NewCCMWithNonceAndTagSizes(c, 12, 8)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, ccm.NonceSize())
	for length := 0; length < ccm.Overhead(); length++ {
		t.Run("length="+strconv.Itoa(length), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("Open() panicked: %v", recovered)
				}
			}()

			if _, err := ccm.Open(nil, nonce, make([]byte, length), nil); err == nil {
				t.Error("Open() error = nil, want error")
			}
		})
	}
}

func TestOpenRejectsTamperedEmptyPlaintextTag(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	ccm, err := NewCCMWithNonceAndTagSizes(c, 12, 8)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, ccm.NonceSize())
	ciphertext := ccm.Seal(nil, nonce, nil, nil)
	ciphertext[0] ^= 1

	if _, err := ccm.Open(nil, nonce, ciphertext, nil); err == nil {
		t.Error("Open() error = nil, want authentication error")
	}
}

func TestConcurrentSealOpen(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewCCMWithNonceAndTagSizes(c, 12, 16)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			nonce := make([]byte, aead.NonceSize())
			binary.LittleEndian.PutUint64(nonce[:8], uint64(id))
			plaintext := []byte(fmt.Sprintf("plaintext from worker %d", id))
			ad := []byte(fmt.Sprintf("associated data %d", id))

			sealed := aead.Seal(nil, nonce, plaintext, ad)
			opened, err := aead.Open(nil, nonce, sealed, ad)
			if err != nil {
				t.Errorf("worker %d failed to open: %v", id, err)
				return
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("worker %d payload mismatch", id)
			}
		}(i)
	}
	wg.Wait()
}
