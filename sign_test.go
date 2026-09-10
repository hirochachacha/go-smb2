package smb2

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func TestSignSegments(t *testing.T) {
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, 112) // SMB2 header + WRITE body
	pkt[0], pkt[1] = 0xfe, 'S'

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}

	s := &session{signer: cmac.New(ciph)}

	// signing segments must produce the same signature as signing the
	// concatenated packet
	contiguous := append(append([]byte{}, pkt...), payload...)
	signedContiguous := s.sign(contiguous)

	signedSegments := s.sign(pkt, payload)

	if !bytes.Equal(smb2.PacketCodec(signedContiguous).Signature(), smb2.PacketCodec(signedSegments).Signature()) {
		t.Error("fail")
	}

	// the signature must also match a manual CMAC computation
	p := smb2.PacketCodec(signedSegments)
	signature := append([]byte(nil), p.Signature()...)
	p.SetSignature(zero[:])

	h := cmac.New(ciph)
	h.Write(pkt)
	h.Write(payload)
	h.Sum(pkt[:48])

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}

func TestSignEmptyOrTruncated(t *testing.T) {
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	s := &session{signer: cmac.New(ciph)}

	if res := s.sign(); res != nil {
		t.Errorf("sign() = %v, want nil", res)
	}
	if res := s.sign(nil); res != nil {
		t.Errorf("sign(nil) = %v, want nil", res)
	}
	short := []byte("short")
	if res := s.sign(short); !bytes.Equal(res, short) {
		t.Errorf("sign(short) = %v, want %v", res, short)
	}
}

func TestSign(t *testing.T) {
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4041393e756a048c9092c4e52dc7037190900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}

	signature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := cmac.New(ciph)

	p := smb2.PacketCodec(pkt)

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}

	p.SetSignature(zero[:])

	signer.Reset()
	signer.Write(pkt)
	signer.Sum(pkt[:48])
	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}
