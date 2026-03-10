package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"net"
	"testing"

	"github.com/cloudsoda/go-smb2/internal/smb2"
)

const bufSize = 1 << 20 // 1MiB

// newBenchConn creates a conn wired to a net.Pipe() with pre-set negotiated
// parameters matching a typical SMB 3.0.2 connection. The returned cleanup
// function tears down the sender/receiver goroutines.
func newBenchConn(netConn net.Conn) (*conn, func()) {
	c := &conn{
		t:                   direct(netConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}
	go c.runSender()
	go c.runReciever()

	cleanup := func() {
		c.rdone <- struct{}{}
		netConn.Close()
	}
	return c, cleanup
}

// newGCM creates an AES-128-GCM cipher with nonce size 12.
func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err)
	}
	return gcm
}

// fakeServer reads SMB2 requests from t and writes back a fixed ReadResponse
// with the matching MessageId. It reuses all buffers to avoid polluting the
// benchmark with server-side allocations.
func fakeServer(t transport, responseData []byte) {
	// Pre-build response template.
	resp := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{
			Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR,
		},
		Data: responseData,
	}
	respBuf := make([]byte, resp.Size())
	resp.Encode(respBuf)

	reqBuf := make([]byte, bufSize)

	for {
		n, err := t.ReadSize()
		if err != nil {
			return
		}
		if _, err := t.Read(reqBuf[:n]); err != nil {
			return
		}

		p := smb2.PacketCodec(reqBuf[:n])

		// Patch MessageId and CreditResponse into the template.
		rp := smb2.PacketCodec(respBuf)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(p.CreditRequest())

		if _, err := t.Write(respBuf); err != nil {
			return
		}
	}
}

// fakeServerEncrypted reads encrypted SMB2 requests, decrypts them, and writes
// back encrypted ReadResponses. It reuses all buffers on the server side.
func fakeServerEncrypted(t transport, responseData []byte, dec, enc cipher.AEAD, sessionId uint64) {
	// Pre-build plaintext response template.
	resp := &smb2.ReadResponse{
		PacketHeader: smb2.PacketHeader{
			Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			SessionId: sessionId,
		},
		Data: responseData,
	}
	plainResp := make([]byte, resp.Size())
	resp.Encode(plainResp)

	reqBuf := make([]byte, bufSize+52+16)        // room for transform header + payload + tag
	decBuf := make([]byte, 0, bufSize+16)        // decrypt work buffer
	encBuf := make([]byte, 52+len(plainResp)+16) // encrypt output buffer

	for {
		n, err := t.ReadSize()
		if err != nil {
			return
		}
		if _, err := t.Read(reqBuf[:n]); err != nil {
			return
		}

		// Decrypt incoming request.
		tc := smb2.TransformCodec(reqBuf[:n])
		decBuf = append(decBuf[:0], tc.EncryptedData()...)
		decBuf = append(decBuf, tc.Signature()...)
		plain, err := dec.Open(decBuf[:0], tc.Nonce(dec.NonceSize()), decBuf, tc.AssociatedData())
		if err != nil {
			return
		}

		p := smb2.PacketCodec(plain)

		// Patch MessageId and CreditResponse into the template.
		rp := smb2.PacketCodec(plainResp)
		rp.SetMessageId(p.MessageId())
		rp.SetCreditResponse(p.CreditRequest())

		// Encrypt response.
		tt := smb2.TransformCodec(encBuf)
		tt.SetProtocolId()
		if err := tt.GenerateNonce(enc.NonceSize()); err != nil {
			return
		}
		tt.SetOriginalMessageSize(uint32(len(plainResp)))
		tt.SetFlags(smb2.Encrypted)
		tt.SetSessionId(sessionId)

		sealed := enc.Seal(encBuf[:52], tt.Nonce(enc.NonceSize()), plainResp, tt.AssociatedData())
		copy(encBuf[4:20], sealed[len(sealed)-16:]) // move tag to signature field

		if _, err := t.Write(sealed[:len(sealed)-16]); err != nil {
			return
		}
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
	}

	for _, sz := range sizes {
		b.Run("Plain/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			responseData := make([]byte, sz.n)
			go fakeServer(direct(serverConn), responseData)

			fid := &smb2.FileId{}
			ctx := context.Background()

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				req := &smb2.ReadRequest{
					Length:       uint32(sz.n),
					Offset:       0,
					FileId:       fid,
					MinimumCount: 1,
				}
				req.CreditCharge = 1
				rr, err := c.send(req, ctx)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := c.recv(rr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	for _, sz := range sizes {
		b.Run("Encrypted/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			// Set up symmetric keys. In production these come from the
			// session setup handshake; here we just need valid AES-128-GCM.
			keyC2S := make([]byte, 16)
			keyS2C := make([]byte, 16)
			if _, err := rand.Read(keyC2S); err != nil {
				panic(err)
			}
			if _, err := rand.Read(keyS2C); err != nil {
				panic(err)
			}

			s := &session{
				conn:           c,
				treeConnTables: make(map[uint32]*treeConn),
				sessionFlags:   smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA,
				sessionId:      0xdeadbeef,
				encrypter:      newGCM(keyC2S),
				decrypter:      newGCM(keyS2C),
			}
			c.session = s
			c.enableSession()

			responseData := make([]byte, sz.n)
			go fakeServerEncrypted(
				direct(serverConn), responseData,
				newGCM(keyC2S), // server decrypts with C2S key
				newGCM(keyS2C), // server encrypts with S2C key
				0xdeadbeef,
			)

			fid := &smb2.FileId{}
			ctx := context.Background()

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				req := &smb2.ReadRequest{
					Length:       uint32(sz.n),
					Offset:       0,
					FileId:       fid,
					MinimumCount: 1,
				}
				req.CreditCharge = 1
				rr, err := c.send(req, ctx)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := c.recv(rr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
