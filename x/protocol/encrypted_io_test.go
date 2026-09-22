package protocol

import (
	"context"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const encryptedBenchmarkChunk = 1 << 20

func newEncryptedBenchmarkTree(b *testing.B, responseData []byte) (*Tree, *conn, func()) {
	b.Helper()
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)

	keyC2S := make([]byte, 16)
	keyS2C := make([]byte, 16)
	c.session = &session{
		conn:         c,
		sessionFlags: wire.SMB2_SESSION_FLAG_ENCRYPT_DATA,
		sessionId:    0xdeadbeef,
		encrypter:    newGCM(keyC2S),
		decrypter:    newGCM(keyS2C),
	}
	c.enableSession()

	go fakeServerEncrypted(
		NewTransport(serverConn), responseData,
		newGCM(keyC2S), newGCM(keyS2C), 0xdeadbeef,
	)

	return &Tree{session: c.session, treeId: 0}, c, func() {
		cleanup()
		_ = serverConn.Close()
	}
}

func BenchmarkEncryptedRead(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{
		{name: "1KB", n: 1 << 10},
		{name: "64KB", n: 1 << 16},
		{name: "1MB", n: 1 << 20},
		{name: "10MB", n: 10 * (1 << 20)},
	} {
		b.Run(size.name, func(b *testing.B) {
			responseData := make([]byte, size.n)
			tree, _, cleanup := newEncryptedBenchmarkTree(b, responseData)
			defer cleanup()
			fd := wire.FileId{}
			ctx := context.Background()

			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for off := 0; off < size.n; {
					chunk := min(encryptedBenchmarkChunk, size.n-off)
					buf := make([]byte, chunk)
					res, err := tree.Request().WithFileID(fd).Append(&DirectReadRequest{
						ReadRequest: &wire.ReadRequest{
							Length: uint32(chunk), Offset: uint64(off), FileId: fd,
						},
						Buffer: buf,
					}).Do(ctx)
					if err != nil {
						b.Fatal(err)
					}
					if got := len(res.DirectData(0)); got != chunk {
						res.Close()
						b.Fatalf("short encrypted read: %d != %d", got, chunk)
					}
					res.Close()
					off += chunk
				}
			}
		})
	}
}

func BenchmarkEncryptedWrite(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{
		{name: "1KB", n: 1 << 10},
		{name: "64KB", n: 1 << 16},
		{name: "1MB", n: 1 << 20},
		{name: "10MB", n: 10 * (1 << 20)},
	} {
		b.Run(size.name, func(b *testing.B) {
			tree, _, cleanup := newEncryptedBenchmarkTree(b, nil)
			defer cleanup()
			fd := wire.FileId{}
			ctx := context.Background()
			data := make([]byte, size.n)

			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for off := 0; off < size.n; {
					chunk := min(encryptedBenchmarkChunk, size.n-off)
					res, err := tree.Request().WithFileID(fd).Write(data[off:off+chunk], uint64(off)).Do(ctx)
					if err != nil {
						b.Fatal(err)
					}
					if got := wire.WriteResponseDecoder(res.Data(0)).Count(); int(got) != chunk {
						res.Close()
						b.Fatalf("short encrypted write: %d != %d", got, chunk)
					}
					res.Close()
					off += chunk
				}
			}
		})
	}
}
