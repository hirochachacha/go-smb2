package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

const bufSize = 10 * (1 << 20) // 10MiB

// newBenchConn creates a conn wired to a net.Pipe() with pre-set negotiated
// parameters matching a typical SMB 3.0.2 connection. The returned cleanup
// function tears down the sender/receiver goroutines.
func newBenchConn(netConn net.Conn) (*conn, func()) {
	c := &conn{
		t:                   direct(netConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(512),
		rdone:               make(chan struct{}, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         1 << 20,
		maxWriteSize:        1 << 20,
		maxTransactSize:     1 << 20,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}
	c.account.charge(511) // replenish initial credits for bench connection
	go c.runReceiver()

	cleanup := func() {
		select {
		case c.rdone <- struct{}{}:
		default:
		}
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

// fakeServer reads SMB2 requests from t and writes back a fixed ReadResponse or WriteResponse.
func fakeServer(t transport, responseData []byte, sessionId uint64) {
	for {
		rp, err := t.ReadPacket()
		if err != nil {
			return
		}

		p := rp.codec()
		cmd := p.Command()
		msgId := p.MessageId()

		var respBuf []byte
		if cmd == smb2.SMB2_WRITE {
			wreq := smb2.WriteRequestDecoder(rp.data())
			wres := &smb2.WriteResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					SessionId: sessionId,
				},
				Count: wreq.Length(),
			}
			respBuf = make([]byte, wres.Size())
			wres.Encode(respBuf)
		} else {
			rreq := smb2.ReadRequestDecoder(rp.data())
			readLen := min(int(rreq.Length()), len(responseData))
			resp := &smb2.ReadResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					SessionId: sessionId,
				},
				Data: responseData[:readLen],
			}
			respBuf = make([]byte, resp.Size())
			resp.Encode(respBuf)
		}

		outPkt := smb2.PacketCodec(respBuf)
		outPkt.SetMessageId(msgId)
		outPkt.SetCreditResponse(p.CreditRequest())

		rp.close()

		if _, err := t.Writev(respBuf); err != nil {
			return
		}
	}
}

// fakeServerEncrypted reads encrypted SMB2 requests, decrypts them, and writes
// back encrypted responses.
func fakeServerEncrypted(t transport, responseData []byte, dec, enc cipher.AEAD, sessionId uint64) {
	decBuf := make([]byte, 0, bufSize+16) // decrypt work buffer

	for {
		rp, err := t.ReadPacket()
		if err != nil {
			return
		}

		// Decrypt incoming request.
		tc := rp.transformCodec()
		decBuf = append(decBuf[:0], tc.EncryptedData()...)
		decBuf = append(decBuf, tc.Signature()...)
		plain, err := dec.Open(decBuf[:0], tc.Nonce()[:dec.NonceSize()], decBuf, tc.AssociatedData())
		rp.close()
		if err != nil {
			return
		}

		p := smb2.PacketCodec(plain)
		cmd := p.Command()
		msgId := p.MessageId()

		var plainResp []byte
		if cmd == smb2.SMB2_WRITE {
			wreq := smb2.WriteRequestDecoder(plain[64:])
			wres := &smb2.WriteResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					SessionId: sessionId,
				},
				Count: wreq.Length(),
			}
			plainResp = make([]byte, wres.Size())
			wres.Encode(plainResp)
		} else {
			rreq := smb2.ReadRequestDecoder(plain[64:])
			readLen := min(int(rreq.Length()), len(responseData))
			resp := &smb2.ReadResponse{
				PacketHeader: smb2.PacketHeader{
					Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
					SessionId: sessionId,
				},
				Data: responseData[:readLen],
			}
			plainResp = make([]byte, resp.Size())
			resp.Encode(plainResp)
		}

		// Patch MessageId and CreditResponse into the template.
		outPkt := smb2.PacketCodec(plainResp)
		outPkt.SetMessageId(msgId)
		outPkt.SetCreditResponse(p.CreditRequest())

		// Encrypt response.
		encBuf := make([]byte, 52+len(plainResp)+16)
		tt := smb2.TransformCodec(encBuf)
		nonce := tt.Nonce()[:enc.NonceSize()]
		if _, err := rand.Read(nonce); err != nil {
			return
		}
		tt.SetProtocolId()
		tt.SetOriginalMessageSize(uint32(len(plainResp)))
		tt.SetFlags(smb2.Encrypted)
		tt.SetSessionId(sessionId)

		sealed := enc.Seal(encBuf[:52], nonce, plainResp, tt.AssociatedData())
		copy(encBuf[4:20], sealed[len(sealed)-16:]) // move tag to signature field

		if _, err := t.Writev(sealed[:len(sealed)-16]); err != nil {
			return
		}
	}
}

// newBenchFile constructs a File wired through the production
// Share → treeConn → session → conn chain, so benchmarks can
// exercise readAt and other production code paths. The caller
// must set up c.session before calling this.
func newBenchFile(c *conn) *File {
	tc := &treeConn{
		session: c.session,
	}

	fs := &Share{
		treeConn: tc,
	}

	return &File{
		fs: fs,
		fd: &smb2.FileId{},
	}
}

func BenchmarkReadAt(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run("Plain/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			responseData := make([]byte, sz.n)
			go fakeServer(direct(serverConn), responseData, 0)

			f := newBenchFile(c)
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.readAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short read: %d != %d", n, sz.n)
				}
			}
		})
	}

	for _, sz := range sizes {
		b.Run("Encrypted/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			keyC2S := make([]byte, 16)
			keyS2C := make([]byte, 16)
			if _, err := rand.Read(keyC2S); err != nil {
				panic(err)
			}
			if _, err := rand.Read(keyS2C); err != nil {
				panic(err)
			}

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA,
				sessionId:    0xdeadbeef,
				encrypter:    newGCM(keyC2S),
				decrypter:    newGCM(keyS2C),
			}
			c.enableSession()

			responseData := make([]byte, sz.n)
			go fakeServerEncrypted(
				direct(serverConn), responseData,
				newGCM(keyC2S),
				newGCM(keyS2C),
				0xdeadbeef,
			)

			f := newBenchFile(c)
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.readAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short read: %d != %d", n, sz.n)
				}
			}
		})
	}
}

func BenchmarkWriteAt(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run("Plain/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			go fakeServer(direct(serverConn), nil, 0)

			f := newBenchFile(c)
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.writeAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short write: %d != %d", n, sz.n)
				}
			}
		})
	}

	for _, sz := range sizes {
		b.Run("Encrypted/"+sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			keyC2S := make([]byte, 16)
			keyS2C := make([]byte, 16)
			if _, err := rand.Read(keyC2S); err != nil {
				panic(err)
			}
			if _, err := rand.Read(keyS2C); err != nil {
				panic(err)
			}

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA,
				sessionId:    0xdeadbeef,
				encrypter:    newGCM(keyC2S),
				decrypter:    newGCM(keyS2C),
			}
			c.enableSession()

			go fakeServerEncrypted(
				direct(serverConn), nil,
				newGCM(keyC2S),
				newGCM(keyS2C),
				0xdeadbeef,
			)

			f := newBenchFile(c)
			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				n, err := f.fs.writeAt(context.Background(), f.fd, buf, 0)
				if err != nil {
					b.Fatal(err)
				}
				if n != sz.n {
					b.Fatalf("short write: %d != %d", n, sz.n)
				}
			}
		})
	}
}

// fakeServerFull processes SMB2 commands for comprehensive benchmarks, including compound request chains.
func fakeServerFull(t transport, responseData []byte, dirEntries []byte, sessionId uint64) {
	dirQueryCount := 0

	for {
		rp, err := t.ReadPacket()
		if err != nil {
			return
		}
		reqBuf := rp.bytes()
		sz := len(reqBuf)

		off := 0
		var respBufs [][]byte

		for {
			p := smb2.PacketCodec(reqBuf[off:sz])
			cmd := p.Command()
			msgId := p.MessageId()
			nextCmd := p.NextCommand()

			var singleResp []byte

			switch cmd {
			case smb2.SMB2_CREATE:
				cres := &smb2.CreateResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					OplockLevel:    smb2.SMB2_OPLOCK_LEVEL_NONE,
					CreateAction:   1, // FILE_OPENED
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					AllocationSize: int64(len(responseData)),
					EndofFile:      int64(len(responseData)),
					FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL,
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				singleResp = make([]byte, cres.Size())
				cres.Encode(singleResp)

			case smb2.SMB2_CLOSE:
				clres := &smb2.CloseResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				singleResp = make([]byte, clres.Size())
				clres.Encode(singleResp)

			case smb2.SMB2_QUERY_DIRECTORY:
				dirQueryCount++
				if dirQueryCount%2 == 1 && dirEntries != nil {
					qdres := &smb2.QueryDirectoryResponse{
						PacketHeader: smb2.PacketHeader{
							Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
							SessionId: sessionId,
						},
						Output: rawEncoder(dirEntries),
					}
					singleResp = make([]byte, qdres.Size())
					qdres.Encode(singleResp)
				} else {
					eres := &smb2.ErrorResponse{
						PacketHeader: smb2.PacketHeader{
							Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
							SessionId: sessionId,
							Status:    0x80000006, // STATUS_NO_MORE_FILES
						},
						CommandCode: smb2.SMB2_QUERY_DIRECTORY,
					}
					singleResp = make([]byte, eres.Size())
					eres.Encode(singleResp)
				}

			case smb2.SMB2_QUERY_INFO:
				stdBuf := make([]byte, 104)
				binary.LittleEndian.PutUint64(stdBuf[40:48], uint64(len(responseData))) // AllocationSize
				binary.LittleEndian.PutUint64(stdBuf[48:56], uint64(len(responseData))) // EndOfFile
				binary.LittleEndian.PutUint32(stdBuf[56:60], 1)                         // NumberOfLinks
				binary.LittleEndian.PutUint32(stdBuf[64:68], uint32(smb2.FILE_ATTRIBUTE_NORMAL))

				qires := &smb2.QueryInfoResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Output: rawEncoder(stdBuf),
				}
				singleResp = make([]byte, qires.Size())
				qires.Encode(singleResp)

			case smb2.SMB2_WRITE:
				wreq := smb2.WriteRequestDecoder(reqBuf[off+64 : sz])
				wres := &smb2.WriteResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Count: wreq.Length(),
				}
				singleResp = make([]byte, wres.Size())
				wres.Encode(singleResp)

			case smb2.SMB2_READ:
				rreq := smb2.ReadRequestDecoder(reqBuf[off+64 : sz])
				readLen := min(int(rreq.Length()), len(responseData))
				resp := &smb2.ReadResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
					},
					Data: responseData[:readLen],
				}
				singleResp = make([]byte, resp.Size())
				resp.Encode(singleResp)

			default:
				eres := &smb2.ErrorResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						SessionId: sessionId,
						Status:    0xC0000002, // STATUS_NOT_IMPLEMENTED
					},
				}
				singleResp = make([]byte, eres.Size())
				eres.Encode(singleResp)
			}

			rp := smb2.PacketCodec(singleResp)
			rp.SetMessageId(msgId)
			rp.SetCreditResponse(p.CreditRequest())

			respBufs = append(respBufs, singleResp)

			if nextCmd == 0 {
				break
			}
			off += int(nextCmd)
		}

		var totalRespLen int
		for i, rb := range respBufs {
			if i < len(respBufs)-1 {
				padded := (len(rb) + 7) &^ 7
				totalRespLen += padded
			} else {
				totalRespLen += len(rb)
			}
		}

		compoundResp := make([]byte, totalRespLen)
		curr := 0
		for i, rb := range respBufs {
			copy(compoundResp[curr:], rb)
			if i < len(respBufs)-1 {
				padded := (len(rb) + 7) &^ 7
				smb2.PacketCodec(compoundResp[curr:]).SetNextCommand(uint32(padded))
				curr += padded
			}
		}

		rp.close()
		if _, err := t.Writev(compoundResp); err != nil {
			return
		}
	}
}

// makeBenchDirEntries constructs synthetic FileIdBothDirectoryInformation entries for Readdir benchmarks.
func makeBenchDirEntries(count int) []byte {
	var buf []byte
	for i := range count {
		name := utf16le.EncodeStringToBytes(fmt.Sprintf("file_%04d.txt", i))
		entryLen := 104 + len(name)
		paddedLen := (entryLen + 7) &^ 7

		entry := make([]byte, paddedLen)
		if i < count-1 {
			binary.LittleEndian.PutUint32(entry[0:4], uint32(paddedLen)) // NextEntryOffset
		}
		binary.LittleEndian.PutUint32(entry[4:8], uint32(i+1)) // FileIndex
		binary.LittleEndian.PutUint64(entry[40:48], 1024)      // EndOfFile
		binary.LittleEndian.PutUint64(entry[48:56], 4096)      // AllocationSize
		binary.LittleEndian.PutUint32(entry[56:60], uint32(smb2.FILE_ATTRIBUTE_NORMAL))
		binary.LittleEndian.PutUint32(entry[60:64], uint32(len(name))) // FileNameLength
		binary.LittleEndian.PutUint64(entry[96:104], uint64(i+1))      // FileId
		copy(entry[104:], name)

		buf = append(buf, entry...)
	}
	return buf
}

func BenchmarkReadFile(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			tc := &treeConn{session: c.session}
			fs := &Share{treeConn: tc}

			responseData := make([]byte, sz.n)
			go fakeServerFull(direct(serverConn), responseData, nil, 0)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				data, err := fs.ReadFile(context.Background(), "test.txt")
				if err != nil {
					b.Fatal(err)
				}
				if len(data) != sz.n {
					b.Fatalf("short read: %d != %d", len(data), sz.n)
				}
			}
		})
	}
}

func BenchmarkWriteFile(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"64KB", 1 << 16},
		{"1MB", 1 << 20},
		{"10MB", 10 * (1 << 20)},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{
				conn:         c,
				sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
			}
			c.enableSession()

			tc := &treeConn{session: c.session}
			fs := &Share{treeConn: tc}

			go fakeServerFull(direct(serverConn), nil, nil, 0)

			buf := make([]byte, sz.n)

			b.SetBytes(int64(sz.n))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				err := fs.WriteFile(context.Background(), "test.txt", buf, 0666)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReaddir(b *testing.B) {
	counts := []struct {
		name  string
		count int
	}{
		{"10Entries", 10},
		{"100Entries", 100},
		{"1000Entries", 1000},
	}

	for _, c := range counts {
		b.Run(c.name, func(b *testing.B) {
			clientConn, serverConn := net.Pipe()
			conn, cleanup := newBenchConn(clientConn)
			defer cleanup()

			conn.session = &session{
				conn:         conn,
				sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
			}
			conn.enableSession()

			dirData := makeBenchDirEntries(c.count)
			go fakeServerFull(direct(serverConn), nil, dirData, 0)

			f := newBenchFile(conn)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				f.noMoreFiles = false
				f.dirents = nil
				entries, err := f.Readdir(context.Background(), -1)
				if err != nil {
					b.Fatal(err)
				}
				if len(entries) != c.count {
					b.Fatalf("readdir entry count mismatch: %d != %d", len(entries), c.count)
				}
			}
		})
	}
}

func BenchmarkStat(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	c.session = &session{
		conn:         c,
		sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST,
	}
	c.enableSession()

	tc := &treeConn{session: c.session}
	fs := &Share{treeConn: tc}

	go fakeServerFull(direct(serverConn), nil, nil, 0)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := fs.Stat(context.Background(), "test.txt")
		if err != nil {
			b.Fatal(err)
		}
	}
}
