package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestMakeOutstandingCompoundRequest(t *testing.T) {
	req := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)

	req1 := &smb2.CreateRequest{
		DesiredAccess: smb2.DELETE,
	}

	req2 := &smb2.CloseRequest{}

	reqs := []smb2.Packet{req1, req2}

	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)

	rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, 2)
	req.Len(parts, 1)
	pkt := parts[0]
	req.Equal(uint64(0), rrs[0].msgId)
	req.Equal(uint64(1), rrs[1].msgId)

	// Check NextCommand alignment in header
	p1 := smb2.PacketCodec(pkt)
	req.Equal(smb2.SMB2_CREATE, p1.Command())
	req.Equal(uint64(0), p1.MessageId())
	req.True(p1.NextCommand() > 0)
	req.Equal(uint32(0), p1.NextCommand()&7) // 8-byte aligned

	nextOff := p1.NextCommand()
	p2 := smb2.PacketCodec(pkt[nextOff:])
	req.Equal(smb2.SMB2_CLOSE, p2.Command())
	req.Equal(uint64(1), p2.MessageId())
	req.Equal(uint32(0), p2.NextCommand())
	req.True(p2.Flags()&smb2.SMB2_FLAGS_RELATED_OPERATIONS != 0)
}

func TestMakeOutstandingRequestDirectWrite(t *testing.T) {
	for _, size := range []int{16, 4096} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			req := require.New(t)

			c := &conn{
				t:                   rejectingTransport{},
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(2),
			}
			c.account.charge(2)
			c.session = &session{conn: c}
			c.enableSession()

			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i)
			}

			wr := &smb2.WriteRequest{
				Offset: 0x1000,
				FileId: &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				Data:   data,
			}

			msgIds, _, err := c.account.loan(context.Background(), wr)
			req.NoError(err)

			rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, wr)
			req.NoError(err)
			req.Len(rrs, 1)
			req.Equal(uint64(0), rrs[0].msgId)
			req.Len(parts, 2)
			req.Equal(data, parts[1])
			req.Same(&data[0], &parts[1][0])
			// pkt holds the fixed part only: header + body without the payload
			req.Equal(64+48, len(parts[0]))

			// the concatenation of parts must be identical to the
			// contiguous encoding of the same request
			full := make([]byte, wr.Size())
			wr.Encode(full)
			req.Equal(full, concat(parts))
		})
	}
}

func directIOCiphers(t *testing.T) map[string]cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 16))
	require.NoError(t, err)
	ccmCipher, err := ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	require.NoError(t, err)
	return map[string]cipher.AEAD{"GCM": newGCM(make([]byte, 16)), "CCM": ccmCipher}
}

func TestMakeOutstandingRequestEncryptedWrite(t *testing.T) {
	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			for position := 0; position < 3; position++ {
				req := require.New(t)

				c := &conn{
					t:                   rejectingTransport{},
					outstandingRequests: newOutstandingRequests(),
					account:             openAccount(2),
				}
				c.account.charge(2)
				c.session = &session{
					conn:      c,
					encrypter: aead,
					sessionId: 0x100,
				}
				c.enableSession()

				data := make([]byte, 4097)
				for i := range data {
					data[i] = byte(i)
				}

				wr := &smb2.WriteRequest{
					Offset: 0x1000,
					FileId: &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					Data:   data,
				}

				requests := []smb2.Packet{&smb2.EchoRequest{}, &smb2.EchoRequest{}}
				requests = append(requests, nil)
				copy(requests[position+1:], requests[position:])
				requests[position] = wr
				msgIds := []uint64{0, 1, 2}
				// The encrypted wire message remains contiguous, but direct encoding puts
				// the plaintext straight into the encryption buffer.
				rrs, parts, err := c.makeOutstandingRequest(context.Background(), true, msgIds, requests...)
				req.NoError(err)
				req.Len(rrs, 3)
				req.Len(parts, 1)
				req.Equal(uint32(len(concat(parts))-52), smb2.TransformCodec(parts[0]).OriginalMessageSize())
				req.Empty(c.encodeBuf)

				tc := smb2.TransformCodec(parts[0])
				ciphertext := append(append([]byte(nil), tc.EncryptedData()...), tc.Signature()...)
				plaintext, err := c.session.encrypter.Open(nil, tc.Nonce()[:c.session.encrypter.NonceSize()], ciphertext, tc.AssociatedData())
				req.NoError(err)
				want := encodeContiguous(requests, nil)
				req.Equal(want, plaintext)
			}
		})
	}
}

// encodeContiguous encodes the requests into a single contiguous buffer,
// mirroring the generic compound path (alignment, chaining flags and per
// sub-packet signing included). It is called after makeOutstandingRequest so
// both paths see the same request state.
func encodeContiguous(reqs []smb2.Packet, s *session) []byte {
	total := 0
	spans := make([]int, len(reqs))
	for i, req := range reqs {
		span := req.Size()
		if i < len(reqs)-1 {
			span = smb2.Roundup(span, 8)
			req.SetNextCommand(uint32(span))
		} else {
			req.SetNextCommand(0)
		}
		if i > 0 {
			req.SetFlags(smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		}
		spans[i] = span
		total += span
	}

	pkt := make([]byte, total)
	off := 0
	for i, req := range reqs {
		req.Encode(pkt[off:])
		if s != nil {
			s.sign(pkt[off : off+spans[i]])
		}
		off += spans[i]
	}
	return pkt
}

func concat(parts [][]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestMakeOutstandingRequestDirectCompoundWrite(t *testing.T) {
	req := require.New(t)

	c := &conn{
		t:                   rejectingTransport{},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(3),
		requireSigning:      true,
	}
	c.account.charge(3)
	signingKey := kdf([]byte("0123456789abcdef"), []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	ciph, err := aes.NewCipher(signingKey)
	req.NoError(err)
	c.session = &session{conn: c, signer: cmac.New(ciph)}
	c.enableSession()

	data := make([]byte, 4094) // 112+4096 is 8-byte aligned, so use 4094 to force padding
	for i := range data {
		data[i] = byte(i)
	}

	reqs := []smb2.Packet{
		&smb2.CreateRequest{DesiredAccess: smb2.DELETE},
		&smb2.WriteRequest{
			Offset: 0x1000,
			FileId: &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
			Data:   data,
		},
		&smb2.CloseRequest{},
	}

	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)

	rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, 3)
	req.Equal([]uint64{0, 1, 2}, []uint64{rrs[0].msgId, rrs[1].msgId, rrs[2].msgId})

	// parts must be [prefix | payload | suffix]: the WRITE's fixed part ends
	// at 64+48, followed by the payload taken from the caller's buffer and
	// the remaining padding plus the CLOSE request
	req.Len(parts, 3)
	req.Equal(data, parts[1])
	req.Same(&data[0], &parts[1][0])
	createSize := smb2.Roundup((&smb2.CreateRequest{DesiredAccess: smb2.DELETE}).Size(), 8)
	req.Equal(createSize+64+48, len(parts[0]))
	// the suffix starts with the 2 bytes of padding after the payload
	req.Equal(make([]byte, 2), parts[2][:2])

	// the concatenation of parts must be identical to the contiguous
	// encoding of the same request chain (signatures included)
	req.Equal(encodeContiguous(reqs, c.session), concat(parts))
}

func TestMakeOutstandingRequestWriteBoundaries(t *testing.T) {
	for _, name := range []string{"first", "last", "empty", "multiple"} {
		t.Run(name, func(t *testing.T) {
			req := require.New(t)
			payload := []byte("payload") // Forces padding when followed by another request.
			wr := &smb2.WriteRequest{FileId: &smb2.FileId{}, Data: payload}
			var reqs []smb2.Packet
			wantParts := 1
			switch name {
			case "first":
				reqs = []smb2.Packet{wr, &smb2.CloseRequest{}}
				wantParts = 3
			case "last":
				reqs = []smb2.Packet{&smb2.CreateRequest{}, wr}
				wantParts = 2
			case "empty":
				wr.Data = nil
				reqs = []smb2.Packet{wr}
			case "multiple":
				reqs = []smb2.Packet{wr, &smb2.WriteRequest{
					FileId: &smb2.FileId{}, Data: []byte("second payload"),
				}}
			}

			c := &conn{
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(3),
				requireSigning:      true,
			}
			c.account.charge(3)
			ciph, err := aes.NewCipher([]byte("0123456789abcdef"))
			req.NoError(err)
			c.session = &session{conn: c, signer: cmac.New(ciph)}
			c.enableSession()

			msgIds, _, err := c.account.loan(context.Background(), reqs...)
			req.NoError(err)
			rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
			req.NoError(err)
			req.Len(rrs, len(reqs))
			req.Len(parts, wantParts)
			if wantParts > 1 {
				req.Equal(payload, parts[1])
				req.Same(&payload[0], &parts[1][0])
			}
			if name == "empty" {
				req.Len(parts[0], 64+48+1)
			}
			req.Equal(encodeContiguous(reqs, c.session), concat(parts))
		})
	}
}

func TestCompoundBuilderIntegration(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}

	// Mock server reading compound request and responding with compound response
	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		p1 := smb2.PacketCodec(reqBuf)

		// Build compound response: Response 1 (CREATE, 64 header + 88 body = 152 bytes, aligned to 160)
		res1 := make([]byte, 160)
		rp1 := smb2.PacketCodec(res1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_CREATE)
		rp1.SetMessageId(p1.MessageId())
		rp1.SetSessionId(p1.SessionId())
		rp1.SetTreeId(p1.TreeId())
		rp1.SetNextCommand(160)
		binary.LittleEndian.PutUint16(res1[64:66], 89) // CreateResponse structure size

		// Response 2 (CLOSE, 64 header + 60 body = 124 bytes)
		res2 := make([]byte, 124)
		rp2 := smb2.PacketCodec(res2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetMessageId(p1.MessageId() + 1)
		rp2.SetSessionId(p1.SessionId())
		rp2.SetTreeId(p1.TreeId())
		rp2.SetNextCommand(0)
		binary.LittleEndian.PutUint16(res2[64:66], 60) // CloseResponse structure size

		compoundResp := append(res1, res2...)
		direct(serverConn).Writev(compoundResp)
	}()

	go c.runReceiver()

	cReq := &smb2.CreateRequest{DesiredAccess: smb2.DELETE}
	clsReq := &smb2.CloseRequest{}

	res, err := tc.request().
		add(cReq).
		add(clsReq).
		sendRecv(context.Background())

	req.NoError(err)
	defer res.close()
	req.NotNil(res.packet(0))
	req.NotNil(res.packet(1))
	req.Equal(smb2.SMB2_CREATE, res.packet(0).codec().Command())
	req.Equal(smb2.SMB2_CLOSE, res.packet(1).codec().Command())
}
