package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/v2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestMakeOutstandingCompoundRequest(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)

	req1 := &smb2.CreateRequest{
		DesiredAccess: smb2.DELETE,
	}
	req1.SetFlags(smb2.SMB2_FLAGS_DFS_OPERATIONS)

	req2 := &smb2.CloseRequest{}
	req2.SetFlags(smb2.SMB2_FLAGS_DFS_OPERATIONS)

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
	req.Equal(uint32(smb2.SMB2_FLAGS_DFS_OPERATIONS), p1.Flags())
	req.True(p1.NextCommand() > 0)
	req.Equal(uint32(0), p1.NextCommand()&7) // 8-byte aligned

	nextOff := p1.NextCommand()
	p2 := smb2.PacketCodec(pkt[nextOff:])
	req.Equal(smb2.SMB2_CLOSE, p2.Command())
	req.Equal(uint64(1), p2.MessageId())
	req.Equal(uint32(smb2.SMB2_FLAGS_DFS_OPERATIONS|smb2.SMB2_FLAGS_RELATED_OPERATIONS), p2.Flags())
	req.Equal(uint32(0), p2.NextCommand())
	req.True(p2.Flags()&smb2.SMB2_FLAGS_RELATED_OPERATIONS != 0)
}

func TestSecurityRequestBuilderFields(t *testing.T) {
	t.Parallel()
	req := (&treeConn{}).request().withFileId(&smb2.FileId{})
	selection := uint32(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	req.queryInfo(smb2.SMB2_0_INFO_SECURITY, 0, selection, 4096)
	query := req.pkts[0].(*smb2.QueryInfoRequest)
	if query.InfoType != smb2.SMB2_0_INFO_SECURITY || query.FileInfoClass != 0 || query.AdditionalInformation != selection || query.OutputBufferLength != 4096 {
		t.Fatalf("security query fields = %#v", query)
	}

	req = (&treeConn{}).request().withFileId(&smb2.FileId{})
	req.setInfo(smb2.SMB2_0_INFO_SECURITY, 0, selection, rawEncoder{})
	set := req.pkts[0].(*smb2.SetInfoRequest)
	if set.InfoType != smb2.SMB2_0_INFO_SECURITY || set.FileInfoClass != 0 || set.AdditionalInformation != selection {
		t.Fatalf("security set fields = %#v", set)
	}
}

func TestMakeOutstandingRequestCompoundCreditHeaders(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(9)

	reqs := []smb2.Packet{
		&smb2.CreateRequest{},
		&smb2.QueryInfoRequest{FileId: &smb2.FileId{}},
		&smb2.CloseRequest{},
	}
	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)
	req.Equal([]uint64{0, 1, 2}, msgIds)

	rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, len(reqs))
	req.Len(parts, 1)

	wantCommands := []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_QUERY_INFO, smb2.SMB2_CLOSE}
	off := 0
	var totalCreditRequest uint32
	for i, wantCommand := range wantCommands {
		p := smb2.PacketCodec(parts[0][off:])
		req.Equal(wantCommand, p.Command())
		req.Equal(uint16(1), p.CreditCharge())
		req.Equal(uint16(1), p.CreditRequest())
		totalCreditRequest += uint32(p.CreditRequest())

		if i < len(wantCommands)-1 {
			req.NotZero(p.NextCommand())
			req.Equal(uint32(0), p.NextCommand()&7)
			off += int(p.NextCommand())
		} else {
			req.Equal(uint32(0), p.NextCommand())
		}
	}
	req.Equal(uint32(3), totalCreditRequest)
}

func TestMakeOutstandingRequestCompoundCreditRequestUint16Boundary(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(^uint16(0)),
	}
	c.account.charge(2)
	reqs := []smb2.Packet{&smb2.CreateRequest{}, &smb2.CreateRequest{}, &smb2.CreateRequest{}}

	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)
	req.Equal([]uint16{65533, 1, 1}, []uint16{
		creditRequest(reqs[0]), creditRequest(reqs[1]), creditRequest(reqs[2]),
	})

	rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, len(reqs))
	req.Len(parts, 1)

	pkt := parts[0]
	off := 0
	var totalCreditRequest uint32
	for i, p := range reqs {
		codec := smb2.PacketCodec(pkt[off:])
		req.Equal(creditRequest(p), codec.CreditRequest())
		totalCreditRequest += uint32(codec.CreditRequest())
		if i < len(reqs)-1 {
			off += int(codec.NextCommand())
		}
	}
	req.Equal(uint32(65535), totalCreditRequest)
}

func TestMakeOutstandingRequestCompoundCreditChargeOverflowRejected(t *testing.T) {
	t.Parallel()
	req := require.New(t)
	a := openAccount(^uint16(0))
	reqs := make([]smb2.Packet, 65536)
	for i := range reqs {
		reqs[i] = &smb2.CreateRequest{}
	}

	msgIds, charge, err := a.loan(context.Background(), reqs...)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Nil(msgIds)
	req.Equal(uint16(0), charge)
}

func TestMakeOutstandingRequestDirectWrite(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			for position := range 3 {
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
	t.Parallel()
	req := require.New(t)

	c := &conn{
		t:                   rejectingTransport{},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(3),
		requireSigning:      true,
	}
	c.account.charge(3)
	signingKey := kdf([]byte("0123456789abcdef"), []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 16)
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
	t.Parallel()
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
	t.Parallel()
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
		rp1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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
		rp2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
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

// rejectingTransport fails on the first write, ensuring that any request
// which reaches the transport layer makes the test fail loudly.
type rejectingTransport struct{}

func (rejectingTransport) Writev(p ...[]byte) (int, error) {
	return 0, errors.New("unexpected request sent")
}

func (t rejectingTransport) send(p ...[]byte) error {
	_, err := t.Writev(p...)
	return err
}

func (rejectingTransport) receive() ([]byte, error) { return nil, io.EOF }

func (rejectingTransport) setReadDeadline(time.Time) error { return nil }

func (rejectingTransport) setWriteDeadline(time.Time) error { return nil }

func (rejectingTransport) setPacketReadTimeout(time.Duration) {}

func (rejectingTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	return nil, io.EOF
}

func (rejectingTransport) Close() error { return nil }

// TestMakeOutstandingRequestReservedCreditCharge verifies that the wire
// CreditCharge is 0 for SMB 2.0.2 requests as required by [MS-SMB2] 2.2.1.2
// and [MS-SMB2] 3.2.4.1.5, while the internal credit accounting and other
// dialects are unaffected.
func TestMakeOutstandingRequestReservedCreditCharge(t *testing.T) {
	t.Parallel()
	t.Run("SMB202ZeroCreditCharge", func(t *testing.T) {
		cases := []struct {
			name string
			reqs []smb2.Packet
		}{
			{"SessionSetup", []smb2.Packet{&smb2.SessionSetupRequest{}}},
			{"TreeConnect", []smb2.Packet{&smb2.TreeConnectRequest{Path: `\\server\share`}}},
			{"Create", []smb2.Packet{&smb2.CreateRequest{Name: "file"}}},
			{"QueryInfo", []smb2.Packet{&smb2.QueryInfoRequest{}}},
			{"Read", []smb2.Packet{&smb2.ReadRequest{Length: 4096}}},
			{"Ioctl", []smb2.Packet{&smb2.IoctlRequest{}}},
			{"EmptyWrite", []smb2.Packet{&smb2.WriteRequest{}}},
			{"DirectWrite", []smb2.Packet{&smb2.WriteRequest{Data: make([]byte, 4096)}}},
			{"CompoundCreateQueryInfo", []smb2.Packet{
				&smb2.CreateRequest{Name: "file"},
				&smb2.QueryInfoRequest{},
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := newCreditTestConn(smb2.SMB202, 0)
				wire, _ := encodeOutstandingRequests(t, c, tc.reqs...)
				want := make([]uint16, len(tc.reqs))
				require.Equal(t, want, wireCreditCharges(t, wire, len(tc.reqs)))
			})
		}
	})

	t.Run("NegotiateSMB202Only", func(t *testing.T) {
		req, err := (&Dialer{}).makeNegotiateRequest([]uint16{smb2.SMB202}, false)
		require.NoError(t, err)
		// The dialect is not negotiated yet when NEGOTIATE is sent.
		c := newCreditTestConn(smb2.UnknownSMB, 0)
		wire, _ := encodeOutstandingRequests(t, c, req)
		require.Equal(t, []uint16{0}, wireCreditCharges(t, wire, 1))
	})

	t.Run("NegotiateDefaultDialects", func(t *testing.T) {
		req, err := (&Dialer{}).makeNegotiateRequest(clientDialects, false)
		require.NoError(t, err)
		c := newCreditTestConn(smb2.UnknownSMB, 0)
		wire, _ := encodeOutstandingRequests(t, c, req)
		require.Equal(t, []uint16{1}, wireCreditCharges(t, wire, 1))
	})

	t.Run("PreservedDialects", func(t *testing.T) {
		for _, dialect := range []uint16{smb2.SMB210, smb2.SMB300, smb2.SMB311} {
			t.Run(fmt.Sprintf("%03x", dialect), func(t *testing.T) {
				c := newCreditTestConn(dialect, smb2.SMB2_GLOBAL_CAP_LARGE_MTU)
				reqs := []smb2.Packet{
					&smb2.TreeConnectRequest{Path: `\\server\share`},
					&smb2.ReadRequest{Length: maxSingleCreditPayloadSize + 1},
				}
				wire, _ := encodeOutstandingRequests(t, c, reqs...)
				require.Equal(t, []uint16{1, 2}, wireCreditCharges(t, wire, 2))
			})
		}
	})

	t.Run("PreservedWithoutMultiCredit", func(t *testing.T) {
		c := newCreditTestConn(smb2.SMB210, 0) // LARGE_MTU disabled
		wire, _ := encodeOutstandingRequests(t, c, &smb2.ReadRequest{Length: maxSingleCreditPayloadSize + 1})
		require.Equal(t, []uint16{2}, wireCreditCharges(t, wire, 1))
	})

	t.Run("AccountingPreserved", func(t *testing.T) {
		c := newCreditTestConn(smb2.SMB202, 0)
		reqs := []smb2.Packet{
			&smb2.TreeConnectRequest{Path: `\\server\share`},
			&smb2.CreateRequest{Name: "file"},
		}
		ctx := context.Background()
		msgIds, totalCharge, err := c.account.loan(ctx, reqs...)
		require.NoError(t, err)
		require.Equal(t, uint16(2), totalCharge)
		require.Equal(t, msgIds[0]+1, msgIds[1])

		rrs, parts, err := c.makeOutstandingRequest(ctx, false, msgIds, reqs...)
		require.NoError(t, err)
		var wire []byte
		for _, part := range parts {
			wire = append(wire, part...)
		}
		require.Equal(t, []uint16{0, 0}, wireCreditCharges(t, wire, 2))
		require.Equal(t, uint16(1), rrs[0].creditCharge)
		require.Equal(t, uint16(1), rrs[1].creditCharge)
		require.Equal(t, uint16(2), c.account.inFlightCredits)

		available := c.account.availableCredits
		c.account.charge(1, rrs[0].creditCharge)
		c.account.charge(1, rrs[1].creditCharge)
		require.Equal(t, uint16(0), c.account.inFlightCredits)
		require.Equal(t, available+2, c.account.availableCredits)
	})
}

func (rejectingTransport) transportType() string { return "tcp" }
