package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/v2/internal/crypto/cmac"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
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

	req1 := &wire.CreateRequest{
		DesiredAccess: wire.DELETE,
	}
	req1.SetFlags(wire.SMB2_FLAGS_DFS_OPERATIONS)

	req2 := &wire.CloseRequest{}
	req2.SetFlags(wire.SMB2_FLAGS_DFS_OPERATIONS)

	reqs := []wire.Packet{req1, req2}

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
	p1 := wire.PacketCodec(pkt)
	req.Equal(wire.SMB2_CREATE, p1.Command())
	req.Equal(uint64(0), p1.MessageId())
	req.Equal(uint32(wire.SMB2_FLAGS_DFS_OPERATIONS), p1.Flags())
	req.True(p1.NextCommand() > 0)
	req.Equal(uint32(0), p1.NextCommand()&7) // 8-byte aligned

	nextOff := p1.NextCommand()
	p2 := wire.PacketCodec(pkt[nextOff:])
	req.Equal(wire.SMB2_CLOSE, p2.Command())
	req.Equal(uint64(1), p2.MessageId())
	req.Equal(uint32(wire.SMB2_FLAGS_DFS_OPERATIONS|wire.SMB2_FLAGS_RELATED_OPERATIONS), p2.Flags())
	req.Equal(uint32(0), p2.NextCommand())
	req.True(p2.Flags()&wire.SMB2_FLAGS_RELATED_OPERATIONS != 0)
}

func TestSecurityRequestBuilderFields(t *testing.T) {
	t.Parallel()
	req := (&Tree{}).Request().WithFileID(&wire.FileId{})
	selection := uint32(security.Owner | security.DACL)
	req.QueryInfo(wire.SMB2_0_INFO_SECURITY, 0, selection, 4096)
	query := req.pkts[0].(*wire.QueryInfoRequest)
	if query.InfoType != wire.SMB2_0_INFO_SECURITY || query.FileInfoClass != 0 || query.AdditionalInformation != selection || query.OutputBufferLength != 4096 {
		t.Fatalf("security query fields = %#v", query)
	}

	req = (&Tree{}).Request().WithFileID(&wire.FileId{})
	req.SetInfo(wire.SMB2_0_INFO_SECURITY, 0, selection, rawEncoder{})
	set := req.pkts[0].(*wire.SetInfoRequest)
	if set.InfoType != wire.SMB2_0_INFO_SECURITY || set.FileInfoClass != 0 || set.AdditionalInformation != selection {
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

	reqs := []wire.Packet{
		&wire.CreateRequest{},
		&wire.QueryInfoRequest{FileId: &wire.FileId{}},
		&wire.CloseRequest{},
	}
	msgIds, _, err := c.account.loan(context.Background(), reqs...)
	req.NoError(err)
	req.Equal([]uint64{0, 1, 2}, msgIds)

	rrs, parts, err := c.makeOutstandingRequest(context.Background(), false, msgIds, reqs...)
	req.NoError(err)
	req.Len(rrs, len(reqs))
	req.Len(parts, 1)

	wantCommands := []wire.Command{wire.SMB2_CREATE, wire.SMB2_QUERY_INFO, wire.SMB2_CLOSE}
	off := 0
	var totalCreditRequest uint32
	for i, wantCommand := range wantCommands {
		p := wire.PacketCodec(parts[0][off:])
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
	reqs := []wire.Packet{&wire.CreateRequest{}, &wire.CreateRequest{}, &wire.CreateRequest{}}

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
		codec := wire.PacketCodec(pkt[off:])
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
	reqs := make([]wire.Packet, 65536)
	for i := range reqs {
		reqs[i] = &wire.CreateRequest{}
	}

	msgIds, charge, err := a.loan(context.Background(), reqs...)
	req.Error(err)
	req.ErrorContains(err, "protocol: compound credit charge exceeds uint16")
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

			wr := &wire.WriteRequest{
				Offset: 0x1000,
				FileId: &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
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

				wr := &wire.WriteRequest{
					Offset: 0x1000,
					FileId: &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					Data:   data,
				}

				requests := []wire.Packet{&wire.EchoRequest{}, &wire.EchoRequest{}}
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
				req.Equal(uint32(len(concat(parts))-52), wire.TransformCodec(parts[0]).OriginalMessageSize())
				req.Empty(c.encodeBuf)

				tc := wire.TransformCodec(parts[0])
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
func encodeContiguous(reqs []wire.Packet, s *session) []byte {
	total := 0
	spans := make([]int, len(reqs))
	for i, req := range reqs {
		span := req.Size()
		if i < len(reqs)-1 {
			span = wire.Roundup(span, 8)
			req.SetNextCommand(uint32(span))
		} else {
			req.SetNextCommand(0)
		}
		if i > 0 {
			req.SetFlags(wire.SMB2_FLAGS_RELATED_OPERATIONS)
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

	reqs := []wire.Packet{
		&wire.CreateRequest{DesiredAccess: wire.DELETE},
		&wire.WriteRequest{
			Offset: 0x1000,
			FileId: &wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
			Data:   data,
		},
		&wire.CloseRequest{},
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
	createSize := wire.Roundup((&wire.CreateRequest{DesiredAccess: wire.DELETE}).Size(), 8)
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
			wr := &wire.WriteRequest{FileId: &wire.FileId{}, Data: payload}
			var reqs []wire.Packet
			wantParts := 1
			switch name {
			case "first":
				reqs = []wire.Packet{wr, &wire.CloseRequest{}}
				wantParts = 3
			case "last":
				reqs = []wire.Packet{&wire.CreateRequest{}, wr}
				wantParts = 2
			case "empty":
				wr.Data = nil
				reqs = []wire.Packet{wr}
			case "multiple":
				reqs = []wire.Packet{wr, &wire.WriteRequest{
					FileId: &wire.FileId{}, Data: []byte("second payload"),
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
		t:                   NewTransport(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(10),
	}
	c.account.charge(10)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &Tree{
		session: c.session,
		treeId:  0x200,
	}

	// Mock server reading compound request and responding with compound response
	go func() {
		dt := NewTransport(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		p1 := wire.PacketCodec(reqBuf)

		// Build compound response: Response 1 (CREATE, 64 header + 88 body = 152 bytes, aligned to 160)
		res1 := make([]byte, 160)
		rp1 := wire.PacketCodec(res1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(wire.SMB2_CREATE)
		rp1.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rp1.SetMessageId(p1.MessageId())
		rp1.SetSessionId(p1.SessionId())
		rp1.SetTreeId(p1.TreeId())
		rp1.SetNextCommand(160)
		binary.LittleEndian.PutUint16(res1[64:66], 89) // CreateResponse structure size

		// Response 2 (CLOSE, 64 header + 60 body = 124 bytes)
		res2 := make([]byte, 124)
		rp2 := wire.PacketCodec(res2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(wire.SMB2_CLOSE)
		rp2.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		rp2.SetMessageId(p1.MessageId() + 1)
		rp2.SetSessionId(p1.SessionId())
		rp2.SetTreeId(p1.TreeId())
		rp2.SetNextCommand(0)
		binary.LittleEndian.PutUint16(res2[64:66], 60) // CloseResponse structure size

		compoundResp := append(res1, res2...)
		NewTransport(serverConn).writev(compoundResp)
	}()

	go c.runReceiver()

	cReq := &wire.CreateRequest{DesiredAccess: wire.DELETE}
	clsReq := &wire.CloseRequest{}

	res, err := tc.Request().
		Append(cReq).
		Append(clsReq).
		Do(context.Background())

	req.NoError(err)
	defer res.Close()
	req.NotNil(res.packet(0))
	req.NotNil(res.packet(1))
	req.Equal(wire.SMB2_CREATE, res.packet(0).codec().Command())
	req.Equal(wire.SMB2_CLOSE, res.packet(1).codec().Command())
}

// rejectingTransport fails on the first write, ensuring that any request
// which reaches the transport layer makes the test fail loudly.
type rejectingTransport struct{}

func (rejectingTransport) writev(p ...[]byte) (int, error) {
	return 0, errors.New("unexpected request sent")
}

func (rejectingTransport) setReadDeadline(time.Time) error { return nil }

func (rejectingTransport) setWriteDeadline(time.Time) error { return nil }

func (rejectingTransport) setPacketReadTimeout(time.Duration) {}

func (rejectingTransport) readPacket(findSink ...directSinkFinder) (*recvPacket, error) {
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
			reqs []wire.Packet
		}{
			{"SessionSetup", []wire.Packet{&wire.SessionSetupRequest{}}},
			{"TreeConnect", []wire.Packet{&wire.TreeConnectRequest{Path: `\\server\share`}}},
			{"Create", []wire.Packet{&wire.CreateRequest{Name: "file"}}},
			{"QueryInfo", []wire.Packet{&wire.QueryInfoRequest{}}},
			{"Read", []wire.Packet{&wire.ReadRequest{Length: 4096}}},
			{"Ioctl", []wire.Packet{&wire.IoctlRequest{}}},
			{"EmptyWrite", []wire.Packet{&wire.WriteRequest{}}},
			{"DirectWrite", []wire.Packet{&wire.WriteRequest{Data: make([]byte, 4096)}}},
			{"CompoundCreateQueryInfo", []wire.Packet{
				&wire.CreateRequest{Name: "file"},
				&wire.QueryInfoRequest{},
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := newCreditTestConn(wire.SMB202, 0)
				wireBytes, _ := encodeOutstandingRequests(t, c, tc.reqs...)
				want := make([]uint16, len(tc.reqs))
				require.Equal(t, want, wireCreditCharges(t, wireBytes, len(tc.reqs)))
			})
		}
	})

	t.Run("NegotiateSMB202Only", func(t *testing.T) {
		req, err := (&Dialer{}).makeNegotiateRequest([]Dialect{SMB202}, false)
		require.NoError(t, err)
		// The dialect is not negotiated yet when NEGOTIATE is sent.
		c := newCreditTestConn(wire.UnknownSMB, 0)
		wireBytes, _ := encodeOutstandingRequests(t, c, req)
		require.Equal(t, []uint16{0}, wireCreditCharges(t, wireBytes, 1))
	})

	t.Run("NegotiateDefaultDialects", func(t *testing.T) {
		req, err := (&Dialer{}).makeNegotiateRequest(clientDialects, false)
		require.NoError(t, err)
		c := newCreditTestConn(wire.UnknownSMB, 0)
		wireBytes, _ := encodeOutstandingRequests(t, c, req)
		require.Equal(t, []uint16{1}, wireCreditCharges(t, wireBytes, 1))
	})

	t.Run("PreservedDialects", func(t *testing.T) {
		for _, dialect := range []uint16{wire.SMB210, wire.SMB300, wire.SMB311} {
			t.Run(fmt.Sprintf("%03x", dialect), func(t *testing.T) {
				c := newCreditTestConn(dialect, wire.SMB2_GLOBAL_CAP_LARGE_MTU)
				reqs := []wire.Packet{
					&wire.TreeConnectRequest{Path: `\\server\share`},
					&wire.ReadRequest{Length: maxSingleCreditPayloadSize + 1},
				}
				wireBytes, _ := encodeOutstandingRequests(t, c, reqs...)
				require.Equal(t, []uint16{1, 2}, wireCreditCharges(t, wireBytes, 2))
			})
		}
	})

	t.Run("PreservedWithoutMultiCredit", func(t *testing.T) {
		c := newCreditTestConn(wire.SMB210, 0) // LARGE_MTU disabled
		wireBytes, _ := encodeOutstandingRequests(t, c, &wire.ReadRequest{Length: maxSingleCreditPayloadSize + 1})
		require.Equal(t, []uint16{2}, wireCreditCharges(t, wireBytes, 1))
	})

	t.Run("AccountingPreserved", func(t *testing.T) {
		c := newCreditTestConn(wire.SMB202, 0)
		reqs := []wire.Packet{
			&wire.TreeConnectRequest{Path: `\\server\share`},
			&wire.CreateRequest{Name: "file"},
		}
		ctx := context.Background()
		msgIds, totalCharge, err := c.account.loan(ctx, reqs...)
		require.NoError(t, err)
		require.Equal(t, uint16(2), totalCharge)
		require.Equal(t, msgIds[0]+1, msgIds[1])

		rrs, parts, err := c.makeOutstandingRequest(ctx, false, msgIds, reqs...)
		require.NoError(t, err)
		var wireBytes []byte
		for _, part := range parts {
			wireBytes = append(wireBytes, part...)
		}
		require.Equal(t, []uint16{0, 0}, wireCreditCharges(t, wireBytes, 2))
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

// TestContinuationSafe exercises the guard that decides whether a compound
// CREATE stopped by the server may be retried without re-executing later
// operations. See [MS-SMB2] 3.3.5.2.7.2 for the ordered execution and the
// STATUS_INVALID_HANDLE / STATUS_INVALID_PARAMETER failures relied on here.
func TestContinuationSafe(t *testing.T) {
	t.Parallel()

	const (
		stop         = uint32(erref.STATUS_STOPPED_ON_SYMLINK)
		notCovered   = uint32(erref.STATUS_PATH_NOT_COVERED)
		invalidFd    = uint32(erref.STATUS_INVALID_HANDLE)
		closedFd     = uint32(erref.STATUS_FILE_CLOSED)
		invalidParam = uint32(erref.STATUS_INVALID_PARAMETER)
		accessDenied = uint32(erref.STATUS_ACCESS_DENIED)
	)

	reqs := func(n int) []wire.Packet {
		pkts := make([]wire.Packet, n)
		for i := range pkts {
			if i == 0 {
				pkts[i] = &wire.CreateRequest{Name: "link"}
			} else {
				pkts[i] = &wire.CloseRequest{}
			}
		}
		return pkts
	}

	tests := []struct {
		name string
		err  error
		reqs []wire.Packet
		want bool
	}{
		{"empty request", &ResponseError{Code: stop}, nil, false},
		{"first is not a response error", errors.New("boom"), reqs(1), false},
		{"first is not a stopped status", &ResponseError{Code: accessDenied}, reqs(1), false},
		{"single create stopped on symlink", &ResponseError{Code: stop}, reqs(1), true},
		{"single create path not covered", &ResponseError{Code: notCovered}, reqs(1), true},
		{"later operation succeeded", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, nil}}, reqs(2), false},
		{"error count mismatch", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}}}, reqs(2), false},
		{"later error is not a response error", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, errors.New("boom")}}, reqs(2), false},
		{"later unrelated failure", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: accessDenied}}}, reqs(2), false},
		{"different stopped status", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: notCovered}}}, reqs(2), false},
		{"later invalid handle", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: invalidFd}}}, reqs(2), true},
		{"later file closed", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: closedFd}, &ResponseError{Code: closedFd}}}, reqs(3), true},
		{"referral followed by file closed", &CompoundResponseError{Errors: []error{&ResponseError{Code: notCovered}, &ResponseError{Code: closedFd}}}, reqs(2), true},
		{"file closed is not a stopped create", &CompoundResponseError{Errors: []error{&ResponseError{Code: closedFd}, &ResponseError{Code: closedFd}}}, reqs(2), false},
		{"file closed followed by success", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: closedFd}, nil}}, reqs(3), false},
		{"file closed followed by unrelated failure", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: closedFd}, &ResponseError{Code: accessDenied}}}, reqs(3), false},
		{"later invalid parameter", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: invalidParam}}}, reqs(2), true},
		{"later repeats stopped status", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: stop}}}, reqs(2), true},
		// sendRecvSequential propagates the first failure to every unsent
		// operation, so the array repeats the same status.
		{"sequential repeated failure", &CompoundResponseError{Errors: []error{&ResponseError{Code: stop}, &ResponseError{Code: stop}, &ResponseError{Code: stop}}}, reqs(3), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, continuationSafe(tt.err, tt.reqs))
		})
	}
}

// compoundCreateName returns the CREATE name from the first operation of a
// compound request. It reports an empty string for a malformed or absent
// CREATE.
func compoundCreateName(req []byte) string {
	for len(req) >= 64 {
		codec := wire.PacketCodec(req)
		if codec.Command() == wire.SMB2_CREATE && len(req) >= 64+48 {
			r := wire.CreateRequestDecoder(req[64:])
			off, size := int(r.NameOffset()), int(r.NameLength())
			if off+size <= len(req) {
				return utf16le.DecodeToString(req[off : off+size])
			}
		}
		next := int(codec.NextCommand())
		if next < 64 || next > len(req) {
			break
		}
		req = req[next:]
	}
	return ""
}

func stoppedSymlinkErrorResponse() *wire.ErrorResponse {
	return &wire.ErrorResponse{
		CommandCode: wire.SMB2_CREATE,
		ErrorData: &wire.SymbolicLinkErrorResponse{
			Flags:          wire.SYMLINK_FLAG_RELATIVE,
			SubstituteName: "target.txt",
			PrintName:      "target.txt",
		},
	}
}

func closeSuccessResponse() *wire.CloseResponse {
	return &wire.CloseResponse{
		CreationTime:   &wire.Filetime{},
		LastAccessTime: &wire.Filetime{},
		LastWriteTime:  &wire.Filetime{},
		ChangeTime:     &wire.Filetime{},
	}
}

func removeCompound(tc *Tree) error {
	res, err := tc.Request().
		WithFollowSymlinks(true).
		Create("link", wire.DELETE, wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		SetInfo(wire.SMB2_0_INFO_FILE, wire.FileDispositionInformation, 0, &wire.FileDispositionInformationEncoder{DeletePending: 1}).
		Close().
		Do(context.Background())
	if res != nil {
		res.Close()
	}
	return err
}

func TestRequestDefaultsToNoSymlinkFollow(t *testing.T) {
	t.Parallel()
	tc, serverConn := newTestTree(t)
	dt := NewTransport(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, stoppedSymlinkErrorResponse(), uint32(erref.STATUS_STOPPED_ON_SYMLINK))
	}()

	res, err := tc.Request().Create("link", wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).Do(context.Background())
	if res != nil {
		res.Close()
	}
	if !errors.Is(err, erref.STATUS_STOPPED_ON_SYMLINK) {
		t.Fatalf("Do error = %v, want STATUS_STOPPED_ON_SYMLINK", err)
	}
	<-done
}

func TestRequestExecuteAndSendReceiveHaveEquivalentOwnership(t *testing.T) {
	for _, send := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "send-receive"}[send], func(t *testing.T) {
			tc, serverConn := newTestTree(t)
			go func() {
				st := NewTransport(serverConn)
				request, err := readMsg(st)
				if err != nil {
					return
				}
				sendTestResponse(st, request, &wire.EchoResponse{}, uint32(erref.STATUS_SUCCESS))
			}()

			req := tc.Request().Append(&wire.EchoRequest{})
			if send {
				pending, err := req.Send(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				res, err := pending.Receive()
				if err != nil {
					t.Fatal(err)
				}
				if res == nil || len(res.Data(0)) == 0 {
					t.Fatal("Send/Receive returned no response data")
				}
				res.Close()
				return
			}
			res, err := req.Do(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res == nil || len(res.Data(0)) == 0 {
				t.Fatal("Do returned no response data")
			}
			res.Close()
		})
	}
}

// TestContinuationSafeDoesNotRetryAfterLaterSuccess verifies that a compound
// CREATE stopped on a symlink is not retried when the server reports success
// for a later operation; the later SET_INFO may have had a side effect that a
// blind retry after symlink resolution would repeat.
func TestContinuationSafeDoesNotRetryAfterLaterSuccess(t *testing.T) {
	t.Parallel()
	tc, serverConn := newTestTree(t)
	dt := NewTransport(serverConn)

	var requests atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			requests.Add(1)
			if err := sendCompoundResponse(dt, req, []compoundResponse{
				{packet: stoppedSymlinkErrorResponse(), status: erref.STATUS_STOPPED_ON_SYMLINK},
				{packet: &wire.SetInfoResponse{}, status: erref.STATUS_SUCCESS},
				{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
			}); err != nil {
				return
			}
		}
	}()

	err := removeCompound(tc)
	require.Error(t, err)
	var ce *CompoundResponseError
	require.ErrorAs(t, err, &ce)
	require.Nil(t, ce.OpError(1))
	require.Nil(t, ce.OpError(2))

	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	<-done
	require.EqualValues(t, 1, requests.Load(), "CREATE must not be reissued after a later operation succeeded")
}

// TestContinuationSafeRetriesSymlinkAfterSkippedOperations verifies that the
// symlink retry is preserved when every later operation reports a skipped
// handle, as [MS-SMB2] 3.3.5.2.7.2 requires when the FileId is unavailable.
func TestContinuationSafeRetriesSymlinkAfterSkippedOperations(t *testing.T) {
	t.Parallel()
	for _, status := range []erref.NtStatus{erref.STATUS_INVALID_HANDLE, erref.STATUS_FILE_CLOSED} {
		t.Run(status.Error(), func(t *testing.T) {

			tc, serverConn := newTestTree(t)
			dt := NewTransport(serverConn)

			attempt := 0
			names := make([]string, 0, 2)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}
					attempt++
					names = append(names, compoundCreateName(req))
					var err2 error
					if attempt == 1 {
						err2 = sendCompoundResponse(dt, req, []compoundResponse{
							{packet: stoppedSymlinkErrorResponse(), status: erref.STATUS_STOPPED_ON_SYMLINK},
							{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, status: status},
							{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}, status: status},
						})
					} else {
						err2 = sendCompoundResponse(dt, req, []compoundResponse{
							{packet: &wire.CreateResponse{
								FileId: &wire.FileId{}, CreationTime: &wire.Filetime{},
								LastAccessTime: &wire.Filetime{}, LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
							}, status: erref.STATUS_SUCCESS},
							{packet: &wire.SetInfoResponse{}, status: erref.STATUS_SUCCESS},
							{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
						})
					}
					if err2 != nil {
						return
					}
				}
			}()

			req := tc.Request().
				WithFollowSymlinks(true).
				Create("link", wire.DELETE, wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
				SetInfo(wire.SMB2_0_INFO_FILE, wire.FileDispositionInformation, 0, &wire.FileDispositionInformationEncoder{DeletePending: 1}).
				Close()
			original := req.Get(0).(*wire.CreateRequest)
			res, err := req.Do(context.Background())
			require.NoError(t, err)
			res.Close()
			require.Equal(t, "target.txt", res.ResolvedPath())
			require.Same(t, original, req.Get(0))
			require.Equal(t, "link", original.Name, "retry must not modify the caller's CREATE")
			serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			<-done
			require.Equal(t, []string{"link", "target.txt"}, names)
		})
	}
}

// TestContinuationSafeDoesNotConvertDFSOnLaterSuccess verifies that a DFS
// CREATE stopped with STATUS_PATH_NOT_COVERED is not turned into a referral
// when a later operation succeeded, since the referral would re-run the
// compound against another target.
func TestContinuationSafeDoesNotConvertDFSOnLaterSuccess(t *testing.T) {
	t.Parallel()
	tc, serverConn := newTestTree(t)
	tc.isDFSShare = true
	dt := NewTransport(serverConn)

	var requests atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			requests.Add(1)
			if err := sendCompoundResponse(dt, req, []compoundResponse{
				{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, status: erref.STATUS_PATH_NOT_COVERED},
				{packet: &wire.SetInfoResponse{}, status: erref.STATUS_SUCCESS},
				{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
			}); err != nil {
				return
			}
		}
	}()

	err := removeCompound(tc)
	require.Error(t, err)
	var ce *CompoundResponseError
	require.ErrorAs(t, err, &ce)
	var referral *DFSReferralRequiredError
	require.False(t, errors.As(err, &referral))

	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	<-done
	require.EqualValues(t, 1, requests.Load())
}

// TestContinuationSafeKeepsDFSReferralAfterSkippedOperations verifies that the
// DFS referral path is preserved when every later operation reports a skipped
// handle or missing session/tree, as [MS-SMB2] 3.3.5.2.7.2 requires.
func TestContinuationSafeKeepsDFSReferralAfterSkippedOperations(t *testing.T) {
	t.Parallel()
	tc, serverConn := newTestTree(t)
	tc.isDFSShare = true
	dt := NewTransport(serverConn)

	var requests atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			requests.Add(1)
			if err := sendCompoundResponse(dt, req, []compoundResponse{
				{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, status: erref.STATUS_PATH_NOT_COVERED},
				{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, status: erref.STATUS_INVALID_PARAMETER},
				{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}, status: erref.STATUS_INVALID_PARAMETER},
			}); err != nil {
				return
			}
		}
	}()

	err := removeCompound(tc)
	require.Error(t, err)
	var referral *DFSReferralRequiredError
	require.ErrorAs(t, err, &referral)

	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	<-done
	require.EqualValues(t, 1, requests.Load())
}
