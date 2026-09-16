package smb2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

type mockReceiver struct {
	pkts []*recvPacket
	errs []error
	idx  int
}

func (m *mockReceiver) recv(*outstandingRequest) (*recvPacket, error) {
	if m.idx < len(m.errs) && m.errs[m.idx] != nil {
		err := m.errs[m.idx]
		m.idx++
		return nil, err
	}
	rp := m.pkts[m.idx]
	m.idx++
	return rp, nil
}

func TestRecvAllReturnsPartialResponsesOnCompoundError(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	p0 := allocRecvPacket(64)
	p1 := allocRecvPacket(64)
	p3 := allocRecvPacket(64)
	failErr := fmt.Errorf("fail at op 2")
	lastErr := fmt.Errorf("fail at op 4")

	mock := &mockReceiver{
		pkts: []*recvPacket{p0, p1, nil, p3, nil},
		errs: []error{nil, nil, failErr, nil, lastErr},
	}

	rrs := []*outstandingRequest{
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
		{cmd: smb2.SMB2_ECHO},
	}

	res, err := recvAll(rrs, mock)
	require.NotNil(res)
	require.Error(err)

	var cerr *CompoundResponseError
	require.ErrorAs(err, &cerr)
	require.Equal(5, len(cerr.Errors))
	require.Nil(cerr.OpError(0))
	require.Nil(cerr.OpError(1))
	require.ErrorIs(cerr.OpError(2), failErr)
	require.Nil(cerr.OpError(3))
	require.ErrorIs(cerr.OpError(4), lastErr)

	// Packets received before and after the error must remain at their
	// corresponding compound operation indexes.
	require.Equal(p0, res.rpkts[0])
	require.Equal(p1, res.rpkts[1])
	require.Equal(p3, res.rpkts[3])

	// Closing res closes every retained packet.
	res.close()
	require.Nil(p0.buf)
	require.Nil(p1.buf)
	require.Nil(p3.buf)
}

func TestAllocEncodeBufSetsLengthToRequestedSize(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	const size = 512

	c := &conn{}

	// new allocation
	pkt := c.allocEncodeBuf(size)
	require.Len(pkt, size)
	// the reusable buffer itself must be trimmed to the requested size,
	// otherwise the preauth integrity hash would be computed over
	// zero-padded bytes beyond the encoded packet.
	require.Len(c.encodeBuf, size)

	// existing buffer reuse
	pkt = c.allocEncodeBuf(size)
	require.Len(pkt, size)
	require.Len(c.encodeBuf, size)
}

func TestReadResponseFlags(t *testing.T) {
	t.Parallel()
	for _, dialect := range []uint16{smb2.SMB202, smb2.SMB210, smb2.SMB300, smb2.SMB302, smb2.SMB311} {
		for _, flags := range []uint32{0, 1, 2, 3, 0x80000000, 0xffffffff} {
			for _, mode := range []string{"ordinary", "direct", "decrypted"} {
				t.Run(fmt.Sprintf("%x/%d/%s", dialect, flags, mode), func(t *testing.T) {
					want := []byte("payload")
					buf := bytes.Repeat([]byte{0xa5}, 16)
					original := bytes.Clone(buf)
					c := &conn{dialect: dialect, outstandingRequests: newOutstandingRequests()}
					c.session = &session{conn: c}
					c.outstandingRequests.set(1, &outstandingRequest{msgId: 1, readBuf: buf})
					res := &smb2.ReadResponse{Data: want}
					pkt := make([]byte, res.Size())
					res.Encode(pkt)
					smb2.PacketCodec(pkt).SetMessageId(1)
					binary.LittleEndian.PutUint32(pkt[76:80], flags)
					rp := &recvPacket{pkt: pkt}
					invalid := dialect == smb2.SMB311 && flags != 0
					switch mode {
					case "direct":
						sink, front := c.directReadSink(pkt[:80], len(pkt)-80)
						if invalid {
							require.Nil(t, sink)
						} else {
							require.NotNil(t, sink)
							copy(sink, pkt[front:])
							rp = &recvPacket{pkt: pkt[:front], ext: sink}
						}
					case "decrypted":
						c.copyDecryptedReadPayload(rp)
						if invalid {
							require.Nil(t, rp.ext)
						}
					}
					got, err := accept(smb2.SMB2_READ, rp, dialect)
					if invalid {
						require.Nil(t, got)
						var responseErr *ResponseError
						require.ErrorAs(t, err, &responseErr)
						require.Equal(t, uint32(erref.STATUS_INVALID_NETWORK_RESPONSE), responseErr.Code)
						require.Equal(t, original, buf)
					} else {
						require.NoError(t, err)
						defer got.close()
						if got.ext != nil {
							require.Equal(t, want, got.ext)
						} else {
							require.Equal(t, want, smb2.ReadResponseDecoder(got.codec().Body()).Data())
						}
					}
				})
			}
		}
	}
}

func TestReadResponseFlagsPreserveEOF(t *testing.T) {
	t.Parallel()
	res := &smb2.ErrorResponse{}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	smb2.PacketCodec(pkt).SetCommand(smb2.SMB2_READ)
	smb2.PacketCodec(pkt).SetStatus(uint32(erref.STATUS_END_OF_FILE))
	_, err := accept(smb2.SMB2_READ, &recvPacket{pkt: pkt}, smb2.SMB311)
	var responseErr *ResponseError
	require.ErrorAs(t, err, &responseErr)
	require.Equal(t, uint32(erref.STATUS_END_OF_FILE), responseErr.Code)
}

func TestReadResponseFlagsTruncated(t *testing.T) {
	t.Parallel()
	for n := range 16 {
		body := make([]byte, n)
		if n >= 2 {
			binary.LittleEndian.PutUint16(body, 17)
		}
		require.NotPanics(t, func() { smb2.ReadResponseDecoder(body).HasInvalidFlags(smb2.SMB311) })
	}
}
