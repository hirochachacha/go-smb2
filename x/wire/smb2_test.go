package wire

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryOnDiskIDContext(t *testing.T) {
	t.Parallel()
	request := QueryOnDiskIDRequest{}
	buf := make([]byte, request.Size())
	for i := range buf {
		buf[i] = 0xff
	}
	request.Encode(buf)
	contexts := CreateContextsDecoder(buf)
	require.False(t, contexts.IsInvalid())
	require.Equal(t, "QFid", string(buf[16:20]))
	require.Zero(t, binary.LittleEndian.Uint32(buf[12:16]))
	require.Zero(t, binary.LittleEndian.Uint32(buf[:4]))

	for _, size := range []int{0, 1, 16, 31, 32, 33} {
		context := make([]byte, 24+size)
		binary.LittleEndian.PutUint16(context[4:6], 16)
		binary.LittleEndian.PutUint16(context[6:8], 4)
		binary.LittleEndian.PutUint16(context[10:12], 24)
		binary.LittleEndian.PutUint32(context[12:16], uint32(size))
		copy(context[16:20], "QFid")
		if size >= 16 {
			binary.LittleEndian.PutUint64(context[24:32], 0x1122334455667788)
			binary.LittleEndian.PutUint64(context[32:40], 0x8877665544332211)
		}
		// Reserved bytes must be ignored on receipt.
		for i := 40; i < len(context); i++ {
			context[i] = 0xff
		}
		response := &CreateResponse{CreationTime: Filetime{}, LastAccessTime: Filetime{}, LastWriteTime: Filetime{}, ChangeTime: Filetime{}, FileId: FileId{}, Contexts: CreateContexts{ioctlResponseTestEncoder(context)}}
		packet := make([]byte, response.Size())
		response.Encode(packet)
		decoded := CreateResponseDecoder(packet[64:])
		require.Equal(t, size != 32, decoded.IsInvalid(), "payload length %d", size)
		if size == 32 {
			identity := decoded.QueryOnDiskID()
			require.NotNil(t, identity)
			require.Equal(t, uint64(0x1122334455667788), identity.DiskFileId())
			require.Equal(t, uint64(0x8877665544332211), identity.VolumeId())
		}
	}
}

func TestQueryOnDiskIDRequestRejectsData(t *testing.T) {
	t.Parallel()
	context := make([]byte, 25)
	QueryOnDiskIDRequest{}.Encode(context)
	binary.LittleEndian.PutUint16(context[10:12], 24)
	binary.LittleEndian.PutUint32(context[12:16], 1)
	request := &CreateRequest{Contexts: CreateContexts{ioctlResponseTestEncoder(context)}}
	packet := make([]byte, request.Size())
	request.Encode(packet)
	require.True(t, CreateRequestDecoder(packet[64:]).IsInvalid())
}

func TestSigningContext(t *testing.T) {
	algorithms := []SigningAlgorithm{AES128GMAC, AES128CMAC}
	c := SigningContext{SigningAlgorithms: algorithms}
	buf := make([]byte, c.Size())
	c.Encode(buf)
	require.Equal(t, []byte{8, 0, 6, 0, 0, 0, 0, 0, 2, 0, 2, 0, 1, 0}, buf)
	ctx := NegotiateContextDecoder(buf)
	require.False(t, ctx.IsInvalid())
	require.EqualValues(t, SMB2_SIGNING_CAPABILITIES, ctx.ContextType())
	data := SigningContextDataDecoder(ctx.Data())
	require.False(t, data.IsInvalid())
	require.EqualValues(t, 2, data.SigningAlgorithmCount())
	require.Equal(t, algorithms, data.SigningAlgorithms())
	// A server response uses the same representation, with exactly one ID.
	response := SigningContext{SigningAlgorithms: []SigningAlgorithm{AES128GMAC}}
	buf = make([]byte, response.Size())
	response.Encode(buf)
	ctx = NegotiateContextDecoder(buf)
	require.False(t, ctx.IsInvalid())
	data = SigningContextDataDecoder(ctx.Data())
	require.False(t, data.IsInvalid())
	require.Equal(t, []SigningAlgorithm{AES128GMAC}, data.SigningAlgorithms())
}

func TestSigningContextDataDecoder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		invalid bool
	}{
		{"nil", nil, true},
		{"short count", []byte{1}, true},
		{"zero count", []byte{0, 0}, true},
		{"missing ID", []byte{1, 0}, true},
		{"partial ID", []byte{1, 0, 2}, true},
		{"truncated list", []byte{2, 0, 2, 0}, true},
		{"maximum count truncated", []byte{255, 255, 2, 0}, true},
		{"extra ID", []byte{1, 0, 2, 0, 1, 0}, true},
		{"extra byte", []byte{1, 0, 2, 0, 0}, true},
		{"HMAC", []byte{1, 0, 0, 0}, false},
		{"CMAC", []byte{1, 0, 1, 0}, false},
		{"GMAC", []byte{1, 0, 2, 0}, false},
		// Selection against the client's offered IDs belongs to negotiation.
		{"unknown selection", []byte{1, 0, 255, 255}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := SigningContextDataDecoder(tc.data)
			require.Equal(t, tc.invalid, d.IsInvalid())
			if !tc.invalid {
				require.Len(t, d.SigningAlgorithms(), int(d.SigningAlgorithmCount()))
			}
		})
	}
	// The uint16 count arithmetic must not wrap on either 32- or 64-bit hosts.
	data := make([]byte, 2+2*32766)
	binary.LittleEndian.PutUint16(data, 32766)
	d := SigningContextDataDecoder(data)
	require.False(t, d.IsInvalid())
	require.Len(t, d.SigningAlgorithms(), 32766)
	data = make([]byte, 2+2*65535)
	binary.LittleEndian.PutUint16(data, 65535)
	require.True(t, SigningContextDataDecoder(data).IsInvalid())
}

func TestSigningContextEmptyEncoding(t *testing.T) {
	for _, c := range []*SigningContext{nil, {}} {
		buf := make([]byte, c.Size())
		require.NotPanics(t, func() { c.Encode(buf) })
		ctx := NegotiateContextDecoder(buf)
		require.False(t, ctx.IsInvalid())
		require.True(t, SigningContextDataDecoder(ctx.Data()).IsInvalid())
	}
}
