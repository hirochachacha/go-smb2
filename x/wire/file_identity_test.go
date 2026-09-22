package wire

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryOnDiskIDContext(t *testing.T) {
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
	context := make([]byte, 25)
	QueryOnDiskIDRequest{}.Encode(context)
	binary.LittleEndian.PutUint16(context[10:12], 24)
	binary.LittleEndian.PutUint32(context[12:16], 1)
	request := &CreateRequest{Contexts: CreateContexts{ioctlResponseTestEncoder(context)}}
	packet := make([]byte, request.Size())
	request.Encode(packet)
	require.True(t, CreateRequestDecoder(packet[64:]).IsInvalid())
}

func TestQueryOnDiskIDResponseFindsContext(t *testing.T) {
	other := make([]byte, 24)
	QueryOnDiskIDRequest{}.Encode(other)
	copy(other[16:20], "Test")
	for _, present := range []bool{false, true} {
		response := &CreateResponse{
			CreationTime: Filetime{}, LastAccessTime: Filetime{}, LastWriteTime: Filetime{}, ChangeTime: Filetime{}, FileId: FileId{},
			Contexts: CreateContexts{ioctlResponseTestEncoder(other)},
		}
		if present {
			response.Contexts = append(response.Contexts, qfidCreateContext{size: 56, response: true})
		}
		packet := make([]byte, response.Size())
		response.Encode(packet)
		decoded := CreateResponseDecoder(packet[64:])
		require.False(t, decoded.IsInvalid())
		if present {
			require.NotNil(t, decoded.QueryOnDiskID())
		} else {
			require.Nil(t, decoded.QueryOnDiskID())
		}
	}
}
