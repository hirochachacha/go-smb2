package protocol

import (
	"encoding/binary"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestAaplExtensionContextFields(t *testing.T) {
	ctx := AaplExtensionContext{
		Command:            2,
		RequestBitmap:      0x1020304050607080,
		ClientCapabilities: 0x8877665544332211,
	}
	encoded := make([]byte, ctx.Size())
	ctx.Encode(encoded)
	require.False(t, wire.CreateContextsDecoder(encoded).IsInvalid())
	require.Equal(t, "AAPL", string(encoded[16:20]))
	require.Equal(t, ctx.Command, binary.LittleEndian.Uint32(encoded[24:28]))
	require.Equal(t, ctx.RequestBitmap, binary.LittleEndian.Uint64(encoded[32:40]))
	require.Equal(t, ctx.ClientCapabilities, binary.LittleEndian.Uint64(encoded[40:48]))
}
