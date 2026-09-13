package smb2

import (
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestQueryDirectoryResponseBufferBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  uint16
		length  uint32
		size    int
		invalid bool
	}{
		{"header", 64, 1, 8, true}, {"fixed fields", 71, 1, 8, true},
		{"valid", 72, 106, 114, false}, {"empty zero offset", 0, 0, 8, false},
		{"empty end", 72, 0, 8, false}, {"empty beyond end", 73, 0, 8, true},
		{"overflow", 72, 0xffffffff, 8, true}, {"truncated", 72, 2, 9, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := make([]byte, 64+tc.size)
			(&smb2.QueryDirectoryResponse{}).Encode(pkt)
			le.PutUint16(pkt[66:68], tc.offset)
			le.PutUint32(pkt[68:72], tc.length)
			if tc.name == "valid" {
				copy(pkt[72:], encodeFileIdBothDirectoryInformation("x"))
			}
			res, err := accept(smb2.SMB2_QUERY_DIRECTORY, &recvPacket{pkt: pkt}, smb2.SMB311)
			if tc.invalid {
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
				require.Nil(t, res)
				return
			}
			require.NoError(t, err)
			defer res.close()
			if tc.name == "valid" {
				entries, err := parseReaddir(smb2.QueryDirectoryResponseDecoder(res.codec().Body()).OutputBuffer())
				require.NoError(t, err)
				require.Len(t, entries, 1)
				require.Equal(t, "x", entries[0].Name())
			}
		})
	}
}
