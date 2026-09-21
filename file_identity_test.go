package smb2

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestShareSameFile(t *testing.T) {
	share := &Share{}
	other := &Share{}
	known := func(id, volume uint64) *FileStat {
		return &FileStat{FileId: id, VolumeId: volume, share: share, hasIdentity: true}
	}
	differentShare := known(42, 7)
	differentShare.share = other
	missing := known(42, 7)
	missing.hasIdentity = false
	for _, tc := range []struct {
		name string
		a, b os.FileInfo
		want bool
	}{
		{"same", known(42, 7), known(42, 7), true},
		{"zero volume is valid", known(42, 0), known(42, 0), true},
		{"different file", known(42, 7), known(43, 7), false},
		{"different volume", known(42, 7), known(42, 8), false},
		{"different share", known(42, 7), differentShare, false},
		{"missing context", known(42, 7), missing, false},
		{"directory entry", known(42, 0), &FileStat{FileId: 42}, false},
		{"unsupported ID", known(0, 7), known(0, 7), false},
		{"nonunique ID", known(^uint64(0), 7), known(^uint64(0), 7), false},
		{"nil", nil, known(42, 7), false},
		{"typed nil", (*FileStat)(nil), known(42, 7), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, share.SameFile(tc.a, tc.b))
			require.Equal(t, tc.want, share.SameFile(tc.b, tc.a))
			require.False(t, other.SameFile(tc.a, tc.b))
			require.False(t, (*Share)(nil).SameFile(tc.a, tc.b))
		})
	}
}

func TestStatFileIdentity(t *testing.T) {
	for _, present := range []bool{false, true} {
		for _, operation := range []string{"Stat", "Lstat", "File.Stat"} {
			t.Run(operation+map[bool]string{false: "/absent", true: "/present"}[present], func(t *testing.T) {
				share, peer := newTestShare(t)
				startFullFakeServer(peer, nil, nil, func(_ uint64, request []byte) []byte {
					q := wire.QueryInfoRequestDecoder(wire.PacketCodec(request).Body())
					if q.IsInvalid() {
						return nil
					}
					size := 8
					if q.FileInfoClass() == wire.FileNetworkOpenInformation {
						size = 56
					}
					response := &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, size))}
					buf := make([]byte, response.Size())
					response.Encode(buf)
					return buf
				}, func(req wire.CreateRequestDecoder, res *wire.CreateResponse) {
					require.False(t, req.IsInvalid())
					contexts := req.Contexts()
					require.NotEmpty(t, contexts)
					require.Contains(t, string(contexts), "QFid")
					if !present {
						return
					}
					context := make([]byte, 56)
					le.PutUint16(context[4:6], 16)
					le.PutUint16(context[6:8], 4)
					le.PutUint16(context[10:12], 24)
					le.PutUint32(context[12:16], 32)
					copy(context[16:20], "QFid")
					le.PutUint64(context[24:32], 42)
					// A zero volume ID is still an explicitly returned identity.
					res.Contexts = wire.CreateContexts{rawEncoder(context)}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var info os.FileInfo
				var err error
				switch operation {
				case "Stat":
					info, err = share.Stat(ctx, "entry")
				case "Lstat":
					info, err = share.Lstat(ctx, "entry")
				default:
					f, openErr := share.Open(ctx, "entry")
					require.NoError(t, openErr)
					defer f.Close(ctx)
					info, err = f.Stat(ctx)
				}
				require.NoError(t, err)
				stat := info.(*FileStat)
				require.Equal(t, present, stat.hasIdentity)
				require.Equal(t, uint64(0), stat.VolumeId)
				if present {
					require.Equal(t, uint64(42), stat.FileId)
				} else {
					require.Zero(t, stat.FileId)
				}
				require.Equal(t, present, share.SameFile(info, info))
			})
		}
	}
}

func TestDirectoryEntryFileIdentity(t *testing.T) {
	buf := make([]byte, 106)
	le.PutUint32(buf[60:64], 2)
	le.PutUint64(buf[96:104], 42)
	buf[104] = 'a'
	entry := wire.FileIdBothDirectoryInformationDecoder(buf)
	require.False(t, entry.IsInvalid())
	stat := newFileStatFromFileIdBothDirectoryInformation(entry, "a")
	require.Equal(t, uint64(42), stat.FileId)
	require.Zero(t, stat.VolumeId)
	require.False(t, (&Share{}).SameFile(stat, stat))
}
