package protocol

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestSymlinkWithoutErrorData(t *testing.T) {
	for _, tc := range []struct {
		name, path, target       string
		malformed, denied, cycle bool
	}{
		{name: "final link", path: `dir\link`, target: "target"},
		{name: "ancestor link", path: `dir\link\child`, target: "target"},
		{name: "malformed reparse data", path: `dir\link`, target: "target", malformed: true},
		{name: "probe denied", path: `dir\link`, target: "target", denied: true},
		{name: "cycle", path: `dir\link`, target: "link", cycle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, peer := newTestTree(t)
			transport := NewTransport(peer)
			done := make(chan struct{})
			var names []string
			var queries, updates int
			go func() {
				defer close(done)
				for {
					packet, err := readMsg(transport)
					if err != nil {
						return
					}
					create := wire.CreateRequestDecoder(wire.PacketCodec(packet).Body())
					if create.IsInvalid() {
						t.Error("invalid CREATE")
						return
					}
					name := create.Name()
					names = append(names, name)
					probe := create.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT != 0
					var responses []compoundResponse
					if probe && name == `dir\link` && !tc.denied {
						queries++
						var output wire.Encoder = &wire.SymbolicLinkReparseDataBuffer{Flags: wire.SYMLINK_FLAG_RELATIVE, SubstituteName: tc.target, PrintName: tc.target}
						if tc.malformed {
							output = rawEncoder{1}
						}
						responses = []compoundResponse{
							{packet: testTreeCreateResponse(&wire.FileId{}), status: erref.STATUS_SUCCESS},
							{packet: &wire.IoctlResponse{CtlCode: wire.FSCTL_GET_REPARSE_POINT, FileId: &wire.FileId{}, Output: output}, status: erref.STATUS_SUCCESS},
							{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
						}
					} else if !probe && strings.HasPrefix(name, `dir\target`) {
						updates++
						responses = []compoundResponse{
							{packet: testTreeCreateResponse(&wire.FileId{}), status: erref.STATUS_SUCCESS},
							{packet: &wire.SetInfoResponse{}, status: erref.STATUS_SUCCESS},
							{packet: closeSuccessResponse(), status: erref.STATUS_SUCCESS},
						}
					} else {
						first := erref.STATUS_STOPPED_ON_SYMLINK
						command := wire.SMB2_SET_INFO
						if probe {
							command = wire.SMB2_IOCTL
							if tc.denied {
								first = erref.STATUS_ACCESS_DENIED
							}
						}
						responses = []compoundResponse{
							{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, status: first},
							{packet: &wire.ErrorResponse{CommandCode: command}, status: erref.STATUS_FILE_CLOSED},
							{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_CLOSE}, status: erref.STATUS_FILE_CLOSED},
						}
					}
					if err := sendCompoundResponse(transport, packet, responses); err != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request := tree.Request().WithFollowSymlinks(true).
				Create(tc.path, wire.DELETE, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL).
				SetInfo(wire.SMB2_0_INFO_FILE, wire.FileDispositionInformation, 0, &wire.FileDispositionInformationEncoder{DeletePending: 1}).Close()
			res, err := request.Do(ctx)
			if res != nil {
				res.Close()
			}
			peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			<-done
			switch {
			case tc.malformed:
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
				require.Equal(t, 1, queries)
				require.Zero(t, updates)
			case tc.denied:
				require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
				require.Zero(t, queries)
				require.Zero(t, updates)
			case tc.cycle:
				require.ErrorContains(t, err, "Too many levels of symbolic links")
				require.LessOrEqual(t, queries, clientMaxSymlinkDepth)
				require.Zero(t, updates)
			default:
				require.NoError(t, err)
				require.Equal(t, 1, queries)
				require.Equal(t, 1, updates)
				if tc.path == `dir\link\child` {
					require.Equal(t, []string{tc.path, tc.path, `dir\link`, `dir\target\child`}, names)
				} else {
					require.Equal(t, []string{tc.path, tc.path, `dir\target`}, names)
				}
			}
		})
	}
}
