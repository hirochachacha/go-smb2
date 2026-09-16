package smb2

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

// TestTreeCreateWirePathAndFlags checks the wire decision made from the
// TREE_CONNECT capability. SMB2_SHAREFLAG_DFS_ROOT is deliberately present in
// both cases: DFS routing is selected only by SMB2_SHARE_CAP_DFS.
func TestTreeCreateWirePathAndFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		isDFSShare bool
		shareFlags uint32
		wantName   string
		wantDFS    bool
	}{
		{
			name:       "capability only",
			isDFSShare: true,
			shareFlags: smb2.SMB2_SHAREFLAG_DFS_ROOT,
			wantName:   `\server\namespace\folder\файл`,
			wantDFS:    true,
		},
		{
			name:       "share flags only",
			shareFlags: smb2.SMB2_SHAREFLAG_DFS_ROOT,
			wantName:   `folder\файл`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, flags := observeCreateWire(t, test.isDFSShare, test.shareFlags)
			if name != test.wantName {
				t.Fatalf("CREATE name = %q, want %q", name, test.wantName)
			}
			gotDFS := flags&smb2.SMB2_FLAGS_DFS_OPERATIONS != 0
			if gotDFS != test.wantDFS {
				t.Fatalf("DFS flag = %v, want %v (flags %#x)", gotDFS, test.wantDFS, flags)
			}
		})
	}
}

func observeCreateWire(t *testing.T, isDFSShare bool, shareFlags uint32) (string, uint32) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	s.enableSession()
	tc := &treeConn{
		session:    s,
		treeId:     7,
		shareFlags: shareFlags,
		isDFSShare: isDFSShare,
		serverName: "server",
		shareName:  "namespace",
	}
	type wireResult struct {
		name  string
		flags uint32
		err   error
	}
	result := make(chan wireResult, 1)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			result <- wireResult{err: err}
			return
		}
		p := smb2.PacketCodec(req)
		cr := smb2.CreateRequestDecoder(p.Body())
		if cr.IsInvalid() {
			result <- wireResult{err: errors.New("invalid CREATE request")}
			return
		}
		start := int(cr.NameOffset())
		end := start + int(cr.NameLength())
		if start < 64 || end < start || end > len(req) {
			result <- wireResult{err: errors.New("CREATE name outside packet")}
			return
		}
		name := utf16le.DecodeToString(req[start:end])
		sendTestResponse(dt, req, &smb2.CreateResponse{
			CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
			LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
			FileId: &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
		}, uint32(erref.STATUS_SUCCESS))
		result <- wireResult{name: name, flags: p.Flags()}
	}()

	res, err := tc.sendRecv(context.Background(), &smb2.CreateRequest{
		Name: "folder\\файл", DesiredAccess: smb2.GENERIC_READ,
		CreateDisposition: smb2.FILE_OPEN, ShareAccess: smb2.FILE_SHARE_READ,
	})
	if err != nil {
		t.Fatal(err)
	}
	res.close()
	got := <-result
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got.name, got.flags
}

type compoundResponse struct {
	packet smb2.Packet
	status erref.NtStatus
}

// sendCompoundResponse emits one response for each request operation. The
// response chain follows [MS-SMB2] compound alignment and related flags.
func sendCompoundResponse(dt transport, request []byte, responses []compoundResponse) error {
	if len(responses) == 0 {
		return errors.New("empty compound response")
	}
	var out []byte
	requestOffset := 0
	for i, response := range responses {
		if requestOffset < 0 || requestOffset >= len(request) {
			return errors.New("compound request ended early")
		}
		reqPacket := smb2.PacketCodec(request[requestOffset:])
		span := smb2.Roundup(response.packet.Size(), 8)
		buf := make([]byte, span)
		response.packet.Encode(buf)
		p := smb2.PacketCodec(buf)
		p.SetMessageId(reqPacket.MessageId())
		p.SetSessionId(reqPacket.SessionId())
		p.SetTreeId(reqPacket.TreeId())
		p.SetStatus(uint32(response.status))
		p.SetCreditResponse(reqPacket.CreditRequest())
		flags := uint32(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		if i > 0 {
			flags |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
		}
		p.SetFlags(flags)
		if i < len(responses)-1 {
			p.SetNextCommand(uint32(span))
		}
		out = append(out, buf...)
		if next := reqPacket.NextCommand(); next != 0 {
			requestOffset += int(next)
		} else {
			requestOffset = len(request)
		}
	}
	_, err := dt.Writev(out)
	return err
}

// Keep this helper available to future lower/upper wire tests. V3 referral
// strings are UTF-16 and offsets are relative to the referral entry.
func makeDFSReferralV3(prefix, target string) []byte {
	path := append(utf16le.EncodeStringToBytes(prefix), 0, 0)
	network := append(utf16le.EncodeStringToBytes(target), 0, 0)
	const entrySize = 34
	b := make([]byte, 8+entrySize+len(path)+len(path)+len(network))
	le := binary.LittleEndian
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(prefix)))
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], entrySize)
	le.PutUint32(b[16:20], 300)
	le.PutUint16(b[20:22], entrySize)
	le.PutUint16(b[22:24], entrySize+uint16(len(path)))
	le.PutUint16(b[24:26], entrySize+uint16(len(path)*2))
	copy(b[8+entrySize:], path)
	copy(b[8+entrySize+len(path):], path)
	copy(b[8+entrySize+len(path)*2:], network)
	return b
}

func TestValidateReferralPathForms(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"",
		`\dc-one`,
		`\\dc-two`,
		`\\server\share`,
		`\\server\share\root\link`,
	} {
		t.Run(path, func(t *testing.T) {
			if err := validateReferralPath(path); err != nil {
				t.Fatalf("validateReferralPath(%q) = %v", path, err)
			}
		})
	}
}

func TestGetDFSReferralsRejectsUndocumentedPathFormsBeforeSessionUse(t *testing.T) {
	t.Parallel()
	var session *Session
	for _, path := range []string{
		`domain`,
		`server\share`,
		`\server\share`,
		`\\server\`,
		`\\\server\share`,
		`\\server\\share`,
	} {
		t.Run(path, func(t *testing.T) {
			validationErr := validateReferralPath(path)
			if validationErr == nil {
				t.Fatalf("validateReferralPath(%q) accepted undocumented path form", path)
			}
			_, publicErr := session.GetDFSReferrals(context.Background(), path)
			if publicErr == nil || publicErr.Error() != validationErr.Error() {
				t.Fatalf("GetDFSReferrals(%q) error = %v, want path validation error %v", path, publicErr, validationErr)
			}
			if errors.Is(publicErr, net.ErrClosed) {
				t.Fatalf("GetDFSReferrals(%q) reached session use: %v", path, publicErr)
			}
		})
	}
}
