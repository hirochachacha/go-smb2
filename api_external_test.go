// This package verifies the phase 1-2 API from a consumer's point of view.
package smb2_test

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	smb2proto "github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

var externalMechanismOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

// externalTestCredentials deliberately uses a one-round mechanism. The fake
// server only needs to establish an SMB session; authentication itself is
// outside the API behavior covered here.
type externalTestCredentials struct{}

func (externalTestCredentials) NewInitiator(context.Context, string) (smb2.Initiator, error) {
	return &externalTestInitiator{}, nil
}

type externalTestInitiator struct{ complete bool }

func (*externalTestInitiator) OID() asn1.ObjectIdentifier { return externalMechanismOID }
func (i *externalTestInitiator) InitSecContext() ([]byte, error) {
	i.complete = false
	return []byte{1}, nil
}

func (i *externalTestInitiator) AcceptSecContext([]byte) ([]byte, error) {
	i.complete = true
	return nil, nil
}
func (*externalTestInitiator) GetMIC([]byte) ([]byte, error)  { return nil, nil }
func (*externalTestInitiator) VerifyMIC([]byte, []byte) error { return nil }
func (i *externalTestInitiator) Complete() bool               { return i.complete }
func (*externalTestInitiator) SessionKey() []byte             { return nil }

type externalTransportDialer struct {
	callback func(net.Conn, []byte) error
	result   chan<- externalServerResult
}

func (d externalTransportDialer) Dial(context.Context, string) (smb2.Transport, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if err := externalServe(server, d.callback); err != nil && !errors.Is(err, io.EOF) {
			select {
			case d.result <- externalServerResult{err: err}:
			default:
			}
		} else {
			select {
			case d.result <- externalServerResult{}:
			default:
			}
		}
	}()
	return smb2.NewTransport(client), nil
}

type externalServerResult struct{ err error }

// newExternalServer wires one fake SMB endpoint to a test callback. The
// callback receives requests after negotiate and session setup and returns
// io.EOF after sending the LOGOFF response.
func newExternalServer(t *testing.T, serve func(net.Conn, []byte) error) (smb2.TransportDialer, <-chan externalServerResult) {
	t.Helper()
	result := make(chan externalServerResult, 1)
	// The result channel lets callers check wire assertions made by the
	// goroutine after closing the Session.
	return externalTransportDialer{callback: serve, result: result}, result
}

// externalServe performs the common SMB handshake and dispatches subsequent
// requests. It uses raw Direct TCP framing because smb2.Transport is sealed.
func externalServe(conn net.Conn, callback func(net.Conn, []byte) error) error {
	req, err := externalReadPacket(conn)
	if err != nil {
		return err
	}
	p := smb2proto.PacketCodec(req)
	if p.Command() != smb2proto.SMB2_NEGOTIATE {
		return fmt.Errorf("first request is %v", p.Command())
	}
	neg := &smb2proto.NegotiateResponse{
		PacketHeader:    smb2proto.PacketHeader{Flags: smb2proto.SMB2_FLAGS_SERVER_TO_REDIR},
		SecurityMode:    smb2proto.SMB2_NEGOTIATE_SIGNING_ENABLED,
		DialectRevision: smb2proto.SMB210,
		Capabilities:    smb2proto.SMB2_GLOBAL_CAP_DFS,
		MaxTransactSize: 1 << 20,
		MaxReadSize:     1 << 20,
		MaxWriteSize:    1 << 20,
		SystemTime:      &smb2proto.Filetime{},
		ServerStartTime: &smb2proto.Filetime{},
	}
	if err := externalWriteResponse(conn, req, neg, erref.STATUS_SUCCESS, 0, 0); err != nil {
		return err
	}

	req, err = externalReadPacket(conn)
	if err != nil {
		return err
	}
	p = smb2proto.PacketCodec(req)
	if p.Command() != smb2proto.SMB2_SESSION_SETUP {
		return fmt.Errorf("second request is %v", p.Command())
	}
	token, err := spnego.EncodeNegTokenResp(0, externalMechanismOID, []byte{2}, nil)
	if err != nil {
		return err
	}
	setup := &smb2proto.SessionSetupResponse{
		PacketHeader:   smb2proto.PacketHeader{Flags: smb2proto.SMB2_FLAGS_SERVER_TO_REDIR, SessionId: 0x1234},
		SessionFlags:   smb2proto.SMB2_SESSION_FLAG_IS_GUEST,
		SecurityBuffer: token,
	}
	if err := externalWriteResponse(conn, req, setup, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
		return err
	}

	for {
		req, err = externalReadPacket(conn)
		if err != nil {
			return err
		}
		if err := callback(conn, req); err != nil {
			return err
		}
	}
}

func externalReadPacket(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 64 || n > 4<<20 {
		return nil, fmt.Errorf("invalid packet length %d", n)
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(conn, pkt)
	return pkt, err
}

func externalWritePacket(conn net.Conn, pkt []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(pkt)))
	if _, err := conn.Write(header[:]); err != nil {
		return err
	}
	_, err := conn.Write(pkt)
	return err
}

func externalWriteResponse(conn net.Conn, req []byte, response smb2proto.Packet, status erref.NtStatus, sessionID uint64, treeID uint32) error {
	buf := make([]byte, response.Size())
	response.Encode(buf)
	reqPacket := smb2proto.PacketCodec(req)
	p := smb2proto.PacketCodec(buf)
	p.SetMessageId(reqPacket.MessageId())
	p.SetSessionId(sessionID)
	p.SetTreeId(treeID)
	p.SetStatus(uint32(status))
	p.SetCreditResponse(reqPacket.CreditRequest())
	p.SetFlags(smb2proto.SMB2_FLAGS_SERVER_TO_REDIR)
	return externalWritePacket(conn, buf)
}

type externalRawEncoder []byte

func (e externalRawEncoder) Size() int         { return len(e) }
func (e externalRawEncoder) Encode(dst []byte) { copy(dst, e) }

func externalCreateSuccess() *smb2proto.CreateResponse {
	return &smb2proto.CreateResponse{
		CreationTime:   &smb2proto.Filetime{},
		LastAccessTime: &smb2proto.Filetime{},
		LastWriteTime:  &smb2proto.Filetime{},
		ChangeTime:     &smb2proto.Filetime{},
		FileId:         &smb2proto.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
	}
}

func externalCloseSuccess() *smb2proto.CloseResponse {
	return &smb2proto.CloseResponse{
		CreationTime:   &smb2proto.Filetime{},
		LastAccessTime: &smb2proto.Filetime{},
		LastWriteTime:  &smb2proto.Filetime{},
		ChangeTime:     &smb2proto.Filetime{},
	}
}

func externalRequestPath(req []byte) string {
	p := smb2proto.PacketCodec(req)
	cr := smb2proto.CreateRequestDecoder(p.Body())
	if cr.IsInvalid() || cr.NameLength() == 0 {
		return ""
	}
	start := int(cr.NameOffset())
	end := start + int(cr.NameLength())
	if start < 64 || end < start || end > len(req) {
		return ""
	}
	return utf16le.DecodeToString(req[start:end])
}

func externalTreePath(req []byte) string {
	p := smb2proto.PacketCodec(req)
	tc := smb2proto.TreeConnectRequestDecoder(p.Body())
	if tc.IsInvalid() || tc.PathLength() == 0 {
		return ""
	}
	start := int(tc.PathOffset())
	end := start + int(tc.PathLength())
	if start < 64 || end < start || end > len(req) {
		return ""
	}
	return utf16le.DecodeToString(req[start:end])
}

func externalDFSReferralV3(prefix, target string) []byte {
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

func externalDFSNameList(special string, names ...string) []byte {
	const entrySize = 18
	specialBytes := append(utf16le.EncodeStringToBytes(special), 0, 0)
	var namesBytes []byte
	for _, name := range namesBytesFromStrings(names) {
		namesBytes = append(namesBytes, name...)
	}
	b := make([]byte, 8+entrySize+len(specialBytes)+len(namesBytes))
	le := binary.LittleEndian
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], entrySize)
	le.PutUint16(b[14:16], dfsc.ReferralNameList)
	le.PutUint16(b[20:22], entrySize)
	le.PutUint16(b[22:24], uint16(len(names)))
	if len(names) > 0 {
		le.PutUint16(b[24:26], entrySize+uint16(len(specialBytes)))
	}
	copy(b[8+entrySize:], specialBytes)
	copy(b[8+entrySize+len(specialBytes):], namesBytes)
	return b
}

func namesBytesFromStrings(names []string) [][]byte {
	out := make([][]byte, len(names))
	for i, name := range names {
		out[i] = append(utf16le.EncodeStringToBytes(name), 0, 0)
	}
	return out
}

func externalServerError(t *testing.T, result <-chan externalServerResult) {
	t.Helper()
	select {
	case r := <-result:
		if r.err != nil {
			t.Fatal(r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("fake SMB server did not finish")
	}
}

func externalReferralInput(req []byte) (string, error) {
	p := smb2proto.PacketCodec(req)
	ir := smb2proto.IoctlRequestDecoder(p.Body())
	if ir.IsInvalid() {
		return "", errors.New("invalid IOCTL request")
	}
	start := int(ir.InputOffset())
	end := start + int(ir.InputCount())
	if start < 64 || end < start || end > len(req) || end-start < 2 {
		return "", errors.New("invalid DFS referral input bounds")
	}
	return utf16le.DecodeToString(req[start+2 : end]), nil
}

func TestExternalSymlinkErrorCanBeFollowedAcrossShares(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var createCount int
	dialer, result := newExternalServer(t, func(conn net.Conn, req []byte) error {
		p := smb2proto.PacketCodec(req)
		switch p.Command() {
		case smb2proto.SMB2_TREE_CONNECT:
			share := externalTreePath(req)
			tree := uint32(10)
			if strings.HasSuffix(strings.ToUpper(share), `\OTHER`) {
				tree = 11
			}
			return externalWriteResponse(conn, req, &smb2proto.TreeConnectResponse{ShareType: smb2proto.SMB2_SHARE_TYPE_DISK}, erref.STATUS_SUCCESS, 0x1234, tree)
		case smb2proto.SMB2_CREATE:
			createCount++
			if createCount == 1 {
				errResponse := &smb2proto.ErrorResponse{
					CommandCode: smb2proto.SMB2_CREATE,
					ErrorData: &smb2proto.SymbolicLinkErrorResponse{
						UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
						Flags:              0,
						SubstituteName:     `\??\UNC\server\other\dest`,
						PrintName:          `\\server\other\dest`,
					},
				}
				return externalWriteResponse(conn, req, errResponse, erref.STATUS_STOPPED_ON_SYMLINK, 0x1234, p.TreeId())
			}
			return externalWriteResponse(conn, req, externalCreateSuccess(), erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_CLOSE:
			return externalWriteResponse(conn, req, externalCloseSuccess(), erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &smb2proto.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &smb2proto.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
				return err
			}
			return io.EOF
		default:
			return fmt.Errorf("unexpected SMB command %v", p.Command())
		}
	})
	d := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer}
	session, err := d.Dial(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	source, err := session.Mount(ctx, "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Unmount(ctx)
	_, err = source.Open(ctx, `link\file`)
	var linkErr *smb2.SymlinkError
	if !errors.As(err, &linkErr) {
		t.Fatalf("Open error = %v, want *smb2.SymlinkError", err)
	}
	if linkErr.Relative || linkErr.Target != `\\server\other\dest` {
		t.Fatalf("symlink details = relative %v target %q", linkErr.Relative, linkErr.Target)
	}
	if linkErr.Path != `\\server\source\link\file` {
		t.Fatalf("symlink path = %q", linkErr.Path)
	}
	if !strings.Contains(linkErr.ResolvedPath, `\\server\other\dest\file`) {
		t.Fatalf("resolved continuation = %q", linkErr.ResolvedPath)
	}

	parts := strings.Split(strings.Trim(linkErr.ResolvedPath, `\`), `\`)
	if len(parts) < 3 || !strings.EqualFold(parts[0], "server") || !strings.EqualFold(parts[1], "other") {
		t.Fatalf("resolved continuation is not a server/share UNC: %q", linkErr.ResolvedPath)
	}
	other, err := session.Mount(ctx, parts[1])
	if err != nil {
		t.Fatal(err)
	}
	defer other.Unmount(ctx)
	f, err := other.Open(ctx, strings.Join(parts[2:], `\`))
	if err != nil {
		t.Fatalf("manual continuation Open(%q): %v", strings.Join(parts[2:], `\`), err)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	externalServerError(t, result)
}

func TestExternalSameShareSymlinkKeepsPathForDFSReferral(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var createCount int
	var referralPath string
	dialer, result := newExternalServer(t, func(conn net.Conn, req []byte) error {
		p := smb2proto.PacketCodec(req)
		switch p.Command() {
		case smb2proto.SMB2_TREE_CONNECT:
			share := externalTreePath(req)
			tree := uint32(10)
			if strings.HasSuffix(strings.ToUpper(share), `\IPC$`) {
				tree = 12
			}
			caps := uint32(0)
			if strings.HasSuffix(strings.ToUpper(share), `\NAMESPACE`) {
				caps = smb2proto.SMB2_SHARE_CAP_DFS
			}
			return externalWriteResponse(conn, req, &smb2proto.TreeConnectResponse{ShareType: smb2proto.SMB2_SHARE_TYPE_DISK, Capabilities: caps}, erref.STATUS_SUCCESS, 0x1234, tree)
		case smb2proto.SMB2_CREATE:
			createCount++
			if createCount == 1 {
				link := &smb2proto.ErrorResponse{
					CommandCode: smb2proto.SMB2_CREATE,
					ErrorData: &smb2proto.SymbolicLinkErrorResponse{
						UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
						Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
						SubstituteName:     "next",
						PrintName:          "next",
					},
				}
				return externalWriteResponse(conn, req, link, erref.STATUS_STOPPED_ON_SYMLINK, 0x1234, p.TreeId())
			}
			if !strings.Contains(strings.ToLower(externalRequestPath(req)), `next\file`) {
				return fmt.Errorf("same-share retry path = %q", externalRequestPath(req))
			}
			return externalWriteResponse(conn, req, &smb2proto.ErrorResponse{CommandCode: smb2proto.SMB2_CREATE}, erref.STATUS_PATH_NOT_COVERED, 0x1234, p.TreeId())
		case smb2proto.SMB2_IOCTL:
			path, err := externalReferralInput(req)
			if err != nil {
				return err
			}
			referralPath = path
			return externalWriteResponse(conn, req, &smb2proto.IoctlResponse{
				CtlCode: smb2proto.FSCTL_DFS_GET_REFERRALS,
				FileId:  smb2proto.RelatedFileId,
				Output:  externalRawEncoder(externalDFSReferralV3(`\server\namespace\dir\next`, `\\target\share\root`)),
			}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &smb2proto.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &smb2proto.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
				return err
			}
			return io.EOF
		default:
			return fmt.Errorf("unexpected SMB command %v", p.Command())
		}
	})
	session, err := (&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer}).Dial(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := session.Mount(ctx, "namespace")
	if err != nil {
		t.Fatal(err)
	}
	_, err = namespace.Open(ctx, `dir\link\file`)
	var referralErr *smb2.DFSReferralError
	if !errors.As(err, &referralErr) {
		t.Fatalf("Open error = %v, want *smb2.DFSReferralError", err)
	}
	if !strings.Contains(strings.ToLower(referralErr.Path), `dir\next\file`) || strings.Contains(strings.ToLower(referralErr.Path), `dir\link\file`) {
		t.Fatalf("referral continuation path = %q", referralErr.Path)
	}
	if referralErr.Path != `\\server\namespace\dir\next\file` {
		t.Fatalf("referral path = %q", referralErr.Path)
	}
	response, err := session.GetDFSReferrals(ctx, referralErr.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(referralPath), `dir\next\file`) || strings.Contains(strings.ToLower(referralPath), `dir\link\file`) {
		t.Fatalf("referral request path = %q", referralPath)
	}
	if len(response.Entries) != 1 || response.Entries[0].NetworkAddress != `\\target\share\root` {
		t.Fatalf("referral response = %#v", response)
	}
	if response.Prefix != `\\server\namespace\dir\next` || response.Entries[0].TargetPath != `\\target\share\root\file` {
		t.Fatalf("referral paths = prefix %q target %q", response.Prefix, response.Entries[0].TargetPath)
	}
	_ = namespace.Unmount(ctx)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	externalServerError(t, result)
}

func TestExternalGetDFSReferralsSupportsDomainAndDCNameLists(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var paths []string
	dialer, result := newExternalServer(t, func(conn net.Conn, req []byte) error {
		p := smb2proto.PacketCodec(req)
		switch p.Command() {
		case smb2proto.SMB2_TREE_CONNECT:
			return externalWriteResponse(conn, req, &smb2proto.TreeConnectResponse{ShareType: smb2proto.SMB2_SHARE_TYPE_PIPE}, erref.STATUS_SUCCESS, 0x1234, 12)
		case smb2proto.SMB2_IOCTL:
			path, err := externalReferralInput(req)
			if err != nil {
				return err
			}
			paths = append(paths, path)
			var output []byte
			switch path {
			case "":
				output = externalDFSNameList("EXAMPLE", "DC1", "DC2")
			case `\example`:
				output = externalDFSNameList("EXAMPLE", "DC1")
			default:
				return fmt.Errorf("unexpected DFS name-list path %q", path)
			}
			return externalWriteResponse(conn, req, &smb2proto.IoctlResponse{
				CtlCode: smb2proto.FSCTL_DFS_GET_REFERRALS,
				FileId:  smb2proto.RelatedFileId,
				Output:  externalRawEncoder(output),
			}, erref.STATUS_SUCCESS, 0x1234, 12)
		case smb2proto.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &smb2proto.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case smb2proto.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &smb2proto.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
				return err
			}
			return io.EOF
		default:
			return fmt.Errorf("unexpected SMB command %v", p.Command())
		}
	})
	session, err := (&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer}).Dial(ctx, "server")
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.GetDFSReferrals(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Prefix != "" || len(first.Entries) != 1 || first.Entries[0].SpecialName != "EXAMPLE" || strings.Join(first.Entries[0].ExpandedNames, ",") != "DC1,DC2" || first.Entries[0].TargetPath != "" {
		t.Fatalf("DOMAIN name-list response = %#v", first)
	}
	second, err := session.GetDFSReferrals(ctx, `\example`)
	if err != nil {
		t.Fatal(err)
	}
	if second.Prefix != "" || len(second.Entries) != 1 || strings.Join(second.Entries[0].ExpandedNames, ",") != "DC1" || second.Entries[0].TargetPath != "" {
		t.Fatalf("DC name-list response = %#v", second)
	}
	if len(paths) != 2 || paths[0] != "" || paths[1] != `\example` {
		t.Fatalf("wire DFS request paths = %#v", paths)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	externalServerError(t, result)
}

func TestExternalGetDFSReferralsGrowsOutputBuffer(t *testing.T) {
	t.Parallel()
	for _, capped := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry succeeds", true: "size limit"}[capped], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var sizes []uint32
			dialer, result := newExternalServer(t, func(conn net.Conn, req []byte) error {
				p := smb2proto.PacketCodec(req)
				switch p.Command() {
				case smb2proto.SMB2_TREE_CONNECT:
					return externalWriteResponse(conn, req, &smb2proto.TreeConnectResponse{ShareType: smb2proto.SMB2_SHARE_TYPE_PIPE}, erref.STATUS_SUCCESS, 0x1234, 12)
				case smb2proto.SMB2_IOCTL:
					request := smb2proto.IoctlRequestDecoder(p.Body())
					if request.IsInvalid() || request.CtlCode() != smb2proto.FSCTL_DFS_GET_REFERRALS {
						return fmt.Errorf("invalid referral IOCTL")
					}
					path, err := externalReferralInput(req)
					if err != nil || path != `\domain\root\file` {
						return fmt.Errorf("referral request path %q: %v", path, err)
					}
					if level := binary.LittleEndian.Uint16(req[request.InputOffset():]); level != 4 {
						return fmt.Errorf("referral level = %d, want 4", level)
					}
					sizes = append(sizes, request.MaxOutputResponse())
					if capped || len(sizes) == 1 {
						return externalWriteResponse(conn, req, &smb2proto.ErrorResponse{CommandCode: smb2proto.SMB2_IOCTL}, erref.STATUS_BUFFER_OVERFLOW, 0x1234, p.TreeId())
					}
					return externalWriteResponse(conn, req, &smb2proto.IoctlResponse{
						CtlCode: smb2proto.FSCTL_DFS_GET_REFERRALS, FileId: smb2proto.RelatedFileId,
						Output: externalRawEncoder(externalDFSReferralV3(`\domain\root`, `\\files\share`)),
					}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
				case smb2proto.SMB2_TREE_DISCONNECT:
					return externalWriteResponse(conn, req, &smb2proto.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
				case smb2proto.SMB2_LOGOFF:
					if err := externalWriteResponse(conn, req, &smb2proto.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
						return err
					}
					return io.EOF
				default:
					return fmt.Errorf("unexpected SMB command %v", p.Command())
				}
			})
			session, err := (&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer}).Dial(ctx, "server")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			response, err := session.GetDFSReferrals(ctx, `\\domain\root\file`)
			want := []uint32{4096, 8192}
			if capped {
				want = []uint32{4096, 8192, 16384, 32768, 56 * 1024}
				if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
					t.Fatalf("GetDFSReferrals = %v, want buffer overflow", err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if len(response.Entries) != 1 || response.Entries[0].TargetPath != `\\files\share\file` {
				t.Fatalf("referral response = %#v", response)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			externalServerError(t, result)
			if fmt.Sprint(sizes) != fmt.Sprint(want) {
				t.Fatalf("buffer sizes = %v, want %v", sizes, want)
			}
		})
	}
}
