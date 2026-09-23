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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/auth"
	smbclient "github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

var externalMechanismOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

// externalTestCredentials deliberately uses a one-round mechanism. The fake
// server only needs to establish an SMB session; authentication itself is
// outside the API behavior covered here.
type externalTestCredentials struct{}

func (externalTestCredentials) NewInitiator(context.Context, string) (auth.Initiator, error) {
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
	p := wire.PacketCodec(req)
	if p.Command() != wire.SMB2_NEGOTIATE {
		return fmt.Errorf("first request is %v", p.Command())
	}
	neg := &wire.NegotiateResponse{
		Flags:           wire.SMB2_FLAGS_SERVER_TO_REDIR,
		SecurityMode:    wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
		DialectRevision: wire.SMB210,
		Capabilities:    wire.SMB2_GLOBAL_CAP_DFS,
		MaxTransactSize: 1 << 20,
		MaxReadSize:     1 << 20,
		MaxWriteSize:    1 << 20,
		SystemTime:      wire.Filetime{},
		ServerStartTime: wire.Filetime{},
	}
	if err := externalWriteResponse(conn, req, neg, erref.STATUS_SUCCESS, 0, 0); err != nil {
		return err
	}

	req, err = externalReadPacket(conn)
	if err != nil {
		return err
	}
	p = wire.PacketCodec(req)
	if p.Command() != wire.SMB2_SESSION_SETUP {
		return fmt.Errorf("second request is %v", p.Command())
	}
	token, err := spnego.EncodeNegTokenResp(0, externalMechanismOID, []byte{2}, nil)
	if err != nil {
		return err
	}
	setup := &wire.SessionSetupResponse{
		Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, SessionId: 0x1234,
		SessionFlags:   wire.SMB2_SESSION_FLAG_IS_GUEST,
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

func externalWriteResponse(conn net.Conn, req []byte, response wire.Packet, status erref.NtStatus, sessionID uint64, treeID uint32) error {
	buf := make([]byte, response.Size())
	response.Encode(buf)
	reqPacket := wire.PacketCodec(req)
	p := wire.PacketCodec(buf)
	p.SetMessageId(reqPacket.MessageId())
	p.SetSessionId(sessionID)
	p.SetTreeId(treeID)
	p.SetStatus(uint32(status))
	p.SetCreditResponse(reqPacket.CreditRequest())
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	return externalWritePacket(conn, buf)
}

type externalRawEncoder []byte

func (e externalRawEncoder) Size() int         { return len(e) }
func (e externalRawEncoder) Encode(dst []byte) { copy(dst, e) }

func externalCreateSuccess() *wire.CreateResponse {
	return &wire.CreateResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
		FileId:         wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
	}
}

func externalCloseSuccess() *wire.CloseResponse {
	return &wire.CloseResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}
}

func externalRequestPath(req []byte) string {
	p := wire.PacketCodec(req)
	cr := wire.CreateRequestDecoder(p.Body())
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
	p := wire.PacketCodec(req)
	tc := wire.TreeConnectRequestDecoder(p.Body())
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
	p := wire.PacketCodec(req)
	ir := wire.IoctlRequestDecoder(p.Body())
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
		p := wire.PacketCodec(req)
		switch p.Command() {
		case wire.SMB2_TREE_CONNECT:
			share := externalTreePath(req)
			tree := uint32(10)
			if strings.HasSuffix(strings.ToUpper(share), `\OTHER`) {
				tree = 11
			}
			return externalWriteResponse(conn, req, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_DISK}, erref.STATUS_SUCCESS, 0x1234, tree)
		case wire.SMB2_CREATE:
			createCount++
			if createCount == 1 {
				errResponse := &wire.ErrorResponse{
					CommandCode: wire.SMB2_CREATE,
					ErrorData: &wire.SymbolicLinkErrorResponse{
						UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
						Flags:              0,
						SubstituteName:     `\??\UNC\server\other\dest`,
						PrintName:          `\\server\other\dest`,
					},
				}
				return externalWriteResponse(conn, req, errResponse, erref.STATUS_STOPPED_ON_SYMLINK, 0x1234, p.TreeId())
			}
			return externalWriteResponse(conn, req, externalCreateSuccess(), erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_CLOSE:
			return externalWriteResponse(conn, req, externalCloseSuccess(), erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &wire.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &wire.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
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
	var linkErr *protocol.CrossShareSymlinkError
	if !errors.As(err, &linkErr) {
		t.Fatalf("Open error = %v, want *protocol.CrossShareSymlinkError", err)
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
		p := wire.PacketCodec(req)
		switch p.Command() {
		case wire.SMB2_TREE_CONNECT:
			share := externalTreePath(req)
			tree := uint32(10)
			if strings.HasSuffix(strings.ToUpper(share), `\IPC$`) {
				tree = 12
			}
			caps := uint32(0)
			if strings.HasSuffix(strings.ToUpper(share), `\NAMESPACE`) {
				caps = wire.SMB2_SHARE_CAP_DFS
			}
			return externalWriteResponse(conn, req, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_DISK, Capabilities: caps}, erref.STATUS_SUCCESS, 0x1234, tree)
		case wire.SMB2_CREATE:
			createCount++
			if createCount == 1 {
				link := &wire.ErrorResponse{
					CommandCode: wire.SMB2_CREATE,
					ErrorData: &wire.SymbolicLinkErrorResponse{
						UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
						Flags:              wire.SYMLINK_FLAG_RELATIVE,
						SubstituteName:     "next",
						PrintName:          "next",
					},
				}
				return externalWriteResponse(conn, req, link, erref.STATUS_STOPPED_ON_SYMLINK, 0x1234, p.TreeId())
			}
			if !strings.Contains(strings.ToLower(externalRequestPath(req)), `next\file`) {
				return fmt.Errorf("same-share retry path = %q", externalRequestPath(req))
			}
			return externalWriteResponse(conn, req, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, erref.STATUS_PATH_NOT_COVERED, 0x1234, p.TreeId())
		case wire.SMB2_IOCTL:
			path, err := externalReferralInput(req)
			if err != nil {
				return err
			}
			referralPath = path
			return externalWriteResponse(conn, req, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_DFS_GET_REFERRALS,
				FileId:  wire.RelatedFileId,
				Output:  externalRawEncoder(externalDFSReferralV3(`\server\namespace\dir\next`, `\\target\share\root`)),
			}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &wire.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &wire.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
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
	var referralErr *protocol.DFSReferralRequiredError
	if !errors.As(err, &referralErr) {
		t.Fatalf("Open error = %v, want *protocol.DFSReferralRequiredError", err)
	}
	if !strings.Contains(strings.ToLower(referralErr.Path), `dir\next\file`) || strings.Contains(strings.ToLower(referralErr.Path), `dir\link\file`) {
		t.Fatalf("referral continuation path = %q", referralErr.Path)
	}
	if referralErr.Path != `\\server\namespace\dir\next\file` {
		t.Fatalf("referral path = %q", referralErr.Path)
	}
	ipc, err := session.IPC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	response, err := dfs.NewClient(ipc).GetReferrals(ctx, referralErr.Path)
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
		p := wire.PacketCodec(req)
		switch p.Command() {
		case wire.SMB2_TREE_CONNECT:
			return externalWriteResponse(conn, req, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_PIPE}, erref.STATUS_SUCCESS, 0x1234, 12)
		case wire.SMB2_IOCTL:
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
			return externalWriteResponse(conn, req, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_DFS_GET_REFERRALS,
				FileId:  wire.RelatedFileId,
				Output:  externalRawEncoder(output),
			}, erref.STATUS_SUCCESS, 0x1234, 12)
		case wire.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &wire.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &wire.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
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
	ipc, err := session.IPC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dfsClient := dfs.NewClient(ipc)
	if _, err := dfsClient.GetReferrals(ctx, "domain"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("invalid referral path error = %v, want os.ErrInvalid", err)
	}
	if len(paths) != 0 {
		t.Fatalf("invalid referral path sent requests: %q", paths)
	}
	first, err := dfsClient.GetReferrals(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Prefix != "" || len(first.Entries) != 1 || first.Entries[0].SpecialName != "EXAMPLE" || strings.Join(first.Entries[0].ExpandedNames, ",") != "DC1,DC2" || first.Entries[0].TargetPath != "" {
		t.Fatalf("DOMAIN name-list response = %#v", first)
	}
	second, err := dfsClient.GetReferrals(ctx, `\example`)
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
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_TREE_CONNECT:
					return externalWriteResponse(conn, req, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_PIPE}, erref.STATUS_SUCCESS, 0x1234, 12)
				case wire.SMB2_IOCTL:
					request := wire.IoctlRequestDecoder(p.Body())
					if request.IsInvalid() || request.CtlCode() != wire.FSCTL_DFS_GET_REFERRALS {
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
						return externalWriteResponse(conn, req, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, erref.STATUS_BUFFER_OVERFLOW, 0x1234, p.TreeId())
					}
					return externalWriteResponse(conn, req, &wire.IoctlResponse{
						CtlCode: wire.FSCTL_DFS_GET_REFERRALS, FileId: wire.RelatedFileId,
						Output: externalRawEncoder(externalDFSReferralV3(`\domain\root`, `\\files\share`)),
					}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
				case wire.SMB2_TREE_DISCONNECT:
					return externalWriteResponse(conn, req, &wire.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
				case wire.SMB2_LOGOFF:
					if err := externalWriteResponse(conn, req, &wire.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
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
			ipc, err := session.IPC(ctx)
			if err != nil {
				t.Fatal(err)
			}
			response, err := dfs.NewClient(ipc).GetReferrals(ctx, `\\domain\root\file`)
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

func TestExternalGetDFSReferralsWithSiteName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer, result := newExternalServer(t, func(conn net.Conn, req []byte) error {
		p := wire.PacketCodec(req)
		switch p.Command() {
		case wire.SMB2_TREE_CONNECT:
			return externalWriteResponse(conn, req, &wire.TreeConnectResponse{ShareType: wire.SMB2_SHARE_TYPE_PIPE}, erref.STATUS_SUCCESS, 0x1234, 12)
		case wire.SMB2_IOCTL:
			request := wire.IoctlRequestDecoder(p.Body())
			if request.IsInvalid() || request.CtlCode() != wire.FSCTL_DFS_GET_REFERRALS_EX {
				return fmt.Errorf("unexpected CtlCode %x, want FSCTL_DFS_GET_REFERRALS_EX", request.CtlCode())
			}
			input := req[request.InputOffset() : request.InputOffset()+request.InputCount()]
			if len(input) < 8 {
				return fmt.Errorf("input too short: %d", len(input))
			}
			level := binary.LittleEndian.Uint16(input[0:2])
			flags := binary.LittleEndian.Uint16(input[2:4])
			dataLen := binary.LittleEndian.Uint32(input[4:8])
			if level != 4 || flags != 1 {
				return fmt.Errorf("level = %d, flags = %d", level, flags)
			}
			pathLen := int(binary.LittleEndian.Uint16(input[8:10]))
			pathBytes := input[10 : 10+pathLen]
			if utf16le.DecodeToString(pathBytes) != `\domain\root` {
				return fmt.Errorf("unexpected path: %q", utf16le.DecodeToString(pathBytes))
			}
			siteOffset := 10 + pathLen
			siteLen := int(binary.LittleEndian.Uint16(input[siteOffset : siteOffset+2]))
			siteBytes := input[siteOffset+2 : siteOffset+2+siteLen]
			if utf16le.DecodeToString(siteBytes) != "SiteA" {
				return fmt.Errorf("unexpected site: %q", utf16le.DecodeToString(siteBytes))
			}
			if int(dataLen) != 2+pathLen+2+siteLen {
				return fmt.Errorf("dataLen = %d, want %d", dataLen, 2+pathLen+2+siteLen)
			}
			return externalWriteResponse(conn, req, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_DFS_GET_REFERRALS_EX, FileId: wire.RelatedFileId,
				Output: externalRawEncoder(externalDFSReferralV3(`\domain\root`, `\\files\share`)),
			}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_TREE_DISCONNECT:
			return externalWriteResponse(conn, req, &wire.TreeDisconnectResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		case wire.SMB2_LOGOFF:
			if err := externalWriteResponse(conn, req, &wire.LogoffResponse{}, erref.STATUS_SUCCESS, 0x1234, 0); err != nil {
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

	ipc, err := session.IPC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	response, err := dfs.NewClient(ipc).GetReferrals(ctx, `\\domain\root`, dfs.WithSiteName("SiteA"))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) != 1 || response.Entries[0].NetworkAddress != `\\files\share` {
		t.Fatalf("unexpected referral response: %#v", response)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	externalServerError(t, result)
}

func TestDialerDialectsAndCiphersConfiguration(t *testing.T) {
	d := &smb2.Dialer{
		SpecifiedDialects: []smb2.Dialect{
			smb2.SMB202,
			smb2.SMB210,
			smb2.SMB300,
			smb2.SMB302,
			smb2.SMB311,
		},
		Ciphers: []smb2.Cipher{
			smb2.AES128CCM,
			smb2.AES128GCM,
			smb2.AES256CCM,
			smb2.AES256GCM,
		},
	}
	if len(d.SpecifiedDialects) != 5 {
		t.Fatalf("unexpected dialect count: %d", len(d.SpecifiedDialects))
	}
	if len(d.Ciphers) != 4 {
		t.Fatalf("unexpected cipher count: %d", len(d.Ciphers))
	}
}

func TestShareContextLookupErrors(t *testing.T) {
	testFileSystemContextLookupErrors(t, "share")
}

func testFileSystemContextLookupErrors(t *testing.T, layer string) {
	t.Helper()
	for _, operation := range []string{"Glob", "MkdirAll"} {
		for _, deadline := range []bool{false, true} {
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			t.Run(operation+"/"+layer+"/"+want.Error(), func(t *testing.T) {
				endpoint := newDFSExternalEndpoint("server")
				var ctx context.Context
				var cancel context.CancelFunc
				lookups := 0
				lookupStarted := make(chan struct{})
				endpoint.create = func(name string, request wire.PacketCodec) (erref.NtStatus, uint32) {
					if name != "child" {
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
					}
					if wire.CreateRequestDecoder(request.Body()).CreateDisposition() == wire.FILE_CREATE {
						return erref.STATUS_ACCESS_DENIED, 0
					}
					lookups++
					if operation == "MkdirAll" && lookups == 1 {
						return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
					}
					// Cancel during the lookup. For MkdirAll, this is the
					// recheck after a failed mkdir, whose error must not mask cancellation.
					close(lookupStarted)
					if !deadline {
						cancel()
					}
					<-ctx.Done()
					return erref.STATUS_ACCESS_DENIED, 0
				}
				transport, result := newExternalServer(t, func(conn net.Conn, request []byte) error {
					if wire.PacketCodec(request).Command() == wire.SMB2_CANCEL {
						return nil
					}
					return endpoint.serve(conn, request)
				})
				dialer := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: transport}
				var run func(context.Context) error
				var closeSession func() error
				if layer == "client" {
					client := smbclient.New(dialer)
					run = func(ctx context.Context) error {
						if operation == "Glob" {
							_, err := client.WithContext(ctx).Glob("server/share/child/*")
							return err
						}
						return client.MkdirAll(ctx, `\\server\share\child`, 0700)
					}
					closeSession = client.Close
				} else {
					session, err := dialer.Dial(context.Background(), "server")
					if err != nil {
						t.Fatal(err)
					}
					closeSession = session.Close
					share, err := session.Mount(context.Background(), "share")
					if err != nil {
						_ = session.Close()
						t.Fatal(err)
					}
					run = func(ctx context.Context) error {
						if operation == "Glob" {
							_, err := share.WithContext(ctx).Glob("child/*")
							return err
						}
						return share.MkdirAll(ctx, "child", 0700)
					}
				}
				t.Cleanup(func() {
					if err := closeSession(); err != nil {
						t.Error(err)
					}
					externalServerError(t, result)
				})
				timeout := 5 * time.Second
				if deadline {
					timeout = 100 * time.Millisecond
				}
				ctx, cancel = context.WithTimeout(context.Background(), timeout)
				defer cancel()
				if err := run(ctx); !errors.Is(err, want) {
					t.Fatalf("%s error = %v, want %v", operation, err, want)
				}
				select {
				case <-lookupStarted:
				default:
					t.Fatal("context ended before the intended lookup")
				}
			})
		}
	}
}
