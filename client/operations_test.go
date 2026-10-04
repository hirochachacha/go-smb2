package client

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
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

func (*externalTestInitiator) GetMIC([]byte) ([]byte, error) { return nil, nil }

func (*externalTestInitiator) VerifyMIC([]byte, []byte) error { return nil }

func (i *externalTestInitiator) Complete() bool { return i.complete }

func (*externalTestInitiator) SessionKey() []byte { return nil }

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
		if isAAPLServerQuery(req) {
			if wire.PacketCodec(req).NextCommand() == 0 {
				err = externalWriteResponse(conn, req, externalCreateSuccess(), erref.STATUS_SUCCESS, 0x1234, wire.PacketCodec(req).TreeId())
			} else {
				err = dfsExternalWriteCompound(conn, req, []dfsExternalCompoundResponse{
					{packet: externalCreateSuccess(), status: erref.STATUS_SUCCESS},
					{packet: externalCloseSuccess(), status: erref.STATUS_SUCCESS},
				})
			}
			if err != nil {
				return err
			}
			continue
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

func (e externalRawEncoder) Size() int { return len(e) }

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
	if _, err := dfsClient.GetReferrals(ctx, "domain"); err == nil {
		t.Fatalf("invalid referral path error = %v, want DFS error", err)
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
				synctest.Test(t, func(t *testing.T) {
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
						client := New(dialer)
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
			})
		}
	}
}

func TestClientPreservesTransportEOF(t *testing.T) {
	for _, method := range []string{"ReadFile", "ReadDir", "FS.ReadFile", "FS.Open.ReadDir", "FS.Open.Read"} {
		for _, n := range []int{-1, 0, 1, 3} {
			if method != "FS.Open.ReadDir" && n != -1 {
				continue
			}
			t.Run(fmt.Sprintf("%s/n=%d", method, n), func(t *testing.T) {
				ep := newClientTestEndpoint("server")
				queries := 0
				contents := strings.Repeat("x", 128<<10)
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := wire.PacketCodec(request)
					require.False(t, p.IsInvalid())
					switch p.Command() {
					case wire.SMB2_CREATE:
						writeFileRecoveryResponse(t, conn, request, &wire.CreateResponse{EndofFile: int64(len(contents)), FileId: wire.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}}, 0)
					case wire.SMB2_READ:
						r := wire.ReadRequestDecoder(request[64:])
						require.False(t, r.IsInvalid())
						if method != "FS.Open.Read" && r.Offset() == 0 {
							writeFileRecoveryResponse(t, conn, request, &wire.ReadResponse{Data: []byte(contents[:64<<10])}, 0)
						} else {
							require.NoError(t, conn.Close())
						}
					case wire.SMB2_QUERY_DIRECTORY:
						queries++
						if queries == 1 {
							writeFileRecoveryResponse(t, conn, request, &wire.QueryDirectoryResponse{Output: clientTestDirectoryPage("z", "a")}, 0)
						} else {
							require.NoError(t, conn.Close())
						}
					default:
						return false
					}
					return true
				}
				dialer := newClientTestDialer(&clientTestCredentials{}, ep)
				dialer.MaxCreditBalance = 1
				dialer.DisableAAPLExtension = true
				d := New(dialer)
				defer d.Close()
				ctx := context.Background()
				name := `\\server\share\file`
				var err error
				switch method {
				case "ReadFile", "FS.ReadFile":
					var data []byte
					if method == "ReadFile" {
						data, err = d.ReadFile(ctx, name)
					} else {
						name = "server/share/file"
						data, err = d.WithContext(ctx).ReadFile(name)
					}
					require.Equal(t, contents[:64<<10], string(data))
				case "ReadDir":
					var entries []os.FileInfo
					entries, err = d.ReadDir(ctx, name)
					require.Len(t, entries, 2)
					require.Equal(t, "a", entries[0].Name())
					require.Equal(t, "z", entries[1].Name())
				case "FS.Open.ReadDir", "FS.Open.Read":
					name = "server/share/file"
					f, openErr := d.WithContext(ctx).Open(name)
					require.NoError(t, openErr)
					defer f.Close()
					if method == "FS.Open.Read" {
						count, readErr := f.Read(make([]byte, 1))
						require.Zero(t, count)
						err = readErr
					} else {
						var entries []fs.DirEntry
						entries, err = f.(fs.ReadDirFile).ReadDir(n)
						if n == 1 {
							require.NoError(t, err)
							require.Len(t, entries, 1)
							entries, err = f.(fs.ReadDirFile).ReadDir(n)
							require.NoError(t, err)
							require.Len(t, entries, 1)
							entries, err = f.(fs.ReadDirFile).ReadDir(n)
							require.Empty(t, entries)
						} else {
							require.Len(t, entries, 2)
						}
					}
				}
				var transportErr *protocol.TransportError
				require.ErrorAs(t, err, &transportErr)
				require.ErrorIs(t, transportErr, io.EOF)
				var pathErr *os.PathError
				require.ErrorAs(t, err, &pathErr)
				require.Equal(t, name, pathErr.Path)
				wantOp := "readdir"
				if method == "ReadFile" || method == "FS.ReadFile" {
					wantOp = "readfile"
				} else if method == "FS.Open.Read" {
					wantOp = "read"
				}
				require.Equal(t, wantOp, pathErr.Op)
				_, nested := pathErr.Err.(*os.PathError)
				require.False(t, nested)
				// Only a subsequent independent operation may establish a new session.
				fresh, openErr := d.Open(ctx, `\\server\share\fresh`)
				require.NoError(t, openErr)
				require.NoError(t, fresh.Close(ctx))
				ep.mu.Lock()
				dials := ep.dials
				ep.mu.Unlock()
				require.Equal(t, 2, dials)
			})
		}
	}
}

func TestClientWriteFileJoinedErrorsKeepOriginalUNC(t *testing.T) {
	for _, test := range []struct {
		name                       string
		writeFailure, closeFailure bool
	}{
		{name: "success"},
		{name: "write-only", writeFailure: true},
		{name: "close-only", closeFailure: true},
		{name: "both", writeFailure: true, closeFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			var writes, closes atomic.Int32
			ep.handleRequest = func(conn net.Conn, request []byte) bool {
				p := wire.PacketCodec(request)
				var response wire.Packet
				status := erref.STATUS_SUCCESS
				switch p.Command() {
				case wire.SMB2_WRITE:
					writes.Add(1)
					if test.writeFailure {
						status = erref.STATUS_ACCESS_DENIED
					} else {
						r := wire.WriteRequestDecoder(request[64:])
						require.False(t, r.IsInvalid())
						response = &wire.WriteResponse{Count: r.Length()}
					}
				case wire.SMB2_CLOSE:
					closes.Add(1)
					if test.closeFailure {
						status = erref.STATUS_UNSUCCESSFUL
					} else {
						response = &wire.CloseResponse{}
					}
				default:
					return false
				}
				if response == nil {
					response = &wire.ErrorResponse{CommandCode: p.Command()}
				}
				data := make([]byte, response.Size())
				response.Encode(data)
				out := wire.PacketCodec(data)
				out.SetMessageId(p.MessageId())
				out.SetSessionId(p.SessionId())
				out.SetTreeId(p.TreeId())
				out.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
				out.SetCreditResponse(1)
				out.SetStatus(uint32(status))
				require.NoError(t, writeClientTestPacket(conn, data))
				return true
			}
			dialer := newClientTestDialer(&clientTestCredentials{}, ep)
			dialer.DisableAAPLExtension = true
			dialer.IOPipelineDepth = 1
			d := New(dialer)
			defer d.Close()
			const name = `\\server\share\dir\file`
			err := d.WriteFile(context.Background(), name, make([]byte, (64<<10)+1), 0600)
			require.Positive(t, closes.Load(), "cleanup CLOSE must run even after WRITE fails")
			if !test.writeFailure && !test.closeFailure {
				require.NoError(t, err)
				require.EqualValues(t, 2, writes.Load())
				return
			}
			var outer *os.PathError
			require.ErrorAs(t, err, &outer)
			require.Equal(t, "writefile", outer.Op)
			require.Equal(t, name, outer.Path)
			joined, ok := outer.Err.(interface{ Unwrap() []error })
			require.True(t, ok, "preserve the separate operation errors in the join")
			branches := joined.Unwrap()
			wantOps := []string{}
			if test.writeFailure {
				wantOps = append(wantOps, "write")
				require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
				require.ErrorIs(t, err, os.ErrPermission)
			}
			if test.closeFailure {
				wantOps = append(wantOps, "close")
				require.ErrorIs(t, err, erref.STATUS_UNSUCCESSFUL)
			}
			require.Len(t, branches, len(wantOps))
			for i, branch := range branches {
				var pathErr *os.PathError
				require.ErrorAs(t, branch, &pathErr)
				require.Equal(t, wantOps[i], pathErr.Op)
				require.Equal(t, name, pathErr.Path)
				_, nested := pathErr.Err.(*os.PathError)
				require.False(t, nested)
			}
			require.False(t, strings.Contains(err.Error(), `write dir\file:`), "diagnostics must not expose the resolved relative name")
			require.False(t, strings.Contains(err.Error(), `close dir\file:`))
			require.Equal(t, test.writeFailure, errors.Is(err, erref.STATUS_ACCESS_DENIED))
			require.Equal(t, test.closeFailure, errors.Is(err, erref.STATUS_UNSUCCESSFUL))
		})
	}
}

func TestWriteFileJoinErrorPreservesOtherErrors(t *testing.T) {
	opaque := errors.New("opaque error")
	otherPath := &os.PathError{Op: "stat", Path: "other", Err: os.ErrNotExist}
	for _, err := range []error{nil, os.ErrInvalid, opaque, otherPath, errors.Join(opaque, otherPath)} {
		require.True(t, writeFileJoinError(err, "UNC") == err, "unrelated errors must retain identity")
	}
	write := &os.PathError{Op: "write", Path: "file", Err: context.Canceled}
	got := writeFileJoinError(errors.Join(write, otherPath, opaque), "UNC")
	require.ErrorIs(t, got, context.Canceled)
	require.ErrorIs(t, got, os.ErrNotExist)
	require.ErrorIs(t, got, opaque)
	branches := got.(interface{ Unwrap() []error }).Unwrap()
	require.Len(t, branches, 3)
	require.Equal(t, "UNC", branches[0].(*os.PathError).Path)
	require.Same(t, otherPath, branches[1])
	require.Same(t, opaque, branches[2])
	require.Equal(t, "file", write.Path, "do not modify the original operation error")
}

func TestMkdirAllRecheckAfterMkdirFailure(t *testing.T) {
	for _, layer := range []string{"Share", "Client"} {
		for _, recheck := range []string{"directory", "file", "error"} {
			t.Run(layer+"/"+recheck, func(t *testing.T) {
				ep := newDFSExternalEndpoint("server")
				var lookups, mkdirs atomic.Int32
				ep.create = func(name string, p wire.PacketCodec) (erref.NtStatus, uint32) {
					require.False(t, p.IsInvalid())
					cr := wire.CreateRequestDecoder(p.Body())
					require.False(t, cr.IsInvalid())
					if name != "child" {
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
					}
					if cr.CreateDisposition() == wire.FILE_CREATE {
						mkdirs.Add(1)
						return erref.STATUS_OBJECT_NAME_COLLISION, 0
					}
					if lookups.Add(1) == 1 {
						return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
					}
					require.NotZero(t, cr.CreateOptions()&wire.FILE_OPEN_REPARSE_POINT, "recheck must use Lstat")
					switch recheck {
					case "directory":
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
					case "file":
						return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_NORMAL
					default:
						return erref.STATUS_IO_DEVICE_ERROR, 0
					}
				}
				transport, result := newExternalServer(t, func(conn net.Conn, req []byte) error { return ep.serve(conn, req) })
				dialer := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: transport}
				ctx := context.Background()
				var name string
				var mkdirAll func(context.Context, string, os.FileMode) error
				var closeSession func() error
				if layer == "Client" {
					client := New(dialer)
					mkdirAll, closeSession, name = client.MkdirAll, client.Close, `\\server\share\child`
				} else {
					session, err := dialer.Dial(ctx, "server")
					require.NoError(t, err)
					closeSession = session.Close
					share, err := session.Mount(ctx, "share")
					require.NoError(t, err)
					mkdirAll, name = share.MkdirAll, "child"
				}
				t.Cleanup(func() {
					require.NoError(t, closeSession())
					externalServerError(t, result)
				})
				err := mkdirAll(ctx, name, 0700)
				if recheck == "directory" {
					require.NoError(t, err)
				} else {
					var pe *os.PathError
					require.ErrorAs(t, err, &pe)
					require.Equal(t, "mkdir", pe.Op)
					require.Equal(t, name, pe.Path)
					require.ErrorIs(t, err, erref.STATUS_OBJECT_NAME_COLLISION)
					require.NotErrorIs(t, err, erref.STATUS_IO_DEVICE_ERROR, "preserve the first mkdir error")
					require.IsNotType(t, &os.PathError{}, pe.Err)
				}
				require.EqualValues(t, 1, mkdirs.Load())
				require.EqualValues(t, 2, lookups.Load())
			})
		}
	}
}

func TestPathnameTruncateSetInfoFailure(t *testing.T) {
	for _, layer := range []string{"Share", "Client"} {
		t.Run(layer, func(t *testing.T) {
			ep := newDFSExternalEndpoint("server")
			var creates, closes atomic.Int32
			ep.custom = func(conn net.Conn, req []byte) error {
				p := wire.PacketCodec(req)
				require.False(t, p.IsInvalid())
				if p.Command() != wire.SMB2_CREATE || isAAPLServerQuery(req) {
					return ep.serve(conn, req)
				}
				var commands []wire.Command
				for offset := 0; ; {
					part := wire.PacketCodec(req[offset:])
					require.False(t, part.IsInvalid())
					commands = append(commands, part.Command())
					switch part.Command() {
					case wire.SMB2_CREATE:
						cr := wire.CreateRequestDecoder(part.Body())
						require.False(t, cr.IsInvalid())
						require.Equal(t, "file.txt", cr.Name())
						creates.Add(1)
					case wire.SMB2_SET_INFO:
						si := wire.SetInfoRequestDecoder(part.Body())
						require.False(t, si.IsInvalid())
						require.Equal(t, uint8(wire.SMB2_0_INFO_FILE), si.InfoType())
						require.Equal(t, uint8(wire.FileEndOfFileInformation), si.FileInfoClass())
						info := wire.FileEndOfFileInformationDecoder(si.Input())
						require.False(t, info.IsInvalid())
						require.EqualValues(t, 123, info.EndOfFile())
					case wire.SMB2_CLOSE:
						cr := wire.CloseRequestDecoder(part.Body())
						require.False(t, cr.IsInvalid())
						require.Equal(t, wire.RelatedFileId, cr.FileId().Decode())
						closes.Add(1)
					}
					if part.NextCommand() == 0 {
						break
					}
					next := int(part.NextCommand())
					require.GreaterOrEqual(t, next, 64)
					require.Less(t, next, len(req)-offset)
					offset += next
				}
				require.Equal(t, []wire.Command{wire.SMB2_CREATE, wire.SMB2_SET_INFO, wire.SMB2_CLOSE}, commands)
				return dfsExternalWriteCompound(conn, req, []dfsExternalCompoundResponse{
					{packet: externalCreateSuccess()},
					{packet: &wire.ErrorResponse{CommandCode: wire.SMB2_SET_INFO}, status: erref.STATUS_DISK_FULL},
					{packet: externalCloseSuccess()},
				})
			}
			ctx := context.Background()
			var name string
			var truncate func(context.Context, string, int64) error
			if layer == "Client" {
				client := newDFSExternalClient(t, ep)
				truncate = client.Truncate
				name = `\\server\share\file.txt`
			} else {
				dialer := &smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: &dfsExternalDialer{
					endpoints: map[string]*dfsExternalEndpoint{"server": ep},
				}}
				session, err := dialer.Dial(ctx, "server")
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, session.Close()) })
				share, err := session.Mount(ctx, "share")
				require.NoError(t, err)
				truncate = share.Truncate
				name = "file.txt"
			}
			err := truncate(ctx, name, 123)
			var pe *os.PathError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "truncate", pe.Op)
			require.Equal(t, name, pe.Path)
			require.ErrorIs(t, err, erref.STATUS_DISK_FULL)
			require.IsNotType(t, &os.PathError{}, pe.Err)
			require.EqualValues(t, 1, creates.Load())
			require.EqualValues(t, 1, closes.Load())
		})
	}
}

func TestSourceCandidateColdDFSRename(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		warmSource, warmDestination, samePrefix, distinct bool
	}{
		{name: "both-cold"}, {name: "cold-source-warm-destination", warmDestination: true},
		{name: "warm-source", warmSource: true}, {name: "same-prefix", samePrefix: true},
		{name: "distinct-shares", warmSource: true, distinct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := newDFSExternalEndpoint("namespace-server")
			ns.caps["namespace"] = true
			ns.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
				lower := strings.ToLower(path)
				if strings.Contains(lower, `\namespace\left`) || strings.Contains(lower, `\namespace\right`) {
					return erref.STATUS_PATH_NOT_COVERED, 0
				}
				return erref.STATUS_SUCCESS, 0
			}
			ns.referral = func(path string) []byte {
				lower := strings.ToLower(path)
				for _, alias := range []string{"left", "right"} {
					prefix := `\namespace-server\namespace\` + alias
					if strings.HasPrefix(lower, prefix) {
						share := "storage"
						if tc.distinct && alias == "right" {
							share = "other"
						}
						return externalDFSReferralV3(prefix, `\\target-server\`+share+`\base`)
					}
				}
				return nil
			}
			target := newDFSExternalEndpoint("target-server")
			// The seeded source exists before constructing the tested Client. This
			// fixture counts mutations only; it does not pretend to mutate contents.
			target.create = func(path string, p wire.PacketCodec) (erref.NtStatus, uint32) {
				if strings.HasSuffix(strings.ToLower(path), `\destination`) {
					return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
				}
				return erref.STATUS_SUCCESS, 0
			}
			client := newDFSExternalClient(t, ns, target)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			oldpath := `\\namespace-server\namespace\left\source`
			destAlias := "right"
			if tc.samePrefix {
				destAlias = "left"
			}
			newpath := `\\namespace-server\namespace\` + destAlias + `\destination`
			warm := func(path string) {
				f, err := client.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err = f.Close(cleanup); err != nil {
					t.Fatal(err)
				}
			}
			if tc.warmSource {
				warm(oldpath)
			}
			if tc.warmDestination {
				warm(`\\namespace-server\namespace\right\seed`)
			}
			err := client.Rename(ctx, oldpath, newpath)
			target.mu.Lock()
			mutations := target.mutations
			details := append([]dfsExternalCreate(nil), target.createDetails...)
			names := append([]string(nil), target.setInfoNames...)
			target.mu.Unlock()
			ns.mu.Lock()
			queries := append([]string(nil), ns.referralQueries...)
			nsMutations := ns.mutations
			ns.mu.Unlock()
			t.Logf("Rename=%v; namespace referrals=%q; target mutations=%d; destination names=%q", err, queries, mutations, names)
			if tc.distinct {
				if err == nil || mutations != 0 || nsMutations != 0 {
					t.Errorf("distinct shares must reject without mutations: %v,%d,%d", err, mutations, nsMutations)
				}
				return
			}
			if err != nil {
				t.Errorf("same storage/base Rename: %v", err)
			} else if mutations != 1 {
				t.Errorf("mutations=%d; want 1", mutations)
			}
			for _, detail := range details {
				if detail.access&wire.DELETE != 0 && detail.options&wire.FILE_OPEN_REPARSE_POINT == 0 {
					t.Errorf("final source link would be followed: %+v", detail)
				}
			}
			if !tc.warmSource && !tc.samePrefix {
				for _, query := range queries {
					if strings.Contains(strings.ToLower(query), `\left`) {
						t.Logf("source discovery occurred: %s", query)
					}
				}
			}
			var link *os.LinkError
			if err != nil && !errors.As(err, &link) {
				t.Error(fmt.Sprintf("missing LinkError: %v", err))
			}
		})
	}
}
