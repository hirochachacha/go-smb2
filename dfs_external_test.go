package smb2_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	smbclient "github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// dfsExternalDialer is intentionally server aware. A DFS operation can own
// sessions to several servers, so a single callback (as used by the lower API
// tests) cannot prove that a request reached the selected target.
type dfsExternalDialer struct {
	mu        sync.Mutex
	endpoints map[string]*dfsExternalEndpoint
}

type dfsExternalResult struct {
	server string
	err    error
}

func (d *dfsExternalDialer) Dial(_ context.Context, server string) (smb2.Transport, error) {
	d.mu.Lock()
	ep := d.endpoints[strings.ToLower(server)]
	d.mu.Unlock()
	if ep == nil {
		return nil, fmt.Errorf("unexpected DFS server %q", server)
	}
	ep.mu.Lock()
	ep.dials++
	if ep.dialErr != nil {
		err := ep.dialErr
		ep.mu.Unlock()
		return nil, err
	}
	ep.connections++
	ep.mu.Unlock()
	client, peer := net.Pipe()
	go func() {
		err := externalServe(peer, ep.callback)
		_ = peer.Close()
		ep.results <- dfsExternalResult{server: server, err: err}
	}()
	return smb2.NewTransport(client), nil
}

type dfsExternalEndpoint struct {
	name string

	// caps identifies DFS namespace shares. The map keys are share names.
	caps map[string]bool

	mu              sync.Mutex
	creates         []string
	createDetails   []dfsExternalCreate
	setInfoNames    []string
	requests        []string
	dials           int
	connections     int
	dialErr         error
	mutations       int
	referralQueries []string
	referral        func(string) []byte
	create          func(string, wire.PacketCodec) (erref.NtStatus, uint32)
	ioctl           func(string, wire.PacketCodec) ([]byte, uint32)
	reparse         *wire.SymbolicLinkReparseDataBuffer
	reparseByPath   func(string) *wire.SymbolicLinkReparseDataBuffer
	reparsePaths    []string
	symlink         *wire.SymbolicLinkErrorResponse
	results         chan dfsExternalResult
	custom          func(net.Conn, []byte) error
	treeEntered     chan struct{}
	treeEnterOnce   sync.Once
}

type dfsExternalCreate struct {
	path        string
	access      uint32
	disposition uint32
	options     uint32
}

func dfsExternalRootReferralV3(prefix, target string) []byte {
	packet := externalDFSReferralV3(prefix, target)
	// The V3 entry starts after the eight byte response header; ServerType is
	// the second uint16 in that entry.
	binary.LittleEndian.PutUint16(packet[12:14], 1)
	return packet
}

func dfsExternalReferralV3TTL(prefix, target string, ttl uint32) []byte {
	packet := externalDFSReferralV3(prefix, target)
	binary.LittleEndian.PutUint32(packet[16:20], ttl)
	return packet
}

func dfsExternalReferralV3Configured(prefix, target string, ttl, flags uint32, root bool) []byte {
	packet := dfsExternalReferralV3TTL(prefix, target, ttl)
	binary.LittleEndian.PutUint32(packet[4:8], flags)
	if root {
		binary.LittleEndian.PutUint16(packet[12:14], 1)
	}
	return packet
}

func dfsExternalReferralV3Multi(prefix string, targets []string, ttl uint32) []byte {
	path := append(utf16le.EncodeStringToBytes(prefix), 0, 0)
	const entrySize = 34
	entriesEnd := 8 + entrySize*len(targets)
	total := entriesEnd + len(path)*2
	for _, target := range targets {
		total += utf16le.EncodedStringLen(target) + 2
	}
	packet := make([]byte, total)
	le := binary.LittleEndian
	le.PutUint16(packet[:2], uint16(utf16le.EncodedStringLen(prefix)))
	le.PutUint16(packet[2:4], uint16(len(targets)))
	for i := range targets {
		off := 8 + i*entrySize
		le.PutUint16(packet[off:off+2], 3)
		le.PutUint16(packet[off+2:off+4], entrySize)
		le.PutUint32(packet[off+8:off+12], ttl)
		le.PutUint16(packet[off+12:off+14], uint16(entriesEnd-off))
		le.PutUint16(packet[off+14:off+16], uint16(entriesEnd-off+len(path)))
		targetOffset := entriesEnd - off + len(path)*2
		for j := range i {
			targetOffset += utf16le.EncodedStringLen(targets[j]) + 2
		}
		le.PutUint16(packet[off+16:off+18], uint16(targetOffset))
	}
	// Rebuild the shared strings in their documented order. The copy above is
	// deliberately avoided for path strings because every entry shares them.
	pos := entriesEnd
	copy(packet[pos:], path)
	pos += len(path)
	copy(packet[pos:], path)
	pos += len(path)
	for _, target := range targets {
		targetBytes := append(utf16le.EncodeStringToBytes(target), 0, 0)
		copy(packet[pos:], targetBytes)
		pos += len(targetBytes)
	}
	return packet
}

func dfsExternalReferralV1(prefix, target string) []byte {
	targetBytes := append(utf16le.EncodeStringToBytes(target), 0, 0)
	const entrySize = 8
	packet := make([]byte, 8+entrySize+len(targetBytes))
	le := binary.LittleEndian
	le.PutUint16(packet[:2], uint16(utf16le.EncodedStringLen(prefix)))
	le.PutUint16(packet[2:4], 1)
	le.PutUint16(packet[8:10], 1)
	le.PutUint16(packet[10:12], entrySize+uint16(len(targetBytes)))
	copy(packet[8+entrySize:], targetBytes)
	return packet
}

func newDFSExternalEndpoint(name string) *dfsExternalEndpoint {
	return &dfsExternalEndpoint{
		name:    name,
		caps:    make(map[string]bool),
		results: make(chan dfsExternalResult, 8),
	}
}

func (e *dfsExternalEndpoint) callback(conn net.Conn, req []byte) error {
	if e.custom != nil {
		return e.custom(conn, req)
	}
	return e.serve(conn, req)
}

func (e *dfsExternalEndpoint) serve(conn net.Conn, req []byte) error {
	p := wire.PacketCodec(req)
	e.mu.Lock()
	e.requests = append(e.requests, fmt.Sprintf("%v:%q", p.Command(), externalRequestPath(req)))
	e.mu.Unlock()
	switch p.Command() {
	case wire.SMB2_TREE_CONNECT:
		e.treeEnterOnce.Do(func() {
			if e.treeEntered != nil {
				close(e.treeEntered)
			}
		})
		sharePath := externalTreePath(req)
		share := sharePath
		if i := strings.LastIndexByte(share, '\\'); i >= 0 {
			share = share[i+1:]
		}
		e.mu.Lock()
		isDFS := e.caps[strings.ToLower(share)]
		e.mu.Unlock()
		caps := uint32(0)
		if isDFS {
			caps = wire.SMB2_SHARE_CAP_DFS
		}
		return externalWriteResponse(conn, req, &wire.TreeConnectResponse{
			ShareType: wire.SMB2_SHARE_TYPE_DISK, Capabilities: caps,
		}, erref.STATUS_SUCCESS, 0x1234, e.treeID(share))
	case wire.SMB2_CREATE:
		path := externalRequestPath(req)
		if e.create != nil {
			status, attrs := e.create(path, p)
			if status != erref.STATUS_SUCCESS {
				return e.writeCompoundFailure(conn, req, status)
			}
			return e.writeCompoundSuccess(conn, req, attrs)
		}
		return e.writeCompoundSuccess(conn, req, 0)
	case wire.SMB2_IOCTL:
		path, err := externalReferralInput(req)
		if err == nil && e.referral != nil {
			e.mu.Lock()
			e.referralQueries = append(e.referralQueries, path)
			e.mu.Unlock()
			return externalWriteResponse(conn, req, &wire.IoctlResponse{
				CtlCode: wire.FSCTL_DFS_GET_REFERRALS,
				FileId:  wire.RelatedFileId,
				Output:  externalRawEncoder(e.referral(path)),
			}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		}
		var output []byte
		if e.ioctl != nil {
			output, _ = e.ioctl(path, p)
		}
		return externalWriteResponse(conn, req, &wire.IoctlResponse{
			CtlCode: wire.FSCTL_GET_REPARSE_POINT,
			FileId:  wire.RelatedFileId,
			Output:  externalRawEncoder(output),
		}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
	case wire.SMB2_SET_INFO:
		e.mu.Lock()
		e.mutations++
		e.mu.Unlock()
		return externalWriteResponse(conn, req, &wire.SetInfoResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
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
		return fmt.Errorf("%s: unexpected SMB command %v", e.name, p.Command())
	}
}

func (e *dfsExternalEndpoint) treeID(share string) uint32 {
	if strings.EqualFold(share, "ipc$") {
		return 90
	}
	if strings.EqualFold(share, "namespace") || strings.EqualFold(share, "source") {
		return 91
	}
	return 92
}

func (e *dfsExternalEndpoint) writeCompoundSuccess(conn net.Conn, req []byte, attrs uint32) error {
	commands := dfsExternalCompoundCommands(req)
	if len(commands) == 0 {
		return errors.New("empty SMB compound")
	}
	responses := make([]dfsExternalCompoundResponse, len(commands))
	var reparsePaths []string
	requestOffset := 0
	createPath := ""
	for i, command := range commands {
		requestPart := wire.PacketCodec(req[requestOffset:])
		if command == wire.SMB2_CREATE {
			createPath = externalRequestPath(req[requestOffset:])
		}
		packet := dfsExternalResponseForCommand(command, attrs)
		if command == wire.SMB2_QUERY_INFO {
			query := wire.QueryInfoRequestDecoder(requestPart.Body())
			if !query.IsInvalid() && query.FileInfoClass() == wire.FileAttributeTagInformation {
				output := make([]byte, 8)
				binary.LittleEndian.PutUint32(output, attrs)
				if attrs&wire.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
					binary.LittleEndian.PutUint32(output[4:], wire.IO_REPARSE_TAG_SYMLINK)
				}
				packet = &wire.QueryInfoResponse{Output: externalRawEncoder(output)}
			}
		}
		reparse := e.reparse
		if e.reparseByPath != nil {
			reparse = e.reparseByPath(createPath)
		}
		if command == wire.SMB2_IOCTL && reparse != nil {
			ir := wire.IoctlRequestDecoder(requestPart.Body())
			if !ir.IsInvalid() && ir.CtlCode() == wire.FSCTL_GET_REPARSE_POINT {
				reparsePaths = append(reparsePaths, createPath)
				buf := make([]byte, reparse.Size())
				reparse.Encode(buf)
				packet = &wire.IoctlResponse{CtlCode: wire.FSCTL_GET_REPARSE_POINT, FileId: wire.RelatedFileId, Output: externalRawEncoder(buf)}
			}
		}
		responses[i] = dfsExternalCompoundResponse{packet: packet, status: erref.STATUS_SUCCESS}
		if next := requestPart.NextCommand(); next != 0 {
			requestOffset += int(next)
		}
	}
	e.mu.Lock()
	e.reparsePaths = append(e.reparsePaths, reparsePaths...)
	requestOffset = 0
	for _, command := range commands {
		if command == wire.SMB2_CREATE {
			part := wire.PacketCodec(req[requestOffset:])
			path := externalRequestPath(req[requestOffset:])
			e.creates = append(e.creates, path)
			cr := wire.CreateRequestDecoder(part.Body())
			if !cr.IsInvalid() {
				e.createDetails = append(e.createDetails, dfsExternalCreate{
					path: path, access: cr.DesiredAccess(),
					disposition: cr.CreateDisposition(), options: cr.CreateOptions(),
				})
			}
		}
		if command == wire.SMB2_SET_INFO {
			e.mutations++
			part := wire.PacketCodec(req[requestOffset:])
			setInfo := wire.SetInfoRequestDecoder(part.Body())
			if !setInfo.IsInvalid() && setInfo.InfoType() == wire.SMB2_0_INFO_FILE && setInfo.FileInfoClass() == wire.FileRenameInformation {
				off := requestOffset + int(setInfo.BufferOffset())
				length := int(setInfo.BufferLength())
				if off >= 64 && length >= 20 && off <= len(req) && length <= len(req)-off {
					nameLength := int(binary.LittleEndian.Uint32(req[off+16 : off+20]))
					if nameLength >= 0 && nameLength <= length-20 && nameLength&1 == 0 {
						e.setInfoNames = append(e.setInfoNames, utf16le.DecodeToString(req[off+20:off+20+nameLength]))
					}
				}
			}
		}
		part := wire.PacketCodec(req[requestOffset:])
		if command == wire.SMB2_IOCTL {
			ir := wire.IoctlRequestDecoder(part.Body())
			if !ir.IsInvalid() && ir.CtlCode() == wire.FSCTL_SET_REPARSE_POINT {
				e.mutations++
			}
		}
		if next := part.NextCommand(); next != 0 {
			requestOffset += int(next)
		}
	}
	e.mu.Unlock()
	if len(commands) == 1 {
		return externalWriteResponse(conn, req, responses[0].packet, responses[0].status, 0x1234, wire.PacketCodec(req).TreeId())
	}
	return dfsExternalWriteCompound(conn, req, responses)
}

func (e *dfsExternalEndpoint) writeCompoundFailure(conn net.Conn, req []byte, status erref.NtStatus) error {
	commands := dfsExternalCompoundCommands(req)
	if len(commands) == 0 {
		return errors.New("empty SMB compound")
	}
	e.mu.Lock()
	if commands[0] == wire.SMB2_CREATE {
		e.creates = append(e.creates, externalRequestPath(req))
	}
	e.mu.Unlock()
	responses := make([]dfsExternalCompoundResponse, len(commands))
	for i, command := range commands {
		code := status
		if i > 0 {
			code = erref.STATUS_INVALID_HANDLE
		}
		packet := wire.Packet(&wire.ErrorResponse{CommandCode: command})
		if i == 0 && command == wire.SMB2_CREATE && status == erref.STATUS_STOPPED_ON_SYMLINK && e.symlink != nil {
			packet = &wire.ErrorResponse{CommandCode: command, ErrorData: e.symlink}
		}
		responses[i] = dfsExternalCompoundResponse{packet: packet, status: code}
	}
	if len(commands) == 1 {
		return externalWriteResponse(conn, req, responses[0].packet, status, 0x1234, wire.PacketCodec(req).TreeId())
	}
	return dfsExternalWriteCompound(conn, req, responses)
}

type dfsExternalCompoundResponse struct {
	packet wire.Packet
	status erref.NtStatus
}

func dfsExternalCompoundCommands(req []byte) []wire.Command {
	var commands []wire.Command
	for offset := 0; offset >= 0 && offset < len(req); {
		p := wire.PacketCodec(req[offset:])
		commands = append(commands, p.Command())
		next := p.NextCommand()
		if next == 0 {
			break
		}
		if next < 64 || int(next) > len(req)-offset {
			return nil
		}
		offset += int(next)
	}
	return commands
}

func dfsExternalResponseForCommand(command wire.Command, attrs uint32) wire.Packet {
	switch command {
	case wire.SMB2_CREATE:
		response := externalCreateSuccess()
		response.FileAttributes = attrs
		return response
	case wire.SMB2_CLOSE:
		return externalCloseSuccess()
	case wire.SMB2_IOCTL:
		return &wire.IoctlResponse{CtlCode: wire.FSCTL_SET_REPARSE_POINT, FileId: wire.RelatedFileId}
	case wire.SMB2_SET_INFO:
		return &wire.SetInfoResponse{}
	default:
		return &wire.ErrorResponse{CommandCode: command}
	}
}

func dfsExternalWriteCompound(conn net.Conn, request []byte, responses []dfsExternalCompoundResponse) error {
	var out []byte
	requestOffset := 0
	for i, response := range responses {
		if requestOffset < 0 || requestOffset >= len(request) {
			return errors.New("compound request ended early")
		}
		req := wire.PacketCodec(request[requestOffset:])
		span := wire.Roundup(response.packet.Size(), 8)
		buf := make([]byte, span)
		response.packet.Encode(buf)
		p := wire.PacketCodec(buf)
		p.SetMessageId(req.MessageId())
		p.SetSessionId(req.SessionId())
		p.SetTreeId(req.TreeId())
		p.SetStatus(uint32(response.status))
		p.SetCreditResponse(req.CreditRequest())
		flags := uint32(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		if i > 0 {
			flags |= wire.SMB2_FLAGS_RELATED_OPERATIONS
		}
		p.SetFlags(flags)
		if i < len(responses)-1 {
			p.SetNextCommand(uint32(span))
		}
		out = append(out, buf...)
		next := req.NextCommand()
		if next == 0 {
			requestOffset = len(request)
		} else {
			requestOffset += int(next)
		}
	}
	return externalWritePacket(conn, out)
}

func newDFSExternalClient(t *testing.T, endpoints ...*dfsExternalEndpoint) *smbclient.Client {
	t.Helper()
	dialer := &dfsExternalDialer{endpoints: make(map[string]*dfsExternalEndpoint, len(endpoints))}
	for _, endpoint := range endpoints {
		dialer.endpoints[strings.ToLower(endpoint.name)] = endpoint
	}
	client := smbclient.New(&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer})
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("DFS client close: %v", err)
		}
		for _, endpoint := range endpoints {
			endpoint.mu.Lock()
			connections := endpoint.connections
			endpoint.mu.Unlock()
			for range connections {
				select {
				case result := <-endpoint.results:
					if result.err != nil && !errors.Is(result.err, io.EOF) && !errors.Is(result.err, net.ErrClosed) {
						t.Errorf("%s fake server: %v", result.server, result.err)
					}
				case <-time.After(time.Second):
					t.Errorf("%s fake server did not finish", endpoint.name)
				}
			}
		}
	})
	return client
}

func TestExternalDFSOpenBindsTargetFileAndOriginalUNC(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\link\file`) {
			return nil
		}
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\base`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_REPARSE_POINT
	}
	client := newDFSExternalClient(t, namespace, target)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(f).(*smbclient.File); !ok {
		t.Fatalf("Open returned %T, want *smbclient.File", f)
	}
	if f.Name() != original {
		t.Fatalf("File.Name() = %q, want original UNC %q", f.Name(), original)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	gotCreates := append([]string(nil), target.creates...)
	targetRequests := append([]string(nil), target.requests...)
	target.mu.Unlock()
	if len(gotCreates) != 1 || !strings.EqualFold(gotCreates[0], `base\file`) {
		t.Fatalf("target CREATE paths = %#v, requests=%#v, want [base\\file]", gotCreates, targetRequests)
	}
}

func TestExternalDFSRemoveLinkDoesNotMutateReferralTarget(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasSuffix(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_REPARSE_POINT
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := `\\namespace-server\namespace\link`
	for range 2 {
		if err := client.RemoveAll(ctx, path); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("RemoveAll DFS link = %v, want os.ErrPermission", err)
		}
	}
	if err := client.Remove(ctx, path); !errors.Is(err, os.ErrPermission) {
		namespace.mu.Lock()
		requests := append([]string(nil), namespace.requests...)
		namespace.mu.Unlock()
		t.Fatalf("uncached Remove error = %v, requests=%#v, want os.ErrPermission", err, requests)
	}
	if err := client.Remove(ctx, path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cached Remove error = %v, want os.ErrPermission", err)
	}
	if _, err := client.Readlink(ctx, path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Readlink DFS link error = %v, want os.ErrPermission", err)
	}
	if _, err := client.Lstat(ctx, path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Lstat DFS link error = %v, want os.ErrPermission", err)
	}
	if _, err := client.OpenFile(ctx, path, os.O_RDONLY|os.O_EXCL, 0); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("OpenFile O_EXCL DFS link error = %v, want os.ErrPermission", err)
	}
	target.mu.Lock()
	creates, mutations := len(target.creates), target.mutations
	details := append([]dfsExternalCreate(nil), target.createDetails...)
	target.mu.Unlock()
	for _, detail := range details {
		if detail.access&(wire.DELETE|wire.GENERIC_WRITE) != 0 || detail.disposition != wire.FILE_OPEN {
			t.Fatalf("referral target destructive CREATE: %#v (all creates=%d mutations=%d)", detail, creates, mutations)
		}
	}
	if creates != 0 {
		t.Fatalf("referral target creates = %d, want 0", creates)
	}
	if mutations != 0 {
		t.Fatalf("referral target mutation requests = %d (read-only creates=%d)", mutations, creates)
	}
	namespace.mu.Lock()
	queries := append([]string(nil), namespace.referralQueries...)
	namespace.mu.Unlock()
	if len(queries) != 1 {
		t.Fatalf("cached referral queries = %#v, want one query", queries)
	}
}

func TestExternalDFSRemoveChildAndFinalSymlinkAreExplicitObjects(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\base`)
	}
	target := newDFSExternalEndpoint("target-server")
	// The object beneath the DFS link is an explicitly named ordinary child.
	// Its removal must reach the selected storage share.
	target.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, 0
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Remove(ctx, `\\namespace-server\namespace\link\child`); err != nil {
		t.Fatalf("Remove explicit child: %v", err)
	}
	if err := client.RemoveAll(ctx, `\\namespace-server\namespace\link\child`); err != nil {
		t.Fatalf("RemoveAll explicit child: %v", err)
	}
	createsBefore, mutationsBefore := func() (int, int) {
		target.mu.Lock()
		defer target.mu.Unlock()
		return len(target.creates), target.mutations
	}()
	if createsBefore == 0 {
		t.Fatal("child removal never reached target share")
	}
	if mutationsBefore == 0 {
		t.Fatal("child removal did not send a target mutation")
	}

	// Remove follows intermediate symbolic links (os.Remove semantics) and
	// deletes the object it reaches without a separate reparse validation.
	finalLink := newDFSExternalEndpoint("same-final-server")
	finalLink.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\child`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-dir`,
		PrintName:          `real-dir`,
	}
	finalLink.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		switch strings.ToLower(path) {
		case `link\child`:
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		case `real-dir\child`:
			return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_REPARSE_POINT
		default:
			return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
		}
	}
	unopened := newDFSExternalEndpoint("unopened-server")
	finalClient := newDFSExternalClient(t, finalLink, unopened)
	if err := finalClient.Remove(ctx, `\\same-final-server\data\link\child`); err != nil {
		t.Fatalf("Remove final symlink through same-share intermediate symlink: %v", err)
	}
	finalLink.mu.Lock()
	finalDetails := append([]dfsExternalCreate(nil), finalLink.createDetails...)
	finalMutations := finalLink.mutations
	finalLink.mu.Unlock()
	var finalDestructive []dfsExternalCreate
	for _, detail := range finalDetails {
		if detail.access&wire.DELETE != 0 {
			finalDestructive = append(finalDestructive, detail)
		}
	}
	if len(finalDestructive) != 1 || !strings.EqualFold(finalDestructive[0].path, `real-dir\child`) {
		t.Fatalf("final symlink destructive CREATEs = %#v, want canonical real-dir\\child", finalDestructive)
	}
	if finalMutations != 1 {
		t.Fatalf("final symlink mutations = %d, want one SET_INFO", finalMutations)
	}
	unopened.mu.Lock()
	unopenedDials := unopened.dials
	unopened.mu.Unlock()
	if unopenedDials != 0 {
		t.Fatalf("final symlink target was contacted: dials=%d", unopenedDials)
	}

	// A final ordinary symlink is removed by its reparse point. Its target is
	// never opened, and the operation is allowed because the caller named the
	// link itself.
	source := newDFSExternalEndpoint("source-server")
	source.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_REPARSE_POINT
	}
	source.reparse = &wire.SymbolicLinkReparseDataBuffer{
		Flags:          0,
		SubstituteName: `\??\UNC\unopened-server\other\target`,
		PrintName:      `\\unopened-server\other\target`,
	}
	source.ioctl = func(_ string, p wire.PacketCodec) ([]byte, uint32) {
		if p.Command() != wire.SMB2_IOCTL || source.reparse == nil {
			return nil, 0
		}
		buf := make([]byte, source.reparse.Size())
		source.reparse.Encode(buf)
		return buf, 0
	}
	ordinary := newDFSExternalClient(t, source)
	if _, err := ordinary.Readlink(ctx, `\\source-server\source\link`); err != nil {
		t.Fatalf("Readlink final symlink: %v", err)
	}
	if err := ordinary.Remove(ctx, `\\source-server\source\link`); err != nil {
		t.Fatalf("Remove final symlink: %v", err)
	}
}

func TestExternalDFSCrossShareRenameDoesNotMutateEitherTarget(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\left`) || strings.Contains(strings.ToLower(path), `\namespace\right`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if strings.Contains(strings.ToLower(path), `\left`) {
			return externalDFSReferralV3(`\namespace-server\namespace\left`, `\\left-server\storage\base`)
		}
		return externalDFSReferralV3(`\namespace-server\namespace\right`, `\\right-server\storage\base`)
	}
	left := newDFSExternalEndpoint("left-server")
	right := newDFSExternalEndpoint("right-server")
	client := newDFSExternalClient(t, namespace, left, right)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Rename(ctx,
		`\\namespace-server\namespace\left\old`,
		`\\namespace-server\namespace\right\new`,
	)
	if err == nil || !strings.Contains(err.Error(), "cross-share") {
		t.Fatalf("Rename error = %v, want cross-share rename error", err)
	}
	for _, endpoint := range []*dfsExternalEndpoint{left, right} {
		endpoint.mu.Lock()
		creates, mutations := len(endpoint.creates), endpoint.mutations
		details := append([]dfsExternalCreate(nil), endpoint.createDetails...)
		endpoint.mu.Unlock()
		for _, detail := range details {
			if detail.access&(wire.DELETE|wire.GENERIC_WRITE) != 0 || detail.disposition != wire.FILE_OPEN {
				t.Fatalf("target %s destructive CREATE: %#v", endpoint.name, detail)
			}
		}
		if mutations != 0 {
			t.Fatalf("target %s mutation requests = %d (read-only creates=%d)", endpoint.name, mutations, creates)
		}
	}
}

func TestExternalDFSSymlinkCreationAndReadlinkDoNotConnectTarget(t *testing.T) {
	t.Parallel()
	source := newDFSExternalEndpoint("source-server")
	source.reparse = &wire.SymbolicLinkReparseDataBuffer{
		SubstituteName: `\??\UNC\target-server\storage\missing`,
		PrintName:      `\\target-server\storage\missing`,
	}
	source.ioctl = func(_ string, _ wire.PacketCodec) ([]byte, uint32) {
		buf := make([]byte, source.reparse.Size())
		source.reparse.Encode(buf)
		return buf, 0
	}
	target := newDFSExternalEndpoint("target-server")
	client := newDFSExternalClient(t, source, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	link := `\\source-server\source\link`
	if err := client.Symlink(ctx, `\\target-server\storage\missing`, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	got, err := client.Readlink(ctx, link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != `\\target-server\storage\missing` {
		t.Fatalf("Readlink = %q", got)
	}
	target.mu.Lock()
	targetCreates := len(target.creates)
	targetDials := target.dials
	target.mu.Unlock()
	if targetCreates != 0 || targetDials != 0 {
		t.Fatalf("symlink target was contacted: dials=%d creates=%d", targetDials, targetCreates)
	}
}

func TestExternalDFSReferralSymlinkReferralChainBindsFinalFile(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return nil
		}
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\link`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(0),
		SubstituteName:     `\??\UNC\next-server\namespace\hop`,
		PrintName:          `\\next-server\namespace\hop`,
	}
	target.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasPrefix(strings.ToLower(path), `link`) {
			target.symlink.UnparsedPathLength = uint16(utf16le.EncodedStringLen(`\file`))
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	next := newDFSExternalEndpoint("next-server")
	next.caps["namespace"] = true
	next.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\hop`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	next.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\hop`) {
			return nil
		}
		return externalDFSReferralV3(`\next-server\namespace\hop`, `\\final-server\storage\base`)
	}
	final := newDFSExternalEndpoint("final-server")
	client := newDFSExternalClient(t, namespace, target, next, final)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != original {
		t.Fatalf("final File.Name() = %q, want %q", f.Name(), original)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []*dfsExternalEndpoint{target, next, final} {
		endpoint.mu.Lock()
		dials := endpoint.dials
		endpoint.mu.Unlock()
		if dials == 0 {
			t.Fatalf("DFS/symlink/DFS chain never contacted %s", endpoint.name)
		}
	}
}

func TestExternalDFSRootReferralThenLinkReferralReachesFinalShare(t *testing.T) {
	t.Parallel()
	root := newDFSExternalEndpoint("root-server")
	root.caps["root"] = true
	root.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	var queryCount int
	root.referral = func(path string) []byte {
		queryCount++
		switch queryCount {
		case 1:
			if !strings.Contains(strings.ToLower(path), `\root-server\root\link`) {
				return nil
			}
			return dfsExternalReferralV3Configured(`\root-server\root`, `\\root-server\root`, 300, 0, true)
		case 2:
			if !strings.Contains(strings.ToLower(path), `\root-server\root\link`) {
				return nil
			}
			return externalDFSReferralV3(`\root-server\root\link`, `\\final-server\storage\base`)
		default:
			return nil
		}
	}
	final := newDFSExternalEndpoint("final-server")
	client := newDFSExternalClient(t, root, final)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\root-server\root\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != original {
		t.Fatalf("root/link File.Name() = %q, want %q", f.Name(), original)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if queryCount != 2 {
		t.Fatalf("root then link referral queries = %d, want 2", queryCount)
	}
	final.mu.Lock()
	dials, creates := final.dials, len(final.creates)
	final.mu.Unlock()
	if dials != 1 || creates != 1 {
		t.Fatalf("final share activity = dials %d creates %d, want one each", dials, creates)
	}
}

func TestExternalDFSCandidateFailureFallsBackAndReusesSelectedTarget(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	namespace.referral = func(string) []byte {
		return dfsExternalReferralV3Multi(`\namespace-server\namespace\link`, []string{
			`\\unavailable-server\storage\base`, `\\selected-server\storage\base`,
		}, 300)
	}
	unavailable := newDFSExternalEndpoint("unavailable-server")
	unavailable.dialErr = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("endpoint unavailable")}
	selected := newDFSExternalEndpoint("selected-server")
	client := newDFSExternalClient(t, namespace, unavailable, selected)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := `\\namespace-server\namespace\link\file`
	for range 2 {
		f, err := client.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	namespace.mu.Lock()
	queries := len(namespace.referralQueries)
	namespace.mu.Unlock()
	unavailable.mu.Lock()
	badDials := unavailable.dials
	unavailable.mu.Unlock()
	selected.mu.Lock()
	goodDials, goodCreates := selected.dials, len(selected.creates)
	selected.mu.Unlock()
	if queries != 1 || badDials != 1 || goodDials != 1 || goodCreates != 2 {
		t.Fatalf("candidate reuse = referral queries %d, unavailable dials %d, selected dials %d creates %d; want 1,1,1,2", queries, badDials, goodDials, goodCreates)
	}
}

func TestExternalDFSReferralTTLExpiryAndV1NonCaching(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		wait        time.Duration
		referral    func(int) []byte
		wantQueries int
		opens       int
	}{
		{
			name: "expired TTL refreshes",
			wait: 1100 * time.Millisecond,
			referral: func(query int) []byte {
				ttl := uint32(1)
				if query > 1 {
					ttl = 300
				}
				return dfsExternalReferralV3TTL(`\namespace-server\namespace\link`, `\\selected-server\storage\base`, ttl)
			},
			wantQueries: 2,
		},
		{
			name:  "expired V3 refresh becomes uncached V1",
			wait:  1100 * time.Millisecond,
			opens: 3,
			referral: func(query int) []byte {
				if query == 1 {
					return dfsExternalReferralV3TTL(`\namespace-server\namespace\link`, `\\selected-server\storage\base`, 1)
				}
				return dfsExternalReferralV1(`\namespace-server\namespace\link`, `\\selected-server\storage\base`)
			},
			wantQueries: 3,
		},
		{
			name: "V1 is never cached",
			referral: func(int) []byte {
				return dfsExternalReferralV1(`\namespace-server\namespace\link`, `\\selected-server\storage\base`)
			},
			wantQueries: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			namespace := newDFSExternalEndpoint("namespace-server")
			namespace.caps["namespace"] = true
			namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
				return erref.STATUS_PATH_NOT_COVERED, 0
			}
			var queries int
			namespace.referral = func(string) []byte {
				queries++
				return test.referral(queries)
			}
			selected := newDFSExternalEndpoint("selected-server")
			client := newDFSExternalClient(t, namespace, selected)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := `\\namespace-server\namespace\link\file`
			for i := 0; i < max(2, test.opens); i++ {
				f, err := client.Open(ctx, path)
				if err != nil {
					t.Fatalf("open in %s case: %v", test.name, err)
				}
				if err := f.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if i == 0 && test.wait > 0 {
					time.Sleep(test.wait)
				}
			}
			selected.mu.Lock()
			selectedDials := selected.dials
			selected.mu.Unlock()
			if queries != test.wantQueries || selectedDials != 1 {
				t.Fatalf("referral cache behavior = queries %d selected dials %d, want %d and 1", queries, selectedDials, test.wantQueries)
			}
		})
	}
}

func TestExternalDFSInterlinkReferralChainReachesStorage(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	namespace.referral = func(string) []byte {
		return dfsExternalReferralV3Configured(`\namespace-server\namespace\link`, `\\mid-server\namespace\hop`, 300, 1, false)
	}
	mid := newDFSExternalEndpoint("mid-server")
	mid.caps["namespace"] = true
	mid.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\mid-server\namespace\hop`) {
			return nil
		}
		return dfsExternalReferralV3Configured(`\mid-server\namespace\hop`, `\\hop-server\namespace\exit`, 300, 1, false)
	}
	hop := newDFSExternalEndpoint("hop-server")
	hop.caps["namespace"] = true
	hop.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\hop-server\namespace\exit`) {
			return nil
		}
		return dfsExternalReferralV3Configured(`\hop-server\namespace\exit`, `\\final-server\storage\base`, 300, 2, false)
	}
	final := newDFSExternalEndpoint("final-server")
	client := newDFSExternalClient(t, namespace, mid, hop, final)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != original {
		t.Fatalf("interlink File.Name() = %q, want %q", f.Name(), original)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	final.mu.Lock()
	creates := append([]string(nil), final.creates...)
	final.mu.Unlock()
	if len(creates) != 1 || creates[0] != `base\file` {
		t.Fatalf("final storage CREATE paths = %q, want [base\\file]", creates)
	}
	for _, endpoint := range []*dfsExternalEndpoint{mid, hop} {
		endpoint.mu.Lock()
		queries := append([]string(nil), endpoint.referralQueries...)
		endpoint.mu.Unlock()
		if len(queries) != 1 {
			t.Fatalf("%s interlink queries = %#v, want one", endpoint.name, queries)
		}
	}
}

func TestExternalDFSInterlinkReferralCycleTerminates(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	namespace.referral = func(string) []byte {
		return dfsExternalReferralV3Configured(`\namespace-server\namespace\link`, `\\mid-server\namespace\hop`, 300, 1, false)
	}
	mid := newDFSExternalEndpoint("mid-server")
	mid.caps["namespace"] = true
	mid.referral = func(string) []byte {
		return dfsExternalReferralV3Configured(`\mid-server\namespace\hop`, `\\namespace-server\namespace\link`, 300, 1, false)
	}
	client := newDFSExternalClient(t, namespace, mid)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Open(ctx, `\\namespace-server\namespace\link\file`)
	if err == nil || !strings.Contains(err.Error(), "referral traversal limit exceeded") {
		t.Fatalf("interlink cycle error = %v", err)
	}
	namespace.mu.Lock()
	nsQueries := len(namespace.referralQueries)
	namespace.mu.Unlock()
	mid.mu.Lock()
	midQueries := len(mid.referralQueries)
	mid.mu.Unlock()
	if nsQueries == 0 || midQueries == 0 {
		t.Fatalf("interlink cycle did not traverse both namespaces: namespace=%d mid=%d", nsQueries, midQueries)
	}
}

func TestExternalDFSInitialReferralSameShareSymlinkUsesChangedPath(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return nil
		}
		return dfsExternalRootReferralV3(`\namespace-server\namespace\link`, `\\target-server\namespace\start`)
	}

	target := newDFSExternalEndpoint("target-server")
	target.caps["namespace"] = true
	target.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `next`,
		PrintName:          `next`,
	}
	var targetCreates int
	target.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		targetCreates++
		if targetCreates == 1 {
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		if strings.Contains(strings.ToLower(path), `\namespace\next`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	target.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\target-server\namespace\next`) || strings.Contains(strings.ToLower(path), `\target-server\namespace\start`) {
			return nil
		}
		return dfsExternalRootReferralV3(`\target-server\namespace\next`, `\\final-server\storage\base`)
	}
	final := newDFSExternalEndpoint("final-server")
	client := newDFSExternalClient(t, namespace, target, final)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != original {
		t.Fatalf("final File.Name() = %q, want %q", f.Name(), original)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	queries := append([]string(nil), target.referralQueries...)
	target.mu.Unlock()
	if len(queries) != 1 || !strings.Contains(strings.ToLower(queries[0]), `\target-server\namespace\next`) || strings.Contains(strings.ToLower(queries[0]), `\target-server\namespace\start`) {
		t.Fatalf("same share changed-path referral queries = %#v", queries)
	}
}

func TestExternalDFSFinalLinkPathNotCoveredDoesNotQueryAnotherReferral(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return nil
		}
		// The default V3 ServerType is LINK. This is a final link mapping,
		// so PATH_NOT_COVERED from its target must fail the original open.
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\final`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `final`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Open(ctx, `\\namespace-server\namespace\link\file`)
	if err == nil || !errors.Is(err, erref.STATUS_PATH_NOT_COVERED) {
		t.Fatalf("unchanged final-link PATH_NOT_COVERED error = %v", err)
	}
	target.mu.Lock()
	queries := append([]string(nil), target.referralQueries...)
	target.mu.Unlock()
	if len(queries) != 0 {
		t.Fatalf("final-link target triggered referral queries: %#v", queries)
	}
}

func TestExternalDFSAlternatingReferralAndSymlinkCycleIsBounded(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\namespace\link`) {
			return nil
		}
		return dfsExternalRootReferralV3(`\namespace-server\namespace\link`, `\\a-server\namespace\hop1`)
	}

	a := newDFSExternalEndpoint("a-server")
	a.caps["namespace"] = true
	a.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `hop2`,
		PrintName:          `hop2`,
	}
	a.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\hop1`) {
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		if strings.Contains(strings.ToLower(path), `\namespace\hop2`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	a.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\a-server\namespace\hop2`) {
			return nil
		}
		return dfsExternalRootReferralV3(`\a-server\namespace\hop2`, `\\b-server\namespace\hop3`)
	}

	b := newDFSExternalEndpoint("b-server")
	b.caps["namespace"] = true
	b.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `hop4`,
		PrintName:          `hop4`,
	}
	b.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.Contains(strings.ToLower(path), `\namespace\hop3`) {
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		if strings.Contains(strings.ToLower(path), `\namespace\hop4`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	b.referral = func(path string) []byte {
		if !strings.Contains(strings.ToLower(path), `\b-server\namespace\hop4`) {
			return nil
		}
		return dfsExternalRootReferralV3(`\b-server\namespace\hop4`, `\\a-server\namespace\hop1`)
	}

	client := newDFSExternalClient(t, namespace, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Open(ctx, `\\namespace-server\namespace\link\file`)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("alternating referral/symlink cycle error = %v", err)
	}
	a.mu.Lock()
	aQueries := len(a.referralQueries)
	a.mu.Unlock()
	b.mu.Lock()
	bQueries := len(b.referralQueries)
	b.mu.Unlock()
	if aQueries == 0 || bQueries == 0 {
		t.Fatalf("cycle did not alternate referral queries: a=%d b=%d", aQueries, bQueries)
	}
}

func TestExternalDFSSameShareSymlinkUsesUpdatedReferralPath(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	var creates int
	namespace.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `next`,
		PrintName:          `next`,
	}
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		creates++
		if creates == 1 {
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		if strings.Contains(strings.ToLower(path), `\namespace\next`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		if strings.Contains(strings.ToLower(path), `\namespace\link`) || !strings.Contains(strings.ToLower(path), `\namespace\next`) {
			return nil
		}
		return externalDFSReferralV3(`\namespace-server\namespace\next`, `\\target-server\storage\base`)
	}
	target := newDFSExternalEndpoint("target-server")
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	namespace.mu.Lock()
	queries := append([]string(nil), namespace.referralQueries...)
	namespace.mu.Unlock()
	if len(queries) != 1 || !strings.Contains(strings.ToLower(queries[0]), `\namespace\next`) || strings.Contains(strings.ToLower(queries[0]), `\namespace\link`) {
		t.Fatalf("updated referral queries = %#v", queries)
	}
}

func TestExternalDFSSameShareIntermediateSymlinkRemoveUsesResolvedChild(t *testing.T) {
	t.Parallel()
	server := newDFSExternalEndpoint("same-server")
	server.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\child`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-dir`,
		PrintName:          `real-dir`,
	}
	server.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		switch strings.ToLower(path) {
		case `link\child`:
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		case `real-dir\child`:
			return erref.STATUS_SUCCESS, 0
		default:
			return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
		}
	}
	client := newDFSExternalClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	path := `\\same-server\data\link\child`
	if err := client.Remove(ctx, path); err != nil {
		t.Fatalf("Remove through same-share intermediate symlink: %v", err)
	}

	server.mu.Lock()
	details := append([]dfsExternalCreate(nil), server.createDetails...)
	mutations := server.mutations
	server.mu.Unlock()
	var destructive []dfsExternalCreate
	for _, detail := range details {
		if detail.access&wire.DELETE != 0 {
			destructive = append(destructive, detail)
		}
	}
	if len(destructive) != 1 || !strings.EqualFold(destructive[0].path, `real-dir\child`) {
		t.Fatalf("Remove destructive CREATEs = %#v, want canonical real-dir\\child", destructive)
	}
	if mutations != 1 {
		t.Fatalf("Remove mutations = %d, want one SET_INFO", mutations)
	}
}

func TestExternalDFSSameShareIntermediateSymlinkRename(t *testing.T) {
	t.Parallel()
	server := newDFSExternalEndpoint("same-server")
	server.symlink = &wire.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\source`)),
		Flags:              wire.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-old`,
		PrintName:          `real-old`,
	}
	server.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		switch strings.ToLower(path) {
		case `old-link\source`:
			server.symlink.UnparsedPathLength = uint16(utf16le.EncodedStringLen(`\source`))
			server.symlink.SubstituteName = `real-old`
			server.symlink.PrintName = `real-old`
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		case `new-link\destination`:
			server.symlink.UnparsedPathLength = uint16(utf16le.EncodedStringLen(`\destination`))
			server.symlink.SubstituteName = `real-new`
			server.symlink.PrintName = `real-new`
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		case `real-old\source`:
			return erref.STATUS_SUCCESS, 0
		case `real-new\destination`:
			return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
		default:
			return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
		}
	}
	client := newDFSExternalClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldpath := `\\same-server\data\old-link\source`
	newpath := `\\same-server\data\new-link\destination`
	if err := client.Rename(ctx, oldpath, newpath); err != nil {
		t.Fatalf("Rename through same-share intermediate symlinks: %v", err)
	}

	server.mu.Lock()
	details := append([]dfsExternalCreate(nil), server.createDetails...)
	names := append([]string(nil), server.setInfoNames...)
	mutations := server.mutations
	server.mu.Unlock()
	var destructive []dfsExternalCreate
	for _, detail := range details {
		if detail.access&wire.DELETE != 0 {
			destructive = append(destructive, detail)
		}
	}
	if len(destructive) != 1 || !strings.EqualFold(destructive[0].path, `real-old\source`) {
		t.Fatalf("Rename destructive CREATEs = %#v, want canonical real-old\\source", destructive)
	}
	if len(names) != 1 || !strings.EqualFold(names[0], `new-link\destination`) {
		t.Fatalf("Rename SET_INFO destination names = %#v, want new-link\\destination (resolved by the server)", names)
	}
	if mutations != 1 {
		t.Fatalf("Rename mutations = %d, want one SET_INFO", mutations)
	}
}

func TestExternalDFSNamespaceReparseMetadataRemovalSucceeds(t *testing.T) {
	t.Parallel()
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_REPARSE_POINT
	}
	client := newDFSExternalClient(t, namespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Remove(ctx, `\\namespace-server\namespace\link`); err != nil {
		t.Fatalf("Remove namespace reparse object: %v", err)
	}
	namespace.mu.Lock()
	mutations := namespace.mutations
	namespace.mu.Unlock()
	if mutations != 1 {
		t.Fatalf("namespace reparse removal sent %d mutation requests, want 1", mutations)
	}
}

func TestExternalDFSCanceledCoalescedWaiterDoesNotCancelOther(t *testing.T) {
	t.Parallel()
	endpoint := newDFSExternalEndpoint("source-server")
	var release sync.Once
	gate := make(chan struct{})
	endpoint.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.EqualFold(path, `file`) {
			release.Do(func() { close(gate) })
		}
		return erref.STATUS_SUCCESS, 0
	}

	// The callback waits before its first TREE_CONNECT. Both callers therefore
	// wait on the same upper-layer session/share creation.
	blocked := newDFSExternalEndpoint("blocked-server")
	blocked.caps["source"] = false
	blocked.treeEntered = make(chan struct{})
	allowTree := make(chan struct{})
	blocked.custom = func(conn net.Conn, req []byte) error {
		if wire.PacketCodec(req).Command() == wire.SMB2_TREE_CONNECT {
			blocked.treeEnterOnce.Do(func() {
				if blocked.treeEntered != nil {
					close(blocked.treeEntered)
				}
			})
			select {
			case <-allowTree:
			case <-time.After(3 * time.Second):
				return context.DeadlineExceeded
			}
		}
		return endpoint.serve(conn, req)
	}
	client := newDFSExternalClient(t, blocked)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := client.Open(firstCtx, `\\blocked-server\source\file`)
		first <- err
	}()
	select {
	case <-blocked.treeEntered:
	case <-time.After(time.Second):
		t.Fatal("first waiter did not enter shared TREE_CONNECT")
	}
	second := make(chan error, 1)
	go func() {
		_, err := client.Open(context.Background(), `\\blocked-server\source\file`)
		second <- err
	}()
	cancelFirst()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}
	close(allowTree)
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("remaining coalesced waiter error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("remaining coalesced waiter was disrupted")
	}
}

func TestExternalDFSCloseCancelsBlockedCreation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	dialer := &blockingDFSExternalDialer{started: started}
	client := smbclient.New(&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer})
	operationDone := make(chan error, 1)
	go func() {
		_, err := client.Open(context.Background(), `\\blocked-server\source\file`)
		operationDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked Dial did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Close remained blocked on creation")
	}
	select {
	case err := <-operationDone:
		if err == nil {
			t.Fatal("blocked operation unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked operation did not observe Client.Close")
	}
}

type blockingDFSExternalDialer struct {
	started chan<- struct{}
}

func (d *blockingDFSExternalDialer) Dial(ctx context.Context, _ string) (smb2.Transport, error) {
	close(d.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// Updating timestamps needs write-attribute access even when the caller cannot
// read attributes. A preliminary Stat would incorrectly reject this operation.
func TestExternalDFSChtimesWithoutReadAttributes(t *testing.T) {
	t.Parallel()
	endpoint := newDFSExternalEndpoint("server")
	endpoint.create = func(_ string, packet wire.PacketCodec) (erref.NtStatus, uint32) {
		request := wire.CreateRequestDecoder(packet.Body())
		if request.DesiredAccess()&wire.FILE_READ_ATTRIBUTES != 0 {
			return erref.STATUS_ACCESS_DENIED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	client := newDFSExternalClient(t, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := client.Chtimes(ctx, `\\server\share\file`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	endpoint.mu.Lock()
	mutations := endpoint.mutations
	endpoint.mu.Unlock()
	if mutations != 1 {
		t.Fatalf("timestamp updates = %d, want 1", mutations)
	}
}

func TestExternalClientRemoveAllObjects(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    erref.NtStatus
		attrs     uint32
		want      error
		mutations int
	}{
		{name: "file", mutations: 1},
		{name: "link", attrs: wire.FILE_ATTRIBUTE_REPARSE_POINT, mutations: 1},
		{name: "missing", status: erref.STATUS_OBJECT_NAME_NOT_FOUND},
		{name: "denied", status: erref.STATUS_ACCESS_DENIED, want: os.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := newDFSExternalEndpoint("server")
			ep.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) { return tc.status, tc.attrs }
			client := newDFSExternalClient(t, ep)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := `\\server\storage\` + tc.name
			err := client.RemoveAll(ctx, path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("RemoveAll = %v, want %v", err, tc.want)
			}
			if err != nil {
				var pe *os.PathError
				if !errors.As(err, &pe) || pe.Path != path || pe.Op != "removeall" {
					t.Fatalf("PathError = %#v", err)
				}
			}
			ep.mu.Lock()
			defer ep.mu.Unlock()
			if ep.mutations != tc.mutations {
				t.Fatalf("mutations = %d, want %d", ep.mutations, tc.mutations)
			}
			for _, create := range ep.createDetails {
				if create.options&wire.FILE_OPEN_REPARSE_POINT == 0 {
					t.Fatalf("followed final link: %#v", create)
				}
			}
		})
	}
}

func TestExternalClientRemoveAllDoesNotFollowChildReferral(t *testing.T) {
	ep := newDFSExternalEndpoint("server")
	ep.caps["namespace"] = true
	ep.create = func(path string, p wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasSuffix(path, `\child`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		cr := wire.CreateRequestDecoder(p.Body())
		if cr.IsInvalid() {
			return erref.STATUS_INVALID_PARAMETER, 0
		}
		if cr.DesiredAccess()&wire.DELETE != 0 {
			return erref.STATUS_DIRECTORY_NOT_EMPTY, 0
		}
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
	}
	ep.referral = func(string) []byte {
		return externalDFSReferralV3(`\server\namespace\dir\child`, `\\target\storage\precious`)
	}
	queries := 0
	ep.custom = func(conn net.Conn, req []byte) error {
		p := wire.PacketCodec(req)
		if p.Command() != wire.SMB2_QUERY_DIRECTORY {
			return ep.serve(conn, req)
		}
		queries++
		if queries > 1 {
			return externalWriteResponse(conn, req, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, erref.STATUS_NO_MORE_FILES, p.SessionId(), p.TreeId())
		}
		name := utf16le.EncodeStringToBytes("child")
		entry := make([]byte, 104+len(name))
		binary.LittleEndian.PutUint32(entry[56:60], wire.FILE_ATTRIBUTE_DIRECTORY)
		binary.LittleEndian.PutUint32(entry[60:64], uint32(len(name)))
		copy(entry[104:], name)
		return externalWriteResponse(conn, req, &wire.QueryDirectoryResponse{Output: externalRawEncoder(entry)}, erref.STATUS_SUCCESS, p.SessionId(), p.TreeId())
	}
	target := newDFSExternalEndpoint("target")
	client := newDFSExternalClient(t, ep, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.RemoveAll(ctx, `\\server\namespace\dir`); !errors.Is(err, erref.STATUS_PATH_NOT_COVERED) {
		t.Fatalf("RemoveAll = %v, want child referral failure", err)
	}
	ep.mu.Lock()
	referrals := len(ep.referralQueries)
	ep.mu.Unlock()
	target.mu.Lock()
	dials := target.dials
	target.mu.Unlock()
	if referrals != 0 || dials != 0 {
		t.Fatalf("followed child referral: queries=%d target dials=%d", referrals, dials)
	}
}

func TestExternalClientMkdirAllThroughDFS(t *testing.T) {
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	namespace.referral = func(string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\base`)
	}
	target := newDFSExternalEndpoint("target-server")
	dirs := map[string]bool{"base": true}
	target.create = func(path string, p wire.PacketCodec) (erref.NtStatus, uint32) {
		cr := wire.CreateRequestDecoder(p.Body())
		if cr.IsInvalid() {
			return erref.STATUS_INVALID_PARAMETER, 0
		}
		if path == `base\file` {
			return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_NORMAL
		}
		if cr.CreateDisposition() == wire.FILE_CREATE {
			parent := path[:strings.LastIndexByte(path, '\\')]
			if !dirs[parent] {
				return erref.STATUS_OBJECT_PATH_NOT_FOUND, 0
			}
			dirs[path] = true
		}
		if dirs[path] {
			return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
		}
		return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		if err := client.MkdirAll(ctx, `\\namespace-server\namespace\link\parent\child`, 0750); err != nil {
			t.Fatalf("MkdirAll = %v", err)
		}
	}
	if err := client.MkdirAll(ctx, `\\namespace-server\namespace\link\file`, 0750); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("MkdirAll existing file = %v", err)
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	var created []string
	for _, cr := range target.createDetails {
		if cr.disposition == wire.FILE_CREATE {
			if cr.options&wire.FILE_DIRECTORY_FILE == 0 {
				t.Fatalf("not a directory CREATE: %#v", cr)
			}
			created = append(created, cr.path)
		}
	}
	if strings.Join(created, ",") != `base\parent,base\parent\child` {
		t.Fatalf("created = %q", created)
	}
}

func TestExternalClientSecurityDescriptorThroughDFS(t *testing.T) {
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_PATH_NOT_COVERED, 0
	}
	namespace.referral = func(string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\base`)
	}
	descriptor := &security.Descriptor{DACL: security.NullACL}
	encoded, err := descriptor.Encode()
	if err != nil {
		t.Fatal(err)
	}
	target := newDFSExternalEndpoint("target-server")
	target.custom = func(conn net.Conn, req []byte) error {
		commands := dfsExternalCompoundCommands(req)
		if len(commands) == 3 && commands[1] == wire.SMB2_QUERY_INFO {
			if path := externalRequestPath(req); path != `base\file` {
				return fmt.Errorf("unexpected query path %q", path)
			}
			return dfsExternalWriteCompound(conn, req, []dfsExternalCompoundResponse{
				{packet: externalCreateSuccess()},
				{packet: &wire.QueryInfoResponse{Output: externalRawEncoder(encoded)}},
				{packet: externalCloseSuccess()},
			})
		}
		return target.serve(conn, req)
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := `\\namespace-server\namespace\link\file`
	got, err := client.GetSecurityDescriptor(ctx, path, security.DACL)
	if err != nil {
		t.Fatal(err)
	}
	if got.DACL != security.NullACL {
		t.Fatalf("DACL = %#v", got.DACL)
	}
	if err := client.SetSecurityDescriptor(ctx, path, descriptor); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		client.SetSecurityDescriptor(ctx, path, nil),
		func() error { _, err := client.GetSecurityDescriptor(ctx, path, 0); return err }(),
	} {
		var pe *os.PathError
		if !errors.Is(err, os.ErrInvalid) || !errors.As(err, &pe) || pe.Path != path {
			t.Fatalf("invalid descriptor/selection error = %v", err)
		}
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	if target.mutations != 1 {
		t.Fatalf("mutations = %d, want 1", target.mutations)
	}
	if len(target.createDetails) != 1 || target.createDetails[0].path != `base\file` || target.createDetails[0].access&wire.WRITE_DAC == 0 {
		t.Fatalf("security update CREATE = %#v", target.createDetails)
	}
}

func TestExternalClientGlobThroughDFS(t *testing.T) {
	namespace := newDFSExternalEndpoint("namespace-server")
	namespace.caps["namespace"] = true
	namespace.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasSuffix(path, `\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
	}
	namespace.referral = func(string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage\base`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
	}
	installListing := func(ep *dfsExternalEndpoint, names []string, wantPattern string) {
		page := 0
		ep.custom = func(conn net.Conn, req []byte) error {
			p := wire.PacketCodec(req)
			if p.Command() != wire.SMB2_QUERY_DIRECTORY {
				return ep.serve(conn, req)
			}
			q := wire.QueryDirectoryRequestDecoder(p.Body())
			if q.IsInvalid() {
				return errors.New("invalid query directory request")
			}
			if got := q.FileName(); got != wantPattern {
				return fmt.Errorf("server search pattern = %q, want %q", got, wantPattern)
			}
			page++
			if page%2 == 0 {
				return externalWriteResponse(conn, req, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, erref.STATUS_NO_MORE_FILES, p.SessionId(), p.TreeId())
			}
			var output []byte
			for i, name := range names {
				encoded := utf16le.EncodeStringToBytes(name)
				entry := make([]byte, wire.Roundup(104+len(encoded), 8))
				if i+1 < len(names) {
					binary.LittleEndian.PutUint32(entry[:4], uint32(len(entry)))
				}
				binary.LittleEndian.PutUint32(entry[56:60], wire.FILE_ATTRIBUTE_NORMAL)
				binary.LittleEndian.PutUint32(entry[60:64], uint32(len(encoded)))
				copy(entry[104:], encoded)
				output = append(output, entry...)
			}
			return externalWriteResponse(conn, req, &wire.QueryDirectoryResponse{Output: externalRawEncoder(output)}, erref.STATUS_SUCCESS, p.SessionId(), p.TreeId())
		}
	}
	installListing(namespace, []string{"link"}, "*")
	// The server's bracket-class approximation returns a superset. The common
	// search must still filter c1.go and sort the remaining logical UNC paths.
	installListing(target, []string{"b1.go", "c1.go", "a2.go"}, "??.go")
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	matches, err := client.WithContext(ctx).Glob("namespace-server/namespace/*/[ab]?.go")
	if err != nil {
		t.Fatal(err)
	}
	want := "namespace-server/namespace/link/a2.go,namespace-server/namespace/link/b1.go"
	if strings.Join(matches, ",") != want {
		t.Fatalf("Glob = %q, want %q", matches, want)
	}
	matches, err = client.WithContext(ctx).Glob("namespace-server/namespace/link")
	if err != nil || len(matches) != 0 {
		t.Fatalf("literal DFS link Glob = %q, %v", matches, err)
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	if len(target.createDetails) != 1 || target.createDetails[0].options&wire.FILE_DIRECTORY_FILE == 0 {
		t.Fatalf("target directory must be opened once: %#v", target.createDetails)
	}
}

func TestExternalClientVirtualFilesystem(t *testing.T) {
	ep := newDFSExternalEndpoint("server")
	ep.create = func(string, wire.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, wire.FILE_ATTRIBUTE_DIRECTORY
	}
	ep.custom = func(conn net.Conn, req []byte) error {
		p := wire.PacketCodec(req)
		ioctlPacket := p
		if p.Command() == wire.SMB2_CREATE && p.NextCommand() != 0 {
			ioctlPacket = wire.PacketCodec(req[p.NextCommand():])
		}
		if ioctlPacket.Command() == wire.SMB2_IOCTL {
			ir := wire.IoctlRequestDecoder(ioctlPacket.Body())
			if ir.IsInvalid() {
				return errors.New("invalid ioctl")
			}
			input := ir.Input()
			if len(input) < 16 {
				return errors.New("short RPC request")
			}
			var output []byte
			if input[2] == msrpc.RPC_TYPE_BIND {
				output = []byte{
					5, 0, 12, 3, 0x10, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0,
					0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
					0, 0, 0, 0, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
					0x9f, 0xe8, 0x08, 0, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0,
				}
			} else {
				enc := msrpc.NewEncoder()
				for _, v := range []uint32{1, 1, 1, 1, 1, 1, 1, 0, 0} {
					enc.WriteUint32(v)
				}
				enc.WriteConformantVaryingString("storage")
				for _, v := range []uint32{1, 0, 0} {
					enc.WriteUint32(v)
				}
				output = make([]byte, msrpc.HeaderSize+len(enc.Bytes()))
				output[0] = msrpc.RPC_VERSION
				output[2] = msrpc.RPC_TYPE_RESPONSE
				output[3] = msrpc.RPC_PACKET_FLAG_FIRST | msrpc.RPC_PACKET_FLAG_LAST
				binary.LittleEndian.PutUint16(output[8:10], uint16(len(output)))
				copy(output[msrpc.HeaderSize:], enc.Bytes())
			}
			copy(output[12:16], input[12:16])
			response := &wire.IoctlResponse{CtlCode: wire.FSCTL_PIPE_TRANSCEIVE, Output: externalRawEncoder(output)}
			if p.Command() == wire.SMB2_CREATE {
				return dfsExternalWriteCompound(conn, req, []dfsExternalCompoundResponse{{packet: externalCreateSuccess()}, {packet: response}})
			}
			return externalWriteResponse(conn, req, response, erref.STATUS_SUCCESS, p.SessionId(), p.TreeId())
		}
		commands := dfsExternalCompoundCommands(req)
		for _, command := range commands {
			if command == wire.SMB2_QUERY_DIRECTORY {
				responses := make([]dfsExternalCompoundResponse, len(commands))
				for i, c := range commands {
					responses[i].packet = dfsExternalResponseForCommand(c, wire.FILE_ATTRIBUTE_DIRECTORY)
					if c == wire.SMB2_QUERY_DIRECTORY {
						responses[i].packet = &wire.ErrorResponse{CommandCode: c}
						responses[i].status = erref.STATUS_NO_MORE_FILES
					}
				}
				if len(commands) > 1 {
					return dfsExternalWriteCompound(conn, req, responses)
				}
				return externalWriteResponse(conn, req, responses[0].packet, responses[0].status, p.SessionId(), p.TreeId())
			}
		}
		return ep.serve(conn, req)
	}
	client := newDFSExternalClient(t, ep)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := client.WithContext(ctx)
	entries, err := network.ReadDir(".")
	if err != nil || len(entries) != 0 {
		t.Fatalf("initial root = %v, %v", entries, err)
	}
	// Direct access connects a server that was absent from the root listing.
	entries, err = network.ReadDir("server")
	if err != nil || len(entries) != 1 || entries[0].Name() != "storage" {
		t.Fatalf("shares = %v, %v", entries, err)
	}
	var visited []string
	err = fs.WalkDir(network, ".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		visited = append(visited, name)
		return nil
	})
	if err != nil || strings.Join(visited, ",") != ".,server,server/storage" {
		t.Fatalf("WalkDir = %v, %v", visited, err)
	}
	sub, err := fs.Sub(network, "server/storage")
	if err != nil {
		t.Fatal(err)
	}
	entries, err = fs.ReadDir(sub, ".")
	if err != nil || len(entries) != 0 {
		t.Fatalf("sub ReadDir = %v, %v", entries, err)
	}
	matches, err := fs.Glob(network, "*/*")
	if err != nil || strings.Join(matches, ",") != "server/storage" {
		t.Fatalf("virtual Glob = %v, %v", matches, err)
	}
	info, err := fs.Stat(sub, ".")
	if err != nil || info.Name() != "storage" || !info.IsDir() {
		t.Fatalf("sub Stat = %v, %v", info, err)
	}
}

func TestExternalClientContextLookupErrors(t *testing.T) {
	testFileSystemContextLookupErrors(t, "client")
}
