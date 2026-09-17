package smb2_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	smb2proto "github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
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
	create          func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32)
	ioctl           func(string, smb2proto.PacketCodec) ([]byte, uint32)
	reparse         *smb2proto.SymbolicLinkReparseDataBuffer
	reparseByPath   func(string) *smb2proto.SymbolicLinkReparseDataBuffer
	reparsePaths    []string
	symlink         *smb2proto.SymbolicLinkErrorResponse
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
		for j := 0; j < i; j++ {
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
	p := smb2proto.PacketCodec(req)
	e.mu.Lock()
	e.requests = append(e.requests, fmt.Sprintf("%v:%q", p.Command(), externalRequestPath(req)))
	e.mu.Unlock()
	switch p.Command() {
	case smb2proto.SMB2_TREE_CONNECT:
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
			caps = smb2proto.SMB2_SHARE_CAP_DFS
		}
		return externalWriteResponse(conn, req, &smb2proto.TreeConnectResponse{
			ShareType: smb2proto.SMB2_SHARE_TYPE_DISK, Capabilities: caps,
		}, erref.STATUS_SUCCESS, 0x1234, e.treeID(share))
	case smb2proto.SMB2_CREATE:
		path := externalRequestPath(req)
		if e.create != nil {
			status, attrs := e.create(path, p)
			if status != erref.STATUS_SUCCESS {
				return e.writeCompoundFailure(conn, req, status)
			}
			return e.writeCompoundSuccess(conn, req, attrs)
		}
		return e.writeCompoundSuccess(conn, req, 0)
	case smb2proto.SMB2_IOCTL:
		path, err := externalReferralInput(req)
		if err == nil && e.referral != nil {
			e.mu.Lock()
			e.referralQueries = append(e.referralQueries, path)
			e.mu.Unlock()
			return externalWriteResponse(conn, req, &smb2proto.IoctlResponse{
				CtlCode: smb2proto.FSCTL_DFS_GET_REFERRALS,
				FileId:  smb2proto.RelatedFileId,
				Output:  externalRawEncoder(e.referral(path)),
			}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
		}
		var output []byte
		if e.ioctl != nil {
			output, _ = e.ioctl(path, p)
		}
		return externalWriteResponse(conn, req, &smb2proto.IoctlResponse{
			CtlCode: smb2proto.FSCTL_GET_REPARSE_POINT,
			FileId:  smb2proto.RelatedFileId,
			Output:  externalRawEncoder(output),
		}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
	case smb2proto.SMB2_SET_INFO:
		e.mu.Lock()
		e.mutations++
		e.mu.Unlock()
		return externalWriteResponse(conn, req, &smb2proto.SetInfoResponse{}, erref.STATUS_SUCCESS, 0x1234, p.TreeId())
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
		requestPart := smb2proto.PacketCodec(req[requestOffset:])
		if command == smb2proto.SMB2_CREATE {
			createPath = externalRequestPath(req[requestOffset:])
		}
		packet := dfsExternalResponseForCommand(command, attrs)
		reparse := e.reparse
		if e.reparseByPath != nil {
			reparse = e.reparseByPath(createPath)
		}
		if command == smb2proto.SMB2_IOCTL && reparse != nil {
			ir := smb2proto.IoctlRequestDecoder(requestPart.Body())
			if !ir.IsInvalid() && ir.CtlCode() == smb2proto.FSCTL_GET_REPARSE_POINT {
				reparsePaths = append(reparsePaths, createPath)
				buf := make([]byte, reparse.Size())
				reparse.Encode(buf)
				packet = &smb2proto.IoctlResponse{CtlCode: smb2proto.FSCTL_GET_REPARSE_POINT, FileId: smb2proto.RelatedFileId, Output: externalRawEncoder(buf)}
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
		if command == smb2proto.SMB2_CREATE {
			part := smb2proto.PacketCodec(req[requestOffset:])
			path := externalRequestPath(req[requestOffset:])
			e.creates = append(e.creates, path)
			cr := smb2proto.CreateRequestDecoder(part.Body())
			if !cr.IsInvalid() {
				e.createDetails = append(e.createDetails, dfsExternalCreate{
					path: path, access: cr.DesiredAccess(),
					disposition: cr.CreateDisposition(), options: cr.CreateOptions(),
				})
			}
		}
		if command == smb2proto.SMB2_SET_INFO {
			e.mutations++
			part := smb2proto.PacketCodec(req[requestOffset:])
			setInfo := smb2proto.SetInfoRequestDecoder(part.Body())
			if !setInfo.IsInvalid() && setInfo.InfoType() == smb2proto.SMB2_0_INFO_FILE && setInfo.FileInfoClass() == smb2proto.FileRenameInformation {
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
		part := smb2proto.PacketCodec(req[requestOffset:])
		if command == smb2proto.SMB2_IOCTL {
			ir := smb2proto.IoctlRequestDecoder(part.Body())
			if !ir.IsInvalid() && ir.CtlCode() == smb2proto.FSCTL_SET_REPARSE_POINT {
				e.mutations++
			}
		}
		if next := part.NextCommand(); next != 0 {
			requestOffset += int(next)
		}
	}
	e.mu.Unlock()
	if len(commands) == 1 {
		return externalWriteResponse(conn, req, responses[0].packet, responses[0].status, 0x1234, smb2proto.PacketCodec(req).TreeId())
	}
	return dfsExternalWriteCompound(conn, req, responses)
}

func (e *dfsExternalEndpoint) writeCompoundFailure(conn net.Conn, req []byte, status erref.NtStatus) error {
	commands := dfsExternalCompoundCommands(req)
	if len(commands) == 0 {
		return errors.New("empty SMB compound")
	}
	e.mu.Lock()
	if commands[0] == smb2proto.SMB2_CREATE {
		e.creates = append(e.creates, externalRequestPath(req))
	}
	e.mu.Unlock()
	responses := make([]dfsExternalCompoundResponse, len(commands))
	for i, command := range commands {
		code := status
		if i > 0 {
			code = erref.STATUS_INVALID_HANDLE
		}
		packet := smb2proto.Packet(&smb2proto.ErrorResponse{CommandCode: command})
		if i == 0 && command == smb2proto.SMB2_CREATE && status == erref.STATUS_STOPPED_ON_SYMLINK && e.symlink != nil {
			packet = &smb2proto.ErrorResponse{CommandCode: command, ErrorData: e.symlink}
		}
		responses[i] = dfsExternalCompoundResponse{packet: packet, status: code}
	}
	if len(commands) == 1 {
		return externalWriteResponse(conn, req, responses[0].packet, status, 0x1234, smb2proto.PacketCodec(req).TreeId())
	}
	return dfsExternalWriteCompound(conn, req, responses)
}

type dfsExternalCompoundResponse struct {
	packet smb2proto.Packet
	status erref.NtStatus
}

func dfsExternalCompoundCommands(req []byte) []smb2proto.Command {
	var commands []smb2proto.Command
	for offset := 0; offset >= 0 && offset < len(req); {
		p := smb2proto.PacketCodec(req[offset:])
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

func dfsExternalResponseForCommand(command smb2proto.Command, attrs uint32) smb2proto.Packet {
	switch command {
	case smb2proto.SMB2_CREATE:
		response := externalCreateSuccess()
		response.FileAttributes = attrs
		return response
	case smb2proto.SMB2_CLOSE:
		return externalCloseSuccess()
	case smb2proto.SMB2_IOCTL:
		return &smb2proto.IoctlResponse{CtlCode: smb2proto.FSCTL_SET_REPARSE_POINT, FileId: smb2proto.RelatedFileId}
	case smb2proto.SMB2_SET_INFO:
		return &smb2proto.SetInfoResponse{}
	default:
		return &smb2proto.ErrorResponse{CommandCode: command}
	}
}

func dfsExternalWriteCompound(conn net.Conn, request []byte, responses []dfsExternalCompoundResponse) error {
	var out []byte
	requestOffset := 0
	for i, response := range responses {
		if requestOffset < 0 || requestOffset >= len(request) {
			return errors.New("compound request ended early")
		}
		req := smb2proto.PacketCodec(request[requestOffset:])
		span := smb2proto.Roundup(response.packet.Size(), 8)
		buf := make([]byte, span)
		response.packet.Encode(buf)
		p := smb2proto.PacketCodec(buf)
		p.SetMessageId(req.MessageId())
		p.SetSessionId(req.SessionId())
		p.SetTreeId(req.TreeId())
		p.SetStatus(uint32(response.status))
		p.SetCreditResponse(req.CreditRequest())
		flags := uint32(smb2proto.SMB2_FLAGS_SERVER_TO_REDIR)
		if i > 0 {
			flags |= smb2proto.SMB2_FLAGS_RELATED_OPERATIONS
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

func newDFSExternalClient(t *testing.T, endpoints ...*dfsExternalEndpoint) *dfs.DFS {
	t.Helper()
	dialer := &dfsExternalDialer{endpoints: make(map[string]*dfsExternalEndpoint, len(endpoints))}
	for _, endpoint := range endpoints {
		dialer.endpoints[strings.ToLower(endpoint.name)] = endpoint
	}
	client := dfs.New(&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer})
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	target.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, smb2proto.FILE_ATTRIBUTE_REPARSE_POINT
	}
	client := newDFSExternalClient(t, namespace, target)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := `\\namespace-server\namespace\link\file`
	f, err := client.Open(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(f).(*dfs.File); !ok {
		t.Fatalf("Open returned %T, want *dfs.File", f)
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasSuffix(strings.ToLower(path), `\namespace\link`) {
			return erref.STATUS_PATH_NOT_COVERED, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	namespace.referral = func(path string) []byte {
		return externalDFSReferralV3(`\namespace-server\namespace\link`, `\\target-server\storage`)
	}
	target := newDFSExternalEndpoint("target-server")
	target.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, smb2proto.FILE_ATTRIBUTE_REPARSE_POINT
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := `\\namespace-server\namespace\link`
	if err := client.Remove(ctx, path); !errors.Is(err, os.ErrInvalid) {
		namespace.mu.Lock()
		requests := append([]string(nil), namespace.requests...)
		namespace.mu.Unlock()
		t.Fatalf("uncached Remove error = %v, requests=%#v, want os.ErrInvalid", err, requests)
	}
	if err := client.Remove(ctx, path); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("cached Remove error = %v, want os.ErrInvalid", err)
	}
	target.mu.Lock()
	creates, mutations := len(target.creates), target.mutations
	details := append([]dfsExternalCreate(nil), target.createDetails...)
	target.mu.Unlock()
	for _, detail := range details {
		if detail.access&(smb2proto.DELETE|smb2proto.GENERIC_WRITE) != 0 || detail.disposition != smb2proto.FILE_OPEN {
			t.Fatalf("referral target destructive CREATE: %#v (all creates=%d mutations=%d)", detail, creates, mutations)
		}
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	target.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, 0
	}
	client := newDFSExternalClient(t, namespace, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Remove(ctx, `\\namespace-server\namespace\link\child`); err != nil {
		t.Fatalf("Remove explicit child: %v", err)
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
	finalLink.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\child`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-dir`,
		PrintName:          `real-dir`,
	}
	finalLink.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		switch strings.ToLower(path) {
		case `link\child`:
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		case `real-dir\child`:
			return erref.STATUS_SUCCESS, smb2proto.FILE_ATTRIBUTE_REPARSE_POINT
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
		if detail.access&smb2proto.DELETE != 0 {
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
	source.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, smb2proto.FILE_ATTRIBUTE_REPARSE_POINT
	}
	source.reparse = &smb2proto.SymbolicLinkReparseDataBuffer{
		Flags:          0,
		SubstituteName: `\??\UNC\unopened-server\other\target`,
		PrintName:      `\\unopened-server\other\target`,
	}
	source.ioctl = func(_ string, p smb2proto.PacketCodec) ([]byte, uint32) {
		if p.Command() != smb2proto.SMB2_IOCTL || source.reparse == nil {
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
			if detail.access&(smb2proto.DELETE|smb2proto.GENERIC_WRITE) != 0 || detail.disposition != smb2proto.FILE_OPEN {
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
	source.reparse = &smb2proto.SymbolicLinkReparseDataBuffer{
		SubstituteName: `\??\UNC\target-server\storage\missing`,
		PrintName:      `\\target-server\storage\missing`,
	}
	source.ioctl = func(_ string, _ smb2proto.PacketCodec) ([]byte, uint32) {
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	target.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(0),
		SubstituteName:     `\??\UNC\next-server\namespace\hop`,
		PrintName:          `\\next-server\namespace\hop`,
	}
	target.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		if strings.HasPrefix(strings.ToLower(path), `link`) {
			target.symlink.UnparsedPathLength = uint16(utf16le.EncodedStringLen(`\file`))
			return erref.STATUS_STOPPED_ON_SYMLINK, 0
		}
		return erref.STATUS_SUCCESS, 0
	}
	next := newDFSExternalEndpoint("next-server")
	next.caps["namespace"] = true
	next.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	root.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
			namespace.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	target.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `next`,
		PrintName:          `next`,
	}
	var targetCreates int
	target.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	target.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	a.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `hop2`,
		PrintName:          `hop2`,
	}
	a.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	b.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `hop4`,
		PrintName:          `hop4`,
	}
	b.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	namespace.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\file`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `next`,
		PrintName:          `next`,
	}
	namespace.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
	server.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\child`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-dir`,
		PrintName:          `real-dir`,
	}
	server.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
		if detail.access&smb2proto.DELETE != 0 {
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
	server.symlink = &smb2proto.SymbolicLinkErrorResponse{
		UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\source`)),
		Flags:              smb2proto.SYMLINK_FLAG_RELATIVE,
		SubstituteName:     `real-old`,
		PrintName:          `real-old`,
	}
	server.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
		if detail.access&smb2proto.DELETE != 0 {
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
	namespace.create = func(string, smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		return erref.STATUS_SUCCESS, smb2proto.FILE_ATTRIBUTE_REPARSE_POINT
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
	endpoint.create = func(path string, _ smb2proto.PacketCodec) (erref.NtStatus, uint32) {
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
		if smb2proto.PacketCodec(req).Command() == smb2proto.SMB2_TREE_CONNECT {
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
	client := dfs.New(&smb2.Dialer{Credentials: externalTestCredentials{}, TransportDialer: dialer})
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
	endpoint.create = func(_ string, packet smb2proto.PacketCodec) (erref.NtStatus, uint32) {
		request := smb2proto.CreateRequestDecoder(packet.Body())
		if request.DesiredAccess()&smb2proto.FILE_READ_ATTRIBUTES != 0 {
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
