package protocol

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

var le = binary.LittleEndian

// testNTLMInitiator keeps protocol tests independent of the root package's
// credential constructors while exercising the real NTLM wire exchange.
type testNTLMInitiator struct {
	User, Password string
	client         *ntlm.Client
	complete       bool
	sendSeq        uint32
	recvSeq        uint32
}

func (*testNTLMInitiator) OID() asn1.ObjectIdentifier { return spnego.NlmpOid }

func (i *testNTLMInitiator) InitSecContext() ([]byte, error) {
	i.client = &ntlm.Client{User: i.User, Password: i.Password}
	i.complete = false
	i.sendSeq, i.recvSeq = 0, 0
	return i.client.Negotiate()
}

func (i *testNTLMInitiator) AcceptSecContext(token []byte) ([]byte, error) {
	if i.client == nil || i.complete {
		return nil, errors.New("ntlm: unexpected authentication token")
	}
	msg, err := i.client.Authenticate(token)
	if err == nil {
		i.complete = true
	}
	return msg, err
}

func (i *testNTLMInitiator) GetMIC(message []byte) ([]byte, error) {
	if !i.complete || i.client == nil || i.client.Session() == nil {
		return nil, errors.New("ntlm: authentication is incomplete")
	}
	var mic []byte
	mic, i.sendSeq = i.client.Session().Sign(message, i.sendSeq)
	return mic, nil
}

func (i *testNTLMInitiator) VerifyMIC(message, mic []byte) error {
	if !i.complete || i.client == nil || i.client.Session() == nil {
		return errors.New("ntlm: authentication is incomplete")
	}
	ok, next := i.client.Session().Verify(mic, message, i.recvSeq)
	if !ok {
		return errors.New("ntlm: invalid mechanism list MIC")
	}
	i.recvSeq = next
	return nil
}

func (i *testNTLMInitiator) Complete() bool { return i.complete }

func (i *testNTLMInitiator) SessionKey() []byte {
	if i.client == nil || i.client.Session() == nil {
		return nil
	}
	return i.client.Session().SessionKey()
}

type countingClientTransport struct {
	Transport
	closes *atomic.Int32
}

func (t *countingClientTransport) Close() error {
	t.closes.Add(1)
	return t.Transport.Close()
}

type negotiateQUICTransport struct{ Transport }

func (negotiateQUICTransport) transportType() string { return "quic" }

type rawEncoder []byte

func (b rawEncoder) Size() int       { return len(b) }
func (b rawEncoder) Encode(p []byte) { copy(p, b) }

// newTestTree creates a negotiated-looking tree backed by a pipe. Protocol
// tests use this fixture directly so root file-system types do not leak into
// the low-level package.
func newTestTree(t *testing.T) (*Tree, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		_ = serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	return &Tree{session: c.session, treeId: 0x200}, serverConn
}

func sendTestResponse(dt Transport, req []byte, res wire.Packet, status uint32) {
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := wire.PacketCodec(req)
	rp := wire.PacketCodec(resBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(status)
	rp.SetCreditResponse(1)
	rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	_, _ = dt.writev(resBuf)
}

func sendTestCloseResponse(dt Transport, req []byte) {
	sendTestResponse(dt, req, &wire.CloseResponse{
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
	}, uint32(0))
}

func sendTestCreateAttributesResponse(dt Transport, req []byte, fileID wire.FileId, attrs uint32) {
	sendTestResponse(dt, req, &wire.CreateResponse{
		FileId:         fileID,
		CreationTime:   wire.Filetime{},
		LastAccessTime: wire.Filetime{},
		LastWriteTime:  wire.Filetime{},
		ChangeTime:     wire.Filetime{},
		FileAttributes: attrs,
	}, uint32(0))
}

type compoundResponse struct {
	packet wire.Packet
	status erref.NtStatus
}

func sendCompoundResponse(dt Transport, request []byte, responses []compoundResponse) error {
	if len(responses) == 0 {
		return fmt.Errorf("empty compound response")
	}
	var out []byte
	requestOffset := 0
	for i, response := range responses {
		if requestOffset < 0 || requestOffset >= len(request) {
			return fmt.Errorf("compound request ended early")
		}
		reqPacket := wire.PacketCodec(request[requestOffset:])
		span := wire.Roundup(response.packet.Size(), 8)
		buf := make([]byte, span)
		response.packet.Encode(buf)
		p := wire.PacketCodec(buf)
		p.SetMessageId(reqPacket.MessageId())
		p.SetSessionId(reqPacket.SessionId())
		p.SetTreeId(reqPacket.TreeId())
		p.SetStatus(uint32(response.status))
		p.SetCreditResponse(reqPacket.CreditRequest())
		flags := uint32(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		if i > 0 {
			flags |= wire.SMB2_FLAGS_RELATED_OPERATIONS
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
	_, err := dt.writev(out)
	return err
}
