package smb2

import (
	"fmt"
	"unicode/utf16"

	. "github.com/hirochachacha/smb2/internal/smb2"
)

type treeConn struct {
	*session
	path string

	treeId uint32

	shareType     uint8
	shareFlags    uint32
	capabilities  uint32
	maximalAccess uint32
}

func treeConnect(s *session, path string, flags uint16) (*treeConn, error) {
	req := &TreeConnectRequest{
		Flags: flags,
		Path:  utf16.Encode([]rune(path)),
	}

	req.CreditCharge = 1

	rr, err := s.send(req)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err := accept(SMB2_TREE_CONNECT, pkt)
	if err != nil {
		return nil, err
	}

	r := TreeConnectResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:       s,
		path:          path,
		treeId:        PacketCodec(pkt).TreeId(),
		shareType:     r.ShareType(),
		shareFlags:    r.ShareFlags(),
		capabilities:  r.Capabilities(),
		maximalAccess: r.MaximalAccess(),
	}

	return tc, nil
}

func (tc *treeConn) disconnect() error {
	req := new(TreeDisconnectRequest)

	req.CreditCharge = 1

	res, err := tc.sendRecv(SMB2_TREE_DISCONNECT, req)
	if err != nil {
		return err
	}

	r := TreeDisconnectResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree disconnect response format"}
	}

	return nil
}

func (tc *treeConn) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	rr, err := tc.send(req)
	if err != nil {
		return nil, err
	}

	pkt, err := tc.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (tc *treeConn) send(req Packet) (rr *requestResponse, err error) {
	return tc.sendWith(req, tc.session, tc)
}

func (tc *treeConn) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if treeId := PacketCodec(pkt).TreeId(); treeId != tc.treeId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
	}
	return pkt, err
}
