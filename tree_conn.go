package smb2

import (
	"context"
	"fmt"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

type treeConn struct {
	*session
	treeId     uint32
	shareFlags uint32

	// path string
	// shareType  uint8
	// capabilities uint32
	// maximalAccess uint32
}

func treeConnect(s *session, path string, flags uint16, ctx context.Context) (*treeConn, error) {
	req := &smb2.TreeConnectRequest{
		Flags: flags,
		Path:  path,
	}

	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	rp, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err := accept(smb2.SMB2_TREE_CONNECT, rp)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	r := smb2.TreeConnectResponseDecoder(res.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:    s,
		treeId:     rp.PacketCodec().TreeId(),
		shareFlags: r.ShareFlags(),
		// path:    path,
		// shareType:  r.ShareType(),
		// capabilities: r.Capabilities(),
		// maximalAccess: r.MaximalAccess(),
	}

	return tc, nil
}

func (tc *treeConn) disconnect(ctx context.Context) error {
	req := new(smb2.TreeDisconnectRequest)

	res, err := tc.sendRecv(smb2.SMB2_TREE_DISCONNECT, req, ctx)
	if err != nil {
		return err
	}
	defer res.Close()

	r := smb2.TreeDisconnectResponseDecoder(res.Data())
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree disconnect response format"}
	}

	return nil
}

func (tc *treeConn) sendRecv(cmd uint16, req smb2.Packet, ctx context.Context) (res *receivedPacket, err error) {
	rr, err := tc.send(req, ctx)
	if err != nil {
		return nil, err
	}

	rp, err := tc.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, rp)
}

func (tc *treeConn) send(req smb2.Packet, ctx context.Context) (rr *outstandingRequest, err error) {
	return tc.sendWith(req, tc, ctx)
}

func (tc *treeConn) recv(rr *outstandingRequest) (rp *receivedPacket, err error) {
	rp, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if rr.asyncId != 0 {
		if asyncId := rp.PacketCodec().AsyncId(); asyncId != rr.asyncId {
			rp.Close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", rr.asyncId, asyncId)}
		}
	} else {
		if treeId := rp.PacketCodec().TreeId(); treeId != tc.treeId {
			rp.Close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return rp, err
}
