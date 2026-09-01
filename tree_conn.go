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

func (s *session) treeConnect(ctx context.Context, path string, flags uint16) (*treeConn, error) {
	req := &smb2.TreeConnectRequest{
		Flags: flags,
		Path:  path,
	}

	rrs, err := s.send(ctx, req)
	if err != nil {
		return nil, err
	}

	res, err := s.recv(rrs[0])
	if err != nil {
		return nil, err
	}
	defer res.close()

	r := smb2.TreeConnectResponseDecoder(res.data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:    s,
		treeId:     res.packetCodec().TreeId(),
		shareFlags: r.ShareFlags(),
		// path:    path,
		// shareType:  r.ShareType(),
		// capabilities: r.Capabilities(),
		// maximalAccess: r.MaximalAccess(),
	}

	s.treeConnTables[tc.treeId] = tc // TODO consider concurrent access

	return tc, nil
}

func (tc *treeConn) disconnect(ctx context.Context) error {
	req := new(smb2.TreeDisconnectRequest)

	res, err := tc.sendRecv(ctx, req)
	if err != nil {
		return err
	}
	defer res[0].close()

	r := smb2.TreeDisconnectResponseDecoder(res[0].data())
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree disconnect response format"}
	}

	return nil
}

func (tc *treeConn) sendRecv(ctx context.Context, reqs ...smb2.Packet) (res []*receivedPacket, err error) {
	rrs, err := tc.send(ctx, reqs...)
	if err != nil {
		return nil, err
	}

	res = make([]*receivedPacket, len(reqs))
	for i, rr := range rrs {
		rr, err := tc.recv(rr)
		if err != nil {
			return nil, err
		}
		res[i] = rr
	}

	return res, nil
}

func (tc *treeConn) send(ctx context.Context, reqs ...smb2.Packet) (rrs []*outstandingRequest, err error) {
	for _, req := range reqs {
		req.SetTreeId(tc.treeId)
	}

	rrs, err = tc.session.send(ctx, reqs...)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

func (tc *treeConn) recv(rr *outstandingRequest) (rp *receivedPacket, err error) {
	rp, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if rr.asyncId != 0 {
		if asyncId := rp.packetCodec().AsyncId(); asyncId != rr.asyncId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", rr.asyncId, asyncId)}
		}
	} else {
		if treeId := rp.packetCodec().TreeId(); treeId != tc.treeId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return rp, err
}
