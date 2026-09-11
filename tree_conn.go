package smb2

import (
	"context"
	"fmt"
	"os"

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

	res, err := s.sendRecv(ctx, req)
	if err != nil {
		return nil, err
	}
	defer res.close()

	r := smb2.TreeConnectResponseDecoder(res.data(0))

	tc := &treeConn{
		session:    s,
		treeId:     res.packet(0).codec().TreeId(),
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

	res, err := tc.sendRecv(ctx, req)
	if err != nil {
		return err
	}
	defer res.close()

	return nil
}

func (tc *treeConn) closeFile(ctx context.Context, fd *smb2.FileId) error {
	if fd == nil {
		return os.ErrInvalid
	}

	res, err := tc.request().withFileId(fd).close().sendRecv(ctx)
	if err != nil {
		return err
	}
	res.close()

	return nil
}

func (tc *treeConn) sendRecv(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	if len(reqs) == 0 {
		return nil, &InternalError{"empty request"}
	}

	rrs, err := tc.send(ctx, reqs...)
	if err != nil {
		return nil, err
	}
	return recvAll(rrs, tc)
}


func (tc *treeConn) send(ctx context.Context, reqs ...smb2.Packet) (rrs []*outstandingRequest, err error) {
	for _, req := range reqs {
		req.SetTreeId(tc.treeId)
	}

	encrypt := (tc.session.sessionFlags&smb2.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0) || (tc.shareFlags&smb2.SMB2_SHAREFLAG_ENCRYPT_DATA != 0)

	rrs, err = tc.session.send(ctx, encrypt, reqs...)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

func (tc *treeConn) recv(rr *outstandingRequest) (rp *recvPacket, err error) {
	rp, err = tc.session.recv(rr)
	if err != nil {
		return nil, err
	}
	if asyncId := rr.asyncId.Load(); asyncId != 0 {
		if rpAsyncId := rp.codec().AsyncId(); rpAsyncId != asyncId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", asyncId, rpAsyncId)}
		}
	} else {
		if treeId := rp.codec().TreeId(); treeId != tc.treeId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return rp, err
}

func (tc *treeConn) unloan(rrs ...*outstandingRequest) {
	if tc == nil || tc.session == nil {
		return
	}
	tc.session.unloan(rrs...)
}


