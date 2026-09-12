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
	_, hasCreate := reqs[0].(*smb2.CreateRequest)
	if hasCreate {
		for _, rr := range rrs {
			rr.waitFinal = true
		}
	}
	res, err := recvAll(rrs, tc)
	if hasCreate && ctx.Err() != nil {
		// CANCEL can lose to a successful CREATE. Drain every related response
		// before deciding whether the server already executed CLOSE. Keeping
		// ownership here also covers a response buffered before cancellation.
		tc.closeResponseFile(reqs, res)
		res.close()
		return nil, &ContextError{Err: ctx.Err()}
	}
	return res, err
}

// closeResponseFile reclaims a handle after an unsuccessful operation. The
// responses must remain owned by the caller until this function returns.
func (tc *treeConn) closeResponseFile(reqs []smb2.Packet, res *response) {
	if res == nil {
		return
	}
	last := len(reqs) - 1
	closeReq, hasClose := reqs[last].(*smb2.CloseRequest)
	if hasClose && res.packet(last) != nil {
		return // The related CLOSE already succeeded.
	}
	var fd *smb2.FileId
	if _, hasCreate := reqs[0].(*smb2.CreateRequest); hasCreate && res.packet(0) != nil {
		r := smb2.CreateResponseDecoder(res.data(0))
		if !r.IsInvalid() {
			fd = r.FileId().Decode()
		}
	}
	if fd == nil && hasClose && closeReq.FileId != nil && !closeReq.FileId.IsRelated() {
		fd = closeReq.FileId
	}
	if fd != nil {
		_ = tc.closeFile(context.Background(), fd)
	}
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
