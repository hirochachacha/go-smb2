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
	var isCompoundCreateClose bool
	if len(reqs) > 1 {
		_, isCreate := reqs[0].(*smb2.CreateRequest)
		_, isClose := reqs[len(reqs)-1].(*smb2.CloseRequest)
		isCompoundCreateClose = isCreate && isClose
	}
	if !isCompoundCreateClose {
		rrs, err := tc.send(ctx, reqs...)
		if err != nil {
			return nil, err
		}
		return recvAll(rrs, tc)
	}

	rrs, err := tc.send(ctx, reqs...)
	if err != nil {
		return nil, err
	}

	rpkts := make([]*recvPacket, len(rrs))
	var firstErr error
	var openedFileId *smb2.FileId

	for i, rr := range rrs {
		rp, err := tc.recv(rr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rpkts[i] = rp
		if i == 0 {
			r := smb2.CreateResponseDecoder(rp.data())
			if !r.IsInvalid() {
				openedFileId = r.FileId().Decode()
			}
		}
	}

	if firstErr != nil {
		for _, rp := range rpkts {
			if rp != nil {
				rp.close()
			}
		}
		if openedFileId != nil && rpkts[len(rpkts)-1] == nil {
			_ = tc.closeFile(context.Background(), openedFileId)
		}
		return nil, firstErr
	}

	return &response{rpkts: rpkts}, nil
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
	if rr.asyncId != 0 {
		if asyncId := rp.codec().AsyncId(); asyncId != rr.asyncId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected async id: %v, got %v", rr.asyncId, asyncId)}
		}
	} else {
		if treeId := rp.codec().TreeId(); treeId != tc.treeId {
			rp.close()
			return nil, &InvalidResponseError{fmt.Sprintf("expected tree id: %v, got %v", tc.treeId, treeId)}
		}
	}
	return rp, err
}
