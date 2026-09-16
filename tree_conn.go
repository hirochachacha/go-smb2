package smb2

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

type treeConn struct {
	*session
	treeId       uint32
	shareType    uint8
	shareFlags   uint32
	capabilities uint32
	isDFSShare   bool
	serverName   string
	shareName    string

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
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken tree connect response format"}
	}

	tc := &treeConn{
		session:      s,
		treeId:       res.packet(0).codec().TreeId(),
		shareType:    r.ShareType(),
		shareFlags:   r.ShareFlags(),
		capabilities: r.Capabilities(),
		isDFSShare:   r.Capabilities()&smb2.SMB2_SHARE_CAP_DFS != 0,
		// maximalAccess: r.MaximalAccess(),
	}
	if server, share, err := splitSharePath(path); err == nil {
		tc.serverName, tc.shareName = server, share
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
		if err == errCompoundCredits {
			return tc.sendRecvSequential(ctx, reqs)
		}
		return nil, err
	}
	_, hasCreate := reqs[0].(*smb2.CreateRequest)
	if hasCreate {
		for _, rr := range rrs {
			rr.waitFinal = true
		}
	}
	res, err := recvAll(rrs, tc)
	if res != nil {
		res.treeConn = tc
	}
	if hasCreate && ctx.Err() != nil {
		// CANCEL can lose to a successful CREATE. Drain every related response
		// before deciding whether the server already executed CLOSE. Keeping
		// ownership here also covers a response buffered before cancellation.
		tc.closeResponseFile(reqs, res)
		res.close()
		return nil, ctx.Err()
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
	if tc.isDFSShare {
		// DFS CREATE requests carry SMB2_FLAGS_DFS_OPERATIONS and the full path
		// name. Rewrite copies so the caller's request objects keep their
		// share-relative name and flags.
		cloned := false
		for i, req := range reqs {
			cr, ok := req.(*smb2.CreateRequest)
			if !ok {
				continue
			}
			if !cloned {
				reqs = slices.Clone(reqs)
				cloned = true
			}
			clone := *cr
			clone.Name = tc.dfsPath(cr.Name)
			clone.SetFlags(cr.HeaderFlags() | smb2.SMB2_FLAGS_DFS_OPERATIONS)
			reqs[i] = &clone
		}
	}
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

// uncPath returns the public UNC path \\server\share\name for a share-relative
// name.
func (tc *treeConn) uncPath(name string) string {
	path := tc.serverName + `\` + tc.shareName
	if name = strings.TrimLeft(name, `\`); name != "" {
		path += `\` + name
	}
	return `\\` + path
}

// dfsPath returns the [MS-SMB2] "full path name" \server\share\name for a
// share-relative name, the form required with SMB2_FLAGS_DFS_OPERATIONS
// ([MS-DFSC] 3.2.4.1).
func (tc *treeConn) dfsPath(name string) string {
	return tc.uncPath(name)[1:]
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
