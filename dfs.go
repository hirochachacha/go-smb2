package smb2

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// dfsTree adapts SMB tree operations and session ownership to the DFS resolver.
type dfsTree struct {
	*treeConn
	owner *clientSession
}

func newDFSResolver(owner *clientSession, server, share string) *dfsc.Resolver[*dfsTree] {
	return dfsc.NewResolver(server, share, func(ctx context.Context, targetServer, targetShare string) (*dfsTree, error) {
		return connectDFSTree(ctx, owner, server, targetServer, targetShare)
	})
}

func connectDFSTree(ctx context.Context, owner *clientSession, namespaceServer, server, share string) (*dfsTree, error) {
	ss := owner
	var err error
	if owner.client != nil {
		ss, err = owner.client.connect(ctx, server)
		if err != nil {
			return nil, err
		}
	} else if !strings.EqualFold(server, namespaceServer) {
		return nil, fmt.Errorf("DFS target %q requires Client", server)
	}
	tc, err := ss.s.treeConnect(ctx, `\\`+server+`\`+share, 0)
	if err != nil {
		if owner.client != nil {
			_ = owner.client.closeSession(ctx, ss)
		}
		return nil, err
	}
	tree := &dfsTree{treeConn: tc}
	if owner.client != nil {
		tree.owner = ss
	}
	return tree, nil
}

func (t *dfsTree) IsNamespace() bool {
	return t.shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) != 0
}

func (t *dfsTree) Close(ctx context.Context) error {
	err := t.disconnect(ctx)
	if t.owner != nil {
		if releaseErr := t.owner.client.closeSession(ctx, t.owner); err == nil {
			err = releaseErr
		}
	}
	return err
}

// Referral sends one referral IOCTL; dfsc owns sizing retries and decoding.
func (t *dfsTree) Referral(ctx context.Context, req *dfsc.ReferralRequest, maxOutput uint32) ([]byte, error) {
	res, err := t.request().withFileId(smb2.RelatedFileId).ioctl(smb2.FSCTL_DFS_GET_REFERRALS, req, maxOutput).sendRecv(ctx)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, &InvalidResponseError{"missing DFS referral response"}
	}
	defer res.close()
	out := smb2.IoctlResponseDecoder(res.data(0))
	if out.IsInvalid() {
		return nil, &InvalidResponseError{"broken DFS referral IOCTL response"}
	}
	if out.OutputCount() > maxOutput {
		return nil, &InvalidResponseError{"DFS referral IOCTL output exceeds requested size"}
	}
	return append([]byte(nil), out.Output()...), nil
}

func translateDFSError(err error) error {
	var referral *dfsc.ReferralError
	if errors.As(err, &referral) {
		return &InvalidResponseError{referral.Message}
	}
	var resolution *dfsc.ResolutionError
	if errors.As(err, &resolution) {
		return &InternalError{resolution.Message}
	}
	if err == erref.STATUS_OBJECT_PATH_NOT_FOUND {
		return &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)}
	}
	return err
}

func (fs *Share) sendRouted(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	if len(reqs) == 0 || fs.dfs == nil {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	create, ok := reqs[0].(*smb2.CreateRequest)
	if !ok {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	originalName, originalFlags := create.Name, create.HeaderFlags()
	defer func() { create.Name = originalName; create.SetFlags(originalFlags) }()
	var res *response
	primary := &dfsTree{treeConn: fs.treeConn}
	err := fs.dfs.Send(ctx, originalName, primary, func(route dfsc.Route[*dfsTree]) (bool, error) {
		namespace := route.Tree == primary || route.Tree.IsNamespace()
		create.Flags &^= smb2.SMB2_FLAGS_DFS_OPERATIONS
		create.Name = route.Name
		if namespace {
			create.Flags |= smb2.SMB2_FLAGS_DFS_OPERATIONS
			create.Name = route.Path
		}
		var err error
		res, err = route.Tree.sendRecv(ctx, reqs...)
		if res != nil {
			res.treeConn = route.Tree.treeConn
		}
		if !namespace || !dfsPathNotCovered(err) {
			return false, err
		}
		res.close()
		res = nil
		return true, nil
	})
	return res, translateDFSError(err)
}

func dfsPathNotCovered(err error) bool {
	var re *ResponseError
	if errors.As(err, &re) {
		return erref.NtStatus(re.Code) == erref.STATUS_PATH_NOT_COVERED
	}
	var ce *CompoundResponseError
	if errors.As(err, &ce) {
		return dfsPathNotCovered(ce.OpError(0))
	}
	return false
}

func (fs *Share) routed(tc *treeConn) *Share {
	if tc == nil || tc == fs.treeConn {
		return fs
	}
	return &Share{treeConn: tc, dfs: fs.dfs}
}
