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

	if len(reqs) == 1 {
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
	errs := make([]error, len(rrs))
	var hasErr bool
	var openedFileId *smb2.FileId

	for i, rr := range rrs {
		rp, err := tc.recv(rr)
		if err != nil {
			hasErr = true
			errs[i] = err

			// Per [MS-SMB2] 3.3.5.2.7, servers halt processing and do not send
			// responses for subsequent requests in the compounded chain.
			// Drain any responses that already arrived, abandon unexecuted requests,
			// and restore their loaned credits.
			for j, nextRR := range rrs[i+1:] {
				idx := i + 1 + j
				select {
				case subRp := <-nextRR.recv:
					if subRp != nil {
						acceptedRp, acceptErr := accept(nextRR.cmd, subRp)
						if acceptErr != nil {
							errs[idx] = acceptErr
						} else {
							rpkts[idx] = acceptedRp
						}
					} else if nextRR.err != nil {
						errs[idx] = nextRR.err
					}
				default:
					nextRR.canceled.Store(true)
					if tc.session != nil && tc.session.conn != nil {
						conn := tc.session.conn
						if conn.outstandingRequests != nil {
							if _, ok := conn.outstandingRequests.pop(nextRR.msgId); ok {
								if conn.account != nil {
									conn.account.unloan(nextRR.creditCharge)
								}
							}
						}
					}
					select {
					case subRp := <-nextRR.recv:
						if subRp != nil {
							subRp.close()
						}
					default:
					}
				}
			}
			break
		}
		rpkts[i] = rp
		if i == 0 {
			if _, isCreate := reqs[0].(*smb2.CreateRequest); isCreate {
				r := smb2.CreateResponseDecoder(rp.data())
				if !r.IsInvalid() {
					openedFileId = r.FileId().Decode()
				}
			}
		}
	}

	if hasErr {
		for _, rp := range rpkts {
			if rp != nil {
				rp.close()
			}
		}

		lastIdx := len(reqs) - 1
		closeReq, hasClose := reqs[lastIdx].(*smb2.CloseRequest)
		closeSucceeded := hasClose && rpkts[lastIdx] != nil

		if !closeSucceeded {
			if openedFileId != nil {
				_ = tc.closeFile(context.Background(), openedFileId)
			} else if hasClose && closeReq.FileId != nil && !closeReq.FileId.IsRelated() {
				_ = tc.closeFile(context.Background(), closeReq.FileId)
			}
		}

		return nil, &CompoundResponseError{Errors: errs}
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
