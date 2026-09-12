package smb2

import (
	"context"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// sendRecvSequential preserves response indexes and handle ownership while
// issuing a related operation group with fewer credits. Unlike a compound,
// each request carries a concrete FileId ([MS-SMB2] 3.2.4.1.4). Stop at the
// first failure; requestBuilder closes any handle left open by the group.
func (tc *treeConn) sendRecvSequential(ctx context.Context, reqs []smb2.Packet) (*response, error) {
	res := &response{rpkts: make([]*recvPacket, len(reqs)), treeConn: tc}
	var fd *smb2.FileId
	for i, req := range reqs {
		packet, err := separateFileRequest(req, fd)
		if err == nil {
			var part *response
			if packet.Command() == smb2.SMB2_CREATE {
				part, err = tc.sendRecv(ctx, packet)
			} else {
				var rrs []*outstandingRequest
				rrs, err = tc.send(ctx, packet)
				if err == nil {
					// Retain final responses just as for a CREATE compound.
					// In particular, a canceled CLOSE may still succeed.
					for _, rr := range rrs {
						rr.waitFinal = true
					}
					part, err = recvAll(rrs, tc)
				}
			}
			if err == nil {
				res.rpkts[i] = part.packet(0)
				if packet.Command() == smb2.SMB2_CREATE {
					fd = smb2.CreateResponseDecoder(part.data(0)).FileId().Decode()
				}
				if ctx.Err() != nil {
					err = &ContextError{Err: ctx.Err()}
				}
			}
		}
		if err != nil {
			errs := make([]error, len(reqs))
			for j := i; j < len(errs); j++ {
				errs[j] = err // Failed or not sent because its predecessor failed.
			}
			return res, &CompoundResponseError{Errors: errs}
		}
	}
	return res, nil
}

// Clone before replacing a related FileId: the builder may retry after a
// symlink response or a required-buffer-length error with a different handle.
func separateFileRequest(req smb2.Packet, fd *smb2.FileId) (smb2.Packet, error) {
	var packet smb2.Packet
	var header *smb2.PacketHeader
	var fileID **smb2.FileId
	switch r := req.(type) {
	case *smb2.CreateRequest:
		p := *r
		header = &p.PacketHeader
		packet = &p
	case *smb2.CloseRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.FlushRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.QueryInfoRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.SetInfoRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.IoctlRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.QueryDirectoryRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.ReadRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *directReadRequest:
		p, read := *r, *r.ReadRequest
		p.ReadRequest = &read
		header = &read.PacketHeader
		packet, fileID = &p, &read.FileId
	case *smb2.WriteRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.ChangeNotifyRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	case *smb2.LockRequest:
		p := *r
		header = &p.PacketHeader
		packet, fileID = &p, &p.FileId
	default:
		return nil, &InternalError{"cannot send this compound command separately"}
	}
	if fileID != nil && *fileID != nil && (*fileID).IsRelated() {
		if fd == nil {
			return nil, &InternalError{"related request has no open file"}
		}
		*fileID = fd
	}
	header.Flags &^= smb2.SMB2_FLAGS_RELATED_OPERATIONS
	packet.SetNextCommand(0)
	return packet, nil
}
