package smb2

import (
	"context"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

type compoundItem struct {
	cmd uint16
	req smb2.Packet
}

type requestBuilder struct {
	tc    *treeConn
	fd    *smb2.FileId
	items []compoundItem
}

type response struct {
	rpkts []*receivedPacket
}

func (r *response) close() {
	if r == nil {
		return
	}
	for _, res := range r.rpkts {
		if res != nil {
			res.Close()
		}
	}
}

func (r *response) get(i int) *receivedPacket {
	if r == nil || i < 0 || i >= len(r.rpkts) {
		return nil
	}
	return r.rpkts[i]
}

func (r *response) data(i int) []byte {
	res := r.get(i)
	if res == nil {
		return nil
	}
	return res.Data()
}

func (tc *treeConn) request() *requestBuilder {
	return &requestBuilder{tc: tc, fd: smb2.RelatedFileId}
}

func (fs *Share) request() *requestBuilder {
	return fs.treeConn.request()
}

func (f *File) request() *requestBuilder {
	return &requestBuilder{tc: f.fs.treeConn, fd: f.fd}
}

func (req *requestBuilder) withFileId(fd *smb2.FileId) *requestBuilder {
	req.fd = fd
	return req
}

func (req *requestBuilder) add(cmd uint16, p smb2.Packet) *requestBuilder {
	req.items = append(req.items, compoundItem{cmd: cmd, req: p})
	return req
}

func (req *requestBuilder) create(name string, access, disposition, options uint32) *requestBuilder {
	p := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    disposition,
		CreateOptions:        options,
		Name:                 name,
	}
	p.CreditCharge = 1
	req.add(smb2.SMB2_CREATE, p)
	req.fd = smb2.RelatedFileId
	return req
}

func (req *requestBuilder) close() *requestBuilder {
	p := &smb2.CloseRequest{
		Flags:  0,
		FileId: req.fd,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_CLOSE, p)
}

func (req *requestBuilder) flush() *requestBuilder {
	p := &smb2.FlushRequest{
		FileId: req.fd,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_FLUSH, p)
}

func (req *requestBuilder) setInfo(infoClass uint8, input smb2.Encoder) *requestBuilder {
	p := &smb2.SetInfoRequest{
		FileInfoClass:         infoClass,
		AdditionalInformation: 0,
		FileId:                req.fd,
		Input:                 input,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_SET_INFO, p)
}

func (req *requestBuilder) queryInfo(infoType, infoClass uint8, bufferLen uint32) *requestBuilder {
	p := &smb2.QueryInfoRequest{
		InfoType:              infoType,
		FileInfoClass:         infoClass,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    bufferLen,
		FileId:                req.fd,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_QUERY_INFO, p)
}

func (req *requestBuilder) ioctl(ctlCode uint32, input smb2.Encoder, maxOutput uint32) *requestBuilder {
	p := &smb2.IoctlRequest{
		CtlCode:           ctlCode,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: maxOutput,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             input,
		FileId:            req.fd,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_IOCTL, p)
}

func (req *requestBuilder) queryDir(infoClass uint8, pattern string, bufferLen uint32) *requestBuilder {
	p := &smb2.QueryDirectoryRequest{
		FileInfoClass:      infoClass,
		Flags:              0,
		FileIndex:          0,
		FileId:             req.fd,
		FileName:           pattern,
		OutputBufferLength: bufferLen,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_QUERY_DIRECTORY, p)
}

func (req *requestBuilder) read(length uint32, offset uint64) *requestBuilder {
	p := &smb2.ReadRequest{
		Padding:      0,
		Flags:        0,
		Length:       length,
		Offset:       offset,
		FileId:       req.fd,
		MinimumCount: 0,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_READ, p)
}

func (req *requestBuilder) write(data []byte, offset uint64) *requestBuilder {
	p := &smb2.WriteRequest{
		Offset: offset,
		Flags:  0,
		FileId: req.fd,
		Data:   data,
	}
	p.CreditCharge = 1
	return req.add(smb2.SMB2_WRITE, p)
}

func (req *requestBuilder) sendRecv(ctx context.Context) (*response, error) {
	if len(req.items) == 0 {
		return nil, &InternalError{"empty compound request"}
	}

	if len(req.items) == 1 {
		item := req.items[0]
		res, err := req.tc.sendRecv(item.cmd, item.req, ctx)
		if err != nil {
			return nil, err
		}
		return &response{rpkts: []*receivedPacket{res}}, nil
	}

	reqs := make([]smb2.Packet, len(req.items))
	for i, item := range req.items {
		reqs[i] = item.req
	}

	rrs, err := req.tc.sendCompoundWith(reqs, req.tc, ctx)
	if err != nil {
		return nil, err
	}

	rpkts := make([]*receivedPacket, len(req.items))
	var firstErr error

	for i, item := range req.items {
		rp, err := req.tc.recv(rrs[i])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		res, err := accept(item.cmd, rp)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		rpkts[i] = res
	}

	resp := &response{rpkts: rpkts}

	if firstErr != nil {
		resp.close()
		return nil, firstErr
	}

	return resp, nil
}
