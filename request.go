package smb2

import (
	"context"
	"errors"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

type requestBuilder struct {
	tc   *treeConn
	fd   *smb2.FileId
	pkts []smb2.Packet
}

func (tc *treeConn) request() *requestBuilder {
	return &requestBuilder{tc: tc}
}

func (fs *Share) request() *requestBuilder {
	return fs.treeConn.request()
}

func (req *requestBuilder) withFileId(fd *smb2.FileId) *requestBuilder {
	req.fd = fd
	return req
}

func (req *requestBuilder) add(p smb2.Packet) *requestBuilder {
	req.pkts = append(req.pkts, p)
	return req
}

func (req *requestBuilder) get(i int) smb2.Packet {
	return req.pkts[i]
}

func (req *requestBuilder) create(name string, access, disposition, options, attrs uint32) *requestBuilder {
	p := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       attrs,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    disposition,
		CreateOptions:        options,
		Name:                 name,
	}
	req.add(p)
	req.fd = smb2.RelatedFileId
	return req
}

func (req *requestBuilder) close() *requestBuilder {
	p := &smb2.CloseRequest{
		Flags:  0,
		FileId: req.fd,
	}
	return req.add(p)
}

func (req *requestBuilder) flush() *requestBuilder {
	p := &smb2.FlushRequest{
		FileId: req.fd,
	}
	return req.add(p)
}

func (req *requestBuilder) setInfo(infoType, infoClass uint8, additionalInfo uint32, input smb2.Encoder) *requestBuilder {
	p := &smb2.SetInfoRequest{
		InfoType:              infoType,
		FileInfoClass:         infoClass,
		AdditionalInformation: additionalInfo,
		FileId:                req.fd,
		Input:                 input,
	}
	return req.add(p)
}

func (req *requestBuilder) queryInfo(infoType, infoClass uint8, additionalInfo, bufferLen uint32) *requestBuilder {
	p := &smb2.QueryInfoRequest{
		InfoType:              infoType,
		FileInfoClass:         infoClass,
		AdditionalInformation: additionalInfo,
		Flags:                 0,
		OutputBufferLength:    bufferLen,
		FileId:                req.fd,
	}
	return req.add(p)
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
	return req.add(p)
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
	return req.add(p)
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
	return req.add(p)
}

func (req *requestBuilder) write(data []byte, offset uint64) *requestBuilder {
	p := &smb2.WriteRequest{
		Offset: offset,
		Flags:  0,
		FileId: req.fd,
		Data:   data,
	}
	return req.add(p)
}

func (req *requestBuilder) changeNotify(filter uint32, recursive bool, outputBufferLength uint32) *requestBuilder {
	flags := uint16(0)
	if recursive {
		flags = smb2.SMB2_WATCH_TREE
	}
	return req.add(&smb2.ChangeNotifyRequest{
		Flags:              flags,
		OutputBufferLength: outputBufferLength,
		FileId:             req.fd,
		CompletionFilter:   filter,
	})
}

func (req *requestBuilder) lock(locks []smb2.LockElement) *requestBuilder {
	return req.add(&smb2.LockRequest{
		FileId: req.fd,
		Locks:  locks,
	})
}

func (req *requestBuilder) sendRecv(ctx context.Context) (*response, error) {
	if len(req.pkts) == 0 {
		return nil, &InternalError{"empty compound request"}
	}

	createReq, hasCreate := req.pkts[0].(*smb2.CreateRequest)
	if !hasCreate {
		return req.sendRecvOnce(ctx)
	}

	name := createReq.Name
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		createReq.Name = name

		res, err := req.sendRecvOnce(ctx)
		if err != nil {
			var cerr *CompoundResponseError
			var rerr *ResponseError
			if errors.As(err, &cerr) {
				_ = errors.As(cerr.OpError(0), &rerr)
			} else {
				_ = errors.As(err, &rerr)
			}
			if rerr != nil && erref.NtStatus(rerr.Code) == erref.STATUS_STOPPED_ON_SYMLINK && len(rerr.data) > 0 && len(rerr.data[0]) > 0 {
				name, err = evalSymlinkError(createReq.Name, rerr.data[0])
				if err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}

		return res, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func (req *requestBuilder) sendRecvOnce(ctx context.Context) (*response, error) {
	res, err := req.tc.sendRecv(ctx, req.pkts...)
	if err != nil {
		if res != nil {
			req.tc.closeResponseFile(req.pkts, res)
			res.close()
		}
		return nil, err
	}
	return res, nil
}
