package smb2

import (
	"context"

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

func (req *requestBuilder) setInfo(infoClass uint8, input smb2.Encoder) *requestBuilder {
	p := &smb2.SetInfoRequest{
		InfoType:              smb2.SMB2_0_INFO_FILE,
		FileInfoClass:         infoClass,
		AdditionalInformation: 0,
		FileId:                req.fd,
		Input:                 input,
	}
	return req.add(p)
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

func (req *requestBuilder) sendRecv(ctx context.Context) (*response, error) {
	if len(req.pkts) == 0 {
		return nil, &InternalError{"empty compound request"}
	}

	return req.tc.sendRecv(ctx, req.pkts...)
}
