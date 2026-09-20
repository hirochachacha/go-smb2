package smb2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// ----------------------------------------------------------------------------
// Share Private Core Protocol Implementations (fd-aware)
// ----------------------------------------------------------------------------

func (fs *Share) statPath(ctx context.Context, name string, createOptions uint32) (os.FileInfo, error) {
	res, err := fs.Request().WithFollowSymlinks(true).
		Create(name, wire.FILE_READ_ATTRIBUTES, wire.FILE_OPEN, createOptions, wire.FILE_ATTRIBUTE_NORMAL).
		Close().
		Do(ctx)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	r, err := res.Create(0)
	if err != nil {
		return nil, err
	}
	return newFileStatFromCreateResponse(r, name), nil
}

func (fs *Share) stat(ctx context.Context, fd *wire.FileId, name string) (os.FileInfo, error) {
	if fd == nil {
		return fs.statPath(ctx, name, 0)
	}

	res, err := fs.Request().WithFollowSymlinks(true).
		WithFileID(fd).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileNetworkOpenInformation, 0, 56).
		Do(ctx)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	queryRes, err := res.QueryInfo(0)
	if err != nil {
		return nil, err
	}
	info, err := queryRes.FileNetworkOpenInformation()
	if err != nil {
		return nil, err
	}

	return newFileStatFromFileNetworkOpenInformation(info, name), nil
}

func (fs *Share) lstat(ctx context.Context, name string) (os.FileInfo, error) {
	return fs.statPath(ctx, name, wire.FILE_OPEN_REPARSE_POINT)
}

func (fs *Share) statfs(ctx context.Context, fd *wire.FileId, name string) (FileFsInfo, error) {
	req := fs.Request().WithFollowSymlinks(true)
	idx := 0
	if fd != nil {
		req.WithFileID(fd)
	} else {
		req.Create(name, wire.FILE_READ_ATTRIBUTES, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL)
		idx = 1
	}

	req.QueryInfo(wire.SMB2_0_INFO_FILESYSTEM, wire.FileFsFullSizeInformation, 0, 32)

	if fd == nil {
		req.Close()
	}

	res, err := req.Do(ctx)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	queryRes, err := res.QueryInfo(idx)
	if err != nil {
		return nil, err
	}
	return parseFsFullSizeInfo(queryRes)
}

func (fs *Share) truncate(ctx context.Context, fd *wire.FileId, name string, size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	req := fs.Request().WithFollowSymlinks(true)
	if fd != nil {
		req.WithFileID(fd)
	} else {
		req.Create(name, wire.FILE_WRITE_DATA, wire.FILE_OPEN, wire.FILE_NON_DIRECTORY_FILE, wire.FILE_ATTRIBUTE_NORMAL)
	}

	req.SetInfo(wire.SMB2_0_INFO_FILE, wire.FileEndOfFileInformation, 0, &wire.FileEndOfFileInformationEncoder{EndOfFile: size})

	if fd == nil {
		req.Close()
	}

	res, err := req.Do(ctx)
	if err != nil {
		return err
	}
	res.Close()
	return nil
}

func (fs *Share) chtimes(ctx context.Context, fd *wire.FileId, name string, atime time.Time, mtime time.Time) error {
	accessTime := wire.TimeToFiletime(atime)
	if !atime.IsZero() && accessTime == nil {
		return os.ErrInvalid
	}
	writeTime := wire.TimeToFiletime(mtime)
	if !mtime.IsZero() && writeTime == nil {
		return os.ErrInvalid
	}

	req := fs.Request().WithFollowSymlinks(true)
	if fd != nil {
		req.WithFileID(fd)
	} else {
		req.Create(name, wire.FILE_WRITE_ATTRIBUTES, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL)
	}

	req.SetInfo(wire.SMB2_0_INFO_FILE, wire.FileBasicInformation, 0, &wire.FileBasicInformationEncoder{
		LastAccessTime: accessTime,
		LastWriteTime:  writeTime,
	})

	if fd == nil {
		req.Close()
	}

	res, err := req.Do(ctx)
	if err != nil {
		return err
	}
	res.Close()
	return nil
}

func (fs *Share) chmod(ctx context.Context, fd *wire.FileId, name string, mode os.FileMode, followSymlink bool) error {
	req1 := fs.Request().WithFollowSymlinks(true)
	if fd != nil {
		req1.WithFileID(fd).QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileBasicInformation, 0, 40)
	} else {
		var options uint32
		if !followSymlink {
			options = wire.FILE_OPEN_REPARSE_POINT
		}
		req1.Create(name, wire.FILE_READ_ATTRIBUTES|wire.FILE_WRITE_ATTRIBUTES, wire.FILE_OPEN, options, wire.FILE_ATTRIBUTE_NORMAL)
	}

	// 1st RTT: CREATE or QUERY_INFO for an existing handle.
	res1, err := req1.Do(ctx)
	if err != nil {
		return err
	}
	defer res1.Close()

	var targetFd *wire.FileId
	var attrs uint32
	if fd != nil {
		targetFd = fd
		queryRes, err := res1.QueryInfo(0)
		if err != nil {
			return err
		}
		base, err := queryRes.FileBasicInformation()
		if err != nil {
			return err
		}
		attrs = base.FileAttributes()
	} else {
		createRes, err := res1.Create(0)
		if err != nil {
			return err
		}
		targetFd = createRes.FileId().Decode()
		attrs = createRes.FileAttributes()
	}

	attrs = computeChmodAttrs(attrs, mode)

	// 2nd RTT: SET_INFO
	// Keep SET_INFO separate from CLOSE. Some servers close the handle while
	// processing a related SET_INFO+CLOSE compound request for read-only files.
	res2, err := fs.Request().WithFollowSymlinks(true).
		WithFileID(targetFd).
		SetInfo(wire.SMB2_0_INFO_FILE, wire.FileBasicInformation, 0, &wire.FileBasicInformationEncoder{FileAttributes: attrs}).
		Do(ctx)
	if err != nil {
		if fd == nil {
			// This internal handle has no caller to retry cleanup after cancellation.
			_ = fs.closeFile(context.Background(), targetFd)
		}
		return err
	}
	res2.Close()

	if fd == nil {
		if err := fs.closeFile(context.Background(), targetFd); err != nil {
			return err
		}
		return ctx.Err()
	}

	return nil
}

func (fs *Share) flush(ctx context.Context, fd *wire.FileId) error {
	res, err := fs.Request().WithFollowSymlinks(true).WithFileID(fd).Flush().Do(ctx)
	if err != nil {
		return err
	}
	res.Close()

	return nil
}

func (fs *Share) readAtChunk(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxReadSize(0))
	if m == 0 {
		return 0, nil
	}
	job := ioPipelineJob{start: 0, end: m, off: off}
	res, err := fs.Request().Append(fs.makeReadRequest(fd, b, job)).Do(ctx)
	if err != nil {
		return fs.parseReadResponse(b, job, nil, err)
	}
	defer res.Close()
	return fs.parseReadResponse(b, job, res, nil)
}

func (fs *Share) readAtChunkAtLeast(ctx context.Context, fd *wire.FileId, b []byte, min int, off int64) (n int, err error) {
	if len(b) < min {
		return 0, io.ErrShortBuffer
	}
	for n < min {
		nn, err := fs.readAtChunk(ctx, fd, b[n:], off+int64(n))
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
				if nn > 0 {
					n += nn
					continue
				}
			}
			return n, err
		}
		if nn == 0 {
			return n, io.ErrUnexpectedEOF
		}
		n += nn
	}
	return n, nil
}

func (fs *Share) writeAtChunk(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxWriteSize(0))
	if m == 0 {
		return 0, nil
	}

	req := &wire.WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
		FileId:           fd,
	}

	res, err := fs.Request().Append(req).Do(ctx)
	if err != nil {
		return 0, err
	}
	defer res.Close()

	return parseWriteResponse(res, m)
}

func parseWriteResponse(rp *protocol.Response, requested int) (int, error) {
	r, err := rp.Write(0)
	if err != nil {
		return 0, err
	}
	if r.Count() < uint32(requested) {
		return int(r.Count()), io.ErrShortWrite
	}
	return int(r.Count()), nil
}

func (fs *Share) readdir(ctx context.Context, fd *wire.FileId, pattern string) (fi []os.FileInfo, err error) {
	dotOnlyPages := 0
	for {
		res, err := fs.Request().WithFollowSymlinks(true).
			WithFileID(fd).
			QueryDir(wire.FileIdBothDirectoryInformation, pattern, maxSingleCreditPayloadSize).
			Do(ctx)
		if err != nil {
			return nil, err
		}

		r, err := res.QueryDir(0)
		if err != nil {
			res.Close()
			return nil, err
		}
		entries, err := r.FileIdBothDirectoryInformation()
		if err != nil {
			res.Close()
			return nil, err
		}
		outputEmpty := len(entries) == 0
		fi := parseDirectoryEntries(entries)
		res.Close()
		if outputEmpty || len(fi) > 0 {
			return fi, nil
		}

		// [MS-FSA] 2.1.5.6.3 treats "." and ".." as enumeration records and
		// advances QueryLastEntry for each response; bound a server that does
		// not make that progress after three dot-only pages.
		dotOnlyPages++
		if dotOnlyPages == 3 {
			return nil, errors.New("query directory returned only dot entries")
		}
	}
}

func (fs *Share) ioctl(ctx context.Context, fd *wire.FileId, req *wire.IoctlRequest) (output []byte, err error) {
	req.FileId = fd

	res, err := fs.Request().Append(req).Do(ctx)
	if err != nil {
		if data, ok := protocol.BufferOverflowData(err); ok {
			return data, err
		}
		return nil, err
	}
	defer res.Close()

	r, err := res.Ioctl(0)
	if err != nil {
		return nil, err
	}

	return append([]byte(nil), r.Output()...), nil
}

func validFileRange(off int64, size int) bool {
	return off >= 0 && (size == 0 || int64(size-1) <= math.MaxInt64-off)
}

func (fs *Share) maxReadSize(companions int) int {
	return fs.treeConn.MaxReadSize(companions)
}

func (fs *Share) maxWriteSize(companions int) int {
	return fs.treeConn.MaxWriteSize(companions)
}

func (fs *Share) maxTransactSize(companions int) int {
	return fs.treeConn.MaxTransactSize(companions)
}

func (fs *Share) ioPipelineDepth() uint { return fs.treeConn.IOPipelineDepth() }

type ioPipelineJob struct {
	start int
	end   int
	off   int64
	req   wire.Packet
}

type ioPipelineSend struct {
	job ioPipelineJob
	rr  *protocol.PendingRequest
	err error
}

// runIOPipeline sends at most IOPipelineDepth requests ahead of the ordered
// response collector. The sender is the only goroutine; the caller releases a
// bounded outstanding-request token after each response.
func (fs *Share) runIOPipeline(ctx context.Context, next func() (ioPipelineJob, bool), handle func(context.Context, ioPipelineJob, *protocol.Response, error) error) error {
	pipeCtx, stop := context.WithCancel(ctx)
	defer stop()
	depth := fs.ioPipelineDepth()
	tokens := make(chan struct{}, depth)
	sends := make(chan ioPipelineSend, depth)
	go func() {
		defer close(sends)
		for {
			job, ok := next()
			if !ok {
				return
			}
			select {
			case tokens <- struct{}{}:
			case <-pipeCtx.Done():
				return
			}
			pending, err := fs.Request().Append(job.req).Send(pipeCtx)
			if err != nil {
				<-tokens
				sends <- ioPipelineSend{job: job, err: err}
				return
			}
			// A successful send is always published before the sender observes
			// cancellation, so the caller can drain its outstanding request.
			sends <- ioPipelineSend{job: job, rr: pending}
		}
	}()

	var firstErr error
	stopPipeline := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
		stop()
	}
	for sent := range sends {
		if sent.err != nil {
			stopPipeline(sent.err)
			break
		}
		rp, recvErr := sent.rr.Receive()
		err := handle(pipeCtx, sent.job, rp, recvErr)
		if err != nil {
			stopPipeline(err)
			<-tokens
			break
		}
		<-tokens
	}

	// Cancellation may leave successful sends in the channel. Drain every one
	// before returning, including direct READs and caller-owned WRITE buffers.
	for sent := range sends {
		if sent.rr == nil {
			continue
		}
		rp, _ := sent.rr.Receive()
		if rp != nil {
			rp.Close()
		}
		<-tokens
	}
	if firstErr == nil && ctx.Err() != nil {
		firstErr = ctx.Err()
	}
	return firstErr
}

func (fs *Share) makeReadRequest(fd *wire.FileId, b []byte, job ioPipelineJob) wire.Packet {
	remaining := job.end - job.start
	buf := b[job.start:job.end]
	req := &wire.ReadRequest{
		Padding:         0,
		Flags:           0,
		Length:          uint32(remaining),
		Offset:          uint64(job.off),
		MinimumCount:    1,
		Channel:         0,
		RemainingBytes:  0,
		ReadChannelInfo: nil,
		FileId:          fd,
	}
	if remaining >= clientMinBufSize {
		// Bound the direct-receive buffer to the requested Length so a server
		// cannot copy more than Length bytes into b. [MS-SMB2] 3.3.5.12
		// requires the response DataLength to be capped at the requested Length.
		return &protocol.DirectReadRequest{ReadRequest: req, Buffer: buf}
	}
	return req
}

// readAt fills the requested range concurrently by fixed, non-overlapping
// chunks. A short successful response is retried only inside its assigned
// chunk, so out-of-order responses cannot overlap a neighboring range.
func (fs *Share) readAt(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	maxChunk := fs.maxReadSize(0)
	if maxChunk <= 0 {
		return 0, fmt.Errorf("smb2: invalid maximum read size: %w", os.ErrInvalid)
	}
	if fs.ioPipelineDepth() == 1 || (fs.treeConn.ShareType() != 0 && fs.treeConn.ShareType() != wire.SMB2_SHARE_TYPE_DISK) || len(b) <= maxChunk {
		return fs.readAtSequential(ctx, fd, b, off)
	}

	start := 0
	next := func() (ioPipelineJob, bool) {
		if start >= len(b) {
			return ioPipelineJob{}, false
		}
		end := start + min(maxChunk, len(b)-start)
		job := ioPipelineJob{start: start, end: end, off: off + int64(start)}
		job.req = fs.makeReadRequest(fd, b, job)
		start = end
		return job, true
	}
	handle := func(pipeCtx context.Context, job ioPipelineJob, rp *protocol.Response, recvErr error) error {
		readN, readErr := fs.parseReadResponse(b, job, rp, recvErr)
		n += readN
		if rp != nil {
			rp.Close()
		}
		if readErr == nil && readN < job.end-job.start {
			more, moreErr := fs.readAtSequential(pipeCtx, fd,
				b[job.start+readN:job.end],
				job.off+int64(readN))
			n += more
			return moreErr
		}
		if errors.Is(readErr, erref.STATUS_BUFFER_OVERFLOW) && readN > 0 {
			more, moreErr := fs.readAtSequential(pipeCtx, fd,
				b[job.start+readN:job.end],
				job.off+int64(readN))
			n += more
			if moreErr != nil {
				return moreErr
			}
			return nil
		}
		if errors.Is(readErr, erref.STATUS_END_OF_FILE) {
			return io.EOF
		}
		return readErr
	}
	err = fs.runIOPipeline(ctx, next, handle)
	return n, err
}

func (fs *Share) readAtSequential(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	for n < len(b) {
		readN, readErr := fs.readAtChunk(ctx, fd, b[n:], off+int64(n))
		n += readN
		if readErr != nil {
			if errors.Is(readErr, erref.STATUS_END_OF_FILE) {
				return n, io.EOF
			}
			if errors.Is(readErr, erref.STATUS_BUFFER_OVERFLOW) && readN > 0 {
				continue
			}
			return n, readErr
		}
	}
	return n, nil
}

func (fs *Share) parseReadResponse(b []byte, job ioPipelineJob, rp *protocol.Response, recvErr error) (int, error) {
	if recvErr != nil {
		if data, ok := protocol.BufferOverflowData(recvErr); ok {
			copy(b[job.start:], data)
			return len(data), recvErr
		}
		return 0, recvErr
	}
	if ext := rp.DirectData(0); ext != nil {
		return len(ext), nil
	}
	r, err := rp.Read(0)
	if err != nil {
		return 0, err
	}
	data := r.Data()
	copy(b[job.start:], data)
	return len(data), nil
}

func (fs *Share) read(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	readN, err := fs.readAtChunk(ctx, fd, b, off)
	if err != nil {
		if status, ok := errors.AsType[erref.NtStatus](err); ok {
			switch status {
			case erref.STATUS_END_OF_FILE:
				return 0, io.EOF
			case erref.STATUS_BUFFER_OVERFLOW:
				if readN > 0 {
					return readN, nil
				}
			}
		}
		return 0, err
	}
	return readN, nil
}

func (fs *Share) writeAt(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	maxChunk := fs.maxWriteSize(0)
	if maxChunk <= 0 {
		return 0, fmt.Errorf("smb2: invalid maximum write size: %w", os.ErrInvalid)
	}
	if fs.ioPipelineDepth() == 1 || (fs.treeConn.ShareType() != 0 && fs.treeConn.ShareType() != wire.SMB2_SHARE_TYPE_DISK) || len(b) <= maxChunk {
		return fs.writeAtSequential(ctx, fd, b, off)
	}
	// Requests already sent for later offsets may complete after an earlier
	// request fails. They are drained before returning, while n reports only
	// the contiguous prefix through the first failed offset.
	start := 0
	next := func() (ioPipelineJob, bool) {
		if start >= len(b) {
			return ioPipelineJob{}, false
		}
		end := start + min(maxChunk, len(b)-start)
		job := ioPipelineJob{
			start: start,
			end:   end,
			off:   off + int64(start),
			req: &wire.WriteRequest{
				Flags:            0,
				Channel:          0,
				RemainingBytes:   0,
				Offset:           uint64(off + int64(start)),
				WriteChannelInfo: nil,
				Data:             b[start:end],
				FileId:           fd,
			},
		}
		start = end
		return job, true
	}
	handle := func(_ context.Context, job ioPipelineJob, rp *protocol.Response, recvErr error) error {
		if recvErr != nil {
			return recvErr
		}
		defer rp.Close()
		count, err := parseWriteResponse(rp, job.end-job.start)
		n += count
		return err
	}
	err = fs.runIOPipeline(ctx, next, handle)
	return n, err
}

func (fs *Share) writeAtSequential(ctx context.Context, fd *wire.FileId, b []byte, off int64) (n int, err error) {
	for n < len(b) {
		written, writeErr := fs.writeAtChunk(ctx, fd, b[n:], off+int64(n))
		n += written
		if writeErr != nil {
			return n, writeErr
		}
	}
	return n, nil
}

func (fs *Share) copyFile(ctx context.Context, srcFd, dstFd *wire.FileId, srcName, dstName string, srcOffset, dstOffset int64, dstReadAccess bool) (supported bool, n int64, err error) {
	// [MS-SMB2] 2.2.31: FSCTL_SRV_COPYCHUNK requires FILE_READ_DATA on the
	// destination handle, while FSCTL_SRV_COPYCHUNK_WRITE only requires write
	// access. Choose the strongest code the destination handle permits.
	copyCtlCode := uint32(wire.FSCTL_SRV_COPYCHUNK_WRITE)
	if dstReadAccess {
		copyCtlCode = wire.FSCTL_SRV_COPYCHUNK
	}

	if srcOffset < 0 || dstOffset < 0 {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: os.ErrInvalid}
	}

	req := &wire.IoctlRequest{
		FileId:            srcFd,
		CtlCode:           wire.FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             wire.SMB2_0_IOCTL_IS_FSCTL,
	}

	res, err := fs.Request().WithFileID(srcFd).Append(req).Do(ctx)
	if err != nil {
		// [MS-SMB2] 3.3.5.15 recommends these statuses for FSCTLs not allowed
		// on the server or unsupported by the filesystem, respectively.
		// The resume key request has not copied any bytes, so fallback is safe.
		if errors.Is(err, erref.STATUS_NOT_SUPPORTED) || errors.Is(err, erref.STATUS_INVALID_DEVICE_REQUEST) {
			return false, 0, nil
		}

		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	defer res.Close()

	ioctlRes, err := res.Ioctl(0)
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	sr, err := ioctlRes.SrvRequestResumeKey()
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}

	infoRes, err := fs.Request().WithFollowSymlinks(true).WithFileID(srcFd).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).
		Do(ctx)
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	defer infoRes.Close()

	queryRes, err := infoRes.QueryInfo(0)
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	info, err := queryRes.FileStandardInformation()
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}

	end := info.EndOfFile()
	off := srcOffset
	woff := dstOffset

	if end <= off {
		return true, 0, nil
	}

	remains := end - off
	if remains > math.MaxInt64-dstOffset {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: os.ErrInvalid}
	}
	// [MS-SMB2] 2.2.31.1.1 defines these as offsets from each file's start.
	// Nonnegative offsets, a nonnegative EndOfFile, and the full-range check
	// keep every chunk offset and the final file position within int64.

	var srvChunks [16]wire.SrvCopychunk
	var chunks [16]*wire.SrvCopychunk
	for i := range chunks {
		chunks[i] = &srvChunks[i]
	}

	for {
		var reqChunks []*wire.SrvCopychunk

		if remains < clientMaxCopyTotalSize {
			nchunks := remains / clientMaxCopyChunkSize
			for i := int64(0); i < nchunks; i++ {
				srvChunks[i] = wire.SrvCopychunk{
					SourceOffset: off + i*clientMaxCopyChunkSize,
					TargetOffset: woff + i*clientMaxCopyChunkSize,
					Length:       clientMaxCopyChunkSize,
				}
			}

			remains %= clientMaxCopyChunkSize
			if remains != 0 {
				srvChunks[nchunks] = wire.SrvCopychunk{
					SourceOffset: off + nchunks*clientMaxCopyChunkSize,
					TargetOffset: woff + nchunks*clientMaxCopyChunkSize,
					Length:       uint32(remains),
				}
				nchunks++
				remains = 0
			}

			reqChunks = chunks[:nchunks]
		} else {
			for i := range int64(16) {
				srvChunks[i] = wire.SrvCopychunk{
					SourceOffset: off + i*clientMaxCopyChunkSize,
					TargetOffset: woff + i*clientMaxCopyChunkSize,
					Length:       clientMaxCopyChunkSize,
				}
			}

			reqChunks = chunks[:16]
			remains -= clientMaxCopyTotalSize
			off += clientMaxCopyTotalSize
			woff += clientMaxCopyTotalSize
		}

		scc := &wire.SrvCopychunkCopy{
			Chunks: reqChunks,
		}

		copy(scc.SourceKey[:], sr.ResumeKey())

		cReq := &wire.IoctlRequest{
			FileId:            dstFd,
			CtlCode:           copyCtlCode,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             wire.SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		copyRes, err := fs.Request().WithFileID(dstFd).Append(cReq).Do(ctx)
		if err != nil {
			// [MS-SMB2] 3.3.5.15: STATUS_NOT_SUPPORTED is the server-wide
			// "unknown FSCTL" answer and STATUS_INVALID_DEVICE_REQUEST is the
			// filesystem-wide "unsupported FSCTL" answer. Only the WRITE
			// variant may fall back to a buffered copy, and only before any
			// byte was transferred. ACCESS_DENIED is not an unsupported
			// signal and must be surfaced as-is.
			if copyCtlCode == wire.FSCTL_SRV_COPYCHUNK_WRITE && n == 0 &&
				(errors.Is(err, erref.STATUS_NOT_SUPPORTED) || errors.Is(err, erref.STATUS_INVALID_DEVICE_REQUEST)) {
				return false, 0, nil
			}

			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
		}

		copyIoctl, decodeErr := copyRes.Ioctl(0)
		if decodeErr != nil {
			copyRes.Close()
			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: decodeErr}
		}
		c, decodeErr := copyIoctl.SrvCopychunk()
		written := uint32(0)
		if decodeErr == nil {
			written = c.TotalBytesWritten()
		}
		copyRes.Close()
		if decodeErr != nil {
			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: decodeErr}
		}

		n += int64(written)

		if remains == 0 {
			return true, n, nil
		}
	}
}

func (fs *Share) closeFile(ctx context.Context, fd *wire.FileId) error {
	return fs.treeConn.CloseFile(ctx, fd)
}
