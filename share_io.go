package smb2

import (
	"context"
	"errors"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

// ----------------------------------------------------------------------------
// Share Private Core Protocol Implementations (fd-aware)
// ----------------------------------------------------------------------------

func (fs *Share) createFile(ctx context.Context, name string, req *smb2.CreateRequest, appendMode bool) (f *File, err error) {
	req.Name = name
	res, err := fs.request().add(req).sendRecv(ctx)
	if err != nil {
		return nil, err
	}
	r := smb2.CreateResponseDecoder(res.data(0))
	f = fs.newFile(r, req.Name)
	if appendMode {
		f.offset = r.EndofFile()
	}
	// Record whether the open granted read data access so copyFile can pick
	// the copy IOCTL the destination handle is allowed to use ([MS-SMB2]
	// 2.2.31, 3.2.5.15.6).
	f.readAccess = req.DesiredAccess&(smb2.FILE_READ_DATA|smb2.GENERIC_READ|smb2.GENERIC_ALL) != 0
	res.close()
	return f, nil
}

func (req *requestBuilder) resolveSymlink(ctx context.Context, name string, rerr *ResponseError, data []byte) (string, error) {
	d := smb2.SymbolicLinkErrorResponseDecoder(data)
	// d.IsInvalid() validates the Symbolic Link Error Response according to
	// [MS-SMB2] 2.2.2.2.1: structure sizes, tags, valid flags (absolute 0 or
	// SYMLINK_FLAG_RELATIVE), non-empty substitute name, relative un-rooted
	// format, and remote UNC format for absolute targets.
	// d.SubstituteName() returns the target path normalized by stripping
	// device LongNamePrefix ("\\?\", "\??\") and converting device UNC
	// prefixes ("\\?\UNC\", "\??\UNC\") to standard UNC ("\\") format.
	if d.IsInvalid() {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}
	ud, suffix := d.SplitUnparsedPath(name)
	if ud == "" && suffix == "" {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}
	target := d.SubstituteName()
	relative := d.Flags()&smb2.SYMLINK_FLAG_RELATIVE != 0
	resolved := ""
	if relative {
		var err error
		resolved, err = resolveRelativeLink(ud, target, suffix)
		if err != nil {
			return "", err
		}
		if utf16le.EncodedStringLen(resolved) > math.MaxUint16 {
			return "", &InternalError{"resolved symbolic link path exceeds uint16"}
		}
		return resolved, nil
	}
	resolved = target + suffix
	normalized, ok := normalizeAbsoluteUNC(resolved)
	if !ok {
		return "", &InvalidResponseError{"symbolic link target is not a valid UNC path"}
	}
	resolved = normalized
	if utf16le.EncodedStringLen(resolved) > math.MaxUint16 {
		return "", &InternalError{"resolved symbolic link path exceeds uint16"}
	}
	server, share, rest, ok := parseUNCPath(resolved)
	if !ok {
		return "", &InvalidResponseError{"symbolic link target is not a UNC path"}
	}
	if strings.EqualFold(server, req.tc.serverName) && strings.EqualFold(share, req.tc.shareName) {
		return rest, nil
	}
	return "", &SymlinkError{Path: req.tc.uncPath(name), Target: target, Relative: false, UnparsedPath: suffix, ResolvedPath: resolved, err: rerr}
}

func parseUNCPath(path string) (server, share, rest string, ok bool) {
	p, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", "", "", false
	}
	parts := strings.Split(p, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	for i, part := range parts {
		if part == "" {
			if i == len(parts)-1 {
				continue // A trailing separator names the share root.
			}
			return "", "", "", false
		}
		if part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return "", "", "", false
		}
	}
	server, share = parts[0], parts[1]
	if len(parts) > 2 {
		rest = strings.Join(parts[2:], `\`)
	}
	return server, share, rest, true
}

func normalizeAbsoluteUNC(path string) (string, bool) {
	p, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", false
	}
	parts := strings.Split(p, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	for _, part := range parts[:2] {
		if part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return "", false
		}
	}
	clean := append([]string(nil), parts[:2]...)
	for _, part := range parts[2:] {
		switch part {
		case "":
			continue
		case ".":
		case "..":
			if len(clean) <= 2 {
				continue
			}
			clean = clean[:len(clean)-1]
		default:
			if strings.ContainsAny(part, "/:\x00") {
				return "", false
			}
			clean = append(clean, part)
		}
	}
	return pathpkg.JoinUNC(clean[0], clean[1], clean[2:]...), true
}

func resolveRelativeLink(linkPath, target, suffix string) (string, error) {
	stack := pathpkg.SplitAll(pathpkg.Dir(linkPath))
	targetParts := strings.Split(strings.ReplaceAll(target, `/`, `\`), `\`)
	for i, p := range targetParts {
		switch p {
		case ".":
		case "":
			if i != 0 && i != len(targetParts)-1 {
				return "", &InvalidResponseError{"relative symbolic link target has an empty component"}
			}
		case "..":
			if len(stack) == 0 {
				return "", &InvalidResponseError{"symbolic link escapes share root"}
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(p, ':') {
				return "", &InvalidResponseError{"relative symbolic link target contains a drive separator"}
			}
			stack = append(stack, p)
		}
	}
	for _, p := range pathpkg.SplitAll(suffix) {
		switch p {
		case ".":
		case "..":
			if len(stack) == 0 {
				return "", &InvalidResponseError{"symbolic link suffix escapes share root"}
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(p, ':') {
				return "", &InvalidResponseError{"symbolic link suffix contains a drive separator"}
			}
			stack = append(stack, p)
		}
	}
	return pathpkg.Join(stack...), nil
}

func (fs *Share) sendRecv(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	return fs.treeConn.sendRecv(ctx, reqs...)
}

// ----------------------------------------------------------------------------
// Share Private Core Protocol Implementations (fd-aware)
// ----------------------------------------------------------------------------

func (fs *Share) statPath(ctx context.Context, name string, createOptions uint32) (os.FileInfo, error) {
	res, err := fs.request().
		create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, createOptions, smb2.FILE_ATTRIBUTE_NORMAL).
		close().
		sendRecv(ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	r := smb2.CreateResponseDecoder(res.data(0))
	return newFileStatFromCreateResponse(r, name), nil
}

func (fs *Share) stat(ctx context.Context, fd *smb2.FileId, name string) (os.FileInfo, error) {
	if fd == nil {
		return fs.statPath(ctx, name, 0)
	}

	res, err := fs.request().
		withFileId(fd).
		queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileNetworkOpenInformation, 0, 56).
		sendRecv(ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	info := smb2.FileNetworkOpenInformationDecoder(smb2.QueryInfoResponseDecoder(res.data(0)).Output())
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return newFileStatFromFileNetworkOpenInformation(info, name), nil
}

func (fs *Share) lstat(ctx context.Context, name string) (os.FileInfo, error) {
	return fs.statPath(ctx, name, smb2.FILE_OPEN_REPARSE_POINT)
}

func (fs *Share) statfs(ctx context.Context, fd *smb2.FileId, name string) (FileFsInfo, error) {
	req := fs.request()
	idx := 0
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
		idx = 1
	}

	req.queryInfo(smb2.SMB2_0_INFO_FILESYSTEM, smb2.FileFsFullSizeInformation, 0, 32)

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	return parseFsFullSizeInfo(res.data(idx))
}

func (fs *Share) truncate(ctx context.Context, fd *smb2.FileId, name string, size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	req := fs.request()
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_WRITE_DATA, smb2.FILE_OPEN, smb2.FILE_NON_DIRECTORY_FILE, smb2.FILE_ATTRIBUTE_NORMAL)
	}

	req.setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileEndOfFileInformation, 0, &smb2.FileEndOfFileInformationEncoder{EndOfFile: size})

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(ctx)
	if err != nil {
		return err
	}
	res.close()
	return nil
}

func validateChtimesTime(t time.Time) error {
	if t.IsZero() {
		return nil
	}
	if smb2.TimeToFiletime(t) == nil {
		return os.ErrInvalid
	}
	return nil
}

func (fs *Share) chtimes(ctx context.Context, fd *smb2.FileId, name string, atime time.Time, mtime time.Time) error {
	accessTime := smb2.TimeToFiletime(atime)
	if !atime.IsZero() && accessTime == nil {
		return os.ErrInvalid
	}
	writeTime := smb2.TimeToFiletime(mtime)
	if !mtime.IsZero() && writeTime == nil {
		return os.ErrInvalid
	}

	req := fs.request()
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
	}

	req.setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileBasicInformation, 0, &smb2.FileBasicInformationEncoder{
		LastAccessTime: accessTime,
		LastWriteTime:  writeTime,
	})

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(ctx)
	if err != nil {
		return err
	}
	res.close()
	return nil
}

func (fs *Share) chmod(ctx context.Context, fd *smb2.FileId, name string, mode os.FileMode, followSymlink bool) error {
	req1 := fs.request()
	if fd != nil {
		req1.withFileId(fd).queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileBasicInformation, 0, 40)
	} else {
		var options uint32
		if !followSymlink {
			options = smb2.FILE_OPEN_REPARSE_POINT
		}
		req1.create(name, smb2.FILE_READ_ATTRIBUTES|smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_OPEN, options, smb2.FILE_ATTRIBUTE_NORMAL)
	}

	// 1st RTT: CREATE or QUERY_INFO for an existing handle.
	res1, err := req1.sendRecv(ctx)
	if err != nil {
		return err
	}
	defer res1.close()

	var targetFd *smb2.FileId
	var attrs uint32
	if fd != nil {
		targetFd = fd
		base := smb2.FileBasicInformationDecoder(smb2.QueryInfoResponseDecoder(res1.data(0)).Output())
		if base.IsInvalid() {
			return &InvalidResponseError{"broken query info response format"}
		}
		attrs = base.FileAttributes()
	} else {
		createRes := smb2.CreateResponseDecoder(res1.data(0))
		targetFd = createRes.FileId().Decode()
		attrs = createRes.FileAttributes()
	}

	attrs = computeChmodAttrs(attrs, mode)

	// 2nd RTT: SET_INFO
	// Keep SET_INFO separate from CLOSE. Some servers close the handle while
	// processing a related SET_INFO+CLOSE compound request for read-only files.
	res2, err := fs.request().
		withFileId(targetFd).
		setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileBasicInformation, 0, &smb2.FileBasicInformationEncoder{FileAttributes: attrs}).
		sendRecv(ctx)
	if err != nil {
		if fd == nil {
			// This internal handle has no caller to retry cleanup after cancellation.
			_ = fs.closeFile(context.Background(), targetFd)
		}
		return err
	}
	res2.close()

	if fd == nil {
		if err := fs.closeFile(context.Background(), targetFd); err != nil {
			return err
		}
		return ctx.Err()
	}

	return nil
}

func (fs *Share) flush(ctx context.Context, fd *smb2.FileId) error {
	res, err := fs.request().withFileId(fd).flush().sendRecv(ctx)
	if err != nil {
		return err
	}
	res.close()

	return nil
}

// for direct I/O
type directReadRequest struct {
	*smb2.ReadRequest

	b []byte
}

func (fs *Share) readAtChunk(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxReadSize(0))
	if m == 0 {
		return 0, nil
	}
	job := ioPipelineJob{start: 0, end: m, off: off}
	res, err := fs.sendRecv(ctx, fs.makeReadRequest(fd, b, job))
	if err != nil {
		return fs.parseReadResponse(b, job, nil, err)
	}
	defer res.close()
	return fs.parseReadResponse(b, job, res.packet(0), nil)
}

func (fs *Share) readAtChunkAtLeast(ctx context.Context, fd *smb2.FileId, b []byte, min int, off int64) (n int, err error) {
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

func (fs *Share) readRpcFrag(ctx context.Context, fd *smb2.FileId, initial, buf []byte, callId uint32) (pdu, rem []byte, err error) {
	pdu = initial
	if len(pdu) < 24 {
		n, err := fs.readAtChunkAtLeast(ctx, fd, buf, 24-len(pdu), 0)
		if err != nil {
			return nil, nil, err
		}
		pdu = append(pdu, buf[:n]...)
	}

	header := msrpc.ResponseHeaderDecoder(pdu)
	if header.IsInvalid() || header.CallId() != callId {
		return nil, nil, &InvalidResponseError{"broken net share enum response format"}
	}

	fragLen := int(header.FragLength())
	if len(pdu) < fragLen {
		n, err := fs.readAtChunkAtLeast(ctx, fd, buf, fragLen-len(pdu), 0)
		if err != nil {
			return nil, nil, err
		}
		pdu = append(pdu, buf[:n]...)
	}
	return pdu[:fragLen], pdu[fragLen:], nil
}

func (fs *Share) writeAtChunk(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxWriteSize(0))
	if m == 0 {
		return 0, nil
	}

	req := &smb2.WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
		FileId:           fd,
	}

	res, err := fs.sendRecv(ctx, req)
	if err != nil {
		return 0, err
	}
	defer res.close()

	return parseWriteResponse(res.packet(0), m)
}

func parseWriteResponse(rp *recvPacket, requested int) (int, error) {
	r := smb2.WriteResponseDecoder(rp.data())
	if r.Count() > uint32(requested) {
		return 0, &InvalidResponseError{"write count exceeds requested length"}
	}
	if r.Count() < uint32(requested) {
		return int(r.Count()), io.ErrShortWrite
	}
	return int(r.Count()), nil
}

func (fs *Share) readdir(ctx context.Context, fd *smb2.FileId, pattern string) (fi []os.FileInfo, err error) {
	dotOnlyPages := 0
	for {
		res, err := fs.request().
			withFileId(fd).
			queryDir(smb2.FileIdBothDirectoryInformation, pattern, maxSingleCreditPayloadSize).
			sendRecv(ctx)
		if err != nil {
			return nil, err
		}

		r := smb2.QueryDirectoryResponseDecoder(res.data(0))
		output := r.Output()
		outputEmpty := len(output) == 0
		fi, err := parseReaddir(output)
		res.close()
		if err != nil || outputEmpty || len(fi) > 0 {
			return fi, err
		}

		// [MS-FSA] 2.1.5.6.3 treats "." and ".." as enumeration records and
		// advances QueryLastEntry for each response; bound a server that does
		// not make that progress after three dot-only pages.
		dotOnlyPages++
		if dotOnlyPages == 3 {
			return nil, &InvalidResponseError{"query directory returned only dot entries"}
		}
	}
}

func (fs *Share) ioctl(ctx context.Context, fd *smb2.FileId, req *smb2.IoctlRequest) (output []byte, err error) {
	req.FileId = fd

	res, err := fs.sendRecv(ctx, req)
	if err != nil {
		if data, ok := bufferOverflowData(err); ok {
			return data, err
		}
		return nil, err
	}
	defer res.close()

	r := smb2.IoctlResponseDecoder(res.data(0))

	return append([]byte(nil), r.Output()...), nil
}

func (fs *Share) queryInfo(ctx context.Context, fd *smb2.FileId, infoType, infoClass uint8, maxOutput uint32) (output []byte, err error) {
	req := &smb2.QueryInfoRequest{
		InfoType:              infoType,
		FileInfoClass:         infoClass,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    maxOutput,
		FileId:                fd,
	}

	res, err := fs.sendRecv(ctx, req)
	if err != nil {
		if data, ok := bufferOverflowData(err); ok {
			return data, err
		}
		return nil, err
	}
	defer res.close()

	r := smb2.QueryInfoResponseDecoder(res.data(0))

	return append([]byte(nil), r.Output()...), nil
}

func validFileRange(off int64, size int) bool {
	return off >= 0 && (size == 0 || int64(size-1) <= math.MaxInt64-off)
}

func (fs *Share) maxReadSize(companions int) int {
	return fs.conn.effectivePayloadSize(fs.conn.maxReadSize, companions)
}

func (fs *Share) maxWriteSize(companions int) int {
	return fs.conn.effectivePayloadSize(fs.conn.maxWriteSize, companions)
}

func (fs *Share) maxTransactSize(companions int) int {
	return fs.conn.effectivePayloadSize(fs.conn.maxTransactSize, companions)
}

func (fs *Share) ioPipelineDepth() uint {
	if fs.conn.ioPipelineDepth == 0 {
		return clientIOPipelineDepth
	}
	return fs.conn.ioPipelineDepth
}

type ioPipelineJob struct {
	start int
	end   int
	off   int64
	req   smb2.Packet
}

type ioPipelineSend struct {
	job ioPipelineJob
	rr  *outstandingRequest
	err error
}

// runIOPipeline sends at most IOPipelineDepth requests ahead of the ordered
// response collector. The sender is the only goroutine; the caller releases a
// bounded outstanding-request token after each response.
func (fs *Share) runIOPipeline(ctx context.Context, next func() (ioPipelineJob, bool), handle func(context.Context, ioPipelineJob, *recvPacket, error) error) error {
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
			rrs, err := fs.treeConn.send(pipeCtx, job.req)
			if err != nil {
				<-tokens
				sends <- ioPipelineSend{job: job, err: err}
				return
			}
			// A successful send is always published before the sender observes
			// cancellation, so the caller can drain its outstanding request.
			sends <- ioPipelineSend{job: job, rr: rrs[0]}
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
		rp, recvErr := fs.treeConn.recv(sent.rr)
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
		rp, _ := fs.treeConn.recv(sent.rr)
		if rp != nil {
			rp.close()
		}
		<-tokens
	}
	if firstErr == nil && ctx.Err() != nil {
		firstErr = ctx.Err()
	}
	return firstErr
}

func (fs *Share) makeReadRequest(fd *smb2.FileId, b []byte, job ioPipelineJob) smb2.Packet {
	remaining := job.end - job.start
	buf := b[job.start:job.end]
	req := &smb2.ReadRequest{
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
		return &directReadRequest{ReadRequest: req, b: buf}
	}
	return req
}

// readAt fills the requested range concurrently by fixed, non-overlapping
// chunks. A short successful response is retried only inside its assigned
// chunk, so out-of-order responses cannot overlap a neighboring range.
func (fs *Share) readAt(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	maxChunk := fs.maxReadSize(0)
	if fs.ioPipelineDepth() == 1 || (fs.treeConn.shareType != 0 && fs.treeConn.shareType != smb2.SMB2_SHARE_TYPE_DISK) || len(b) <= maxChunk {
		return fs.readAtSequential(ctx, fd, b, off)
	}
	if maxChunk <= 0 {
		return 0, &InternalError{"invalid maximum read size"}
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
	handle := func(pipeCtx context.Context, job ioPipelineJob, rp *recvPacket, recvErr error) error {
		readN, readErr := fs.parseReadResponse(b, job, rp, recvErr)
		n += readN
		if rp != nil {
			rp.close()
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

func (fs *Share) readAtSequential(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
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

func (fs *Share) parseReadResponse(b []byte, job ioPipelineJob, rp *recvPacket, recvErr error) (int, error) {
	requested := job.end - job.start
	if recvErr != nil {
		if data, ok := bufferOverflowData(recvErr); ok {
			if len(data) > requested {
				return 0, &InvalidResponseError{"read length exceeds requested length"}
			}
			copy(b[job.start:], data)
			return len(data), recvErr
		}
		return 0, recvErr
	}
	r := smb2.ReadResponseDecoder(rp.data())
	if r.HasInvalidFlags(fs.dialect) {
		return 0, invalidNetworkResponseError()
	}
	if ext := rp.ext; ext != nil {
		if len(ext) == 0 {
			return 0, &InvalidResponseError{"empty successful read response"}
		}
		return len(ext), nil
	}
	data := r.Data()
	if len(data) == 0 {
		return 0, &InvalidResponseError{"empty successful read response"}
	}
	if len(data) > requested {
		return 0, &InvalidResponseError{"read length exceeds requested length"}
	}
	copy(b[job.start:], data)
	return len(data), nil
}

func (fs *Share) read(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
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

func (fs *Share) writeAt(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	maxChunk := fs.maxWriteSize(0)
	if fs.ioPipelineDepth() == 1 || (fs.treeConn.shareType != 0 && fs.treeConn.shareType != smb2.SMB2_SHARE_TYPE_DISK) || len(b) <= maxChunk {
		return fs.writeAtSequential(ctx, fd, b, off)
	}
	if maxChunk <= 0 {
		return 0, &InternalError{"invalid maximum write size"}
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
			req: &smb2.WriteRequest{
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
	handle := func(_ context.Context, job ioPipelineJob, rp *recvPacket, recvErr error) error {
		if recvErr != nil {
			return recvErr
		}
		defer rp.close()
		requested := job.end - job.start
		count, err := parseWriteResponse(rp, requested)
		n += count
		return err
	}
	err = fs.runIOPipeline(ctx, next, handle)
	return n, err
}

func (fs *Share) writeAtSequential(ctx context.Context, fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	for n < len(b) {
		written, writeErr := fs.writeAtChunk(ctx, fd, b[n:], off+int64(n))
		n += written
		if writeErr != nil {
			return n, writeErr
		}
	}
	return n, nil
}

func (fs *Share) copyFile(ctx context.Context, srcFd, dstFd *smb2.FileId, srcName, dstName string, srcOffset, dstOffset int64, dstReadAccess bool) (supported bool, n int64, err error) {
	// [MS-SMB2] 2.2.31: FSCTL_SRV_COPYCHUNK requires FILE_READ_DATA on the
	// destination handle, while FSCTL_SRV_COPYCHUNK_WRITE only requires write
	// access. Choose the strongest code the destination handle permits.
	copyCtlCode := uint32(smb2.FSCTL_SRV_COPYCHUNK_WRITE)
	if dstReadAccess {
		copyCtlCode = smb2.FSCTL_SRV_COPYCHUNK
	}

	if srcOffset < 0 || dstOffset < 0 {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: os.ErrInvalid}
	}

	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
	}

	output, err := fs.ioctl(ctx, srcFd, req)
	if err != nil {
		// [MS-SMB2] 3.3.5.15 recommends these statuses for FSCTLs not allowed
		// on the server or unsupported by the filesystem, respectively.
		// The resume key request has not copied any bytes, so fallback is safe.
		if errors.Is(err, erref.STATUS_NOT_SUPPORTED) || errors.Is(err, erref.STATUS_INVALID_DEVICE_REQUEST) {
			return false, 0, nil
		}

		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}

	sr := smb2.SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"broken srv request resume key response format"}}
	}

	res, err := fs.request().withFileId(srcFd).
		queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 0, 24).
		sendRecv(ctx)
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	defer res.close()

	info := smb2.FileStandardInformationDecoder(smb2.QueryInfoResponseDecoder(res.data(0)).Output())
	if info.IsInvalid() {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"broken query info response format"}}
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

	var srvChunks [16]smb2.SrvCopychunk
	var chunks [16]*smb2.SrvCopychunk
	for i := range chunks {
		chunks[i] = &srvChunks[i]
	}

	for {
		var reqChunks []*smb2.SrvCopychunk

		if remains < clientMaxCopyTotalSize {
			nchunks := remains / clientMaxCopyChunkSize
			for i := int64(0); i < nchunks; i++ {
				srvChunks[i] = smb2.SrvCopychunk{
					SourceOffset: off + i*clientMaxCopyChunkSize,
					TargetOffset: woff + i*clientMaxCopyChunkSize,
					Length:       clientMaxCopyChunkSize,
				}
			}

			remains %= clientMaxCopyChunkSize
			if remains != 0 {
				srvChunks[nchunks] = smb2.SrvCopychunk{
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
				srvChunks[i] = smb2.SrvCopychunk{
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

		// [MS-SMB2] 2.2.34: the server must report the sum of chunk lengths.
		reqTotal := uint32(0)
		for _, chunk := range reqChunks {
			reqTotal += chunk.Length
		}

		scc := &smb2.SrvCopychunkCopy{
			Chunks: reqChunks,
		}

		copy(scc.SourceKey[:], sr.ResumeKey())

		cReq := &smb2.IoctlRequest{
			CtlCode:           copyCtlCode,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		output, err = fs.ioctl(ctx, dstFd, cReq)
		if err != nil {
			// [MS-SMB2] 3.3.5.15: STATUS_NOT_SUPPORTED is the server-wide
			// "unknown FSCTL" answer and STATUS_INVALID_DEVICE_REQUEST is the
			// filesystem-wide "unsupported FSCTL" answer. Only the WRITE
			// variant may fall back to a buffered copy, and only before any
			// byte was transferred. ACCESS_DENIED is not an unsupported
			// signal and must be surfaced as-is.
			if copyCtlCode == smb2.FSCTL_SRV_COPYCHUNK_WRITE && n == 0 &&
				(errors.Is(err, erref.STATUS_NOT_SUPPORTED) || errors.Is(err, erref.STATUS_INVALID_DEVICE_REQUEST)) {
				return false, 0, nil
			}

			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
		}

		c := smb2.SrvCopychunkResponseDecoder(output)
		if c.IsInvalid() {
			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"broken srv copy chunk response format"}}
		}

		if c.TotalBytesWritten() != reqTotal {
			return true, n, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"srv copy chunk wrote fewer bytes than requested"}}
		}

		n += int64(c.TotalBytesWritten())

		if remains == 0 {
			return true, n, nil
		}
	}
}

func (fs *Share) closeFile(ctx context.Context, fd *smb2.FileId) error {
	return fs.treeConn.closeFile(ctx, fd)
}
