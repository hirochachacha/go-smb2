package smb2

import (
	"context"
	"errors"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func fileAttributesFromPerm(perm os.FileMode) uint32 {
	attrs := uint32(wire.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attrs |= wire.FILE_ATTRIBUTE_READONLY
	}
	return attrs
}

// Share represents a SMB tree connection with VFS interface.
type Share struct {
	*treeConn
	closeOnce sync.Once
	closeErr  error
}

// WithContext returns a share using ctx for its operations. After a CREATE has
// been sent, cancellation waits for the final responses and handle cleanup so
// a successful open cannot leak. A server that does not finish the request can
// delay cancellation until the connection is closed.
func (fs *Share) WithContext(ctx context.Context) *BoundShare {
	if ctx == nil {
		panic("nil context")
	}
	return &BoundShare{share: fs, ctx: ctx}
}

// Unmount disconnects the current SMB tree and cached DFS trees.
// The Client retains their sessions until Client.Close.
//
// While [MS-SMB2] 3.3.5.8 guarantees that the server will clean up and close
// any remaining opens upon receiving TREE_DISCONNECT, [MS-SMB2] 3.2.4.22
// specifies that the client MUST close all open files on the tree connect
// beforehand. Callers should properly manage and close their open file
// resources rather than relying on server teardown, as abrupt disconnects
// can discard write errors or invalidate active handles.
func (fs *Share) Unmount(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	fs.closeOnce.Do(func() {
		if fs.treeConn != nil {
			fs.closeErr = fs.treeConn.disconnect(ctx)
		}
	})
	return fs.closeErr
}

// ----------------------------------------------------------------------------
// Share Public File System Operations (Path-based)
// ----------------------------------------------------------------------------

func (fs *Share) Create(ctx context.Context, name string) (*File, error) {
	return fs.OpenFile(ctx, name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (fs *Share) Open(ctx context.Context, name string) (*File, error) {
	return fs.OpenFile(ctx, name, os.O_RDONLY, 0)
}

func (fs *Share) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*File, error) {
	var err error
	name, err = pathpkg.NormalizeRelPath(name)
	if err != nil {
		return nil, err
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = wire.GENERIC_READ
	case os.O_WRONLY:
		access = wire.GENERIC_WRITE
	case os.O_RDWR:
		access = wire.GENERIC_READ | wire.GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= wire.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		if flag&os.O_TRUNC == 0 {
			access &^= wire.GENERIC_WRITE
		}
		access |= wire.FILE_APPEND_DATA | wire.FILE_WRITE_EA | wire.FILE_WRITE_ATTRIBUTES | wire.READ_CONTROL | wire.SYNCHRONIZE
	}

	sharemode := uint32(wire.FILE_SHARE_READ | wire.FILE_SHARE_WRITE)

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = wire.FILE_CREATE
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = wire.FILE_OVERWRITE_IF
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = wire.FILE_OPEN_IF
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = wire.FILE_OVERWRITE
	default:
		createmode = wire.FILE_OPEN
	}

	var createoptions uint32
	if flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL) {
		createoptions |= wire.FILE_OPEN_REPARSE_POINT
	}
	if flag&os.O_SYNC != 0 {
		createoptions |= wire.FILE_WRITE_THROUGH
	}

	req := &wire.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: wire.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   wire.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       fileAttributesFromPerm(perm),
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        createoptions,
	}

	f, err := fs.createFile(ctx, name, req, flag&os.O_APPEND != 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return f, nil
}

func (fs *Share) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}

	res, err := fs.request().
		create(name, wire.FILE_WRITE_ATTRIBUTES, wire.FILE_CREATE, wire.FILE_DIRECTORY_FILE, fileAttributesFromPerm(perm)).
		close().
		sendRecv(ctx)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	res.close()
	return nil
}

func (fs *Share) Remove(ctx context.Context, name string) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}

	// [MS-SMB2] 2.2.13 defines a zero-length CREATE file name as a request
	// to open the root of the share, so an empty name must not reach CREATE.
	if len(name) == 0 {
		return os.ErrInvalid
	}

	remove := fs.request().
		create(name, wire.DELETE, wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		setInfo(wire.SMB2_0_INFO_FILE, wire.FileDispositionInformation, 0, &wire.FileDispositionInformationEncoder{DeletePending: 1}).
		close()
	res, err := remove.sendRecv(ctx)
	if err != nil {
		if !errors.Is(err, erref.STATUS_ACCESS_DENIED) && !errors.Is(err, erref.STATUS_CANNOT_DELETE) {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		if err := fs.chmod(ctx, nil, name, 0o666, false); err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		res, err = remove.sendRecv(ctx)
		if err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}
	}
	res.close()

	return nil
}

func (fs *Share) Rename(ctx context.Context, oldpath, newpath string) error {
	var err error
	oldpath, err = pathpkg.NormalizeRelPath(oldpath)
	if err != nil {
		return err
	}
	newpath, err = pathpkg.NormalizeRelPath(newpath)
	if err != nil {
		return err
	}

	// [MS-SMB2] 2.2.13 defines a zero-length CREATE file name as a request
	// to open the root of the share, so neither end may name the share root.
	if len(oldpath) == 0 || len(newpath) == 0 {
		return os.ErrInvalid
	}

	rename := &wire.FileRenameInformationType2Encoder{
		ReplaceIfExists: 1,
		RootDirectory:   0,
		FileName:        newpath,
	}
	// [MS-SMB2] 3.2.1.2 defines MaxTransactSize and 3.3.5.21 requires the
	// server to reject a SET_INFO whose BufferLength exceeds it. Reject an
	// oversized rename locally so no oversized compound request is sent.
	if rename.Size() > fs.maxTransactSize(2) {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: os.ErrInvalid}
	}

	res, err := fs.request().
		create(oldpath, wire.DELETE, wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		setInfo(wire.SMB2_0_INFO_FILE, wire.FileRenameInformation, 0, rename).
		close().
		sendRecv(ctx)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	res.close()

	return nil
}

func (fs *Share) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return nil, err
	}

	fi, err := fs.stat(ctx, nil, name)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Lstat(ctx context.Context, name string) (os.FileInfo, error) {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return nil, err
	}

	fi, err := fs.lstat(ctx, name)
	if err != nil {
		return nil, &os.PathError{Op: "lstat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Readlink(ctx context.Context, name string) (string, error) {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return "", err
	}

	res, err := fs.request().
		create(name, wire.FILE_READ_ATTRIBUTES, wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		ioctl(wire.FSCTL_GET_REPARSE_POINT, nil, maxSingleCreditPayloadSize).
		close().
		sendRecv(ctx)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}
	defer res.close()

	r1 := wire.IoctlResponseDecoder(res.data(1))
	if r1.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: name, Err: &InvalidResponseError{"broken ioctl response format"}}
	}

	r := wire.SymbolicLinkReparseDataBufferDecoder(r1.Output())
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	return r.SubstituteName(), nil
}

// Symlink mimics os.Symlink.
// This API should work on latest Windows, latest MacOS, and Samba 4.21 or later.
// Also there is a restriction on target pathname. Generally, a pathname begins with leading backslash (e.g `\dir\name`) can be interpreted as two ways.
// On windows, it is evaluated as a relative path, on other systems, it is evaluated as an absolute path.
// This implementation always assumes that format is absolute path. So, if you know the target server is Windows, you should avoid that format.
// If you want to use an absolute target path on windows, you can use `C:\dir\name` format instead.
func (fs *Share) Symlink(ctx context.Context, target, linkpath string) error {
	target = pathpkg.Normalize(target)
	if len(target) == 0 {
		return os.ErrInvalid
	}

	linkpath, err := pathpkg.NormalizeRelPath(linkpath)
	if err != nil {
		return err
	}

	rdbuf := new(wire.SymbolicLinkReparseDataBuffer)

	if len(target) >= 2 && target[1] == ':' {
		if len(target) == 2 {
			return os.ErrInvalid
		}

		if target[2] != '\\' {
			rdbuf.Flags = wire.SYMLINK_FLAG_RELATIVE
		}
		rdbuf.SubstituteName = `\??\` + target
		rdbuf.PrintName = rdbuf.SubstituteName[4:]
	} else {
		if strings.HasPrefix(target, `\\`) {
			// Symbolic-link reparse data uses the NT substitute-name form for
			// UNC targets while PrintName remains the user-visible UNC.
			rdbuf.SubstituteName = `\??\UNC\` + strings.TrimLeft(target, `\`)
			rdbuf.PrintName = target
		} else if target[0] != '\\' {
			rdbuf.Flags = wire.SYMLINK_FLAG_RELATIVE
			rdbuf.SubstituteName = target
			rdbuf.PrintName = target
		} else {
			rdbuf.SubstituteName = target
			rdbuf.PrintName = target
		}
	}

	// [MS-FSCC] 2.3.82 rejects FSCTL_SET_REPARSE_POINT input buffers over
	// 16,384 bytes, including the common header. The symbolic-link layout
	// is defined in [MS-FSCC] 2.1.2.4.
	if rdbuf.Size() > maxReparseDataBufferSize {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: os.ErrInvalid}
	}

	res, err := fs.request().
		create(linkpath, wire.FILE_WRITE_ATTRIBUTES|wire.DELETE, wire.FILE_CREATE, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		ioctl(wire.FSCTL_SET_REPARSE_POINT, rdbuf, 0).
		close().
		sendRecv(ctx)
	if err != nil {
		if cerr, ok := errors.AsType[*CompoundResponseError](err); ok && cerr.OpError(0) == nil {
			fs.Remove(ctx, linkpath)
		}
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}
	res.close()

	return nil
}

func (fs *Share) ReadDir(ctx context.Context, dirname string) ([]os.FileInfo, error) {
	var err error
	dirname, err = pathpkg.NormalizeRelPath(dirname)
	if err != nil {
		return nil, err
	}

	req := fs.request().
		create(dirname, wire.FILE_READ_DATA|wire.FILE_READ_ATTRIBUTES|wire.READ_CONTROL, wire.FILE_OPEN, wire.FILE_DIRECTORY_FILE, wire.FILE_ATTRIBUTE_NORMAL).
		queryDir(wire.FileIdBothDirectoryInformation, "*", maxSingleCreditPayloadSize)
	res, err := req.sendRecv(ctx)
	if err != nil {
		// An empty directory is not an error: some servers (e.g. Samba)
		// report STATUS_NO_MORE_FILES or STATUS_NO_SUCH_FILE on the first
		// QUERY_DIRECTORY of a compound CREATE+QUERY_DIRECTORY when the
		// directory has no entries ([MS-FSA] 2.1.5.6.3). Treat it as
		// success with no content.
		if cerr, ok := errors.AsType[*CompoundResponseError](err); ok && cerr.OpError(0) == nil {
			if rerr, ok := errors.AsType[*ResponseError](cerr.OpError(1)); ok {
				switch erref.NtStatus(rerr.Code) {
				case erref.STATUS_NO_MORE_FILES, erref.STATUS_NO_SUCH_FILE:
					return []os.FileInfo{}, nil
				}
			}
		}
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}
	defer res.close()

	createR := wire.CreateResponseDecoder(res.data(0))
	if createR.IsInvalid() {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: &InvalidResponseError{"broken create response format"}}
	}
	f := fs.newFile(createR, req.pkts[0].(*wire.CreateRequest).Name)
	defer f.Close(ctx)

	fis, err := f.readdirAll(ctx, res.data(1))
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}

	return fis, nil
}

func (fs *Share) ReadFile(ctx context.Context, filename string) ([]byte, error) {
	filename, err := pathpkg.NormalizeRelPath(filename)
	if err != nil {
		return nil, err
	}

	firstReq := fs.request().
		create(filename, wire.GENERIC_READ, wire.FILE_OPEN, wire.FILE_NON_DIRECTORY_FILE, wire.FILE_ATTRIBUTE_NORMAL).
		read(maxSingleCreditPayloadSize, 0)
	res, err := firstReq.sendRecv(ctx)
	var (
		overflowData []byte
		isOverflow   bool
	)
	if err != nil {
		// An empty file is not an error: servers report STATUS_END_OF_FILE on
		// the READ of a compound CREATE+READ when the file has no data
		// ([MS-SMB2] 2.2.42). Treat it as success with no content.
		readErr := responseErrorAt(err, 1)
		if cerr, ok := errors.AsType[*CompoundResponseError](err); ok && cerr.OpError(0) != nil {
			// The opening CREATE failed, so op 1 was not a completed READ.
			readErr = nil
		}
		if readErr != nil {
			switch erref.NtStatus(readErr.Code) {
			case erref.STATUS_END_OF_FILE:
				return []byte{}, nil
			case erref.STATUS_BUFFER_OVERFLOW:
				isOverflow = true
				if data, ok := bufferOverflowData(readErr); ok {
					// [MS-SMB2] 3.3.5.12 requires DataLength to be no greater than Length
					// for SMB2_CHANNEL_NONE.
					if uint64(len(data)) > uint64(maxSingleCreditPayloadSize) {
						return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"read length exceeds requested length"}}
					}
					overflowData = append([]byte(nil), data...)
				}
			}
		}
		if !isOverflow {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: err}
		}
	}

	var (
		f         *File
		createRes wire.CreateResponseDecoder
		data      []byte
	)
	if isOverflow {
		secondReq := fs.request().
			create(filename, wire.GENERIC_READ, wire.FILE_OPEN, wire.FILE_NON_DIRECTORY_FILE, wire.FILE_ATTRIBUTE_NORMAL)
		res2, err := secondReq.sendRecv(ctx)
		if err != nil {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: err}
		}
		defer res2.close()

		createR := wire.CreateResponseDecoder(res2.data(0))
		if createR.IsInvalid() {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"broken create response format"}}
		}
		f = fs.newFile(createR, secondReq.pkts[0].(*wire.CreateRequest).Name)
		defer f.Close(ctx)
		createRes = createR
		data = overflowData
	} else {
		defer res.close()
		createR := wire.CreateResponseDecoder(res.data(0))
		if createR.IsInvalid() {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"broken create response format"}}
		}
		f = fs.newFile(createR, firstReq.pkts[0].(*wire.CreateRequest).Name)
		defer f.Close(ctx)
		createRes = createR
		readRes := wire.ReadResponseDecoder(res.data(1))
		if readRes.IsInvalid() || hasInvalidReadFlags(readRes, fs.dialect) {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"broken read response format"}}
		}
		// [MS-SMB2] 3.3.5.12 requires DataLength to be no greater than Length
		// for SMB2_CHANNEL_NONE.
		if uint64(len(readRes.Data())) > uint64(maxSingleCreditPayloadSize) {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"read length exceeds requested length"}}
		}
		data = append([]byte(nil), readRes.Data()...)
	}

	endOfFile := createRes.EndofFile()

	if int64(len(data)) < endOfFile {
		remaining := endOfFile - int64(len(data))
		bufferSize := min(remaining, int64(winMaxPayloadSize))
		buf := make([]byte, bufferSize)
		off := int64(len(data))
		for off < endOfFile {
			readSize := min(int64(len(buf)), endOfFile-off)
			n, readErr := f.fs.readAt(ctx, f.fd, buf[:readSize], off)
			if n > 0 {
				data = append(data, buf[:n]...)
				off += int64(n)
			}
			if readErr != nil {
				if readErr == io.EOF {
					return nil, &os.PathError{Op: "readfile", Path: filename, Err: io.ErrUnexpectedEOF}
				}
				return nil, &os.PathError{Op: "readfile", Path: filename, Err: readErr}
			}
			if n == 0 {
				return nil, &os.PathError{Op: "readfile", Path: filename, Err: io.ErrUnexpectedEOF}
			}
		}
	}

	return data, nil
}

func (fs *Share) WriteFile(ctx context.Context, filename string, data []byte, perm os.FileMode) error {
	filename, err := pathpkg.NormalizeRelPath(filename)
	if err != nil {
		return err
	}

	attrs := fileAttributesFromPerm(perm)

	maxWriteSize := fs.maxWriteSize(2)

	if len(data) <= maxWriteSize { // first path
		res, err := fs.request().
			create(filename, wire.GENERIC_WRITE, wire.FILE_OVERWRITE_IF, wire.FILE_NON_DIRECTORY_FILE, attrs).
			write(data, 0).
			close().
			sendRecv(ctx)
		if err != nil {
			return &os.PathError{Op: "writefile", Path: filename, Err: err}
		}
		defer res.close()

		writeR := wire.WriteResponseDecoder(res.data(1))
		if writeR.IsInvalid() {
			return &os.PathError{Op: "writefile", Path: filename, Err: &InvalidResponseError{"broken write response format"}}
		}
		count := writeR.Count()
		// Count is the number of bytes written and cannot exceed the request
		// length ([MS-SMB2] 2.2.22).
		if uint64(count) > uint64(len(data)) {
			return &os.PathError{Op: "writefile", Path: filename, Err: &InvalidResponseError{"write count exceeds requested length"}}
		}
		if uint64(count) < uint64(len(data)) {
			return &os.PathError{Op: "writefile", Path: filename, Err: io.ErrShortWrite}
		}
		return nil
	}

	f, err := fs.OpenFile(ctx, filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = f.Write(ctx, data)
	if err1 := f.Close(ctx); err == nil {
		err = err1
	}

	return err
}

func (fs *Share) Truncate(ctx context.Context, name string, size int64) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}

	if err := fs.truncate(ctx, nil, name, size); err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chtimes(ctx context.Context, name string, atime time.Time, mtime time.Time) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}

	if err := fs.chtimes(ctx, nil, name, atime, mtime); err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chmod(ctx context.Context, name string, mode os.FileMode) error {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return err
	}

	if err := fs.chmod(ctx, nil, name, mode, true); err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Statfs(ctx context.Context, name string) (FileFsInfo, error) {
	name, err := pathpkg.NormalizeRelPath(name)
	if err != nil {
		return nil, err
	}

	info, err := fs.statfs(ctx, nil, name)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}
	return info, nil
}
