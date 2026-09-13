package smb2

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

func fileAttributesFromPerm(perm os.FileMode) uint32 {
	attrs := uint32(smb2.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attrs |= smb2.FILE_ATTRIBUTE_READONLY
	}
	return attrs
}

// Share represents a SMB tree connection with VFS interface.
type Share struct {
	*treeConn
	ctx context.Context
	dfs *dfsState
}

// WithContext returns a share using ctx for its operations. After a CREATE has
// been sent, cancellation waits for the final responses and handle cleanup so
// a successful open cannot leak. A server that does not finish the request can
// delay cancellation until the connection is closed.
func (fs *Share) WithContext(ctx context.Context) *Share {
	if ctx == nil {
		panic("nil context")
	}
	return &Share{
		treeConn: fs.treeConn,
		ctx:      ctx,
		dfs:      fs.dfs,
	}
}

// Umount disconects the current SMB tree.
func (fs *Share) Umount() error {
	var first error
	if err := fs.treeConn.disconnect(fs.ctx); err != nil {
		first = err
	}
	if fs.dfs != nil {
		if err := fs.dfs.close(fs.ctx); err != nil {
			if first == nil {
				first = err
			}
		}
	}
	if first != nil {
		return &os.PathError{Op: "umount", Path: "", Err: first}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Share Public File System Operations (Path-based)
// ----------------------------------------------------------------------------

func (fs *Share) Create(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (fs *Share) Open(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *Share) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	name = normPath(name)

	if err := validatePath("open", name, false); err != nil {
		return nil, err
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = smb2.GENERIC_READ
	case os.O_WRONLY:
		access = smb2.GENERIC_WRITE
	case os.O_RDWR:
		access = smb2.GENERIC_READ | smb2.GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= smb2.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		if flag&os.O_TRUNC == 0 {
			access &^= smb2.GENERIC_WRITE
		}
		access |= smb2.FILE_APPEND_DATA | smb2.FILE_WRITE_EA | smb2.FILE_WRITE_ATTRIBUTES | smb2.READ_CONTROL | smb2.SYNCHRONIZE
	}

	sharemode := uint32(smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE)

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = smb2.FILE_CREATE
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = smb2.FILE_OVERWRITE_IF
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = smb2.FILE_OPEN_IF
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = smb2.FILE_OVERWRITE
	default:
		createmode = smb2.FILE_OPEN
	}

	var createoptions uint32
	if flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL) {
		createoptions |= smb2.FILE_OPEN_REPARSE_POINT
	}
	if flag&os.O_SYNC != 0 {
		createoptions |= smb2.FILE_WRITE_THROUGH
	}

	req := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       fileAttributesFromPerm(perm),
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        createoptions,
	}

	f, err := fs.createFile(name, req, flag&os.O_APPEND != 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return f, nil
}

func (fs *Share) Mkdir(name string, perm os.FileMode) error {
	name = normPath(name)

	if err := validatePath("mkdir", name, false); err != nil {
		return err
	}

	res, err := fs.request().
		create(name, smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_CREATE, smb2.FILE_DIRECTORY_FILE, fileAttributesFromPerm(perm)).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	res.close()
	return nil
}

func (fs *Share) Remove(name string) error {
	name = normPath(name)

	if err := validatePath("remove", name, false); err != nil {
		return err
	}

	remove := fs.request().
		create(name, smb2.DELETE, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileDispositionInformation, 0, &smb2.FileDispositionInformationEncoder{DeletePending: 1}).
		close()
	res, err := remove.sendRecv(fs.ctx)
	if err != nil {
		if !errors.Is(err, erref.STATUS_ACCESS_DENIED) && !errors.Is(err, erref.STATUS_CANNOT_DELETE) {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		if err := fs.chmod(nil, name, 0o666, false); err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		res, err = remove.sendRecv(fs.ctx)
		if err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}
	}
	res.close()

	return nil
}

func (fs *Share) Rename(oldpath, newpath string) error {
	oldpath = normPath(oldpath)
	newpath = normPath(newpath)

	if err := validatePath("rename", oldpath, false); err != nil {
		if pe, ok := errors.AsType[*os.PathError](err); ok {
			err = pe.Err
		}
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	if err := validatePath("rename", newpath, false); err != nil {
		if pe, ok := errors.AsType[*os.PathError](err); ok {
			err = pe.Err
		}
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	rename := &smb2.FileRenameInformationType2Encoder{
		ReplaceIfExists: 1,
		RootDirectory:   0,
		FileName:        newpath,
	}
	if fs.dfs != nil {
		oldDFS := fs.dfs.fullPath(oldpath)
		newDFS := fs.dfs.fullPath(newpath)
		_, ot, _, oerr := fs.dfs.resolvePath(fs.ctx, oldDFS)
		ne, nt, nbase, nerr := fs.dfs.resolvePath(fs.ctx, newDFS)
		if oerr != nil || nerr != nil {
			err := oerr
			if err == nil {
				err = nerr
			}
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
		}
		if ot != nt {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: errors.New("cross-device DFS rename")}
		}
		rename.FileName = joinDFSBase(nbase, dfsPathSuffix(newDFS, ne.prefix))
	}
	// [MS-SMB2] 3.2.1.2 defines MaxTransactSize and 3.3.5.21 requires the
	// server to reject a SET_INFO whose BufferLength exceeds it. Reject an
	// oversized rename locally so no oversized compound request is sent.
	if rename.Size() > fs.maxTransactSize(2) {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: os.ErrInvalid}
	}

	res, err := fs.request().
		create(oldpath, smb2.DELETE, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileRenameInformation, 0, rename).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	res.close()

	return nil
}

func (fs *Share) Stat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("stat", name, false); err != nil {
		return nil, err
	}

	fi, err := fs.stat(nil, name)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Lstat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("lstat", name, false); err != nil {
		return nil, err
	}

	fi, err := fs.lstat(name)
	if err != nil {
		return nil, &os.PathError{Op: "lstat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Readlink(name string) (string, error) {
	name = normPath(name)

	if err := validatePath("readlink", name, false); err != nil {
		return "", err
	}

	res, err := fs.request().
		create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		ioctl(smb2.FSCTL_GET_REPARSE_POINT, nil, maxSingleCreditPayloadSize).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}
	defer res.close()

	r1 := smb2.IoctlResponseDecoder(res.data(1))

	r := smb2.SymbolicLinkReparseDataBufferDecoder(r1.Output())
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	target := normalizeSymlinkTarget(r.SubstituteName())

	return target, nil
}

// Symlink mimics os.Symlink.
// This API should work on latest Windows and latest MacOS. However it may not work on Linux because Samba doesn't support reparse point well.
// Also there is a restriction on target pathname. Generally, a pathname begins with leading backslash (e.g `\dir\name`) can be interpreted as two ways.
// On windows, it is evaluated as a relative path, on other systems, it is evaluated as an absolute path.
// This implementation always assumes that format is absolute path. So, if you know the target server is Windows, you should avoid that format.
// If you want to use an absolute target path on windows, you can use `C:\dir\name` format instead.
func (fs *Share) Symlink(target, linkpath string) error {
	target = normPath(target)
	linkpath = normPath(linkpath)

	if len(target) == 0 {
		return os.ErrInvalid
	}

	if err := validatePath("symlink", target, true); err != nil {
		if pe, ok := errors.AsType[*os.PathError](err); ok {
			err = pe.Err
		}
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	if err := validatePath("symlink", linkpath, false); err != nil {
		if pe, ok := errors.AsType[*os.PathError](err); ok {
			err = pe.Err
		}
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	rdbuf := new(smb2.SymbolicLinkReparseDataBuffer)

	if len(target) >= 2 && target[1] == ':' {
		if len(target) == 2 {
			return os.ErrInvalid
		}

		if target[2] != '\\' {
			rdbuf.Flags = smb2.SYMLINK_FLAG_RELATIVE
		}
		rdbuf.SubstituteName = `\??\` + target
		rdbuf.PrintName = rdbuf.SubstituteName[4:]
	} else {
		if target[0] != '\\' {
			rdbuf.Flags = smb2.SYMLINK_FLAG_RELATIVE
		}
		rdbuf.SubstituteName = target
		rdbuf.PrintName = rdbuf.SubstituteName
	}

	// [MS-FSCC] 2.3.82 rejects FSCTL_SET_REPARSE_POINT input buffers over
	// 16,384 bytes, including the common header. The symbolic-link layout
	// is defined in [MS-FSCC] 2.1.2.4.
	if rdbuf.Size() > maxReparseDataBufferSize {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: os.ErrInvalid}
	}

	res, err := fs.request().
		create(linkpath, smb2.FILE_WRITE_ATTRIBUTES|smb2.DELETE, smb2.FILE_CREATE, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		ioctl(smb2.FSCTL_SET_REPARSE_POINT, rdbuf, 0).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		if cerr, ok := errors.AsType[*CompoundResponseError](err); ok && cerr.OpError(0) == nil {
			fs.Remove(linkpath)
		}
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}
	res.close()

	return nil
}

func (fs *Share) ReadDir(dirname string) ([]os.FileInfo, error) {
	dirname = normPath(dirname)

	if err := validatePath("readdir", dirname, false); err != nil {
		return nil, err
	}

	res, err := fs.request().
		create(dirname, smb2.FILE_READ_DATA|smb2.FILE_READ_ATTRIBUTES|smb2.READ_CONTROL, smb2.FILE_OPEN, smb2.FILE_DIRECTORY_FILE, smb2.FILE_ATTRIBUTE_NORMAL).
		queryDir(smb2.FileIdBothDirectoryInformation, "*", maxSingleCreditPayloadSize).
		sendRecv(fs.ctx)
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

	f := fs.routed(res.treeConn).newFile(res.data(0), dirname)
	defer f.Close()

	fis, err := f.readdirAll(res.data(1))
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}

	return fis, nil
}

func (fs *Share) ReadFile(filename string) ([]byte, error) {
	filename = normPath(filename)

	if err := validatePath("readfile", filename, false); err != nil {
		return nil, err
	}

	res, err := fs.request().
		create(filename, smb2.GENERIC_READ, smb2.FILE_OPEN, smb2.FILE_NON_DIRECTORY_FILE, smb2.FILE_ATTRIBUTE_NORMAL).
		read(maxSingleCreditPayloadSize, 0).
		sendRecv(fs.ctx)
	var (
		overflowData []byte
		isOverflow   bool
	)
	if err != nil {
		// An empty file is not an error: servers report STATUS_END_OF_FILE on
		// the READ of a compound CREATE+READ when the file has no data
		// ([MS-SMB2] 2.2.42). Treat it as success with no content.
		if cerr, ok := errors.AsType[*CompoundResponseError](err); ok {
			if cerr.OpError(0) == nil {
				if rerr, ok := errors.AsType[*ResponseError](cerr.OpError(1)); ok {
					switch erref.NtStatus(rerr.Code) {
					case erref.STATUS_END_OF_FILE:
						return []byte{}, nil
					case erref.STATUS_BUFFER_OVERFLOW:
						isOverflow = true
						if len(rerr.data) > 0 {
							// [MS-SMB2] 3.3.5.12 requires DataLength to be no greater than Length
							// for SMB2_CHANNEL_NONE.
							if uint64(len(rerr.data[0])) > uint64(maxSingleCreditPayloadSize) {
								return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"read length exceeds requested length"}}
							}
							overflowData = append([]byte(nil), rerr.data[0]...)
						}
					}
				}
			}
		} else {
			if rerr, ok := errors.AsType[*ResponseError](err); ok {
				switch erref.NtStatus(rerr.Code) {
				case erref.STATUS_END_OF_FILE:
					return []byte{}, nil
				case erref.STATUS_BUFFER_OVERFLOW:
					isOverflow = true
					if len(rerr.data) > 0 {
						// [MS-SMB2] 3.3.5.12 requires DataLength to be no greater than Length
						// for SMB2_CHANNEL_NONE.
						if uint64(len(rerr.data[0])) > uint64(maxSingleCreditPayloadSize) {
							return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"read length exceeds requested length"}}
						}
						overflowData = append([]byte(nil), rerr.data[0]...)
					}
				}
			}
		}
		if !isOverflow {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: err}
		}
	}

	var (
		f         *File
		createRes smb2.CreateResponseDecoder
		data      []byte
	)
	if isOverflow {
		res2, err := fs.request().
			create(filename, smb2.GENERIC_READ, smb2.FILE_OPEN, smb2.FILE_NON_DIRECTORY_FILE, smb2.FILE_ATTRIBUTE_NORMAL).
			sendRecv(fs.ctx)
		if err != nil {
			return nil, &os.PathError{Op: "readfile", Path: filename, Err: err}
		}
		defer res2.close()

		f = fs.routed(res2.treeConn).newFile(res2.data(0), filename)
		defer f.Close()
		createRes = smb2.CreateResponseDecoder(res2.data(0))
		data = overflowData
	} else {
		defer res.close()
		f = fs.routed(res.treeConn).newFile(res.data(0), filename)
		defer f.Close()
		createRes = smb2.CreateResponseDecoder(res.data(0))
		readRes := smb2.ReadResponseDecoder(res.data(1))
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
			n, readErr := fs.readAt(f.fd, buf[:readSize], off)
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

func (fs *Share) WriteFile(filename string, data []byte, perm os.FileMode) error {
	filename = normPath(filename)

	if err := validatePath("writefile", filename, false); err != nil {
		return err
	}

	attrs := fileAttributesFromPerm(perm)

	maxWriteSize := fs.maxWriteSize(2)

	if len(data) <= maxWriteSize { // first path
		res, err := fs.request().
			create(filename, smb2.GENERIC_WRITE, smb2.FILE_OVERWRITE_IF, smb2.FILE_NON_DIRECTORY_FILE, attrs).
			write(data, 0).
			close().
			sendRecv(fs.ctx)
		if err != nil {
			return &os.PathError{Op: "writefile", Path: filename, Err: err}
		}
		defer res.close()

		count := smb2.WriteResponseDecoder(res.data(1)).Count()
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

	f, err := fs.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return err
}

func (fs *Share) Truncate(name string, size int64) error {
	name = normPath(name)

	if err := validatePath("truncate", name, false); err != nil {
		return err
	}

	if err := fs.truncate(nil, name, size); err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normPath(name)

	if err := validatePath("chtimes", name, false); err != nil {
		return err
	}

	if err := fs.chtimes(nil, name, atime, mtime); err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chmod(name string, mode os.FileMode) error {
	name = normPath(name)

	if err := validatePath("chmod", name, false); err != nil {
		return err
	}

	if err := fs.chmod(nil, name, mode, true); err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Statfs(name string) (FileFsInfo, error) {
	name = normPath(name)

	if err := validatePath("statfs", name, false); err != nil {
		return nil, err
	}

	info, err := fs.statfs(nil, name)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}
	return info, nil
}
