package smb2

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

// Dialer contains options for func (*Dialer) Dial.
type Dialer struct {
	MaxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	Negotiator       Negotiator
	Initiator        Initiator
}

// Dial performs negotiation and authentication.
// It returns a client. It doesn't support NetBIOS transport.
func (d *Dialer) Dial(tcpConn net.Conn) (*Client, error) {
	return d.DialContext(tcpConn, context.Background())
}

func (d *Dialer) DialContext(tcpConn net.Conn, ctx context.Context) (*Client, error) {
	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(direct(tcpConn), a, ctx)
	if err != nil {
		return nil, err
	}

	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		return nil, err
	}

	return &Client{s: s, ctx: context.Background()}, nil
}

// Client represents a SMB session.
type Client struct {
	s   *session
	ctx context.Context
}

func (c *Client) WithContext(ctx context.Context) *Client {
	return &Client{s: c.s, ctx: ctx}
}

// Logoff invalidates the current SMB session.
func (c *Client) Logoff() error {
	return c.s.logoff(c.ctx)
}

// Mount connects to a SMB tree.
func (c *Client) Mount(path string) (*RemoteFileSystem, error) {
	if isInvalidPath(path, true) {
		return nil, os.ErrInvalid
	}

	tc, err := treeConnect(c.s, path, 0, c.ctx)
	if err != nil {
		return nil, err
	}
	return &RemoteFileSystem{treeConn: tc, ctx: context.Background()}, nil
}

// RemoteFileSystem represents a SMB tree connection with VFS interface.
type RemoteFileSystem struct {
	*treeConn
	ctx context.Context
}

func (fs *RemoteFileSystem) WithContext(ctx context.Context) *RemoteFileSystem {
	return &RemoteFileSystem{
		treeConn: fs.treeConn,
		ctx:      ctx,
	}
}

// Umount disconects the current SMB tree.
func (fs *RemoteFileSystem) Umount() error {
	return fs.treeConn.disconnect(fs.ctx)
}

func (fs *RemoteFileSystem) Create(name string) (*RemoteFile, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *RemoteFileSystem) newFile(fd FileIdDecoder, name string) *RemoteFile {
	f := &RemoteFile{fs: fs, fd: fd.Decode(), name: name, ctx: context.Background()}

	runtime.SetFinalizer(f, func(f *RemoteFile) { f.close(context.Background()) })

	return f
}

func (fs *RemoteFileSystem) Open(name string) (*RemoteFile, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *RemoteFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*RemoteFile, error) {
	if isInvalidPath(name, false) {
		return nil, os.ErrInvalid
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = GENERIC_READ
	case os.O_WRONLY:
		access = GENERIC_WRITE
	case os.O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= GENERIC_WRITE
		access |= FILE_APPEND_DATA
	}

	sharemode := uint32(FILE_SHARE_READ | FILE_SHARE_WRITE)

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = FILE_CREATE
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = FILE_OVERWRITE_IF
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = FILE_OPEN_IF
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = FILE_OVERWRITE
	default:
		createmode = FILE_OPEN
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, req, true, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if flag&os.O_APPEND != 0 {
		f.seek(0, os.SEEK_END, fs.ctx)
	}
	return f, nil
}

func (fs *RemoteFileSystem) Mkdir(name string, perm os.FileMode) error {
	if isInvalidPath(name, false) {
		return os.ErrInvalid
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_CREATE,
		CreateOptions:        FILE_DIRECTORY_FILE,
	}

	f, err := fs.createFile(name, req, false, fs.ctx)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}

	err = f.close(fs.ctx)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	return nil
}

func (fs *RemoteFileSystem) Readlink(name string) (string, error) {
	if isInvalidPath(name, false) {
		return "", os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false, fs.ctx)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FSCTL_GET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 64 * 1024,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             nil,
	}

	_, output, err := f.ioctl(req, fs.ctx)
	e := f.close(fs.ctx)
	err = multiError(err, e)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: err}
	}

	r := SymbolicLinkReparseDataBufferDecoder(output)
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	target := UTF16ToString(r.SubstituteName())

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	return target, nil
}

func (fs *RemoteFileSystem) Remove(name string) error {
	if isInvalidPath(name, false) {
		return os.ErrInvalid
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       0,
		ShareAccess:          FILE_SHARE_DELETE,
		CreateDisposition:    FILE_OPEN,
		// CreateOptions:        FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE,
		CreateOptions: FILE_OPEN_REPARSE_POINT,
	}
	// FILE_DELETE_ON_CLOSE doesn't work for reparse point, so use FileDispositionInformation instead

	f, err := fs.createFile(name, req, false, fs.ctx)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	e1 := f.remove(fs.ctx)
	e2 := f.close(fs.ctx)
	err = multiError(e1, e2)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	return nil
}

func (fs *RemoteFileSystem) Rename(oldpath, newpath string) error {
	if isInvalidPath(oldpath, false) || isInvalidPath(newpath, false) {
		return os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_DELETE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(oldpath, create, false, fs.ctx)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	ws := UTF16FromString(newpath)

	info := &SetInfoRequest{
		FileInfoClass:         FileRenameInformation,
		AdditionalInformation: 0,
		Input: &FileRenameInformationType2Encoder{
			ReplaceIfExists: 0,
			RootDirectory:   0,
			FileName:        ws,
		},
	}

	e1 := f.setInfo(info, fs.ctx)
	e2 := f.close(fs.ctx)
	err = multiError(e1, e2)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// Symlink mimics os.Symlink.
// This API should work on latest Windows and latest MacOS.
// However it may not work on Linux because Samba doesn't support reparse point well.
// Also there is a restriction on target pathname.
// Generally, a pathname begins with leading backslash (e.g `\dir\name`) can be interpreted as two ways.
// On windows, it is evaluated as a relative path, on other systems, it is evaluated as an absolute path.
// This implementation always assumes that format is absolute path.
// So, if you know the target server is Windows, you should avoid that format.
// If you want to use an absolute target path on windows, you can use // `C:\dir\name` format instead.
func (fs *RemoteFileSystem) Symlink(target, linkpath string) error {
	if isInvalidPath(target, true) || isInvalidPath(linkpath, false) {
		return os.ErrInvalid
	}

	rdbuf := new(SymbolicLinkReparseDataBuffer)

	if len(target) >= 2 && target[1] == ':' {
		if len(target) == 2 {
			return os.ErrInvalid
		}

		if target[2] != '\\' {
			rdbuf.Flags = SYMLINK_FLAG_RELATIVE
		}
		rdbuf.SubstituteName = UTF16FromString(`\??\` + target)
		rdbuf.PrintName = rdbuf.SubstituteName[4:]
	} else {
		if target[0] != '\\' {
			rdbuf.Flags = SYMLINK_FLAG_RELATIVE // It's not true on window server.
		}
		rdbuf.SubstituteName = UTF16FromString(target)
		rdbuf.PrintName = rdbuf.SubstituteName
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_ATTRIBUTES | DELETE,
		FileAttributes:       FILE_ATTRIBUTE_REPARSE_POINT,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_CREATE,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(linkpath, create, false, fs.ctx)
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FSCTL_SET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 0,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             rdbuf,
	}

	_, _, err = f.ioctl(req, fs.ctx)
	if err != nil {
		e1 := f.remove(fs.ctx)
		e2 := f.close(fs.ctx)
		err = multiError(err, e1, e2)

		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	err = f.close(fs.ctx)
	if err != nil {
		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	return nil
}

func (fs *RemoteFileSystem) Lstat(name string) (os.FileInfo, error) {
	if isInvalidPath(name, false) {
		return nil, os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, e1 := f.stat(fs.ctx)
	e2 := f.close(fs.ctx)
	err = multiError(e1, e2)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *RemoteFileSystem) Stat(name string) (os.FileInfo, error) {
	if isInvalidPath(name, false) {
		return nil, os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, e1 := f.stat(fs.ctx)
	e2 := f.close(fs.ctx)
	err = multiError(e1, e2)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *RemoteFileSystem) Truncate(name string, size int64) error {
	if isInvalidPath(name, false) {
		return os.ErrInvalid
	}

	if size < 0 {
		return os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_DATA | SYNCHRONIZE,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, create, true, fs.ctx)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}

	e1 := f.truncate(size, fs.ctx)
	e2 := f.close(fs.ctx)
	err = multiError(e1, e2)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (fs *RemoteFileSystem) createFile(name string, req *CreateRequest, followSymlinks bool, ctx context.Context) (f *RemoteFile, err error) {
	if followSymlinks {
		return fs.createFileRec(name, req, ctx)
	}

	req.CreditCharge, _, err = fs.loanCredit(0, ctx)
	defer func() {
		if err != nil {
			fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	ws := UTF16FromString(name)

	req.Name = ws

	res, err := fs.sendRecv(SMB2_CREATE, req, ctx)
	if err != nil {
		return nil, err
	}

	r := CreateResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken create response format"}
	}

	f = fs.newFile(r.FileId(), name)

	return f, nil
}

func (fs *RemoteFileSystem) createFileRec(name string, req *CreateRequest, ctx context.Context) (f *RemoteFile, err error) {
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		req.CreditCharge, _, err = fs.loanCredit(0, ctx)
		defer func() {
			if err != nil {
				fs.chargeCredit(req.CreditCharge)
			}
		}()
		if err != nil {
			return nil, err
		}

		ws := UTF16FromString(name)

		req.Name = ws

		res, err := fs.sendRecv(SMB2_CREATE, req, ctx)
		if err != nil {
			if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == STATUS_STOPPED_ON_SYMLINK {
				if len(rerr.data) > 0 {
					name, err = evalSymlinkError(ws, rerr.data[0])
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		r := CreateResponseDecoder(res)
		if r.IsInvalid() {
			return nil, &InvalidResponseError{"broken create response format"}
		}

		f = fs.newFile(r.FileId(), name)

		return f, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func evalSymlinkError(ws []uint16, errData []byte) (string, error) {
	d := SymbolicLinkErrorResponseDecoder(errData)
	if d.IsInvalid() {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	var u string

	ulen := int(d.UnparsedPathLength())
	if ulen/2 > len(ws) {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	u = UTF16ToString(ws[len(ws)-ulen/2:])

	target := UTF16ToString(d.SubstituteName())

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	if d.Flags()&SYMLINK_FLAG_RELATIVE == 0 {
		return target + u, nil
	}

	return dir(UTF16ToString(ws[:len(ws)-ulen/2])) + target + u, nil
}

func (fs *RemoteFileSystem) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	rr, err := fs.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := fs.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

type RemoteFile struct {
	fs      *RemoteFileSystem
	fd      *FileId
	name    string
	dirents []os.FileInfo

	offset int64

	m sync.Mutex

	ctx context.Context
}

func (f *RemoteFile) WithContext(ctx context.Context) *RemoteFile {
	return &RemoteFile{
		fs:   f.fs,
		fd:   f.fd,
		name: f.name,
		ctx:  ctx,
	}
}

func (f *RemoteFile) Close() error {
	if f == nil {
		return os.ErrInvalid
	}

	err := f.close(f.ctx)
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	return nil
}

func (f *RemoteFile) close(ctx context.Context) error {
	if f == nil || f.fd == nil {
		return os.ErrInvalid
	}

	req := &CloseRequest{
		Flags: 0,
	}

	req.CreditCharge = 1

	req.FileId = f.fd

	res, err := f.sendRecv(SMB2_CLOSE, req, ctx)
	if err != nil {
		return err
	}

	r := CloseResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken close response format"}
	}

	f.fd = nil

	runtime.SetFinalizer(f, nil)

	return nil
}

func (f *RemoteFile) remove(ctx context.Context) error {
	info := &SetInfoRequest{
		FileInfoClass:         FileDispositionInformation,
		AdditionalInformation: 0,
		Input: &FileDispositionInformationEncoder{
			DeletePending: 1,
		},
	}

	err := f.setInfo(info, ctx)
	if err != nil {
		return err
	}
	return nil
}

func (f *RemoteFile) Name() string {
	return f.name
}

func (f *RemoteFile) Read(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, os.SEEK_CUR, f.ctx)
	if err != nil {
		return -1, err
	}

	n, err = f.readAt(b, off, f.ctx)
	if n != 0 {
		_, e := f.seek(off+int64(n), os.SEEK_SET, f.ctx)

		err = multiError(err, e)
	}
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	return
}

// ReadAt implements io.ReaderAt.
func (f *RemoteFile) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	n, err = f.readAt(b, off, f.ctx)
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

// MaxReadSizeLimit limits maxReadSize from negotiate data
const MaxReadSizeLimit = 0x100000

func (f *RemoteFile) readAt(b []byte, off int64, ctx context.Context) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	maxReadSize := int(f.fs.maxReadSize)
	if maxReadSize > MaxReadSizeLimit {
		maxReadSize = MaxReadSizeLimit
	}

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxReadSize:
			bs, isEOF, err := f.readAtChunk(len(b)-n, int64(n)+off, ctx)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		default:
			bs, isEOF, err := f.readAtChunk(maxReadSize, int64(n)+off, ctx)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		}
	}
}

func (f *RemoteFile) readAtChunk(n int, off int64, ctx context.Context) (bs []byte, isEOF bool, err error) {
	creditCharge, m, err := f.fs.loanCredit(n, ctx)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return nil, false, err
	}

	req := &ReadRequest{
		Padding:         0,
		Flags:           0,
		Length:          uint32(m),
		Offset:          uint64(off),
		MinimumCount:    1, // for returning EOF
		Channel:         0,
		RemainingBytes:  0,
		ReadChannelInfo: nil,
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, err := f.sendRecv(SMB2_READ, req, ctx)
	if err != nil {
		return nil, false, err
	}

	r := ReadResponseDecoder(res)
	if r.IsInvalid() {
		return nil, false, &InvalidResponseError{"broken read response format"}
	}

	bs = r.Data()

	return bs, len(bs) < m, nil
}

func (f *RemoteFile) Readdir(n int) (fi []os.FileInfo, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	if f.dirents == nil {
		for {
			dirents, err := f.readdir(f.ctx)
			if err != nil {
				if err, ok := err.(*ResponseError); !ok || NtStatus(err.Code) != STATUS_NO_MORE_FILES {
					return nil, &os.PathError{Op: "readdir", Path: f.name, Err: err}
				}
				break
			}
			f.dirents = append(f.dirents, dirents...)
		}
	}

	fi = f.dirents

	if n > 0 {
		if len(fi) < n {
			f.dirents = []os.FileInfo{}
			return fi, io.EOF
		}

		f.dirents = fi[n:]
		return fi[:n], nil

	}

	f.dirents = []os.FileInfo{}

	return fi, nil
}

func (f *RemoteFile) Readdirnames(n int) (names []string, err error) {
	fi, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}

	names = make([]string, len(fi))

	for i, st := range fi {
		names[i] = st.Name()
	}

	return names, nil
}

// Seek implements io.Seeker.
func (f *RemoteFile) Seek(offset int64, whence int) (ret int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	ret, err = f.seek(offset, whence, f.ctx)
	if err != nil {
		return ret, &os.PathError{Op: "seek", Path: f.name, Err: err}
	}
	return ret, nil
}

func (f *RemoteFile) seek(offset int64, whence int, ctx context.Context) (ret int64, err error) {
	switch whence {
	case os.SEEK_SET:
		f.offset = offset
	case os.SEEK_CUR:
		f.offset += offset
	case os.SEEK_END:
		req := &QueryInfoRequest{
			FileInfoClass:         FileStandardInformation,
			AdditionalInformation: 0,
			Flags: 0,
		}

		infoBytes, err := f.queryInfo(req, ctx)
		if err != nil {
			return -1, err
		}

		info := FileStandardInformationDecoder(infoBytes)
		if info.IsInvalid() {
			return -1, &InvalidResponseError{"broken query info response format"}
		}

		f.offset = offset + info.EndOfFile()
	default:
		return -1, os.ErrInvalid
	}

	return f.offset, nil
}

func (f *RemoteFile) Stat() (os.FileInfo, error) {
	fi, err := f.stat(f.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *RemoteFile) stat(ctx context.Context) (os.FileInfo, error) {
	req := &QueryInfoRequest{
		FileInfoClass:         FileAllInformation,
		AdditionalInformation: 0,
		Flags: 0,
	}

	infoBytes, err := f.queryInfo(req, ctx)
	if err != nil {
		return nil, err
	}

	info := FileAllInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	basic := info.BasicInformation()
	std := info.StandardInformation()

	return &RemoteFileStat{
		CreationTime:   time.Unix(0, basic.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, basic.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, basic.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, basic.ChangeTime().Nanoseconds()),
		EndOfFile:      std.EndOfFile(),
		AllocationSize: std.AllocationSize(),
		FileAttributes: basic.FileAttributes(),
		FileName:       base(f.name),
	}, nil
}

func (f *RemoteFile) Sync() (err error) {
	req := new(FlushRequest)
	req.FileId = f.fd

	req.CreditCharge, _, err = f.fs.loanCredit(0, f.ctx)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return err
	}

	res, err := f.sendRecv(SMB2_FLUSH, req, f.ctx)
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	r := FlushResponseDecoder(res)
	if r.IsInvalid() {
		return &os.PathError{Op: "sync", Path: f.name, Err: &InvalidResponseError{"broken flush response format"}}
	}

	return nil
}

func (f *RemoteFile) Truncate(size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	err := f.truncate(size, f.ctx)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

func (f *RemoteFile) truncate(size int64, ctx context.Context) error {
	info := &SetInfoRequest{
		FileInfoClass:         FileEndOfFileInformation,
		AdditionalInformation: 0,
		Input: &FileEndOfFileInformationEncoder{
			EndOfFile: size,
		},
	}

	err := f.setInfo(info, ctx)
	if err != nil {
		return err
	}
	return nil
}

func (f *RemoteFile) Write(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, os.SEEK_CUR, f.ctx)
	if err != nil {
		return -1, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	n, err = f.writeAt(b, off, f.ctx)
	if n != 0 {
		_, e := f.seek(off+int64(n), os.SEEK_SET, f.ctx)

		err = multiError(err, e)
	}
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	return n, nil
}

// WriteAt implements io.WriterAt.
func (f *RemoteFile) WriteAt(b []byte, off int64) (n int, err error) {
	n, err = f.writeAt(b, off, f.ctx)
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

func (f *RemoteFile) writeAt(b []byte, off int64, ctx context.Context) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	if len(b) == 0 {
		return 0, nil
	}

	maxWriteSize := int(f.fs.maxWriteSize)

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxWriteSize:
			m, err := f.writeAtChunk(b[n:], int64(n)+off, ctx)
			if err != nil {
				return -1, err
			}

			n += m
		default:
			m, err := f.writeAtChunk(b[n:n+maxWriteSize], int64(n)+off, ctx)
			if err != nil {
				return -1, err
			}

			n += m
		}
	}
}

// writeAt allows partial write
func (f *RemoteFile) writeAtChunk(b []byte, off int64, ctx context.Context) (n int, err error) {
	creditCharge, m, err := f.fs.loanCredit(len(b), ctx)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return 0, err
	}

	req := &WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, err := f.sendRecv(SMB2_WRITE, req, ctx)
	if err != nil {
		return 0, err
	}

	r := WriteResponseDecoder(res)
	if r.IsInvalid() {
		return 0, &InvalidResponseError{"broken write response format"}
	}

	return int(r.Count()), nil
}

func copyBuffer(r io.Reader, w io.Writer, buf []byte) (n int64, err error) {
	for {
		nr, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				return n, nil
			}

			return n, err
		}

		nw, err := w.Write(buf[:nr])
		if err != nil {
			return n, err
		}
		if nr != nw {
			return n, io.ErrShortWrite
		}

		n += int64(nr)

		if nr < len(buf) {
			return n, nil
		}
	}
}

func (f *RemoteFile) copyTo(op string, wf *RemoteFile, ctx context.Context) (supported bool, n int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	req := &IoctlRequest{
		CtlCode:           FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
	}

	_, output, err := f.ioctl(req, ctx)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == STATUS_NOT_SUPPORTED {
			return false, -1, nil
		}

		return true, -1, &os.LinkError{Op: op, Old: f.name, New: wf.name, Err: err}

	}

	sr := SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return true, -1, &os.LinkError{Op: op, Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken c request resume key response format"}}
	}

	off, err := f.seek(0, os.SEEK_CUR, ctx)
	if err != nil {
		if err != nil {
			return true, -1, &os.PathError{Op: "seek", Path: f.name, Err: err}
		}
	}

	end, err := f.seek(0, os.SEEK_END, ctx)
	if err != nil {
		if err != nil {
			return true, -1, &os.PathError{Op: "seek", Path: f.name, Err: err}
		}
	}

	woff, err := wf.seek(0, os.SEEK_CUR, ctx)
	if err != nil {
		if err != nil {
			return true, -1, &os.PathError{Op: "seek", Path: f.name, Err: err}
		}
	}

	var chunks []*SrvCopychunk

	remains := end

	for {
		const maxChunkSize = 1024 * 1024
		const maxTotalSize = 16 * 1024 * 1024
		// https://msdn.microsoft.com/en-us/library/cc512134(v=vs.85).aspx

		if remains < maxTotalSize {
			nchunks := remains / maxChunkSize

			chunks = make([]*SrvCopychunk, nchunks, nchunks+1)
			for i := range chunks {
				chunks[i] = &SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains %= maxChunkSize
			if remains != 0 {
				chunks = append(chunks, &SrvCopychunk{
					SourceOffset: off + int64(nchunks)*maxChunkSize,
					TargetOffset: woff + int64(nchunks)*maxChunkSize,
					Length:       uint32(remains),
				})
				remains = 0
			}
		} else {
			chunks = make([]*SrvCopychunk, 16)
			for i := range chunks {
				chunks[i] = &SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains -= maxTotalSize
		}

		scc := &SrvCopychunkCopy{
			Chunks: chunks,
		}

		copy(scc.SourceKey[:], sr.ResumeKey())

		cReq := &IoctlRequest{
			CtlCode:           FSCTL_SRV_COPYCHUNK,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		_, output, err = wf.ioctl(cReq, ctx)
		if err != nil {
			return true, -1, &os.LinkError{Op: op, Old: f.name, New: wf.name, Err: err}
		}

		c := SrvCopychunkResponseDecoder(output)
		if c.IsInvalid() {
			return true, -1, &os.LinkError{Op: op, Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken c copy chunk response format"}}
		}

		n += int64(c.TotalBytesWritten())

		if remains == 0 {
			return true, n, nil
		}
	}
}

// ReadFrom implements io.ReadFrom.
// If r is *RemoteFile on the same *RemoteFileSystem as f, it invokes server-side copy.
func (f *RemoteFile) ReadFrom(r io.Reader) (n int64, err error) {
	rf, ok := r.(*RemoteFile)
	if ok && rf.fs == f.fs {
		if supported, n, err := rf.copyTo("read_from", f, f.ctx); supported {
			return n, err
		}

		maxBufferSize := int(f.fs.maxReadSize)
		if maxWriteSize := int(f.fs.maxWriteSize); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(r, f, make([]byte, maxBufferSize))
	}

	maxWriteSize := int(f.fs.maxWriteSize)

	return copyBuffer(r, f, make([]byte, maxWriteSize))
}

// WriteTo implements io.WriteTo.
// If w is *RemoteFile on the same *RemoteFileSystem as f, it invokes server-side copy.
func (f *RemoteFile) WriteTo(w io.Writer) (n int64, err error) {
	wf, ok := w.(*RemoteFile)
	if ok && wf.fs == f.fs {
		if supported, n, err := f.copyTo("write_to", wf, f.ctx); supported {
			return n, err
		}

		maxBufferSize := int(f.fs.maxReadSize)
		if maxWriteSize := int(f.fs.maxWriteSize); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(f, w, make([]byte, maxBufferSize))
	}

	maxReadSize := int(f.fs.maxReadSize)

	return copyBuffer(f, w, make([]byte, maxReadSize))
}

func (f *RemoteFile) ioctl(req *IoctlRequest, ctx context.Context) (input, output []byte, err error) {
	req.CreditCharge, _, err = f.fs.loanCredit(64*1024, ctx) // hope it is enough
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(SMB2_IOCTL, req, ctx)
	if err != nil {
		return nil, nil, err
	}

	r := IoctlResponseDecoder(res)
	if r.IsInvalid() {
		return nil, nil, &InvalidResponseError{"broken ioctl response format"}
	}

	return r.Input(), r.Output(), nil
}

func (f *RemoteFile) readdir(ctx context.Context) (fi []os.FileInfo, err error) {
	req := &QueryDirectoryRequest{
		FileInfoClass:      FileDirectoryInformation,
		Flags:              0,
		FileIndex:          0,
		OutputBufferLength: 64 * 1024,
		FileName:           UTF16FromString("*"),
	}

	req.CreditCharge, _, err = f.fs.loanCredit(64*1024, ctx) // hope it is enough
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(SMB2_QUERY_DIRECTORY, req, ctx)
	if err != nil {
		return nil, err
	}

	r := QueryDirectoryResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query directory response format"}
	}

	output := r.OutputBuffer()

	for {
		info := FileDirectoryInformationDecoder(output)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		name := UTF16ToString(info.FileName())

		if name != "." && name != ".." {
			fi = append(fi, &RemoteFileStat{
				CreationTime:   time.Unix(0, info.CreationTime().Nanoseconds()),
				LastAccessTime: time.Unix(0, info.LastAccessTime().Nanoseconds()),
				LastWriteTime:  time.Unix(0, info.LastWriteTime().Nanoseconds()),
				ChangeTime:     time.Unix(0, info.ChangeTime().Nanoseconds()),
				EndOfFile:      info.EndOfFile(),
				AllocationSize: info.AllocationSize(),
				FileAttributes: info.FileAttributes(),
				FileName:       name,
			})
		}

		next := info.NextEntryOffset()
		if next == 0 {
			return fi, nil
		}

		output = output[next:]
	}
}

func (f *RemoteFile) queryInfo(req *QueryInfoRequest, ctx context.Context) (infoBytes []byte, err error) {
	req.CreditCharge, _, err = f.fs.loanCredit(0, ctx)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	req.InfoType = SMB2_0_INFO_FILE

	req.OutputBufferLength = 64 * 1024

	res, err := f.sendRecv(SMB2_QUERY_INFO, req, ctx)
	if err != nil {
		return nil, err
	}

	r := QueryInfoResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return r.OutputBuffer(), nil
}

func (f *RemoteFile) setInfo(req *SetInfoRequest, ctx context.Context) (err error) {
	req.CreditCharge, _, err = f.fs.loanCredit(0, ctx)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return err
	}

	req.FileId = f.fd

	req.InfoType = SMB2_0_INFO_FILE

	res, err := f.sendRecv(SMB2_SET_INFO, req, ctx)
	if err != nil {
		return err
	}

	r := SetInfoResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken set info response format"}
	}

	return nil
}

func (f *RemoteFile) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	return f.fs.sendRecv(cmd, req, ctx)
}

type RemoteFileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64
	AllocationSize int64
	FileAttributes uint32
	FileName       string
}

func (fs *RemoteFileStat) Name() string {
	return fs.FileName
}

func (fs *RemoteFileStat) Size() int64 {
	return fs.EndOfFile
}

func (fs *RemoteFileStat) Mode() os.FileMode {
	var m os.FileMode

	if fs.FileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0 {
		m |= os.ModeDir | 0111
	}

	if fs.FileAttributes&FILE_ATTRIBUTE_READONLY != 0 {
		m |= 0444
	} else {
		m |= 0666
	}

	if fs.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		m |= os.ModeSymlink
	}

	return m
}

func (fs *RemoteFileStat) ModTime() time.Time {
	return fs.LastWriteTime
}

func (fs *RemoteFileStat) IsDir() bool {
	return fs.Mode().IsDir()
}

func (fs *RemoteFileStat) Sys() interface{} {
	return fs
}
