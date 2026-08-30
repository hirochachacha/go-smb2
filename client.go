package smb2

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// Dialer contains options for func (*Dialer) Dial.
type Dialer struct {
	MaxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	Negotiator       Negotiator
	Initiator        Initiator
}

// DialWithHostname performs negotiation and authentication.
// It returns a session. It doesn't support NetBIOS transport.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) DialWithHostname(tcpConn net.Conn, hostname string) (*Session, error) {
	return d.DialContextWithHostname(context.Background(), tcpConn, hostname)
}

// DialContextWithHostname performs negotiation and authentication using the provided context.
// Note that returned session doesn't inherit context.
// If you want to use the same context, call Session.WithContext manually.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) DialContextWithHostname(ctx context.Context, tcpConn net.Conn, hostname string) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}

	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(direct(tcpConn), a, ctx)
	if err != nil {
		return nil, err
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		return nil, err
	}

	return &Session{s: s, ctx: context.Background(), addr: tcpConn.RemoteAddr().String(), hostname: hostname}, nil
}

// Session represents a SMB session.
type Session struct {
	s        *session
	ctx      context.Context
	addr     string
	hostname string
}

func (c *Session) WithContext(ctx context.Context) *Session {
	if ctx == nil {
		panic("nil context")
	}
	return &Session{s: c.s, ctx: ctx, addr: c.addr, hostname: c.hostname}
}

// Logoff invalidates the current SMB session.
func (c *Session) Logoff() error {
	return c.s.logoff(c.ctx)
}

// Echo sends an echo request to the server.
func (c *Session) Echo() error {
	return c.s.echo(c.ctx)
}

// Mount mounts the SMB share.
// sharename must follow format like `<share>` or `\\<server>\<share>`.
// Note that the mounted share doesn't inherit session's context.
// If you want to use the same context, call Share.WithContext manually.
func (c *Session) Mount(sharename string) (*Share, error) {
	servername := c.addr
	if c.hostname != "" {
		servername = c.hostname
	}

	sharename = normPath(sharename)

	if !strings.ContainsRune(sharename, '\\') {
		sharename = fmt.Sprintf(`\\%s\%s`, servername, sharename)
	}

	if err := validateMountPath(sharename); err != nil {
		return nil, err
	}

	tc, err := treeConnect(c.s, sharename, 0, c.ctx)
	if err != nil {
		return nil, err
	}

	return &Share{treeConn: tc, ctx: context.Background()}, nil
}

func (c *Session) ListSharenames() ([]string, error) {
	servername := c.addr
	if c.hostname != "" {
		servername = c.hostname
	}

	fs, err := c.Mount(fmt.Sprintf(`\\%s\IPC$`, servername))
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	fs = fs.WithContext(c.ctx)

	f, err := fs.OpenFile("srvsvc", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	callId := rand.Uint32()

	bindReq := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 4280,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.Bind{
			CallId: callId,
		},
	}

	output, err := f.ioctl(bindReq)
	if err != nil {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r1 := msrpc.BindAckDecoder(output)
	if r1.IsInvalid() || r1.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken bind ack response format"}}
	}

	callId++

	reqReq := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 4280,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.NetShareEnumAllRequest{
			CallId:     callId,
			ServerName: servername,
			Level:      1, // level 1 seems to be portable
		},
	}

	output, err = f.ioctl(reqReq)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && erref.NtStatus(rerr.Code) == erref.STATUS_BUFFER_OVERFLOW {
			buf := make([]byte, 4280)

			rlen := 4280 - len(output)

			n, err := f.readAt(buf[:rlen], 0)
			if err != nil {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
			}

			output = append(output, buf[:n]...)

			r2 := msrpc.NetShareEnumAllResponseDecoder(output)
			if r2.IsInvalid() || r2.CallId() != callId {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
			}

			for r2.IsIncomplete() {
				n, err := f.readAt(buf, 0)
				if err != nil {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
				}

				r3 := msrpc.NetShareEnumAllResponseDecoder(buf[:n])
				if r3.IsInvalid() || r3.CallId() != callId {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
				}

				output = append(output, r3.Buffer()...)

				r2 = msrpc.NetShareEnumAllResponseDecoder(output)
			}

			return r2.ShareNameList(), nil
		}

		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r2 := msrpc.NetShareEnumAllResponseDecoder(output)
	if r2.IsInvalid() || r2.IsIncomplete() || r2.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
	}

	return r2.ShareNameList(), nil
}

// Share represents a SMB tree connection with VFS interface.
type Share struct {
	*treeConn
	ctx context.Context
}

func (fs *Share) WithContext(ctx context.Context) *Share {
	if ctx == nil {
		panic("nil context")
	}
	return &Share{
		treeConn: fs.treeConn,
		ctx:      ctx,
	}
}

// Umount disconects the current SMB tree.
func (fs *Share) Umount() error {
	return fs.treeConn.disconnect(fs.ctx)
}

func (fs *Share) Create(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *Share) newFile(r smb2.CreateResponseDecoder, name string) *File {
	fd := r.FileId().Decode()

	fileStat := &FileStat{
		CreationTime:   time.Unix(0, r.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, r.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, r.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, r.ChangeTime().Nanoseconds()),
		EndOfFile:      r.EndofFile(),
		AllocationSize: r.AllocationSize(),
		FileAttributes: r.FileAttributes(),
		FileName:       base(name),
	}

	f := &File{fs: fs, fd: fd, name: name, fileStat: fileStat}

	runtime.SetFinalizer(f, (*File).close)

	return f
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
		access &^= smb2.GENERIC_WRITE
		access |= smb2.FILE_APPEND_DATA
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

	var attrs uint32 = smb2.FILE_ATTRIBUTE_NORMAL
	if perm&0200 == 0 {
		attrs |= smb2.FILE_ATTRIBUTE_READONLY
	}

	req := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       attrs,
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        smb2.FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, req, true)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if flag&os.O_APPEND != 0 {
		f.seek(0, io.SeekEnd)
	}
	return f, nil
}

func (fs *Share) Mkdir(name string, perm os.FileMode) error {
	name = normPath(name)

	if err := validatePath("mkdir", name, false); err != nil {
		return err
	}

	req := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_WRITE_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_CREATE,
		CreateOptions:        smb2.FILE_DIRECTORY_FILE,
	}

	f, err := fs.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Readlink(name string) (string, error) {
	name = normPath(name)

	if err := validatePath("readlink", name, false); err != nil {
		return "", err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_READ_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}

	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_GET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: uint32(f.maxTransactSize()),
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             nil,
	}

	output, err := f.ioctl(req)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: err}
	}

	r := smb2.SymbolicLinkReparseDataBufferDecoder(output)
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	target := r.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	return target, nil
}

func (fs *Share) Remove(name string) error {
	err := fs.remove(name)
	if os.IsPermission(err) {
		if e := fs.Chmod(name, 0666); e != nil {
			return err
		}
		return fs.remove(name)
	}
	return err
}

func (fs *Share) remove(name string) error {
	name = normPath(name)

	if err := validatePath("remove", name, false); err != nil {
		return err
	}

	req := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.DELETE,
		FileAttributes:       0,
		ShareAccess:          smb2.FILE_SHARE_DELETE,
		CreateDisposition:    smb2.FILE_OPEN,
		// CreateOptions:        FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE,
		CreateOptions: smb2.FILE_OPEN_REPARSE_POINT,
	}
	// FILE_DELETE_ON_CLOSE doesn't work for reparse point, so use FileDispositionInformation instead

	f, err := fs.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	err = f.remove()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	return nil
}

func (fs *Share) Rename(oldpath, newpath string) error {
	oldpath = normPath(oldpath)
	newpath = normPath(newpath)

	if err := validatePath("rename from", oldpath, false); err != nil {
		return err
	}

	if err := validatePath("rename to", newpath, false); err != nil {
		return err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.DELETE,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_DELETE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(oldpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	info := &smb2.SetInfoRequest{
		FileInfoClass:         smb2.FileRenameInformation,
		AdditionalInformation: 0,
		Input: &smb2.FileRenameInformationType2Encoder{
			ReplaceIfExists: 1,
			RootDirectory:   0,
			FileName:        newpath,
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
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
func (fs *Share) Symlink(target, linkpath string) error {
	target = normPath(target)
	linkpath = normPath(linkpath)

	if err := validatePath("symlink target", target, true); err != nil {
		return err
	}

	if err := validatePath("symlink linkpath", linkpath, false); err != nil {
		return err
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
			rdbuf.Flags = smb2.SYMLINK_FLAG_RELATIVE // It's not true on window server.
		}
		rdbuf.SubstituteName = target
		rdbuf.PrintName = rdbuf.SubstituteName
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_WRITE_ATTRIBUTES | smb2.DELETE,
		FileAttributes:       smb2.FILE_ATTRIBUTE_REPARSE_POINT,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_CREATE,
		CreateOptions:        smb2.FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(linkpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_SET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 0,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             rdbuf,
	}

	_, err = f.ioctl(req)
	if err != nil {
		f.remove()
		f.close()

		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	return nil
}

func (fs *Share) Lstat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("lstat", name, false); err != nil {
		return nil, err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_READ_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Stat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("stat", name, false); err != nil {
		return nil, err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_READ_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Truncate(name string, size int64) error {
	name = normPath(name)

	if err := validatePath("truncate", name, false); err != nil {
		return err
	}

	if size < 0 {
		return os.ErrInvalid
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_WRITE_DATA,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_NON_DIRECTORY_FILE | smb2.FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}

	err = f.truncate(size)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normPath(name)

	if err := validatePath("chtimes", name, false); err != nil {
		return err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_WRITE_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}

	info := &smb2.SetInfoRequest{
		FileInfoClass:         smb2.FileBasicInformation,
		AdditionalInformation: 0,
		Input: &smb2.FileBasicInformationEncoder{
			LastAccessTime: smb2.NsecToFiletime(atime.UnixNano()),
			LastWriteTime:  smb2.NsecToFiletime(mtime.UnixNano()),
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chmod(name string, mode os.FileMode) error {
	name = normPath(name)

	if err := validatePath("chmod", name, false); err != nil {
		return err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_READ_ATTRIBUTES | smb2.FILE_WRITE_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}

	err = f.chmod(mode)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) ReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := fs.Open(dirname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fis, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}

	sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() })

	return fis, nil
}

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

func (fs *Share) ReadFile(filename string) ([]byte, error) {
	f, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size64 := f.fileStat.Size() + 1 // one byte for final read at EOF

	var size int

	if size64 <= maxInt {
		size = int(size64)

		// If a file claims a small size, read at least 512 bytes.
		// In particular, files in Linux's /proc claim size 0 but
		// then do not work right if read in small pieces,
		// so an initial read of 1 byte would not work correctly.
		if size < 512 {
			size = 512
		}
	} else {
		size = maxInt
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

func (fs *Share) WriteFile(filename string, data []byte, perm os.FileMode) error {
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

func (fs *Share) Statfs(name string) (FileFsInfo, error) {
	name = normPath(name)

	if err := validatePath("statfs", name, false); err != nil {
		return nil, err
	}

	create := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_READ_ATTRIBUTES,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE,
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_DIRECTORY_FILE,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}

	fi, err := f.statfs()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) createFile(name string, req *smb2.CreateRequest, followSymlinks bool) (f *File, err error) {
	if followSymlinks {
		return fs.createFileRec(name, req)
	}

	req.CreditCharge, _, err = fs.loanCredit(0)
	defer func() {
		if err != nil {
			fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.Name = name

	res, err := fs.sendRecv(smb2.SMB2_CREATE, req)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	r := smb2.CreateResponseDecoder(res.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken create response format"}
	}

	f = fs.newFile(r, name)

	return f, nil
}

func (fs *Share) createFileRec(name string, req *smb2.CreateRequest) (f *File, err error) {
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		req.CreditCharge, _, err = fs.loanCredit(0)
		defer func() {
			if err != nil {
				fs.chargeCredit(req.CreditCharge)
			}
		}()
		if err != nil {
			return nil, err
		}

		req.Name = name

		res, err := fs.sendRecv(smb2.SMB2_CREATE, req)
		if err != nil {
			if rerr, ok := err.(*ResponseError); ok && erref.NtStatus(rerr.Code) == erref.STATUS_STOPPED_ON_SYMLINK {
				if len(rerr.data) > 0 {
					name, err = evalSymlinkError(req.Name, rerr.data[0])
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		r := smb2.CreateResponseDecoder(res.Data())
		if r.IsInvalid() {
			res.Close()
			return nil, &InvalidResponseError{"broken create response format"}
		}

		f = fs.newFile(r, name)

		res.Close()

		return f, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func evalSymlinkError(name string, errData []byte) (string, error) {
	d := smb2.SymbolicLinkErrorResponseDecoder(errData)
	if d.IsInvalid() {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	ud, u := d.SplitUnparsedPath(name)
	if ud == "" && u == "" {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	target := d.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	if d.Flags()&smb2.SYMLINK_FLAG_RELATIVE == 0 {
		return target + u, nil
	}

	return dir(ud) + target + u, nil
}

func (fs *Share) sendRecv(cmd uint16, req smb2.Packet) (res *receivedPacket, err error) {
	return fs.session.sendRecv(cmd, req, fs.ctx)
}

func (fs *Share) loanCredit(payloadSize int) (creditCharge uint16, grantedPayloadSize int, err error) {
	return fs.session.conn.loanCredit(payloadSize, fs.ctx)
}

type File struct {
	fs          *Share
	fd          *smb2.FileId
	name        string
	fileStat    *FileStat
	dirents     []os.FileInfo
	noMoreFiles bool

	offset int64

	m sync.Mutex
}

func (f *File) Close() error {
	if f == nil {
		return os.ErrInvalid
	}

	err := f.close()
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) close() error {
	if f == nil || f.fd == nil {
		return os.ErrInvalid
	}

	req := &smb2.CloseRequest{
		Flags: 0,
	}

	req.CreditCharge = 1

	req.FileId = f.fd

	res, err := f.sendRecv(smb2.SMB2_CLOSE, req)
	if err != nil {
		return err
	}
	defer res.Close()

	r := smb2.CloseResponseDecoder(res.Data())
	if r.IsInvalid() {
		return &InvalidResponseError{"broken close response format"}
	}

	f.fd = nil

	runtime.SetFinalizer(f, nil)

	return nil
}

func (f *File) remove() error {
	info := &smb2.SetInfoRequest{
		FileInfoClass:         smb2.FileDispositionInformation,
		AdditionalInformation: 0,
		Input: &smb2.FileDispositionInformationEncoder{
			DeletePending: 1,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Name() string {
	return f.name
}

func (f *File) Read(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	n, err = f.readAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		if err, ok := err.(*ResponseError); ok && erref.NtStatus(err.Code) == erref.STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	return
}

// ReadAt implements io.ReaderAt.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	n, err = f.readAt(b, off)
	if err != nil {
		if err, ok := err.(*ResponseError); ok && erref.NtStatus(err.Code) == erref.STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

const (
	winMaxPayloadSize          = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
	singleCreditMaxPayloadSize = 64 * 1024
)

func (f *File) maxReadSize() int {
	size := int(f.fs.maxReadSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxWriteSize() int {
	size := int(f.fs.maxWriteSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxTransactSize() int {
	size := int(f.fs.maxTransactSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) readAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	maxReadSize := f.maxReadSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxReadSize:
			readN, isEOF, err := f.readAtChunk(b[n:], int64(n)+off)
			n += readN
			if err != nil {
				if err, ok := err.(*ResponseError); ok && erref.NtStatus(err.Code) == erref.STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			if isEOF {
				return n, nil
			}
		default:
			readN, isEOF, err := f.readAtChunk(b[n:n+maxReadSize], int64(n)+off)
			n += readN
			if err != nil {
				if err, ok := err.(*ResponseError); ok && erref.NtStatus(err.Code) == erref.STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			if isEOF {
				return n, nil
			}
		}
	}
}

func (f *File) readAtChunk(b []byte, off int64) (n int, isEOF bool, err error) {
	creditCharge, m, err := f.fs.loanCredit(len(b))
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return 0, false, err
	}

	req := &smb2.ReadRequest{
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

	res, err := f.sendRecv(smb2.SMB2_READ, req)
	if err != nil {
		return 0, false, err
	}
	defer res.Close()

	r := smb2.ReadResponseDecoder(res.Data())
	if r.IsInvalid() {
		return 0, false, &InvalidResponseError{"broken read response format"}
	}

	bs := r.Data()
	n = copy(b, bs)

	return n, len(bs) < m, nil
}

func (f *File) Readdir(n int) (fi []os.FileInfo, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	if !f.noMoreFiles {
		if f.dirents == nil {
			f.dirents = []os.FileInfo{}
		}
		for n <= 0 || n > len(f.dirents) {
			dirents, err := f.readdir("*")
			if len(dirents) > 0 {
				f.dirents = append(f.dirents, dirents...)
			}
			if err != nil {
				if err, ok := err.(*ResponseError); ok && erref.NtStatus(err.Code) == erref.STATUS_NO_MORE_FILES {
					f.noMoreFiles = true
					break
				}
				return nil, &os.PathError{Op: "readdir", Path: f.name, Err: err}
			}
		}
	}

	fi = f.dirents

	if n > 0 {
		if len(fi) == 0 {
			return fi, io.EOF
		}

		if len(fi) < n {
			f.dirents = []os.FileInfo{}
			return fi, nil
		}

		f.dirents = fi[n:]
		return fi[:n], nil

	}

	f.dirents = []os.FileInfo{}

	return fi, nil
}

func (f *File) Readdirnames(n int) (names []string, err error) {
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
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	ret, err = f.seek(offset, whence)
	if err != nil {
		return ret, &os.PathError{Op: "seek", Path: f.name, Err: err}
	}
	return ret, nil
}

func (f *File) seek(offset int64, whence int) (ret int64, err error) {
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		req := &smb2.QueryInfoRequest{
			InfoType:              smb2.SMB2_0_INFO_FILE,
			FileInfoClass:         smb2.FileStandardInformation,
			AdditionalInformation: 0,
			Flags:                 0,
			OutputBufferLength:    24,
		}

		infoBytes, err := f.queryInfo(req)
		if err != nil {
			return -1, err
		}

		info := smb2.FileStandardInformationDecoder(infoBytes)
		if info.IsInvalid() {
			return -1, &InvalidResponseError{"broken query info response format"}
		}

		f.offset = offset + info.EndOfFile()
	default:
		return -1, os.ErrInvalid
	}

	return f.offset, nil
}

func (f *File) Stat() (os.FileInfo, error) {
	fi, err := f.stat()
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) stat() (os.FileInfo, error) {
	req := &smb2.QueryInfoRequest{
		InfoType:              smb2.SMB2_0_INFO_FILE,
		FileInfoClass:         smb2.FileAllInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    uint32(f.maxTransactSize()),
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := smb2.FileAllInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	basic := info.BasicInformation()
	std := info.StandardInformation()

	return &FileStat{
		CreationTime:   time.Unix(0, basic.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, basic.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, basic.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, basic.ChangeTime().Nanoseconds()),
		EndOfFile:      std.EndOfFile(),
		AllocationSize: std.AllocationSize(),
		FileAttributes: basic.FileAttributes(),
		FileId:         uint64(info.InternalInformation().IndexNumber()),
		FileName:       base(f.name),
	}, nil
}

func (f *File) Statfs() (FileFsInfo, error) {
	fi, err := f.statfs()
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: err}
	}
	return fi, nil
}

type FileFsInfo interface {
	BlockSize() uint64
	FragmentSize() uint64
	TotalBlockCount() uint64
	FreeBlockCount() uint64
	AvailableBlockCount() uint64
}

type fileFsFullSizeInformation struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

func (fi *fileFsFullSizeInformation) BlockSize() uint64 {
	return uint64(fi.BytesPerSector)
}

func (fi *fileFsFullSizeInformation) FragmentSize() uint64 {
	return uint64(fi.SectorsPerAllocationUnit)
}

func (fi *fileFsFullSizeInformation) TotalBlockCount() uint64 {
	return uint64(fi.TotalAllocationUnits)
}

func (fi *fileFsFullSizeInformation) FreeBlockCount() uint64 {
	return uint64(fi.ActualAvailableAllocationUnits)
}

func (fi *fileFsFullSizeInformation) AvailableBlockCount() uint64 {
	return uint64(fi.CallerAvailableAllocationUnits)
}

func (f *File) statfs() (FileFsInfo, error) {
	req := &smb2.QueryInfoRequest{
		InfoType:              smb2.SMB2_0_INFO_FILESYSTEM,
		FileInfoClass:         smb2.FileFsFullSizeInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    32,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := smb2.FileFsFullSizeInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return &fileFsFullSizeInformation{
		TotalAllocationUnits:           info.TotalAllocationUnits(),
		CallerAvailableAllocationUnits: info.CallerAvailableAllocationUnits(),
		ActualAvailableAllocationUnits: info.ActualAvailableAllocationUnits(),
		SectorsPerAllocationUnit:       info.SectorsPerAllocationUnit(),
		BytesPerSector:                 info.BytesPerSector(),
	}, nil
}

func (f *File) Sync() (err error) {
	req := new(smb2.FlushRequest)
	req.FileId = f.fd

	req.CreditCharge, _, err = f.fs.loanCredit(0)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	res, err := f.sendRecv(smb2.SMB2_FLUSH, req)
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}
	defer res.Close()

	r := smb2.FlushResponseDecoder(res.Data())
	if r.IsInvalid() {
		return &os.PathError{Op: "sync", Path: f.name, Err: &InvalidResponseError{"broken flush response format"}}
	}

	return nil
}

func (f *File) Truncate(size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	err := f.truncate(size)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) truncate(size int64) error {
	info := &smb2.SetInfoRequest{
		FileInfoClass:         smb2.FileEndOfFileInformation,
		AdditionalInformation: 0,
		Input: &smb2.FileEndOfFileInformationEncoder{
			EndOfFile: size,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Chmod(mode os.FileMode) error {
	err := f.chmod(mode)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) chmod(mode os.FileMode) error {
	req := &smb2.QueryInfoRequest{
		InfoType:              smb2.SMB2_0_INFO_FILE,
		FileInfoClass:         smb2.FileBasicInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    40,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return err
	}

	base := smb2.FileBasicInformationDecoder(infoBytes)
	if base.IsInvalid() {
		return &InvalidResponseError{"broken query info response format"}
	}

	attrs := base.FileAttributes()

	// If the file is not a directory, we have to set the normal attribute.
	if attrs&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		attrs |= smb2.FILE_ATTRIBUTE_NORMAL
	}

	if mode&0200 != 0 {
		attrs &^= smb2.FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= smb2.FILE_ATTRIBUTE_READONLY
	}

	info := &smb2.SetInfoRequest{
		FileInfoClass:         smb2.FileBasicInformation,
		AdditionalInformation: 0,
		Input: &smb2.FileBasicInformationEncoder{
			FileAttributes: attrs,
		},
	}

	err = f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Write(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	n, err = f.writeAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	return n, nil
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	n, err = f.writeAt(b, off)
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

func (f *File) writeAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	if len(b) == 0 {
		return 0, nil
	}

	maxWriteSize := f.maxWriteSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxWriteSize:
			m, err := f.writeAtChunk(b[n:], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		default:
			m, err := f.writeAtChunk(b[n:n+maxWriteSize], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		}
	}
}

// writeAt allows partial write
func (f *File) writeAtChunk(b []byte, off int64) (n int, err error) {
	creditCharge, m, err := f.fs.loanCredit(len(b))
	defer func() {
		if err != nil {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return 0, err
	}

	req := &smb2.WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, err := f.sendRecv(smb2.SMB2_WRITE, req)
	if err != nil {
		return 0, err
	}
	defer res.Close()

	r := smb2.WriteResponseDecoder(res.Data())
	if r.IsInvalid() {
		return 0, &InvalidResponseError{"broken write response format"}
	}

	return int(r.Count()), nil
}

func copyBuffer(r io.Reader, w io.Writer, buf []byte) (n int64, err error) {
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

func (f *File) copyTo(wf *File) (supported bool, n int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
	}

	output, err := f.ioctl(req)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && erref.NtStatus(rerr.Code) == erref.STATUS_NOT_SUPPORTED {
			return false, -1, nil
		}

		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}

	}

	sr := smb2.SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken srv request resume key response format"}}
	}

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	end, err := f.seek(0, io.SeekEnd)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	woff, err := wf.seek(0, io.SeekCurrent)
	if err != nil {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	var chunks []*smb2.SrvCopychunk

	remains := end

	for {
		const maxChunkSize = 1024 * 1024
		const maxTotalSize = 16 * 1024 * 1024
		// https://msdn.microsoft.com/en-us/library/cc512134(v=vs.85).aspx

		if remains < maxTotalSize {
			nchunks := remains / maxChunkSize

			chunks = make([]*smb2.SrvCopychunk, nchunks, nchunks+1)
			for i := range chunks {
				chunks[i] = &smb2.SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains %= maxChunkSize
			if remains != 0 {
				chunks = append(chunks, &smb2.SrvCopychunk{
					SourceOffset: off + int64(nchunks)*maxChunkSize,
					TargetOffset: woff + int64(nchunks)*maxChunkSize,
					Length:       uint32(remains),
				})
				remains = 0
			}
		} else {
			chunks = make([]*smb2.SrvCopychunk, 16)
			for i := range chunks {
				chunks[i] = &smb2.SrvCopychunk{
					SourceOffset: off + int64(i)*maxChunkSize,
					TargetOffset: woff + int64(i)*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains -= maxTotalSize
		}

		scc := &smb2.SrvCopychunkCopy{
			Chunks: chunks,
		}

		copy(scc.SourceKey[:], sr.ResumeKey())

		cReq := &smb2.IoctlRequest{
			CtlCode:           smb2.FSCTL_SRV_COPYCHUNK,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		output, err = wf.ioctl(cReq)
		if err != nil {
			return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
		}

		c := smb2.SrvCopychunkResponseDecoder(output)
		if c.IsInvalid() {
			return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: &InvalidResponseError{"broken srv copy chunk response format"}}
		}

		n += int64(c.TotalBytesWritten())

		if remains == 0 {
			return true, n, nil
		}
	}
}

// ReadFrom implements io.ReadFrom.
// If r is *File on the same *Share as f, it invokes server-side copy.
func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
	rf, ok := r.(*File)
	if ok && rf.fs == f.fs {
		if supported, n, err := rf.copyTo(f); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(r, f, make([]byte, maxBufferSize))
	}

	return copyBuffer(r, f, make([]byte, f.maxWriteSize()))
}

// WriteTo implements io.WriteTo.
// If w is *File on the same *Share as f, it invokes server-side copy.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	wf, ok := w.(*File)
	if ok && wf.fs == f.fs {
		if supported, n, err := f.copyTo(wf); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(f, w, make([]byte, maxBufferSize))
	}

	return copyBuffer(f, w, make([]byte, f.maxReadSize()))
}

func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

func (f *File) encodeSize(e smb2.Encoder) int {
	if e == nil {
		return 0
	}
	return e.Size()
}

func (f *File) ioctl(req *smb2.IoctlRequest) (output []byte, err error) {
	payloadSize := f.encodeSize(req.Input) + int(req.OutputCount)
	if payloadSize < int(req.MaxOutputResponse+req.MaxInputResponse) {
		payloadSize = int(req.MaxOutputResponse + req.MaxInputResponse)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(smb2.SMB2_IOCTL, req)
	if err != nil {
		if res == nil {
			return nil, err
		}
		defer res.Close()
		r := smb2.IoctlResponseDecoder(res.Data())
		if r.IsInvalid() {
			return nil, err
		}
		return append([]byte(nil), r.Output()...), err
	}
	defer res.Close()

	r := smb2.IoctlResponseDecoder(res.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken ioctl response format"}
	}

	return append([]byte(nil), r.Output()...), nil
}

func (f *File) readdir(pattern string) (fi []os.FileInfo, err error) {
	req := &smb2.QueryDirectoryRequest{
		FileInfoClass:      smb2.FileIdBothDirectoryInformation,
		Flags:              0,
		FileIndex:          0,
		OutputBufferLength: uint32(f.maxTransactSize()),
		FileName:           pattern,
	}

	payloadSize := int(req.OutputBufferLength)

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(smb2.SMB2_QUERY_DIRECTORY, req)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	r := smb2.QueryDirectoryResponseDecoder(res.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query directory response format"}
	}

	output := r.OutputBuffer()

	for {
		info := smb2.FileIdBothDirectoryInformationDecoder(output)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		name := info.FileName()

		if name != "." && name != ".." {
			fi = append(fi, &FileStat{
				CreationTime:   time.Unix(0, info.CreationTime().Nanoseconds()),
				LastAccessTime: time.Unix(0, info.LastAccessTime().Nanoseconds()),
				LastWriteTime:  time.Unix(0, info.LastWriteTime().Nanoseconds()),
				ChangeTime:     time.Unix(0, info.ChangeTime().Nanoseconds()),
				EndOfFile:      info.EndOfFile(),
				AllocationSize: info.AllocationSize(),
				FileAttributes: info.FileAttributes(),
				FileId:         info.FileId(),
				FileName:       name,
			})
		}

		next := info.NextEntryOffset()
		if next == 0 {
			return fi, nil
		}
		if uint64(next) >= uint64(len(output)) {
			return nil, &InvalidResponseError{"bad directory entry offset"}
		}

		output = output[next:]
	}
}

func (f *File) queryInfo(req *smb2.QueryInfoRequest) (infoBytes []byte, err error) {
	payloadSize := f.encodeSize(req.Input)
	if payloadSize < int(req.OutputBufferLength) {
		payloadSize = int(req.OutputBufferLength)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.FileId = f.fd

	res, err := f.sendRecv(smb2.SMB2_QUERY_INFO, req)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	r := smb2.QueryInfoResponseDecoder(res.Data())
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return append([]byte(nil), r.OutputBuffer()...), nil
}

func (f *File) setInfo(req *smb2.SetInfoRequest) (err error) {
	payloadSize := f.encodeSize(req.Input)

	if f.maxTransactSize() < payloadSize {
		return &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	req.CreditCharge, _, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return err
	}

	req.FileId = f.fd

	req.InfoType = smb2.SMB2_0_INFO_FILE

	res, err := f.sendRecv(smb2.SMB2_SET_INFO, req)
	if err != nil {
		return err
	}
	defer res.Close()

	r := smb2.SetInfoResponseDecoder(res.Data())
	if r.IsInvalid() {
		return &InvalidResponseError{"broken set info response format"}
	}

	return nil
}

func (f *File) sendRecv(cmd uint16, req smb2.Packet) (res *receivedPacket, err error) {
	return f.fs.sendRecv(cmd, req)
}

type FileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64
	AllocationSize int64
	FileAttributes uint32
	// FileId is the server's 64-bit file reference number (the MFT record plus
	// sequence number on NTFS, the inode number on Samba). It is populated by
	// File.Readdir, File.ReaddirPlus and File.Stat.
	//
	// It is 0 from Share.Stat and Share.Lstat, which report the stat carried by
	// the CREATE response rather than issuing a separate query, and that
	// response has no file id; obtain one via File.Stat on an open handle. It
	// is also 0 when the server itself supplies none, as some legacy and
	// non-native backends do.
	FileId   uint64
	FileName string
}

func (fs *FileStat) Name() string {
	return fs.FileName
}

func (fs *FileStat) Size() int64 {
	return fs.EndOfFile
}

func (fs *FileStat) Mode() os.FileMode {
	var m os.FileMode

	if fs.FileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY != 0 {
		m |= os.ModeDir | 0111
	}

	if fs.FileAttributes&smb2.FILE_ATTRIBUTE_READONLY != 0 {
		m |= 0444
	} else {
		m |= 0666
	}

	if fs.FileAttributes&smb2.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		m |= os.ModeSymlink
	}

	return m
}

func (fs *FileStat) ModTime() time.Time {
	return fs.LastWriteTime
}

func (fs *FileStat) IsDir() bool {
	return fs.Mode().IsDir()
}

func (fs *FileStat) Sys() interface{} {
	return fs
}
