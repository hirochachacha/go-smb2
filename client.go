package smb2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
		conn.close(err)
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

	tc, err := c.s.treeConnect(c.ctx, sharename, 0)
	if err != nil {
		return nil, &os.PathError{Op: "mount", Path: sharename, Err: err}
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

	callId := rand.Uint32()

	bindReq := &msrpc.Bind{
		CallId: callId,
	}

	res, err := fs.request().
		create("srvsvc", smb2.GENERIC_READ|smb2.GENERIC_WRITE, smb2.FILE_OPEN, smb2.FILE_SYNCHRONOUS_IO_NONALERT, smb2.FILE_ATTRIBUTE_NORMAL).
		ioctl(smb2.FSCTL_PIPE_TRANSCEIVE, bindReq, msrpc.DefaultMaxFragmentSize).
		sendRecv(fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "listSharenames", Path: "srvsvc", Err: err}
	}
	defer res.close()

	f := fs.newFile(res.data(0), "srvsvc")
	defer f.Close()

	output := smb2.IoctlResponseDecoder(res.data(1)).Output()

	bindAck := msrpc.BindAckDecoder(output)
	if bindAck.IsInvalid() || bindAck.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken bind ack response format"}}
	}

	callId++

	shareEnumReq := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: msrpc.DefaultMaxFragmentSize,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.NetShareEnumAllRequest{
			CallId:     callId,
			ServerName: servername,
			Level:      1, // level 1 seems to be portable
		},
	}

	output, err = fs.ioctl(f.fd, shareEnumReq)
	if err != nil {
		if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
			return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
		}

		buf := make([]byte, msrpc.DefaultMaxFragmentSize)

		var (
			pdu []byte
			rem = output
		)

		pdu, rem, err = fs.readRpcFrag(f.fd, rem, buf, callId)
		if err != nil {
			return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
		}
		output = append([]byte(nil), pdu...)
		firstFrag := msrpc.NetShareEnumAllResponseDecoder(output)

		for firstFrag.PacketFlags()&msrpc.RPC_PACKET_FLAG_LAST == 0 {
			pdu, rem, err = fs.readRpcFrag(f.fd, rem, buf, callId)
			if err != nil {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
			}

			nextFrag := msrpc.NetShareEnumAllResponseDecoder(pdu)
			chunk := nextFrag.Buffer()
			if len(chunk) == 0 {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"empty net share enum response fragment"}}
			}

			if len(output)+len(chunk) > maxNetShareEnumResponseSize {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"net share enum response exceeds maximum size"}}
			}

			output = append(output, chunk...)

			if nextFrag.PacketFlags()&msrpc.RPC_PACKET_FLAG_LAST != 0 {
				break
			}
		}
	}

	enumResp := msrpc.NetShareEnumAllResponseDecoder(output)
	if enumResp.IsInvalid() || enumResp.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
	}

	names, err := enumResp.Sharenames()
	if err != nil {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{fmt.Sprintf("broken net share enum response format: %v", err)}}
	}

	return names, nil
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
	if err := fs.treeConn.disconnect(fs.ctx); err != nil {
		return &os.PathError{Op: "umount", Path: "", Err: err}
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
	if perm&0o200 == 0 {
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

	f, err := fs.createFile(name, req)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if flag&os.O_APPEND != 0 {
		f.offset = f.fileStat.EndOfFile
	}
	return f, nil
}

func (fs *Share) Mkdir(name string, perm os.FileMode) error {
	name = normPath(name)

	if err := validatePath("mkdir", name, false); err != nil {
		return err
	}

	res, err := fs.request().
		create(name, smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_CREATE, smb2.FILE_DIRECTORY_FILE, smb2.FILE_ATTRIBUTE_NORMAL).
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
		setInfo(smb2.FileDispositionInformation, &smb2.FileDispositionInformationEncoder{DeletePending: 1}).
		close()
	res, err := remove.sendRecv(fs.ctx)
	if err != nil {
		if !errors.Is(err, erref.STATUS_ACCESS_DENIED) && !errors.Is(err, erref.STATUS_CANNOT_DELETE) {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		// Fallback for read-only files: opening with DELETE access fails on read-only files.
		// First clear FILE_ATTRIBUTE_READONLY and close the handle, then re-open with DELETE access to set DeletePending.
		chmod, err2 := fs.request().
			create(name, smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
			setInfo(smb2.FileBasicInformation, &smb2.FileBasicInformationEncoder{FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL}).
			close().
			sendRecv(fs.ctx)
		if err2 != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}
		chmod.close()

		retryRes, err := remove.sendRecv(fs.ctx)
		if err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}
		retryRes.close()
		return nil
	}
	res.close()

	return nil
}

func (fs *Share) Rename(oldpath, newpath string) error {
	oldpath = normPath(oldpath)
	newpath = normPath(newpath)

	if err := validatePath("rename", oldpath, false); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	if err := validatePath("rename", newpath, false); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	res, err := fs.request().
		create(oldpath, smb2.DELETE, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.FileRenameInformation, &smb2.FileRenameInformationType2Encoder{
			ReplaceIfExists: 1,
			RootDirectory:   0,
			FileName:        newpath,
		}).
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
		ioctl(smb2.FSCTL_GET_REPARSE_POINT, nil, uint32(fs.maxTransactSize())).
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
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	if err := validatePath("symlink", linkpath, false); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
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

	res, err := fs.request().
		create(linkpath, smb2.FILE_WRITE_ATTRIBUTES|smb2.DELETE, smb2.FILE_CREATE, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		ioctl(smb2.FSCTL_SET_REPARSE_POINT, rdbuf, 0).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		var cerr *CompoundResponseError
		if errors.As(err, &cerr) && cerr.OpError(0) == nil {
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
		queryDir(smb2.FileIdBothDirectoryInformation, "*", uint32(fs.maxTransactSize())).
		sendRecv(fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}
	defer res.close()

	f := fs.newFile(res.data(0), dirname)
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

	maxReadSize := uint32(fs.maxReadSize())

	res, err := fs.request().
		create(filename, smb2.FILE_READ_DATA|smb2.FILE_READ_ATTRIBUTES|smb2.READ_CONTROL, smb2.FILE_OPEN, smb2.FILE_NON_DIRECTORY_FILE|smb2.FILE_SYNCHRONOUS_IO_NONALERT, smb2.FILE_ATTRIBUTE_NORMAL).
		queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 24).
		read(maxReadSize, 0).
		sendRecv(fs.ctx)
	if err != nil {
		// An empty file is not an error: servers report STATUS_END_OF_FILE on
		// the READ of a compound CREATE+QUERY_INFO+READ when the file has no
		// data ([MS-SMB2] 2.2.42). Treat it as success with no content.
		var cerr *CompoundResponseError
		if errors.As(err, &cerr) {
			if cerr.OpError(0) == nil && cerr.OpError(1) == nil {
				var rerr *ResponseError
				if errors.As(cerr.OpError(2), &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_END_OF_FILE {
					return []byte{}, nil
				}
			}
		} else {
			var rerr *ResponseError
			if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_END_OF_FILE {
				return []byte{}, nil
			}
		}
		return nil, &os.PathError{Op: "readfile", Path: filename, Err: err}
	}
	defer res.close()

	f := fs.newFile(res.data(0), filename)
	defer f.Close()

	queryInfoRes := smb2.QueryInfoResponseDecoder(res.data(1))
	readRes := smb2.ReadResponseDecoder(res.data(2))

	data := append([]byte(nil), readRes.Data()...)

	stdInfo := smb2.FileStandardInformationDecoder(queryInfoRes.OutputBuffer())
	if stdInfo.IsInvalid() {
		return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"broken query info response format"}}
	}
	endOfFile := stdInfo.EndOfFile()
	if endOfFile < 0 {
		return nil, &os.PathError{Op: "readfile", Path: filename, Err: &InvalidResponseError{"negative file size"}}
	}

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

	var attrs uint32 = smb2.FILE_ATTRIBUTE_NORMAL
	if perm&0o200 == 0 {
		attrs |= smb2.FILE_ATTRIBUTE_READONLY
	}

	maxWriteSize := fs.maxWriteSize()

	if len(data) <= maxWriteSize { // first path
		res, err := fs.request().
			create(filename, smb2.FILE_WRITE_DATA|smb2.FILE_WRITE_ATTRIBUTES|smb2.READ_CONTROL|smb2.WRITE_DAC, smb2.FILE_OVERWRITE_IF, smb2.FILE_NON_DIRECTORY_FILE|smb2.FILE_SYNCHRONOUS_IO_NONALERT, attrs).
			write(data, 0).
			close().
			sendRecv(fs.ctx)
		if err != nil {
			return &os.PathError{Op: "writefile", Path: filename, Err: err}
		}
		res.close()
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

	if err := fs.chmod(nil, name, mode); err != nil {
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

// ----------------------------------------------------------------------------
// Share Private Core Protocol Implementations (fd-aware)
// ----------------------------------------------------------------------------

func (fs *Share) createFile(name string, req *smb2.CreateRequest) (f *File, err error) {
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		req.Name = name

		res, err := fs.sendRecv(req)
		if err != nil {
			var rerr *ResponseError
			if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_STOPPED_ON_SYMLINK {
				if len(rerr.data) > 0 && len(rerr.data[0]) > 0 {
					name, err = evalSymlinkError(req.Name, rerr.data[0])
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		f = fs.newFile(res.data(0), name)

		res.close()

		return f, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func normalizeSymlinkTarget(target string) string {
	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		return `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		return target[4:]
	default:
		return target
	}
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

	target := normalizeSymlinkTarget(d.SubstituteName())

	if d.Flags()&smb2.SYMLINK_FLAG_RELATIVE == 0 {
		return target + u, nil
	}

	return join(dir(ud), target) + u, nil
}

func (fs *Share) sendRecv(reqs ...smb2.Packet) (*response, error) {
	return fs.treeConn.sendRecv(fs.ctx, reqs...)
}

// ----------------------------------------------------------------------------
// Share Private Core Protocol Implementations (fd-aware)
// ----------------------------------------------------------------------------

func (fs *Share) stat(fd *smb2.FileId, name string) (os.FileInfo, error) {
	req := fs.request()
	idx := 0
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
		idx = 1
	}

	req.queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileAllInformation, uint32(fs.maxTransactSize()))

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(fs.ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	info := smb2.FileAllInformationDecoder(smb2.QueryInfoResponseDecoder(res.data(idx)).OutputBuffer())
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return newFileStatFromFileAllInformation(info, name), nil
}

func (fs *Share) lstat(name string) (os.FileInfo, error) {
	res, err := fs.request().
		create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		close().
		sendRecv(fs.ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	return newFileStatFromCreateResponse(res.data(0), name), nil
}

func (fs *Share) statfs(fd *smb2.FileId, name string) (FileFsInfo, error) {
	req := fs.request()
	idx := 0
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_READ_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
		idx = 1
	}

	req.queryInfo(smb2.SMB2_0_INFO_FILESYSTEM, smb2.FileFsFullSizeInformation, 32)

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(fs.ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	return parseFsFullSizeInfo(res.data(idx))
}

func (fs *Share) truncate(fd *smb2.FileId, name string, size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	req := fs.request()
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_WRITE_DATA, smb2.FILE_OPEN, smb2.FILE_NON_DIRECTORY_FILE|smb2.FILE_SYNCHRONOUS_IO_NONALERT, smb2.FILE_ATTRIBUTE_NORMAL)
	}

	req.setInfo(smb2.FileEndOfFileInformation, &smb2.FileEndOfFileInformationEncoder{EndOfFile: size})

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(fs.ctx)
	if err != nil {
		return err
	}
	res.close()
	return nil
}

func (fs *Share) chtimes(fd *smb2.FileId, name string, atime time.Time, mtime time.Time) error {
	req := fs.request()
	if fd != nil {
		req.withFileId(fd)
	} else {
		req.create(name, smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
	}

	req.setInfo(smb2.FileBasicInformation, &smb2.FileBasicInformationEncoder{
		LastAccessTime: smb2.NsecToFiletime(atime.UnixNano()),
		LastWriteTime:  smb2.NsecToFiletime(mtime.UnixNano()),
	})

	if fd == nil {
		req.close()
	}

	res, err := req.sendRecv(fs.ctx)
	if err != nil {
		return err
	}
	res.close()
	return nil
}

func (fs *Share) chmod(fd *smb2.FileId, name string, mode os.FileMode) error {
	req1 := fs.request()
	idx1 := 0
	if fd != nil {
		req1.withFileId(fd)
	} else {
		req1.create(name, smb2.FILE_READ_ATTRIBUTES|smb2.FILE_WRITE_ATTRIBUTES, smb2.FILE_OPEN, 0, smb2.FILE_ATTRIBUTE_NORMAL)
		idx1 = 1
	}

	// 1st RTT: CREATE(if fd==nil) + QUERY_INFO
	res1, err := req1.
		queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileBasicInformation, 40).
		sendRecv(fs.ctx)
	if err != nil {
		return err
	}
	defer res1.close()

	var targetFd *smb2.FileId
	if fd != nil {
		targetFd = fd
	} else {
		createRes := smb2.CreateResponseDecoder(res1.data(0))
		targetFd = createRes.FileId().Decode()
	}

	base := smb2.FileBasicInformationDecoder(smb2.QueryInfoResponseDecoder(res1.data(idx1)).OutputBuffer())
	if base.IsInvalid() {
		if fd == nil {
			_ = fs.closeFile(targetFd)
		}
		return &InvalidResponseError{"broken query info response format"}
	}

	attrs := computeChmodAttrs(base.FileAttributes(), mode)

	// 2nd RTT: SET_INFO + CLOSE(if fd==nil)
	req2 := fs.request().withFileId(targetFd).
		setInfo(smb2.FileBasicInformation, &smb2.FileBasicInformationEncoder{FileAttributes: attrs})
	if fd == nil {
		req2.close()
	}

	res2, err := req2.sendRecv(fs.ctx)
	if err != nil {
		return err
	}
	defer res2.close()

	return nil
}

func (fs *Share) flush(fd *smb2.FileId) error {
	res, err := fs.request().withFileId(fd).flush().sendRecv(fs.ctx)
	if err != nil {
		return err
	}
	res.close()

	return nil
}

func (fs *Share) readAtChunk(fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxReadSize())
	if m == 0 {
		return 0, nil
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
		FileId:          fd,
	}

	res, err := fs.sendRecv(req)
	if err != nil {
		var rerr *ResponseError
		if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_BUFFER_OVERFLOW && len(rerr.data) > 0 {
			bs := rerr.data[0]
			if len(bs) > m {
				return 0, &InvalidResponseError{"read length exceeds requested length"}
			}
			return copy(b, bs), err
		}
		return 0, err
	}
	defer res.close()

	r := smb2.ReadResponseDecoder(res.data(0))

	bs := r.Data()
	if len(bs) == 0 {
		return 0, &InvalidResponseError{"empty successful read response"}
	}
	if len(bs) > m {
		return 0, &InvalidResponseError{"read length exceeds requested length"}
	}
	n = copy(b, bs)

	return n, nil
}

func (fs *Share) readAtChunkAtLeast(fd *smb2.FileId, b []byte, min int, off int64) (n int, err error) {
	if len(b) < min {
		return 0, io.ErrShortBuffer
	}
	for n < min {
		nn, err := fs.readAtChunk(fd, b[n:], off+int64(n))
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

func (fs *Share) readRpcFrag(fd *smb2.FileId, initial, buf []byte, callId uint32) (pdu, rem []byte, err error) {
	pdu = initial
	if len(pdu) < 24 {
		n, err := fs.readAtChunkAtLeast(fd, buf, 24-len(pdu), 0)
		if err != nil {
			return nil, nil, err
		}
		pdu = append(pdu, buf[:n]...)
	}

	frag := msrpc.NetShareEnumAllResponseDecoder(pdu)
	if frag.IsInvalid() || frag.CallId() != callId {
		return nil, nil, &InvalidResponseError{"broken net share enum response format"}
	}

	fragLen := int(frag.FragLength())
	if len(pdu) < fragLen {
		n, err := fs.readAtChunkAtLeast(fd, buf, fragLen-len(pdu), 0)
		if err != nil {
			return nil, nil, err
		}
		pdu = append(pdu, buf[:n]...)
	}

	return pdu[:fragLen], pdu[fragLen:], nil
}

func (fs *Share) writeAtChunk(fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	m := min(len(b), fs.maxWriteSize())

	req := &smb2.WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
		FileId:           fd,
	}

	res, err := fs.sendRecv(req)
	if err != nil {
		return 0, err
	}
	defer res.close()

	r := smb2.WriteResponseDecoder(res.data(0))
	if r.Count() > uint32(m) {
		return 0, &InvalidResponseError{"write count exceeds requested length"}
	}

	return int(r.Count()), nil
}

func (fs *Share) readdir(fd *smb2.FileId, pattern string) (fi []os.FileInfo, err error) {
	res, err := fs.request().
		withFileId(fd).
		queryDir(smb2.FileIdBothDirectoryInformation, pattern, uint32(fs.maxTransactSize())).
		sendRecv(fs.ctx)
	if err != nil {
		return nil, err
	}
	defer res.close()

	r := smb2.QueryDirectoryResponseDecoder(res.data(0))

	return parseReaddir(r.OutputBuffer())
}

func (fs *Share) ioctl(fd *smb2.FileId, req *smb2.IoctlRequest) (output []byte, err error) {
	payloadSize := int64(encodeSize(req.Input)) + int64(req.OutputCount)
	if payloadSize < int64(req.MaxOutputResponse)+int64(req.MaxInputResponse) {
		payloadSize = int64(req.MaxOutputResponse) + int64(req.MaxInputResponse)
	}

	if int64(fs.maxTransactSize()) < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, fs.maxTransactSize())}
	}

	req.FileId = fd

	res, err := fs.sendRecv(req)
	if err != nil {
		var rerr *ResponseError
		if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_BUFFER_OVERFLOW && len(rerr.data) > 0 {
			return rerr.data[0], err
		}
		return nil, err
	}
	defer res.close()

	r := smb2.IoctlResponseDecoder(res.data(0))

	return append([]byte(nil), r.Output()...), nil
}

func (fs *Share) queryInfo(fd *smb2.FileId, infoType, infoClass uint8, maxOutput uint32) (output []byte, err error) {
	req := &smb2.QueryInfoRequest{
		InfoType:              infoType,
		FileInfoClass:         infoClass,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    maxOutput,
		FileId:                fd,
	}

	res, err := fs.sendRecv(req)
	if err != nil {
		var rerr *ResponseError
		if errors.As(err, &rerr) && erref.NtStatus(rerr.Code) == erref.STATUS_BUFFER_OVERFLOW && len(rerr.data) > 0 {
			return rerr.data[0], err
		}
		return nil, err
	}
	defer res.close()

	r := smb2.QueryInfoResponseDecoder(res.data(0))

	return append([]byte(nil), r.OutputBuffer()...), nil
}

const (
	winMaxPayloadSize           = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
	singleCreditMaxPayloadSize  = 64 * 1024
	maxInt64                    = 1<<63 - 1
	maxNetShareEnumResponseSize = 1024 * 1024
)

func validFileRange(off int64, size int) bool {
	return off >= 0 && (size == 0 || int64(size-1) <= maxInt64-off)
}

func (fs *Share) maxReadSize() int {
	size := int(fs.conn.maxReadSize)
	if size <= 0 {
		size = singleCreditMaxPayloadSize
	}
	if fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		return min(size, singleCreditMaxPayloadSize, fs.conn.maxCreditSize())
	}
	return min(size, winMaxPayloadSize, fs.conn.maxCreditSize())
}

func (fs *Share) maxWriteSize() int {
	size := int(fs.conn.maxWriteSize)
	if size <= 0 {
		size = singleCreditMaxPayloadSize
	}
	if fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		return min(size, singleCreditMaxPayloadSize, fs.conn.maxCreditSize())
	}
	return min(size, winMaxPayloadSize, fs.conn.maxCreditSize())
}

func (fs *Share) maxTransactSize() int {
	size := int(fs.conn.maxTransactSize)
	if size <= 0 {
		size = singleCreditMaxPayloadSize
	}
	if fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		return min(size, singleCreditMaxPayloadSize, fs.conn.maxCreditSize())
	}
	return min(size, winMaxPayloadSize, fs.conn.maxCreditSize())
}

// readAt fills the requested range sequentially until b is full or an error/EOF occurs.
func (fs *Share) readAt(fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	maxReadSize := fs.maxReadSize()
	for n < len(b) {
		m := min(len(b)-n, maxReadSize)
		readN, err := fs.readAtChunk(fd, b[n:n+m], off+int64(n))
		n += readN
		if err != nil {
			var status erref.NtStatus
			if errors.As(err, &status) {
				switch status {
				case erref.STATUS_END_OF_FILE:
					return n, io.EOF
				case erref.STATUS_BUFFER_OVERFLOW:
					if readN > 0 {
						continue
					}
				}
			}
			return n, err
		}
	}
	return n, nil
}

func (fs *Share) read(fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	m := min(len(b), fs.maxReadSize())
	readN, err := fs.readAtChunk(fd, b[:m], off)
	if err != nil {
		var status erref.NtStatus
		if errors.As(err, &status) {
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

func (fs *Share) writeAt(fd *smb2.FileId, b []byte, off int64) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	maxWriteSize := fs.maxWriteSize()
	for n < len(b) {
		m := min(len(b)-n, maxWriteSize)
		written, err := fs.writeAtChunk(fd, b[n:n+m], off+int64(n))
		n += written
		if err != nil {
			return n, err
		}
		if written < m {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (fs *Share) copyFile(srcFd, dstFd *smb2.FileId, srcName, dstName string, srcOffset, dstOffset int64) (supported bool, n int64, err error) {
	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
	}

	output, err := fs.ioctl(srcFd, req)
	if err != nil {
		if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
			return false, 0, nil
		}

		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}

	sr := smb2.SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"broken srv request resume key response format"}}
	}

	res, err := fs.request().withFileId(srcFd).
		queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 24).
		sendRecv(fs.ctx)
	if err != nil {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: err}
	}
	defer res.close()

	info := smb2.FileStandardInformationDecoder(smb2.QueryInfoResponseDecoder(res.data(0)).OutputBuffer())
	if info.IsInvalid() {
		return true, 0, &os.LinkError{Op: "copy", Old: srcName, New: dstName, Err: &InvalidResponseError{"broken query info response format"}}
	}

	end := info.EndOfFile()
	off := srcOffset
	woff := dstOffset

	remains := end - off
	if remains <= 0 {
		return true, 0, nil
	}

	var srvChunks [16]smb2.SrvCopychunk
	var chunks [16]*smb2.SrvCopychunk
	for i := range chunks {
		chunks[i] = &srvChunks[i]
	}

	for {
		const maxChunkSize = 1024 * 1024
		const maxTotalSize = 16 * 1024 * 1024

		var reqChunks []*smb2.SrvCopychunk

		if remains < maxTotalSize {
			nchunks := remains / maxChunkSize
			for i := int64(0); i < nchunks; i++ {
				srvChunks[i] = smb2.SrvCopychunk{
					SourceOffset: off + i*maxChunkSize,
					TargetOffset: woff + i*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			remains %= maxChunkSize
			if remains != 0 {
				srvChunks[nchunks] = smb2.SrvCopychunk{
					SourceOffset: off + nchunks*maxChunkSize,
					TargetOffset: woff + nchunks*maxChunkSize,
					Length:       uint32(remains),
				}
				nchunks++
				remains = 0
			}

			reqChunks = chunks[:nchunks]
		} else {
			for i := int64(0); i < 16; i++ {
				srvChunks[i] = smb2.SrvCopychunk{
					SourceOffset: off + i*maxChunkSize,
					TargetOffset: woff + i*maxChunkSize,
					Length:       maxChunkSize,
				}
			}

			reqChunks = chunks[:16]
			remains -= maxTotalSize
			off += maxTotalSize
			woff += maxTotalSize
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
			CtlCode:           smb2.FSCTL_SRV_COPYCHUNK,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		output, err = fs.ioctl(dstFd, cReq)
		if err != nil {
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

func (fs *Share) closeFile(fd *smb2.FileId) error {
	return fs.closeFileWithContext(fs.ctx, fd)
}

func (fs *Share) closeFileWithContext(ctx context.Context, fd *smb2.FileId) error {
	return fs.treeConn.closeFile(ctx, fd)
}

// ----------------------------------------------------------------------------
// File Operations (Handle-based - Thin Wrappers & Interface)
// ----------------------------------------------------------------------------

type FileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64
	AllocationSize int64
	FileAttributes uint32
	FileId         uint64
	FileName       string
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
		m |= os.ModeDir | 0o111
	}

	if fs.FileAttributes&smb2.FILE_ATTRIBUTE_READONLY != 0 {
		m |= 0o444
	} else {
		m |= 0o666
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

type File struct {
	fs          *Share
	fd          *smb2.FileId
	name        string
	fileStat    *FileStat
	dirents     []os.FileInfo
	noMoreFiles bool

	offset int64

	m sync.Mutex

	closed atomic.Bool
}

var filePairLock sync.Mutex

func lockFilePair(first, second *File) func() {
	filePairLock.Lock()
	first.m.Lock()
	second.m.Lock()
	filePairLock.Unlock()

	return func() {
		second.m.Unlock()
		first.m.Unlock()
	}
}

func newFileStat(creation, access, write, change time.Time, size, allocSize int64, attrs uint32, id uint64, name string) *FileStat {
	return &FileStat{
		CreationTime:   creation,
		LastAccessTime: access,
		LastWriteTime:  write,
		ChangeTime:     change,
		EndOfFile:      size,
		AllocationSize: allocSize,
		FileAttributes: attrs,
		FileId:         id,
		FileName:       name,
	}
}

func newFileStatFromCreateResponse(r smb2.CreateResponseDecoder, name string) *FileStat {
	return newFileStat(
		r.CreationTime().Time(),
		r.LastAccessTime().Time(),
		r.LastWriteTime().Time(),
		r.ChangeTime().Time(),
		r.EndofFile(),
		r.AllocationSize(),
		r.FileAttributes(),
		0,
		base(name),
	)
}

func newFileStatFromFileAllInformation(info smb2.FileAllInformationDecoder, name string) *FileStat {
	basic := info.BasicInformation()
	std := info.StandardInformation()

	return newFileStat(
		basic.CreationTime().Time(),
		basic.LastAccessTime().Time(),
		basic.LastWriteTime().Time(),
		basic.ChangeTime().Time(),
		std.EndOfFile(),
		std.AllocationSize(),
		basic.FileAttributes(),
		uint64(info.InternalInformation().IndexNumber()),
		base(name),
	)
}

func newFileStatFromFileIdBothDirectoryInformation(info smb2.FileIdBothDirectoryInformationDecoder, name string) *FileStat {
	return newFileStat(
		info.CreationTime().Time(),
		info.LastAccessTime().Time(),
		info.LastWriteTime().Time(),
		info.ChangeTime().Time(),
		info.EndOfFile(),
		info.AllocationSize(),
		info.FileAttributes(),
		info.FileId(),
		name,
	)
}

func (fs *Share) newFile(r smb2.CreateResponseDecoder, name string) *File {
	fd := r.FileId().Decode()

	fileStat := newFileStatFromCreateResponse(r, name)

	f := &File{fs: fs, fd: fd, name: name, fileStat: fileStat}

	runtime.SetFinalizer(f, func(f *File) {
		if f == nil {
			return
		}
		if f.closed.CompareAndSwap(false, true) {
			f.fs.closeFileWithContext(context.Background(), f.fd)
		}
	})

	return f
}

func (f *File) checkValid() error {
	if f == nil {
		return os.ErrInvalid
	}
	if f.fd == nil || f.closed.Load() {
		return os.ErrClosed
	}
	return nil
}

func (f *File) Close() error {
	if f == nil {
		return os.ErrInvalid
	}
	if f.fd == nil || !f.closed.CompareAndSwap(false, true) {
		return os.ErrClosed
	}

	runtime.SetFinalizer(f, nil)

	err := f.fs.closeFile(f.fd)
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Sync() (err error) {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.flush(f.fd); err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Name() string {
	return f.name
}

func (f *File) Stat() (os.FileInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	fi, err := f.fs.stat(f.fd, f.name)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) Statfs() (FileFsInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	fi, err := f.fs.statfs(f.fd, f.name)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) Truncate(size int64) error {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.truncate(f.fd, f.name, size); err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	f.m.Lock()
	f.fileStat.EndOfFile = size
	f.m.Unlock()
	return nil
}

func (f *File) Chmod(mode os.FileMode) error {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.chmod(f.fd, f.name, mode); err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Read(b []byte) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	f.m.Lock()
	defer f.m.Unlock()
	if !validFileRange(f.offset, len(b)) {
		return 0, os.ErrInvalid
	}

	// io.Reader may return short, so the missing suffix is left to the next
	// call instead of being retried. Large reads remain chunked in parallel.
	n, err = f.fs.read(f.fd, b, f.offset)
	f.offset += int64(n)
	if err != nil {
		if err == io.EOF {
			return n, io.EOF
		}
		if errors.Is(err, erref.STATUS_END_OF_FILE) {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

// ReadAt implements io.ReaderAt.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	if !validFileRange(off, len(b)) {
		return 0, os.ErrInvalid
	}
	n, err = f.fs.readAt(f.fd, b, off)
	if err == nil && n < len(b) {
		return n, io.EOF
	}
	if err != nil {
		if err == io.EOF {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

func (f *File) Write(b []byte) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	f.m.Lock()
	defer f.m.Unlock()
	if !validFileRange(f.offset, len(b)) {
		return 0, os.ErrInvalid
	}

	n, err = f.fs.writeAt(f.fd, b, f.offset)
	if n > 0 {
		f.offset += int64(n)
	}
	if err != nil {
		if n < 0 {
			n = 0
		}
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	return n, nil
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	if !validFileRange(off, len(b)) {
		return 0, os.ErrInvalid
	}
	n, err = f.fs.writeAt(f.fd, b, off)
	if err != nil {
		if n < 0 {
			n = 0
		}
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

// Seek implements io.Seeker.
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	f.m.Lock()
	defer f.m.Unlock()

	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = f.offset + offset
	case io.SeekEnd:
		res, err := f.fs.request().withFileId(f.fd).
			queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 24).
			sendRecv(f.fs.ctx)
		if err != nil {
			return 0, &os.PathError{Op: "seek", Path: f.name, Err: err}
		}
		defer res.close()

		info := smb2.FileStandardInformationDecoder(smb2.QueryInfoResponseDecoder(res.data(0)).OutputBuffer())
		if info.IsInvalid() {
			return 0, &os.PathError{Op: "seek", Path: f.name, Err: &InvalidResponseError{"broken query info response format"}}
		}

		newOffset = offset + info.EndOfFile()
	default:
		return 0, os.ErrInvalid
	}

	if newOffset < 0 {
		return 0, os.ErrInvalid
	}

	f.offset = newOffset
	return f.offset, nil
}

func (f *File) Readdir(n int) (fi []os.FileInfo, err error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	f.m.Lock()
	defer f.m.Unlock()

	if !f.noMoreFiles {
		if f.dirents == nil {
			f.dirents = []os.FileInfo{}
		}
		for n <= 0 || n > len(f.dirents) {
			dirents, err := f.fs.readdir(f.fd, "*")
			if len(dirents) > 0 {
				f.dirents = append(f.dirents, dirents...)
			}
			if err != nil {
				if errors.Is(err, erref.STATUS_NO_MORE_FILES) {
					f.noMoreFiles = true
					break
				}
				return nil, &os.PathError{Op: "readdir", Path: f.name, Err: err}
			}
			if len(dirents) == 0 {
				f.noMoreFiles = true
				break
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
		return fi[:n:n], nil
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

func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

// ReadFrom implements io.ReadFrom.
// If r is *File on the same tree connection (share) as f, it invokes server-side copy.
func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
	rf, ok := r.(*File)
	if ok && rf == f {
		return 0, os.ErrInvalid
	}
	if ok && rf.fs != nil && f.fs != nil && rf.fs.treeConn == f.fs.treeConn {
		unlock := lockFilePair(rf, f)

		supported, n, err := f.fs.copyFile(rf.fd, f.fd, rf.name, f.name, rf.offset, f.offset)
		if supported {
			if n > 0 {
				rf.offset += n
				f.offset += n
			}
			unlock()
			return n, err
		}
		unlock()

		maxBufferSize := min(f.fs.maxReadSize(), f.fs.maxWriteSize())

		return copyBuffer(r, f, make([]byte, maxBufferSize))
	}

	return copyBuffer(r, f, make([]byte, f.fs.maxWriteSize()))
}

// WriteTo implements io.WriteTo.
// If w is *File on the same tree connection (share) as f, it invokes server-side copy.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	wf, ok := w.(*File)
	if ok && wf == f {
		return 0, os.ErrInvalid
	}
	if ok && wf.fs != nil && f.fs != nil && wf.fs.treeConn == f.fs.treeConn {
		unlock := lockFilePair(f, wf)

		supported, n, err := f.fs.copyFile(f.fd, wf.fd, f.name, wf.name, f.offset, wf.offset)
		if supported {
			if n > 0 {
				f.offset += n
				wf.offset += n
			}
			unlock()
			return n, err
		}
		unlock()

		maxBufferSize := min(f.fs.maxReadSize(), f.fs.maxWriteSize())

		return copyBuffer(f, w, make([]byte, maxBufferSize))
	}

	return copyBuffer(f, w, make([]byte, f.fs.maxReadSize()))
}

// ----------------------------------------------------------------------------
// File Private Helpers
// ----------------------------------------------------------------------------

func (f *File) readdirAll(initialQueryData []byte) ([]os.FileInfo, error) {
	queryRes := smb2.QueryDirectoryResponseDecoder(initialQueryData)
	buf := queryRes.OutputBuffer()

	fis, err := parseReaddir(buf)
	if err != nil {
		return nil, err
	}

	f.m.Lock()
	f.dirents = fis
	f.m.Unlock()

	moreFis, err := f.Readdir(-1)
	if err != nil && err != io.EOF {
		return nil, err
	}

	sort.Slice(moreFis, func(i, j int) bool { return moreFis[i].Name() < moreFis[j].Name() })

	return moreFis, nil
}

// ----------------------------------------------------------------------------
// Types & Low-Level Helpers
// ----------------------------------------------------------------------------

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

func computeChmodAttrs(attrs uint32, mode os.FileMode) uint32 {
	if attrs&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		attrs |= smb2.FILE_ATTRIBUTE_NORMAL
	}

	if mode&0o200 != 0 {
		attrs &^= smb2.FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= smb2.FILE_ATTRIBUTE_READONLY
	}
	return attrs
}

func parseFsFullSizeInfo(buf []byte) (FileFsInfo, error) {
	r1 := smb2.QueryInfoResponseDecoder(buf)
	if r1.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	info := smb2.FileFsFullSizeInformationDecoder(r1.OutputBuffer())
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

func isDotOrDotDot(info smb2.FileIdBothDirectoryInformationDecoder) bool {
	b := info.FileNameBytes()
	if len(b) == 2 {
		return b[0] == '.' && b[1] == 0
	}
	if len(b) == 4 {
		return b[0] == '.' && b[1] == 0 && b[2] == '.' && b[3] == 0
	}
	return false
}

func parseReaddir(output []byte) (fi []os.FileInfo, err error) {
	fi = make([]os.FileInfo, 0, len(output)/128)
	for {
		if len(output) == 0 {
			return fi, nil
		}
		info := smb2.FileIdBothDirectoryInformationDecoder(output)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		if !isDotOrDotDot(info) {
			fi = append(fi, newFileStatFromFileIdBothDirectoryInformation(info, info.FileName()))
		}

		next := info.NextEntryOffset()
		if next == 0 {
			return fi, nil
		}
		if uint64(next) > uint64(len(output)) {
			return nil, &InvalidResponseError{"bad directory entry offset"}
		}
		if uint64(next) == uint64(len(output)) {
			return fi, nil
		}

		output = output[next:]
	}
}

func encodeSize(e smb2.Encoder) int {
	if e == nil {
		return 0
	}
	return e.Size()
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
