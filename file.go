package smb2

import (
	"context"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

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

func (fs *FileStat) Sys() any {
	return fs
}

type File struct {
	fs          *Share
	fd          *smb2.FileId
	name        string
	isDir       bool
	dirents     []os.FileInfo
	noMoreFiles bool

	// readAccess reports whether the open granted read data access, which
	// selects FSCTL_SRV_COPYCHUNK over FSCTL_SRV_COPYCHUNK_WRITE as the copy
	// destination ([MS-SMB2] 2.2.31, 3.3.5.15.6).
	readAccess bool

	offset int64

	m sync.Mutex

	notify *notifyState

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

func newFileStat(creation, access, write, change time.Time, size, allocSize int64, attrs uint32, name string) *FileStat {
	return &FileStat{
		CreationTime:   creation,
		LastAccessTime: access,
		LastWriteTime:  write,
		ChangeTime:     change,
		EndOfFile:      size,
		AllocationSize: allocSize,
		FileAttributes: attrs,
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
		base(name),
	)
}

func newFileStatFromFileNetworkOpenInformation(info smb2.FileNetworkOpenInformationDecoder, name string) *FileStat {
	return newFileStat(
		info.CreationTime().Time(),
		info.LastAccessTime().Time(),
		info.LastWriteTime().Time(),
		info.ChangeTime().Time(),
		info.EndOfFile(),
		info.AllocationSize(),
		info.FileAttributes(),
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
		name,
	)
}

func (fs *Share) newFile(r smb2.CreateResponseDecoder, name string) *File {
	fd := r.FileId().Decode()

	f := &File{
		fs:    fs,
		fd:    fd,
		name:  name,
		isDir: r.FileAttributes()&smb2.FILE_ATTRIBUTE_DIRECTORY != 0,
	}

	runtime.SetFinalizer(f, func(f *File) {
		if f == nil {
			return
		}
		if f.closed.CompareAndSwap(false, true) {
			f.fs.closeFile(context.Background(), f.fd)
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

func (f *File) Close(ctx context.Context) error {
	if f == nil {
		return os.ErrInvalid
	}
	if ctx == nil {
		panic("nil context")
	}
	if f.fd == nil || !f.closed.CompareAndSwap(false, true) {
		return os.ErrClosed
	}

	err := f.fs.closeFile(ctx, f.fd)
	if err != nil {
		f.closed.Store(false)
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	runtime.SetFinalizer(f, nil)
	return nil
}

func (f *File) Sync(ctx context.Context) (err error) {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.flush(ctx, f.fd); err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Name() string {
	return f.name
}

// WithContext returns an io/fs/io.Reader adapter sharing this File's state.
func (f *File) WithContext(ctx context.Context) *ContextFile {
	if ctx == nil {
		panic("nil context")
	}
	return &ContextFile{file: f, ctx: ctx}
}

func (f *File) Stat(ctx context.Context) (os.FileInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	fi, err := f.fs.stat(ctx, f.fd, f.name)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) Statfs(ctx context.Context) (FileFsInfo, error) {
	if err := f.checkValid(); err != nil {
		return nil, err
	}
	fi, err := f.fs.statfs(ctx, f.fd, f.name)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) Truncate(ctx context.Context, size int64) error {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.truncate(ctx, f.fd, f.name, size); err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Chmod(ctx context.Context, mode os.FileMode) error {
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := f.fs.chmod(ctx, f.fd, f.name, mode, true); err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) Read(ctx context.Context, b []byte) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	f.m.Lock()
	defer f.m.Unlock()
	if !validFileRange(f.offset, len(b)) {
		return 0, os.ErrInvalid
	}

	// Reads a single chunk of at most maxReadSize bytes. If b is larger, the
	// read returns short and the caller must retry to fetch the remainder.
	n, err = f.fs.read(ctx, f.fd, b, f.offset)
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
func (f *File) ReadAt(ctx context.Context, b []byte, off int64) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	if !validFileRange(off, len(b)) {
		return 0, os.ErrInvalid
	}
	n, err = f.fs.readAt(ctx, f.fd, b, off)
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

func (f *File) Write(ctx context.Context, b []byte) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	f.m.Lock()
	defer f.m.Unlock()
	if !validFileRange(f.offset, len(b)) {
		return 0, os.ErrInvalid
	}

	n, err = f.fs.writeAt(ctx, f.fd, b, f.offset)
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
func (f *File) WriteAt(ctx context.Context, b []byte, off int64) (n int, err error) {
	if err := f.checkValid(); err != nil {
		return 0, err
	}
	if !validFileRange(off, len(b)) {
		return 0, os.ErrInvalid
	}
	n, err = f.fs.writeAt(ctx, f.fd, b, off)
	if err != nil {
		if n < 0 {
			n = 0
		}
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

// Seek implements io.Seeker.
func (f *File) Seek(ctx context.Context, offset int64, whence int) (ret int64, err error) {
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
			queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 0, 24).
			sendRecv(ctx)
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

func (f *File) Readdir(ctx context.Context, n int) (fi []os.FileInfo, err error) {
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
			dirents, err := f.fs.readdir(ctx, f.fd, "*")
			if len(dirents) > 0 {
				f.dirents = append(f.dirents, dirents...)
			}
			if err != nil {
				// Some servers (e.g. Samba) report STATUS_NO_SUCH_FILE on the
				// first QUERY_DIRECTORY of an empty directory instead of
				// STATUS_NO_MORE_FILES ([MS-FSA] 2.1.5.6.3). Treat it as a
				// normal end-of-directory.
				if errors.Is(err, erref.STATUS_NO_MORE_FILES) || errors.Is(err, erref.STATUS_NO_SUCH_FILE) {
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

func (f *File) ReadDir(ctx context.Context, n int) (dirents []iofs.DirEntry, err error) {
	infos, err := f.Readdir(ctx, n)
	if err != nil {
		return nil, err
	}
	dirents = make([]iofs.DirEntry, len(infos))
	for i, info := range infos {
		dirents[i] = iofs.FileInfoToDirEntry(info)
	}
	return dirents, nil
}

func (f *File) Readdirnames(ctx context.Context, n int) (names []string, err error) {
	fi, err := f.Readdir(ctx, n)
	if err != nil {
		return nil, err
	}

	names = make([]string, len(fi))

	for i, st := range fi {
		names[i] = st.Name()
	}

	return names, nil
}

// ReadFrom implements io.ReadFrom.
// If r is *File on the same tree connection (share) as f, it invokes server-side copy.
func (f *File) ReadFrom(ctx context.Context, r io.Reader) (n int64, err error) {
	rw, ok := r.(*ContextFile)
	var rf *File
	if ok {
		rf = rw.file
	}
	if ok && rf == f {
		return 0, os.ErrInvalid
	}
	if ok && rf.fs != nil && f.fs != nil && rf.fs.treeConn == f.fs.treeConn {
		unlock := lockFilePair(rf, f)

		supported, n, err := f.fs.copyFile(ctx, rf.fd, f.fd, rf.name, f.name, rf.offset, f.offset, f.readAccess)
		if supported {
			if n > 0 {
				rf.offset += n
				f.offset += n
			}
			unlock()
			return n, err
		}
		unlock()

		maxBufferSize := min(f.fs.maxReadSize(0), f.fs.maxWriteSize(0))

		return copyBuffer(r, &contextWriter{ctx: ctx, file: f}, make([]byte, maxBufferSize))
	}

	return copyBuffer(r, &contextWriter{ctx: ctx, file: f}, make([]byte, f.fs.maxWriteSize(0)))
}

// WriteTo implements io.WriteTo.
// If w is *File on the same tree connection (share) as f, it invokes server-side copy.
func (f *File) WriteTo(ctx context.Context, w io.Writer) (n int64, err error) {
	ww, ok := w.(*ContextFile)
	var wf *File
	if ok {
		wf = ww.file
	}
	if ok && wf == f {
		return 0, os.ErrInvalid
	}
	if ok && wf.fs != nil && f.fs != nil && wf.fs.treeConn == f.fs.treeConn {
		unlock := lockFilePair(f, wf)

		supported, n, err := f.fs.copyFile(ctx, f.fd, wf.fd, f.name, wf.name, f.offset, wf.offset, wf.readAccess)
		if supported {
			if n > 0 {
				f.offset += n
				wf.offset += n
			}
			unlock()
			return n, err
		}
		unlock()

		maxBufferSize := min(f.fs.maxReadSize(0), f.fs.maxWriteSize(0))

		return copyBuffer(&contextReader{ctx: ctx, file: f}, w, make([]byte, maxBufferSize))
	}

	return copyBuffer(&contextReader{ctx: ctx, file: f}, w, make([]byte, f.fs.maxReadSize(0)))
}

// ----------------------------------------------------------------------------
// File Private Helpers
// ----------------------------------------------------------------------------

func (f *File) readdirAll(ctx context.Context, initialQueryData []byte) ([]os.FileInfo, error) {
	queryRes := smb2.QueryDirectoryResponseDecoder(initialQueryData)
	buf := queryRes.OutputBuffer()

	fis, err := parseReaddir(buf)
	if err != nil {
		return nil, err
	}

	f.m.Lock()
	f.dirents = fis
	f.m.Unlock()

	moreFis, err := f.Readdir(ctx, -1)
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
	return uint64(fi.SectorsPerAllocationUnit) * uint64(fi.BytesPerSector)
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
		if uint64(next) == uint64(len(output)) {
			return fi, nil
		}

		output = output[next:]
	}
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
