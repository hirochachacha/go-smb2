package smb2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var le = binary.LittleEndian

var (
	_ func(context.Context, string) ([]string, error) = (&Client{}).ListShareNames
	_ func(string) (*Share, error)                    = (&Session{}).Mount
	_ func() ([]string, error)                        = (&Session{}).ListSharenames
)

type partialReader struct {
	buf *bytes.Buffer
}

type testCredentialsFunc func(context.Context, string) (Initiator, error)

func (f testCredentialsFunc) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	return f(ctx, serverName)
}

func TestNewClientRequiresCredentials(t *testing.T) {
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Fatal("NewClient accepted empty Credentials")
	}
}

func TestClientMountSelectsCredentialsAndTransport(t *testing.T) {
	wantErr := errors.New("transport failed")
	var credentialServer, transportServer string
	client, err := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(_ context.Context, serverName string) (Initiator, error) {
			credentialServer = serverName
			return &NTLMInitiator{User: "user"}, nil
		}),
		Transport: func(_ context.Context, serverName string) (Transport, error) {
			transportServer = serverName
			return nil, wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Mount(context.Background(), `\\files.example.com\share`)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Mount error = %v, want %v", err, wantErr)
	}
	if credentialServer != "files.example.com" || transportServer != "files.example.com" {
		t.Fatalf("credential/transport servers = %q, %q", credentialServer, transportServer)
	}
}

func TestClientClosePreventsConnections(t *testing.T) {
	providerCalled := false
	client, err := NewClient(ClientConfig{Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
		providerCalled = true
		return &NTLMInitiator{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	_, err = client.Mount(context.Background(), `\\server\share`)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Mount after Close = %v", err)
	}
	if providerCalled {
		t.Fatal("Credentials called after Close")
	}
}

func TestNTLMCredentialCreatesFreshInitiators(t *testing.T) {
	hash := []byte{1, 2, 3}
	credentials := NTLMCredential{User: "user", Password: "password", Hash: hash, Domain: "domain", Workstation: "workstation"}
	firstValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*NTLMInitiator)
	second := secondValue.(*NTLMInitiator)
	if first == second || first.TargetSPN != "cifs/server" || second.TargetSPN != "cifs/server" {
		t.Fatalf("initiators were not created independently: %p, %p", first, second)
	}
	hash[0] = 9
	if first.Hash[0] != 1 || second.Hash[0] != 1 {
		t.Fatal("credential hash was not copied")
	}
}

func (p *partialReader) Read(b []byte) (int, error) {
	if len(b) < 2 {
		return p.buf.Read(b)
	}
	// read partial of b
	return p.buf.Read(b[:len(b)/2])
}

func TestSessionServername(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "ipv4 address", addr: "192.0.2.10:445", want: "192.0.2.10"},
		{name: "ipv6 address", addr: "[2001:db8::10]:445", want: "2001:db8::10"},
		{name: "unparseable address", addr: "server", want: "server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{addr: tt.addr}
			if got := s.serverName(); got != tt.want {
				t.Errorf("servername = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFileAttributesFromPerm(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
		want uint32
	}{
		{name: "writable", perm: 0o666, want: smb2.FILE_ATTRIBUTE_NORMAL},
		{name: "readonly", perm: 0o444, want: smb2.FILE_ATTRIBUTE_NORMAL | smb2.FILE_ATTRIBUTE_READONLY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileAttributesFromPerm(tt.perm); got != tt.want {
				t.Errorf("fileAttributesFromPerm(%#o) = %#x, want %#x", tt.perm, got, tt.want)
			}
		})
	}
}

func TestChmodStillUsesFileBasicInformation(t *testing.T) {
	f, serverConn := newTestFile(t)
	dt := direct(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		query, err := readMsg(dt)
		if err != nil {
			return
		}
		queryPacket := smb2.PacketCodec(query)
		queryRequest := smb2.QueryInfoRequestDecoder(queryPacket.Body())
		if queryPacket.Command() != smb2.SMB2_QUERY_INFO || queryRequest.IsInvalid() ||
			queryRequest.InfoType() != smb2.SMB2_0_INFO_FILE || queryRequest.FileInfoClass() != smb2.FileBasicInformation {
			return
		}
		sendTestResponse(dt, query, &smb2.QueryInfoResponse{
			Output: &smb2.FileBasicInformationEncoder{FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL},
		}, uint32(erref.STATUS_SUCCESS))

		set, err := readMsg(dt)
		if err != nil {
			return
		}
		setPacket := smb2.PacketCodec(set)
		setRequest := smb2.SetInfoRequestDecoder(setPacket.Body())
		if setPacket.Command() != smb2.SMB2_SET_INFO || setRequest.IsInvalid() ||
			setRequest.InfoType() != smb2.SMB2_0_INFO_FILE || setRequest.FileInfoClass() != smb2.FileBasicInformation ||
			setRequest.AdditionalInformation() != 0 {
			return
		}
		sendTestResponse(dt, set, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
	}()

	if err := f.Chmod(0o644); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestValidateChtimesTime(t *testing.T) {
	tests := []struct {
		name string
		when time.Time
		want bool
	}{
		{name: "zero", when: time.Time{}, want: true},
		{name: "filetime epoch", when: time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "before filetime epoch", when: time.Date(1600, time.December, 31, 23, 59, 59, 0, time.UTC), want: false},
		{name: "normal", when: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "future FILETIME", when: time.Date(2300, time.January, 1, 0, 0, 0, 0, time.UTC), want: true},
		{name: "after FILETIME range", when: time.Date(100000, time.January, 1, 0, 0, 0, 0, time.UTC), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChtimesTime(tt.when)
			if (err == nil) != tt.want {
				t.Errorf("validateChtimesTime(%v) error = %v, want valid=%v", tt.when, err, tt.want)
			}
		})
	}
}

func TestCopyBufferPartialRead(t *testing.T) {
	bufIn := []byte("this is a partial read test data")
	bufR := make([]byte, len(bufIn))
	copy(bufR, bufIn)
	p := &partialReader{
		buf: bytes.NewBuffer(bufR),
	}
	var bufW bytes.Buffer
	n, err := copyBuffer(p, &bufW, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(bufIn)) {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(bufIn, bufW.Bytes()) {
		t.Fatal("data not equal")
	}
}

func TestNilAndClosedFileMethods(t *testing.T) {
	var nilFile *File
	closedFile := &File{}

	if err := nilFile.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("nil.Close() should return os.ErrInvalid, got %v", err)
	}
	if err := closedFile.Close(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("closedFile.Close() should return os.ErrClosed, got %v", err)
	}

	testCases := []struct {
		name        string
		f           *File
		expectedErr error
	}{
		{"nil", nilFile, os.ErrInvalid},
		{"closed", closedFile, os.ErrClosed},
	}

	for _, tc := range testCases {
		f := tc.f
		expected := tc.expectedErr

		if err := f.Sync(); !errors.Is(err, expected) {
			t.Errorf("[%s] Sync error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Stat(); !errors.Is(err, expected) {
			t.Errorf("[%s] Stat error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Statfs(); !errors.Is(err, expected) {
			t.Errorf("[%s] Statfs error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Truncate(0); !errors.Is(err, expected) {
			t.Errorf("[%s] Truncate error expected %v, got %v", tc.name, expected, err)
		}
		if err := f.Chmod(0o644); !errors.Is(err, expected) {
			t.Errorf("[%s] Chmod error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Read(make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Read error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] ReadAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Write(make([]byte, 1)); !errors.Is(err, expected) {
			t.Errorf("[%s] Write error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.WriteAt(make([]byte, 1), 0); !errors.Is(err, expected) {
			t.Errorf("[%s] WriteAt error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Seek(0, 0); !errors.Is(err, expected) {
			t.Errorf("[%s] Seek error expected %v, got %v", tc.name, expected, err)
		}
		if _, err := f.Readdir(-1); !errors.Is(err, expected) {
			t.Errorf("[%s] Readdir error expected %v, got %v", tc.name, expected, err)
		}
	}
}

func TestNegativeOffsetValidation(t *testing.T) {
	f := &File{fd: &smb2.FileId{}}

	if _, err := f.ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("ReadAt with negative offset should return error")
	}

	if _, err := f.WriteAt(make([]byte, 1), -1); err == nil {
		t.Error("WriteAt with negative offset should return error")
	}

	if _, err := f.Seek(-1, 0); err == nil {
		t.Error("Seek to negative offset should return error")
	}
}

func TestSymlinkRejectsEmptyTarget(t *testing.T) {
	fs := &Share{}
	var err error

	require.NotPanics(t, func() {
		err = fs.Symlink("", "link")
	})
	require.Error(t, err)
}

func TestSymlinkReparseDataBufferBoundary(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		flags          uint32
		substituteName string
		printName      string
	}{
		{
			name:           "relative",
			target:         strings.Repeat("r", 4091),
			flags:          smb2.SYMLINK_FLAG_RELATIVE,
			substituteName: strings.Repeat("r", 4091),
			printName:      strings.Repeat("r", 4091),
		},
		{
			name:           "leading backslash",
			target:         `\` + strings.Repeat("a", 4090),
			flags:          0,
			substituteName: `\` + strings.Repeat("a", 4090),
			printName:      `\` + strings.Repeat("a", 4090),
		},
		{
			name:           "drive",
			target:         `C:\` + strings.Repeat("d", 4086),
			flags:          0,
			substituteName: `\??\C:\` + strings.Repeat("d", 4086),
			printName:      `C:\` + strings.Repeat("d", 4086),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			tc := &treeConn{session: s, treeId: 1}
			fs := &Share{treeConn: tc, ctx: context.Background()}

			var input []byte
			var ctlCode uint32
			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt transport) bool {
				req := smb2.IoctlRequestDecoder(reqBuf[64:])
				ctlCode = req.CtlCode()
				inputOffset := int(req.InputOffset()) - 64
				inputCount := int(req.InputCount())
				input = append([]byte(nil), reqBuf[64+inputOffset:64+inputOffset+inputCount]...)

				res := &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_SET_REPARSE_POINT,
					FileId:  &smb2.FileId{},
				}
				sendTestResponse(dt, reqBuf, res, 0)
				return true
			}, nil)

			require.NoError(t, fs.Symlink(tt.target, "link"))
			require.Equal(t, uint32(smb2.FSCTL_SET_REPARSE_POINT), ctlCode)
			require.Len(t, input, 16384)

			rdbuf := smb2.SymbolicLinkReparseDataBufferDecoder(input)
			require.False(t, rdbuf.IsInvalid())
			require.Equal(t, uint16(16376), rdbuf.ReparseDataLength())
			require.Equal(t, tt.flags, rdbuf.Flags())
			require.Equal(t, uint16(0), rdbuf.SubstituteNameOffset())
			require.Equal(t, uint16(utf16le.EncodedStringLen(tt.substituteName)), rdbuf.SubstituteNameLength())
			require.Equal(t, rdbuf.SubstituteNameLength(), rdbuf.PrintNameOffset())
			require.Equal(t, uint16(utf16le.EncodedStringLen(tt.printName)), rdbuf.PrintNameLength())

			pathBuffer := rdbuf.PathBuffer()
			substituteEnd := int(rdbuf.SubstituteNameOffset()) + int(rdbuf.SubstituteNameLength())
			printStart := int(rdbuf.PrintNameOffset())
			printEnd := printStart + int(rdbuf.PrintNameLength())
			require.Equal(t, utf16le.EncodeStringToBytes(tt.substituteName), pathBuffer[:substituteEnd])
			require.Equal(t, utf16le.EncodeStringToBytes(tt.printName), pathBuffer[printStart:printEnd])
		})
	}
}

func TestSymlinkRejectsOversizedReparseDataBuffer(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "relative", target: strings.Repeat("r", 4092)},
		{name: "leading backslash", target: `\` + strings.Repeat("a", 4091)},
		{name: "drive", target: `C:\` + strings.Repeat("d", 4087)},
		{name: "large target", target: strings.Repeat("x", 32767)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			tc := &treeConn{session: s, treeId: 1}
			fs := &Share{treeConn: tc, ctx: context.Background()}

			errCh := make(chan error, 1)
			go func() { errCh <- fs.Symlink(tt.target, "link") }()

			var err error
			select {
			case err = <-errCh:
			case <-time.After(time.Second):
				t.Fatal("oversized symlink did not return before sending a request")
			}

			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "symlink", linkErr.Op)
			require.Equal(t, tt.target, linkErr.Old)
			require.Equal(t, "link", linkErr.New)
			require.ErrorIs(t, err, os.ErrInvalid)

			require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			_, readErr := readMsg(direct(serverConn))
			require.Error(t, readErr, "oversized symlink must not send CREATE, IOCTL, or CLOSE")
		})
	}
}

func TestFileCopyToSelf(t *testing.T) {
	f := &File{}

	if _, err := f.ReadFrom(f); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("ReadFrom self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
	if _, err := f.WriteTo(f); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("WriteTo self-copy error expected %v, got %v", os.ErrInvalid, err)
	}
}

func TestFileCopyAcrossSharesSharingTreeConn(t *testing.T) {
	tests := []struct {
		name string
		op   func(src, dst *File)
	}{
		{"ReadFrom", func(src, dst *File) { _, _ = dst.ReadFrom(src) }},
		{"WriteTo", func(src, dst *File) { _, _ = src.WriteTo(dst) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()

			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()
			tcConn := &treeConn{session: c.session, treeId: 0x200}
			fs1 := &Share{treeConn: tcConn, ctx: context.Background()}
			fs2 := fs1.WithContext(context.Background())

			var resumeKeyRequests atomic.Int32
			go func() {
				dt := direct(serverConn)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}

					switch smb2.PacketCodec(req).Command() {
					case smb2.SMB2_IOCTL:
						reqData := req[64:]
						if smb2.IoctlRequestDecoder(reqData).CtlCode() == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
							resumeKeyRequests.Add(1)
						}
						sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, 0xC0000001)
					case smb2.SMB2_READ:
						readReq := smb2.ReadRequestDecoder(req[64:])
						sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
					case smb2.SMB2_WRITE:
						sendTestResponse(dt, req, &smb2.WriteResponse{}, 0)
					}
				}
			}()

			srcFile := fs1.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "src.txt")
			dstFile := fs2.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

			tc.op(srcFile, dstFile)

			require.Equal(t, int32(1), resumeKeyRequests.Load(),
				"copyFile (FSCTL_SRV_REQUEST_RESUME_KEY) must be attempted between files opened from different Share instances sharing the same treeConn")
		})
	}
}

func TestResponseErrorIs(t *testing.T) {
	tests := []struct {
		code     uint32
		target   error
		expected bool
	}{
		{0xC0000034, os.ErrNotExist, true},   // STATUS_OBJECT_NAME_NOT_FOUND
		{0xC000003A, os.ErrNotExist, true},   // STATUS_OBJECT_PATH_NOT_FOUND
		{0xC0000035, os.ErrExist, true},      // STATUS_OBJECT_NAME_COLLISION
		{0xC0000022, os.ErrPermission, true}, // STATUS_ACCESS_DENIED
		{0xC0000121, os.ErrPermission, true}, // STATUS_CANNOT_DELETE
		{0xC0000128, os.ErrClosed, true},     // STATUS_FILE_CLOSED
		{0xC0000034, os.ErrPermission, false},
		{0xC0000034, os.ErrExist, false},
		{uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND), erref.STATUS_OBJECT_NAME_NOT_FOUND, true},
		{uint32(erref.STATUS_ACCESS_DENIED), erref.STATUS_ACCESS_DENIED, true},
		{uint32(erref.STATUS_ACCESS_DENIED), erref.STATUS_BUFFER_OVERFLOW, false},
	}

	for _, tc := range tests {
		err := &ResponseError{Code: tc.code}
		pathErr := &os.PathError{Op: "open", Path: "test", Err: err}

		if errors.Is(err, tc.target) != tc.expected {
			t.Errorf("ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
		if errors.Is(pathErr, tc.target) != tc.expected {
			t.Errorf("PathError wrapping ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
	}
}

func TestResponseErrorAsNtStatus(t *testing.T) {
	err := &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}
	pathErr := &os.PathError{Op: "open", Path: "test", Err: err}

	var status erref.NtStatus
	require.True(t, errors.As(err, &status))
	require.Equal(t, erref.STATUS_ACCESS_DENIED, status)

	var statusFromPathErr erref.NtStatus
	require.True(t, errors.As(pathErr, &statusFromPathErr))
	require.Equal(t, erref.STATUS_ACCESS_DENIED, statusFromPathErr)

	// Verify coexistence of NtStatus and standard errors
	require.True(t, errors.Is(err, erref.STATUS_ACCESS_DENIED))
	require.True(t, errors.Is(err, os.ErrPermission))
	require.True(t, errors.Is(pathErr, erref.STATUS_ACCESS_DENIED))
	require.True(t, errors.Is(pathErr, os.ErrPermission))
}

func TestCompoundResponseError(t *testing.T) {
	err0 := &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_COLLISION)}
	err1 := &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}
	cerr := &CompoundResponseError{Errors: []error{err0, nil, err1}}

	firstIdx, firstErr := cerr.FirstError()
	require.Equal(t, 0, firstIdx)
	require.Equal(t, err0, firstErr)
	require.Equal(t, err0, cerr.OpError(0))
	require.Nil(t, cerr.OpError(1))
	require.Equal(t, err1, cerr.OpError(2))
	require.Nil(t, cerr.OpError(3))
	require.Nil(t, cerr.OpError(-1))

	// Unwrap only non-nil
	unwrapped := cerr.Unwrap()
	require.Equal(t, []error{err0, err1}, unwrapped)

	// errors.Is
	require.True(t, errors.Is(cerr, os.ErrExist))
	require.True(t, errors.Is(cerr, os.ErrPermission))
	require.True(t, errors.Is(cerr, erref.STATUS_OBJECT_NAME_COLLISION))
	require.True(t, errors.Is(cerr, erref.STATUS_ACCESS_DENIED))
	require.False(t, errors.Is(cerr, os.ErrNotExist))

	// errors.As
	var rerr *ResponseError
	require.True(t, errors.As(cerr, &rerr))
	require.Equal(t, err0, rerr)

	var status erref.NtStatus
	require.True(t, errors.As(cerr, &status))
	require.Equal(t, erref.STATUS_OBJECT_NAME_COLLISION, status)
}

func TestSymlinkCreateCollisionDoesNotRemove(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	var receivedCommands []smb2.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		resp0 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp0[64:66], 9) // ErrorResponse StructureSize
		rp0 := smb2.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetStructureSize()
		rp0.SetCommand(smb2.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_OBJECT_NAME_COLLISION))
		rp0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(uint32(len(resp0)))

		resp1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp1[64:66], 9)
		rp1 := smb2.PacketCodec(resp1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_IOCTL)
		rp1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := smb2.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, append(resp1, resp2...)...)
		_, _ = st.Writev(allResp)

		for {
			reqBuf2, err := readMsg(st)
			if err != nil {
				return
			}
			p2 := smb2.PacketCodec(reqBuf2)
			mu.Lock()
			receivedCommands = append(receivedCommands, p2.Command())
			mu.Unlock()
		}
	}()

	err := fs.Symlink("target", "existing_file")
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrExist))

	_ = clientConn.Close()
	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	// Should only have received the initial CREATE (compound start) and NOT a second CREATE (for Remove)
	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE}, receivedCommands)
}

func TestSymlinkIoctlFailureDoesRemove(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	var receivedCommands []smb2.Command
	var mu sync.Mutex

	done := make(chan struct{})
	go func() {
		defer close(done)
		st := direct(serverConn)
		// 1. Read initial Symlink compound request
		reqBuf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, p.Command())
		mu.Unlock()

		// Server responds: op 0 (Create) SUCCESS, op 1 (Ioctl) NOT_SUPPORTED, op 2 (Close) NOT_SUPPORTED
		createRes := &smb2.CreateResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			FileId: &smb2.FileId{
				Persistent: [8]byte{1, 2, 3, 4},
				Volatile:   [8]byte{5, 6, 7, 8},
			},
		}
		resp0 := make([]byte, smb2.Roundup(createRes.Size(), 8))
		createRes.Encode(resp0)
		rp0 := smb2.PacketCodec(resp0)
		rp0.SetProtocolId()
		rp0.SetCommand(smb2.SMB2_CREATE)
		rp0.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp0.SetMessageId(p.MessageId())
		rp0.SetCreditResponse(1)
		rp0.SetSessionId(0x1234)
		rp0.SetTreeId(p.TreeId())
		rp0.SetNextCommand(uint32(len(resp0)))

		resp1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp1[64:66], 9)
		rp1 := smb2.PacketCodec(resp1)
		rp1.SetProtocolId()
		rp1.SetStructureSize()
		rp1.SetCommand(smb2.SMB2_IOCTL)
		rp1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp1.SetMessageId(p.MessageId() + 1)
		rp1.SetSessionId(0x1234)
		rp1.SetTreeId(p.TreeId())
		rp1.SetNextCommand(uint32(len(resp1)))

		resp2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(resp2[64:66], 9)
		rp2 := smb2.PacketCodec(resp2)
		rp2.SetProtocolId()
		rp2.SetStructureSize()
		rp2.SetCommand(smb2.SMB2_CLOSE)
		rp2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rp2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rp2.SetMessageId(p.MessageId() + 2)
		rp2.SetSessionId(0x1234)
		rp2.SetTreeId(p.TreeId())
		rp2.SetNextCommand(0)

		allResp := append(resp0, append(resp1, resp2...)...)
		_, _ = st.Writev(allResp)

		// 2. Since op 0 succeeded but op 2 failed, treeConn.sendRecv will auto-close the opened file.
		// Read closeFile request
		closeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pClose := smb2.PacketCodec(closeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pClose.Command())
		mu.Unlock()

		// Respond to closeFile
		closeResp := make([]byte, 64+60)
		binary.LittleEndian.PutUint16(closeResp[64:66], 60)
		rpClose := smb2.PacketCodec(closeResp)
		rpClose.SetProtocolId()
		rpClose.SetStructureSize()
		rpClose.SetCommand(smb2.SMB2_CLOSE)
		rpClose.SetStatus(uint32(erref.STATUS_SUCCESS))
		rpClose.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rpClose.SetMessageId(pClose.MessageId())
		rpClose.SetCreditResponse(1)
		rpClose.SetSessionId(0x1234)
		rpClose.SetTreeId(pClose.TreeId())
		_, _ = st.Writev(closeResp)

		// 3. Now Symlink should call fs.Remove!
		// Read Remove compound request (starts with CREATE)
		removeBuf, err := readMsg(st)
		if err != nil {
			return
		}
		pRemove := smb2.PacketCodec(removeBuf)
		mu.Lock()
		receivedCommands = append(receivedCommands, pRemove.Command())
		mu.Unlock()

		// Respond to Remove compound chain (Create, SetInfo, Close)
		rem0 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem0[64:66], 9)
		rpRem0 := smb2.PacketCodec(rem0)
		rpRem0.SetProtocolId()
		rpRem0.SetStructureSize()
		rpRem0.SetCommand(smb2.SMB2_CREATE)
		rpRem0.SetStatus(uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		rpRem0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem0.SetMessageId(pRemove.MessageId())
		rpRem0.SetCreditResponse(1)
		rpRem0.SetSessionId(0x1234)
		rpRem0.SetTreeId(pRemove.TreeId())
		rpRem0.SetNextCommand(uint32(len(rem0)))

		rem1 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem1[64:66], 9)
		rpRem1 := smb2.PacketCodec(rem1)
		rpRem1.SetProtocolId()
		rpRem1.SetStructureSize()
		rpRem1.SetCommand(smb2.SMB2_SET_INFO)
		rpRem1.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rpRem1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem1.SetMessageId(pRemove.MessageId() + 1)
		rpRem1.SetSessionId(0x1234)
		rpRem1.SetTreeId(pRemove.TreeId())
		rpRem1.SetNextCommand(uint32(len(rem1)))

		rem2 := make([]byte, 64+8)
		binary.LittleEndian.PutUint16(rem2[64:66], 9)
		rpRem2 := smb2.PacketCodec(rem2)
		rpRem2.SetProtocolId()
		rpRem2.SetStructureSize()
		rpRem2.SetCommand(smb2.SMB2_CLOSE)
		rpRem2.SetStatus(uint32(erref.STATUS_NOT_SUPPORTED))
		rpRem2.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		rpRem2.SetMessageId(pRemove.MessageId() + 2)
		rpRem2.SetSessionId(0x1234)
		rpRem2.SetTreeId(pRemove.TreeId())
		rpRem2.SetNextCommand(0)

		allRemResp := append(rem0, append(rem1, rem2...)...)
		_, _ = st.Writev(allRemResp)
	}()

	err := fs.Symlink("target", "new_link")
	require.Error(t, err)

	<-done

	mu.Lock()
	defer mu.Unlock()
	// Received: initial CREATE (symlink), CLOSE (auto-cleanup fileId), CREATE (fs.Remove)
	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CLOSE, smb2.SMB2_CREATE}, receivedCommands)
}

func TestParallelChunkedReadWrite(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	const fileSize = 512 * 1024
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case smb2.SMB2_WRITE:
				wreq := smb2.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &smb2.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Writev(resBuf)

			case smb2.SMB2_READ:
				rreq := smb2.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				var chunkData []byte
				if int(off) < len(mockStorage) {
					end := min(int(off)+int(length), len(mockStorage))
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &smb2.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Writev(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	_, err := rand.Read(testPayload)
	req.NoError(err)

	dummyFd := &smb2.FileId{}
	wn, err := fs.writeAt(dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestLargeMockFileCopy(t *testing.T) {
	req := require.New(t)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{
		session: c.session,
		treeId:  0x200,
	}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	const fileSize = 10 * 1024 * 1024 // 10MB
	mockStorage := make([]byte, fileSize)
	var storageMu sync.Mutex

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(reqBuf)
			msgId := p.MessageId()
			cmd := p.Command()

			switch cmd {
			case smb2.SMB2_WRITE:
				wreq := smb2.WriteRequestDecoder(reqBuf[64:])
				off := wreq.Offset()
				dataOff := wreq.DataOffset()
				length := wreq.Length()
				data := reqBuf[dataOff : int(dataOff)+int(length)]

				storageMu.Lock()
				if int(off)+len(data) <= len(mockStorage) {
					copy(mockStorage[off:], data)
				}
				storageMu.Unlock()

				wres := &smb2.WriteResponse{Count: uint32(len(data))}
				resBuf := make([]byte, wres.Size())
				wres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Writev(resBuf)

			case smb2.SMB2_READ:
				rreq := smb2.ReadRequestDecoder(reqBuf[64:])
				off := rreq.Offset()
				length := rreq.Length()

				storageMu.Lock()
				end := min(int(off)+int(length), len(mockStorage))
				var chunkData []byte
				if int(off) < len(mockStorage) {
					chunkData = append([]byte(nil), mockStorage[off:end]...)
				}
				storageMu.Unlock()

				rres := &smb2.ReadResponse{Data: chunkData}
				resBuf := make([]byte, rres.Size())
				rres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				dt.Writev(resBuf)
			}
		}
	}()

	testPayload := make([]byte, fileSize)
	for i := range testPayload {
		testPayload[i] = byte((i*17 + 13) % 251)
	}

	dummyFd := &smb2.FileId{}
	wn, err := fs.writeAt(dummyFd, testPayload, 0)
	req.NoError(err)
	req.Equal(fileSize, wn)

	readBuf := make([]byte, fileSize)
	rn, err := fs.readAt(dummyFd, readBuf, 0)
	req.NoError(err)
	req.Equal(fileSize, rn)

	req.Equal(testPayload, readBuf)
}

func TestEvalSymlinkErrorRelativePath(t *testing.T) {
	unparsed := func(s string) uint16 { return uint16(utf16le.EncodedStringLen(s)) }

	tests := []struct {
		name               string
		path               string
		substituteName     string
		unparsedPathLength uint16
		want               string
	}{
		{
			name:           "replace link name",
			path:           `sub1\sub2\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\sub2\target.txt`,
		},
		{
			name:           "parent reference in substitute name",
			path:           `sub1\sub2\symlink`,
			substituteName: `..\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "current directory reference in substitute name",
			path:           `sub1\symlink`,
			substituteName: `.\target.txt`,
			want:           `sub1\target.txt`,
		},
		{
			name:           "multiple parent references",
			path:           `a\link`,
			substituteName: `..\..\x`,
			want:           `x`,
		},
		{
			name:           "root level symlink",
			path:           `symlink`,
			substituteName: `target.txt`,
			want:           `target.txt`,
		},
		{
			name:           "parent beyond root stays at root",
			path:           `symlink`,
			substituteName: `..\target.txt`,
			want:           `target.txt`,
		},
		{
			name:           "result is share root",
			path:           `a\link`,
			substituteName: `..`,
			want:           ``,
		},
		{
			name:           "leading backslash is removed",
			path:           `symlink`,
			substituteName: `\target.txt`,
			want:           `target.txt`,
		},
		{
			name:               "unparsed suffix is preserved",
			path:               `sub1\symlink\dir2\file.txt`,
			substituteName:     `..\target.txt`,
			unparsedPathLength: unparsed(`\dir2\file.txt`),
			want:               `target.txt\dir2\file.txt`,
		},
		{
			name:               "unparsed suffix with dot components is normalized",
			path:               `sub1\symlink\dir2\..\file.txt`,
			substituteName:     `target.txt`,
			unparsedPathLength: unparsed(`\dir2\..\file.txt`),
			want:               `sub1\target.txt\file.txt`,
		},
		{
			name:           "non-ASCII components are preserved",
			path:           `sub1\リンク\symlink`,
			substituteName: `..\ターゲット.txt`,
			want:           `sub1\ターゲット.txt`,
		},
		{
			name:           "names containing dots are preserved",
			path:           `sub1\file..txt\symlink`,
			substituteName: `target.txt`,
			want:           `sub1\file..txt\target.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symErr := &smb2.SymbolicLinkErrorResponse{
				UnparsedPathLength: tt.unparsedPathLength,
				Flags:              smb2.SYMLINK_FLAG_RELATIVE,
				SubstituteName:     tt.substituteName,
				PrintName:          tt.substituteName,
			}
			buf := make([]byte, symErr.Size())
			symErr.Encode(buf)

			resolved, err := evalSymlinkError(tt.path, buf)
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
		})
	}
}

func TestCreateFileCleansRelativeSymlinkTarget(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	defer cleanup()

	s := &session{conn: c, sessionId: 0x1234}
	c.session = s
	c.enableSession()
	tc := &treeConn{session: s, treeId: 1}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	createNames := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(serverConn)

		// The first CREATE resolves a relative symlink whose substitute name
		// still contains a ".." component.
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}
		req := smb2.CreateRequestDecoder(reqBuf[64:])
		off, size := int(req.NameOffset()), int(req.NameLength())
		createNames <- utf16le.DecodeToString(reqBuf[off : off+size])

		sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_CREATE,
			ErrorData: &smb2.SymbolicLinkErrorResponse{
				Flags:          smb2.SYMLINK_FLAG_RELATIVE,
				SubstituteName: `..\target.txt`,
				PrintName:      `..\target.txt`,
			},
		}, uint32(erref.STATUS_STOPPED_ON_SYMLINK))

		// The retried CREATE must carry the cleaned path.
		reqBuf, err = readMsg(dt)
		if err != nil {
			return
		}
		req = smb2.CreateRequestDecoder(reqBuf[64:])
		off, size = int(req.NameOffset()), int(req.NameLength())
		createNames <- utf16le.DecodeToString(reqBuf[off : off+size])

		sendTestResponse(dt, reqBuf, &smb2.CreateResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			FileId:         &smb2.FileId{},
			FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL,
		}, 0)

		// Service the CLOSE issued by f.Close().
		for {
			reqBuf, err = readMsg(dt)
			if err != nil {
				return
			}
			if smb2.PacketCodec(reqBuf).Command() == smb2.SMB2_CLOSE {
				sendTestResponse(dt, reqBuf, &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}, 0)
				return
			}
		}
	}()

	f, err := fs.OpenFile(`sub1\sub2\symlink`, os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	<-done

	require.Equal(t, `sub1\sub2\symlink`, <-createNames)
	require.Equal(t, `sub1\target.txt`, <-createNames)
}

func encodeSymlinkErrorResponse(unparsedPathLength uint16, relative bool, substituteName, printName string) []byte {
	flags := uint32(0)
	if relative {
		flags = smb2.SYMLINK_FLAG_RELATIVE
	}
	symErr := &smb2.SymbolicLinkErrorResponse{
		UnparsedPathLength: unparsedPathLength,
		Flags:              flags,
		SubstituteName:     substituteName,
		PrintName:          printName,
	}
	buf := make([]byte, symErr.Size())
	symErr.Encode(buf)
	return buf
}

func TestEvalSymlinkErrorResolvedNameLength(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		unparsed    uint16
		substitute  string
		relative    bool
		want        string
		wantNameLen int
		wantErr     bool
	}{
		{
			name:        "relative resolved name at limit",
			path:        "d" + strings.Repeat("a", 32766),
			unparsed:    65532,
			substitute:  "t",
			relative:    true,
			want:        "t" + strings.Repeat("a", 32766),
			wantNameLen: 65534,
		},
		{
			name:       "relative resolved name over limit",
			path:       "d" + strings.Repeat("a", 32766),
			unparsed:   65532,
			substitute: strings.Repeat("t", 100),
			relative:   true,
			wantErr:    true,
		},
		{
			name:        "absolute resolved name at limit",
			path:        "d" + strings.Repeat("a", 32760),
			unparsed:    65520,
			substitute:  `\\?\C:\`,
			want:        `\\?\C:\` + strings.Repeat("a", 32760),
			wantNameLen: 65534,
		},
		{
			name:       "absolute resolved name over limit",
			path:       "d" + strings.Repeat("a", 32761),
			unparsed:   65522,
			substitute: `\\?\C:\`,
			wantErr:    true,
		},
		{
			name:        "supplementary plane resolved name at limit",
			path:        "d" + strings.Repeat("\U0001F600", 16383),
			unparsed:    65532,
			substitute:  "t",
			relative:    true,
			want:        "t" + strings.Repeat("\U0001F600", 16383),
			wantNameLen: 65534,
		},
		{
			name:       "supplementary plane resolved name over limit",
			path:       "d" + strings.Repeat("\U0001F600", 16383) + "a",
			unparsed:   65534,
			substitute: "t",
			relative:   true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeSymlinkErrorResponse(tt.unparsed, tt.relative, tt.substitute, tt.substitute)
			resolved, err := evalSymlinkError(tt.path, buf)
			if tt.wantErr {
				var ierr *InternalError
				require.ErrorAs(t, err, &ierr)
				require.Contains(t, ierr.Message, "exceeds uint16")
				require.Equal(t, "", resolved)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, resolved)
			require.Equal(t, tt.wantNameLen, utf16le.EncodedStringLen(resolved))
		})
	}
}

func TestEvalSymlinkErrorResolvedNameNormalizedWithinLimit(t *testing.T) {
	// The raw substitution overflows the uint16 name bound, but eliminating the
	// "." and ".." components brings it back within the limit. [MS-SMB2]
	// 2.2.2.2.1.1 requires those components to be removed during symlink
	// processing, so the retry must succeed.
	target := strings.Repeat("t", 32761) // 65522 bytes
	suffix := strings.Repeat(`\..`, 40)
	path := "d" + suffix
	unparsed := uint16(utf16le.EncodedStringLen(suffix))

	buf := encodeSymlinkErrorResponse(unparsed, true, target, "")
	resolved, err := evalSymlinkError(path, buf)
	require.NoError(t, err)
	require.Equal(t, "", resolved)
}

func TestRejectsOverlongResolvedSymlinkPath(t *testing.T) {
	for _, useBuilder := range []bool{false, true} {
		name := "OpenFile"
		if useBuilder {
			name = "requestBuilder"
		}
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))

			c, cleanup := newBenchConn(clientConn)
			defer cleanup()
			c.account.charge(8) // Leave credits available for CREATE retries.
			s := &session{conn: c, sessionId: 0x1234}
			c.session = s
			c.enableSession()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fs := &Share{treeConn: &treeConn{session: s, treeId: 1}, ctx: ctx}

			overlongName := "d" + strings.Repeat("a", 32766)
			creates := make(chan string, 3)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer close(creates)
				defer serverConn.Close()
				dt := direct(serverConn)
				for count := 0; ; count++ {
					reqBuf, err := readMsg(dt)
					if err != nil || len(reqBuf) < 64 {
						return
					}
					if smb2.PacketCodec(reqBuf).Command() == smb2.SMB2_CLOSE {
						if smb2.CloseRequestDecoder(reqBuf[64:]).IsInvalid() {
							return
						}
						sendTestResponse(dt, reqBuf, &smb2.CloseResponse{
							CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
							LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
						}, 0)
						return
					}
					if smb2.PacketCodec(reqBuf).Command() != smb2.SMB2_CREATE || count >= 3 {
						return
					}
					req := smb2.CreateRequestDecoder(reqBuf[64:])
					if req.IsInvalid() {
						return
					}
					off, size := int(req.NameOffset()), int(req.NameLength())
					if off > len(reqBuf) || size > len(reqBuf)-off {
						return
					}
					creates <- utf16le.DecodeToString(reqBuf[off : off+size])
					var closeReq []byte
					if useBuilder {
						next := uint64(smb2.PacketCodec(reqBuf).NextCommand())
						if next < 64 || next > uint64(len(reqBuf)) || uint64(len(reqBuf))-next < 64 {
							return
						}
						closeReq = reqBuf[next:]
						if smb2.PacketCodec(closeReq).Command() != smb2.SMB2_CLOSE ||
							smb2.CloseRequestDecoder(closeReq[64:]).IsInvalid() {
							return
						}
					}
					sendCreate := func(res smb2.Packet, status uint32) {
						sendTestResponse(dt, reqBuf, res, status)
						if closeReq == nil {
							return
						}
						if status != 0 {
							sendTestResponse(dt, closeReq, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CLOSE}, status)
						} else {
							sendTestResponse(dt, closeReq, &smb2.CloseResponse{
								CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
								LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
							}, 0)
						}
					}
					if count == 0 {
						sendCreate(&smb2.ErrorResponse{
							CommandCode: smb2.SMB2_CREATE,
							ErrorData: &smb2.SymbolicLinkErrorResponse{
								UnparsedPathLength: 65532, Flags: smb2.SYMLINK_FLAG_RELATIVE,
								SubstituteName: strings.Repeat("t", 100), PrintName: strings.Repeat("t", 100),
							},
						}, uint32(erref.STATUS_STOPPED_ON_SYMLINK))
						continue
					}
					// Only the short follow-up CREATE may follow the rejected link.
					sendCreate(&smb2.CreateResponse{
						CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
						LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
						FileId: &smb2.FileId{}, FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL,
					}, 0)
				}
			}()

			open := func(path string) error {
				if useBuilder {
					res, err := fs.request().create(path, smb2.GENERIC_READ, smb2.FILE_OPEN, 0, 0).close().sendRecv(ctx)
					if res != nil {
						res.close()
					}
					return err
				}
				f, err := fs.OpenFile(path, os.O_RDONLY, 0)
				if err == nil {
					return f.Close()
				}
				return err
			}
			var ierr *InternalError
			require.ErrorAs(t, open(overlongName), &ierr)
			require.Equal(t, "resolved symbolic link path exceeds uint16", ierr.Message)
			require.NoError(t, open("plain.txt"))
			clientConn.Close()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("symlink test server did not finish")
			}
			var names []string
			for name := range creates {
				names = append(names, name)
			}
			require.Equal(t, []string{overlongName, "plain.txt"}, names)
		})
	}
}

func TestNormalizeSymlinkTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expected string
	}{
		{
			name:     "UNC prefix",
			target:   `\??\UNC\server\share`,
			expected: `\\server\share`,
		},
		{
			name:     "drive prefix",
			target:   `\??\C:\path`,
			expected: `C:\path`,
		},
		{
			name:     "plain path",
			target:   `dir\target.txt`,
			expected: `dir\target.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSymlinkTarget(tt.target)
			if got != tt.expected {
				t.Errorf("normalizeSymlinkTarget(%q) = %q, want %q", tt.target, got, tt.expected)
			}
		})
	}
}

type rawEncoder []byte

func (r rawEncoder) Size() int       { return len(r) }
func (r rawEncoder) Encode(b []byte) { copy(b, r) }

func startFullFakeServer(serverConn net.Conn, onQueryDir func(msgId uint64, reqBuf []byte, dt transport) bool, onIoctl func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool, onQueryInfo func(msgId uint64, reqBuf []byte) []byte, onCreate ...func(req smb2.CreateRequestDecoder, cres *smb2.CreateResponse)) {
	go func() {
		dt := direct(serverConn)
		var callId uint32
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_DISK,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					attrs := uint32(0)
					if onQueryDir != nil {
						attrs = smb2.FILE_ATTRIBUTE_DIRECTORY
					}
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileAttributes: attrs,
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					if len(onCreate) > 0 && onCreate[0] != nil {
						onCreate[0](smb2.CreateRequestDecoder(currBuf[64:]), cres)
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_QUERY_INFO:
					if onQueryInfo != nil {
						resBuf = onQueryInfo(msgId, currBuf)
					}

				case smb2.SMB2_READ:
					reqData := currBuf[64:]
					readLen := int(le.Uint32(reqData[4:8]))
					rres := &smb2.ReadResponse{Data: make([]byte, readLen)}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					if onIoctl != nil && onIoctl(&callId, msgId, currBuf, dt) {
						resBuf = nil
					}

				case smb2.SMB2_QUERY_DIRECTORY:
					if onQueryDir != nil && onQueryDir(msgId, currBuf, dt) {
						resBuf = nil
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()
}

func encodeFileIdBothDirectoryInformation(name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
	b := make([]byte, 104+len(nameBytes))
	le.PutUint32(b[0:4], 0)
	le.PutUint32(b[4:8], 1)
	le.PutUint64(b[40:48], 100)
	le.PutUint64(b[48:56], 4096)
	le.PutUint32(b[56:60], 0x20)
	le.PutUint32(b[60:64], uint32(len(nameBytes)))
	le.PutUint64(b[96:104], 1001)
	copy(b[104:], nameBytes)
	return b
}

func encodeFileIdBothDirectoryInformations(names []string) []byte {
	var buf []byte
	for i, name := range names {
		e := encodeFileIdBothDirectoryInformation(name)
		if i < len(names)-1 {
			next := smb2.Roundup(len(e), 8)
			le.PutUint32(e[0:4], uint32(next))
			e = append(e, make([]byte, next-len(e))...)
		}
		buf = append(buf, e...)
	}
	return buf
}

func encodeFileIdBothDirectoryInformationAtOffset(firstName string, next uint32, secondName string) []byte {
	first := encodeFileIdBothDirectoryInformation(firstName)
	second := encodeFileIdBothDirectoryInformation(secondName)
	buf := make([]byte, int(next)+len(second))
	copy(buf, first)
	le.PutUint32(buf[0:4], next)
	copy(buf[int(next):], second)
	return buf
}

func TestParseReaddir_MultipleEntries(t *testing.T) {
	names := []string{".", "..", "alpha", "beta.txt"}
	buf := encodeFileIdBothDirectoryInformations(names)

	fis, err := parseReaddir(buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != 2 {
		t.Fatalf("expected 2 entries after excluding dot entries, got %d", len(fis))
	}
	for i, name := range names[2:] {
		if fis[i].Name() != name {
			t.Errorf("entry %d: expected name %q, got %q", i, name, fis[i].Name())
		}
		if got := fis[i].(*FileStat).FileAttributes; got != 0x20 {
			t.Errorf("entry %d: expected attributes %#x, got %#x", i, uint32(0x20), got)
		}
	}
}

func TestParseReaddir_UnpaddedFinalEntry(t *testing.T) {
	buf := encodeFileIdBothDirectoryInformations([]string{"final"})

	fis, err := parseReaddir(buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != 1 || fis[0].Name() != "final" {
		t.Fatalf("expected unpadded final entry, got %#v", fis)
	}
}

func TestParseReaddir_Filetimes(t *testing.T) {
	const futureFiletime = uint64(283696992000000000)
	buf := encodeFileIdBothDirectoryInformation("timestamps.txt")
	for _, offset := range []int{8, 16} {
		le.PutUint64(buf[offset:offset+8], 0)
	}
	for _, offset := range []int{24, 32} {
		le.PutUint64(buf[offset:offset+8], futureFiletime)
	}

	fis, err := parseReaddir(buf)
	require.NoError(t, err)
	require.Len(t, fis, 1)

	fst := fis[0].(*FileStat)
	zero := time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC)
	require.True(t, fst.CreationTime.Equal(zero))
	require.True(t, fst.LastAccessTime.Equal(zero))
	require.True(t, fst.LastWriteTime.Equal(future))
	require.True(t, fst.ChangeTime.Equal(future))
}

func TestParseReaddir_NextEntryOffsetEqualsBufferLength(t *testing.T) {
	names := []string{"file1.txt", "file2.txt"}
	buf := encodeFileIdBothDirectoryInformations(names)

	// Some servers terminate the entry list with
	// NextEntryOffset == len(output) instead of 0 on the last entry.
	lastEntrySize := 104 + len(utf16le.EncodeStringToBytes(names[len(names)-1]))
	lastEntryOffset := len(buf) - lastEntrySize
	le.PutUint32(buf[lastEntryOffset:lastEntryOffset+4], uint32(lastEntrySize))

	fis, err := parseReaddir(buf)
	if err != nil {
		t.Fatalf("parseReaddir failed: %v", err)
	}
	if len(fis) != len(names) {
		t.Fatalf("expected %d entries, got %d", len(names), len(fis))
	}
	for i, fi := range fis {
		if fi.Name() != names[i] {
			t.Errorf("entry %d: expected name %q, got %q", i, names[i], fi.Name())
		}
	}
}

func TestParseReaddir_InvalidSmallNextEntryOffset(t *testing.T) {
	for _, next := range []uint32{8, 50} {
		buf := encodeFileIdBothDirectoryInformation("file1.txt")
		// A non-zero NextEntryOffset smaller than the fixed part of
		// FILE_ID_BOTH_DIRECTORY_INFORMATION (104 bytes) is malformed.
		le.PutUint32(buf[0:4], next)

		_, err := parseReaddir(buf)
		if err == nil {
			t.Fatalf("parseReaddir(next=%d): expected error, got nil", next)
		}
		if _, ok := err.(*InvalidResponseError); !ok {
			t.Fatalf("parseReaddir(next=%d): expected *InvalidResponseError, got %T", next, err)
		}
	}
}

func TestParseReaddir_InvalidNextEntryOffset(t *testing.T) {
	tests := []struct {
		name      string
		buf       []byte
		wantError string
	}{
		{
			name:      "not eight byte aligned",
			buf:       encodeFileIdBothDirectoryInformationAtOffset("", 105, "next"),
			wantError: "non-aligned continuation",
		},
		{
			name:      "overlaps file name",
			buf:       encodeFileIdBothDirectoryInformationAtOffset("a", 104, "next"),
			wantError: "continuation overlaps current entry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseReaddir(tc.buf)
			if err == nil {
				t.Fatalf("parseReaddir: expected %s error, got nil", tc.wantError)
			}
			if _, ok := err.(*InvalidResponseError); !ok {
				t.Fatalf("parseReaddir: expected *InvalidResponseError, got %T", err)
			}
		})
	}

	t.Run("outside buffer", func(t *testing.T) {
		buf := encodeFileIdBothDirectoryInformation("")
		le.PutUint32(buf[0:4], uint32(len(buf)+1))

		_, err := parseReaddir(buf)
		if err == nil {
			t.Fatal("parseReaddir: expected out-of-range error, got nil")
		}
		if _, ok := err.(*InvalidResponseError); !ok {
			t.Fatalf("parseReaddir: expected *InvalidResponseError, got %T", err)
		}
	})
}

func TestParseReaddir_RejectsNegativeEndOfFile(t *testing.T) {
	for _, eof := range []int64{-1, -1 << 63, 0, 42, 1<<63 - 1} {
		buf := encodeFileIdBothDirectoryInformation("file1.txt")
		le.PutUint64(buf[40:48], uint64(eof))

		fis, err := parseReaddir(buf)
		if eof >= 0 {
			require.NoError(t, err)
			require.Len(t, fis, 1)
			require.Equal(t, eof, fis[0].Size())
			continue
		}
		if fis != nil {
			t.Fatalf("parseReaddir(EndOfFile=%d): expected no FileInfo, got %d entries", eof, len(fis))
		}
		if _, ok := err.(*InvalidResponseError); !ok {
			t.Fatalf("parseReaddir(EndOfFile=%d): expected *InvalidResponseError, got %T", eof, err)
		}
	}
}

func TestParseReaddir_RejectsNegativeDirectoryTimes(t *testing.T) {
	tests := []struct {
		name   string
		offset int
	}{
		{"CreationTime", 8},
		{"LastAccessTime", 16},
		{"LastWriteTime", 24},
		{"ChangeTime", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeFileIdBothDirectoryInformation("file1.txt")
			le.PutUint64(buf[tt.offset:tt.offset+8], 0x8000000000000000)

			fis, err := parseReaddir(buf)
			if fis != nil {
				t.Fatalf("parseReaddir(%s): expected no FileInfo, got %d entries", tt.name, len(fis))
			}
			if _, ok := err.(*InvalidResponseError); !ok {
				t.Fatalf("parseReaddir(%s): expected *InvalidResponseError, got %T", tt.name, err)
			}
		})
	}

	t.Run("later entry is invalid", func(t *testing.T) {
		buf := encodeFileIdBothDirectoryInformations([]string{"first", "second"})
		firstSize := smb2.Roundup(104+len(utf16le.EncodeStringToBytes("first")), 8)
		le.PutUint64(buf[firstSize+32:firstSize+40], 0xffffffffffffffff)

		fis, err := parseReaddir(buf)
		if fis != nil {
			t.Fatalf("parseReaddir: expected no FileInfo, got %d entries", len(fis))
		}
		if _, ok := err.(*InvalidResponseError); !ok {
			t.Fatalf("parseReaddir: expected *InvalidResponseError, got %T", err)
		}
	})
}

func TestReaddirAll_RequestedBufferSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     128 * 1024,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	const numFiles = 700
	names := make([]string, numFiles)
	for i := range names {
		names[i] = fmt.Sprintf("f%03d", i)
	}
	dirData := encodeFileIdBothDirectoryInformations(names)
	// 700 entries * 112 bytes = 78400 bytes: more than a single-credit payload
	// (64KB) but less than the negotiated max transact size (128KB).
	if len(dirData) <= 64*1024 || len(dirData) > 128*1024 {
		t.Fatalf("test setup: dirData size %d does not match scenario", len(dirData))
	}

	go func() {
		dt := direct(serverConn)
		off := 0
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(reqBuf)
			switch p.Command() {
			case smb2.SMB2_CREATE:
				// compound CREATE + QUERY_DIRECTORY: locate the query part
				qdir := reqBuf
				for {
					if smb2.PacketCodec(qdir).Command() == smb2.SMB2_QUERY_DIRECTORY {
						break
					}
					qdir = qdir[smb2.PacketCodec(qdir).NextCommand():]
				}
				requested := smb2.QueryDirectoryRequestDecoder(qdir[64:]).OutputBufferLength()
				require.EqualValues(t, maxSingleCreditPayloadSize, requested)

				// The server returns as many complete entries as fit in the
				// requested output buffer. The last returned entry terminates
				// the chain (NextEntryOffset = 0), like a real server.
				output := make([]byte, 0, min(int(requested), len(dirData)-off))
				lastEntryLen := 0
				for off < len(dirData) {
					entryLen := int(le.Uint32(dirData[off : off+4]))
					if entryLen == 0 {
						entryLen = len(dirData) - off
					}
					if len(output)+entryLen > int(requested) {
						break
					}
					output = append(output, dirData[off:off+entryLen]...)
					lastEntryLen = entryLen
					off += entryLen
				}
				if len(output) > 0 {
					le.PutUint32(output[len(output)-lastEntryLen:], 0)
				}

				cres := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				cresBuf := make([]byte, cres.Size())
				cres.Encode(cresBuf)

				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(output),
				}
				qresBuf := make([]byte, qres.Size())
				qres.Encode(qresBuf)

				pad := (8 - (len(cresBuf) % 8)) % 8
				nextCmd := uint32(len(cresBuf) + pad)
				padded := make([]byte, nextCmd)
				copy(padded, cresBuf)
				smb2.PacketCodec(padded).SetNextCommand(nextCmd)

				compound := append(append([]byte{}, padded...), qresBuf...)

				head0 := smb2.PacketCodec(compound[:len(padded)])
				head0.SetMessageId(p.MessageId())
				head0.SetSessionId(p.SessionId())
				head0.SetTreeId(p.TreeId())
				head0.SetCreditResponse(1)
				head0.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				head1 := smb2.PacketCodec(compound[len(padded):])
				head1.SetMessageId(p.MessageId() + 1)
				head1.SetSessionId(p.SessionId())
				head1.SetTreeId(p.TreeId())
				head1.SetCreditResponse(3)
				head1.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)

				dt.Writev(compound)

			case smb2.SMB2_QUERY_DIRECTORY:
				if off >= len(dirData) {
					eres := &smb2.ErrorResponse{
						CommandCode: smb2.SMB2_QUERY_DIRECTORY,
					}
					resBuf := make([]byte, eres.Size())
					eres.Encode(resBuf)

					erp := smb2.PacketCodec(resBuf)
					erp.SetMessageId(p.MessageId())
					erp.SetSessionId(p.SessionId())
					erp.SetTreeId(p.TreeId())
					erp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
					erp.SetCreditResponse(1)
					erp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					dt.Writev(resBuf)
					break
				}

				requested := smb2.QueryDirectoryRequestDecoder(p.Body()).OutputBufferLength()
				require.EqualValues(t, maxSingleCreditPayloadSize, requested)

				output := make([]byte, 0, min(int(requested), len(dirData)-off))
				lastEntryLen := 0
				for off < len(dirData) {
					entryLen := int(le.Uint32(dirData[off : off+4]))
					if entryLen == 0 {
						entryLen = len(dirData) - off
					}
					if len(output)+entryLen > int(requested) {
						break
					}
					output = append(output, dirData[off:off+entryLen]...)
					lastEntryLen = entryLen
					off += entryLen
				}
				if len(output) > 0 {
					le.PutUint32(output[len(output)-lastEntryLen:], 0)
				}

				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(output),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)

			case smb2.SMB2_CLOSE:
				clres := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf := make([]byte, clres.Size())
				clres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			}
		}
	}()

	fis, err := fs.ReadDir("testdir")
	require.NoError(t, err)
	require.Len(t, fis, numFiles)
	for i, fi := range fis {
		require.Equal(t, names[i], fi.Name())
	}
}

func TestReaddir_NormalVsBugBehavior(t *testing.T) {
	t.Run("NormalServer_ReturnsFilesThenNoMoreFiles", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()

		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}
		f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

		go c.runReceiver()

		var reqCount atomic.Int64

		// Normal fakeServer: 1st call returns "file1.txt", 2nd call returns STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
			count := reqCount.Add(1)
			p := smb2.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			} else {
				// 2nd call: STATUS_NO_MORE_FILES (0x80000606) using standard ErrorResponse
				eres := &smb2.ErrorResponse{
					CommandCode: smb2.SMB2_QUERY_DIRECTORY,
				}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Normal Readdir completed cleanly after %d requests, got %d files", reqCount.Load(), len(fis))
	})

	t.Run("BugBehavior_ServerReturnsEmptySuccessInsteadOfNoMoreFiles", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()

		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}
		f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

		go c.runReceiver()

		var reqCount atomic.Int64

		// Parameter change: 1st call returns "file1.txt", 2nd call returns STATUS_SUCCESS (0) with empty output instead of STATUS_NO_MORE_FILES
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
			count := reqCount.Add(1)
			p := smb2.PacketCodec(reqBuf)

			if count == 1 {
				dirData := encodeFileIdBothDirectoryInformation("file1.txt")
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder(dirData),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0)
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			} else {
				// 2nd call: PARAMETER CHANGED to STATUS_SUCCESS (0) with 0 bytes output
				qres := &smb2.QueryDirectoryResponse{
					Output: rawEncoder([]byte{}),
				}
				resBuf := make([]byte, qres.Size())
				qres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0) // STATUS_SUCCESS
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			}
			return true
		}, nil, nil)

		fis, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, fis, 1)
		require.Equal(t, "file1.txt", fis[0].Name())
		t.Logf("PASS: Readdir completed cleanly after fix even with empty STATUS_SUCCESS response (%d requests)", reqCount.Load())
	})

	t.Run("EmptyDir_ServerReturnsNoSuchFile", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()

		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}
		f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "emptydir")

		go c.runReceiver()

		var reqCount atomic.Int64

		// Some servers report STATUS_NO_SUCH_FILE on the first QUERY_DIRECTORY
		// of an empty directory instead of STATUS_NO_MORE_FILES. Readdir must
		// treat it as a normal end-of-directory, not an error.
		startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
			reqCount.Add(1)
			p := smb2.PacketCodec(reqBuf)

			eres := &smb2.ErrorResponse{
				CommandCode: smb2.SMB2_QUERY_DIRECTORY,
			}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)

			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(uint32(erref.STATUS_NO_SUCH_FILE))
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		}, nil, nil)

		fis, err := f.Readdir(-1)
		require.NoError(t, err)
		require.Empty(t, fis)

		// End of directory is reached: a subsequent read reports io.EOF.
		_, err = f.Readdir(1)
		require.ErrorIs(t, err, io.EOF)
		t.Logf("PASS: Readdir treated STATUS_NO_SUCH_FILE as empty directory after %d requests", reqCount.Load())
	})
}

func TestReaddirContinuesPastDotOnlyPages(t *testing.T) {
	for _, n := range []int{-1, 1} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

			queryCount := startQueryDirectoryPages(t, serverConn,
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformations([]string{"."}),
				},
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformations([]string{".."}),
				},
				queryDirectoryPage{
					output: encodeFileIdBothDirectoryInformation("visible.txt"),
				},
				queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)},
			)

			fis, err := f.Readdir(n)
			require.NoError(t, err)
			require.Len(t, fis, 1)
			require.Equal(t, "visible.txt", fis[0].Name())
			if n == 1 {
				require.EqualValues(t, 3, atomic.LoadInt64(queryCount))
			} else {
				require.EqualValues(t, 4, atomic.LoadInt64(queryCount))
			}
		})
	}
}

// directoryResponseTransport exposes received packets to the mock server so
// it can check their release before servicing the next directory query.
type directoryResponseTransport struct {
	transport
	responses chan *recvPacket
}

func (dt *directoryResponseTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	rp, err := dt.transport.ReadPacket(findSink...)
	if err == nil {
		dt.responses <- rp
	}
	return rp, err
}

func TestReaddirReleasesDotOnlyPagesBeforeNextQuery(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	responses := make(chan *recvPacket, 1)
	c := &conn{
		t:                   &directoryResponseTransport{transport: direct(clientConn), responses: responses},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(1),
		maxTransactSize:     64 * 1024,
	}
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	go c.runReceiver()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fs := &Share{treeConn: &treeConn{session: c.session, treeId: 0x200}, ctx: ctx}
	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

	const dotPages = 2
	released := make(chan bool, dotPages)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		dt := direct(serverConn)
		for i := 0; i <= dotPages; i++ {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if i > 0 {
				previous := <-responses
				released <- previous.buf == nil
			}
			output := encodeFileIdBothDirectoryInformations([]string{".", ".."})
			if i == dotPages {
				output = encodeFileIdBothDirectoryInformation("visible.txt")
			}
			sendTestResponse(dt, req, &smb2.QueryDirectoryResponse{Output: rawEncoder(output)}, 0)
		}
	}()

	entries, err := f.Readdir(1)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "visible.txt", entries[0].Name())
	<-serverDone
	for i := range dotPages {
		require.True(t, <-released, "page %d was retained until the next query", i)
	}
	require.Nil(t, (<-responses).buf)
}

func TestReaddirReturnsParseErrorAfterDotOnlyPage(t *testing.T) {
	fs, serverConn := newTestShare(t)
	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

	queryCount := startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{output: []byte{0}},
	)

	_, err := f.Readdir(-1)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.EqualValues(t, 2, atomic.LoadInt64(queryCount))
}

func TestReaddirDotPagesBeforeEnd(t *testing.T) {
	for _, dotPages := range []int{1, 2} {
		for _, status := range []uint32{0, uint32(erref.STATUS_NO_MORE_FILES)} {
			t.Run(fmt.Sprintf("pages=%d/status=%x", dotPages, status), func(t *testing.T) {
				fs, serverConn := newTestShare(t)
				f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")
				pages := []queryDirectoryPage{{output: encodeFileIdBothDirectoryInformation(".")}}
				if dotPages == 2 {
					pages = append(pages, queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("..")})
				}
				pages = append(pages, queryDirectoryPage{status: status})
				queryCount := startQueryDirectoryPages(t, serverConn, pages...)
				fis, err := f.Readdir(-1)
				require.NoError(t, err)
				require.Empty(t, fis)
				require.EqualValues(t, dotPages+1, atomic.LoadInt64(queryCount))
			})
		}
	}
}

func TestReaddirStopsAfterThreeDotOnlyPages(t *testing.T) {
	fs, serverConn := newTestShare(t)
	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")

	var queryCount int64
	startFullFakeServer(serverConn, func(_ uint64, reqBuf []byte, dt transport) bool {
		count := atomic.AddInt64(&queryCount, 1)
		if count <= 3 {
			sendTestResponse(dt, reqBuf, &smb2.QueryDirectoryResponse{
				Output: rawEncoder(encodeFileIdBothDirectoryInformations([]string{".", ".."})),
			}, uint32(erref.STATUS_SUCCESS))
		} else {
			errRes := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
			sendTestResponse(dt, reqBuf, errRes, uint32(erref.STATUS_NO_MORE_FILES))
		}
		return true
	}, nil, nil)

	_, err := f.Readdir(-1)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "invalid response error: query directory returned only dot entries", invalid.Error())
	require.EqualValues(t, 3, atomic.LoadInt64(&queryCount))

	// A malformed enumeration must not poison the shared connection.
	_, err = fs.Stat("other")
	require.NoError(t, err)
}

func TestReadFile_LargeFile(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	const totalFileSize = 200 * 1024 // 200KB (> 2 * maxReadSize = 128KB)

	startFullFakeServer(serverConn, nil, nil, nil, func(req smb2.CreateRequestDecoder, cres *smb2.CreateResponse) {
		cres.EndofFile = totalFileSize
	})

	done := make(chan struct{})
	var data []byte
	var err error
	go func() {
		defer close(done)
		data, err = fs.ReadFile("largefile.dat")
	}()

	select {
	case <-done:
		require.NoError(t, err)
		if len(data) != totalFileSize {
			t.Fatalf("BUG CONFIRMED: ReadFile truncated data! Expected %d bytes, got %d bytes", totalFileSize, len(data))
		}
		t.Logf("PASS: ReadFile read complete %d bytes", len(data))
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadFile timed out")
	}
}

func sendReadFileLengthResponse(dt transport, req []byte, fileID *smb2.FileId, status uint32, adjustment int) {
	p := smb2.PacketCodec(req)
	readReqBuf := req
	for {
		readP := smb2.PacketCodec(readReqBuf)
		if readP.Command() == smb2.SMB2_READ {
			break
		}
		readReqBuf = readReqBuf[readP.NextCommand():]
	}
	readReq := smb2.ReadRequestDecoder(smb2.PacketCodec(readReqBuf).Body())
	data := make([]byte, int(readReq.Length())+adjustment)

	createRes := &smb2.CreateResponse{
		FileId:         fileID,
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
		EndofFile:      int64(len(data)),
	}
	createBuf := make([]byte, createRes.Size())
	createRes.Encode(createBuf)
	createPad := (8 - (len(createBuf) % 8)) % 8
	createNext := uint32(len(createBuf) + createPad)
	createPadded := make([]byte, createNext)
	copy(createPadded, createBuf)
	createPacket := smb2.PacketCodec(createPadded)
	createPacket.SetMessageId(p.MessageId())
	createPacket.SetSessionId(p.SessionId())
	createPacket.SetTreeId(p.TreeId())
	createPacket.SetStatus(uint32(erref.STATUS_SUCCESS))
	createPacket.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	createPacket.SetNextCommand(createNext)

	readRes := &smb2.ReadResponse{Data: data}
	readBuf := make([]byte, readRes.Size())
	readRes.Encode(readBuf)
	readPacket := smb2.PacketCodec(readBuf)
	readPacket.SetMessageId(p.MessageId() + 1)
	readPacket.SetSessionId(p.SessionId())
	readPacket.SetTreeId(p.TreeId())
	readPacket.SetStatus(status)
	readPacket.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	readPacket.SetCreditResponse(1)

	compound := append(createPadded, readBuf...)
	_, _ = dt.Writev(compound)
}

func sendReadFileCloseResponse(dt transport, req []byte) *smb2.FileId {
	p := smb2.PacketCodec(req)
	fileID := smb2.CloseRequestDecoder(p.Body()).FileId().Decode()
	closeRes := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	closeBuf := make([]byte, closeRes.Size())
	closeRes.Encode(closeBuf)
	rp := smb2.PacketCodec(closeBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(uint32(erref.STATUS_SUCCESS))
	rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	rp.SetCreditResponse(1)
	_, _ = dt.Writev(closeBuf)
	return fileID
}

func requireReadFileLengthError(t *testing.T, data []byte, err error) {
	t.Helper()
	require.Nil(t, data)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "readfile", pathErr.Op)
	require.Equal(t, "test.txt", pathErr.Path)
	var invalidErr *InvalidResponseError
	require.ErrorAs(t, err, &invalidErr)
	require.Equal(t, "read length exceeds requested length", invalidErr.Message)
}

func TestReadFileReadLengthBoundary(t *testing.T) {
	for _, adjustment := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(adjustment), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
			dt := direct(serverConn)
			expectedFileID := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			closeReceived := make(chan *smb2.FileId, 1)
			go func() {
				defer close(closeReceived)
				defer serverConn.Close()
				req, err := readMsg(dt)
				if err != nil {
					return
				}
				sendReadFileLengthResponse(dt, req, expectedFileID, uint32(erref.STATUS_SUCCESS), adjustment)
				closeReq, err := readMsg(dt)
				if err != nil {
					return
				}
				if smb2.PacketCodec(closeReq).Command() == smb2.SMB2_CLOSE {
					closeReceived <- sendReadFileCloseResponse(dt, closeReq)
				}
			}()
			data, err := fs.ReadFile("test.txt")
			if adjustment > 0 {
				requireReadFileLengthError(t, data, err)
			} else {
				require.NoError(t, err)
				require.Len(t, data, maxSingleCreditPayloadSize+adjustment)
			}
			require.Equal(t, expectedFileID, <-closeReceived)
		})
	}
}

func TestReadFileRejectsOversizedOverflowReadWithoutFallback(t *testing.T) {
	fs, serverConn := newTestShare(t)
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	dt := direct(serverConn)
	expectedFileID := &smb2.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	closeReceived := make(chan *smb2.FileId, 1)
	extraCreate := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(closeReceived)
		defer serverConn.Close()
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendReadFileLengthResponse(dt, req, expectedFileID, uint32(erref.STATUS_BUFFER_OVERFLOW), 1)

		closeReq, err := readMsg(dt)
		if err != nil {
			return
		}
		if smb2.PacketCodec(closeReq).Command() == smb2.SMB2_CLOSE {
			closeReceived <- sendReadFileCloseResponse(dt, closeReq)
		}

		_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if nextReq, err := readMsg(dt); err == nil && smb2.PacketCodec(nextReq).Command() == smb2.SMB2_CREATE {
			extraCreate <- struct{}{}
			_ = serverConn.Close()
		}
	}()

	result := make(chan struct{})
	var data []byte
	var err error
	go func() {
		data, err = fs.ReadFile("test.txt")
		close(result)
	}()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("ReadFile timed out")
	}
	requireReadFileLengthError(t, data, err)
	<-done
	require.Equal(t, expectedFileID, <-closeReceived)
	select {
	case <-extraCreate:
		t.Fatal("oversized overflow response must not trigger fallback CREATE")
	default:
	}
}

func TestCopyFile_ZeroBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	var sentCopyChunkReq bool

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			qres := &smb2.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, qres.Size())
			qres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		} else if ctlCode == smb2.FSCTL_SRV_COPYCHUNK || ctlCode == smb2.FSCTL_SRV_COPYCHUNK_WRITE {
			sentCopyChunkReq = true
			eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC000000D) // STATUS_INVALID_PARAMETER
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[0:8], 0)  // AllocationSize = 0
		le.PutUint64(stdInfoBuf[8:16], 0) // EndOfFile = 0
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := &smb2.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.NoError(t, err)
	require.True(t, supported)
	require.Equal(t, int64(0), n)
	if sentCopyChunkReq {
		t.Fatal("BUG CONFIRMED: copyFile sent FSCTL_SRV_COPYCHUNK request with 0 chunks for 0-byte copy!")
	}
}

type copyChunkRecorder struct {
	mu     sync.Mutex
	chunks []smb2.SrvCopychunk
}

func (r *copyChunkRecorder) snapshot() []smb2.SrvCopychunk {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]smb2.SrvCopychunk(nil), r.chunks...)
}

func newCopyFileTestShare(t *testing.T, endOfFile int64) (*Share, *copyChunkRecorder) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	recorder := &copyChunkRecorder{}

	go c.runReceiver()
	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			res := &smb2.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, res.Size())
			res.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		}
		if ctlCode != smb2.FSCTL_SRV_COPYCHUNK {
			return false
		}

		inputCount := int(le.Uint32(reqData[28:32]))
		input := reqData[56 : 56+inputCount]
		chunkCount := le.Uint32(input[24:28])
		var total uint32
		chunks := make([]smb2.SrvCopychunk, chunkCount)
		for i := range chunks {
			off := 32 + i*24
			chunks[i] = smb2.SrvCopychunk{
				SourceOffset: int64(le.Uint64(input[off : off+8])),
				TargetOffset: int64(le.Uint64(input[off+8 : off+16])),
				Length:       le.Uint32(input[off+16 : off+20]),
			}
			total += chunks[i].Length
		}
		recorder.mu.Lock()
		recorder.chunks = append(recorder.chunks, chunks...)
		recorder.mu.Unlock()

		respBuf := make([]byte, 12)
		le.PutUint32(respBuf[0:4], chunkCount)
		le.PutUint32(respBuf[4:8], total)
		le.PutUint32(respBuf[8:12], total)
		res := &smb2.IoctlResponse{Output: rawEncoder(respBuf)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		dt.Writev(resBuf)
		return true
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], uint64(endOfFile))
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	return fs, recorder
}

func TestCopyFileRejectsInvalidOffsets(t *testing.T) {
	tests := []struct {
		name      string
		readFrom  bool
		srcOffset int64
		dstOffset int64
	}{
		{name: "ReadFrom source", readFrom: true, srcOffset: -1},
		{name: "ReadFrom destination", readFrom: true, dstOffset: -1},
		{name: "WriteTo source", srcOffset: -1},
		{name: "WriteTo destination", dstOffset: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &Share{}
			src := &File{fs: fs, fd: &smb2.FileId{}, name: "src.txt", offset: tt.srcOffset}
			dst := &File{fs: fs, fd: &smb2.FileId{}, name: "dst.txt", offset: tt.dstOffset}

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(src)
			} else {
				n, err = src.WriteTo(dst)
			}

			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, os.ErrInvalid)
			var linkErr *os.LinkError
			require.ErrorAs(t, err, &linkErr)
			require.Equal(t, "copy", linkErr.Op)
			require.Equal(t, int64(tt.srcOffset), src.offset)
			require.Equal(t, int64(tt.dstOffset), dst.offset)
		})
	}
}

func TestCopyFileRangeValidation(t *testing.T) {
	const twoMiB = int64(2 * 1024 * 1024)

	tests := []struct {
		name      string
		readFrom  bool
		endOfFile int64
		dstOffset int64
		wantErr   bool
	}{
		{name: "ReadFrom reaches MaxInt64", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB},
		{name: "WriteTo reaches MaxInt64", endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB},
		{name: "ReadFrom exceeds MaxInt64", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - 1024*1024 + 1, wantErr: true},
		{name: "WriteTo exceeds MaxInt64", endOfFile: twoMiB, dstOffset: math.MaxInt64 - 1024*1024 + 1, wantErr: true},
		{name: "ReadFrom exceeds by one byte", readFrom: true, endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB + 1, wantErr: true},
		{name: "WriteTo exceeds by one byte", endOfFile: twoMiB, dstOffset: math.MaxInt64 - twoMiB + 1, wantErr: true},
		{name: "multiple batches exceed MaxInt64", readFrom: true, endOfFile: 17 * 1024 * 1024, dstOffset: math.MaxInt64 - 16*1024*1024 + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, recorder := newCopyFileTestShare(t, tt.endOfFile)
			src := &File{fs: fs, fd: &smb2.FileId{Persistent: [8]byte{1}}, name: "src.txt"}
			dst := &File{fs: fs, fd: &smb2.FileId{Persistent: [8]byte{2}}, name: "dst.txt", offset: tt.dstOffset, readAccess: true}

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(src)
			} else {
				n, err = src.WriteTo(dst)
			}

			if tt.wantErr {
				require.Equal(t, int64(0), n)
				require.ErrorIs(t, err, os.ErrInvalid)
				var linkErr *os.LinkError
				require.ErrorAs(t, err, &linkErr)
				require.Equal(t, int64(0), src.offset)
				require.Equal(t, tt.dstOffset, dst.offset)
				require.Empty(t, recorder.snapshot())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.endOfFile, n)
			require.Equal(t, tt.endOfFile, src.offset)
			require.Equal(t, int64(math.MaxInt64), dst.offset)

			chunks := recorder.snapshot()
			require.Len(t, chunks, 2)
			for _, chunk := range chunks {
				require.GreaterOrEqual(t, chunk.SourceOffset, int64(0))
				require.GreaterOrEqual(t, chunk.TargetOffset, int64(0))
				require.LessOrEqual(t, chunk.SourceOffset, math.MaxInt64-int64(chunk.Length))
				require.LessOrEqual(t, chunk.TargetOffset, math.MaxInt64-int64(chunk.Length))
			}
			require.Equal(t, int64(0), chunks[0].SourceOffset)
			require.Equal(t, int64(math.MaxInt64)-twoMiB, chunks[0].TargetOffset)
			require.Equal(t, int64(1024*1024), chunks[1].SourceOffset)
			require.Equal(t, int64(math.MaxInt64)-1024*1024, chunks[1].TargetOffset)
		})
	}
}

func TestCopyFileUnsupportedFallsBackToNormalCopy(t *testing.T) {
	const sourceByte = byte(0x5a)

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					src, serverConn := newTestFile(t)
					dst := &File{fs: src.fs, fd: &smb2.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

					var mu sync.Mutex
					var ioctlCtlCodes []uint32
					var resumeKeyStatus uint32
					var readCount, writeCount int
					var written []byte
					done := make(chan struct{})
					t.Cleanup(func() {
						_ = serverConn.Close()
						<-done
					})

					go func() {
						defer close(done)
						defer serverConn.Close()
						dt := direct(serverConn)
						for {
							req, err := readMsg(dt)
							if err != nil {
								return
							}
							if len(req) < 64 {
								return
							}
							switch smb2.PacketCodec(req).Command() {
							case smb2.SMB2_IOCTL:
								ioctlReq := smb2.IoctlRequestDecoder(req[64:])
								if ioctlReq.IsInvalid() {
									return
								}
								ctlCode := ioctlReq.CtlCode()
								mu.Lock()
								ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
								if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
									resumeKeyStatus = uint32(status.status)
								}
								mu.Unlock()
								if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
									sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(status.status))
								} else {
									sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(erref.STATUS_INVALID_PARAMETER))
								}
							case smb2.SMB2_READ:
								mu.Lock()
								readCount++
								first := readCount == 1
								mu.Unlock()
								if first {
									sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{sourceByte}}, 0)
								} else {
									sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
								}
							case smb2.SMB2_WRITE:
								writeReq := smb2.WriteRequestDecoder(req[64:])
								if writeReq.IsInvalid() {
									return
								}
								dataOffset, dataLength := uint64(writeReq.DataOffset()), uint64(writeReq.Length())
								if dataOffset > uint64(len(req)) || dataLength > uint64(len(req))-dataOffset {
									return
								}
								data := append([]byte(nil), req[dataOffset:dataOffset+dataLength]...)
								mu.Lock()
								writeCount++
								written = append(written, data...)
								mu.Unlock()
								sendTestResponse(dt, req, &smb2.WriteResponse{Count: writeReq.Length()}, 0)
							}
						}
					}()

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(1), n)
					require.Equal(t, int64(1), src.offset)
					require.Equal(t, int64(1), dst.offset)

					_ = serverConn.Close()
					<-done

					mu.Lock()
					defer mu.Unlock()
					require.Equal(t, []uint32{smb2.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
					require.Equal(t, uint32(status.status), resumeKeyStatus)
					require.Greater(t, readCount, 0)
					require.Greater(t, writeCount, 0)
					require.Equal(t, []byte{sourceByte}, written)
				})
			}
		})
	}
}

func TestCopyFileResumeKeyAccessDeniedDoesNotFallBack(t *testing.T) {
	src, serverConn := newTestFile(t)
	dst := &File{fs: src.fs, fd: &smb2.FileId{Persistent: [8]byte{2}}, name: "dst.txt", readAccess: true}

	var mu sync.Mutex
	var ioctlCtlCodes []uint32
	var readCount, writeCount int
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = serverConn.Close()
		<-done
	})

	go func() {
		defer close(done)
		defer serverConn.Close()
		dt := direct(serverConn)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if len(req) < 64 {
				return
			}
			switch smb2.PacketCodec(req).Command() {
			case smb2.SMB2_IOCTL:
				ioctlReq := smb2.IoctlRequestDecoder(req[64:])
				if ioctlReq.IsInvalid() {
					return
				}
				ctlCode := ioctlReq.CtlCode()
				mu.Lock()
				ioctlCtlCodes = append(ioctlCtlCodes, ctlCode)
				mu.Unlock()
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(erref.STATUS_ACCESS_DENIED))
			case smb2.SMB2_READ:
				mu.Lock()
				readCount++
				mu.Unlock()
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
			case smb2.SMB2_WRITE:
				mu.Lock()
				writeCount++
				mu.Unlock()
				sendTestResponse(dt, req, &smb2.WriteResponse{}, 0)
			}
		}
	}()

	n, err := dst.ReadFrom(src)
	require.Equal(t, int64(0), n)
	require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
	require.Equal(t, int64(0), src.offset)
	require.Equal(t, int64(0), dst.offset)

	_ = serverConn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []uint32{smb2.FSCTL_SRV_REQUEST_RESUME_KEY}, ioctlCtlCodes)
	require.Equal(t, 0, readCount)
	require.Equal(t, 0, writeCount)
}

func newCopyFailureTestFiles(t *testing.T, endOfFile int64, failAfter int, status erref.NtStatus) (*File, *File) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	copyCalls := 0
	startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt transport) bool {
		req := smb2.IoctlRequestDecoder(reqBuf[64:])
		switch req.CtlCode() {
		case smb2.FSCTL_SRV_REQUEST_RESUME_KEY:
			sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
				CtlCode: smb2.FSCTL_SRV_REQUEST_RESUME_KEY,
				Output:  rawEncoder(make([]byte, 32)),
			}, 0)
			return true
		case smb2.FSCTL_SRV_COPYCHUNK:
			copyCalls++
			inputCount := int(req.InputCount())
			inputOffset := int(req.InputOffset())
			input := reqBuf[inputOffset : inputOffset+inputCount]
			chunkCount := le.Uint32(input[24:28])
			var total uint32
			for i := range chunkCount {
				off := 32 + i*24
				total += le.Uint32(input[off+16 : off+20])
			}

			if copyCalls == failAfter {
				// These values are server limits, not bytes transferred by a
				// failed request ([MS-SMB2] 3.2.5.14.3).
				limit := make([]byte, 12)
				le.PutUint32(limit[0:4], 1)
				le.PutUint32(limit[4:8], 1)
				le.PutUint32(limit[8:12], 1)
				sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_SRV_COPYCHUNK,
					Output:  rawEncoder(limit),
				}, uint32(status))
				return true
			}

			response := make([]byte, 12)
			le.PutUint32(response[0:4], chunkCount)
			le.PutUint32(response[4:8], total)
			le.PutUint32(response[8:12], total)
			sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
				CtlCode: smb2.FSCTL_SRV_COPYCHUNK,
				Output:  rawEncoder(response),
			}, 0)
			return true
		default:
			return false
		}
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], uint64(endOfFile))
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	src := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "src.txt")
	dst := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "dst.txt")
	dst.readAccess = true
	return src, dst
}

func TestCopyFileFailurePreservesStatusAndProgress(t *testing.T) {
	const firstBatch = int64(16 * 1024 * 1024)

	tests := []struct {
		name      string
		readFrom  bool
		endOfFile int64
		failAfter int
		status    erref.NtStatus
		wantN     int64
	}{
		{name: "ReadFrom first disk full", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "WriteTo first disk full", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_DISK_FULL},
		{name: "ReadFrom after success disk full", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "WriteTo after success disk full", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_DISK_FULL, wantN: firstBatch},
		{name: "ReadFrom first invalid parameter", readFrom: true, endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "WriteTo first invalid parameter", endOfFile: 1 * 1024 * 1024, failAfter: 1, status: erref.STATUS_INVALID_PARAMETER},
		{name: "ReadFrom after success invalid parameter", readFrom: true, endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
		{name: "WriteTo after success invalid parameter", endOfFile: firstBatch + 1*1024*1024, failAfter: 2, status: erref.STATUS_INVALID_PARAMETER, wantN: firstBatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := newCopyFailureTestFiles(t, tt.endOfFile, tt.failAfter, tt.status)

			var n int64
			var err error
			if tt.readFrom {
				n, err = dst.ReadFrom(src)
			} else {
				n, err = src.WriteTo(dst)
			}

			require.Equal(t, tt.wantN, n)
			require.ErrorIs(t, err, tt.status)
			var responseErr *ResponseError
			require.ErrorAs(t, err, &responseErr)
			require.Equal(t, uint32(tt.status), responseErr.Code)
			require.Empty(t, responseErr.data)
			require.Equal(t, tt.wantN, src.offset)
			require.Equal(t, tt.wantN, dst.offset)
		})
	}
}

// copyPermissionFile is the per-CREATE state tracked by copyPermissionServer.
type copyPermissionFile struct {
	id      smb2.FileId
	access  uint32
	content []byte
}

func fileIdKey(id *smb2.FileId) string {
	return string(id.Persistent[:]) + string(id.Volatile[:])
}

// copyPermissionConfig selects the behavior of the fake copy-permission server.
type copyPermissionConfig struct {
	sourceSize int64

	// rejectCopyStatus, when nonzero, rejects every server-side copy FSCTL.
	rejectCopyStatus erref.NtStatus
	// rejectWriteCtlStatus, when nonzero, rejects FSCTL_SRV_COPYCHUNK_WRITE.
	rejectWriteCtlStatus erref.NtStatus
	// failCopyRequest is the 1-based copy request to fail (0 disables).
	failCopyRequest int
	failCopyStatus  erref.NtStatus
}

// copyPermissionServer is a fake SMB2 server that enforces the access rights
// required by the server-side copy FSCTLs ([MS-SMB2] 2.2.31, 3.3.5.15.6) and
// records the control codes and buffered READ/WRITE requests it receives.
type copyPermissionServer struct {
	config copyPermissionConfig

	mu      sync.Mutex
	files   map[string]*copyPermissionFile
	source  *copyPermissionFile
	creates int

	copyCtlCodes  []uint32
	copyRequests  int
	readRequests  int
	writeRequests int
}

func newCopyPermissionPattern(n int64) []byte {
	const block = 64 * 1024
	pattern := make([]byte, block)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	b := make([]byte, n)
	for off := 0; off < len(b); off += block {
		copy(b[off:], pattern)
	}
	return b
}

func newCopyPermissionShare(t *testing.T, config copyPermissionConfig) (*Share, *copyPermissionServer) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(10*time.Second)))
	srv := &copyPermissionServer{
		config: config,
		files:  map[string]*copyPermissionFile{},
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(cleanup)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go srv.serve(serverConn)

	return fs, srv
}

func (s *copyPermissionServer) serve(serverConn net.Conn) {
	defer serverConn.Close()
	dt := direct(serverConn)
	for {
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		if len(reqBuf) < 64 {
			return
		}
		body := reqBuf[64:]
		var invalid bool
		switch smb2.PacketCodec(reqBuf).Command() {
		case smb2.SMB2_CREATE:
			invalid = smb2.CreateRequestDecoder(body).IsInvalid()
		case smb2.SMB2_QUERY_INFO:
			invalid = smb2.QueryInfoRequestDecoder(body).IsInvalid()
		case smb2.SMB2_READ:
			invalid = smb2.ReadRequestDecoder(body).IsInvalid()
		case smb2.SMB2_WRITE:
			invalid = smb2.WriteRequestDecoder(body).IsInvalid()
		case smb2.SMB2_IOCTL:
			invalid = smb2.IoctlRequestDecoder(body).IsInvalid()
		}
		if invalid {
			return
		}
		switch smb2.PacketCodec(reqBuf).Command() {
		case smb2.SMB2_TREE_CONNECT:
			sendTestResponse(dt, reqBuf, &smb2.TreeConnectResponse{ShareType: smb2.SMB2_SHARE_TYPE_DISK}, 0)
		case smb2.SMB2_TREE_DISCONNECT:
			sendTestResponse(dt, reqBuf, &smb2.TreeDisconnectResponse{}, 0)
		case smb2.SMB2_CREATE:
			s.handleCreate(dt, reqBuf)
		case smb2.SMB2_CLOSE:
			sendTestResponse(dt, reqBuf, &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}, 0)
		case smb2.SMB2_QUERY_INFO:
			s.handleQueryInfo(dt, reqBuf)
		case smb2.SMB2_READ:
			s.handleRead(dt, reqBuf)
		case smb2.SMB2_WRITE:
			s.handleWrite(dt, reqBuf)
		case smb2.SMB2_IOCTL:
			s.handleIoctl(dt, reqBuf)
		}
	}
}

func (s *copyPermissionServer) handleCreate(dt transport, reqBuf []byte) {
	req := smb2.CreateRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.creates++
	idx := uint64(s.creates)
	id := smb2.FileId{}
	le.PutUint64(id.Persistent[:], idx)
	le.PutUint64(id.Volatile[:], idx)
	f := &copyPermissionFile{id: id, access: req.DesiredAccess()}
	if s.source == nil {
		f.content = newCopyPermissionPattern(s.config.sourceSize)
		s.source = f
	}
	s.files[fileIdKey(&id)] = f
	s.mu.Unlock()

	sendTestResponse(dt, reqBuf, &smb2.CreateResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
		FileId:         &id,
	}, 0)
}

func (s *copyPermissionServer) handleQueryInfo(dt transport, reqBuf []byte) {
	req := smb2.QueryInfoRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	f := s.files[fileIdKey(req.FileId().Decode())]
	s.mu.Unlock()

	var end int64
	if f != nil {
		end = int64(len(f.content))
	}

	stdInfoBuf := make([]byte, 24)
	le.PutUint64(stdInfoBuf[8:16], uint64(end))
	sendTestResponse(dt, reqBuf, &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}, 0)
}

func (s *copyPermissionServer) handleRead(dt transport, reqBuf []byte) {
	req := smb2.ReadRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.readRequests++
	f := s.files[fileIdKey(req.FileId().Decode())]
	var data []byte
	if f != nil {
		offset := int64(req.Offset())
		if offset >= 0 && offset < int64(len(f.content)) {
			end := min(offset+int64(req.Length()), int64(len(f.content)))
			data = append([]byte(nil), f.content[offset:end]...)
		}
	}
	s.mu.Unlock()

	if len(data) == 0 {
		sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, uint32(erref.STATUS_END_OF_FILE))
		return
	}
	sendTestResponse(dt, reqBuf, &smb2.ReadResponse{Data: data}, 0)
}

func (s *copyPermissionServer) handleWrite(dt transport, reqBuf []byte) {
	req := smb2.WriteRequestDecoder(reqBuf[64:])
	dataOffset, dataLength := uint64(req.DataOffset()), uint64(req.Length())
	if dataOffset > uint64(len(reqBuf)) || dataLength > uint64(len(reqBuf))-dataOffset ||
		req.Offset() > uint64(s.config.sourceSize) || dataLength > uint64(s.config.sourceSize)-req.Offset() {
		sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_WRITE}, uint32(erref.STATUS_INVALID_PARAMETER))
		return
	}
	data := reqBuf[dataOffset : dataOffset+dataLength]

	s.mu.Lock()
	s.writeRequests++
	f := s.files[fileIdKey(req.FileId().Decode())]
	if f != nil {
		offset := int(req.Offset())
		end := offset + len(data)
		if end > len(f.content) {
			f.content = append(f.content, make([]byte, end-len(f.content))...)
		}
		copy(f.content[offset:], data)
	}
	s.mu.Unlock()

	sendTestResponse(dt, reqBuf, &smb2.WriteResponse{Count: req.Length()}, 0)
}

func (s *copyPermissionServer) handleIoctl(dt transport, reqBuf []byte) {
	req := smb2.IoctlRequestDecoder(reqBuf[64:])

	switch req.CtlCode() {
	case smb2.FSCTL_SRV_REQUEST_RESUME_KEY:
		s.mu.Lock()
		f := s.files[fileIdKey(req.FileId().Decode())]
		readable := f != nil && f.access&(smb2.FILE_READ_DATA|smb2.GENERIC_READ|smb2.GENERIC_ALL) != 0
		s.mu.Unlock()
		if !readable {
			sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(erref.STATUS_ACCESS_DENIED))
			return
		}
		sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{Output: rawEncoder(make([]byte, 32))}, 0)
	case smb2.FSCTL_SRV_COPYCHUNK, smb2.FSCTL_SRV_COPYCHUNK_WRITE:
		s.handleCopyChunk(dt, reqBuf, req.CtlCode())
	default:
		sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(erref.STATUS_NOT_SUPPORTED))
	}
}

func (s *copyPermissionServer) handleCopyChunk(dt transport, reqBuf []byte, ctlCode uint32) {
	req := smb2.IoctlRequestDecoder(reqBuf[64:])

	s.mu.Lock()
	s.copyRequests++
	copyRequest := s.copyRequests
	s.copyCtlCodes = append(s.copyCtlCodes, ctlCode)
	dstFile := s.files[fileIdKey(req.FileId().Decode())]
	source := s.source
	s.mu.Unlock()

	reject := func(status erref.NtStatus) {
		sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}, uint32(status))
	}

	if s.config.rejectCopyStatus != 0 {
		reject(s.config.rejectCopyStatus)
		return
	}
	if ctlCode == smb2.FSCTL_SRV_COPYCHUNK_WRITE && s.config.rejectWriteCtlStatus != 0 {
		reject(s.config.rejectWriteCtlStatus)
		return
	}
	if s.config.failCopyRequest != 0 && copyRequest == s.config.failCopyRequest {
		reject(s.config.failCopyStatus)
		return
	}

	// [MS-SMB2] 2.2.31: FSCTL_SRV_COPYCHUNK requires FILE_READ_DATA on the
	// destination handle; FSCTL_SRV_COPYCHUNK_WRITE only requires write access.
	if source == nil || source.access&(smb2.FILE_READ_DATA|smb2.GENERIC_READ|smb2.GENERIC_ALL) == 0 ||
		dstFile == nil || dstFile.access&(smb2.FILE_WRITE_DATA|smb2.FILE_APPEND_DATA|smb2.GENERIC_WRITE|smb2.GENERIC_ALL) == 0 {
		reject(erref.STATUS_ACCESS_DENIED)
		return
	}
	if ctlCode == smb2.FSCTL_SRV_COPYCHUNK {
		if dstFile.access&(smb2.FILE_READ_DATA|smb2.GENERIC_READ|smb2.GENERIC_ALL) == 0 {
			reject(erref.STATUS_ACCESS_DENIED)
			return
		}
	}

	inputOffset := uint64(req.InputOffset())
	inputCount := uint64(req.InputCount())
	if inputCount < 32 || inputOffset > uint64(len(reqBuf)) || inputCount > uint64(len(reqBuf))-inputOffset {
		reject(erref.STATUS_INVALID_PARAMETER)
		return
	}
	input := reqBuf[inputOffset : inputOffset+inputCount]
	chunkCount := uint64(le.Uint32(input[24:28]))
	if chunkCount > uint64(len(input)-32)/24 {
		reject(erref.STATUS_INVALID_PARAMETER)
		return
	}

	s.mu.Lock()
	var total uint32
	for i := range chunkCount {
		off := 32 + i*24
		sourceOffset := int64(le.Uint64(input[off : off+8]))
		targetOffset := int64(le.Uint64(input[off+8 : off+16]))
		length := le.Uint32(input[off+16 : off+20])
		if sourceOffset < 0 || sourceOffset > int64(len(source.content)) || int64(length) > int64(len(source.content))-sourceOffset ||
			targetOffset < 0 || targetOffset > s.config.sourceSize || int64(length) > s.config.sourceSize-targetOffset {
			s.mu.Unlock()
			reject(erref.STATUS_INVALID_PARAMETER)
			return
		}
		end := targetOffset + int64(length)
		if end > int64(len(dstFile.content)) {
			dstFile.content = append(dstFile.content, make([]byte, end-int64(len(dstFile.content)))...)
		}
		copy(dstFile.content[targetOffset:], source.content[sourceOffset:sourceOffset+int64(length)])
		total += length
	}
	s.mu.Unlock()

	respBuf := make([]byte, 12)
	le.PutUint32(respBuf[0:4], uint32(chunkCount))
	// [MS-SMB2] 3.3.5.15.6 requires ChunkBytesWritten to be zero on success.
	le.PutUint32(respBuf[8:12], total)
	sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{Output: rawEncoder(respBuf)}, 0)
}

func (s *copyPermissionServer) content(id *smb2.FileId) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.files[fileIdKey(id)]
	if f == nil {
		return nil
	}
	return append([]byte(nil), f.content...)
}

func (s *copyPermissionServer) sourceContent() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.source.content...)
}

func (s *copyPermissionServer) snapshot() (ctlCodes []uint32, reads, writes, copies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.copyCtlCodes...), s.readRequests, s.writeRequests, s.copyRequests
}

type copyPath struct {
	name string
	run  func(src, dst *File) (int64, error)
}

func copyPaths() []copyPath {
	return []copyPath{
		{name: "ReadFrom", run: func(src, dst *File) (int64, error) { return dst.ReadFrom(src) }},
		{name: "WriteTo", run: func(src, dst *File) (int64, error) { return src.WriteTo(dst) }},
		{name: "io.Copy", run: func(src, dst *File) (int64, error) { return io.Copy(dst, src) }},
	}
}

func TestCopyFileWriteOnlyDestinationUsesWriteVariant(t *testing.T) {
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{sourceSize: sourceSize})

			src, err := fs.OpenFile("src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close()

			dst, err := fs.OpenFile("dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close()

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{smb2.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileReadWriteDestinationUsesCopyChunk(t *testing.T) {
	const sourceSize = 300 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			// The server rejects FSCTL_SRV_COPYCHUNK_WRITE, proving a read/write
			// destination never relies on it.
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:           sourceSize,
				rejectWriteCtlStatus: erref.STATUS_NOT_SUPPORTED,
			})

			src, err := fs.OpenFile("src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close()

			dst, err := fs.OpenFile("dst.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close()

			n, err := tc.run(src, dst)
			require.NoError(t, err)
			require.Equal(t, int64(sourceSize), n)
			require.Equal(t, int64(sourceSize), src.offset)
			require.Equal(t, int64(sourceSize), dst.offset)
			require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{smb2.FSCTL_SRV_COPYCHUNK}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
		})
	}
}

func TestCopyFileWriteVariantUnsupportedFallsBackToNormalCopy(t *testing.T) {
	const sourceSize = 150 * 1024

	statuses := []struct {
		name   string
		status erref.NtStatus
	}{
		{name: "not supported", status: erref.STATUS_NOT_SUPPORTED},
		{name: "invalid device request", status: erref.STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, status := range statuses {
		t.Run(status.name, func(t *testing.T) {
			for _, tc := range copyPaths() {
				t.Run(tc.name, func(t *testing.T) {
					fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
						sourceSize:           sourceSize,
						rejectWriteCtlStatus: status.status,
					})

					src, err := fs.OpenFile("src.txt", os.O_RDONLY, 0)
					require.NoError(t, err)
					defer src.Close()

					dst, err := fs.OpenFile("dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
					require.NoError(t, err)
					defer dst.Close()

					n, err := tc.run(src, dst)
					require.NoError(t, err)
					require.Equal(t, int64(sourceSize), n)
					require.Equal(t, int64(sourceSize), src.offset)
					require.Equal(t, int64(sourceSize), dst.offset)
					require.Equal(t, srv.sourceContent(), srv.content(dst.fd))

					codes, reads, writes, copies := srv.snapshot()
					require.Equal(t, []uint32{smb2.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
					require.Equal(t, 1, copies)
					require.Greater(t, reads, 0)
					require.Greater(t, writes, 0)
				})
			}
		})
	}
}

func TestCopyFileAccessDeniedDoesNotFallBack(t *testing.T) {
	const sourceSize = 150 * 1024

	for _, tc := range copyPaths() {
		t.Run(tc.name, func(t *testing.T) {
			fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
				sourceSize:       sourceSize,
				rejectCopyStatus: erref.STATUS_ACCESS_DENIED,
			})

			src, err := fs.OpenFile("src.txt", os.O_RDONLY, 0)
			require.NoError(t, err)
			defer src.Close()

			dst, err := fs.OpenFile("dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
			require.NoError(t, err)
			defer dst.Close()

			n, err := tc.run(src, dst)
			require.Equal(t, int64(0), n)
			require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
			require.Equal(t, int64(0), src.offset)
			require.Equal(t, int64(0), dst.offset)

			codes, reads, writes, copies := srv.snapshot()
			require.Equal(t, []uint32{smb2.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
			require.Equal(t, 1, copies)
			require.Equal(t, 0, reads)
			require.Equal(t, 0, writes)
			require.Empty(t, srv.content(dst.fd))
		})
	}
}

func TestCopyFileWriteVariantFailureAfterFirstBatchPreservesProgress(t *testing.T) {
	const firstBatch = int64(16 * 1024 * 1024)
	const sourceSize = firstBatch + 1024*1024

	fs, srv := newCopyPermissionShare(t, copyPermissionConfig{
		sourceSize:      sourceSize,
		failCopyRequest: 2,
		failCopyStatus:  erref.STATUS_NOT_SUPPORTED,
	})

	src, err := fs.OpenFile("src.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer src.Close()

	dst, err := fs.OpenFile("dst.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	require.NoError(t, err)
	defer dst.Close()

	n, err := dst.ReadFrom(src)
	require.Equal(t, firstBatch, n)
	require.ErrorIs(t, err, erref.STATUS_NOT_SUPPORTED)
	require.Equal(t, firstBatch, src.offset)
	require.Equal(t, firstBatch, dst.offset)

	codes, reads, writes, copies := srv.snapshot()
	require.Equal(t, []uint32{smb2.FSCTL_SRV_COPYCHUNK_WRITE, smb2.FSCTL_SRV_COPYCHUNK_WRITE}, codes)
	require.Equal(t, 2, copies)
	require.Equal(t, 0, reads)
	require.Equal(t, 0, writes)
	require.Equal(t, srv.sourceContent()[:firstBatch], srv.content(dst.fd))
}

func TestCopyFile_RejectsShortTotalBytesWritten(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	const totalFileSize = 100

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			resKeyBuf := make([]byte, 32)
			ires := &smb2.IoctlResponse{Output: rawEncoder(resKeyBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		} else if ctlCode == smb2.FSCTL_SRV_COPYCHUNK {
			// Sum up the chunk lengths requested by the client.
			reqData := reqBuf[64:]
			inputCount := int(le.Uint32(reqData[28:32]))
			input := reqData[56 : 56+inputCount] // SrvCopychunkCopy
			reqTotal := uint64(0)
			chunks := le.Uint32(input[24:28])
			for i := range chunks {
				off := 32 + i*24
				reqTotal += uint64(le.Uint32(input[off+16 : off+20]))
			}

			// Respond with a SrvCopychunkResponse reporting one byte less than requested.
			respBuf := make([]byte, 12)
			le.PutUint32(respBuf[0:4], chunks)
			le.PutUint32(respBuf[4:8], uint32(reqTotal-1))  // ChunksBytesWritten
			le.PutUint32(respBuf[8:12], uint32(reqTotal-1)) // TotalBytesWritten
			ires := &smb2.IoctlResponse{Output: rawEncoder(respBuf)}
			resBuf := make([]byte, ires.Size())
			ires.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		}
		return false
	}, func(msgId uint64, reqBuf []byte) []byte {
		stdInfoBuf := make([]byte, 24)
		le.PutUint64(stdInfoBuf[8:16], totalFileSize) // EndOfFile = 100
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(stdInfoBuf)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	srcFd := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}
	dstFd := &smb2.FileId{Persistent: [8]byte{2}, Volatile: [8]byte{2}}

	supported, n, err := fs.copyFile(srcFd, dstFd, "src.txt", "dst.txt", 0, 0, true)
	require.True(t, supported)
	require.Error(t, err, "copyFile must fail when TotalBytesWritten is less than the requested bytes")

	var linkErr *os.LinkError
	require.True(t, errors.As(err, &linkErr))
	require.Equal(t, "copy", linkErr.Op)
	require.Equal(t, "src.txt", linkErr.Old)
	require.Equal(t, "dst.txt", linkErr.New)

	var invalidResp *InvalidResponseError
	require.True(t, errors.As(linkErr.Err, &invalidResp))
	require.Equal(t, "srv copy chunk wrote fewer bytes than requested", invalidResp.Message)

	require.Equal(t, int64(0), n)
}

func TestFileWrite_NegativeBytesWrittenOnChunkError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == smb2.SMB2_WRITE {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			}
		}
	}()

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.Write([]byte("test data"))
	require.Error(t, err)

	if n < 0 || f.offset < 0 {
		t.Fatalf("BUG CONFIRMED: File.Write returned negative bytes written n=%d or corrupted offset=%d!", n, f.offset)
	}
}

func TestFileWriteAt_NegativeBytesWrittenOnErr(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			cmd := p.Command()
			msgId := p.MessageId()

			if cmd == smb2.SMB2_WRITE {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_WRITE}
				resBuf := make([]byte, eres.Size())
				eres.Encode(resBuf)

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetStatus(0xC000007F) // STATUS_DISK_FULL
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				dt.Writev(resBuf)
			}
		}
	}()

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	n, err := f.WriteAt([]byte("test data"), 0)
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.WriteAt returned negative bytes written n=%d!", n)
	}
}

func TestFileSeek_NegativeReturnOnErr(t *testing.T) {
	fs := &Share{ctx: context.Background()}
	f := &File{fs: fs}

	ret, err := f.Seek(0, io.SeekStart)
	require.Error(t, err)
	if ret < 0 {
		t.Fatalf("BUG CONFIRMED: File.Seek returned negative offset ret=%d on closed file!", ret)
	}
}

func TestFileStatQueriesFileNetworkOpenInformation(t *testing.T) {
	fs, serverConn := newTestShare(t)

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	var gotClass uint8
	var gotLen uint32
	var gotCharge uint16
	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		p := smb2.PacketCodec(reqBuf)
		gotCharge = p.CreditCharge()
		qreq := smb2.QueryInfoRequestDecoder(p.Body())
		gotClass = qreq.FileInfoClass()
		gotLen = qreq.OutputBufferLength()

		buf := make([]byte, 56)
		le.PutUint32(buf[0:4], 0x11223344)
		le.PutUint32(buf[4:8], 0x01234567)
		le.PutUint32(buf[8:12], 0x55667788)
		le.PutUint32(buf[12:16], 0x01234567)
		le.PutUint32(buf[16:20], 0x99aabbcc)
		le.PutUint32(buf[20:24], 0x01234567)
		le.PutUint32(buf[24:28], 0xddeeff00)
		le.PutUint32(buf[28:32], 0x01234567)
		le.PutUint64(buf[32:40], 16384)
		le.PutUint64(buf[40:48], 8192)
		le.PutUint32(buf[48:52], 0x20)

		res := &smb2.QueryInfoResponse{Output: rawEncoder(buf)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		return resBuf
	})

	fi, err := f.Stat()
	require.NoError(t, err)
	require.NotNil(t, fi)
	require.Equal(t, uint8(smb2.FileNetworkOpenInformation), gotClass)
	require.Equal(t, uint32(56), gotLen)
	require.Equal(t, uint16(1), gotCharge)
	require.Equal(t, int64(8192), fi.Size())
	require.False(t, fi.IsDir())

	fst, ok := fi.(*FileStat)
	require.True(t, ok)
	require.Equal(t, uint32(0x20), fst.FileAttributes)
	require.Equal(t, int64(16384), fst.AllocationSize)
}

func TestFileStatRejectsNegativeFileNetworkOpenInformationTime(t *testing.T) {
	fs, serverConn := newTestShare(t)

	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
		info := make([]byte, 56)
		le.PutUint64(info[0:8], ^uint64(0)) // CreationTime = -1
		qres := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		resBuf := make([]byte, qres.Size())
		qres.Encode(resBuf)
		return resBuf
	})

	fi, err := f.Stat()
	require.Nil(t, fi)
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestShareStatUsesCompoundCreateClose(t *testing.T) {
	fs, serverConn := newTestShare(t)

	var recordedCmds []smb2.Command
	var createOptions uint32
	var createCount, closeCount int

	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := smb2.PacketCodec(currBuf)
			cmd := p.Command()
			recordedCmds = append(recordedCmds, cmd)

			var resBuf []byte
			switch cmd {
			case smb2.SMB2_CREATE:
				createCount++
				req := smb2.CreateRequestDecoder(currBuf[64:])
				createOptions = req.CreateOptions()
				cres := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{LowDateTime: 0x11223344, HighDateTime: 0x01234567},
					LastAccessTime: &smb2.Filetime{LowDateTime: 0x55667788, HighDateTime: 0x01234567},
					LastWriteTime:  &smb2.Filetime{LowDateTime: 0x99aabbcc, HighDateTime: 0x01234567},
					ChangeTime:     &smb2.Filetime{LowDateTime: 0xddeeff00, HighDateTime: 0x01234567},
					AllocationSize: 8192,
					EndofFile:      4096,
					FileAttributes: smb2.FILE_ATTRIBUTE_ARCHIVE,
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case smb2.SMB2_CLOSE:
				closeCount++
				clres := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, clres.Size())
				clres.Encode(resBuf)
			}

			if resBuf != nil {
				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				responseBufs = append(responseBufs, resBuf)
			}

			if p.NextCommand() == 0 {
				break
			}
			currBuf = currBuf[p.NextCommand():]
		}

		if len(responseBufs) > 0 {
			var finalBuf []byte
			for i, rb := range responseBufs {
				if i < len(responseBufs)-1 {
					pad := (8 - (len(rb) % 8)) % 8
					nextCmd := uint32(len(rb) + pad)
					padded := make([]byte, nextCmd)
					copy(padded, rb)
					smb2.PacketCodec(padded).SetNextCommand(nextCmd)
					finalBuf = append(finalBuf, padded...)
				} else {
					finalBuf = append(finalBuf, rb...)
				}
			}
			_, _ = dt.Writev(finalBuf)
		}
	}()

	fi, err := fs.Stat("test.txt")
	require.NoError(t, err)
	require.NotNil(t, fi)

	require.Equal(t, "test.txt", fi.Name())
	require.Equal(t, int64(4096), fi.Size())
	require.False(t, fi.IsDir())

	fst, ok := fi.(*FileStat)
	require.True(t, ok)
	require.Equal(t, uint32(smb2.FILE_ATTRIBUTE_ARCHIVE), fst.FileAttributes)
	require.Equal(t, int64(8192), fst.AllocationSize)

	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(0), createOptions, "Share.Stat must not set FILE_OPEN_REPARSE_POINT")
	require.Equal(t, 1, createCount)
	require.Equal(t, 1, closeCount)
}

func TestShareReadlinkUsesSingleCredit(t *testing.T) {
	fs, serverConn := newTestShare(t)

	var recordedCmds []smb2.Command
	var ioctlCreditCharge uint16
	var maxOutputResponse uint32

	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}

		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := smb2.PacketCodec(currBuf)
			cmd := p.Command()
			recordedCmds = append(recordedCmds, cmd)

			var resBuf []byte
			switch cmd {
			case smb2.SMB2_CREATE:
				cres := &smb2.CreateResponse{
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, cres.Size())
				cres.Encode(resBuf)

			case smb2.SMB2_IOCTL:
				ioctlCreditCharge = p.CreditCharge()
				req := smb2.IoctlRequestDecoder(currBuf[64:])
				maxOutputResponse = req.MaxOutputResponse()

				reparse := &smb2.SymbolicLinkReparseDataBuffer{
					Flags:          smb2.SYMLINK_FLAG_RELATIVE,
					SubstituteName: "target.txt",
					PrintName:      "target.txt",
				}
				buf := make([]byte, reparse.Size())
				reparse.Encode(buf)

				ires := &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_GET_REPARSE_POINT,
					Output:  rawEncoder(buf),
				}
				resBuf = make([]byte, ires.Size())
				ires.Encode(resBuf)

			case smb2.SMB2_CLOSE:
				clres := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, clres.Size())
				clres.Encode(resBuf)
			}

			if resBuf != nil {
				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				responseBufs = append(responseBufs, resBuf)
			}

			if p.NextCommand() == 0 {
				break
			}
			currBuf = currBuf[p.NextCommand():]
		}

		if len(responseBufs) > 0 {
			var finalBuf []byte
			for i, rb := range responseBufs {
				if i < len(responseBufs)-1 {
					pad := (8 - (len(rb) % 8)) % 8
					nextCmd := uint32(len(rb) + pad)
					padded := make([]byte, nextCmd)
					copy(padded, rb)
					smb2.PacketCodec(padded).SetNextCommand(nextCmd)
					finalBuf = append(finalBuf, padded...)
				} else {
					finalBuf = append(finalBuf, rb...)
				}
			}
			_, _ = dt.Writev(finalBuf)
		}
	}()

	target, err := fs.Readlink("link.txt")
	require.NoError(t, err)
	require.Equal(t, "target.txt", target)

	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_IOCTL, smb2.SMB2_CLOSE}, recordedCmds)
	require.Equal(t, uint32(maxSingleCreditPayloadSize), maxOutputResponse)
	require.Equal(t, uint16(1), ioctlCreditCharge)
}

func TestParseFsFullSizeInfoRejectsNegativeAllocationUnits(t *testing.T) {
	testCases := []struct {
		name   string
		offset int
	}{
		{name: "TotalAllocationUnits", offset: 0},
		{name: "CallerAvailableAllocationUnits", offset: 8},
		{name: "ActualAvailableAllocationUnits", offset: 16},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			info := make([]byte, 32)
			le.PutUint64(info[0:8], 1000)
			le.PutUint64(info[8:16], 600)
			le.PutUint64(info[16:24], 500)
			le.PutUint32(info[24:28], 8)
			le.PutUint32(info[28:32], 512)
			le.PutUint64(info[testCase.offset:testCase.offset+8], ^uint64(0))

			qres := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
			resBuf := make([]byte, qres.Size())
			qres.Encode(resBuf)

			got, err := parseFsFullSizeInfo(smb2.PacketCodec(resBuf).Body())
			require.Nil(t, got)
			var invalid *InvalidResponseError
			require.ErrorAs(t, err, &invalid)
		})
	}
}

func TestReadFileRejectsUnreasonableEndOfFile(t *testing.T) {
	fs, serverConn := newTestShare(t)

	createReady := make(chan struct{})
	go func() {
		<-createReady
		// Stop the fake server from supplying an effectively unlimited file.
		time.Sleep(10 * time.Millisecond)
		serverConn.Close()
	}()
	startFullFakeServer(serverConn, nil, nil, nil, func(req smb2.CreateRequestDecoder, cres *smb2.CreateResponse) {
		cres.EndofFile = int64(^uint64(0) >> 1) // max int64
		close(createReady)
	})

	var err error
	require.NotPanics(t, func() {
		_, err = fs.ReadFile("test.txt")
	})
	require.Error(t, err)
}

func TestNewBenchConnCleanupWithCompletedReceiver(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	c, cleanup := newBenchConn(clientConn)
	c.m.Lock()
	defer c.m.Unlock()

	require.NoError(t, c.closeLocked(nil))
	select {
	case c.rdone <- struct{}{}:
	default:
	}

	cleanupWithTimeout := func() {
		done := make(chan struct{})
		go func() {
			cleanup()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup timed out")
		}
	}

	cleanupWithTimeout()
	cleanupWithTimeout()
}

func TestReadFile_EmptyFile(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{3, 4, 5, 6, 7, 8, 9, 10},
		Volatile:   [8]byte{11, 12, 13, 14, 15, 16, 17, 18},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + read (ReadFile)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := smb2.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &smb2.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		smb2.PacketCodec(padded0).SetMessageId(p.MessageId())
		smb2.PacketCodec(padded0).SetSessionId(p.SessionId())
		smb2.PacketCodec(padded0).SetTreeId(p.TreeId())
		smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: Read ErrorResponse STATUS_END_OF_FILE (empty file)
		errPkt1 := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_READ,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		smb2.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
		smb2.PacketCodec(resBuf1).SetSessionId(p.SessionId())
		smb2.PacketCodec(resBuf1).SetTreeId(p.TreeId())
		smb2.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_END_OF_FILE))
		smb2.PacketCodec(resBuf1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		smb2.PacketCodec(resBuf1).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.Writev(compound)

		// Request 2: automatic close of the opened file handle
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeReq := smb2.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}
	}()

	data, err := fs.ReadFile("test.txt")
	require.NoError(t, err, "reading an empty file must not fail")
	require.NotNil(t, data, "reading an empty file must return a non-nil empty slice")
	require.Len(t, data, 0)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle")
}

func TestShare_ReadFile_StatusBufferOverflowFallback(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	dt := direct(serverConn)
	fileId1 := &smb2.FileId{Persistent: [8]byte{1, 1}, Volatile: [8]byte{2, 2}}
	fileId2 := &smb2.FileId{Persistent: [8]byte{3, 3}, Volatile: [8]byte{4, 4}}

	done := make(chan struct{})
	go func() {
		defer close(done)

		// Request 1: compound CREATE + READ
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		p1 := smb2.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS (EndofFile = 12)
		cres1 := &smb2.CreateResponse{
			FileId:         fileId1,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			EndofFile:      12,
		}
		resBuf0 := make([]byte, cres1.Size())
		cres1.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		smb2.PacketCodec(padded0).SetMessageId(p1.MessageId())
		smb2.PacketCodec(padded0).SetSessionId(p1.SessionId())
		smb2.PacketCodec(padded0).SetTreeId(p1.TreeId())
		smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: ReadResponse with STATUS_BUFFER_OVERFLOW and partial data "hello"
		partialData := []byte("hello")
		rres := &smb2.ReadResponse{Data: partialData}
		resBuf1 := make([]byte, rres.Size())
		rres.Encode(resBuf1)
		smb2.PacketCodec(resBuf1).SetMessageId(p1.MessageId() + 1)
		smb2.PacketCodec(resBuf1).SetSessionId(p1.SessionId())
		smb2.PacketCodec(resBuf1).SetTreeId(p1.TreeId())
		smb2.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_BUFFER_OVERFLOW))
		smb2.PacketCodec(resBuf1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		smb2.PacketCodec(resBuf1).SetCreditResponse(1)

		compound := append(padded0, resBuf1...)
		_, _ = dt.Writev(compound)

		// Request 2: auto-close of fileId1 by tree_conn.sendRecv
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}

		// Request 3: fallback CREATE (single op, no compound)
		reqBuf3, err := readMsg(dt)
		if err != nil {
			return
		}
		p3 := smb2.PacketCodec(reqBuf3)

		// CreateResponse SUCCESS with fileId2 (EndofFile = 12)
		cres2 := &smb2.CreateResponse{
			FileId:         fileId2,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			EndofFile:      12,
		}
		resBuf3 := make([]byte, cres2.Size())
		cres2.Encode(resBuf3)
		smb2.PacketCodec(resBuf3).SetMessageId(p3.MessageId())
		smb2.PacketCodec(resBuf3).SetSessionId(p3.SessionId())
		smb2.PacketCodec(resBuf3).SetTreeId(p3.TreeId())
		smb2.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(resBuf3).SetCreditResponse(1)
		_, _ = dt.Writev(resBuf3)

		// Request 4: READ request at offset 5 for remaining 7 bytes (" world!")
		reqBuf4, err := readMsg(dt)
		if err != nil {
			return
		}
		p4 := smb2.PacketCodec(reqBuf4)
		remainData := []byte(" world!")
		rres4 := &smb2.ReadResponse{Data: remainData}
		resBuf4 := make([]byte, rres4.Size())
		rres4.Encode(resBuf4)
		rp4 := smb2.PacketCodec(resBuf4)
		rp4.SetMessageId(p4.MessageId())
		rp4.SetSessionId(p4.SessionId())
		rp4.SetTreeId(p4.TreeId())
		rp4.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp4.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp4.SetCreditResponse(1)
		_, _ = dt.Writev(resBuf4)

		// Request 5: CLOSE of fileId2 by defer f.Close()
		reqBuf5, err := readMsg(dt)
		if err != nil {
			return
		}
		p5 := smb2.PacketCodec(reqBuf5)
		closeRes2 := &smb2.CloseResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}
		closeBuf2 := make([]byte, closeRes2.Size())
		closeRes2.Encode(closeBuf2)
		rp5 := smb2.PacketCodec(closeBuf2)
		rp5.SetMessageId(p5.MessageId())
		rp5.SetSessionId(p5.SessionId())
		rp5.SetTreeId(p5.TreeId())
		rp5.SetStatus(uint32(erref.STATUS_SUCCESS))
		rp5.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		rp5.SetCreditResponse(1)
		_, _ = dt.Writev(closeBuf2)
	}()

	data, err := fs.ReadFile("test.txt")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world!"), data)

	<-done
}

func TestReadAtPropagatesChunkError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

	go c.runReceiver()
	go func() {
		dt := direct(serverConn)
		for range 2 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			p := smb2.PacketCodec(req)
			readReq := smb2.ReadRequestDecoder(req[64:])
			var res []byte
			if readReq.Offset() == 0 {
				rres := &smb2.ReadResponse{Data: make([]byte, readReq.Length())}
				res = make([]byte, rres.Size())
				rres.Encode(res)
			} else {
				eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}
				res = make([]byte, eres.Size())
				eres.Encode(res)
			}

			rp := smb2.PacketCodec(res)
			rp.SetMessageId(p.MessageId())
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			if readReq.Offset() != 0 {
				rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			}
			_, _ = dt.Writev(res)
		}
	}()

	_, err := f.ReadAt(make([]byte, fs.maxReadSize(0)+1), 0)
	require.Error(t, err)
}

func newTestFile(t *testing.T) (*File, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	return fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt"), serverConn
}

func sendTestResponse(dt transport, req []byte, res smb2.Packet, status uint32) {
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	p := smb2.PacketCodec(req)
	rp := smb2.PacketCodec(resBuf)
	rp.SetMessageId(p.MessageId())
	rp.SetSessionId(p.SessionId())
	rp.SetTreeId(p.TreeId())
	rp.SetStatus(status)
	rp.SetCreditResponse(1)
	rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	_, _ = dt.Writev(resBuf)
}

func TestReadAtCompletesShortSMBRead(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			readReq := smb2.ReadRequestDecoder(req[64:])
			data := []byte{1}
			if readReq.Offset() != 0 {
				data = make([]byte, readReq.Length())
			}
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: data}, 0)
		}
	}()

	buf := make([]byte, f.fs.maxReadSize(0)+1)
	n, err := f.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
}

func TestReadAtCompletesMultipleShortSMBReads(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
		}
	}()

	n, err := f.ReadAt(make([]byte, 4), 0)
	require.NoError(t, err)
	require.Equal(t, 4, n)
}

func TestReadAtReturnsEOFOnShortFile(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for i := range 3 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			if i < 2 {
				sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
			} else {
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_READ}, 0xC0000011) // STATUS_END_OF_FILE
			}
		}
	}()

	n, err := f.ReadAt(make([]byte, 8), 0)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, n)
}

func TestReadCompletesShortSMBRead(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &smb2.ReadResponse{Data: []byte{1}}, 0)
	}()

	n, err := f.Read(make([]byte, 8))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadReturnsErrorOnBufferOverflowWithNoData(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &smb2.ReadResponse{}, 0x80000005) // STATUS_BUFFER_OVERFLOW
	}()

	n, err := f.Read(make([]byte, 8))
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestReadLargeBufferReadsSingleChunk(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		readReq := smb2.ReadRequestDecoder(req[64:])
		data := []byte{1}
		if readReq.Offset() != 0 {
			data = make([]byte, readReq.Length())
		}
		sendTestResponse(dt, req, &smb2.ReadResponse{Data: data}, 0)
	}()

	n, err := f.Read(make([]byte, f.fs.maxReadSize(0)+1))
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestReadAtRejectsInvalidLength(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		readReq := smb2.ReadRequestDecoder(req[64:])
		sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length()+1)}, 0)
	}()

	n, err := f.ReadAt(make([]byte, 8), 0)
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestWriteAtRejectsInvalidCount(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		writeReq := smb2.WriteRequestDecoder(req[64:])
		sendTestResponse(dt, req, &smb2.WriteResponse{Count: writeReq.Length() + 1}, 0)
	}()

	n, err := f.WriteAt(make([]byte, 8), 0)
	require.Error(t, err)
	require.LessOrEqual(t, n, 8)
}

func TestFileWriteAtShortWriteReturnsErrShortWrite(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		writeReq := smb2.WriteRequestDecoder(req[64:])
		sendTestResponse(dt, req, &smb2.WriteResponse{Count: writeReq.Length() - 1}, 0)
	}()

	n, err := f.WriteAt(make([]byte, 8), 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, io.ErrShortWrite), "expected io.ErrShortWrite, got %v", err)
	require.Equal(t, 7, n)
}

func TestReadAtRejectsOffsetOverflow(t *testing.T) {
	f, serverConn := newTestFile(t)
	go func() {
		dt := direct(serverConn)
		for range 2 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			readReq := smb2.ReadRequestDecoder(req[64:])
			sendTestResponse(dt, req, &smb2.ReadResponse{Data: make([]byte, readReq.Length())}, 0)
		}
	}()

	buf := make([]byte, f.fs.maxReadSize(0)+1)
	_, err := f.ReadAt(buf, math.MaxInt64-1)
	require.Error(t, err)
}

func TestReadFrom_NegativeBytesWrittenOnCopyFileErr(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	startFullFakeServer(serverConn, nil, func(callId *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		ctlCode := smb2.IoctlRequestDecoder(reqData).CtlCode()

		if ctlCode == smb2.FSCTL_SRV_REQUEST_RESUME_KEY {
			eres := &smb2.ErrorResponse{CommandCode: smb2.SMB2_IOCTL}
			resBuf := make([]byte, eres.Size())
			eres.Encode(resBuf)
			rp := smb2.PacketCodec(resBuf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(0xC0000001) // STATUS_UNSUCCESSFUL
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(resBuf)
			return true
		}
		return false
	}, nil)

	srcFile := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "src.txt")
	dstFile := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "dst.txt")

	n, err := dstFile.ReadFrom(srcFile)
	require.Error(t, err)

	if n < 0 {
		t.Fatalf("BUG CONFIRMED: File.ReadFrom returned negative bytes read n=%d on copyFile error!", n)
	}
}

// acceptedBindAck returns one NDR v2 acceptance with an empty secondary address.
func acceptedBindAck(callId uint32) []byte {
	ack := []byte{
		5, 0, 12, 3, 0x10, 0, 0, 0,
		56, 0, 0, 0, 0, 0, 0, 0,
		0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		2, 0, 0, 0,
	}
	le.PutUint32(ack[12:16], callId)
	return ack
}

func TestListSharenames_BindAck(t *testing.T) {
	for _, tt := range []struct {
		name      string
		modify    func([]byte) []byte
		wantError string
	}{
		{name: "accepted"},
		{name: "header only", modify: func(b []byte) []byte { b[8] = 24; return b[:24] }, wantError: "broken bind ack response format"},
		{name: "length mismatch", modify: func(b []byte) []byte { b[8]--; return b }, wantError: "broken bind ack response format"},
		{name: "secondary address out of bounds", modify: func(b []byte) []byte { le.PutUint16(b[24:26], 0xffff); return b }, wantError: "broken bind ack response format"},
		{name: "incomplete results", modify: func(b []byte) []byte { b[8]--; return b[:55] }, wantError: "broken bind ack response format"},
		{name: "wrong call ID", modify: func(b []byte) []byte { le.PutUint32(b[12:16], le.Uint32(b[12:16])+1); return b }, wantError: "broken bind ack response format"},
		{name: "user rejection", modify: func(b []byte) []byte { b[32] = 1; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "provider rejection", modify: func(b []byte) []byte { b[32] = 2; b[34] = 2; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "zero results", modify: func(b []byte) []byte { b[28] = 0; b[8] = 32; return b[:32] }, wantError: "bind ack did not accept NDR v2"},
		{name: "two results", modify: func(b []byte) []byte { b[28] = 2; b[8] = 80; return append(b, b[32:56]...) }, wantError: "bind ack did not accept NDR v2"},
		{name: "different UUID", modify: func(b []byte) []byte { b[36]++; return b }, wantError: "bind ack did not accept NDR v2"},
		{name: "different version", modify: func(b []byte) []byte { b[52]++; return b }, wantError: "bind ack did not accept NDR v2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			c := &conn{
				t:                   direct(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			s := &Session{s: c.session, ctx: ctx, addr: "testserver"}
			go c.runReceiver()

			var ioctlCount atomic.Int32
			var bindCallId uint32
			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt transport) bool {
				ioctlCount.Add(1)
				req := smb2.IoctlRequestDecoder(reqBuf[64:])
				input := reqBuf[req.InputOffset() : req.InputOffset()+req.InputCount()]
				var output []byte
				if input[2] == msrpc.RPC_TYPE_BIND {
					bindCallId = le.Uint32(input[12:16])
					output = acceptedBindAck(bindCallId)
					if tt.modify != nil {
						output = tt.modify(output)
					}
				} else {
					// A complete successful level 1 response with no shares.
					output = make([]byte, 56)
					output[0] = msrpc.RPC_VERSION
					output[2] = msrpc.RPC_TYPE_RESPONSE
					output[3] = msrpc.RPC_PACKET_FLAG_FIRST | msrpc.RPC_PACKET_FLAG_LAST
					output[4] = 0x10
					le.PutUint16(output[8:10], uint16(len(output)))
					le.PutUint32(output[12:16], bindCallId+1)
					le.PutUint32(output[24:28], 1)       // level
					le.PutUint32(output[28:32], 1)       // switch
					le.PutUint32(output[32:36], 0x20004) // container pointer
				}
				sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
					Output:  rawEncoder(output),
				}, 0)
				return true
			}, nil)

			names, err := s.ListSharenames()
			if tt.wantError == "" {
				require.NoError(t, err)
				require.Empty(t, names)
				require.Equal(t, int32(2), ioctlCount.Load())
			} else {
				var pathErr *os.PathError
				require.ErrorAs(t, err, &pathErr)
				require.Equal(t, "listShareNames", pathErr.Op)
				require.Equal(t, "srvsvc", pathErr.Path)
				var invalidRespErr *InvalidResponseError
				require.ErrorAs(t, pathErr.Err, &invalidRespErr)
				require.Equal(t, "invalid response error: "+tt.wantError, invalidRespErr.Error())
				require.Equal(t, int32(1), ioctlCount.Load())
			}
			// Deferred CLOSE and Umount have completed; the shared connection
			// must still service a new request after either bind outcome.
			fs, err := s.Mount("IPC$")
			require.NoError(t, err)
			require.NoError(t, fs.Umount())
		})
	}
}

func TestListSharenames_RejectsExcessiveResponseSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 300 // 300 * ~4KB > 1MB

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment read: level 1, large count (incomplete)
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Subsequent incomplete fragments
						frag = make([]byte, 4000)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4000)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	_, err := s.listShareNames(s.serverName(), clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Less(t, readCount, maxReads)
}

func TestListSharenames_MaxShareResponseSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment: PFC_FIRST_FRAG (0x01)
						// Its 65-byte stub already exceeds the 64-byte limit.
						frag = make([]byte, 89)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 1 // PFC_FIRST_FRAG
						le.PutUint16(frag[8:10], 89)
						le.PutUint32(frag[12:16], rpcCallId)
					} else if readCount == 2 {
						// Second fragment: PFC_LAST_FRAG (0x02)
						frag = make([]byte, 128)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 2 // PFC_LAST_FRAG
						le.PutUint16(frag[8:10], 128)
						le.PutUint32(frag[12:16], rpcCallId)
					} else {
						serverConn.Close()
						return
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	// The first fragment's 65-byte Stub exceeds the low limit and must be
	// rejected before the client reads another RPC fragment.
	_, err := s.listShareNames(s.serverName(), 64)
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Equal(t, "invalid response error: net share enum response exceeds maximum size", invalidRespErr.Error())
	require.Equal(t, 1, readCount)
}

func TestListSharenames_MaxShareResponseSizeBoundaries(t *testing.T) {
	enc := msrpc.NewEncoder()
	// Level 1, one container entry, and one disk share with no remark.
	for _, v := range []uint32{
		1, 1, 1, // Level, discriminant, container pointer.
		1, 1, 1, // EntriesRead, buffer pointer, array count.
		1, 0, 0, // Name pointer, share type, remark pointer.
	} {
		enc.WriteUint32(v)
	}
	enc.WriteConformantVaryingString("SHARE1")
	for _, v := range []uint32{1, 0, 0} { // TotalEntries, NULL ResumeHandle, success.
		enc.WriteUint32(v)
	}
	stub := enc.Bytes()
	names, err := msrpc.NetShareEnumAllResponseDecoder(stub).Sharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)

	for _, tt := range []struct {
		name       string
		overflow   bool
		split      bool
		invalidNDR bool
		limit      int
		wantError  bool
	}{
		{name: "single exceeds", limit: len(stub) - 1, wantError: true},
		{name: "single equals", limit: len(stub)},
		{name: "unlimited", limit: -1},
		{name: "single invalid NDR exceeds", invalidNDR: true, limit: len(stub) - 1, wantError: true},
		{name: "overflow first last exceeds", overflow: true, limit: len(stub) - 1, wantError: true},
		{name: "overflow first last equals", overflow: true, limit: len(stub)},
		{name: "multiple equals", overflow: true, split: true, limit: len(stub)},
		{name: "multiple cumulative exceeds", overflow: true, split: true, limit: len(stub) - 1, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c := &conn{
				t:                   direct(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			s := &Session{
				s:    c.session,
				ctx:  ctx,
				addr: "testserver",
			}

			go c.runReceiver()

			startFullFakeServer(serverConn, nil, func(_ *uint32, _ uint64, reqBuf []byte, dt transport) bool {
				iReq := smb2.IoctlRequestDecoder(reqBuf[64:])
				input := reqBuf[iReq.InputOffset() : iReq.InputOffset()+iReq.InputCount()]

				if input[2] == msrpc.RPC_TYPE_BIND {
					bindAck := acceptedBindAck(le.Uint32(input[12:16]))
					sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
						CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
						Output:  rawEncoder(bindAck),
					}, 0)
					return true
				}

				responseStub := append([]byte(nil), stub...)
				if tt.invalidNDR {
					le.PutUint32(responseStub, 99) // Unsupported NDR level.
				}
				chunks := [][]byte{responseStub}
				if tt.split {
					chunks = [][]byte{responseStub[:len(stub)/2], responseStub[len(stub)/2:]}
				}
				var response []byte
				for i, chunk := range chunks {
					fragment := make([]byte, msrpc.HeaderSize+len(chunk))
					fragment[0] = msrpc.RPC_VERSION
					fragment[2] = msrpc.RPC_TYPE_RESPONSE
					if i == 0 {
						fragment[3] |= msrpc.RPC_PACKET_FLAG_FIRST
					}
					if i == len(chunks)-1 {
						fragment[3] |= msrpc.RPC_PACKET_FLAG_LAST
					}
					le.PutUint16(fragment[8:10], uint16(len(fragment)))
					copy(fragment[12:16], input[12:16])
					copy(fragment[msrpc.HeaderSize:], chunk)
					response = append(response, fragment...)
				}
				var status uint32
				if tt.overflow {
					status = uint32(erref.STATUS_BUFFER_OVERFLOW)
				}
				sendTestResponse(dt, reqBuf, &smb2.IoctlResponse{
					CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
					Output:  rawEncoder(response),
				}, status)
				return true
			}, nil)

			names, err := s.listShareNames(s.serverName(), tt.limit)
			if !tt.wantError {
				require.NoError(t, err)
				require.Equal(t, []string{"SHARE1"}, names)
				return
			}
			require.Error(t, err)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			var invalidRespErr *InvalidResponseError
			require.ErrorAs(t, pathErr.Err, &invalidRespErr)
			require.Equal(t, "invalid response error: net share enum response exceeds maximum size", invalidRespErr.Error())
		})
	}
}

func TestListSharenames_RejectsEmptyFragment(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int
	const maxReads = 10

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						frag = make([]byte, 4280)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 4280)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)      // level 1
						le.PutUint32(frag[36:40], 100000) // large count makes it incomplete
					} else {
						if readCount > maxReads {
							serverConn.Close()
							return
						}
						// Return empty fragment (header only: 24 bytes, Buffer() is 0 bytes)
						frag = make([]byte, 24)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						le.PutUint16(frag[8:10], 24)
						le.PutUint32(frag[12:16], rpcCallId)
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	_, err := s.ListSharenames()
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Equal(t, 2, readCount)
}

func TestListSharenames_TerminatesOnLastFrag(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var frag []byte
					if readCount == 1 {
						// First fragment: PFC_FIRST_FRAG (0x01)
						frag = make([]byte, 60)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 1 // PFC_FIRST_FRAG
						le.PutUint16(frag[8:10], 60)
						le.PutUint32(frag[12:16], rpcCallId)
						le.PutUint32(frag[24:28], 1)       // level 1
						le.PutUint32(frag[28:32], 1)       // CTR pointer
						le.PutUint32(frag[32:36], 0x20004) // Referent ID
						le.PutUint32(frag[36:40], 1)       // Count = 1
						le.PutUint32(frag[40:44], 0x20008) // Array pointer
						le.PutUint32(frag[44:48], 1)       // Array MaxCount = 1
						le.PutUint32(frag[48:52], 0x2000c) // Name pointer
						le.PutUint32(frag[52:56], 0)       // Type
						le.PutUint32(frag[56:60], 0x20010) // Comment pointer
					} else if readCount == 2 {
						// Second fragment: PFC_LAST_FRAG (0x02) containing deferred name
						nameBytes := utf16le.EncodeStringToBytes("SHARE1")
						nameCount := uint32(len(nameBytes)/2 + 1)
						commentBytes := utf16le.EncodeStringToBytes("")
						commentCount := uint32(1)

						frag = make([]byte, 128)
						frag[0] = 5 // RPC_VERSION
						frag[1] = 0 // RPC_VERSION_MINOR
						frag[2] = 2 // RPC_TYPE_RESPONSE
						frag[3] = 2 // PFC_LAST_FRAG
						le.PutUint32(frag[12:16], rpcCallId)

						off := 24
						// Name deferred
						le.PutUint32(frag[off:off+4], nameCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], nameCount)
						copy(frag[off+12:], nameBytes)
						off = (off + 12 + int(nameCount*2) + 3) &^ 3

						// Comment deferred
						le.PutUint32(frag[off:off+4], commentCount)
						le.PutUint32(frag[off+4:off+8], 0)
						le.PutUint32(frag[off+8:off+12], commentCount)
						copy(frag[off+12:], commentBytes)
						off = (off + 12 + int(commentCount*2) + 3) &^ 3
						le.PutUint32(frag[off:off+4], 1) // TotalEntries
						off += 4
						le.PutUint32(frag[off:off+4], 0) // ResumeHandle (NULL)
						off += 4
						le.PutUint32(frag[off:off+4], 0) // ReturnStatus (NERR_Success)
						off += 4

						frag = frag[:off]
						le.PutUint16(frag[8:10], uint16(off))
					} else {
						// Should not reach here if PFC_LAST_FRAG terminates
						serverConn.Close()
						return
					}
					rres := &smb2.ReadResponse{
						Data: frag,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestListSharenames_StatusSuccessFirstFragment(t *testing.T) {
	enc := msrpc.NewEncoder()
	for _, v := range []uint32{
		1, 1, 1, // Level, discriminant, container pointer.
		1, 1, 1, // EntriesRead, buffer pointer, array count.
		1, 0, 0, // Name pointer, share type, remark pointer.
	} {
		enc.WriteUint32(v)
	}
	enc.WriteConformantVaryingString("SHARE1")
	for _, v := range []uint32{1, 0, 0} { // TotalEntries, NULL ResumeHandle, success.
		enc.WriteUint32(v)
	}
	stub := enc.Bytes()

	makeFragment := func(flags uint8, chunk []byte) []byte {
		fragment := make([]byte, msrpc.HeaderSize+len(chunk))
		fragment[0] = msrpc.RPC_VERSION
		fragment[2] = msrpc.RPC_TYPE_RESPONSE
		fragment[3] = flags
		le.PutUint16(fragment[8:10], uint16(len(fragment)))
		copy(fragment[msrpc.HeaderSize:], chunk)
		return fragment
	}

	for _, tt := range []struct {
		name      string
		first     []byte
		readFrags [][]byte
		readCount int
	}{
		{
			name:      "single fragment",
			first:     makeFragment(msrpc.RPC_PACKET_FLAG_FIRST|msrpc.RPC_PACKET_FLAG_LAST, stub),
			readCount: 0,
		},
		{
			name:      "success first fragment followed by read",
			first:     makeFragment(msrpc.RPC_PACKET_FLAG_FIRST, stub[:len(stub)/2]),
			readFrags: [][]byte{makeFragment(msrpc.RPC_PACKET_FLAG_LAST, stub[len(stub)/2:])},
			readCount: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			c := &conn{
				t:                   direct(clientConn),
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(100),
				maxReadSize:         64 * 1024,
				maxWriteSize:        64 * 1024,
				maxTransactSize:     64 * 1024,
			}
			c.account.charge(100)
			c.session = &session{conn: c, sessionId: 0x100}
			c.enableSession()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			s := &Session{s: c.session, ctx: ctx, addr: "testserver"}

			go c.runReceiver()
			var readCount int
			go func() {
				dt := direct(serverConn)
				var callID uint32
				for {
					reqBuf, err := readMsg(dt)
					if err != nil {
						return
					}
					var responseBufs [][]byte
					currBuf := reqBuf
					for {
						p := smb2.PacketCodec(currBuf)
						var response smb2.Packet
						var status uint32

						switch p.Command() {
						case smb2.SMB2_TREE_CONNECT:
							response = &smb2.TreeConnectResponse{ShareType: smb2.SMB2_SHARE_TYPE_PIPE}
						case smb2.SMB2_CREATE:
							response = &smb2.CreateResponse{
								CreationTime:   &smb2.Filetime{},
								LastAccessTime: &smb2.Filetime{},
								LastWriteTime:  &smb2.Filetime{},
								ChangeTime:     &smb2.Filetime{},
								FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
							}
						case smb2.SMB2_CLOSE:
							response = &smb2.CloseResponse{
								CreationTime:   &smb2.Filetime{},
								LastAccessTime: &smb2.Filetime{},
								LastWriteTime:  &smb2.Filetime{},
								ChangeTime:     &smb2.Filetime{},
							}
						case smb2.SMB2_TREE_DISCONNECT:
							response = &smb2.TreeDisconnectResponse{}
						case smb2.SMB2_IOCTL:
							iReq := smb2.IoctlRequestDecoder(currBuf[64:])
							input := currBuf[int(iReq.InputOffset()):int(iReq.InputOffset()+iReq.InputCount())]
							callID = le.Uint32(input[12:16])
							if input[2] == msrpc.RPC_TYPE_BIND {
								bindAck := acceptedBindAck(callID)
								response = &smb2.IoctlResponse{
									CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
									Output:  rawEncoder(bindAck),
								}
							} else {
								first := append([]byte(nil), tt.first...)
								le.PutUint32(first[12:16], callID)
								response = &smb2.IoctlResponse{
									CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
									Output:  rawEncoder(first),
								}
							}
						case smb2.SMB2_READ:
							if readCount >= len(tt.readFrags) {
								serverConn.Close()
								return
							}
							fragment := append([]byte(nil), tt.readFrags[readCount]...)
							readCount++
							le.PutUint32(fragment[12:16], callID)
							response = &smb2.ReadResponse{Data: fragment}
						}

						if response != nil {
							resBuf := make([]byte, response.Size())
							response.Encode(resBuf)
							rp := smb2.PacketCodec(resBuf)
							rp.SetMessageId(p.MessageId())
							rp.SetSessionId(p.SessionId())
							rp.SetTreeId(p.TreeId())
							rp.SetStatus(status)
							rp.SetCreditResponse(1)
							rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
							responseBufs = append(responseBufs, resBuf)
						}

						if p.NextCommand() == 0 {
							break
						}
						currBuf = currBuf[p.NextCommand():]
					}

					if len(responseBufs) > 0 {
						var finalBuf []byte
						for i, rb := range responseBufs {
							if i < len(responseBufs)-1 {
								pad := (8 - (len(rb) % 8)) % 8
								nextCmd := uint32(len(rb) + pad)
								padded := make([]byte, nextCmd)
								copy(padded, rb)
								smb2.PacketCodec(padded).SetNextCommand(nextCmd)
								finalBuf = append(finalBuf, padded...)
							} else {
								finalBuf = append(finalBuf, rb...)
							}
						}
						dt.Writev(finalBuf)
					}
				}
			}()

			names, err := s.ListSharenames()
			require.NoError(t, err)
			require.Equal(t, []string{"SHARE1"}, names)
			require.Equal(t, tt.readCount, readCount)
		})
	}
}

func TestListSharenames_HandlesShortRead(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}

				case smb2.SMB2_READ:
					readCount++
					// Build PDU 1 (60 bytes)
					pdu1 := make([]byte, 60)
					pdu1[0] = 5                  // RPC_VERSION
					pdu1[1] = 0                  // RPC_VERSION_MINOR
					pdu1[2] = 2                  // RPC_TYPE_RESPONSE
					pdu1[3] = 1                  // PFC_FIRST_FRAG
					le.PutUint16(pdu1[8:10], 60) // FragLength = 60
					le.PutUint32(pdu1[12:16], rpcCallId)
					le.PutUint32(pdu1[24:28], 1)       // level 1
					le.PutUint32(pdu1[28:32], 1)       // CTR pointer
					le.PutUint32(pdu1[32:36], 0x20004) // Referent ID
					le.PutUint32(pdu1[36:40], 1)       // Count = 1
					le.PutUint32(pdu1[40:44], 0x20008) // Array pointer
					le.PutUint32(pdu1[44:48], 1)       // Array MaxCount = 1
					le.PutUint32(pdu1[48:52], 0x2000c) // Name pointer
					le.PutUint32(pdu1[52:56], 0)       // Type
					le.PutUint32(pdu1[56:60], 0x20010) // Comment pointer

					// Build PDU 2 (72 bytes)
					nameBytes := utf16le.EncodeStringToBytes("SHARE1")
					nameCount := uint32(len(nameBytes)/2 + 1)
					commentBytes := utf16le.EncodeStringToBytes("")
					commentCount := uint32(1)

					pdu2 := make([]byte, 128)
					pdu2[0] = 5 // RPC_VERSION
					pdu2[1] = 0 // RPC_VERSION_MINOR
					pdu2[2] = 2 // RPC_TYPE_RESPONSE
					pdu2[3] = 2 // PFC_LAST_FRAG
					le.PutUint32(pdu2[12:16], rpcCallId)

					off := 24
					le.PutUint32(pdu2[off:off+4], nameCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], nameCount)
					copy(pdu2[off+12:], nameBytes)
					off = (off + 12 + int(nameCount*2) + 3) &^ 3

					le.PutUint32(pdu2[off:off+4], commentCount)
					le.PutUint32(pdu2[off+4:off+8], 0)
					le.PutUint32(pdu2[off+8:off+12], commentCount)
					copy(pdu2[off+12:], commentBytes)
					off = (off + 12 + int(commentCount*2) + 3) &^ 3
					le.PutUint32(pdu2[off:off+4], 1) // TotalEntries
					off += 4
					le.PutUint32(pdu2[off:off+4], 0) // ResumeHandle (NULL)
					off += 4
					le.PutUint32(pdu2[off:off+4], 0) // ReturnStatus (NERR_Success)
					off += 4
					pdu2 = pdu2[:off]
					le.PutUint16(pdu2[8:10], uint16(len(pdu2))) // FragLength

					stream := append(pdu1, pdu2...)
					// Chunks to serve: 20, 4 (completes pdu1 header), 36 (completes pdu1 stub), 24 (pdu2 header), 48 (pdu2 stub)
					chunkSizes := []int{20, 4, 36, 24, len(pdu2) - 24}
					if readCount > len(chunkSizes) {
						serverConn.Close()
						return
					}

					chunkOffset := 0
					for i := 0; i < readCount-1; i++ {
						chunkOffset += chunkSizes[i]
					}
					fragData := stream[chunkOffset : chunkOffset+chunkSizes[readCount-1]]

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 5, readCount)
}

func TestListSharenames_HandlesResidualData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	var rpcCallId uint32
	var readCount int

	go func() {
		dt := direct(serverConn)
		var frag1, frag2 []byte

		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId = le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns STATUS_BUFFER_OVERFLOW
							rpcCallId = le.Uint32(in[12:16])
							status = 0x80000005 // STATUS_BUFFER_OVERFLOW
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)

							// Prepare frag1 and frag2
							frag1 = make([]byte, 60)
							frag1[0] = 5 // RPC_VERSION
							frag1[1] = 0 // RPC_VERSION_MINOR
							frag1[2] = 2 // RPC_TYPE_RESPONSE
							frag1[3] = 1 // PFC_FIRST_FRAG
							le.PutUint16(frag1[8:10], 60)
							le.PutUint32(frag1[12:16], rpcCallId)
							le.PutUint32(frag1[24:28], 1)       // level 1
							le.PutUint32(frag1[28:32], 1)       // CTR pointer
							le.PutUint32(frag1[32:36], 0x20004) // Referent ID
							le.PutUint32(frag1[36:40], 1)       // Count = 1
							le.PutUint32(frag1[40:44], 0x20008) // Array pointer
							le.PutUint32(frag1[44:48], 1)       // Array MaxCount = 1
							le.PutUint32(frag1[48:52], 0x2000c) // Name pointer
							le.PutUint32(frag1[52:56], 0)       // Type
							le.PutUint32(frag1[56:60], 0x20010) // Comment pointer

							nameBytes := utf16le.EncodeStringToBytes("SHARE1")
							nameCount := uint32(len(nameBytes)/2 + 1)
							commentBytes := utf16le.EncodeStringToBytes("")
							commentCount := uint32(1)

							frag2 = make([]byte, 128)
							frag2[0] = 5 // RPC_VERSION
							frag2[1] = 0 // RPC_VERSION_MINOR
							frag2[2] = 2 // RPC_TYPE_RESPONSE
							frag2[3] = 2 // PFC_LAST_FRAG
							le.PutUint32(frag2[12:16], rpcCallId)

							off := 24
							le.PutUint32(frag2[off:off+4], nameCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], nameCount)
							copy(frag2[off+12:], nameBytes)
							off = (off + 12 + int(nameCount*2) + 3) &^ 3

							le.PutUint32(frag2[off:off+4], commentCount)
							le.PutUint32(frag2[off+4:off+8], 0)
							le.PutUint32(frag2[off+8:off+12], commentCount)
							copy(frag2[off+12:], commentBytes)
							off = (off + 12 + int(commentCount*2) + 3) &^ 3
							le.PutUint32(frag2[off:off+4], 1) // TotalEntries
							off += 4
							le.PutUint32(frag2[off:off+4], 0) // ResumeHandle (NULL)
							off += 4
							le.PutUint32(frag2[off:off+4], 0) // ReturnStatus (NERR_Success)
							off += 4

							frag2 = frag2[:off]
							le.PutUint16(frag2[8:10], uint16(off))
						}
					}

				case smb2.SMB2_READ:
					readCount++
					var fragData []byte
					if readCount == 1 {
						// Return frag1 + first 30 bytes of frag2 (overflowing frag1)
						fragData = append(append([]byte(nil), frag1...), frag2[:30]...)
					} else if readCount == 2 {
						// Return remainder of frag2
						fragData = frag2[30:]
					}

					rres := &smb2.ReadResponse{
						Data: fragData,
					}
					resBuf = make([]byte, rres.Size())
					rres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	names, err := s.ListSharenames()
	require.NoError(t, err)
	require.Equal(t, []string{"SHARE1"}, names)
	require.Equal(t, 2, readCount)
}

func TestListSharenames_IncompleteResponse(t *testing.T) {
	// Craft a level 1 NetShareEnumAll response that advertises one share
	// entry but truncates the buffer before the share name data:
	// IsInvalid() is false, but ShareNames() fails.
	frag := make([]byte, 84)
	frag[0] = msrpc.RPC_VERSION
	frag[1] = msrpc.RPC_VERSION_MINOR
	frag[2] = msrpc.RPC_TYPE_RESPONSE
	frag[3] = msrpc.RPC_PACKET_FLAG_LAST
	le.PutUint16(frag[8:10], 84)   // frag length
	le.PutUint32(frag[12:16], 123) // call id (patched later)
	le.PutUint32(frag[24:28], 1)   // level 1
	le.PutUint32(frag[36:40], 1)   // count = 1
	le.PutUint32(frag[48:52], 1)   // name ptr
	le.PutUint32(frag[64:68], 0)   // name offset
	le.PutUint32(frag[68:72], 10)  // name max count (10 -> 20 bytes)

	enumResp := msrpc.NetShareEnumAllResponseDecoder(frag[msrpc.HeaderSize:])
	require.False(t, msrpc.ResponseFragmentDecoder(frag).IsInvalid(), "fixture must be a valid response PDU")
	_, decodeErr := enumResp.Sharenames()
	require.Error(t, decodeErr, "fixture must fail to decode incomplete response PDU")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				var status uint32

				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId := le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						} else {
							// NetShareEnumAllRequest returns a complete (LAST flag set)
							// response whose buffer is truncated mid share entry.
							rpcCallId := le.Uint32(in[12:16])
							le.PutUint32(frag[12:16], rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(frag),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(status)
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	_, err := s.ListSharenames()
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
	require.Contains(t, invalidRespErr.Error(), "broken net share enum response format")
}

func TestListSharenames_RejectsDataOutsideFragment(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := &Session{s: c.session, ctx: ctx, addr: "testserver"}

	go c.runReceiver()
	startFullFakeServer(serverConn, nil, func(_ *uint32, msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		reqData := reqBuf[64:]
		if smb2.IoctlRequestDecoder(reqData).CtlCode() != smb2.FSCTL_PIPE_TRANSCEIVE {
			return false
		}
		in := reqBuf[smb2.IoctlRequestDecoder(reqData).InputOffset():]
		if len(in) < 16 {
			return false
		}
		callId := le.Uint32(in[12:16])

		var output []byte
		if in[2] == msrpc.RPC_TYPE_BIND {
			output = acceptedBindAck(callId)
		} else {
			// The declared fragment ends after TotalEntries. ResumeHandle and
			// ReturnStatus are outside the fragment boundary.
			output = make([]byte, 56)
			output[0] = msrpc.RPC_VERSION
			output[1] = msrpc.RPC_VERSION_MINOR
			output[2] = msrpc.RPC_TYPE_RESPONSE
			output[3] = msrpc.RPC_PACKET_FLAG_FIRST | msrpc.RPC_PACKET_FLAG_LAST
			le.PutUint16(output[8:10], 48)
			le.PutUint32(output[12:16], callId)
			le.PutUint32(output[24:28], 1)       // Level
			le.PutUint32(output[28:32], 1)       // switch
			le.PutUint32(output[32:36], 0x20004) // container pointer
			le.PutUint32(output[36:40], 0)       // EntriesRead
			le.PutUint32(output[40:44], 0)       // Buffer (NULL)
			le.PutUint32(output[44:48], 0)       // TotalEntries
			le.PutUint32(output[48:52], 0)       // ResumeHandle (outside fragment)
			le.PutUint32(output[52:56], 0)       // ReturnStatus (outside fragment)
		}

		iores := &smb2.IoctlResponse{
			CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
			Output:  rawEncoder(output),
		}
		resBuf := make([]byte, iores.Size())
		iores.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		dt.Writev(resBuf)
		if in[2] != msrpc.RPC_TYPE_BIND {
			// The malformed response is expected to make ListSharenames return
			// before the fake server needs to service the deferred unmount.
			serverConn.Close()
		}
		return true
	}, nil)

	_, err := s.ListSharenames()
	require.Error(t, err)
	var pathErr *os.PathError
	require.True(t, errors.As(err, &pathErr))
	var invalidRespErr *InvalidResponseError
	require.True(t, errors.As(pathErr.Err, &invalidRespErr))
}

func TestFile_ConcurrentClose(t *testing.T) {
	f, serverConn := newTestFile(t)
	dt := direct(serverConn)

	var closeRequests atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(reqBuf)
			if p.Command() == smb2.SMB2_CLOSE {
				closeRequests.Add(1)
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				sendTestResponse(dt, reqBuf, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	start := make(chan struct{})
	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = f.Close()
		}(i)
	}

	close(start)
	wg.Wait()

	var successCount, closedErrCount int
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, os.ErrClosed) {
			closedErrCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	require.Equal(t, 1, successCount, "exactly one Close() should succeed")
	require.Equal(t, concurrency-1, closedErrCount, "remaining Close() calls should return os.ErrClosed")
	require.Equal(t, int32(1), closeRequests.Load(), "server should receive exactly one SMB2_CLOSE request")
}

func TestFileCloseRetriesAfterFailure(t *testing.T) {
	require := require.New(t)

	f, serverConn := newTestFile(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.fs.ctx = ctx

	err := f.Close()
	require.Error(err)
	require.False(f.closed.Load())

	f.fs.ctx = context.Background()
	dt := direct(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, req, &smb2.CloseResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}, uint32(erref.STATUS_SUCCESS))
	}()

	require.NoError(f.Close())
	<-done
}

func TestFile_Readdir_NoSliceAliasing(t *testing.T) {
	entry1 := &FileStat{FileName: "file1.txt"}
	entry2 := &FileStat{FileName: "file2.txt"}
	entry3 := &FileStat{FileName: "file3.txt"}

	f := &File{
		fd:          &smb2.FileId{},
		noMoreFiles: true,
		dirents:     []os.FileInfo{entry1, entry2, entry3},
	}

	first, err := f.Readdir(1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "file1.txt", first[0].Name())

	// If capacity is not restricted with 3-index slicing, append would overwrite entry2 in f.dirents
	bogus := &FileStat{FileName: "corrupted.txt"}
	_ = append(first, bogus)

	second, err := f.Readdir(1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "file2.txt", second[0].Name())
}

func newTestShare(t *testing.T) (*Share, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(func() {
		cleanup()
		serverConn.Close()
	})

	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}
	return fs, serverConn
}

func sendTestCompoundErrorResponse(dt transport, req []byte, status uint32) {
	p := smb2.PacketCodec(req)
	baseMsgId := p.MessageId()

	var parts [][]byte
	for i := range 3 {
		errPkt := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_CREATE,
		}
		resBuf := make([]byte, errPkt.Size())
		errPkt.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(baseMsgId + uint64(i))
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		if i == 0 {
			rp.SetStatus(status)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		} else {
			rp.SetStatus(uint32(erref.STATUS_INVALID_PARAMETER))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		}
		parts = append(parts, resBuf)
	}

	var compound []byte
	for i, part := range parts {
		if i < len(parts)-1 {
			pad := (8 - (len(part) % 8)) % 8
			next := uint32(len(part) + pad)
			padded := make([]byte, next)
			copy(padded, part)
			smb2.PacketCodec(padded).SetNextCommand(next)
			compound = append(compound, padded...)
		} else {
			smb2.PacketCodec(part).SetCreditResponse(1)
			compound = append(compound, part...)
		}
	}
	_, _ = dt.Writev(compound)
}

func TestShare_Remove_NoFallbackOnNonAccessError(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			requestCount.Add(1)
			// Return STATUS_OBJECT_NAME_NOT_FOUND on the first request
			sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
		}
	}()

	err := fs.Remove("nonexistent.txt")
	require.Error(t, err)

	// Must NOT attempt fallback chmod; requestCount must be exactly 1
	require.Equal(t, int32(1), requestCount.Load(), "should not trigger chmod fallback on STATUS_OBJECT_NAME_NOT_FOUND")
}

func TestShareOpenFileRejectsNegativeCreateEndofFileAndKeepsConnection(t *testing.T) {
	fs, serverConn := newTestShare(t)
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(5*time.Second)))
	dt := direct(serverConn)

	commands := make(chan smb2.Command, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(commands)
		for i := range 3 {
			req, err := readMsg(dt)
			if err != nil {
				return
			}

			commands <- smb2.PacketCodec(req).Command()

			switch i {
			case 0, 1:
				endofFile := int64(4096)
				if i == 0 {
					endofFile = -1
				}
				res := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					EndofFile:      endofFile,
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			case 2:
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
			}
		}
	}()

	file, err := fs.OpenFile("negative.txt", os.O_WRONLY|os.O_APPEND, 0)
	var invalidResponseErr *InvalidResponseError
	require.Nil(t, file)
	require.ErrorAs(t, err, &invalidResponseErr)

	file, err = fs.OpenFile("normal.txt", os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4096), file.offset)
	require.NoError(t, file.Close())

	<-done
	var gotCommands []smb2.Command
	for command := range commands {
		gotCommands = append(gotCommands, command)
	}
	require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CREATE, smb2.SMB2_CLOSE}, gotCommands)
}

func sendTestCompoundSuccessResponse(dt transport, req []byte) {
	createRes := &smb2.CreateResponse{
		FileId:         &smb2.FileId{},
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	setInfoRes := &smb2.SetInfoResponse{}
	closeRes := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)
	resBuf2 := make([]byte, setInfoRes.Size())
	setInfoRes.Encode(resBuf2)
	resBuf3 := make([]byte, closeRes.Size())
	closeRes.Encode(resBuf3)

	p := smb2.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	smb2.PacketCodec(padded1).SetMessageId(p.MessageId())
	smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	smb2.PacketCodec(padded1).SetNextCommand(next1)

	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	smb2.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	smb2.PacketCodec(padded2).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded2).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded2).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(padded2).SetNextCommand(next2)

	smb2.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	smb2.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	smb2.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	smb2.PacketCodec(resBuf3).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(resBuf3).SetCreditResponse(1)

	compound := append(padded1, padded2...)
	compound = append(compound, resBuf3...)
	_, _ = dt.Writev(compound)
}

func sendTestCloseResponse(dt transport, req []byte) {
	res := &smb2.CloseResponse{
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	sendTestResponse(dt, req, res, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_FallbackOnCannotDelete(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, smb2.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// Fourth request closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// Fifth request is retry remove (CREATE + SET_INFO + CLOSE compound)
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove("readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load(), "should perform remove, create, set attributes, close, then retry remove")
}

func TestShare_Remove_FallbackOnAccessDenied(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_ACCESS_DENIED
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_ACCESS_DENIED))
			case 2:
				// Second request is chmod 1st RTT (CREATE)
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, smb2.FILE_ATTRIBUTE_READONLY)
			case 3:
				// Third request is chmod 2nd RTT (SET_INFO kept separate from CLOSE)
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// Fourth request closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// Fifth request is retry remove
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove("readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load(), "should perform remove, create, set attributes, close, then retry remove")
}

func TestShare_Remove_PropagatesChmodFallbackError(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var requestCount atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// First remove attempt fails with STATUS_CANNOT_DELETE (read-only file)
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// Second request is chmod fallback CREATE,
				// which fails because the file is locked by another opener
				sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_SHARING_VIOLATION))
			}
		}
	}()

	err := fs.Remove("locked.txt")
	require.Error(t, err)

	// Should not retry remove after chmod fallback failure
	require.Equal(t, int32(2), requestCount.Load(), "should stop after chmod fallback failure")

	var pe *os.PathError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "remove", pe.Op)
	require.Equal(t, "locked.txt", pe.Path)
	// Must report the chmod failure, not the initial STATUS_CANNOT_DELETE error
	require.ErrorIs(t, pe.Err, erref.STATUS_SHARING_VIOLATION, "should propagate chmod fallback error")
}

func sendTestCreateAttributesResponse(dt transport, req []byte, fileId *smb2.FileId, fileAttributes uint32) {
	sendTestResponse(dt, req, &smb2.CreateResponse{
		FileId:         fileId,
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
		FileAttributes: fileAttributes,
	}, uint32(erref.STATUS_SUCCESS))
}

func TestShare_Remove_ReadonlyFallbackPreservesExistingAttributes(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	var (
		requestCount  atomic.Int32
		capturedAttrs atomic.Uint32
	)
	fileId := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
	const initialAttrs = smb2.FILE_ATTRIBUTE_READONLY | smb2.FILE_ATTRIBUTE_HIDDEN | smb2.FILE_ATTRIBUTE_SYSTEM

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}
			cnt := requestCount.Add(1)
			switch cnt {
			case 1:
				// 1st request: remove fails with STATUS_CANNOT_DELETE
				sendTestCompoundErrorResponse(dt, reqBuf, uint32(erref.STATUS_CANNOT_DELETE))
			case 2:
				// 2nd request: CREATE
				sendTestCreateAttributesResponse(dt, reqBuf, fileId, initialAttrs)
			case 3:
				// 3rd request: SET_INFO (kept separate from CLOSE)
				p := smb2.PacketCodec(reqBuf)
				if p.Command() == smb2.SMB2_SET_INFO {
					d := smb2.SetInfoRequestDecoder(p.Body())
					if !d.IsInvalid() && d.BufferLength() >= 40 {
						buf := p[d.BufferOffset() : d.BufferOffset()+uint16(d.BufferLength())]
						base := smb2.FileBasicInformationDecoder(buf)
						if !base.IsInvalid() {
							capturedAttrs.Store(base.FileAttributes())
						}
					}
				}
				sendTestResponse(dt, reqBuf, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case 4:
				// 4th request: closes the handle opened by chmod
				sendTestCloseResponse(dt, reqBuf)
			case 5:
				// 5th request: retry remove
				sendTestCompoundSuccessResponse(dt, reqBuf)
			}
		}
	}()

	err := fs.Remove("hidden_readonly.txt")
	require.NoError(t, err)
	require.Equal(t, int32(5), requestCount.Load())
	// computeChmodAttrs clears readonly, preserves hidden/system, and sets NORMAL for non-directories
	expectedAttrs := uint32(smb2.FILE_ATTRIBUTE_NORMAL | smb2.FILE_ATTRIBUTE_HIDDEN | smb2.FILE_ATTRIBUTE_SYSTEM)
	require.Equal(t, expectedAttrs, capturedAttrs.Load(), "fallback chmod must preserve existing attributes (hidden, system) while clearing readonly")
}

func TestDialClosesConnectionOnSessionSetupError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	st := direct(serverConn)

	go func() {
		// Round 1: server replies to Negotiate request with success
		buf, err := readMsg(st)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(buf)
		resp := &smb2.NegotiateResponse{
			PacketHeader: smb2.PacketHeader{
				Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId: p.MessageId(),
			},
			SecurityMode:    1,
			DialectRevision: smb2.SMB210,
			MaxTransactSize: 65536,
			MaxReadSize:     65536,
			MaxWriteSize:    65536,
			SystemTime:      &smb2.Filetime{},
			ServerStartTime: &smb2.Filetime{},
		}
		respBuf := make([]byte, resp.Size())
		resp.Encode(respBuf)
		smb2.PacketCodec(respBuf).SetCreditResponse(1)
		if _, err := st.Writev(respBuf); err != nil {
			return
		}

		// Round 2: read SessionSetup request then close serverConn to simulate network/auth failure
		if _, err := readMsg(st); err != nil {
			return
		}
		_ = serverConn.Close()
	}()

	d := &Dialer{
		Initiator: &NTLMInitiator{
			User:     "user",
			Password: "password",
		},
	}

	_, err := d.DialContext(context.Background(), clientConn)
	require.Error(t, err)

	// clientConn must be closed on sessionSetup failure
	readBuf := make([]byte, 1)
	_, readErr := clientConn.Read(readBuf)
	require.Error(t, readErr, "clientConn should be closed after failed sessionSetup")
}

func TestShare_MaxPayloadSizeCappedByCredits(t *testing.T) {
	c := &conn{
		account:         openAccount(4),
		capabilities:    smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	// Initially, maxCredits = 1 -> capped to 1 * 64KB = 64KB
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))

	// Replenish to 4 credits (maxCreditBalance) -> capped to 4 * 64KB = 256KB
	c.account.charge(3)
	require.Equal(t, 256*1024, fs.maxReadSize(0))
	require.Equal(t, 256*1024, fs.maxWriteSize(0))
	require.Equal(t, 256*1024, fs.maxTransactSize(0))

	// If maxCreditBalance is large and credits are granted, scales up to winMaxPayloadSize (1MB)
	c.account.maxCreditBalance = 128
	c.account.charge(30)
	require.Equal(t, 1024*1024, fs.maxReadSize(0))
	require.Equal(t, 1024*1024, fs.maxWriteSize(0))
	require.Equal(t, 1024*1024, fs.maxTransactSize(0))
}

func TestShare_MaxPayloadSizeReservesCompoundCredits(t *testing.T) {
	c := &conn{
		account:         openAccount(4),
		capabilities:    smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     1024 * 1024,
		maxWriteSize:    1024 * 1024,
		maxTransactSize: 1024 * 1024,
	}
	s := &session{conn: c}
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	// Replenish to maxCreditBalance so the cap is 4 * 64KB.
	c.account.charge(3)

	// A standalone request may use the whole credit cap.
	require.Equal(t, 256*1024, fs.maxReadSize(0))
	require.Equal(t, 256*1024, fs.maxWriteSize(0))
	require.Equal(t, 256*1024, fs.maxTransactSize(0))

	// A compound leaves room for its single-credit companions.
	require.Equal(t, 128*1024, fs.maxWriteSize(2))
	require.Equal(t, 128*1024, fs.maxTransactSize(2))
	require.Equal(t, 192*1024, fs.maxTransactSize(1))

	// Sizing never drops below a single credit.
	require.Equal(t, 64*1024, fs.maxTransactSize(8))
}

func TestShare_MaxPayloadSizeRespectsServerAdvertisedValues(t *testing.T) {
	c := &conn{
		account:         openAccount(4),
		capabilities:    smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s := &session{conn: c}
	tc := &treeConn{session: s}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	// server advertises 32KB (< singleCreditMaxPayloadSize) -> respect it
	require.Equal(t, 32*1024, fs.maxReadSize(0))
	require.Equal(t, 32*1024, fs.maxWriteSize(0))
	require.Equal(t, 32*1024, fs.maxTransactSize(0))

	// non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))

	// without LARGE_MTU, server-advertised sizes are still respected
	c = &conn{
		account:         openAccount(4),
		capabilities:    0,
		maxReadSize:     32 * 1024,
		maxWriteSize:    32 * 1024,
		maxTransactSize: 32 * 1024,
	}
	s = &session{conn: c}
	tc = &treeConn{session: s}
	fs = &Share{treeConn: tc, ctx: context.Background()}
	require.Equal(t, 32*1024, fs.maxReadSize(0))
	require.Equal(t, 32*1024, fs.maxWriteSize(0))
	require.Equal(t, 32*1024, fs.maxTransactSize(0))

	// without LARGE_MTU, non-positive advertised values -> fall back to singleCreditMaxPayloadSize
	c.maxReadSize = 0
	c.maxWriteSize = 0
	c.maxTransactSize = 0
	require.Equal(t, 64*1024, fs.maxReadSize(0))
	require.Equal(t, 64*1024, fs.maxWriteSize(0))
	require.Equal(t, 64*1024, fs.maxTransactSize(0))
}

func sendTestCompoundMidFailureResponse(dt transport, req []byte, fileId *smb2.FileId, status uint32) {
	createRes := &smb2.CreateResponse{
		FileId:         fileId,
		CreationTime:   &smb2.Filetime{},
		LastAccessTime: &smb2.Filetime{},
		LastWriteTime:  &smb2.Filetime{},
		ChangeTime:     &smb2.Filetime{},
	}
	resBuf1 := make([]byte, createRes.Size())
	createRes.Encode(resBuf1)

	p := smb2.PacketCodec(req)
	pad1 := (8 - (len(resBuf1) % 8)) % 8
	next1 := uint32(len(resBuf1) + pad1)
	padded1 := make([]byte, next1)
	copy(padded1, resBuf1)
	smb2.PacketCodec(padded1).SetMessageId(p.MessageId())
	smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_SUCCESS))
	smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	smb2.PacketCodec(padded1).SetNextCommand(next1)

	errPkt := &smb2.ErrorResponse{
		CommandCode: smb2.SMB2_SET_INFO,
	}
	resBuf2 := make([]byte, errPkt.Size())
	errPkt.Encode(resBuf2)
	pad2 := (8 - (len(resBuf2) % 8)) % 8
	next2 := uint32(len(resBuf2) + pad2)
	padded2 := make([]byte, next2)
	copy(padded2, resBuf2)
	smb2.PacketCodec(padded2).SetMessageId(p.MessageId() + 1)
	smb2.PacketCodec(padded2).SetSessionId(p.SessionId())
	smb2.PacketCodec(padded2).SetTreeId(p.TreeId())
	smb2.PacketCodec(padded2).SetStatus(status)
	smb2.PacketCodec(padded2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(padded2).SetNextCommand(next2)

	closeErrPkt := &smb2.ErrorResponse{
		CommandCode: smb2.SMB2_CLOSE,
	}
	resBuf3 := make([]byte, closeErrPkt.Size())
	closeErrPkt.Encode(resBuf3)
	smb2.PacketCodec(resBuf3).SetMessageId(p.MessageId() + 2)
	smb2.PacketCodec(resBuf3).SetSessionId(p.SessionId())
	smb2.PacketCodec(resBuf3).SetTreeId(p.TreeId())
	smb2.PacketCodec(resBuf3).SetStatus(status)
	smb2.PacketCodec(resBuf3).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	smb2.PacketCodec(resBuf3).SetCreditResponse(1)

	var compound []byte
	compound = append(compound, padded1...)
	compound = append(compound, padded2...)
	compound = append(compound, resBuf3...)

	_, _ = dt.Writev(compound)
}

type testRawBytes []byte

func (b testRawBytes) Size() int       { return len(b) }
func (b testRawBytes) Encode(p []byte) { copy(p, b) }

func TestCompoundMidFailureClosesServerHandle(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + setInfo + close (Rename)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestCompoundMidFailureResponse(dt, reqBuf1, expectedFileId, uint32(erref.STATUS_ACCESS_DENIED))

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeReq := smb2.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}
	}()

	err := fs.Rename("old.txt", "new.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when compound fails mid-flight")
}

func TestReadFileCompoundFailureClosesServerHandle(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryInfo + read (ReadFile)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := smb2.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &smb2.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		smb2.PacketCodec(padded0).SetMessageId(p.MessageId())
		smb2.PacketCodec(padded0).SetSessionId(p.SessionId())
		smb2.PacketCodec(padded0).SetTreeId(p.TreeId())
		smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryInfo ErrorResponse
		errPkt1 := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_QUERY_INFO,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		pad1 := (8 - (len(resBuf1) % 8)) % 8
		next1 := uint32(len(resBuf1) + pad1)
		padded1 := make([]byte, next1)
		copy(padded1, resBuf1)
		smb2.PacketCodec(padded1).SetMessageId(p.MessageId() + 1)
		smb2.PacketCodec(padded1).SetSessionId(p.SessionId())
		smb2.PacketCodec(padded1).SetTreeId(p.TreeId())
		smb2.PacketCodec(padded1).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		smb2.PacketCodec(padded1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		smb2.PacketCodec(padded1).SetNextCommand(next1)

		// Op 2: Read ErrorResponse
		errPkt2 := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_READ,
		}
		resBuf2 := make([]byte, errPkt2.Size())
		errPkt2.Encode(resBuf2)
		smb2.PacketCodec(resBuf2).SetMessageId(p.MessageId() + 2)
		smb2.PacketCodec(resBuf2).SetSessionId(p.SessionId())
		smb2.PacketCodec(resBuf2).SetTreeId(p.TreeId())
		smb2.PacketCodec(resBuf2).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		smb2.PacketCodec(resBuf2).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		smb2.PacketCodec(resBuf2).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, padded1...)
		compound = append(compound, resBuf2...)
		_, _ = dt.Writev(compound)

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeReq := smb2.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}
	}()

	_, err := fs.ReadFile("test.txt")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened file handle when ReadFile fails mid-flight")
}

// renameObservation records the SET_INFO BufferLength and the per-command
// CreditCharge of the CREATE + SET_INFO + CLOSE compound that Rename sends.
type renameObservation struct {
	commands      []smb2.Command
	creditCharges []uint16
	setInfoLength uint32
}

func (o renameObservation) totalCreditCharge() uint32 {
	var total uint32
	for _, charge := range o.creditCharges {
		total += uint32(charge)
	}
	return total
}

// longPathOfLength builds a relative path of exactly n ASCII characters from
// short components separated by backslashes, so no single component hits a
// server-side name limit.
func longPathOfLength(n int) string {
	const componentLen = 32

	var b strings.Builder
	b.Grow(n)
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('\\')
		}
		remaining := n - b.Len()
		b.WriteString(strings.Repeat("a", min(remaining, componentLen)))
	}
	return b.String()
}

// serveRenameCompound reads a single CREATE + SET_INFO + CLOSE compound request
// and replies with a successful response for each operation, reporting what it
// observed on the observed channel.
func serveRenameCompound(t *testing.T, serverConn net.Conn, observed chan<- renameObservation) {
	t.Helper()

	go func() {
		dt := direct(serverConn)
		reqBuf, err := readMsg(dt)
		if err != nil {
			observed <- renameObservation{}
			return
		}

		var obs renameObservation
		var responseBufs [][]byte
		currBuf := reqBuf
		for {
			p := smb2.PacketCodec(currBuf)
			obs.commands = append(obs.commands, p.Command())
			obs.creditCharges = append(obs.creditCharges, p.CreditCharge())
			nextCommand := p.NextCommand()

			var resBuf []byte
			switch p.Command() {
			case smb2.SMB2_CREATE:
				res := &smb2.CreateResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
					FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case smb2.SMB2_SET_INFO:
				obs.setInfoLength = smb2.SetInfoRequestDecoder(p.Body()).BufferLength()
				res := &smb2.SetInfoResponse{}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			case smb2.SMB2_CLOSE:
				res := &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf = make([]byte, res.Size())
				res.Encode(resBuf)
			}

			if resBuf != nil {
				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(p.MessageId())
				rp.SetSessionId(p.SessionId())
				rp.SetTreeId(p.TreeId())
				rp.SetCreditResponse(1)
				flags := uint32(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				if len(responseBufs) > 0 {
					flags |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
				}
				rp.SetFlags(flags)
				responseBufs = append(responseBufs, resBuf)
			}

			if nextCommand == 0 {
				break
			}
			currBuf = currBuf[nextCommand:]
		}

		var compound []byte
		for i, rb := range responseBufs {
			if i < len(responseBufs)-1 {
				pad := (8 - (len(rb) % 8)) % 8
				next := uint32(len(rb) + pad)
				padded := make([]byte, next)
				copy(padded, rb)
				smb2.PacketCodec(padded).SetNextCommand(next)
				compound = append(compound, padded...)
			} else {
				compound = append(compound, rb...)
			}
		}
		if len(compound) > 0 {
			if _, err := dt.Writev(compound); err != nil {
				observed <- renameObservation{}
				return
			}
		}
		observed <- obs
	}()
}

// requireNoRequest asserts that the server receives nothing before the
// read deadline elapses.
func requireNoRequest(t *testing.T, serverConn net.Conn) {
	t.Helper()

	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	var buf [1]byte
	_, err := serverConn.Read(buf[:])
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout(), "expected read deadline, got %v", err)
}

// requireRenameRejectedLocally asserts that Rename fails with an os.LinkError
// wrapping os.ErrInvalid and that no request reaches the server.
func requireRenameRejectedLocally(t *testing.T, fs *Share, serverConn net.Conn, newpath string) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fs.Rename("old.txt", newpath)
	}()

	select {
	case err := <-errCh:
		var linkErr *os.LinkError
		require.ErrorAs(t, err, &linkErr)
		require.ErrorIs(t, err, os.ErrInvalid)
		require.Equal(t, "rename", linkErr.Op)
		require.Equal(t, "old.txt", linkErr.Old)
		require.Equal(t, newpath, linkErr.New)
	case <-time.After(2 * time.Second):
		t.Fatal("Rename did not reject the oversized request locally")
	}

	requireNoRequest(t, serverConn)
}

func TestShareRenameRespectsMaxTransactSize(t *testing.T) {
	const maxTransact = 65536

	t.Run("input at MaxTransactSize is sent", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = maxTransact
		require.Equal(t, maxTransact, fs.maxTransactSize(2))

		observed := make(chan renameObservation, 1)
		serveRenameCompound(t, serverConn, observed)

		newpath := longPathOfLength((maxTransact - 20) / 2)
		require.NoError(t, fs.Rename("old.txt", newpath))

		obs := <-observed
		require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_SET_INFO, smb2.SMB2_CLOSE}, obs.commands)
		require.Equal(t, uint32(maxTransact), obs.setInfoLength)
	})

	t.Run("input over MaxTransactSize is rejected before send", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = maxTransact

		newpath := longPathOfLength((maxTransact-20)/2 + 1)
		requireRenameRejectedLocally(t, fs, serverConn, newpath)
	})
}

func TestShareRenameRespectsReservedCreditBudget(t *testing.T) {
	// A 65538-byte SET_INFO input (20-byte fixed part plus an encoded path)
	// needs a 2-credit CreditCharge, so the compound needs 4 credits in total
	// once the CREATE and CLOSE companions are accounted for.
	const setInfoSize = 65538
	newpath := longPathOfLength((setInfoSize - 20) / 2)

	t.Run("credit cap of three rejects locally", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = 1 << 20
		fs.conn.account.maxCreditBalance = 3
		require.Equal(t, maxSingleCreditPayloadSize, fs.maxTransactSize(2))

		requireRenameRejectedLocally(t, fs, serverConn, newpath)
	})

	t.Run("credit cap of four sends a four-credit compound", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		fs.conn.maxTransactSize = 1 << 20
		fs.conn.account.maxCreditBalance = 4
		require.Equal(t, 2*maxSingleCreditPayloadSize, fs.maxTransactSize(2))

		observed := make(chan renameObservation, 1)
		serveRenameCompound(t, serverConn, observed)

		require.NoError(t, fs.Rename("old.txt", newpath))

		obs := <-observed
		require.Equal(t, []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_SET_INFO, smb2.SMB2_CLOSE}, obs.commands)
		require.Equal(t, uint32(setInfoSize), obs.setInfoLength)
		require.Equal(t, []uint16{1, 2, 1}, obs.creditCharges)
		require.Equal(t, uint32(4), obs.totalCreditCharge())
	})
}

func TestReadDirCompoundFailureClosesServerHandle(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{2, 3, 4, 5, 6, 7, 8, 9},
		Volatile:   [8]byte{10, 11, 12, 13, 14, 15, 16, 17},
	}

	var closeReceived atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}

		p := smb2.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &smb2.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		smb2.PacketCodec(padded0).SetMessageId(p.MessageId())
		smb2.PacketCodec(padded0).SetSessionId(p.SessionId())
		smb2.PacketCodec(padded0).SetTreeId(p.TreeId())
		smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectory ErrorResponse
		errPkt1 := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_QUERY_DIRECTORY,
		}
		resBuf1 := make([]byte, errPkt1.Size())
		errPkt1.Encode(resBuf1)
		smb2.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
		smb2.PacketCodec(resBuf1).SetSessionId(p.SessionId())
		smb2.PacketCodec(resBuf1).SetTreeId(p.TreeId())
		smb2.PacketCodec(resBuf1).SetStatus(uint32(erref.STATUS_ACCESS_DENIED))
		smb2.PacketCodec(resBuf1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
		smb2.PacketCodec(resBuf1).SetCreditResponse(1)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.Writev(compound)

		// Request 2: automatic fallback close request
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		if p2.Command() == smb2.SMB2_CLOSE {
			closeReq := smb2.CloseRequestDecoder(p2.Body())
			if !closeReq.IsInvalid() {
				fd := closeReq.FileId().Decode()
				if *fd == *expectedFileId {
					closeReceived.Store(true)
				}
			}
			// Reply SUCCESS to close
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p2.MessageId())
			rp.SetSessionId(p2.SessionId())
			rp.SetTreeId(p2.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}
	}()

	_, err := fs.ReadDir("some_dir")
	require.Error(t, err)

	<-done
	require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle when ReadDir fails mid-flight")
}

func TestReadDir_EmptyDirectory(t *testing.T) {
	// Some servers (e.g. Samba) report STATUS_NO_MORE_FILES or even
	// STATUS_NO_SUCH_FILE on the first QUERY_DIRECTORY of a compound
	// CREATE+QUERY_DIRECTORY when the directory has no entries.
	for _, status := range []erref.NtStatus{erref.STATUS_NO_MORE_FILES, erref.STATUS_NO_SUCH_FILE} {
		t.Run(status.Error(), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := direct(serverConn)

			expectedFileId := &smb2.FileId{
				Persistent: [8]byte{4, 5, 6, 7, 8, 9, 10, 11},
				Volatile:   [8]byte{12, 13, 14, 15, 16, 17, 18, 19},
			}

			var closeReceived atomic.Bool

			done := make(chan struct{})
			go func() {
				defer close(done)
				// Request 1: compound create + queryDir (ReadDir)
				reqBuf1, err := readMsg(dt)
				if err != nil {
					return
				}

				p := smb2.PacketCodec(reqBuf1)

				// Op 0: CreateResponse SUCCESS
				createRes := &smb2.CreateResponse{
					FileId:         expectedFileId,
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}
				resBuf0 := make([]byte, createRes.Size())
				createRes.Encode(resBuf0)
				pad0 := (8 - (len(resBuf0) % 8)) % 8
				next0 := uint32(len(resBuf0) + pad0)
				padded0 := make([]byte, next0)
				copy(padded0, resBuf0)
				smb2.PacketCodec(padded0).SetMessageId(p.MessageId())
				smb2.PacketCodec(padded0).SetSessionId(p.SessionId())
				smb2.PacketCodec(padded0).SetTreeId(p.TreeId())
				smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
				smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				smb2.PacketCodec(padded0).SetNextCommand(next0)

				// Op 1: QueryDirectory ErrorResponse
				errPkt1 := &smb2.ErrorResponse{
					CommandCode: smb2.SMB2_QUERY_DIRECTORY,
				}
				resBuf1 := make([]byte, errPkt1.Size())
				errPkt1.Encode(resBuf1)
				smb2.PacketCodec(resBuf1).SetMessageId(p.MessageId() + 1)
				smb2.PacketCodec(resBuf1).SetSessionId(p.SessionId())
				smb2.PacketCodec(resBuf1).SetTreeId(p.TreeId())
				smb2.PacketCodec(resBuf1).SetStatus(uint32(status))
				smb2.PacketCodec(resBuf1).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
				smb2.PacketCodec(resBuf1).SetCreditResponse(1)

				var compound []byte
				compound = append(compound, padded0...)
				compound = append(compound, resBuf1...)
				_, _ = dt.Writev(compound)

				// Request 2: automatic fallback close request
				reqBuf2, err := readMsg(dt)
				if err != nil {
					return
				}
				p2 := smb2.PacketCodec(reqBuf2)
				if p2.Command() == smb2.SMB2_CLOSE {
					closeReq := smb2.CloseRequestDecoder(p2.Body())
					if !closeReq.IsInvalid() {
						fd := closeReq.FileId().Decode()
						if *fd == *expectedFileId {
							closeReceived.Store(true)
						}
					}
					closeRes := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					closeBuf := make([]byte, closeRes.Size())
					closeRes.Encode(closeBuf)
					rp := smb2.PacketCodec(closeBuf)
					rp.SetMessageId(p2.MessageId())
					rp.SetSessionId(p2.SessionId())
					rp.SetTreeId(p2.TreeId())
					rp.SetStatus(uint32(erref.STATUS_SUCCESS))
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					rp.SetCreditResponse(1)
					_, _ = dt.Writev(closeBuf)
				}
			}()

			fis, err := fs.ReadDir("some_dir")
			require.NoError(t, err, "an empty directory must not fail")
			require.NotNil(t, fis, "an empty directory must return a non-nil slice")
			require.Len(t, fis, 0)

			<-done
			require.True(t, closeReceived.Load(), "server must receive CLOSE for the opened directory handle")
		})
	}
}

// encodeFileIdBothDirEntry builds a FILE_ID_BOTH_DIR_INFORMATION entry
// (MS-FSCC 2.4.22) carrying a single file name.
func encodeFileIdBothDirEntry(name string) []byte {
	nameBytes := utf16le.EncodeStringToBytes(name)
	entry := make([]byte, 104+len(nameBytes))
	le.PutUint64(entry[40:48], 1) // EndOfFile
	le.PutUint64(entry[48:56], 1) // AllocationSize
	le.PutUint32(entry[56:60], smb2.FILE_ATTRIBUTE_NORMAL)
	le.PutUint32(entry[60:64], uint32(len(nameBytes))) // FileNameLength
	le.PutUint64(entry[96:104], 42)                    // FileId
	copy(entry[104:], nameBytes)
	return entry
}

// encodeQueryDirResponse builds a standalone SMB2 QUERY_DIRECTORY response
// packet carrying the given output buffer.
func encodeQueryDirResponse(msgId, sessionId uint64, treeId uint32, output []byte, status uint32, related bool) []byte {
	res := &smb2.QueryDirectoryResponse{Output: rawEncoder(output)}
	resBuf := make([]byte, res.Size())
	res.Encode(resBuf)
	rp := smb2.PacketCodec(resBuf)
	rp.SetMessageId(msgId)
	rp.SetSessionId(sessionId)
	rp.SetTreeId(treeId)
	rp.SetStatus(status)
	if related {
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR | smb2.SMB2_FLAGS_RELATED_OPERATIONS)
	} else {
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	}
	rp.SetCreditResponse(1)
	return resBuf
}

type queryDirectoryPage struct {
	output []byte
	status uint32
}

func startQueryDirectoryPages(t *testing.T, serverConn net.Conn, pages ...queryDirectoryPage) *int64 {
	t.Helper()
	var queryCount int64
	onQueryInfo := func(msgId uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], smb2.FILE_ATTRIBUTE_DIRECTORY)
		res := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		resBuf := make([]byte, res.Size())
		res.Encode(resBuf)
		return resBuf
	}
	startFullFakeServer(serverConn, func(msgId uint64, reqBuf []byte, dt transport) bool {
		pageIndex := int(atomic.AddInt64(&queryCount, 1)) - 1
		page := queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)}
		if pageIndex < len(pages) {
			page = pages[pageIndex]
		}

		p := smb2.PacketCodec(reqBuf)
		if page.status == uint32(erref.STATUS_SUCCESS) {
			_, _ = dt.Writev(encodeQueryDirResponse(msgId, p.SessionId(), p.TreeId(), page.output, page.status, false))
			return true
		}

		errRes := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
		resBuf := make([]byte, errRes.Size())
		errRes.Encode(resBuf)
		rp := smb2.PacketCodec(resBuf)
		rp.SetMessageId(msgId)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetStatus(page.status)
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		_, _ = dt.Writev(resBuf)
		return true
	}, nil, onQueryInfo)
	return &queryCount
}

func TestReadDirContinuesEnumerationWhenFirstResponseIsSmallerThanRequested(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)

	expectedFileId := &smb2.FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Request 1: compound create + queryDir (Share.ReadDir)
		reqBuf1, err := readMsg(dt)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf1)

		// Op 0: CreateResponse SUCCESS
		createRes := &smb2.CreateResponse{
			FileId:         expectedFileId,
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
		}
		resBuf0 := make([]byte, createRes.Size())
		createRes.Encode(resBuf0)
		pad0 := (8 - (len(resBuf0) % 8)) % 8
		next0 := uint32(len(resBuf0) + pad0)
		padded0 := make([]byte, next0)
		copy(padded0, resBuf0)
		smb2.PacketCodec(padded0).SetMessageId(p.MessageId())
		smb2.PacketCodec(padded0).SetSessionId(p.SessionId())
		smb2.PacketCodec(padded0).SetTreeId(p.TreeId())
		smb2.PacketCodec(padded0).SetStatus(uint32(erref.STATUS_SUCCESS))
		smb2.PacketCodec(padded0).SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		smb2.PacketCodec(padded0).SetNextCommand(next0)

		// Op 1: QueryDirectoryResponse with a single entry. The response is
		// far smaller than the requested OutputBufferLength (maxTransactSize),
		// but the server still has more entries to return.
		resBuf1 := encodeQueryDirResponse(p.MessageId()+1, p.SessionId(), p.TreeId(), encodeFileIdBothDirEntry("alpha.txt"), uint32(erref.STATUS_SUCCESS), true)

		var compound []byte
		compound = append(compound, padded0...)
		compound = append(compound, resBuf1...)
		_, _ = dt.Writev(compound)

		// Request 2: follow-up queryDir issued by Readdir(-1); one more entry
		reqBuf2, err := readMsg(dt)
		if err != nil {
			return
		}
		p2 := smb2.PacketCodec(reqBuf2)
		resBuf2 := encodeQueryDirResponse(p2.MessageId(), p2.SessionId(), p2.TreeId(), encodeFileIdBothDirEntry("beta.txt"), uint32(erref.STATUS_SUCCESS), false)
		_, _ = dt.Writev(resBuf2)

		// Request 3: follow-up queryDir; no more entries
		reqBuf3, err := readMsg(dt)
		if err != nil {
			return
		}
		p3 := smb2.PacketCodec(reqBuf3)
		errPkt := &smb2.ErrorResponse{
			CommandCode: smb2.SMB2_QUERY_DIRECTORY,
		}
		errBuf := make([]byte, errPkt.Size())
		errPkt.Encode(errBuf)
		ep := smb2.PacketCodec(errBuf)
		ep.SetMessageId(p3.MessageId())
		ep.SetSessionId(p3.SessionId())
		ep.SetTreeId(p3.TreeId())
		ep.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		ep.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		ep.SetCreditResponse(1)
		_, _ = dt.Writev(errBuf)

		// Request 4: automatic close issued by ReadDir's deferred Close
		reqBuf4, err := readMsg(dt)
		if err != nil {
			return
		}
		p4 := smb2.PacketCodec(reqBuf4)
		if p4.Command() == smb2.SMB2_CLOSE {
			closeRes := &smb2.CloseResponse{
				CreationTime:   &smb2.Filetime{},
				LastAccessTime: &smb2.Filetime{},
				LastWriteTime:  &smb2.Filetime{},
				ChangeTime:     &smb2.Filetime{},
			}
			closeBuf := make([]byte, closeRes.Size())
			closeRes.Encode(closeBuf)
			rp := smb2.PacketCodec(closeBuf)
			rp.SetMessageId(p4.MessageId())
			rp.SetSessionId(p4.SessionId())
			rp.SetTreeId(p4.TreeId())
			rp.SetStatus(uint32(erref.STATUS_SUCCESS))
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			rp.SetCreditResponse(1)
			_, _ = dt.Writev(closeBuf)
		}
	}()

	fis, err := fs.ReadDir("some_dir")
	require.NoError(t, err)

	names := make([]string, len(fis))
	for i, fi := range fis {
		names[i] = fi.Name()
	}
	require.Equal(t, []string{"alpha.txt", "beta.txt"}, names, "entries from subsequent query batches must not be dropped")

	<-done
}

func TestReadDirStopsAfterThreeDotOnlyPages(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)
	var queryCount int64 = 1 // The initial QUERY_DIRECTORY is compound with CREATE.
	done := make(chan struct{})
	go func() {
		defer close(done)

		reqBuf, err := readMsg(dt)
		if err != nil {
			return
		}
		p := smb2.PacketCodec(reqBuf)

		createRes := &smb2.CreateResponse{
			CreationTime:   &smb2.Filetime{},
			LastAccessTime: &smb2.Filetime{},
			LastWriteTime:  &smb2.Filetime{},
			ChangeTime:     &smb2.Filetime{},
			FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
		}
		createBuf := make([]byte, createRes.Size())
		createRes.Encode(createBuf)
		pad := (8 - (len(createBuf) % 8)) % 8
		paddedCreate := make([]byte, len(createBuf)+pad)
		copy(paddedCreate, createBuf)
		createPacket := smb2.PacketCodec(paddedCreate)
		createPacket.SetMessageId(p.MessageId())
		createPacket.SetSessionId(p.SessionId())
		createPacket.SetTreeId(p.TreeId())
		createPacket.SetStatus(uint32(erref.STATUS_SUCCESS))
		createPacket.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		createPacket.SetNextCommand(uint32(len(paddedCreate)))

		queryBuf := encodeQueryDirResponse(
			p.MessageId()+1,
			p.SessionId(),
			p.TreeId(),
			encodeFileIdBothDirectoryInformations([]string{".", ".."}),
			uint32(erref.STATUS_SUCCESS),
			true,
		)
		_, _ = dt.Writev(append(paddedCreate, queryBuf...))

		for {
			reqBuf, err = readMsg(dt)
			if err != nil {
				return
			}
			if smb2.PacketCodec(reqBuf).Command() == smb2.SMB2_CLOSE {
				sendTestResponse(dt, reqBuf, &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
				return
			}

			count := atomic.AddInt64(&queryCount, 1)
			if count <= 4 {
				sendTestResponse(dt, reqBuf, &smb2.QueryDirectoryResponse{
					Output: rawEncoder(encodeFileIdBothDirectoryInformations([]string{".", ".."})),
				}, uint32(erref.STATUS_SUCCESS))
			} else {
				sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{
					CommandCode: smb2.SMB2_QUERY_DIRECTORY,
				}, uint32(erref.STATUS_NO_MORE_FILES))
			}
		}
	}()

	_, err := fs.ReadDir("testdir")
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "invalid response error: query directory returned only dot entries", invalid.Error())
	require.EqualValues(t, 4, atomic.LoadInt64(&queryCount))
	<-done
}

func TestGlobStopsAfterThreeDotOnlyPages(t *testing.T) {
	fs, serverConn := newTestShare(t)
	queryCount := startQueryDirectoryPages(t, serverConn,
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
		queryDirectoryPage{
			output: encodeFileIdBothDirectoryInformations([]string{".", ".."}),
		},
	)

	matches, err := fs.Glob("*")
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
	require.Nil(t, matches)
	require.Equal(t, "invalid response error: query directory returned only dot entries", invalid.Error())
	require.EqualValues(t, 3, atomic.LoadInt64(queryCount))

	// Glob's directory error must not close the shared connection.
	_, err = fs.Stat("other")
	require.NoError(t, err)
}

func TestReaddirContinuesPastSplitDotEntries(t *testing.T) {
	dot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{"."})}
	dotdot := queryDirectoryPage{output: encodeFileIdBothDirectoryInformations([]string{".."})}
	visible := queryDirectoryPage{output: encodeFileIdBothDirectoryInformation("visible.txt")}
	end := queryDirectoryPage{status: uint32(erref.STATUS_NO_MORE_FILES)}

	cases := []struct {
		name  string
		pages []queryDirectoryPage
		want  []string
	}{
		{
			name:  "single dot page then entry",
			pages: []queryDirectoryPage{dot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then entry",
			pages: []queryDirectoryPage{dot, dotdot, visible, end},
			want:  []string{"visible.txt"},
		},
		{
			name:  "dot and dot-dot on separate pages then end of enumeration",
			pages: []queryDirectoryPage{dot, dotdot, end},
			want:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "testdir")
			queryCount := startQueryDirectoryPages(t, serverConn, tc.pages...)

			fis, err := f.Readdir(-1)
			require.NoError(t, err)
			names := make([]string, len(fis))
			for i, fi := range fis {
				names[i] = fi.Name()
			}
			require.Equal(t, tc.want, names)
			require.EqualValues(t, len(tc.pages), atomic.LoadInt64(queryCount))
		})
	}
}

func TestShareChmodUsesCreateAttributes(t *testing.T) {
	for _, status := range []erref.NtStatus{erref.STATUS_SUCCESS, erref.STATUS_ACCESS_DENIED} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			dt := direct(serverConn)
			fileID := &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}}
			const initialAttrs = smb2.FILE_ATTRIBUTE_READONLY | smb2.FILE_ATTRIBUTE_HIDDEN | smb2.FILE_ATTRIBUTE_SYSTEM
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverConn.Close()
				create, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p := smb2.PacketCodec(create)
				assert.Equal(t, smb2.SMB2_CREATE, p.Command())
				assert.Zero(t, p.NextCommand(), "CREATE must not include QUERY_INFO")
				sendTestCreateAttributesResponse(dt, create, fileID, initialAttrs)

				set, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p = smb2.PacketCodec(set)
				assert.Equal(t, smb2.SMB2_SET_INFO, p.Command())
				assert.Zero(t, p.NextCommand())
				req := smb2.SetInfoRequestDecoder(p.Body())
				assert.Equal(t, *fileID, *req.FileId().Decode())
				base := smb2.FileBasicInformationDecoder(p[req.BufferOffset():])
				assert.Equal(t, uint32(smb2.FILE_ATTRIBUTE_NORMAL|smb2.FILE_ATTRIBUTE_HIDDEN|smb2.FILE_ATTRIBUTE_SYSTEM), base.FileAttributes())
				if status == erref.STATUS_SUCCESS {
					sendTestResponse(dt, set, &smb2.SetInfoResponse{}, uint32(status))
				} else {
					sendTestResponse(dt, set, &smb2.ErrorResponse{CommandCode: smb2.SMB2_SET_INFO}, uint32(status))
				}

				closeReq, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				p = smb2.PacketCodec(closeReq)
				assert.Equal(t, smb2.SMB2_CLOSE, p.Command())
				assert.Equal(t, *fileID, *smb2.CloseRequestDecoder(p.Body()).FileId().Decode())
				sendTestCloseResponse(dt, closeReq)
			}()
			err := fs.Chmod("file.txt", 0o644)
			<-done
			if status == erref.STATUS_SUCCESS {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, status)
			}
		})
	}
}

func TestFileChmodRejectsInvalidQueryInfo(t *testing.T) {
	f, serverConn := newTestFile(t)
	dt := direct(serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		query, err := readMsg(dt)
		if err != nil {
			return
		}
		sendTestResponse(dt, query, &smb2.QueryInfoResponse{
			Output: testRawBytes([]byte{1, 2, 3}),
		}, uint32(erref.STATUS_SUCCESS))
	}()
	err := f.Chmod(0o644)
	<-done
	var invalid *InvalidResponseError
	require.ErrorAs(t, err, &invalid)
}

func TestLstatDoesNotRegisterFinalizer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	go c.runReceiver()

	var createCount, closeCount int64

	const (
		creationLow    = uint32(0x11223344)
		creationHigh   = uint32(0x01234567)
		accessLow      = uint32(0x55667788)
		accessHigh     = uint32(0x01234567)
		writeLow       = uint32(0x99aabbcc)
		writeHigh      = uint32(0x01234567)
		changeLow      = uint32(0xddeeff00)
		changeHigh     = uint32(0x01234567)
		allocationSize = int64(8192)
		endOfFile      = int64(4096)
		fileAttributes = uint32(0x20)
	)

	filetime := func(low, high uint32) time.Time {
		raw := make([]byte, 8)
		le.PutUint32(raw[0:4], low)
		le.PutUint32(raw[4:8], high)
		return smb2.FiletimeDecoder(raw).Time()
	}

	// Fake server that counts CREATE and CLOSE requests so we can detect
	// a spurious CLOSE triggered by a runtime finalizer after GC.
	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			var responseBufs [][]byte
			currBuf := reqBuf
			for {
				p := smb2.PacketCodec(currBuf)
				msgId := p.MessageId()

				var resBuf []byte
				switch p.Command() {
				case smb2.SMB2_CREATE:
					atomic.AddInt64(&createCount, 1)
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{LowDateTime: creationLow, HighDateTime: creationHigh},
						LastAccessTime: &smb2.Filetime{LowDateTime: accessLow, HighDateTime: accessHigh},
						LastWriteTime:  &smb2.Filetime{LowDateTime: writeLow, HighDateTime: writeHigh},
						ChangeTime:     &smb2.Filetime{LowDateTime: changeLow, HighDateTime: changeHigh},
						AllocationSize: allocationSize,
						EndofFile:      endOfFile,
						FileAttributes: fileAttributes,
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{2}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					atomic.AddInt64(&closeCount, 1)
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(msgId)
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if p.NextCommand() == 0 {
					break
				}
				currBuf = currBuf[p.NextCommand():]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				_, _ = dt.Writev(finalBuf)
			}
		}
	}()

	fi, err := fs.Lstat("test.txt")
	require.NoError(t, err)

	require.Equal(t, "test.txt", fi.Name())
	require.Equal(t, os.FileMode(0o666), fi.Mode())
	require.Equal(t, endOfFile, fi.Size())
	require.True(t, fi.ModTime().Equal(filetime(writeLow, writeHigh)))

	fst, ok := fi.(*FileStat)
	require.True(t, ok, "Lstat must return *FileStat")
	require.True(t, fst.CreationTime.Equal(filetime(creationLow, creationHigh)))
	require.True(t, fst.LastAccessTime.Equal(filetime(accessLow, accessHigh)))
	require.True(t, fst.LastWriteTime.Equal(filetime(writeLow, writeHigh)))
	require.True(t, fst.ChangeTime.Equal(filetime(changeLow, changeHigh)))
	require.Equal(t, endOfFile, fst.EndOfFile)
	require.Equal(t, allocationSize, fst.AllocationSize)
	require.Equal(t, fileAttributes, fst.FileAttributes)

	require.Equal(t, int64(1), atomic.LoadInt64(&createCount))
	require.Equal(t, int64(1), atomic.LoadInt64(&closeCount), "Lstat must send exactly one CLOSE (the compound close)")

	// The *File created by the old implementation becomes unreachable right
	// after Lstat returns, so its finalizer fires on GC and issues a spurious
	// CLOSE request. Force GC and make sure no extra CLOSE ever arrives.
	runtime.GC()
	runtime.GC()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := atomic.LoadInt64(&closeCount); n != 1 {
			t.Fatalf("Lstat registered a finalizer: %d CLOSE requests observed (want 1)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFile_StatRejectsIncompleteFileNetworkOpenInformation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		output []byte
	}{
		{name: "empty output", output: nil},
		{name: "truncated header", output: make([]byte, 32)},
		{name: "one byte short", output: make([]byte, 55)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			f := fs.newFile(smb2.CreateResponseDecoder(make([]byte, 88)), "test.txt")

			startFullFakeServer(serverConn, nil, nil, func(msgId uint64, reqBuf []byte) []byte {
				res := &smb2.QueryInfoResponse{Output: rawEncoder(tt.output)}
				resBuf := make([]byte, res.Size())
				res.Encode(resBuf)
				return resBuf
			})

			fi, err := f.Stat()
			var invalidResponseErr *InvalidResponseError
			require.Nil(t, fi)
			require.ErrorAs(t, err, &invalidResponseErr)
		})
	}
}

func TestNewFileStatConstructors(t *testing.T) {
	// 1. Test newFileStatFromCreateResponse
	createBuf := make([]byte, 88)
	// CreationTime @ 8:16
	le.PutUint32(createBuf[8:12], 0x11223344)
	le.PutUint32(createBuf[12:16], 0x01234567)
	// LastAccessTime @ 16:24
	le.PutUint32(createBuf[16:20], 0x55667788)
	le.PutUint32(createBuf[20:24], 0x01234567)
	// LastWriteTime @ 24:32
	le.PutUint32(createBuf[24:28], 0x99aabbcc)
	le.PutUint32(createBuf[28:32], 0x01234567)
	// ChangeTime @ 32:40
	le.PutUint32(createBuf[32:36], 0xddeeff00)
	le.PutUint32(createBuf[36:40], 0x01234567)
	// AllocationSize @ 40:48
	le.PutUint64(createBuf[40:48], 8192)
	// EndofFile @ 48:56
	le.PutUint64(createBuf[48:56], 4096)
	// FileAttributes @ 56:60
	le.PutUint32(createBuf[56:60], 0x20)

	fst1 := newFileStatFromCreateResponse(createBuf, `foo\bar\test.txt`)
	require.Equal(t, "test.txt", fst1.Name())
	require.Equal(t, int64(4096), fst1.Size())
	require.Equal(t, int64(8192), fst1.AllocationSize)
	require.Equal(t, uint32(0x20), fst1.FileAttributes)

	// 2. Test newFileStatFromFileNetworkOpenInformation
	netInfoBuf := make([]byte, 56)
	// CreationTime @ 0:8
	le.PutUint32(netInfoBuf[0:4], 0x11223344)
	le.PutUint32(netInfoBuf[4:8], 0x01234567)
	// LastAccessTime @ 8:16
	le.PutUint32(netInfoBuf[8:12], 0x55667788)
	le.PutUint32(netInfoBuf[12:16], 0x01234567)
	// LastWriteTime @ 16:24
	le.PutUint32(netInfoBuf[16:20], 0x99aabbcc)
	le.PutUint32(netInfoBuf[20:24], 0x01234567)
	// ChangeTime @ 24:32
	le.PutUint32(netInfoBuf[24:28], 0xddeeff00)
	le.PutUint32(netInfoBuf[28:32], 0x01234567)
	// AllocationSize @ 32:40
	le.PutUint64(netInfoBuf[32:40], 16384)
	// EndOfFile @ 40:48
	le.PutUint64(netInfoBuf[40:48], 8192)
	// FileAttributes @ 48:52
	le.PutUint32(netInfoBuf[48:52], 0x10) // Directory

	fst2 := newFileStatFromFileNetworkOpenInformation(netInfoBuf, `dir\subdir`)
	require.Equal(t, "subdir", fst2.Name())
	require.Equal(t, int64(8192), fst2.Size())
	require.Equal(t, int64(16384), fst2.AllocationSize)
	require.Equal(t, uint32(0x10), fst2.FileAttributes)
	require.True(t, fst2.IsDir())

	// 3. Test newFileStatFromFileIdBothDirectoryInformation
	bothDirBuf := make([]byte, 104)
	// EndOfFile @ 40:48
	le.PutUint64(bothDirBuf[40:48], 100)
	// AllocationSize @ 48:56
	le.PutUint64(bothDirBuf[48:56], 512)
	// FileAttributes @ 56:60
	le.PutUint32(bothDirBuf[56:60], 0x20)

	fst3 := newFileStatFromFileIdBothDirectoryInformation(bothDirBuf, "entry.txt")
	require.Equal(t, "entry.txt", fst3.Name())
	require.Equal(t, int64(100), fst3.Size())
	require.Equal(t, int64(512), fst3.AllocationSize)
	require.Equal(t, uint32(0x20), fst3.FileAttributes)
	require.False(t, fst3.IsDir())
}

func TestStatfs_RegularFilePath(t *testing.T) {
	run := func(t *testing.T, path string, sectorsPerAllocationUnit uint32, expectedBlockSize uint64) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		c := &conn{
			t:                   direct(clientConn),
			outstandingRequests: newOutstandingRequests(),
			account:             openAccount(100),
			maxReadSize:         64 * 1024,
			maxWriteSize:        64 * 1024,
		}
		c.account.charge(100)
		c.session = &session{conn: c, sessionId: 0x100}
		c.enableSession()
		tc := &treeConn{session: c.session, treeId: 0x200}
		fs := &Share{treeConn: tc, ctx: context.Background()}

		go c.runReceiver()

		done := make(chan struct{})
		go func() {
			defer close(done)
			dt := direct(serverConn)
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			// The fake server accepts the CREATE only when it does not force
			// FILE_DIRECTORY_FILE, mirroring how a real server rejects
			// opening a regular file as a directory with
			// STATUS_NOT_A_DIRECTORY.
			notADirectory := false
			curr := reqBuf
			for {
				p := smb2.PacketCodec(curr)
				if p.Command() == smb2.SMB2_CREATE &&
					smb2.CreateRequestDecoder(curr[64:]).CreateOptions()&smb2.FILE_DIRECTORY_FILE != 0 {
					notADirectory = true
					break
				}
				if p.NextCommand() == 0 {
					break
				}
				curr = curr[p.NextCommand():]
			}

			curr = reqBuf
			for {
				p := smb2.PacketCodec(curr)
				msgId := p.MessageId()
				cmd := p.Command()

				var resBuf []byte
				switch {
				case notADirectory:
					resBuf = make([]byte, 64+8)
					le.PutUint16(resBuf[64:66], 9) // ErrorResponse StructureSize
					rp := smb2.PacketCodec(resBuf)
					rp.SetProtocolId()
					rp.SetStructureSize()
					rp.SetCommand(cmd)
					rp.SetStatus(uint32(erref.STATUS_NOT_A_DIRECTORY))
				case cmd == smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)
				case cmd == smb2.SMB2_QUERY_INFO:
					// FileFsFullSizeInformation (32 bytes)
					info := make([]byte, 32)
					le.PutUint64(info[0:8], 1000)                       // TotalAllocationUnits
					le.PutUint64(info[8:16], 600)                       // CallerAvailableAllocationUnits
					le.PutUint64(info[16:24], 500)                      // ActualAvailableAllocationUnits
					le.PutUint32(info[24:28], sectorsPerAllocationUnit) // SectorsPerAllocationUnit
					le.PutUint32(info[28:32], 512)                      // BytesPerSector
					qres := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
					resBuf = make([]byte, qres.Size())
					qres.Encode(resBuf)
				default: // SMB2_CLOSE
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)
				}

				rp := smb2.PacketCodec(resBuf)
				rp.SetMessageId(msgId)
				rp.SetSessionId(0x100)
				rp.SetTreeId(0x200)
				rp.SetCreditResponse(1)
				rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)

				if _, err := dt.Writev(resBuf); err != nil {
					return
				}

				if p.NextCommand() == 0 {
					return
				}
				curr = curr[p.NextCommand():]
			}
		}()

		info, err := fs.Statfs(path)
		require.NoError(t, err)
		require.Equal(t, expectedBlockSize, info.BlockSize())
		require.Equal(t, uint64(sectorsPerAllocationUnit), info.FragmentSize())
		require.Equal(t, uint64(1000), info.TotalBlockCount())
		require.Equal(t, uint64(500), info.FreeBlockCount())
		require.Equal(t, uint64(600), info.AvailableBlockCount())
		require.Equal(t, uint64(1000)*expectedBlockSize, info.TotalBlockCount()*info.BlockSize())
		require.Equal(t, uint64(500)*expectedBlockSize, info.FreeBlockCount()*info.BlockSize())
		require.Equal(t, uint64(600)*expectedBlockSize, info.AvailableBlockCount()*info.BlockSize())
	}

	t.Run("regular file", func(t *testing.T) {
		run(t, "file.txt", 8, 4096)
	})

	t.Run("directory", func(t *testing.T) {
		run(t, "dir", 8, 4096)
	})

	t.Run("single-sector allocation unit", func(t *testing.T) {
		run(t, "file.txt", 1, 512)
	})

	t.Run("allocation unit exceeds 32 bits", func(t *testing.T) {
		run(t, "file.txt", 1<<23, 1<<32)
	})
}

// rejectingTransport fails on the first write, ensuring that any request
// which reaches the transport layer makes the test fail loudly.
type rejectingTransport struct{}

func (rejectingTransport) Writev(p ...[]byte) (int, error) {
	return 0, errors.New("unexpected request sent")
}
func (t rejectingTransport) Send(p ...[]byte) error {
	_, err := t.Writev(p...)
	return err
}
func (rejectingTransport) Receive() ([]byte, error)         { return nil, io.EOF }
func (rejectingTransport) SetWriteDeadline(time.Time) error { return nil }
func (rejectingTransport) ReadPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	return nil, io.EOF
}
func (rejectingTransport) Close() error { return nil }

func TestIoctlResponseSumExceedsMaxTransactSize(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c, cleanup := newBenchConn(clientConn)
	defer cleanup()
	c.maxTransactSize = 65536
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fs := &Share{treeConn: &treeConn{session: c.session, treeId: 1}, ctx: ctx}
	require.Equal(t, 65536, fs.maxTransactSize(0))
	req := &smb2.IoctlRequest{
		CtlCode:           smb2.FSCTL_PIPE_TRANSCEIVE,
		Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
		Input:             rawEncoder([]byte{1}),
		MaxInputResponse:  65536,
		MaxOutputResponse: 1,
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := fs.ioctl(&smb2.FileId{}, req)
		errCh <- err
	}()

	require.NoError(t, serverConn.SetDeadline(time.Now().Add(2*time.Second)))
	dt := direct(serverConn)
	encoded, err := readMsg(dt)
	require.NoError(t, err)
	packet := smb2.PacketCodec(encoded)
	require.Equal(t, smb2.SMB2_IOCTL, packet.Command())
	require.Equal(t, uint16(2), packet.CreditCharge())
	wireReq := smb2.IoctlRequestDecoder(packet.Body())
	require.Equal(t, uint32(1), wireReq.InputCount())
	require.Equal(t, uint32(65536), wireReq.MaxInputResponse())
	require.Equal(t, uint32(1), wireReq.MaxOutputResponse())
	require.Zero(t, wireReq.OutputCount())
	sendTestResponse(dt, encoded, &smb2.IoctlResponse{
		CtlCode: req.CtlCode,
		Flags:   smb2.SMB2_0_IOCTL_IS_FSCTL,
		Output:  rawEncoder([]byte{1}),
	}, 0)
	require.NoError(t, <-errCh)
}

func TestListSharenames_OversizedServerName(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &conn{
		t:                   direct(clientConn),
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(100),
		maxReadSize:         64 * 1024,
		maxWriteSize:        64 * 1024,
		maxTransactSize:     64 * 1024,
	}
	c.account.charge(100)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	oversizedHostname := strings.Repeat("a", 32760)
	s := &Session{
		s:    c.session,
		ctx:  ctx,
		addr: "testserver",
	}

	go c.runReceiver()

	go func() {
		dt := direct(serverConn)
		for {
			reqBuf, err := readMsg(dt)
			if err != nil {
				return
			}

			currBuf := reqBuf
			var responseBufs [][]byte
			for {
				p := smb2.PacketCodec(currBuf)
				cmd := p.Command()
				nextCommand := p.NextCommand()

				var resBuf []byte
				switch cmd {
				case smb2.SMB2_TREE_CONNECT:
					tcres := &smb2.TreeConnectResponse{
						ShareType: smb2.SMB2_SHARE_TYPE_PIPE,
					}
					resBuf = make([]byte, tcres.Size())
					tcres.Encode(resBuf)

				case smb2.SMB2_CREATE:
					cres := &smb2.CreateResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
						FileId:         &smb2.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}},
					}
					resBuf = make([]byte, cres.Size())
					cres.Encode(resBuf)

				case smb2.SMB2_CLOSE:
					clres := &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}
					resBuf = make([]byte, clres.Size())
					clres.Encode(resBuf)

				case smb2.SMB2_TREE_DISCONNECT:
					tdres := &smb2.TreeDisconnectResponse{}
					resBuf = make([]byte, tdres.Size())
					tdres.Encode(resBuf)

				case smb2.SMB2_IOCTL:
					ireq := smb2.IoctlRequestDecoder(currBuf[64:])
					ctlCode := ireq.CtlCode()
					if ctlCode == smb2.FSCTL_PIPE_TRANSCEIVE {
						in := currBuf[ireq.InputOffset() : ireq.InputOffset()+ireq.InputCount()]
						if len(in) >= 16 && in[2] == 11 { // Bind request
							rpcCallId := le.Uint32(in[12:16])
							bindAck := acceptedBindAck(rpcCallId)
							iores := &smb2.IoctlResponse{
								CtlCode: smb2.FSCTL_PIPE_TRANSCEIVE,
								Output:  rawEncoder(bindAck),
							}
							resBuf = make([]byte, iores.Size())
							iores.Encode(resBuf)
						}
					}
				}

				if resBuf != nil {
					rp := smb2.PacketCodec(resBuf)
					rp.SetMessageId(p.MessageId())
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetStatus(uint32(erref.STATUS_SUCCESS))
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					responseBufs = append(responseBufs, resBuf)
				}

				if nextCommand == 0 {
					break
				}
				currBuf = currBuf[nextCommand:]
			}

			if len(responseBufs) > 0 {
				var finalBuf []byte
				for i, rb := range responseBufs {
					if i < len(responseBufs)-1 {
						pad := (8 - (len(rb) % 8)) % 8
						nextCmd := uint32(len(rb) + pad)
						padded := make([]byte, nextCmd)
						copy(padded, rb)
						smb2.PacketCodec(padded).SetNextCommand(nextCmd)
						finalBuf = append(finalBuf, padded...)
					} else {
						finalBuf = append(finalBuf, rb...)
					}
				}
				dt.Writev(finalBuf)
			}
		}
	}()

	_, err := s.listShareNames(oversizedHostname, clientMaxShareResponseSize)
	require.Error(t, err)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	var ierr *InternalError
	require.ErrorAs(t, pathErr.Err, &ierr)
	require.Contains(t, ierr.Error(), "server name exceeds max MSRPC fragment size")
}

func TestCreatePermissionsAndOptions(t *testing.T) {
	t.Run("OpenFile_O_APPEND", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile("append.txt", os.O_WRONLY|os.O_APPEND, 0o666)
		require.Equal(t, uint32(smb2.FILE_APPEND_DATA|smb2.FILE_WRITE_EA|smb2.FILE_WRITE_ATTRIBUTES|smb2.READ_CONTROL|smb2.SYNCHRONIZE), gotAccess)
		require.Zero(t, gotOptions)
	})

	t.Run("Truncate_Options", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := smb2.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_ = f.fs.Truncate("test.txt", 0)
		require.Equal(t, uint32(smb2.FILE_WRITE_DATA), gotAccess)
		require.Equal(t, uint32(smb2.FILE_NON_DIRECTORY_FILE), gotOptions)
		require.Zero(t, gotOptions&smb2.FILE_SYNCHRONOUS_IO_NONALERT)
	})

	t.Run("ReadFile_GENERIC_READ", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotAccess  uint32
			gotOptions uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotAccess = cr.DesiredAccess()
			gotOptions = cr.CreateOptions()
			for off := 0; off < len(req); {
				p := smb2.PacketCodec(req[off:])
				sendTestResponse(dt, req[off:], &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_ACCESS_DENIED))
				next := p.NextCommand()
				if next == 0 {
					break
				}
				off += int(next)
			}
		}()

		_, _ = f.fs.ReadFile("test.txt")
		require.Equal(t, uint32(smb2.GENERIC_READ), gotAccess)
		require.Equal(t, uint32(smb2.FILE_NON_DIRECTORY_FILE), gotOptions)
	})

	t.Run("OpenFile_O_SYNC", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var gotOptions uint32
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile("sync.txt", os.O_WRONLY|os.O_SYNC, 0o666)
		require.Equal(t, uint32(smb2.FILE_WRITE_THROUGH), gotOptions)
	})

	t.Run("OpenFile_O_CREAT_O_EXCL", func(t *testing.T) {
		f, serverConn := newTestFile(t)
		defer serverConn.Close()
		var (
			gotDisposition uint32
			gotOptions     uint32
		)
		go func() {
			dt := direct(serverConn)
			req, err := readMsg(dt)
			if err != nil {
				return
			}
			cr := smb2.CreateRequestDecoder(req[64:])
			gotDisposition = cr.CreateDisposition()
			gotOptions = cr.CreateOptions()
			sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_ACCESS_DENIED))
		}()

		_, _ = f.fs.OpenFile("excl.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		require.Equal(t, uint32(smb2.FILE_CREATE), gotDisposition)
		require.Equal(t, uint32(smb2.FILE_OPEN_REPARSE_POINT), gotOptions)
	})
}
