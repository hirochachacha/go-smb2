package smb2

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
)

// TestGlobKeepsMatchesAfterNoSuchFile verifies that Glob keeps matches from
// earlier directories when a later directory ends its enumeration with
// STATUS_NO_SUCH_FILE (no entry matches the search pattern).
func TestGlobKeepsMatchesAfterNoSuchFile(t *testing.T) {
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
	go c.runReceiver()

	tc := &treeConn{session: c.session, treeId: 0x200}
	fs := &Share{treeConn: tc, ctx: context.Background()}

	// Per-pattern query counters emulating:
	//   dir1 contains "ab1.ext" (and non-matching "zz.txt")
	//   dir2 contains no file matching "ab?.ext" -> readdir ends with STATUS_NO_SUCH_FILE
	queries := make(map[string]int)

	onQueryDir := func(msgId uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		qreq := smb2.QueryDirectoryRequestDecoder(reqBuf[64:])
		fno, fnl := qreq.FileNameOffset(), qreq.FileNameLength()
		pattern := utf16le.DecodeToString(reqBuf[int(fno) : int(fno)+int(fnl)])
		queries[pattern]++
		n := queries[pattern]

		writeEntry := func(name string) {
			entry := encodeFileIdBothDirectoryInformation(name)
			res := &smb2.QueryDirectoryResponse{Output: rawEncoder(entry)}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Write(buf)
		}
		writeError := func(status uint32) {
			res := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgId)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(status)
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Write(buf)
		}

		switch pattern {
		case `dir*`:
			switch n {
			case 1:
				writeEntry("dir1")
			case 2:
				writeEntry("dir2")
			default:
				writeError(uint32(erref.STATUS_NO_MORE_FILES))
			}
		case `ab?.ext`:
			switch n {
			case 1: // dir1: one matching entry
				writeEntry("ab1.ext")
			case 2: // dir1: end of enumeration
				writeError(uint32(erref.STATUS_NO_MORE_FILES))
			default: // dir2: no matching entry
				writeError(uint32(erref.STATUS_NO_SUCH_FILE))
			}
		default:
			writeError(uint32(erref.STATUS_NO_MORE_FILES))
		}
		return true
	}

	onQueryInfo := func(msgId uint64, reqBuf []byte) []byte {
		// FileAllInformation with FILE_ATTRIBUTE_DIRECTORY
		info := make([]byte, 104)
		le.PutUint32(info[32:36], smb2.FILE_ATTRIBUTE_DIRECTORY)
		res := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		return buf
	}

	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	matches, err := fs.Glob(`dir*\ab?.ext`)
	if err != nil {
		t.Fatalf("Glob returned error: %v", err)
	}

	expected := []string{`dir1\ab1.ext`}
	if !reflect.DeepEqual(matches, expected) {
		t.Errorf("Glob(`dir*\\ab?.ext`) = %v, want %v (matches from dir1 must survive STATUS_NO_SUCH_FILE from dir2)", matches, expected)
	}
}

func TestSimplifyPattern(t *testing.T) {
	cases := [][2]string{
		{"test.ext", "test.ext"},
		{"ab[0-9].ext", "ab?.ext"},
		{"tes?", "tes?"},
	}

	for _, tt := range cases {
		if simplifyPattern(tt[0]) != tt[1] {
			t.Errorf("simplifyPattern(%q) = %q, want %q", tt[0], simplifyPattern(tt[0]), tt[1])
		}
	}
}

func TestMatch(t *testing.T) {
	type matchTest struct {
		pattern, s string
		match      bool
		err        error
	}

	var cases = []matchTest{
		{"abc", "abc", true, nil},
		{"*", "abc", true, nil},
		{"*c", "abc", true, nil},
		{"a*", "a", true, nil},
		{"a*", "abc", true, nil},
		{"a*", "ab/c", false, nil},
		{"a*/b", "abc/b", true, nil},
		{"a*/b", "a/c/b", false, nil},
		{"a*b*c*d*e*/f", "axbxcxdxe/f", true, nil},
		{"a*b*c*d*e*/f", "axbxcxdxexxx/f", true, nil},
		{"a*b*c*d*e*/f", "axbxcxdxe/xxx/f", false, nil},
		{"a*b*c*d*e*/f", "axbxcxdxexxx/fff", false, nil},
		{"a*b?c*x", "abxbbxdbxebxczzx", true, nil},
		{"a*b?c*x", "abxbbxdbxebxczzy", false, nil},
		{"ab[c]", "abc", true, nil},
		{"ab[b-d]", "abc", true, nil},
		{"ab[e-g]", "abc", false, nil},
		{"ab[^c]", "abc", false, nil},
		{"ab[^b-d]", "abc", false, nil},
		{"ab[^e-g]", "abc", true, nil},
		{"a?b", "a☺b", true, nil},
		{"a[^a]b", "a☺b", true, nil},
		{"a???b", "a☺b", false, nil},
		{"a[^a][^a][^a]b", "a☺b", false, nil},
		{"[a-ζ]*", "α", true, nil},
		{"*[a-ζ]", "A", false, nil},
		{"a?b", "a/b", false, nil},
		{"a*b", "a/b", false, nil},
		{"[]a]", "]", false, ErrBadPattern},
		{"[-]", "-", false, ErrBadPattern},
		{"[x-]", "x", false, ErrBadPattern},
		{"[x-]", "-", false, ErrBadPattern},
		{"[x-]", "z", false, ErrBadPattern},
		{"[-x]", "x", false, ErrBadPattern},
		{"[-x]", "-", false, ErrBadPattern},
		{"[-x]", "a", false, ErrBadPattern},
		{"[a-b-c]", "a", false, ErrBadPattern},
		{"[", "a", false, ErrBadPattern},
		{"[^", "a", false, ErrBadPattern},
		{"[^bc", "a", false, ErrBadPattern},
		{"a[", "a", false, ErrBadPattern},
		{"a[", "ab", false, ErrBadPattern},
		{"a[", "x", false, ErrBadPattern},
		{"a/b[", "x", false, ErrBadPattern},
		{"*x", "xxx", true, nil},
	}

	errp := func(e error) string {
		if e == nil {
			return "<nil>"
		}
		return e.Error()
	}

	for _, tt := range cases {
		pattern := tt.pattern
		s := strings.Replace(tt.s, `/`, `\`, -1)
		ok, err := Match(pattern, s)
		if ok != tt.match || err != tt.err {
			t.Errorf("Match(%#q, %#q) = %v, %q want %v, %q", pattern, s, ok, errp(err), tt.match, errp(tt.err))
		}
	}
}
