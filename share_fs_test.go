package smb2

import (
	"errors"
	iofs "io/fs"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
)

func TestDirFS(t *testing.T) {
	share := &Share{}

	fs := share.DirFS(`dir/`).(*wfs)
	if got, want := fs.root, `dir`; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
	if got, want := fs.path(`file.txt`), `dir\file.txt`; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	fs = share.DirFS(`dir\`).(*wfs)
	if got, want := fs.root, `dir`; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
	if got, want := fs.path(`file.txt`), `dir\file.txt`; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	fs = share.DirFS(`/`).(*wfs)
	if got, want := fs.root, ``; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
}

func TestDirFSRejectsBackslashPath(t *testing.T) {
	share := &Share{}

	for _, root := range []string{`dir/`, ``} {
		fs := share.DirFS(root)

		for _, name := range []string{`sub\..\secret`, `sub\secret`} {
			if _, err := fs.Open(name); !errors.Is(err, iofs.ErrInvalid) {
				t.Errorf("Open(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
			}
			if rfs, ok := fs.(iofs.ReadDirFS); ok {
				if _, err := rfs.ReadDir(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadDir(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.ReadDirFS")
			}
			if rfs, ok := fs.(iofs.ReadFileFS); ok {
				if _, err := rfs.ReadFile(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadFile(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.ReadFileFS")
			}
			if rfs, ok := fs.(iofs.ReadLinkFS); ok {
				if _, err := rfs.ReadLink(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadLink(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.ReadLinkFS")
			}
			if sfs, ok := fs.(iofs.StatFS); ok {
				if _, err := sfs.Stat(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("Stat(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.StatFS")
			}
			if gfs, ok := fs.(iofs.GlobFS); ok {
				if _, err := gfs.Glob(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("Glob(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("DirFS does not implement iofs.GlobFS")
			}
		}
	}
}

func TestDirFSPatternMetaCharacters(t *testing.T) {
	share := &Share{}

	tests := []struct {
		root     string
		pattern  string
		expected string
	}{
		{`dir[1]`, `*.txt`, `dir[[]1]\*.txt`},
		{`dir*`, `*.txt`, `dir[*]\*.txt`},
		{`dir?`, `*.txt`, `dir[?]\*.txt`},
		{`a[b*c?d]`, `file.txt`, `a[[]b[*]c[?]d]\file.txt`},
		{`normal`, `*.txt`, `normal\*.txt`},
		{``, `*.txt`, `*.txt`},
	}

	for _, tc := range tests {
		fs := share.DirFS(tc.root).(*wfs)
		got := fs.pattern(tc.pattern)
		if got != tc.expected {
			t.Errorf("root=%q pattern=%q: got %q, want %q", tc.root, tc.pattern, got, tc.expected)
		}
	}

	// Verify that escaped root matches literal directory and does not match wildcard expansion
	fsBracket := share.DirFS(`dir[1]`).(*wfs)
	patBracket := fsBracket.pattern(`*.txt`)
	if matched, err := Match(patBracket, `dir[1]\test.txt`); err != nil || !matched {
		t.Errorf("Match(%q, %q) = %v, %v; want true, nil", patBracket, `dir[1]\test.txt`, matched, err)
	}
	if matched, err := Match(patBracket, `dir1\test.txt`); err != nil || matched {
		t.Errorf("Match(%q, %q) = %v, %v; want false, nil", patBracket, `dir1\test.txt`, matched, err)
	}
}

func TestDirFSGlobPrefixValidation(t *testing.T) {
	// Test prefix validation and trimming helper
	matches := []string{
		`dir\file1.txt`,
		`other\file2.txt`,
		`dir\sub\file3.txt`,
		`d`,
		`dir`,
	}

	got := cleanMatches(matches, `dir`)
	want := []string{
		`file1.txt`,
		`sub/file3.txt`,
	}

	if len(got) != len(want) {
		t.Fatalf("cleanMatches len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cleanMatches[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Empty root converts SMB separators to io/fs separators.
	orig := []string{`a.txt`, `sub\b.txt`}
	if gotEmpty := cleanMatches(orig, ``); gotEmpty[1] != `sub/b.txt` {
		t.Errorf("cleanMatches with empty root returned %v, want slash separators", gotEmpty)
	}
}

func TestDirFSGlobResultsOpen(t *testing.T) {
	share, serverConn := newTestShare(t)
	queryCount := 0

	onQueryDir := func(msgID uint64, reqBuf []byte, dt transport) bool {
		queryCount++
		p := smb2.PacketCodec(reqBuf)
		if queryCount%2 == 1 {
			query := &smb2.QueryDirectoryResponse{
				Output: rawEncoder(encodeFileIdBothDirectoryInformation("file.txt")),
			}
			buf := make([]byte, query.Size())
			query.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			_, _ = dt.Writev(buf)
			return true
		}

		errRes := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
		buf := make([]byte, errRes.Size())
		errRes.Encode(buf)
		rp := smb2.PacketCodec(buf)
		rp.SetMessageId(msgID)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		rp.SetCreditResponse(1)
		rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		_, _ = dt.Writev(buf)
		return true
	}

	onQueryInfo := func(msgID uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], smb2.FILE_ATTRIBUTE_DIRECTORY)
		query := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, query.Size())
		query.Encode(buf)
		return buf
	}
	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	for _, root := range []string{"", "root"} {
		dirFS := share.DirFS(root)
		for _, pattern := range []string{"sub/file.txt", "sub/*"} {
			matches, err := iofs.Glob(dirFS, pattern)
			if err != nil {
				t.Fatalf("DirFS(%q).Glob(%q): %v", root, pattern, err)
			}
			want := []string{"sub/file.txt"}
			if len(matches) != 1 || matches[0] != want[0] {
				t.Fatalf("DirFS(%q).Glob(%q) = %v, want %v", root, pattern, matches, want)
			}
			file, err := dirFS.Open(matches[0])
			if err != nil {
				t.Fatalf("DirFS(%q).Open(%q): %v", root, matches[0], err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("DirFS(%q).Open(%q).Close(): %v", root, matches[0], err)
			}
		}
	}
}

// serverSearchMatch models only the '*' and '?' wildcards used by this test,
// not the DOS wildcards also defined in [MS-FSA] 2.1.4.4. Brackets are literal;
// it must not delegate to the client's character-class-aware Match.
func serverSearchMatch(pattern, name string) bool {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String()).MatchString(name)
}

// TestDirFSGlobBracketInRoot is a regression test for a root directory whose
// name contains '['. DirFS escapes the root to "dir[[]1]\*", and the parent
// search must be widened to "dir?1]" because the server treats '[' literally
// ([MS-FSA] 2.1.4.4). The returned names are still filtered with the original
// bracket class, so a sibling such as "dirX1]" is excluded.
func TestDirFSGlobBracketInRoot(t *testing.T) {
	share, serverConn := newTestShare(t)

	// Contents are keyed by directory, independently of the search pattern.
	dirContents := map[string][]string{
		``:       {`dir[1]`, `dirX1]`, `dir1`},
		`dir[1]`: {`file.txt`},
		`dirX1]`: {`wrong.txt`},
		`dir1`:   {`other.txt`},
	}

	var mu sync.Mutex
	var sentPatterns []string
	queries := make(map[string]int)
	openedPaths := make(map[string]int)
	handlePaths := make(map[smb2.FileId]string)

	onQueryDir := func(msgID uint64, reqBuf []byte, dt transport) bool {
		p := smb2.PacketCodec(reqBuf)
		qreq := smb2.QueryDirectoryRequestDecoder(reqBuf[64:])
		if qreq.IsInvalid() {
			t.Error("invalid QUERY_DIRECTORY request")
			sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_INVALID_PARAMETER))
			return true
		}
		currentPath, ok := handlePaths[*qreq.FileId().Decode()]
		if !ok {
			t.Error("QUERY_DIRECTORY used an unknown handle")
			sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_INVALID_PARAMETER))
			return true
		}
		fno, fnl := qreq.FileNameOffset(), qreq.FileNameLength()
		pattern := utf16le.DecodeToString(reqBuf[int(fno) : int(fno)+int(fnl)])

		mu.Lock()
		sentPatterns = append(sentPatterns, pattern)
		queryKey := currentPath + `\` + pattern
		queries[queryKey]++
		n := queries[queryKey]
		mu.Unlock()

		writeEntries := func(names []string) {
			res := &smb2.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformations(names))}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(buf)
		}
		writeError := func(status uint32) {
			res := &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := smb2.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(status)
			rp.SetCreditResponse(1)
			rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
			dt.Writev(buf)
		}

		if n > 1 {
			writeError(uint32(erref.STATUS_NO_MORE_FILES))
			return true
		}

		var matched []string
		for _, name := range dirContents[currentPath] {
			if serverSearchMatch(pattern, name) {
				matched = append(matched, name)
			}
		}
		if len(matched) == 0 {
			writeError(uint32(erref.STATUS_NO_SUCH_FILE))
			return true
		}
		writeEntries(matched)
		return true
	}

	onQueryInfo := func(msgID uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], smb2.FILE_ATTRIBUTE_DIRECTORY)
		res := &smb2.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		return buf
	}

	go func() {
		dt := direct(serverConn)
		var nextID uint64
		for {
			packet, err := readMsg(dt)
			if err != nil {
				return
			}
			for len(packet) > 0 {
				p := smb2.PacketCodec(packet)
				if p.IsInvalid() {
					t.Error("invalid directory test request header")
					return
				}
				next := uint64(p.NextCommand())
				if next != 0 && (next < 64 || next > uint64(len(packet)) || next%8 != 0) {
					t.Error("invalid compound request boundary")
					return
				}
				reqBuf := packet
				if next != 0 {
					reqBuf = packet[:int(next)]
				}
				switch p.Command() {
				case smb2.SMB2_CREATE:
					req := smb2.CreateRequestDecoder(reqBuf[64:])
					if req.IsInvalid() {
						t.Error("invalid CREATE request")
						return
					}
					off, size := int(req.NameOffset()), int(req.NameLength())
					name := utf16le.DecodeToString(reqBuf[off : off+size])
					_, isDir := dirContents[name]
					if !isDir && name != `dir[1]\file.txt` {
						sendTestResponse(dt, reqBuf, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
						break
					}
					nextID++
					id := smb2.FileId{}
					le.PutUint64(id.Persistent[:], nextID)
					handlePaths[id] = name
					mu.Lock()
					openedPaths[name]++
					mu.Unlock()
					attrs := uint32(smb2.FILE_ATTRIBUTE_NORMAL)
					if isDir {
						attrs = smb2.FILE_ATTRIBUTE_DIRECTORY
					}
					sendTestResponse(dt, reqBuf, &smb2.CreateResponse{
						CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
						LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
						FileId: &id, FileAttributes: attrs,
					}, 0)
				case smb2.SMB2_QUERY_DIRECTORY:
					onQueryDir(p.MessageId(), reqBuf, dt)
				case smb2.SMB2_QUERY_INFO:
					buf := onQueryInfo(p.MessageId(), reqBuf)
					rp := smb2.PacketCodec(buf)
					rp.SetMessageId(p.MessageId())
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
					dt.Writev(buf)
				case smb2.SMB2_CLOSE:
					sendTestResponse(dt, reqBuf, &smb2.CloseResponse{
						CreationTime: &smb2.Filetime{}, LastAccessTime: &smb2.Filetime{},
						LastWriteTime: &smb2.Filetime{}, ChangeTime: &smb2.Filetime{},
					}, 0)
				default:
					t.Errorf("unexpected directory test command: %d", p.Command())
					return
				}
				if next == 0 {
					break
				}
				packet = packet[int(next):]
			}
		}
	}()

	dirFS := share.DirFS(`dir[1]`)
	matches, err := iofs.Glob(dirFS, `*`)
	if err != nil {
		t.Fatalf("DirFS(`dir[1]`).Glob(`*`) returned error: %v", err)
	}
	if len(matches) != 1 || matches[0] != "file.txt" {
		t.Fatalf("DirFS(`dir[1]`).Glob(`*`) = %v, want [file.txt]", matches)
	}

	file, err := dirFS.Open(matches[0])
	if err != nil {
		t.Fatalf("DirFS(`dir[1]`).Open(%q): %v", matches[0], err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("DirFS(`dir[1]`).Open(%q).Close(): %v", matches[0], err)
	}

	mu.Lock()
	defer mu.Unlock()
	if openedPaths[`dirX1]`] != 0 || openedPaths[`dir1`] != 0 {
		t.Errorf("unmatched siblings were opened: %v", openedPaths)
	}
	if openedPaths[`dir[1]\file.txt`] != 1 {
		t.Errorf("Glob result did not open the expected file: %v", openedPaths)
	}
	foundParent := false
	for _, pattern := range sentPatterns {
		if pattern == `dir?1]` {
			foundParent = true
		}
		if pattern == `dir[[]1]` {
			t.Errorf("parent search sent escaped literal %q instead of a widened pattern", pattern)
		}
	}
	if !foundParent {
		t.Errorf("parent search patterns = %v, want one of them to be %q", sentPatterns, `dir?1]`)
	}
}
