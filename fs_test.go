package smb2

import (
	"context"
	"errors"
	iofs "io/fs"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func contextSubShare(share *Share, root string) iofs.FS {
	bound := share.WithContext(context.Background())
	fs, err := iofs.Sub(bound, root)
	if err != nil {
		panic(err)
	}
	return fs
}

func TestContextShare(t *testing.T) {
	t.Parallel()
	share := &Share{}

	fs := contextSubShare(share, `dir`).(*boundShare)
	if got, want := fs.root, `dir`; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}
	if got, want := fs.path(`file.txt`), `dir\file.txt`; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}

	fs = contextSubShare(share, `.`).(*boundShare)
	if got, want := fs.root, ``; got != want {
		t.Errorf("root = %q, want %q", got, want)
	}

	for _, root := range []string{`dir/`, `dir\`, `/`} {
		if _, err := iofs.Sub(share.WithContext(context.Background()), root); !errors.Is(err, iofs.ErrInvalid) {
			t.Errorf("Sub(%q) err = %v, want %v", root, err, iofs.ErrInvalid)
		}
	}
}

func TestContextShareRejectsBackslashPath(t *testing.T) {
	t.Parallel()
	share := &Share{}

	for _, root := range []string{`dir`, `.`} {
		fs := contextSubShare(share, root)

		for _, name := range []string{`sub\..\secret`, `sub\secret`} {
			if _, err := fs.Open(name); !errors.Is(err, iofs.ErrInvalid) {
				t.Errorf("Open(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
			}
			if rfs, ok := fs.(iofs.ReadDirFS); ok {
				if _, err := rfs.ReadDir(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadDir(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("ContextShare does not implement iofs.ReadDirFS")
			}
			if rfs, ok := fs.(iofs.ReadFileFS); ok {
				if _, err := rfs.ReadFile(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadFile(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("ContextShare does not implement iofs.ReadFileFS")
			}
			if rfs, ok := fs.(iofs.ReadLinkFS); ok {
				if _, err := rfs.ReadLink(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("ReadLink(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("ContextShare does not implement iofs.ReadLinkFS")
			}
			if sfs, ok := fs.(iofs.StatFS); ok {
				if _, err := sfs.Stat(name); !errors.Is(err, iofs.ErrInvalid) {
					t.Errorf("Stat(%q) err = %v, want %v", name, err, iofs.ErrInvalid)
				}
			} else {
				t.Error("ContextShare does not implement iofs.StatFS")
			}

		}
	}
}

func TestContextShareGlobResultsOpen(t *testing.T) {
	t.Parallel()
	share, serverConn := newTestShare(t)
	queryCount := 0

	onQueryDir := func(msgID uint64, reqBuf []byte, dt net.Conn) bool {
		queryCount++
		p := wire.PacketCodec(reqBuf)
		if queryCount%2 == 1 {
			query := &wire.QueryDirectoryResponse{
				Output: rawEncoder(encodeFileIdBothDirectoryInformation("file.txt")),
			}
			buf := make([]byte, query.Size())
			query.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			_, _ = testWritePacket(dt, buf)
			return true
		}

		errRes := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
		buf := make([]byte, errRes.Size())
		errRes.Encode(buf)
		rp := wire.PacketCodec(buf)
		rp.SetMessageId(msgID)
		rp.SetSessionId(p.SessionId())
		rp.SetTreeId(p.TreeId())
		rp.SetStatus(uint32(erref.STATUS_NO_MORE_FILES))
		rp.SetCreditResponse(1)
		rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
		_, _ = testWritePacket(dt, buf)
		return true
	}

	onQueryInfo := func(msgID uint64, reqBuf []byte) []byte {
		info := make([]byte, 104)
		le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
		query := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, query.Size())
		query.Encode(buf)
		return buf
	}
	startFullFakeServer(serverConn, onQueryDir, nil, onQueryInfo)

	for _, root := range []string{".", "root"} {
		dirFS := contextSubShare(share, root)
		for _, pattern := range []string{"sub/file.txt", "sub/*", `sub/f\ile.txt`, `sub/[\f]ile.txt`, `sub/[\f-\f]ile.txt`} {
			matches, err := iofs.Glob(dirFS, pattern)
			if err != nil {
				t.Fatalf("ContextShare(%q).Glob(%q): %v", root, pattern, err)
			}
			want := []string{"sub/file.txt"}
			if len(matches) != 1 || matches[0] != want[0] {
				t.Fatalf("ContextShare(%q).Glob(%q) = %v, want %v", root, pattern, matches, want)
			}
			file, err := dirFS.Open(matches[0])
			if err != nil {
				t.Fatalf("ContextShare(%q).Open(%q): %v", root, matches[0], err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("ContextShare(%q).Open(%q).Close(): %v", root, matches[0], err)
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

// TestContextShareGlobBracketInRoot is a regression test for a root directory whose
// name contains '['. ContextShare escapes the root to "dir[[]1]\*", and the parent
// search must be widened to "dir?1]" because the server treats '[' literally
// ([MS-FSA] 2.1.4.4). The returned names are still filtered with the original
// bracket class, so a sibling such as "dirX1]" is excluded.
func TestContextShareGlobBracketInRoot(t *testing.T) {
	t.Parallel()
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
	handlePaths := make(map[wire.FileId]string)

	onQueryDir := func(msgID uint64, reqBuf []byte, dt net.Conn) bool {
		p := wire.PacketCodec(reqBuf)
		qreq := wire.QueryDirectoryRequestDecoder(reqBuf[64:])
		if qreq.IsInvalid() {
			t.Error("invalid QUERY_DIRECTORY request")
			sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_INVALID_PARAMETER))
			return true
		}
		currentPath, ok := handlePaths[*qreq.FileId().Decode()]
		if !ok {
			t.Error("QUERY_DIRECTORY used an unknown handle")
			sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_INVALID_PARAMETER))
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
			res := &wire.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformations(names))}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
		}
		writeError := func(status uint32) {
			res := &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_DIRECTORY}
			buf := make([]byte, res.Size())
			res.Encode(buf)
			rp := wire.PacketCodec(buf)
			rp.SetMessageId(msgID)
			rp.SetSessionId(p.SessionId())
			rp.SetTreeId(p.TreeId())
			rp.SetStatus(status)
			rp.SetCreditResponse(1)
			rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			testWritePacket(dt, buf)
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
		le.PutUint32(info[32:36], wire.FILE_ATTRIBUTE_DIRECTORY)
		res := &wire.QueryInfoResponse{Output: rawEncoder(info)}
		buf := make([]byte, res.Size())
		res.Encode(buf)
		return buf
	}

	go func() {
		dt := serverConn
		var nextID uint64
		for {
			packet, err := readMsg(dt)
			if err != nil {
				return
			}
			for len(packet) > 0 {
				p := wire.PacketCodec(packet)
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
				case wire.SMB2_CREATE:
					req := wire.CreateRequestDecoder(reqBuf[64:])
					if req.IsInvalid() {
						t.Error("invalid CREATE request")
						return
					}
					off, size := int(req.NameOffset()), int(req.NameLength())
					name := utf16le.DecodeToString(reqBuf[off : off+size])
					_, isDir := dirContents[name]
					if !isDir && name != `dir[1]\file.txt` {
						sendTestResponse(dt, reqBuf, &wire.ErrorResponse{CommandCode: wire.SMB2_CREATE}, uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND))
						break
					}
					nextID++
					id := wire.FileId{}
					le.PutUint64(id.Persistent[:], nextID)
					handlePaths[id] = name
					mu.Lock()
					openedPaths[name]++
					mu.Unlock()
					attrs := uint32(wire.FILE_ATTRIBUTE_NORMAL)
					if isDir {
						attrs = wire.FILE_ATTRIBUTE_DIRECTORY
					}
					sendTestResponse(dt, reqBuf, &wire.CreateResponse{
						CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
						LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
						FileId: &id, FileAttributes: attrs,
					}, 0)
				case wire.SMB2_QUERY_DIRECTORY:
					onQueryDir(p.MessageId(), reqBuf, dt)
				case wire.SMB2_QUERY_INFO:
					buf := onQueryInfo(p.MessageId(), reqBuf)
					rp := wire.PacketCodec(buf)
					rp.SetMessageId(p.MessageId())
					rp.SetSessionId(p.SessionId())
					rp.SetTreeId(p.TreeId())
					rp.SetCreditResponse(1)
					rp.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
					testWritePacket(dt, buf)
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, reqBuf, &wire.CloseResponse{
						CreationTime: &wire.Filetime{}, LastAccessTime: &wire.Filetime{},
						LastWriteTime: &wire.Filetime{}, ChangeTime: &wire.Filetime{},
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

	dirFS := contextSubShare(share, `dir[1]`)
	matches, err := iofs.Glob(dirFS, `*`)
	if err != nil {
		t.Fatalf("ContextShare(`dir[1]`).Glob(`*`) returned error: %v", err)
	}
	if len(matches) != 1 || matches[0] != "file.txt" {
		t.Fatalf("ContextShare(`dir[1]`).Glob(`*`) = %v, want [file.txt]", matches)
	}

	file, err := dirFS.Open(matches[0])
	if err != nil {
		t.Fatalf("ContextShare(`dir[1]`).Open(%q): %v", matches[0], err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("ContextShare(`dir[1]`).Open(%q).Close(): %v", matches[0], err)
	}

	mu.Lock()
	defer mu.Unlock()
	if openedPaths[`dirX1]`] != 0 || openedPaths[`dir1`] != 0 {
		t.Errorf("unmatched siblings were opened: %v", openedPaths)
	}
	if openedPaths[`dir[1]\file.txt`] != 1 {
		t.Errorf("Glob result did not open the expected file: %v", openedPaths)
	}
	for _, pattern := range sentPatterns {
		if pattern != "*" {
			t.Errorf("literal root must not be glob-expanded: search pattern %q", pattern)
		}
	}

}
