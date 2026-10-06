package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	proto "github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestServerReadDirInvalidatesDisconnectedSession(t *testing.T) {
	t.Parallel()
	for _, timeout := range []time.Duration{0, clientSessionIdleTimeout} {
		t.Run(timeout.String(), func(t *testing.T) {
			ep := newClientTestEndpoint("server")
			d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(timeout))
			defer d.Close()
			ctx := context.Background()
			first, err := d.acquireSession(ctx, "server")
			if err != nil {
				t.Fatal(err)
			}
			first.release()
			share, err := d.acquireShare(ctx, "server", "share")
			if err != nil {
				t.Fatal(err)
			}
			share.session.release()
			ep.closeActivePeers()
			entries, err := d.WithContext(ctx).ReadDir("SERVER")
			var pathErr *os.PathError
			if entries != nil || !isUnavailable(err) || !errors.As(err, &pathErr) || pathErr.Op != "readdir" || pathErr.Path != "SERVER" {
				t.Fatalf("ReadDir=%v, %v; want readdir SERVER unavailable error", entries, err)
			}
			next, err := d.acquireSession(ctx, "server")
			if err != nil {
				t.Fatal(err)
			}
			defer next.release()
			if next == first {
				t.Fatal("server ReadDir left the disconnected generation cached")
			}
			// A delayed failure from the old generation must not retire next.
			d.invalidateSession("SERVER", first)
			d.mu.Lock()
			current, staleUsers := d.sessions[canonicalKey("server")], first.users
			_, staleShare := d.shares[shareKey("server", "share")]
			d.mu.Unlock()
			if current != next || staleUsers != 0 || staleShare {
				t.Fatalf("current=%p next=%p stale users=%d stale share=%t", current, next, staleUsers, staleShare)
			}
			ep.mu.Lock()
			dials := ep.dials
			ep.mu.Unlock()
			if dials != 2 {
				t.Fatalf("dials=%d, want 2", dials)
			}
		})
	}
}

func TestServerReadDirSessionFailureClassification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		status     erref.NtStatus
		cause      error
		invalidate bool
	}{
		{"permission", erref.STATUS_ACCESS_DENIED, erref.STATUS_ACCESS_DENIED, false},
		{"ordinary failure", erref.STATUS_UNSUCCESSFUL, erref.STATUS_UNSUCCESSFUL, false},
		{"canceled", erref.STATUS_ACCESS_DENIED, context.Canceled, false},
		{"deadline", erref.STATUS_ACCESS_DENIED, context.DeadlineExceeded, false},
		{"expired", erref.STATUS_NETWORK_SESSION_EXPIRED, erref.STATUS_NETWORK_SESSION_EXPIRED, true},
		{"deleted", erref.STATUS_USER_SESSION_DELETED, erref.STATUS_USER_SESSION_DELETED, true},
		{"disconnected", erref.STATUS_CONNECTION_DISCONNECTED, erref.STATUS_CONNECTION_DISCONNECTED, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				ep := newClientTestEndpoint("server")
				var pending []byte
				ep.handleRequest = func(conn net.Conn, request []byte) bool {
					p := proto.PacketCodec(request)
					if p.Command() == proto.SMB2_CANCEL {
						p = proto.PacketCodec(pending)
					} else if p.Command() != proto.SMB2_TREE_CONNECT {
						return false
					} else if tc.cause == context.Canceled || tc.cause == context.DeadlineExceeded {
						// Respond only after SMB2 CANCEL so the request cannot
						// consume the ordinary failure before its context error.
						pending = append([]byte(nil), request...)
						if tc.cause == context.Canceled {
							cancel()
						}
						return true
					}
					res := &proto.ErrorResponse{CommandCode: proto.SMB2_TREE_CONNECT}
					packet := make([]byte, res.Size())
					res.Encode(packet)
					out := proto.PacketCodec(packet)
					out.SetMessageId(p.MessageId())
					out.SetSessionId(p.SessionId())
					out.SetTreeId(p.TreeId())
					out.SetFlags(proto.SMB2_FLAGS_SERVER_TO_REDIR)
					out.SetCreditResponse(1)
					out.SetStatus(uint32(tc.status))
					if err := writeClientTestPacket(conn, packet); err != nil {
						t.Error(err)
					}
					return true
				}
				d := New(newClientTestDialer(&clientTestCredentials{}, ep), WithSessionIdleTimeout(0))
				defer d.Close()
				first, err := d.acquireSession(context.Background(), "server")
				if err != nil {
					t.Fatal(err)
				}
				first.release()
				entries, err := d.WithContext(ctx).ReadDir("SERVER")
				var pathErr *os.PathError
				if entries != nil || !errors.Is(err, tc.cause) || !errors.As(err, &pathErr) || pathErr.Op != "readdir" || pathErr.Path != "SERVER" {
					t.Fatalf("ReadDir=%v, %v; want readdir SERVER wrapping %v", entries, err, tc.cause)
				}
				next, err := d.acquireSession(context.Background(), "server")
				if err != nil {
					t.Fatal(err)
				}
				defer next.release()
				if (next != first) != tc.invalidate {
					t.Fatalf("generation changed=%t, want %t", next != first, tc.invalidate)
				}
				d.mu.Lock()
				users := first.users
				d.mu.Unlock()
				wantUsers := 1
				if tc.invalidate {
					wantUsers = 0
				}
				if users != wantUsers {
					t.Fatalf("old users=%d, want %d", users, wantUsers)
				}
			})
		})
	}
}

type lookupErrorCredentials struct{ err error }

func TestNestedInvalidErrorKeepsOperationContext(t *testing.T) {
	t.Parallel()
	inner := &os.PathError{Op: "open", Path: "share/file", Err: os.ErrInvalid}

	pathErr := fsError("stat", "server/share/file", inner)
	var gotPath *os.PathError
	if pathErr == os.ErrInvalid || !errors.As(pathErr, &gotPath) || gotPath.Op != "stat" || gotPath.Path != "server/share/file" {
		t.Fatalf("fsError = %v, want stat path error", pathErr)
	}

	linkErr := filesystemLinkError("rename", "old", "new", inner)
	var gotLink *os.LinkError
	if linkErr == os.ErrInvalid || !errors.As(linkErr, &gotLink) || gotLink.Op != "rename" || gotLink.Old != "old" || gotLink.New != "new" {
		t.Fatalf("filesystemLinkError = %v, want rename link error", linkErr)
	}
}

func (c lookupErrorCredentials) NewInitiator(context.Context, string) (auth.Initiator, error) {
	return nil, &os.PathError{Op: "authenticate", Path: "server", Err: c.err}
}

func TestGlobPropagatesContextLookupErrors(t *testing.T) {
	t.Parallel()
	for _, lookupErr := range []error{context.Canceled, context.DeadlineExceeded, os.ErrPermission} {
		for _, pattern := range []string{"server", "server/*", "server/share/*"} {
			t.Run(lookupErr.Error()+"/"+pattern, func(t *testing.T) {
				d := New(&v2.Dialer{Credentials: lookupErrorCredentials{lookupErr}})
				defer d.Close()
				// The caller's context is live: preserve the error returned by
				// the lookup, rather than only checking the caller's ctx.Err().
				matches, err := d.WithContext(context.Background()).Glob(pattern)
				if lookupErr == os.ErrPermission {
					if err != nil {
						t.Fatalf("Glob must ignore permission errors: %v", err)
					}
				} else if !errors.Is(err, lookupErr) {
					t.Fatalf("Glob error = %v, want %v", err, lookupErr)
				}
				if matches != nil {
					t.Fatalf("Glob matches = %v, want nil", matches)
				}
			})
		}
	}
}

func TestWithContextEmptyFS(t *testing.T) {
	t.Parallel()
	d := New(nil)
	defer d.Close()
	network := d.WithContext(context.Background())
	if err := fstest.TestFS(network); err != nil {
		t.Fatal(err)
	}
}

func TestWithContextCachedServersAndDirectoryCursor(t *testing.T) {
	t.Parallel()
	a, b := newClientTestEndpoint("alpha"), newClientTestEndpoint("beta")
	d := New(newClientTestDialer(&clientTestCredentials{}, a, b))
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := d.WithContext(ctx)
	if _, err := d.acquireSession(ctx, "BETA"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.acquireSession(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.acquireSession(ctx, "ALPHA"); err != nil {
		t.Fatal(err)
	}
	f, err := network.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := f.(fs.ReadDirFile)
	for _, name := range []string{"alpha", "beta"} {
		entries, err := reader.ReadDir(1)
		if err != nil || len(entries) != 1 || entries[0].Name() != name || !entries[0].IsDir() {
			t.Fatalf("ReadDir = %v, %v", entries, err)
		}
	}
	if _, err := reader.ReadDir(1); err != io.EOF {
		t.Fatalf("ReadDir EOF = %v", err)
	}
	if entries, err := reader.ReadDir(-1); err != nil || len(entries) != 0 {
		t.Fatalf("ReadDir all = %v, %v", entries, err)
	}
	matches, err := network.Glob("*")
	if err != nil || len(matches) != 2 || matches[0] != "alpha" || matches[1] != "beta" {
		t.Fatalf("Glob = %v, %v", matches, err)
	}
	for _, pattern := range []string{`\a*`, `[\a]lph[\a-\a]`, `alpha`} {
		matches, err := network.Glob(pattern)
		if err != nil || len(matches) != 1 || matches[0] != "alpha" {
			t.Fatalf("Glob(%q) = %v, %v", pattern, matches, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed Stat = %v", err)
	}
	if _, err := reader.ReadDir(1); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed ReadDir = %v", err)
	}
	// File.Close must not tear down a cached session.
	if _, err := network.Stat("alpha"); err != nil {
		t.Fatal(err)
	}
}

func TestWithContextInvalidPathsAndLifecycle(t *testing.T) {
	t.Parallel()
	d := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	network := d.WithContext(ctx)
	for _, name := range []string{"", "/server", "../server", "a/../b", `server\share`, "a//b"} {
		_, err := network.Open(name)
		if err != os.ErrInvalid {
			t.Fatalf("Open(%q) = %v", name, err)
		}
		if _, err := network.Sub(name); err != os.ErrInvalid {
			t.Fatalf("Sub(%q) = %v", name, err)
		}
	}
	cancel()
	if _, err := network.ReadDir("."); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ReadDir = %v", err)
	}
	network = d.WithContext(context.Background())
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := network.Open("."); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed Open = %v", err)
	}
	var nilClient *Client
	if _, err := nilClient.WithContext(context.Background()).Open("."); err != os.ErrInvalid {
		t.Fatalf("nil client = %v", err)
	}
}
func TestVirtualRootCloseReleasesOwnedSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ep1, ep2 := newClientTestEndpoint("alpha"), newClientTestEndpoint("beta")
	dialer := newClientTestDialer(&clientTestCredentials{}, ep1, ep2)
	dialer.DisableAAPLExtension = true
	d := New(dialer, WithSessionIdleTimeout(0))
	defer d.Close()
	for _, name := range []string{`\\alpha\share\file`, `\\beta\share\file`} {
		f, err := d.Open(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	network := d.WithContext(ctx)
	first, err := network.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	second, err := network.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	directory := first.(*virtualDirectory)
	returned, err := directory.ReadDir(1)
	if err != nil || len(returned) != 1 {
		t.Fatalf("ReadDir=%v,%v", returned, err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if directory.entries != nil {
		t.Fatalf("closed root retains %d snapshot entries", len(directory.entries))
	}
	if returned[0].Name() != "alpha" {
		t.Fatalf("returned entry changed: %s", returned[0].Name())
	}
	if err = first.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("second Close=%v", err)
	}
	independent, err := second.(fs.ReadDirFile).ReadDir(-1)
	if err != nil || len(independent) != 2 || independent[0].Name() != "alpha" || independent[1].Name() != "beta" {
		t.Fatalf("independent snapshot=%v,%v", independent, err)
	}
	current, err := network.ReadDir(".")
	if err != nil || len(current) != 2 {
		t.Fatalf("client cache listing=%v,%v", current, err)
	}
}

func TestVirtualServerClosePreservesReturnedAndIndependentEntries(t *testing.T) {
	// Server-directory snapshots contain share names returned by ListShareNames.
	entries := []fs.DirEntry{fs.FileInfoToDirEntry(virtualInfo("share-a")), fs.FileInfoToDirEntry(virtualInfo("share-b"))}
	first := &virtualDirectory{name: "server", info: virtualInfo("server"), entries: append([]fs.DirEntry(nil), entries...)}
	second := &virtualDirectory{name: "server", info: virtualInfo("server"), entries: append([]fs.DirEntry(nil), entries...)}
	returned, err := first.ReadDir(1)
	if err != nil || len(returned) != 1 {
		t.Fatalf("ReadDir=%v,%v", returned, err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if first.entries != nil {
		t.Fatalf("closed server retains %d snapshot entries", len(first.entries))
	}
	if returned[0].Name() != "share-a" || entries[0].Name() != "share-a" {
		t.Fatal("Close changed borrowed entry values")
	}
	info, err := returned[0].Info()
	if err != nil || info.Name() != "share-a" {
		t.Fatalf("returned Info=%v,%v", info, err)
	}
	if err = first.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("second Close=%v", err)
	}
	if _, err = first.ReadDir(1); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed ReadDir=%v", err)
	}
	remaining, err := second.ReadDir(-1)
	if err != nil || len(remaining) != 2 || remaining[0].Name() != "share-a" || remaining[1].Name() != "share-b" {
		t.Fatalf("independent snapshot=%v,%v", remaining, err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
}
func readDirConversionFixture(tb testing.TB, count int, ending erref.NtStatus) *boundClient {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	ep := newClientTestEndpoint("server")
	var pages []clientTestBytes
	for start := 0; start < count; start += 256 {
		names := make([]string, min(256, count-start))
		for i := range names {
			names[i] = fmt.Sprintf("entry-%05d", count-1-start-i)
		}
		pages = append(pages, clientTestDirectoryPage(names...))
	}
	cursor := 0
	ep.handleRequest = func(conn net.Conn, request []byte) bool {
		p := proto.PacketCodec(request)
		var packet proto.Packet
		var status erref.NtStatus
		switch p.Command() {
		case proto.SMB2_CREATE:
			cursor = 0
			packet = &proto.CreateResponse{FileAttributes: proto.FILE_ATTRIBUTE_DIRECTORY, FileId: proto.FileId{Persistent: [8]byte{1}, Volatile: [8]byte{1}}}
		case proto.SMB2_QUERY_DIRECTORY:
			if cursor == len(pages) {
				packet = &proto.ErrorResponse{CommandCode: p.Command()}
				status = ending
			} else {
				packet = &proto.QueryDirectoryResponse{Output: pages[cursor]}
				cursor++
			}
		default:
			return false
		}
		if err := externalWriteResponse(conn, request, packet, status, p.SessionId(), p.TreeId()); err != nil {
			tb.Error(err)
			_ = conn.Close()
		}
		return true
	}
	dialer := newClientTestDialer(&clientTestCredentials{}, ep)
	dialer.DisableAAPLExtension = true
	dialer.MaxCreditBalance = 1
	d := New(dialer, WithSessionIdleTimeout(0))
	tb.Cleanup(func() {
		if err := d.Close(); err != nil {
			tb.Error(err)
		}
		cancel()
	})
	return d.WithContext(ctx).(*boundClient)
}

func TestReadDirConversionResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		count  int
		status erref.NtStatus
	}{{"empty", 0, erref.STATUS_NO_MORE_FILES}, {"sorted", 3, erref.STATUS_NO_MORE_FILES}, {"partial error", 3, erref.STATUS_IO_DEVICE_ERROR}} {
		t.Run(tc.name, func(t *testing.T) {
			network := readDirConversionFixture(t, tc.count, tc.status)
			entries, err := network.ReadDir("server/share/dir")
			if tc.status == erref.STATUS_IO_DEVICE_ERROR {
				if !errors.Is(err, tc.status) {
					t.Fatalf("ReadDir error=%v", err)
				}
				var pe *os.PathError
				if !errors.As(err, &pe) || pe.Op != "readdir" || pe.Path != "server/share/dir" {
					t.Fatalf("ReadDir attribution=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if entries == nil || len(entries) != tc.count {
				t.Fatalf("ReadDir=%v; want nonnil %d entries", entries, tc.count)
			}
			for i, entry := range entries {
				want := fmt.Sprintf("entry-%05d", i)
				if entry.Name() != want {
					t.Fatalf("entry %d=%q, want %q", i, entry.Name(), want)
				}
				info, err := entry.Info()
				if err != nil || info.Name() != want {
					t.Fatalf("Info=%v,%v", info, err)
				}
			}
			if len(entries) > 0 {
				saved := entries[0]
				entries[0] = nil
				next, _ := network.ReadDir("server/share/dir")
				if len(next) != tc.count || next[0].Name() != saved.Name() {
					t.Fatal("independent listing changed with returned slice")
				}
			}
		})
	}
}

func BenchmarkClientReadDirConversion(b *testing.B) {
	for _, count := range []int{32, 8192} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			network := readDirConversionFixture(b, count, erref.STATUS_NO_MORE_FILES)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				entries, err := network.ReadDir("server/share/dir")
				if err != nil || len(entries) != count {
					b.Fatalf("ReadDir count=%d, error=%v", len(entries), err)
				}
			}
		})
	}
}
