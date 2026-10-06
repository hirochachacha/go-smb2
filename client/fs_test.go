package client

import (
	"context"
	"errors"
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
