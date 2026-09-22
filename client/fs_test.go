package client

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"testing"
	"testing/fstest"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
)

type lookupErrorCredentials struct{ err error }

func (c lookupErrorCredentials) NewInitiator(context.Context, string) (auth.Initiator, error) {
	return nil, &fs.PathError{Op: "authenticate", Path: "server", Err: c.err}
}

func TestGlobPropagatesContextLookupErrors(t *testing.T) {
	for _, lookupErr := range []error{context.Canceled, context.DeadlineExceeded, fs.ErrPermission} {
		for _, pattern := range []string{"server", "server/*", "server/share/*"} {
			t.Run(lookupErr.Error()+"/"+pattern, func(t *testing.T) {
				d := New(&v2.Dialer{Credentials: lookupErrorCredentials{lookupErr}})
				defer d.Close()
				// The caller's context is live: preserve the error returned by
				// the lookup, rather than only checking the caller's ctx.Err().
				matches, err := d.WithContext(context.Background()).Glob(pattern)
				if lookupErr == fs.ErrPermission {
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
	d := New(nil)
	defer d.Close()
	network := d.WithContext(context.Background())
	if err := fstest.TestFS(network); err != nil {
		t.Fatal(err)
	}
}

func TestWithContextCachedServersAndDirectoryCursor(t *testing.T) {
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
	if _, err := f.Stat(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("closed Stat = %v", err)
	}
	if _, err := reader.ReadDir(1); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("closed ReadDir = %v", err)
	}
	// File.Close must not tear down a cached session.
	if _, err := network.Stat("alpha"); err != nil {
		t.Fatal(err)
	}
}

func TestWithContextInvalidPathsAndLifecycle(t *testing.T) {
	d := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	network := d.WithContext(ctx)
	for _, name := range []string{"", "/server", "../server", "a/../b", `server\share`, "a//b"} {
		_, err := network.Open(name)
		var pe *fs.PathError
		if !errors.Is(err, fs.ErrInvalid) || !errors.As(err, &pe) || pe.Path != name {
			t.Fatalf("Open(%q) = %v", name, err)
		}
		if _, err := network.Sub(name); !errors.Is(err, fs.ErrInvalid) {
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
	if _, err := nilClient.WithContext(context.Background()).Open("."); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("nil client = %v", err)
	}
}
