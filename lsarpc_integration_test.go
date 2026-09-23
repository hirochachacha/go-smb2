package smb2_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/user"
)

func TestLSARPCIdentityLookup(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ipc, err := e.session.IPC(ctx)
		if err != nil {
			t.Fatal(err)
		}
		client, err := user.NewClient(ctx, ipc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Close(closeCtx); err != nil {
				t.Error(err)
			}
		})
		var userName string
		var sid *security.SID
		t.Run("Current", func(t *testing.T) {
			identity, err := client.Current(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.EqualFold(identity.Name, e.cfg.Session.User) || identity.Domain == "" || identity.SID == nil {
				t.Fatalf("current identity = %+v", identity)
			}
			userName = identity.Name
			sid = identity.SID
		})
		if userName == "" {
			return
		}
		t.Run("Lookup", func(t *testing.T) {
			resolved, err := client.Lookup(ctx, userName)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.SID == nil {
				t.Fatalf("lookup name result = %+v", resolved)
			}
			if resolved.SID.String() != sid.String() {
				t.Fatalf("lookup SID %s differs from current SID %s", resolved.SID, sid)
			}
		})
		t.Run("LookupUnknown", func(t *testing.T) {
			_, err := client.Lookup(ctx, "go-smb2-unknown-identity-5bb3b5a7")
			if !errors.Is(err, os.ErrNotExist) {
				var invalid *msrpc.InvalidResponseError
				if e.cfg.Name == "macos" && errors.As(err, &invalid) && strings.HasPrefix(invalid.Message, "translated SID count mismatch: got 0, want 1") {
					t.Skipf("macOS server omits the unresolved result: %v", err)
				}
				t.Fatalf("unknown lookup error = %v, want os.ErrNotExist", err)
			}
		})
		t.Run("LookupSID", func(t *testing.T) {
			identity, err := client.LookupSID(ctx, sid)
			if err != nil {
				var fault *msrpc.FaultError
				if e.cfg.Name == "macos" && errors.As(err, &fault) && fault.Status == 0x1c000007 {
					t.Skipf("macOS server rejects LsarLookupSids: %v", err)
				}
				t.Fatal(err)
			}
			if identity.Name == "" || identity.SID.String() != sid.String() {
				t.Fatalf("lookup SID result = %+v", identity)
			}
		})
		t.Run("SetSecurityDescriptorWithResolvedSID", func(t *testing.T) {
			path := join(newTestDirectory(t, e.fs), "resolved-sid.txt")
			file, err := e.fs.Create(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(ctx); err != nil {
				t.Fatal(err)
			}
			original, err := e.fs.GetSecurityDescriptor(ctx, path, security.DACL)
			if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
				t.Skipf("server does not support security descriptors: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if original.DACL == security.NullACL {
				t.Skip("file has a NULL DACL")
			}
			acl := *original.DACL
			countResolvedACE := func(acl *security.ACL) int {
				var count int
				for _, ace := range acl.ACEs {
					if ace.Type == security.AccessAllowed && ace.SID != nil && ace.SID.String() == sid.String() {
						count++
					}
				}
				return count
			}
			before := countResolvedACE(original.DACL)
			acl.ACEs = append(append([]security.ACE(nil), acl.ACEs...), security.ACE{
				Type: security.AccessAllowed, Mask: security.FileGenericRead, SID: sid,
			})
			if err := e.fs.SetSecurityDescriptor(ctx, path, &security.Descriptor{DACL: &acl}); err != nil {
				if errors.Is(err, os.ErrPermission) || errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
					t.Skipf("server rejected DACL update: %v", err)
				}
				t.Fatal(err)
			}
			updated, err := e.fs.GetSecurityDescriptor(ctx, path, security.DACL)
			if err != nil {
				t.Fatal(err)
			}
			if updated.DACL == security.NullACL || countResolvedACE(updated.DACL) <= before {
				t.Fatalf("resolved SID %s is missing from updated DACL", sid)
			}
		})
		if err := client.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Lookup(ctx, userName); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("lookup after close: got %v, want os.ErrClosed", err)
		}
	})
}
