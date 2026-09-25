package user

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/security"
)

func TestUserClientNilArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var nilCtx context.Context

	// NewClient nil context panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in NewClient")
			}
		}()
		_, _ = NewClient(nilCtx, nil)
	}()

	// NewClient nil share returns os.ErrInvalid
	if _, err := NewClient(ctx, nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("NewClient(ctx, nil) = %v, want os.ErrInvalid", err)
	}

	var nilClient *Client
	// Nil receiver Current
	if _, err := nilClient.Current(ctx); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.Current = %v, want os.ErrInvalid", err)
	}

	// Nil receiver Lookup
	if _, err := nilClient.Lookup(ctx, ""); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.Lookup(empty) = %v, want os.ErrInvalid", err)
	}
	if _, err := nilClient.Lookup(ctx, "user"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.Lookup = %v, want os.ErrInvalid", err)
	}

	// Nil receiver LookupSID
	if _, err := nilClient.LookupSID(ctx, nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.LookupSID(nil) = %v, want os.ErrInvalid", err)
	}
	sid := &security.SID{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21}}
	if _, err := nilClient.LookupSID(ctx, sid); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.LookupSID = %v, want os.ErrInvalid", err)
	}

	// Nil receiver Close
	if err := nilClient.Close(ctx); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.Close = %v, want os.ErrInvalid", err)
	}

	// Nil context panics on Client methods
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Current")
			}
		}()
		_, _ = nilClient.Current(nilCtx)
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Lookup")
			}
		}()
		_, _ = nilClient.Lookup(nilCtx, "user")
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in LookupSID")
			}
		}()
		_, _ = nilClient.LookupSID(nilCtx, sid)
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Close")
			}
		}()
		_ = nilClient.Close(nilCtx)
	}()
}
