package dfs

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestClientNilArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Nil context panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context")
			}
		}()
		var c *Client
		var nilCtx context.Context
		_, _ = c.GetReferrals(nilCtx, `\\domain\root`)
	}()

	var nilClient *Client
	if _, err := nilClient.GetReferrals(ctx, `\\domain\root`); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilClient.GetReferrals = %v, want os.ErrInvalid", err)
	}

	clientNilShare := NewClient(nil)
	if _, err := clientNilShare.GetReferrals(ctx, `\\domain\root`); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("clientNilShare.GetReferrals = %v, want os.ErrInvalid", err)
	}

	// Invalid referral paths
	for _, badPath := range []string{
		"",
		"relative/path",
		`\`,
		`\\\server\share`,
		`\\server/share`,
		`\\server:port\share`,
	} {
		if _, err := clientNilShare.GetReferrals(ctx, badPath); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("GetReferrals(%q) = %v, want os.ErrInvalid", badPath, err)
		}
	}
}

func TestReferralOptions(t *testing.T) {
	t.Parallel()
	var cfg referralConfig
	opt := WithSiteName("MySite")
	opt.applyOption(&cfg)
	if cfg.siteName != "MySite" {
		t.Fatalf("siteName = %q, want MySite", cfg.siteName)
	}
}
