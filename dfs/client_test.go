package dfs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
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

func TestConvertReferral(t *testing.T) {
	t.Parallel()

	// Standard target with suffix
	raw := &dfsc.ReferralResponse{
		PathConsumed:        24,
		ReferralHeaderFlags: HeaderStorage,
		Prefix:              `\\domain\dfsroot`,
		Suffix:              `sub\file.txt`,
		Entries: []dfsc.ReferralEntry{
			{
				Version:          3,
				ServerType:       ServerLink,
				TimeToLive:       300,
				NetworkAddress:   `server\share`,
				DFSPath:          `\domain\dfsroot`,
				DFSAlternatePath: `\domain\dfsroot`,
			},
		},
	}
	converted := convertReferral(raw)
	if converted.PathConsumed != 24 || converted.HeaderFlags != HeaderStorage {
		t.Fatalf("unexpected header: %+v", converted)
	}
	if converted.Prefix != `\\domain\dfsroot` {
		t.Fatalf("Prefix = %q, want \\\\domain\\dfsroot", converted.Prefix)
	}
	if len(converted.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(converted.Entries))
	}
	entry := converted.Entries[0]
	if entry.TTL != 300*time.Second {
		t.Fatalf("TTL = %v, want 300s", entry.TTL)
	}
	if entry.TargetPath != `\\server\share\sub\file.txt` {
		t.Fatalf("TargetPath = %q, want \\\\server\\share\\sub\\file.txt", entry.TargetPath)
	}

	// Name list referral
	rawNameList := &dfsc.ReferralResponse{
		PathConsumed:        10,
		ReferralHeaderFlags: FlagNameList,
		Prefix:              `\\domain\ignored`,
		Suffix:              `ignored`,
		Entries: []dfsc.ReferralEntry{
			{
				Version:          3,
				NameListReferral: true,
				SpecialName:      `special`,
				ExpandedNames:    []string{`expand1`, `expand2`},
			},
		},
	}
	convertedNameList := convertReferral(rawNameList)
	if convertedNameList.Prefix != "" {
		t.Fatalf("Prefix = %q, want empty for name list", convertedNameList.Prefix)
	}
	if convertedNameList.Entries[0].TargetPath != "" {
		t.Fatalf("TargetPath = %q, want empty for name list", convertedNameList.Entries[0].TargetPath)
	}
	if len(convertedNameList.Entries[0].ExpandedNames) != 2 {
		t.Fatalf("ExpandedNames count = %d, want 2", len(convertedNameList.Entries[0].ExpandedNames))
	}
}

