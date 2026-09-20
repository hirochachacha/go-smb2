package dfs

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	v2 "github.com/hirochachacha/go-smb2/v2"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
)

func TestUNCPathRequiresServerAndShare(t *testing.T) {
	for _, path := range []string{`server\share\file`, `\server\share`, `\\server`, `\\server\share\..`, "\\\\server\\share\\bad\x00name"} {
		if _, err := pathpkg.ParseUNC(path); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("ParseUNC(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
	p, err := pathpkg.ParseUNC(`\\server\share\folder\file`)
	if err != nil || p.Server != "server" || p.Share != "share" || p.RelPath != `folder\file` {
		t.Fatalf("parsed UNC = %#v, %v", p, err)
	}
}

func TestInvalidPathsReturnErrInvalidBeforeRouting(t *testing.T) {
	d := New(nil)
	for _, path := range []string{
		`server\share\file`,
		`\\server`,
		`\\server\share\..`,
		`\\server\share\.\file`,
		`\\server\share\..\secret`,
	} {
		if _, err := d.Stat(context.Background(), path); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("Stat(%q) = %v, want os.ErrInvalid", path, err)
		}
	}
}

func TestReferralRejectsMalformedTargetBeforeCaching(t *testing.T) {
	for _, target := range []string{
		`//server/share`,
		`\\server\\share`,
		`\\server\share\`,
		`\\server\share\.\file`,
		`\\server\share\..\file`,
		"\\\\server\\share\\bad\x00name",
		"\\\\server\\share\\bad\xffname",
	} {
		t.Run(target, func(t *testing.T) {
			d := New(nil)
			response := &v2.DFSReferralResponse{
				Prefix: `\\namespace\root`,
				Entries: []v2.DFSReferralEntry{{
					Version: 3, NetworkAddress: target,
				}},
			}
			if _, err := d.installReferral(response, response.Prefix); !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("installReferral(%q) = %v, want os.ErrInvalid", target, err)
			}
			if len(d.referrals) != 0 {
				t.Fatal("malformed target was cached")
			}
		})
	}
}

func TestTargetOrderingStaysWithinHintedSet(t *testing.T) {
	targets := []referralTarget{{unc: `\\a\s`, boundary: true}, {unc: `\\b\s`}, {unc: `\\c\s`, boundary: true}, {unc: `\\d\s`}}
	got := orderedTargets(targets, 1)
	want := []int{1, 0, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRefreshPreservesHintWithinEquivalentTargetSets(t *testing.T) {
	old := &referralEntry{prefix: `\\n\r`, targets: []referralTarget{{unc: `\\a\s`, boundary: true}, {unc: `\\b\s`}, {unc: `\\c\s`, boundary: true}}, hint: 2}
	fresh := &referralEntry{prefix: old.prefix, targets: []referralTarget{{unc: `\\b\s`, boundary: true}, {unc: `\\a\s`}, {unc: `\\c\s`, boundary: true}}, failback: true, expires: time.Now().Add(time.Minute), cacheable: true}
	mergeReferral(old, fresh)
	if old.targets[old.hint].unc != `\\a\s` {
		t.Fatalf("hint target = %q", old.targets[old.hint].unc)
	}
	if old.hint != 0 {
		t.Fatalf("failback hint = %d, want first set", old.hint)
	}
}

func TestReferralCacheUsesLongestComponentPrefix(t *testing.T) {
	d := New(nil)
	d.referrals[`\\n\root`] = &referralEntry{prefix: `\\n\root`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\a\s`}}}
	d.referrals[`\\n\root\dir`] = &referralEntry{prefix: `\\n\root\dir`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\b\s`}}}
	entry, suffix, ok := d.cacheEntry(`\\n\root\dir\file`)
	if !ok || entry.prefix != `\\n\root\dir` || suffix != `\file` {
		t.Fatalf("cache match = %#v, %q, %v", entry, suffix, ok)
	}
}

func TestV1ReferralRoutesWithoutCaching(t *testing.T) {
	d := New(nil)
	r := &v2.DFSReferralResponse{Prefix: `\\n\root`, Entries: []v2.DFSReferralEntry{{Version: 1, ServerType: v2.DFSReferralServerRoot, NetworkAddress: `\\a\s`}}}
	entry, err := d.installReferral(r, `\\n\root\file`)
	if err != nil || entry == nil || entry.cacheable {
		t.Fatalf("V1 install = %#v, %v", entry, err)
	}
	if _, _, ok := d.cacheEntry(`\\n\root\file`); ok {
		t.Fatal("V1 referral was cached")
	}
}

func TestReferralHeaderClassifiesRootAndInterlink(t *testing.T) {
	for _, test := range []struct {
		name                    string
		header                  uint32
		serverType              uint16
		wantRoot, wantInterlink bool
	}{
		{name: "storage link", header: v2.DFSReferralHeaderStorage, serverType: v2.DFSReferralServerLink},
		{name: "interlink", header: v2.DFSReferralHeaderServers, serverType: v2.DFSReferralServerLink, wantInterlink: true},
		{name: "root", header: v2.DFSReferralHeaderServers | v2.DFSReferralHeaderStorage, serverType: v2.DFSReferralServerRoot, wantRoot: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := New(nil)
			entry, err := d.installReferral(&v2.DFSReferralResponse{
				HeaderFlags: test.header,
				Prefix:      `\\namespace\root\link`,
				Entries: []v2.DFSReferralEntry{{
					Version: 3, ServerType: test.serverType,
					NetworkAddress: `\\target\share`,
				}},
			}, `\\namespace\root\link\file`)
			if err != nil {
				t.Fatal(err)
			}
			if entry.root != test.wantRoot || entry.interlink != test.wantInterlink {
				t.Fatalf("entry root=%v interlink=%v, want %v %v", entry.root, entry.interlink, test.wantRoot, test.wantInterlink)
			}
		})
	}
}

func TestReferralRefreshDoesNotMutateActiveRouteMetadata(t *testing.T) {
	d := New(nil)
	prefix := `\\namespace\root\link`
	first, err := d.installReferral(&v2.DFSReferralResponse{
		HeaderFlags: v2.DFSReferralHeaderStorage,
		Prefix:      prefix,
		Entries:     []v2.DFSReferralEntry{{Version: 3, ServerType: v2.DFSReferralServerLink, TTL: time.Minute, NetworkAddress: `\\target\share`}},
	}, prefix+`\file`)
	if err != nil {
		t.Fatal(err)
	}
	active := &resolvedRoute{source: first}
	var wg sync.WaitGroup
	failed := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if active.source.interlink || active.source.root {
				select {
				case failed <- "active route metadata changed":
				default:
				}
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		_, err := d.installReferral(&v2.DFSReferralResponse{
			HeaderFlags: v2.DFSReferralHeaderServers,
			Prefix:      prefix,
			Entries:     []v2.DFSReferralEntry{{Version: 3, ServerType: v2.DFSReferralServerLink, TTL: time.Minute, NetworkAddress: `\\target\namespace`}},
		}, prefix+`\file`)
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	select {
	case message := <-failed:
		t.Fatal(message)
	default:
	}
	if active.source == nil || active.source.interlink || active.source.root {
		t.Fatal("active referral entry was mutated during refresh")
	}
	current, _, ok := d.cacheEntry(prefix + `\file`)
	if !ok || !current.interlink {
		t.Fatal("refreshed referral did not publish new interlink metadata")
	}
}

func TestEquivalentTargetSetsRespectBoundaries(t *testing.T) {
	old := []referralTarget{
		{unc: `\\a\share`, boundary: true}, {unc: `\\b\share`},
		{unc: `\\c\share`, boundary: true}, {unc: `\\d\share`},
	}
	if equivalentTargets(old, []referralTarget{
		{unc: `\\a\share`, boundary: true}, {unc: `\\c\share`},
		{unc: `\\b\share`, boundary: true}, {unc: `\\d\share`},
	}) {
		t.Fatal("target membership moved across sets but was considered equivalent")
	}
	if !equivalentTargets(old, []referralTarget{
		{unc: `\\b\share`, boundary: true}, {unc: `\\a\share`},
		{unc: `\\c\share`, boundary: true}, {unc: `\\d\share`},
	}) {
		t.Fatal("target order within a set changed equivalence")
	}
}

func TestRefreshResetsRemovedHint(t *testing.T) {
	old := &referralEntry{
		prefix:  `\\namespace\root`,
		targets: []referralTarget{{unc: `\\old\share`, boundary: true}, {unc: `\\other\share`}},
		hint:    1,
	}
	fresh := &referralEntry{
		prefix:    old.prefix,
		targets:   []referralTarget{{unc: `\\new\share`, boundary: true}},
		cacheable: true,
		expires:   time.Now().Add(time.Minute),
	}
	mergeReferral(old, fresh)
	if old.hint != 0 || old.targets[old.hint].unc != `\\new\share` {
		t.Fatalf("removed hint retained: hint=%d targets=%v", old.hint, old.targets)
	}
}

func TestInterlinkRouteDoesNotMountNamespaceShare(t *testing.T) {
	d := New(nil)
	entry := &referralEntry{
		prefix:    `\\namespace\root\link`,
		interlink: true,
		targets:   []referralTarget{{unc: `\\target\namespace`}},
	}
	route, err := d.selectRoute(context.Background(), `\\namespace\root\link\file`, entry, `\file`)
	if err != nil {
		t.Fatal(err)
	}
	if route.share != nil || route.path.RelPath != `link\file` || route.exact {
		t.Fatalf("interlink route = %#v, want namespace-only route", route)
	}
}

func TestCloseAndInvalidClientOperationsAreSafe(t *testing.T) {
	d := New(nil)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := d.Open(context.Background(), `\\server\share\file`)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v", err)
	}
}

func TestZeroClientOperationsDoNotPanic(t *testing.T) {
	var d DFS
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := d.Open(context.Background(), `\\server\share\file`)
	if err == nil {
		t.Fatal("zero DFS Open succeeded")
	}
}

func TestUpperErrorsStripResolvedPathWrappers(t *testing.T) {
	inner := &protocol.DFSReferralRequiredError{Path: `\\target\share\file`}
	lower := &os.PathError{Op: "open", Path: `target\share\file`, Err: inner}
	wrapped := &os.PathError{Op: "open", Path: `\\namespace\root\file`, Err: lower}
	if got := unwrapFilesystemError(wrapped); got != inner {
		t.Fatalf("unwrapped error = %v, want referral error", got)
	}
}
