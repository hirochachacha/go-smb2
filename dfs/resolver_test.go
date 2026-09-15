package dfs

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
)

func TestUNCPathRequiresServerAndShare(t *testing.T) {
	for _, path := range []string{`server\share\file`, `\server\share`, `\\server`, `\\server\share\..`, "\\\\server\\share\\bad\x00name"} {
		if _, err := parseUNC(path); err == nil {
			t.Errorf("parseUNC(%q) succeeded", path)
		}
	}
	p, err := parseUNC(`\\server\share\folder\file`)
	if err != nil || p.server != "server" || p.share != "share" || p.rest != `folder\file` {
		t.Fatalf("parsed UNC = %#v, %v", p, err)
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
	c := New(nil)
	c.referrals[`\\n\root`] = &referralEntry{prefix: `\\n\root`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\a\s`}}}
	c.referrals[`\\n\root\dir`] = &referralEntry{prefix: `\\n\root\dir`, cacheable: true, expires: time.Now().Add(time.Minute), targets: []referralTarget{{unc: `\\b\s`}}}
	entry, suffix, ok := c.cacheEntry(`\\n\root\dir\file`)
	if !ok || entry.prefix != `\\n\root\dir` || suffix != `\file` {
		t.Fatalf("cache match = %#v, %q, %v", entry, suffix, ok)
	}
}

func TestV1ReferralRoutesWithoutCaching(t *testing.T) {
	c := New(nil)
	r := &v2.DFSReferralResponse{Prefix: `\\n\root`, Entries: []v2.DFSReferralEntry{{Version: 1, ServerType: v2.DFSReferralServerRoot, NetworkAddress: `\\a\s`}}}
	entry, err := c.installReferral(r, `\\n\root\file`)
	if err != nil || entry == nil || entry.cacheable {
		t.Fatalf("V1 install = %#v, %v", entry, err)
	}
	if _, _, ok := c.cacheEntry(`\\n\root\file`); ok {
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
			c := New(nil)
			entry, err := c.installReferral(&v2.DFSReferralResponse{
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
	c := New(nil)
	prefix := `\\namespace\root\link`
	first, err := c.installReferral(&v2.DFSReferralResponse{
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
		_, err := c.installReferral(&v2.DFSReferralResponse{
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
	current, _, ok := c.cacheEntry(prefix + `\file`)
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

func TestRouteLinkOperationOnlyMatchesExactReferralPrefix(t *testing.T) {
	link := &referralEntry{prefix: `\\namespace\root\link`}
	if !errors.Is(routeLinkError(&resolvedRoute{source: link, exact: true}), ErrDFSLinkOperation) {
		t.Fatal("exact link was not protected")
	}
	if routeLinkError(&resolvedRoute{source: link, exact: false}) != nil {
		t.Fatal("child beneath link was treated as the link itself")
	}
	root := &referralEntry{prefix: `\\namespace\root`, root: true}
	if !errors.Is(routeLinkError(&resolvedRoute{source: root, exact: true}), ErrShareRootOperation) {
		t.Fatal("exact root was not protected")
	}
}

func TestInterlinkRouteDoesNotMountNamespaceShare(t *testing.T) {
	c := New(nil)
	entry := &referralEntry{
		prefix:    `\\namespace\root\link`,
		interlink: true,
		targets:   []referralTarget{{unc: `\\target\namespace`}},
	}
	route, err := c.selectRoute(context.Background(), `\\namespace\root\link\file`, entry, `\file`)
	if err != nil {
		t.Fatal(err)
	}
	if route.share != nil || route.path.rest != `link\file` || route.exact {
		t.Fatalf("interlink route = %#v, want namespace-only route", route)
	}
}

func TestCloseAndInvalidClientOperationsAreSafe(t *testing.T) {
	c := New(nil)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := c.Open(context.Background(), `\\server\share\file`)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v", err)
	}
}

func TestZeroClientOperationsDoNotPanic(t *testing.T) {
	var c Client
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := c.Open(context.Background(), `\\server\share\file`)
	if err == nil {
		t.Fatal("zero Client Open succeeded")
	}
}

func TestUpperErrorsStripResolvedPathWrappers(t *testing.T) {
	inner := &v2.DFSReferralError{Path: `\\target\share\file`}
	lower := &os.PathError{Op: "open", Path: `target\share\file`, Err: inner}
	wrapped := &os.PathError{Op: "open", Path: `\\namespace\root\file`, Err: lower}
	if got := unwrapFilesystemError(wrapped); got != inner {
		t.Fatalf("unwrapped error = %v, want referral error", got)
	}
}
