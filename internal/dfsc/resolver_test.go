package dfsc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

type testTree struct {
	namespace bool
	referral  func(context.Context, *ReferralRequest, uint32) ([]byte, error)
	close     func(context.Context) error
}

func (t *testTree) IsNamespace() bool { return t.namespace }
func (t *testTree) Referral(ctx context.Context, req *ReferralRequest, maxOutput uint32) ([]byte, error) {
	return t.referral(ctx, req, maxOutput)
}
func (t *testTree) Close(ctx context.Context) error {
	if t.close != nil {
		return t.close(ctx)
	}
	return nil
}
func newTestResolver() *Resolver[*testTree] {
	return NewResolver("ns", "root", func(context.Context, string, string) (*testTree, error) {
		return nil, errors.New("unexpected connection")
	})
}
func TestDFSCacheLongestComponentPrefix(t *testing.T) {
	d := newTestResolver()
	now := time.Now().Add(time.Minute)
	d.cache[`\ns\root`] = &cacheEntry{prefix: `\ns\root`, cacheable: true, ttl: now, targets: []target{{unc: `\\one\share`}}}
	d.cache[`\ns\root\foo`] = &cacheEntry{prefix: `\ns\root\foo`, cacheable: true, ttl: now, targets: []target{{unc: `\\two\share`}}}
	if got := d.find(`\NS\ROOT\foo\file`); got == nil || got.targets[0].unc != `\\two\share` {
		t.Fatalf("longest prefix = %#v", got)
	}
	if got := d.find(`\ns\root\foobar\file`); got == nil || got.targets[0].unc != `\\one\share` {
		t.Fatalf("component boundary = %#v", got)
	}
	d.cache[`\ns\root\foo`] = &cacheEntry{prefix: `\ns\root\foo`, cacheable: true, ttl: time.Now().Add(-time.Second), targets: []target{{unc: `\\two\share`}}}
	if got := d.find(`\ns\root\foo\file`); got == nil || got.targets[0].unc != `\\one\share` {
		t.Fatalf("expired prefix = %#v", got)
	}
}

func TestDFSPathSuffixIsCaseInsensitiveAndComponentBounded(t *testing.T) {
	if got := pathSuffix(`\NS\ROOT\Link\file`, `\ns\root\link`); got != `\file` {
		t.Fatalf("suffix = %q", got)
	}
	if got := pathSuffix(`\ns\root\foobar\file`, `\ns\root\foo`); got != "" {
		t.Fatalf("non-component suffix = %q", got)
	}
}

func TestDFSTargetOrderPreservesTargetSets(t *testing.T) {
	targets := []target{{boundary: true}, {}, {boundary: true}, {}}
	got := targetOrder(targets, 1)
	want := []int{1, 0, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestDFSTargetTreesAreSharedByServerAndShare(t *testing.T) {
	tc := &testTree{}
	d := newTestResolver()
	d.targetTrees[treeKey("server", "share")] = tc
	e := &cacheEntry{targets: []target{{unc: `\\server\share\other-base`}}}
	got, base, err := d.target(context.Background(), e)
	if err != nil || got != tc || base != `\\server\share\other-base` {
		t.Fatalf("target = %p, %q, %v; want %p, %q, nil", got, base, err, tc, `\\server\share\other-base`)
	}
}

func TestDFSTargetFallsBackAndUpdatesHint(t *testing.T) {
	tc := &testTree{}
	d := newTestResolver()
	d.targetTrees[treeKey("ns", "share")] = tc
	e := &cacheEntry{targets: []target{
		{unc: `invalid`},
		{unc: `\\ns\share\base`},
	}}
	got, base, err := d.target(context.Background(), e)
	if err != nil || got != tc || base != `\\ns\share\base` || e.hint != 1 {
		t.Fatalf("fallback = %p, %q, hint %d, %v", got, base, e.hint, err)
	}
}

func TestDFSReferralV1IsNotCached(t *testing.T) {
	d := newTestResolver()
	r := &ReferralResponse{PathConsumed: uint16(utf16le.EncodedStringLen(`\ns\root`)), Entries: []ReferralEntry{{Version: 1, NetworkAddress: `\\server\share`}}}
	e, err := d.put(r, `\ns\root`)
	if err != nil || e == nil || e.cacheable {
		t.Fatalf("V1 cache entry = %#v, %v", e, err)
	}
	if d.find(`\ns\root\file`) != nil {
		t.Fatal("V1 referral unexpectedly reusable")
	}
}

func TestDFSInterlinkHeaderFlags(t *testing.T) {
	for _, flags := range []uint32{0, ReferralHeaderServers, ReferralHeaderStorage, ReferralHeaderServers | ReferralHeaderStorage} {
		d := newTestResolver()
		e, err := d.put(&ReferralResponse{
			ReferralHeaderFlags: flags,
			Entries:             []ReferralEntry{{Version: 3, DFSPath: `\ns\root\link`, NetworkAddress: `\next\root`, TimeToLive: 60}},
		}, `\ns\root\link\file`)
		if err != nil {
			t.Fatal(err)
		}
		if want := flags == ReferralHeaderServers; e.interlink != want {
			t.Errorf("flags %#x: interlink=%v, want %v", flags, e.interlink, want)
		}
	}
}

func TestDFSInterlinkResolutionBounds(t *testing.T) {
	for _, tt := range []struct {
		name, target, want string
	}{
		{"cycle", `\NS\ROOT\link`, "DFS referral cycle"},
		{"growing_path", `\ns\root\link\extra`, "DFS referral limit"},
		{"oversized_path", `\next\root\` + strings.Repeat("x", 32768), "DFS path exceeds uint16"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestResolver()
			d.cache[`\ns\root\link`] = &cacheEntry{
				prefix: `\ns\root\link`, cacheable: true, ttl: time.Now().Add(time.Minute), interlink: true,
				targets: []target{{unc: tt.target}},
			}
			_, err := d.Resolve(context.Background(), `\ns\root\link\file`)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("resolve error=%v, want %q", err, tt.want)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := d.Resolve(ctx, `\ns\root\link\file`); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled resolution error=%v", err)
			}
		})
	}
}

func TestDFSReferralRejectsUnrelatedPrefix(t *testing.T) {
	d := newTestResolver()
	_, err := d.put(&ReferralResponse{
		Entries: []ReferralEntry{{Version: 3, DFSPath: `\other\root`, NetworkAddress: `\target\share`}},
	}, `\ns\root\link\file`)
	if err == nil {
		t.Fatal("accepted unrelated referral prefix")
	}
}

func TestDFSRootReferralStopsAtNamespaceTree(t *testing.T) {
	d := newTestResolver()
	target := &testTree{namespace: true}
	d.targetTrees[treeKey("ns", "root")] = target
	_, err := d.put(&ReferralResponse{
		ReferralHeaderFlags: ReferralHeaderServers | ReferralHeaderStorage,
		Entries: []ReferralEntry{{Version: 3, ServerType: 1,
			DFSPath: `\ns\root`, NetworkAddress: `\ns\root`, TimeToLive: 60}},
	}, `\ns\root`)
	if err != nil {
		t.Fatal(err)
	}
	// A self-referencing root referral is valid, and must reach CREATE
	// instead of being followed recursively as an interlink.
	route, err := d.Resolve(context.Background(), `\ns\root\file`)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tree != target || route.Path != `\ns\root\file` || route.Name != "file" {
		t.Fatalf("resolved root route=%+v", route)
	}
}

func TestResolverClosesConnectionsOnce(t *testing.T) {
	closeErr := errors.New("IPC disconnect failed")
	connects := make(map[string]int)
	closes := make(map[string]int)
	d := NewResolver("domain", "root", func(_ context.Context, server, share string) (*testTree, error) {
		key := server + `\` + share
		connects[key]++
		return &testTree{
			referral: func(context.Context, *ReferralRequest, uint32) ([]byte, error) {
				return makeDFSResponse(3, `\files\share`), nil
			},
			close: func(context.Context) error {
				closes[key]++
				if share == "IPC$" {
					return closeErr
				}
				return nil
			},
		}, nil
	})
	for _, path := range []string{`\domain\root\a`, `\domain\root\b`} {
		if _, err := d.Resolve(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("Close = %v, want %v", err, closeErr)
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
	for _, key := range []string{`domain\IPC$`, `files\share`} {
		if connects[key] != 1 || closes[key] != 1 {
			t.Errorf("%s: connects=%d, closes=%d", key, connects[key], closes[key])
		}
	}
}

func TestResolverReferralBufferGrowth(t *testing.T) {
	for _, capped := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry succeeds", true: "size limit"}[capped], func(t *testing.T) {
			var sizes []uint32
			d := NewResolver("domain", "root", func(context.Context, string, string) (*testTree, error) {
				return &testTree{referral: func(_ context.Context, req *ReferralRequest, maxOutput uint32) ([]byte, error) {
					if req.MaxReferralLevel != ReferralLevel4 || req.RequestFileName != `\domain\root\file` {
						t.Fatalf("unexpected referral request: %+v", req)
					}
					sizes = append(sizes, maxOutput)
					if capped || len(sizes) == 1 {
						return nil, erref.STATUS_BUFFER_OVERFLOW
					}
					return makeDFSResponse(3, `\files\share`), nil
				}}, nil
			})
			_, err := d.Resolve(context.Background(), `\domain\root\file`)
			want := []uint32{4096, 8192}
			if capped {
				want = []uint32{4096, 8192, 16384, 32768, 56 * 1024}
				if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
					t.Fatalf("Resolve = %v, want buffer overflow", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(sizes) != len(want) {
				t.Fatalf("buffer sizes = %v, want %v", sizes, want)
			}
			for i := range want {
				if sizes[i] != want[i] {
					t.Fatalf("buffer sizes = %v, want %v", sizes, want)
				}
			}
		})
	}
}
