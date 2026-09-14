package dfsc

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

const maxReferrals = 32

// Tree supplies the SMB operations needed by the resolver. Close releases both
// the tree connection and its session ownership. Tree values identify connections.
type Tree interface {
	comparable
	IsNamespace() bool
	Referral(context.Context, *ReferralRequest, uint32) ([]byte, error)
	Close(context.Context) error
}

// ReferralError reports a semantically invalid referral.
type ReferralError struct{ Message string }

func (e *ReferralError) Error() string { return e.Message }

// ResolutionError reports a path, cycle, or referral-depth limit violation.
type ResolutionError struct{ Message string }

func (e *ResolutionError) Error() string { return e.Message }

type target struct {
	unc      string
	boundary bool
}

type cacheEntry struct {
	prefix    string
	targets   []target
	ttl       time.Time
	hint      int
	cacheable bool
	root      bool
	interlink bool
}

// Resolver owns referral caches and connections for one mounted namespace.
// The connect callback returns a new tree with its own ownership reference.
type Resolver[T Tree] struct {
	mu            sync.Mutex
	server, share string
	connect       func(context.Context, string, string) (T, error)
	cache         map[string]*cacheEntry
	ipcByServer   map[string]T
	targetTrees   map[string]T
	closed        bool
}

// NewResolver creates a resolver for a server/share namespace. Each successful
// connect call transfers ownership of its tree to the resolver.
func NewResolver[T Tree](server, share string, connect func(context.Context, string, string) (T, error)) *Resolver[T] {
	return &Resolver[T]{server: server, share: share, connect: connect,
		cache: make(map[string]*cacheEntry), ipcByServer: make(map[string]T), targetTrees: make(map[string]T)}
}

// FullPath expands a share-relative name to the DFS wire path.
func (d *Resolver[T]) FullPath(name string) string {
	name = strings.TrimLeft(name, "\\")
	return `\` + d.server + `\` + d.share + func() string {
		if name == "" {
			return ""
		}
		return `\` + name
	}()
}

func (d *Resolver[T]) find(path string) *cacheEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	var best *cacheEntry
	for _, e := range d.cache {
		if !e.cacheable || !now.Before(e.ttl) || !prefixMatch(e.prefix, path) {
			continue
		}
		if best == nil || len(pathComponents(e.prefix)) > len(pathComponents(best.prefix)) {
			best = e
		}
	}
	return best
}

func prefixMatch(prefix, path string) bool {
	prefixParts := pathComponents(prefix)
	pathParts := pathComponents(path)
	if len(prefixParts) == 0 || len(prefixParts) > len(pathParts) {
		return false
	}
	for i, part := range prefixParts {
		if !strings.EqualFold(part, pathParts[i]) {
			return false
		}
	}
	return true
}

func (d *Resolver[T]) put(r *ReferralResponse, requestPath string) (*cacheEntry, error) {
	if len(r.Entries) == 0 {
		return nil, nil
	}
	prefix := r.Entries[0].DFSPath
	if prefix == "" {
		// V1 has no path field. PathConsumed is a byte count over UTF-16,
		// therefore take the corresponding prefix from the encoded request.
		prefix = pathPrefix(requestPath, int(r.PathConsumed))
		if prefix == "" {
			// V1 does not carry a reusable DFS path or TTL. A zero consumed
			// prefix can still route this operation, but must not become a
			// cache entry that could affect a later path.
			prefix = normalizeDFSPath(requestPath)
		}
	}
	if prefix == "" {
		return nil, &ReferralError{"DFS referral has an empty path prefix"}
	}
	if !prefixMatch(prefix, requestPath) {
		return nil, &ReferralError{"DFS referral prefix does not match request path"}
	}
	e := &cacheEntry{
		prefix: prefix, cacheable: r.Entries[0].Version > 1,
		root: r.Entries[0].ServerType == 1,
		// [MS-DFSC] 3.1.5.4.5: referral servers without storage servers
		// identify a target in another DFS namespace.
		interlink: r.ReferralHeaderFlags&(ReferralHeaderServers|ReferralHeaderStorage) == ReferralHeaderServers,
	}
	if e.cacheable {
		e.ttl = time.Now().Add(time.Duration(r.Entries[0].TimeToLive) * time.Second)
	}
	for _, v := range r.Entries {
		if v.NameListReferral || v.NetworkAddress == "" {
			continue
		}
		e.targets = append(e.targets, target{unc: v.NetworkAddress, boundary: v.TargetSetBoundary})
	}
	if len(e.targets) == 0 {
		return nil, &ReferralError{"DFS referral contains no storage targets"}
	}
	d.mu.Lock()
	if e.cacheable {
		d.cache[strings.ToLower(prefix)] = e
	}
	d.mu.Unlock()
	return e, nil
}

func pathPrefix(path string, consumed int) string {
	path = normalizeDFSPath(path)
	if consumed < 2 {
		return ""
	}
	// DFS paths are UTF-16 byte strings. Go's range gives the same boundary
	// for valid UTF-8 code points, while ASCII UNC components remain exact.
	used := 0
	for i, r := range path {
		n := 2
		if r > 0xffff {
			n = 4
		}
		if used+n > consumed {
			return path[:i]
		}
		used += n
		if used == consumed {
			return path[:i+len(string(r))]
		}
	}
	return path
}

func (d *Resolver[T]) referral(ctx context.Context, path string) (*cacheEntry, error) {
	if e := d.find(path); e != nil {
		return e, nil
	}
	r, err := d.query(ctx, path)
	if err != nil {
		return nil, err
	}
	return d.put(r, path)
}

func (d *Resolver[T]) query(ctx context.Context, path string) (*ReferralResponse, error) {
	server, _, _, err := parseTarget(path)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(server)
	d.mu.Lock()
	ipc, found := d.ipcByServer[key]
	d.mu.Unlock()
	if !found {
		ipc, err = d.connect(ctx, server, "IPC$")
		if err != nil {
			return nil, err
		}
		d.mu.Lock()
		existing, found := d.ipcByServer[key]
		if !found {
			d.ipcByServer[key] = ipc
		}
		d.mu.Unlock()
		if found {
			_ = ipc.Close(ctx)
			ipc = existing
		}
	}
	for maxOutput := uint32(4096); ; {
		req := &ReferralRequest{MaxReferralLevel: ReferralLevel4, RequestFileName: path}
		payload, err := ipc.Referral(ctx, req, maxOutput)
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) && maxOutput < 56*1024 {
				maxOutput = min(maxOutput*2, 56*1024)
				continue
			}
			return nil, err
		}
		referral, err := ParseReferralResponse(payload, path)
		if err != nil {
			return nil, &ReferralError{err.Error()}
		}
		return referral, nil
	}
}

func parseTarget(unc string) (server, share, suffix string, err error) {
	u := strings.TrimLeft(unc, "\\")
	parts := strings.Split(u, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("invalid DFS target %q", unc)
	}
	server, share = parts[0], parts[1]
	if len(parts) > 2 {
		suffix = strings.Join(parts[2:], `\`)
	}
	return
}

func (d *Resolver[T]) target(ctx context.Context, e *cacheEntry) (T, string, error) {
	d.mu.Lock()
	targets := append([]target(nil), e.targets...)
	hint := e.hint
	d.mu.Unlock()
	if hint < 0 || hint >= len(targets) {
		hint = 0
	}
	order := targetOrder(targets, hint)
	var last error
	for _, i := range order {
		server, share, _, err := parseTarget(targets[i].unc)
		if err != nil {
			last = err
			continue
		}
		key := treeKey(server, share)
		d.mu.Lock()
		cached, found := d.targetTrees[key]
		d.mu.Unlock()
		if found {
			d.mu.Lock()
			e.hint = i
			d.mu.Unlock()
			return cached, targets[i].unc, nil
		}
		tc, err := d.connect(ctx, server, share)
		if err != nil {
			last = err
			continue
		}
		d.mu.Lock()
		// Another request may have completed this target while this request
		// was authenticating and connecting. Keep the first tree and dispose
		// of this loser's tree/session ownership instead of overwriting it.
		if existing, found := d.targetTrees[key]; found {
			d.mu.Unlock()
			_ = tc.Close(ctx)
			return existing, targets[i].unc, nil
		}
		e.hint = i
		d.targetTrees[key] = tc
		d.mu.Unlock()
		return tc, targets[i].unc, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	var zero T
	return zero, "", last
}

func targetOrder(targets []target, hint int) []int {
	if len(targets) == 0 {
		return nil
	}
	if hint < 0 || hint >= len(targets) {
		hint = 0
	}
	// Preserve the server-provided target-set order. A target hint is tried
	// first, then the remainder of its set, before moving to a later set.
	setStart := hint
	for setStart > 0 && !targets[setStart].boundary {
		setStart--
	}
	setEnd := setStart + 1
	for setEnd < len(targets) && !targets[setEnd].boundary {
		setEnd++
	}
	order := []int{hint}
	for i := setStart; i < setEnd; i++ {
		if i != hint {
			order = append(order, i)
		}
	}
	for i := 0; i < len(targets); i++ {
		if i < setStart || i >= setEnd {
			order = append(order, i)
		}
	}
	return order
}

func treeKey(server, share string) string {
	return strings.ToLower(server) + `\` + strings.ToLower(share)
}

type resolution struct {
	steps  int
	active map[string]bool
}

// Route identifies a tree and the names used to send an operation to it.
type Route[T Tree] struct {
	Tree T
	Path string // normalized UNC path in the final target namespace
	Name string // relative to tree, for file information and non-DFS CREATE
}

func joinBase(base, rest string) string {
	base = strings.Trim(base, `\`)
	rest = strings.Trim(rest, `\`)
	if base == "" {
		return rest
	}
	if rest == "" {
		return base
	}
	return base + `\` + rest
}

func pathSuffix(path, prefix string) string {
	pathParts := pathComponents(path)
	prefixParts := pathComponents(prefix)
	if len(prefixParts) == 0 || len(prefixParts) > len(pathParts) {
		return ""
	}
	for i, part := range prefixParts {
		if !strings.EqualFold(part, pathParts[i]) {
			return ""
		}
	}
	if len(pathParts) == len(prefixParts) {
		return ""
	}
	return `\` + strings.Join(pathParts[len(prefixParts):], `\`)
}

func pathComponents(path string) []string {
	path = strings.Trim(path, `\`)
	if path == "" {
		return nil
	}
	return strings.Split(path, `\`)
}

// Resolve resolves a full DFS path, following cached or newly queried referrals.
func (d *Resolver[T]) Resolve(ctx context.Context, path string) (Route[T], error) {
	return d.resolve(ctx, path, &resolution{active: make(map[string]bool)})
}

func (d *Resolver[T]) resolve(ctx context.Context, path string, resolution *resolution) (Route[T], error) {
	if err := ctx.Err(); err != nil {
		return Route[T]{}, err
	}
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return Route[T]{}, &ResolutionError{"DFS path exceeds uint16"}
	}
	if resolution.steps >= maxReferrals {
		return Route[T]{}, &ResolutionError{"DFS referral limit exceeded"}
	}
	if resolution.active[strings.ToLower(normalizeDFSPath(path))] {
		return Route[T]{}, &ResolutionError{"DFS referral cycle detected"}
	}
	e, err := d.referral(ctx, path)
	if err != nil {
		return Route[T]{}, err
	}
	if e == nil {
		return Route[T]{}, erref.STATUS_OBJECT_PATH_NOT_FOUND
	}
	return d.resolveEntry(ctx, path, e, resolution)
}

func (d *Resolver[T]) resolveEntry(ctx context.Context, path string, e *cacheEntry, resolution *resolution) (Route[T], error) {
	if err := ctx.Err(); err != nil {
		return Route[T]{}, err
	}
	if resolution.steps >= maxReferrals {
		return Route[T]{}, &ResolutionError{"DFS referral limit exceeded"}
	}
	key := strings.ToLower(normalizeDFSPath(path))
	if resolution.active[key] {
		return Route[T]{}, &ResolutionError{"DFS referral cycle detected"}
	}
	resolution.steps++
	resolution.active[key] = true
	defer delete(resolution.active, key)

	if e.interlink {
		// [MS-DFSC] 3.1.4.1 step 11: substitute the target and resolve again.
		// An interlink need not offer a storage tree; query its IPC$ directly.
		d.mu.Lock()
		targets := append([]target(nil), e.targets...)
		hint := e.hint
		d.mu.Unlock()
		var last error
		for _, i := range targetOrder(targets, hint) {
			next := normalizeDFSPath(joinBase(targets[i].unc, pathSuffix(path, e.prefix)))
			route, err := d.resolve(ctx, next, resolution)
			if err != nil {
				if ctx.Err() != nil {
					return Route[T]{}, ctx.Err()
				}
				last = err
				continue
			}
			d.mu.Lock()
			e.hint = i
			d.mu.Unlock()
			return route, nil
		}
		if last == nil {
			last = os.ErrNotExist
		}
		return Route[T]{}, last
	}
	tc, target, err := d.target(ctx, e)
	if err != nil {
		return Route[T]{}, err
	}
	next := normalizeDFSPath(joinBase(target, pathSuffix(path, e.prefix)))
	if utf16le.EncodedStringLen(next) > math.MaxUint16 {
		return Route[T]{}, &ResolutionError{"DFS path exceeds uint16"}
	}
	// A storage referral can point at a stand-alone DFS root. Its share
	// flags identify the next namespace even without an interlink header.
	if !e.root && tc.IsNamespace() {
		return d.resolve(ctx, next, resolution)
	}
	_, _, name, err := parseTarget(next)
	if err != nil {
		return Route[T]{}, err
	}
	return Route[T]{Tree: tc, Path: next, Name: name}, nil
}

// Send routes a namespace-relative operation, retrying when send requests a
// fresh referral. The callback must release a failed response before retrying.
func (d *Resolver[T]) Send(ctx context.Context, name string, primary T, send func(Route[T]) (retry bool, err error)) error {
	path := d.FullPath(name)
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return &ResolutionError{"DFS path exceeds uint16"}
	}
	resolution := &resolution{active: make(map[string]bool)}
	route := Route[T]{Tree: primary, Path: path, Name: name}
	if d.find(path) != nil {
		var err error
		route, err = d.resolve(ctx, path, resolution)
		if err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		retry, err := send(route)
		if !retry {
			return err
		}
		if resolution.steps >= maxReferrals {
			return &ResolutionError{"DFS referral limit exceeded"}
		}
		r, err := d.query(ctx, route.Path)
		if err != nil {
			return err
		}
		e, err := d.put(r, route.Path)
		if err != nil {
			return err
		}
		if e == nil {
			return erref.STATUS_OBJECT_PATH_NOT_FOUND
		}
		route, err = d.resolveEntry(ctx, route.Path, e, resolution)
		if err != nil {
			return err
		}
	}
}

// Close disconnects the cached trees and releases their session references.
func (d *Resolver[T]) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	all := make([]T, 0, len(d.ipcByServer)+len(d.targetTrees))
	for _, tree := range d.ipcByServer {
		all = append(all, tree)
	}
	for _, tree := range d.targetTrees {
		all = append(all, tree)
	}
	d.mu.Unlock()
	var first error
	seen := make(map[T]bool)
	for _, tree := range all {
		if seen[tree] {
			continue
		}
		seen[tree] = true
		if err := tree.Close(ctx); first == nil {
			first = err
		}
	}
	return first
}
