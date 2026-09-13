package smb2

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

type dfsTarget struct {
	unc      string
	boundary bool
}

type dfsCacheEntry struct {
	prefix    string
	targets   []dfsTarget
	ttl       time.Time
	hint      int
	cacheable bool
	root      bool
	interlink bool
}

type dfsState struct {
	mu             sync.Mutex
	owner          *clientSession
	server         string
	share          string
	primary        *treeConn
	cache          map[string]*dfsCacheEntry
	ipc            []*treeConn
	ipcByServer    map[string]*treeConn
	targetTrees    map[string]*treeConn
	ipcSessions    map[*treeConn]*clientSession
	targetSessions map[*treeConn]*clientSession
	closed         bool
	enabled        bool
}

func newDFSState(owner *clientSession, server, share string, shareFlags uint32) *dfsState {
	// A state is harmless for ordinary shares and lets the first explicit
	// STATUS_PATH_NOT_COVERED response decide whether the share is a namespace.
	return &dfsState{owner: owner, server: server, share: share, cache: make(map[string]*dfsCacheEntry), targetTrees: make(map[string]*treeConn), ipcByServer: make(map[string]*treeConn), ipcSessions: make(map[*treeConn]*clientSession), targetSessions: make(map[*treeConn]*clientSession), enabled: shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) != 0}
}

func (d *dfsState) setLogicalTree(tc *treeConn) {
	d.mu.Lock()
	d.primary = tc
	d.mu.Unlock()
}

func (d *dfsState) isEnabled() bool { d.mu.Lock(); defer d.mu.Unlock(); return d.enabled }

func (d *dfsState) fullPath(name string) string {
	name = strings.TrimLeft(name, "\\")
	return `\` + d.server + `\` + d.share + func() string {
		if name == "" {
			return ""
		}
		return `\` + name
	}()
}

func (d *dfsState) find(path string) *dfsCacheEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	var best *dfsCacheEntry
	for _, e := range d.cache {
		if !e.cacheable || !now.Before(e.ttl) || !dfsPrefixMatch(e.prefix, path) {
			continue
		}
		if best == nil || len(dfsPathComponents(e.prefix)) > len(dfsPathComponents(best.prefix)) {
			best = e
		}
	}
	return best
}

func dfsPrefixMatch(prefix, path string) bool {
	prefixParts := dfsPathComponents(prefix)
	pathParts := dfsPathComponents(path)
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

func (d *dfsState) put(r *dfsc.ReferralResponse, requestPath string) (*dfsCacheEntry, error) {
	if len(r.Entries) == 0 {
		return nil, nil
	}
	prefix := r.Entries[0].DFSPath
	if prefix == "" {
		// V1 has no path field. PathConsumed is a byte count over UTF-16,
		// therefore take the corresponding prefix from the encoded request.
		prefix = dfsPathPrefix(requestPath, int(r.PathConsumed))
		if prefix == "" {
			// V1 does not carry a reusable DFS path or TTL. A zero consumed
			// prefix can still route this operation, but must not become a
			// cache entry that could affect a later path.
			prefix = normalizeDFSPath(requestPath)
		}
	}
	if prefix == "" {
		return nil, &InvalidResponseError{"DFS referral has an empty path prefix"}
	}
	if !dfsPrefixMatch(prefix, requestPath) {
		return nil, &InvalidResponseError{"DFS referral prefix does not match request path"}
	}
	e := &dfsCacheEntry{
		prefix: prefix, cacheable: r.Entries[0].Version > 1,
		root: r.Entries[0].ServerType == 1,
		// [MS-DFSC] 3.1.5.4.5: referral servers without storage servers
		// identify a target in another DFS namespace.
		interlink: r.ReferralHeaderFlags&(dfsc.ReferralHeaderServers|dfsc.ReferralHeaderStorage) == dfsc.ReferralHeaderServers,
	}
	if e.cacheable {
		e.ttl = time.Now().Add(time.Duration(r.Entries[0].TimeToLive) * time.Second)
	}
	for _, v := range r.Entries {
		if v.NameListReferral || v.NetworkAddress == "" {
			continue
		}
		e.targets = append(e.targets, dfsTarget{unc: v.NetworkAddress, boundary: v.TargetSetBoundary})
	}
	if len(e.targets) == 0 {
		return nil, &InvalidResponseError{"DFS referral contains no storage targets"}
	}
	d.mu.Lock()
	if e.cacheable {
		d.cache[strings.ToLower(prefix)] = e
	}
	d.mu.Unlock()
	return e, nil
}

func dfsPathPrefix(path string, consumed int) string {
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

func normalizeDFSPath(path string) string {
	for strings.HasPrefix(path, `\`) {
		path = path[1:]
	}
	return `\` + path
}

func (d *dfsState) referral(ctx context.Context, path string) (*dfsCacheEntry, error) {
	if e := d.find(path); e != nil {
		return e, nil
	}
	r, err := d.query(ctx, path)
	if err != nil {
		return nil, err
	}
	return d.put(r, path)
}

func (d *dfsState) query(ctx context.Context, path string) (*dfsc.ReferralResponse, error) {
	server, _, _, err := parseDFSTarget(path)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(server)
	d.mu.Lock()
	ipc := d.ipcByServer[key]
	d.mu.Unlock()
	if ipc == nil {
		var owner *clientSession
		if d.owner.client != nil {
			owner, err = d.owner.client.connect(ctx, server)
			if err == nil {
				ipc, err = owner.s.treeConnect(ctx, `\\`+server+`\IPC$`, 0)
			}
		} else if strings.EqualFold(server, d.server) {
			owner = d.owner
			ipc, err = d.owner.s.treeConnect(ctx, `\\`+server+`\IPC$`, 0)
		} else {
			return nil, fmt.Errorf("Client required for DFS referral server %q", server)
		}
		if err != nil {
			if owner != nil && owner != d.owner && d.owner.client != nil {
				_ = d.owner.client.closeSession(ctx, owner)
			}
			return nil, err
		}
		d.mu.Lock()
		if existing := d.ipcByServer[key]; existing != nil {
			_ = ipc.disconnect(ctx)
			if owner != nil && owner != d.owner && d.owner.client != nil {
				_ = d.owner.client.closeSession(ctx, owner)
			}
			ipc = existing
		} else {
			d.ipcByServer[key] = ipc
			d.ipc = append(d.ipc, ipc)
			if owner != nil && owner != d.owner {
				d.ipcSessions[ipc] = owner
			}
		}
		d.mu.Unlock()
	}
	for max := uint32(4096); ; {
		b := &dfsc.ReferralRequest{MaxReferralLevel: dfsc.ReferralLevel4, RequestFileName: path}
		res, callErr := ipc.request().withFileId(smb2.RelatedFileId).ioctl(smb2.FSCTL_DFS_GET_REFERRALS, b, max).sendRecv(ctx)
		if callErr != nil {
			var re *ResponseError
			if errors.As(callErr, &re) && erref.NtStatus(re.Code) == erref.STATUS_BUFFER_OVERFLOW {
				if max >= 56*1024 {
					return nil, callErr
				}
				next := max * 2
				if next > 56*1024 {
					next = 56 * 1024
				}
				max = next
				continue
			}
			return nil, callErr
		}
		if res == nil {
			return nil, &InvalidResponseError{"missing DFS referral response"}
		}
		out := smb2.IoctlResponseDecoder(res.data(0))
		if out.IsInvalid() {
			res.close()
			return nil, &InvalidResponseError{"broken DFS referral IOCTL response"}
		}
		payload := append([]byte(nil), out.Output()...)
		res.close()
		r, parseErr := dfsc.ParseReferralResponse(payload, path)
		if parseErr != nil {
			return nil, &InvalidResponseError{parseErr.Error()}
		}
		return r, nil
	}
}

func parseDFSTarget(unc string) (server, share, suffix string, err error) {
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

func (d *dfsState) target(ctx context.Context, e *dfsCacheEntry) (*treeConn, string, error) {
	d.mu.Lock()
	targets := append([]dfsTarget(nil), e.targets...)
	hint := e.hint
	d.mu.Unlock()
	if hint < 0 || hint >= len(targets) {
		hint = 0
	}
	order := dfsTargetOrder(targets, hint)
	var last error
	for _, i := range order {
		server, share, _, err := parseDFSTarget(targets[i].unc)
		if err != nil {
			last = err
			continue
		}
		key := dfsTreeKey(server, share)
		d.mu.Lock()
		cached := d.targetTrees[key]
		d.mu.Unlock()
		if cached != nil {
			d.mu.Lock()
			e.hint = i
			d.mu.Unlock()
			return cached, targets[i].unc, nil
		}
		var tc *treeConn
		var ss *clientSession
		if d.owner.client != nil {
			ss, err = d.owner.client.connect(ctx, server)
			if err != nil {
				last = err
				continue
			}
			if ss == nil || ss.s == nil {
				if ss != nil {
					_ = d.owner.client.closeSession(ctx, ss)
				}
				last = fmt.Errorf("Client returned a nil session for DFS target %q", server)
				continue
			}
			tc, err = ss.s.treeConnect(ctx, `\\`+server+`\`+share, 0)
			if err != nil {
				_ = d.owner.client.closeSession(ctx, ss)
				last = err
				continue
			}
		} else if strings.EqualFold(server, d.server) {
			// Tests and low-level callers can construct a DFS state without a
			// Client. Reuse the owning session for referrals on its own server.
			tc, err = d.owner.s.treeConnect(ctx, `\\`+server+`\`+share, 0)
		} else {
			err = fmt.Errorf("DFS target %q requires Client", server)
		}
		if err != nil {
			last = err
			continue
		}
		d.mu.Lock()
		// Another request may have completed this target while this request
		// was authenticating and connecting. Keep the first tree and dispose
		// of this loser's tree/session ownership instead of overwriting it.
		if existing := d.targetTrees[key]; existing != nil {
			d.mu.Unlock()
			_ = tc.disconnect(ctx)
			if ss != nil && d.owner.client != nil {
				_ = d.owner.client.closeSession(ctx, ss)
			}
			return existing, targets[i].unc, nil
		}
		e.hint = i
		d.targetTrees[key] = tc
		if ss != nil {
			d.targetSessions[tc] = ss
		}
		d.mu.Unlock()
		return tc, targets[i].unc, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return nil, "", last
}

func dfsTargetOrder(targets []dfsTarget, hint int) []int {
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

func dfsTreeKey(server, share string) string {
	return strings.ToLower(server) + `\` + strings.ToLower(share)
}

// maxDFSReferrals is an implementation bound on one resolution, including
// chains that keep extending the path and therefore never repeat an exact path.
const maxDFSReferrals = 32

type dfsResolution struct {
	steps  int
	active map[string]bool
}

type dfsRoute struct {
	tree *treeConn
	path string // normalized UNC path in the final target namespace
	name string // relative to tree, for file information and non-DFS CREATE
}

func (fs *Share) sendRouted(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	if len(reqs) == 0 || fs.dfs == nil || !fs.dfs.isEnabled() {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	create, ok := reqs[0].(*smb2.CreateRequest)
	if !ok {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	originalName, originalFlags := create.Name, create.HeaderFlags()
	defer func() { create.Name = originalName; create.SetFlags(originalFlags) }()
	path := fs.dfs.fullPath(originalName)
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return nil, &InternalError{"DFS path exceeds uint16"}
	}
	resolution := &dfsResolution{active: make(map[string]bool)}
	route := dfsRoute{tree: fs.treeConn, path: path, name: originalName}
	// Keep the initial namespace CREATE: ordinary files inside a DFS root
	// need no referral. Cached paths can be resolved before sending I/O.
	namespace := true
	if fs.dfs.find(path) != nil {
		var err error
		route, err = fs.dfs.resolve(ctx, path, resolution)
		if err != nil {
			return nil, err
		}
		namespace = route.tree.shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) != 0
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		create.Flags &^= smb2.SMB2_FLAGS_DFS_OPERATIONS
		create.Name = route.name
		if namespace {
			create.Flags |= smb2.SMB2_FLAGS_DFS_OPERATIONS
			create.Name = route.path
		}
		res, err := route.tree.sendRecv(ctx, reqs...)
		if res != nil {
			res.treeConn = route.tree
		}
		if !namespace || !dfsPathNotCovered(err) {
			return res, err
		}
		if res != nil {
			res.close()
		}
		// A namespace target may contain another link. Query the current
		// namespace, bypassing a cached root entry that did not cover it.
		if resolution.steps >= maxDFSReferrals {
			return nil, &InternalError{"DFS referral limit exceeded"}
		}
		r, err := fs.dfs.query(ctx, route.path)
		if err != nil {
			return nil, err
		}
		e, err := fs.dfs.put(r, route.path)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)}
		}
		// V1 is deliberately uncached; use this response for the retry too.
		route, err = fs.dfs.resolveEntry(ctx, route.path, e, resolution)
		if err != nil {
			return nil, err
		}
		namespace = route.tree.shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) != 0
	}
}

func dfsPathNotCovered(err error) bool {
	var re *ResponseError
	if errors.As(err, &re) {
		return erref.NtStatus(re.Code) == erref.STATUS_PATH_NOT_COVERED
	}
	var ce *CompoundResponseError
	if errors.As(err, &ce) {
		return dfsPathNotCovered(ce.OpError(0))
	}
	return false
}

func joinDFSBase(base, rest string) string {
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

func dfsPathSuffix(path, prefix string) string {
	pathParts := dfsPathComponents(path)
	prefixParts := dfsPathComponents(prefix)
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

func dfsPathComponents(path string) []string {
	path = strings.Trim(path, `\`)
	if path == "" {
		return nil
	}
	return strings.Split(path, `\`)
}

func (d *dfsState) resolvePath(ctx context.Context, path string) (dfsRoute, error) {
	return d.resolve(ctx, path, &dfsResolution{active: make(map[string]bool)})
}

func (d *dfsState) resolve(ctx context.Context, path string, resolution *dfsResolution) (dfsRoute, error) {
	if err := ctx.Err(); err != nil {
		return dfsRoute{}, err
	}
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return dfsRoute{}, &InternalError{"DFS path exceeds uint16"}
	}
	if resolution.steps >= maxDFSReferrals {
		return dfsRoute{}, &InternalError{"DFS referral limit exceeded"}
	}
	if resolution.active[strings.ToLower(normalizeDFSPath(path))] {
		return dfsRoute{}, &InternalError{"DFS referral cycle detected"}
	}
	e, err := d.referral(ctx, path)
	if err != nil {
		return dfsRoute{}, err
	}
	if e == nil {
		return dfsRoute{}, &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)}
	}
	return d.resolveEntry(ctx, path, e, resolution)
}

func (d *dfsState) resolveEntry(ctx context.Context, path string, e *dfsCacheEntry, resolution *dfsResolution) (dfsRoute, error) {
	if err := ctx.Err(); err != nil {
		return dfsRoute{}, err
	}
	if resolution.steps >= maxDFSReferrals {
		return dfsRoute{}, &InternalError{"DFS referral limit exceeded"}
	}
	key := strings.ToLower(normalizeDFSPath(path))
	if resolution.active[key] {
		return dfsRoute{}, &InternalError{"DFS referral cycle detected"}
	}
	resolution.steps++
	resolution.active[key] = true
	defer delete(resolution.active, key)

	if e.interlink {
		// [MS-DFSC] 3.1.4.1 step 11: substitute the target and resolve again.
		// An interlink need not offer a storage tree; query its IPC$ directly.
		d.mu.Lock()
		targets := append([]dfsTarget(nil), e.targets...)
		hint := e.hint
		d.mu.Unlock()
		var last error
		for _, i := range dfsTargetOrder(targets, hint) {
			next := normalizeDFSPath(joinDFSBase(targets[i].unc, dfsPathSuffix(path, e.prefix)))
			route, err := d.resolve(ctx, next, resolution)
			if err != nil {
				if ctx.Err() != nil {
					return dfsRoute{}, ctx.Err()
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
		return dfsRoute{}, last
	}
	tc, target, err := d.target(ctx, e)
	if err != nil {
		return dfsRoute{}, err
	}
	next := normalizeDFSPath(joinDFSBase(target, dfsPathSuffix(path, e.prefix)))
	if utf16le.EncodedStringLen(next) > math.MaxUint16 {
		return dfsRoute{}, &InternalError{"DFS path exceeds uint16"}
	}
	// A storage referral can point at a stand-alone DFS root. Its share
	// flags identify the next namespace even without an interlink header.
	if !e.root && tc.shareFlags&(smb2.SMB2_SHAREFLAG_DFS|smb2.SMB2_SHAREFLAG_DFS_ROOT) != 0 {
		return d.resolve(ctx, next, resolution)
	}
	_, _, name, err := parseDFSTarget(next)
	if err != nil {
		return dfsRoute{}, err
	}
	return dfsRoute{tree: tc, path: next, name: name}, nil
}

func (fs *Share) routed(tc *treeConn) *Share {
	if tc == nil || tc == fs.treeConn {
		return fs
	}
	return &Share{treeConn: tc, dfs: fs.dfs}
}

func (d *dfsState) close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	all := append([]*treeConn(nil), d.ipc...)
	ipcSessions := make(map[*treeConn]*clientSession, len(d.ipcSessions))
	for tc, ss := range d.ipcSessions {
		ipcSessions[tc] = ss
	}
	targetSessions := make(map[*treeConn]*clientSession, len(d.targetSessions))
	for tc, ss := range d.targetSessions {
		targetSessions[tc] = ss
	}
	for _, tc := range d.targetTrees {
		all = append(all, tc)
	}
	primary := d.primary
	d.mu.Unlock()
	var first error
	seen := make(map[*treeConn]bool)
	for _, tc := range all {
		if tc == primary {
			continue
		}
		if seen[tc] {
			continue
		}
		seen[tc] = true
		if err := tc.disconnect(ctx); err != nil && first == nil {
			first = err
		}
		if ss := ipcSessions[tc]; ss != nil && d.owner.client != nil {
			if err := d.owner.client.closeSession(ctx, ss); err != nil && first == nil {
				first = err
			}
		}
		if ss := targetSessions[tc]; ss != nil && d.owner.client != nil {
			if err := d.owner.client.closeSession(ctx, ss); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
