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
	e := &dfsCacheEntry{prefix: prefix, cacheable: r.Entries[0].Version > 1}
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
	key := strings.ToLower(d.server)
	d.mu.Lock()
	ipc := d.ipcByServer[key]
	d.mu.Unlock()
	var err error
	if ipc == nil {
		var owner *clientSession
		if d.owner.client != nil {
			owner, err = d.owner.client.connect(ctx, d.server)
			if err == nil {
				ipc, err = owner.s.treeConnect(ctx, `\\`+d.server+`\IPC$`, 0)
			}
		} else {
			owner = d.owner
			ipc, err = d.owner.s.treeConnect(ctx, `\\`+d.server+`\IPC$`, 0)
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
		server, share, base, err := parseDFSTarget(targets[i].unc)
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
			return cached, base, nil
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
			return existing, base, nil
		}
		e.hint = i
		d.targetTrees[key] = tc
		if ss != nil {
			d.targetSessions[tc] = ss
		}
		d.mu.Unlock()
		return tc, base, nil
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

func (fs *Share) sendRouted(ctx context.Context, reqs ...smb2.Packet) (*response, error) {
	if len(reqs) == 0 || fs.dfs == nil || !fs.dfs.isEnabled() {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	create, ok := reqs[0].(*smb2.CreateRequest)
	if !ok {
		return fs.treeConn.sendRecv(ctx, reqs...)
	}
	logicalName := create.Name
	originalName, originalFlags := create.Name, create.HeaderFlags()
	defer func() { create.Name = originalName; create.SetFlags(originalFlags) }()
	logicalPath := fs.dfs.fullPath(logicalName)
	if utf16le.EncodedStringLen(logicalPath) > math.MaxUint16 {
		return nil, &InternalError{"DFS path exceeds uint16"}
	}
	if e := fs.dfs.find(logicalPath); e != nil {
		if tc, base, err := fs.dfs.target(ctx, e); err == nil {
			create.Flags &^= smb2.SMB2_FLAGS_DFS_OPERATIONS
			create.Name = joinDFSBase(base, dfsPathSuffix(logicalPath, e.prefix))
			res, err := tc.sendRecv(ctx, reqs...)
			if res != nil {
				res.treeConn = tc
			}
			return res, err
		} else {
			return nil, err
		}
	}
	create.Name = logicalPath
	create.Flags |= smb2.SMB2_FLAGS_DFS_OPERATIONS
	res, err := fs.treeConn.sendRecv(ctx, reqs...)
	if err == nil {
		return res, nil
	}
	if !dfsPathNotCovered(err) {
		return res, err
	}
	fs.dfs.mu.Lock()
	fs.dfs.enabled = true
	fs.dfs.mu.Unlock()
	if res != nil {
		res.close()
	}
	e, refErr := fs.dfs.referral(ctx, logicalPath)
	if refErr != nil {
		return nil, refErr
	}
	if e == nil {
		return nil, &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)}
	}
	tc, base, targetErr := fs.dfs.target(ctx, e)
	if targetErr != nil {
		return nil, targetErr
	}
	create.Flags &^= smb2.SMB2_FLAGS_DFS_OPERATIONS
	create.Name = joinDFSBase(base, dfsPathSuffix(logicalPath, e.prefix))
	res, err = tc.sendRecv(ctx, reqs...)
	if res != nil {
		res.treeConn = tc
	}
	if err == nil {
		return res, nil
	}
	if !dfsPathNotCovered(err) {
		return res, err
	}
	if res != nil {
		res.close()
	}
	return nil, &InternalError{"DFS target returned STATUS_PATH_NOT_COVERED (interlink referral unsupported)"}
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

func (d *dfsState) resolvePath(ctx context.Context, path string) (*dfsCacheEntry, *treeConn, string, error) {
	e, err := d.referral(ctx, path)
	if err != nil {
		return nil, nil, "", err
	}
	if e == nil {
		return nil, nil, "", &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)}
	}
	tc, base, err := d.target(ctx, e)
	return e, tc, base, err
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
