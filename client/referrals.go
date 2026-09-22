package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	v2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
)

// maxReferralDepth bounds how many times referral resolution may restart for a
// single operation. The SMB layer separately bounds same-tree symbolic links
// per CREATE, so alternating referral and symlink traversal stays finite.
const maxReferralDepth = 32

var (
	errCrossShareRename = errors.New("client: cross-share rename")
	errReferralDepth    = errors.New("client: referral traversal limit exceeded")
)

// unwrapFilesystemError removes lower-layer operation wrappers so upper
// errors display the original absolute UNC supplied by the caller.
func unwrapFilesystemError(err error) error {
	for err != nil {
		switch wrapped := err.(type) {
		case *os.PathError:
			err = wrapped.Err
		case *os.LinkError:
			err = wrapped.Err
		default:
			return err
		}
	}
	return nil
}

func (d *Client) executeValue(ctx context.Context, name, op string, action routeAction) (any, error) {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(pathpkg.ToSMBPath(name))
	if err != nil {
		return nil, &os.PathError{Op: op, Path: name, Err: err}
	}
	value, err := d.execute(ctx, path, action)
	if err != nil {
		return nil, &os.PathError{Op: op, Path: name, Err: unwrapFilesystemError(err)}
	}
	return value, nil
}

func (d *Client) executeError(ctx context.Context, path, op string, action routeAction) error {
	_, err := d.executeValue(ctx, path, op, action)
	return err
}

// resolveRoute resolves the DFS namespace for path and returns the route a
// mutation must target. The Lstat probe inspects the final symbolic link itself
// (FILE_OPEN_REPARSE_POINT) and lets execute follow referrals or links that
// cross a share/server boundary, matching os.Remove/os.Rename semantics. When
// allowMissing is set, a missing leaf is not an error. The caller must release
// the returned route's session.
func (d *Client) resolveRoute(ctx context.Context, name string, allowMissing bool) (*resolvedRoute, error) {
	if ctx == nil {
		panic("nil context")
	}
	path, err := pathpkg.NormalizeUNC(pathpkg.ToSMBPath(name))
	if err != nil {
		return nil, err
	}
	var final *resolvedRoute
	_, err = d.execute(ctx, path, func(ctx context.Context, route *resolvedRoute) (any, error) {
		if !route.isExactLink() {
			if _, probeErr := route.share.Lstat(ctx, route.path.RelPath); probeErr != nil {
				if !allowMissing || !errors.Is(probeErr, os.ErrNotExist) {
					return nil, probeErr
				}
			}
		}
		final = route
		d.mu.Lock()
		route.session.retain()
		d.mu.Unlock()
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return final, nil
}

type referralTarget struct {
	unc      string
	boundary bool
}

type referralEntry struct {
	prefix                    string
	root, interlink, failback bool
	expires                   time.Time
	cacheable                 bool
	targets                   []referralTarget
	hint                      int
}

type resolvedRoute struct {
	session *sessionEntry
	share   *v2.Share
	path    pathpkg.UNC
	source  *referralEntry
	exact   bool
}

func (r *resolvedRoute) isExactLink() bool {
	return r != nil && r.source != nil && r.exact && !r.source.root
}

func (d *Client) invalidateRoute(route *resolvedRoute) {
	if route == nil || route.share == nil {
		return
	}
	key := shareKey(route.path.Server, route.path.Share)
	var staleSession *sessionEntry
	d.mu.Lock()
	if entry := d.shares[key]; entry != nil && entry.value == route.share {
		staleSession = entry.session
	}
	d.mu.Unlock()
	if staleSession != nil {
		d.invalidateSession(route.path.Server, staleSession)
	}
}

func (d *Client) lookupReferral(path string, checkExpiry bool) (*referralEntry, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best *referralEntry
	var bestSuffix string
	for _, entry := range d.referrals {
		if entry == nil || !entry.cacheable {
			continue
		}
		if checkExpiry && !time.Now().Before(entry.expires) {
			continue
		}
		suffix, ok := pathpkg.CutPrefix(path, entry.prefix)
		if !ok {
			continue
		}
		if best == nil || len(entry.prefix) > len(best.prefix) {
			best, bestSuffix = entry, suffix
		}
	}
	return best, bestSuffix
}

func (d *Client) cacheEntry(path string) (*referralEntry, string, bool) {
	entry, suffix := d.lookupReferral(path, true)
	return entry, suffix, entry != nil
}

func (d *Client) staleEntry(path string) *referralEntry {
	entry, _ := d.lookupReferral(path, false)
	return entry
}

func (d *Client) installReferral(response *dfs.ReferralResponse, request string) (*referralEntry, error) {
	if response == nil {
		return nil, errors.New("client: nil referral response")
	}
	if len(response.Entries) == 0 {
		return nil, fmt.Errorf("client: referral has no targets: %w", os.ErrNotExist)
	}
	prefix := response.Prefix
	if prefix == "" {
		return nil, errors.New("client: referral has no storage prefix")
	}
	if _, ok := pathpkg.CutPrefix(request, prefix); !ok {
		return nil, fmt.Errorf("client: referral prefix %q does not match %q", prefix, request)
	}
	first := response.Entries[0]
	entry := &referralEntry{
		prefix:    prefix,
		root:      first.ServerType == dfs.ServerRoot,
		interlink: response.HeaderFlags&(dfs.HeaderServers|dfs.HeaderStorage) == dfs.HeaderServers,
		failback:  response.HeaderFlags&dfs.HeaderFailback != 0,
		cacheable: first.Version > 1,
		targets:   make([]referralTarget, 0, len(response.Entries)),
	}
	if entry.cacheable {
		entry.expires = time.Now().Add(first.TTL)
	}
	for _, item := range response.Entries {
		if item.NetworkAddress == "" || item.Flags&dfs.FlagNameList != 0 {
			continue
		}
		target, err := pathpkg.ParseReferralTarget(item.NetworkAddress)
		if err != nil {
			return nil, err
		}
		entry.targets = append(entry.targets, referralTarget{unc: target.String(), boundary: item.Flags&dfs.FlagTargetSetBoundary != 0})
	}
	if len(entry.targets) == 0 {
		return nil, fmt.Errorf("client: referral has no usable targets: %w", os.ErrNotExist)
	}
	d.mu.Lock()
	if entry.cacheable {
		if old := d.referrals[strings.ToLower(prefix)]; old != nil {
			merged := *old
			merged.targets = append([]referralTarget(nil), old.targets...)
			mergeReferral(&merged, entry)
			d.referrals[strings.ToLower(prefix)] = &merged
			entry = &merged
		} else {
			d.referrals[strings.ToLower(prefix)] = entry
		}
	}
	d.mu.Unlock()
	return entry, nil
}

func mergeReferral(old, fresh *referralEntry) {
	var hinted string
	if old.hint >= 0 && old.hint < len(old.targets) {
		hinted = old.targets[old.hint].unc
	}
	old.prefix, old.root = fresh.prefix, fresh.root
	old.interlink, old.failback = fresh.interlink, fresh.failback
	old.expires, old.cacheable = fresh.expires, fresh.cacheable
	if !equivalentTargets(old.targets, fresh.targets) {
		old.targets = fresh.targets
	}
	if hinted != "" {
		old.hint = 0
		for i, target := range old.targets {
			if strings.EqualFold(target.unc, hinted) {
				old.hint = i
				break
			}
		}
	} else {
		old.hint = 0
	}
	if old.failback {
		start, _ := targetSet(old.targets, old.hint)
		if start != 0 {
			old.hint = 0
		}
	}
}

func equivalentTargets(a, b []referralTarget) bool {
	sets := func(in []referralTarget) [][]string {
		var out [][]string
		for i, target := range in {
			if i == 0 || target.boundary {
				out = append(out, nil)
			}
			out[len(out)-1] = append(out[len(out)-1], strings.ToLower(target.unc))
		}
		return out
	}
	aa, bb := sets(a), sets(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if len(aa[i]) != len(bb[i]) {
			return false
		}
		for _, target := range aa[i] {
			found := false
			for _, other := range bb[i] {
				if target == other {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func targetSet(targets []referralTarget, index int) (int, int) {
	if len(targets) == 0 {
		return 0, 0
	}
	if index < 0 || index >= len(targets) {
		index = 0
	}
	start := index
	for start > 0 && !targets[start].boundary {
		start--
	}
	end := start + 1
	for end < len(targets) && !targets[end].boundary {
		end++
	}
	return start, end
}

func orderedTargets(targets []referralTarget, hint int) []int {
	if len(targets) == 0 {
		return nil
	}
	if hint < 0 || hint >= len(targets) {
		hint = 0
	}
	start, end := targetSet(targets, hint)
	order := []int{hint}
	for i := start; i < end; i++ {
		if i != hint {
			order = append(order, i)
		}
	}
	for i := 0; i < len(targets); i++ {
		if i < start || i >= end {
			order = append(order, i)
		}
	}
	return order
}

func isUnavailable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrPermission) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var transportErr *protocol.TransportError
	if errors.As(err, &transportErr) {
		return true
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

func (d *Client) queryReferral(ctx context.Context, path string) (*referralEntry, error) {
	unc, err := pathpkg.ParseUNC(path)
	if err != nil {
		return nil, err
	}
	session, err := d.acquireSession(ctx, unc.Server)
	if err != nil {
		return nil, err
	}
	defer session.release()
	response, err := session.GetDFSReferrals(ctx, path, nil)
	if err != nil {
		if isUnavailable(err) {
			d.invalidateSession(unc.Server, session)
		}
		return nil, err
	}
	return d.installReferral(response, path)
}

func (d *Client) queryInterlink(ctx context.Context, path string, entry *referralEntry) (string, *referralEntry, error) {
	suffix, ok := pathpkg.CutPrefix(path, entry.prefix)
	if !ok {
		return "", nil, errors.New("client: interlink prefix does not match path")
	}
	d.mu.Lock()
	targets := append([]referralTarget(nil), entry.targets...)
	hint := entry.hint
	d.mu.Unlock()
	var last error
	for _, index := range orderedTargets(targets, hint) {
		queryPath := targets[index].unc + suffix
		unc, err := pathpkg.ParseUNC(queryPath)
		if err != nil {
			return "", nil, err
		}
		session, err := d.acquireSession(ctx, unc.Server)
		if err != nil {
			last = err
			if isUnavailable(err) {
				continue
			}
			return "", nil, err
		}
		response, err := session.GetDFSReferrals(ctx, queryPath, nil)
		session.release()
		if err != nil {
			last = err
			if isUnavailable(err) {
				d.invalidateSession(unc.Server, session)
				continue
			}
			return "", nil, err
		}
		fresh, installErr := d.installReferral(response, queryPath)
		if installErr != nil {
			return "", nil, installErr
		}
		d.mu.Lock()
		entry.hint = index
		d.mu.Unlock()
		return queryPath, fresh, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return "", nil, last
}

func (d *Client) selectRoute(ctx context.Context, path string, entry *referralEntry, suffix string) (*resolvedRoute, error) {
	if entry.interlink {
		unc, err := pathpkg.ParseUNC(path)
		if err != nil {
			return nil, err
		}
		return &resolvedRoute{path: unc, source: entry, exact: suffix == ""}, nil
	}
	d.mu.Lock()
	targets := append([]referralTarget(nil), entry.targets...)
	hint := entry.hint
	d.mu.Unlock()
	var last error
	for _, index := range orderedTargets(targets, hint) {
		targetPath := targets[index].unc + suffix
		routePath, err := pathpkg.ParseUNC(targetPath)
		if err != nil {
			return nil, err
		}
		share, err := d.acquireShare(ctx, routePath.Server, routePath.Share)
		if err != nil {
			last = err
			if isUnavailable(err) {
				continue
			}
			return nil, err
		}
		d.mu.Lock()
		entry.hint = index
		d.mu.Unlock()
		return &resolvedRoute{session: share.session, share: share.value, path: routePath, source: entry, exact: suffix == ""}, nil
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return nil, last
}

func (d *Client) route(ctx context.Context, path string) (*resolvedRoute, error) {
	if entry, suffix, ok := d.cacheEntry(path); ok {
		return d.selectRoute(ctx, path, entry, suffix)
	}
	// Expired entries are refreshed on demand. This deliberately uses a hard
	// expiry policy; a failed refresh must not route an operation using stale
	// namespace data.
	if stale := d.staleEntry(path); stale != nil {
		fresh, err := d.queryReferral(ctx, path)
		if err != nil {
			return nil, err
		}
		if suffix, ok := pathpkg.CutPrefix(path, fresh.prefix); ok {
			return d.selectRoute(ctx, path, fresh, suffix)
		}
	}
	unc, err := pathpkg.ParseUNC(path)
	if err != nil {
		return nil, err
	}
	share, err := d.acquireShare(ctx, unc.Server, unc.Share)
	if err != nil {
		return nil, err
	}
	return &resolvedRoute{session: share.session, share: share.value, path: unc}, nil
}

type routeAction func(context.Context, *resolvedRoute) (any, error)

func (d *Client) execute(ctx context.Context, path string, action routeAction) (any, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d == nil {
		return nil, os.ErrInvalid
	}
	var forcedRoute *resolvedRoute
	defer func() {
		if forcedRoute != nil && forcedRoute.session != nil {
			forcedRoute.session.release()
		}
	}()
	for range maxReferralDepth {
		var route *resolvedRoute
		var err error
		if forcedRoute != nil {
			route, forcedRoute = forcedRoute, nil
		} else {
			route, err = d.route(ctx, path)
			if err != nil {
				return nil, err
			}
		}
		if route.source != nil && route.source.interlink {
			// An interlink has no storage server. Query the next namespace using
			// the selected target path, then restart resolution there.
			queryPath, entry, err := d.queryInterlink(ctx, path, route.source)
			if err != nil {
				return nil, err
			}
			suffix, ok := pathpkg.CutPrefix(queryPath, entry.prefix)
			if !ok {
				return nil, errors.New("client: interlink referral prefix does not match continuation")
			}
			forcedRoute, err = d.selectRoute(ctx, queryPath, entry, suffix)
			if err != nil {
				return nil, err
			}
			path = queryPath
			continue
		}
		value, err := action(ctx, route)
		route.session.release()
		if err == nil {
			return value, nil
		}
		var linkErr *protocol.CrossShareSymlinkError
		if errors.As(err, &linkErr) {
			if linkErr.ResolvedPath == "" {
				return nil, err
			}
			path = linkErr.ResolvedPath
			continue
		}
		if isUnavailable(err) {
			d.invalidateRoute(route)
		}
		var referralErr *protocol.DFSReferralRequiredError
		if errors.As(err, &referralErr) {
			// A PATH_NOT_COVERED issued to a link target must fail the original
			// I/O. Only an initial/root-target context may request another link
			// referral.
			actualPath := route.path.String()
			if route.source != nil && !route.source.root && pathpkg.EqualReferralPath(referralErr.Path, actualPath) {
				return nil, err
			}
			entry, qerr := d.queryReferral(ctx, referralErr.Path)
			if qerr != nil {
				return nil, qerr
			}
			suffix, ok := pathpkg.CutPrefix(referralErr.Path, entry.prefix)
			if !ok {
				return nil, errors.New("client: referral prefix does not match continuation")
			}
			if referralErr.ReparsePoint && suffix == "" && !entry.root {
				return nil, os.ErrPermission
			}
			forcedRoute, qerr = d.selectRoute(ctx, referralErr.Path, entry, suffix)
			if qerr != nil {
				return nil, qerr
			}
			path = referralErr.Path
			continue
		}
		return nil, err
	}
	return nil, errReferralDepth
}
