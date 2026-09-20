package smb2

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const (
	DFSReferralHeaderServers                = dfsc.ReferralHeaderServers
	DFSReferralHeaderStorage                = dfsc.ReferralHeaderStorage
	DFSReferralHeaderFailback               = dfsc.ReferralHeaderFailback
	DFSReferralFlagNameList                 = dfsc.ReferralNameList
	DFSReferralFlagTargetSetBoundary        = dfsc.ReferralTargetBoundary
	DFSReferralServerRoot            uint16 = 1
	DFSReferralServerLink            uint16 = 0
)

// DFSReferralResponse is one validated RESP_GET_DFS_REFERRAL response.
type DFSReferralResponse struct {
	PathConsumed uint16             // UTF-16 byte count consumed from the request path.
	HeaderFlags  uint32             // DFS referral header flags.
	Prefix       string             // Full UNC prefix matched by the response.
	Entries      []DFSReferralEntry // Entries in server response order.
}

// DFSReferralEntry describes one ordered referral target or name-list entry.
type DFSReferralEntry struct {
	Version          uint16
	ServerType       uint16
	Flags            uint16
	TTL              time.Duration // Time to live supplied by the server.
	DFSPath          string        // DFS path prefix from the wire response.
	DFSAlternatePath string        // Alternate DFS path from the wire response.
	NetworkAddress   string        // Target exactly as returned by the server.
	TargetPath       string        // Target with the request's unparsed suffix.
	SpecialName      string        // Name-list special name, when present.
	ExpandedNames    []string      // Name-list expanded names, in wire order.
}

// ReferralOption configures a DFS referral query.
type ReferralOption interface {
	applyReferralOption(*referralConfig)
}

type referralConfig struct {
	siteName string
}

type siteNameOption string

func (o siteNameOption) applyReferralOption(c *referralConfig) {
	c.siteName = string(o)
}

// WithSiteName returns a ReferralOption that specifies the client computer's
// Active Directory site name to request site-aware DFS referral ordering
// using REQ_GET_DFS_REFERRAL_EX ([MS-DFSC] 2.2.3).
func WithSiteName(siteName string) ReferralOption {
	return siteNameOption(siteName)
}

func (s *Session) GetDFSReferrals(ctx context.Context, path string, options ...ReferralOption) (*DFSReferralResponse, error) {
	if ctx == nil {
		panic("nil context")
	}
	if !pathpkg.ValidReferralPath(path) {
		return nil, os.ErrInvalid
	}
	var cfg referralConfig
	for _, opt := range options {
		if opt != nil {
			opt.applyReferralOption(&cfg)
		}
	}
	fs, err := s.getOrMountIPC(ctx)
	if err != nil {
		return nil, err
	}
	ctlCode := uint32(wire.FSCTL_DFS_GET_REFERRALS)
	var req wire.Encoder
	if cfg.siteName != "" {
		ctlCode = wire.FSCTL_DFS_GET_REFERRALS_EX
		req = &dfsc.ReferralRequestEx{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
			SiteName:         cfg.siteName,
		}
	} else {
		req = &dfsc.ReferralRequest{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
		}
	}
	for maxOutput := uint32(clientReferralInitialOutputSize); ; {
		res, err := fs.Request().WithFollowSymlinks(true).WithFileID(wire.RelatedFileId).
			Ioctl(ctlCode, req, maxOutput).Do(ctx)
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) && maxOutput < maxDFSReferralResponseSize {
				maxOutput = min(maxOutput*2, uint32(maxDFSReferralResponseSize))
				continue
			}
			return nil, err
		}
		out, err := res.Ioctl(0)
		if err != nil {
			res.Close()
			return nil, err
		}
		buf := append([]byte(nil), out.Output()...)
		res.Close()
		r, err := dfsc.ParseReferralResponse(buf, path)
		if err != nil {
			return nil, &os.PathError{Op: "getDFSReferrals", Path: path, Err: err}
		}
		return convertDFSReferral(r), nil
	}
}

func convertDFSReferral(r *dfsc.ReferralResponse) *DFSReferralResponse {
	nameList := r.IsNameList()
	prefix := ""
	suffix := ""
	if !nameList && len(r.Entries) > 0 {
		prefix, suffix = r.Prefix, r.Suffix
	}
	out := &DFSReferralResponse{PathConsumed: r.PathConsumed, HeaderFlags: r.ReferralHeaderFlags, Prefix: prefix, Entries: make([]DFSReferralEntry, len(r.Entries))}
	for i, e := range r.Entries {
		v := DFSReferralEntry{Version: e.Version, ServerType: e.ServerType, Flags: e.EntryFlags, TTL: time.Duration(e.TimeToLive) * time.Second, DFSPath: e.DFSPath, DFSAlternatePath: e.DFSAlternatePath, NetworkAddress: e.NetworkAddress, SpecialName: e.SpecialName, ExpandedNames: append([]string(nil), e.ExpandedNames...)}
		if !nameList && e.NetworkAddress != "" {
			v.TargetPath = normalizePublicUNC(e.NetworkAddress)
			if suffix != "" {
				v.TargetPath = appendReferralSuffix(v.TargetPath, suffix)
			}
		}
		out.Entries[i] = v
	}
	return out
}

func appendReferralSuffix(target, suffix string) string {
	if suffix == "" {
		return target
	}
	target = normalizePublicUNC(target)
	if strings.HasSuffix(target, `\`) {
		return strings.TrimRight(target, `\`) + suffix
	}
	return target + suffix
}

func normalizePublicUNC(path string) string {
	path = strings.TrimLeft(path, `\`)
	return `\\` + path
}
