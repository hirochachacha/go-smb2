package dfs

import (
	"context"
	"errors"
	"os"
	"time"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const (
	referralInitialOutputSize = 4096
	maxReferralResponseSize   = 56 * 1024
)

// ReferralOption configures a referral query.
type ReferralOption interface {
	applyOption(*referralConfig)
}

type referralConfig struct {
	siteName string
}

type siteNameOption string

func (o siteNameOption) applyOption(c *referralConfig) {
	c.siteName = string(o)
}

// WithSiteName requests site-aware referral ordering for the named Active
// Directory site. An empty name uses the standard referral request.
func WithSiteName(name string) ReferralOption {
	return siteNameOption(name)
}

// Client queries DFS referrals through an IPC$ share.
type Client struct {
	share *smb2.Share
}

// NewClient creates a DFS client using share. It does not unmount share.
func NewClient(share *smb2.Share) *Client {
	return &Client{share: share}
}

// GetReferrals queries referrals for path. With no options, it uses the
// standard referral request.
func (c *Client) GetReferrals(ctx context.Context, path string, options ...ReferralOption) (*ReferralResponse, error) {
	if ctx == nil {
		panic("nil context")
	}
	if !pathpkg.ValidReferralPath(path) || c == nil || c.share == nil {
		return nil, os.ErrInvalid
	}
	var cfg referralConfig
	for _, option := range options {
		if option != nil {
			option.applyOption(&cfg)
		}
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
	for maxOutput := uint32(referralInitialOutputSize); ; {
		res, err := c.share.Request().WithFollowSymlinks(true).WithFileID(wire.RelatedFileId).
			Ioctl(ctlCode, req, maxOutput).Do(ctx)
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) && maxOutput < maxReferralResponseSize {
				maxOutput = min(maxOutput*2, uint32(maxReferralResponseSize))
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
		return convertReferral(r), nil
	}
}

func convertReferral(r *dfsc.ReferralResponse) *ReferralResponse {
	nameList := r.IsNameList()
	prefix := ""
	suffix := ""
	if !nameList && len(r.Entries) > 0 {
		prefix, suffix = r.Prefix, r.Suffix
	}
	out := &ReferralResponse{PathConsumed: r.PathConsumed, HeaderFlags: r.ReferralHeaderFlags, Prefix: prefix, Entries: make([]ReferralEntry, len(r.Entries))}
	for i, e := range r.Entries {
		v := ReferralEntry{Version: e.Version, ServerType: e.ServerType, Flags: e.EntryFlags, TTL: time.Duration(e.TimeToLive) * time.Second, DFSPath: e.DFSPath, DFSAlternatePath: e.DFSAlternatePath, NetworkAddress: e.NetworkAddress, SpecialName: e.SpecialName, ExpandedNames: append([]string(nil), e.ExpandedNames...)}
		if !nameList && e.NetworkAddress != "" {
			v.TargetPath = pathpkg.ToPublicUNC(e.NetworkAddress)
			if suffix != "" {
				v.TargetPath = pathpkg.AppendReferralSuffix(v.TargetPath, suffix)
			}
		}
		out.Entries[i] = v
	}
	return out
}
