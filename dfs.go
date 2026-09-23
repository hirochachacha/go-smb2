package smb2

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

type dfsClient struct {
	ipc *Share
}

func (d *dfsClient) getReferrals(ctx context.Context, path string, options *dfs.ReferralOptions) (*dfs.ReferralResponse, error) {
	ctlCode := uint32(wire.FSCTL_DFS_GET_REFERRALS)
	var req wire.Encoder
	if options != nil && options.SiteName != "" {
		ctlCode = wire.FSCTL_DFS_GET_REFERRALS_EX
		req = &dfsc.ReferralRequestEx{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
			SiteName:         options.SiteName,
		}
	} else {
		req = &dfsc.ReferralRequest{
			MaxReferralLevel: dfsc.ReferralLevel4,
			RequestFileName:  path,
		}
	}
	for maxOutput := uint32(clientReferralInitialOutputSize); ; {
		res, err := d.ipc.Request().WithFollowSymlinks(true).WithFileID(wire.RelatedFileId).
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

func convertDFSReferral(r *dfsc.ReferralResponse) *dfs.ReferralResponse {
	nameList := r.IsNameList()
	prefix := ""
	suffix := ""
	if !nameList && len(r.Entries) > 0 {
		prefix, suffix = r.Prefix, r.Suffix
	}
	out := &dfs.ReferralResponse{PathConsumed: r.PathConsumed, HeaderFlags: r.ReferralHeaderFlags, Prefix: prefix, Entries: make([]dfs.ReferralEntry, len(r.Entries))}
	for i, e := range r.Entries {
		v := dfs.ReferralEntry{Version: e.Version, ServerType: e.ServerType, Flags: e.EntryFlags, TTL: time.Duration(e.TimeToLive) * time.Second, DFSPath: e.DFSPath, DFSAlternatePath: e.DFSAlternatePath, NetworkAddress: e.NetworkAddress, SpecialName: e.SpecialName, ExpandedNames: append([]string(nil), e.ExpandedNames...)}
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
