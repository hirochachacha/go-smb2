package smb2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hirochachacha/go-smb2/v2/internal/dfsc"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
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

func (s *Session) GetDFSReferrals(ctx context.Context, path string) (*DFSReferralResponse, error) {
	if ctx == nil {
		panic("nil context")
	}
	if err := validateReferralPath(path); err != nil {
		return nil, err
	}
	fs, err := s.getOrMountIPC(ctx)
	if err != nil {
		return nil, err
	}
	for maxOutput := uint32(4096); ; {
		req := &dfsc.ReferralRequest{MaxReferralLevel: dfsc.ReferralLevel4, RequestFileName: path}
		res, err := fs.request().withFileId(smb2.RelatedFileId).
			ioctl(smb2.FSCTL_DFS_GET_REFERRALS, req, maxOutput).sendRecv(ctx)
		if err != nil {
			if errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) && maxOutput < 56*1024 {
				maxOutput *= 2
				if maxOutput > 56*1024 {
					maxOutput = 56 * 1024
				}
				continue
			}
			return nil, err
		}
		if res == nil {
			return nil, &InvalidResponseError{"missing DFS referral response"}
		}
		out := smb2.IoctlResponseDecoder(res.data(0))
		if out.IsInvalid() {
			res.close()
			return nil, &InvalidResponseError{"broken DFS referral IOCTL response"}
		}
		if out.OutputCount() > maxOutput {
			res.close()
			return nil, &InvalidResponseError{"DFS referral IOCTL output exceeds requested size"}
		}
		buf := append([]byte(nil), out.Output()...)
		res.close()
		r, err := dfsc.ParseReferralResponse(buf, path)
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}
		}
		return convertDFSReferral(r, path)
	}
}

func validateReferralPath(path string) error {
	if strings.ContainsRune(path, '/') || strings.ContainsRune(path, ':') {
		return fmt.Errorf("invalid DFS referral path %q", path)
	}
	if path == "" {
		return nil
	}
	leading := len(path) - len(strings.TrimLeft(path, `\`))
	if leading == 0 || leading > 2 {
		return fmt.Errorf("invalid DFS referral path %q", path)
	}
	p := path[leading:]
	if p == "" {
		return fmt.Errorf("invalid DFS referral path %q", path)
	}
	components := strings.Split(p, `\`)
	for _, c := range components {
		if c == "" {
			return fmt.Errorf("invalid DFS referral path %q", path)
		}
	}
	// A one-component path is the documented DC referral form. It may use
	// either one or two leading backslashes (\domain or \\domain).
	if len(components) == 1 {
		return nil
	}
	// ROOT/LINK referral requests must be full UNC paths.
	if leading != 2 || len(components) < 2 {
		return fmt.Errorf("invalid DFS referral path %q", path)
	}
	return nil
}

func convertDFSReferral(r *dfsc.ReferralResponse, request string) (*DFSReferralResponse, error) {
	nameList := r.IsNameList()
	prefix := ""
	suffix := ""
	if !nameList && len(r.Entries) > 0 {
		var err error
		prefix, suffix, err = referralPrefixSuffix(request, r.PathConsumed)
		if err != nil {
			return nil, err
		}
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
	return out, nil
}

func referralPrefixSuffix(request string, consumed uint16) (string, string, error) {
	wire := normalizeReferralPath(request)
	runes := []rune(wire)
	units := 0
	cut := -1
	if consumed == 0 {
		cut = 0
	} else {
		for i, r := range runes {
			n := len(utf16.Encode([]rune{r})) * 2
			if units+n > int(consumed) {
				return "", "", &InvalidResponseError{"DFS referral PathConsumed splits a UTF-16 scalar"}
			}
			units += n
			if units == int(consumed) {
				cut = i + 1
				break
			}
		}
	}
	if cut < 0 || units != int(consumed) {
		return "", "", &InvalidResponseError{"invalid DFS referral PathConsumed"}
	}
	if cut > 0 && cut < len(runes) && runes[cut] != '\\' {
		return "", "", &InvalidResponseError{"DFS referral PathConsumed is not a component boundary"}
	}
	prefixWire := string(runes[:cut])
	suffixWire := string(runes[cut:])
	prefix := ""
	if prefixWire != "" {
		prefix = `\\` + strings.TrimLeft(prefixWire, `\`)
	}
	suffix := suffixWire
	if suffix != "" && suffix[0] != '\\' {
		suffix = `\` + suffix
	}
	return prefix, suffix, nil
}

func normalizeReferralPath(path string) string {
	if path == "" {
		return ""
	}
	return `\` + strings.TrimLeft(path, `\`)
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
