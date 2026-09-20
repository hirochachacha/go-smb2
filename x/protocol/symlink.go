package protocol

import (
	"context"
	"errors"
	"math"
	"strings"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func (req *Request) resolveSymlink(_ context.Context, name string, rerr *ResponseError, data []byte) (string, error) {
	d := wire.SymbolicLinkErrorResponseDecoder(data)
	if d.IsInvalid() {
		return "", invalidResponse(wire.SMB2_CREATE, "broken symbolic link error response format")
	}
	ud, suffix := d.SplitUnparsedPath(name)
	if ud == "" && suffix == "" {
		return "", invalidResponse(wire.SMB2_CREATE, "broken symbolic link error response format")
	}
	target := d.SubstituteName()
	if d.Flags()&wire.SYMLINK_FLAG_RELATIVE != 0 {
		resolved, err := resolveRelativeLink(ud, target, suffix)
		if err != nil {
			return "", err
		}
		if utf16le.EncodedStringLen(resolved) > math.MaxUint16 {
			return "", errors.New("protocol: resolved symbolic link path exceeds uint16")
		}
		return resolved, nil
	}
	resolved, ok := normalizeAbsoluteUNC(target + suffix)
	if !ok {
		return "", invalidResponse(wire.SMB2_CREATE, "symbolic link target is not a valid UNC path")
	}
	if utf16le.EncodedStringLen(resolved) > math.MaxUint16 {
		return "", errors.New("protocol: resolved symbolic link path exceeds uint16")
	}
	server, share, rest, ok := parseUNCPath(resolved)
	if !ok {
		return "", invalidResponse(wire.SMB2_CREATE, "symbolic link target is not a UNC path")
	}
	if strings.EqualFold(server, req.tc.serverName) && strings.EqualFold(share, req.tc.shareName) {
		return rest, nil
	}
	return "", &CrossShareSymlinkError{
		Path: req.tc.uncPath(name), Target: target, Relative: false,
		UnparsedPath: suffix, ResolvedPath: resolved, err: rerr,
	}
}

func parseUNCPath(path string) (server, share, rest string, ok bool) {
	p, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", "", "", false
	}
	parts := strings.Split(p, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	for i, part := range parts {
		if part == "" {
			if i == len(parts)-1 {
				continue
			}
			return "", "", "", false
		}
		if part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return "", "", "", false
		}
	}
	server, share = parts[0], parts[1]
	if len(parts) > 2 {
		rest = strings.Join(parts[2:], `\`)
	}
	return server, share, rest, true
}

func normalizeAbsoluteUNC(path string) (string, bool) {
	p, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", false
	}
	parts := strings.Split(p, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	for _, part := range parts[:2] {
		if part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return "", false
		}
	}
	clean := append([]string(nil), parts[:2]...)
	for _, part := range parts[2:] {
		switch part {
		case "", ".":
		case "..":
			if len(clean) > 2 {
				clean = clean[:len(clean)-1]
			}
		default:
			if strings.ContainsAny(part, "/:\x00") {
				return "", false
			}
			clean = append(clean, part)
		}
	}
	return pathpkg.JoinUNC(clean[0], clean[1], clean[2:]...), true
}

func resolveRelativeLink(linkPath, target, suffix string) (string, error) {
	stack := pathpkg.SplitAll(pathpkg.Dir(linkPath))
	parts := strings.Split(strings.ReplaceAll(target, `/`, `\`), `\`)
	for i, part := range parts {
		switch part {
		case ".":
		case "":
			if i != 0 && i != len(parts)-1 {
				return "", invalidResponse(wire.SMB2_CREATE, "relative symbolic link target has an empty component")
			}
		case "..":
			if len(stack) == 0 {
				return "", invalidResponse(wire.SMB2_CREATE, "symbolic link escapes share root")
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(part, ':') {
				return "", invalidResponse(wire.SMB2_CREATE, "relative symbolic link target contains a drive separator")
			}
			stack = append(stack, part)
		}
	}
	for _, part := range pathpkg.SplitAll(suffix) {
		switch part {
		case ".":
		case "..":
			if len(stack) == 0 {
				return "", invalidResponse(wire.SMB2_CREATE, "symbolic link suffix escapes share root")
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(part, ':') {
				return "", invalidResponse(wire.SMB2_CREATE, "symbolic link suffix contains a drive separator")
			}
			stack = append(stack, part)
		}
	}
	return pathpkg.Join(stack...), nil
}
