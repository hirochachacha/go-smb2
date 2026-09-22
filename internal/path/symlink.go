package path

import (
	"errors"
	"strings"
)

// SplitSymlinkUNC validates a resolved symbolic-link UNC, permitting a trailing separator.
func SplitSymlinkUNC(path string) (server, share, rest string, ok bool) {
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

// NormalizeSymlinkUNC resolves dot components while clamping traversal at the share root.
func NormalizeSymlinkUNC(path string) (string, bool) {
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
	return JoinUNC(clean[0], clean[1], clean[2:]...), true
}

// ResolveRelativeSymlink resolves an SMB target and suffix without escaping the share root.
func ResolveRelativeSymlink(linkPath, target, suffix string) (string, error) {
	stack := SplitAll(Dir(linkPath))
	parts := strings.Split(target, `\`)
	for i, part := range parts {
		switch part {
		case ".":
		case "":
			if i != 0 && i != len(parts)-1 {
				return "", errors.New("relative symbolic link target has an empty component")
			}
		case "..":
			if len(stack) == 0 {
				return "", errors.New("symbolic link escapes share root")
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(part, ':') {
				return "", errors.New("relative symbolic link target contains a drive separator")
			}
			stack = append(stack, part)
		}
	}
	for _, part := range SplitAll(suffix) {
		switch part {
		case ".":
		case "..":
			if len(stack) == 0 {
				return "", errors.New("symbolic link suffix escapes share root")
			}
			stack = stack[:len(stack)-1]
		default:
			if strings.ContainsRune(part, ':') {
				return "", errors.New("symbolic link suffix contains a drive separator")
			}
			stack = append(stack, part)
		}
	}
	return Join(stack...), nil
}
