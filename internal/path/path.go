// Package path provides SMB and DFS path normalization and validation
// shared by the SMB2 client and the DFS resolver. SMB pathnames always use
// backslash as the separator.
package path

import (
	"os"
	"strings"
	"unicode/utf8"
)

// Separator is the SMB path separator.
const Separator = '\\'

// IsSeparator reports whether c is an SMB path separator.
func IsSeparator(c uint8) bool {
	return c == Separator
}

// Base returns the last element of path. Trailing separators are removed.
func Base(path string) string {
	j := len(path)
	for j > 0 && IsSeparator(path[j-1]) {
		j--
	}

	if j == 0 {
		return ""
	}

	i := j - 1
	for i > 0 && !IsSeparator(path[i-1]) {
		i--
	}

	return path[i:j]
}

// Dir returns all but the last element of path, typically the path's
// directory.
func Dir(path string) string {
	if path == "" {
		return ""
	}

	i := len(path)
	for i > 0 && IsSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return `\`
	}

	i--
	for i > 0 && !IsSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return ""
	}

	i--
	for i > 0 && IsSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return `\`
	}

	return path[:i]
}

// Split splits path immediately following the final separator, separating it
// into a directory and file name component.
func Split(path string) (dir, file string) {
	i := len(path) - 1
	for i >= 0 && !IsSeparator(path[i]) {
		i--
	}
	return path[:i+1], path[i+1:]
}

// Join joins path elements with the SMB separator and normalizes the result.
// Empty elements are ignored.
func Join(elem ...string) string {
	for i, e := range elem {
		if e != "" {
			return Normalize(strings.Join(elem[i:], string(Separator)))
		}
	}
	return ""
}

// ----------------------------------------------------------------------------
// UNC paths
// ----------------------------------------------------------------------------

// Component length limits from [MS-DTYP] 2.2.57.
const (
	shareNameMaxLen  = 80
	objectPartMaxLen = 255
)

// UNC is a parsed \\<server>\<share>[\<relpath>] path.
type UNC struct {
	Server  string
	Share   string
	RelPath string
}

// JoinUNC joins server, share, and optional relative path components into a
// canonical UNC path \\<server>\<share>[\<relpath>].
func JoinUNC(server, share string, elem ...string) string {
	base := `\\` + server + `\` + share
	if len(elem) == 0 {
		return base
	}
	rest := strings.TrimLeft(Normalize(strings.Join(elem, string(Separator))), `\`)
	if rest == "" {
		return base
	}
	return base + `\` + rest
}

// SplitAll splits path by SMB separators into its non-empty components.
func SplitAll(path string) []string {
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)
	if path == "" {
		return nil
	}
	parts := strings.Split(path, `\`)
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SharePath returns the \\<server>\<share> prefix.
func (u UNC) SharePath() string {
	return JoinUNC(u.Server, u.Share)
}

// String reassembles the UNC path.
func (u UNC) String() string {
	return JoinUNC(u.Server, u.Share, u.RelPath)
}

// ParseUNC parses and validates an absolute UNC path. It returns os.ErrInvalid
// for any malformed path.
func ParseUNC(path string) (UNC, error) {
	server, share, relPath, ok := SplitUNC(path)
	if !ok {
		return UNC{}, os.ErrInvalid
	}
	return UNC{Server: server, Share: share, RelPath: relPath}, nil
}

// SplitUNC splits an absolute UNC path into its server, share, and remaining
// components. It reports false when path is not a well-formed UNC path or
// exceeds component length limits.
func SplitUNC(path string) (server, share, relPath string, ok bool) {
	if len(path) < 3 || path[0] != '\\' || path[1] != '\\' || path[2] == '\\' {
		return "", "", "", false
	}
	parts := strings.Split(path[2:], `\`)
	if len(parts) < 2 {
		return "", "", "", false
	}
	server, share = parts[0], parts[1]
	if !validServerName(server) || !ValidShareName(share) {
		return "", "", "", false
	}
	if len(parts) == 2 {
		return server, share, "", true
	}
	relParts := parts[2:]
	for _, dir := range relParts[:len(relParts)-1] {
		if !validComponent(dir, objectPartMaxLen) {
			return "", "", "", false
		}
	}
	if !validFileComponent(relParts[len(relParts)-1]) {
		return "", "", "", false
	}
	return server, share, strings.Join(relParts, `\`), true
}

func isAllDots(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '.' {
			return false
		}
	}
	return len(s) > 0
}

func validPathChar(c byte) bool {
	return c >= 0x20 && c != '/' && c != '\\' && c != '*' && c != '?' && c != '"' && c != '<' && c != '>' && c != '|'
}

func validServerName(server string) bool {
	if server == "" || isAllDots(server) || utf8.RuneCountInString(server) > objectPartMaxLen {
		return false
	}
	isBracketed := strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]")
	if isBracketed && len(server) <= 2 {
		return false
	}
	for i := 0; i < len(server); i++ {
		c := server[i]
		if c <= 0x20 || !validPathChar(c) {
			return false
		}
		if c == ':' && !isBracketed {
			return false
		}
		if (c == '[' && i != 0) || (c == ']' && i != len(server)-1) {
			return false
		}
	}
	return true
}

func validComponent(name string, maxLen int) bool {
	if name == "" || isAllDots(name) || utf8.RuneCountInString(name) > maxLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !validPathChar(c) || c == ':' {
			return false
		}
	}
	return true
}

func validFileComponent(part string) bool {
	name, streamPart, hasStream := strings.Cut(part, ":")
	if hasStream {
		sub := strings.Split(streamPart, ":")
		switch len(sub) {
		case 1:
			if sub[0] == "" {
				return false
			}
		case 2:
			if sub[1] == "" {
				return false
			}
		default:
			return false
		}
		for _, s := range sub {
			for j := 0; j < len(s); j++ {
				c := s[j]
				if !validPathChar(c) || c == ':' {
					return false
				}
			}
		}
	}
	return validComponent(name, objectPartMaxLen)
}

// NormalizeUNC validates path as an absolute UNC path and returns its
// canonical \\<server>\<share>[\<relpath>] form.
func NormalizeUNC(path string) (string, error) {
	u, err := ParseUNC(Normalize(path))
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// NormalizePattern normalizes an SMB search pattern. Unlike Normalize it does
// not collapse separators, because a pattern may contain trailing elements
// that are meaningful to the matcher.
func NormalizePattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `/`, `\`)
	for strings.HasPrefix(pattern, `.\`) {
		pattern = pattern[2:]
	}
	return pattern
}

// Normalize normalizes path for the wire. It converts '/' to '\', drops a
// leading ".\", and collapses redundant separators while preserving the
// leading run of separators that marks a UNC or absolute pathname. Dot
// components are preserved so ValidRelPath can still reject them.
func Normalize(path string) string {
	path = NormalizePattern(path)
	if path == "." {
		return ""
	}

	// A leading run of separators marks a UNC or absolute pathname and is
	// significant, so it must be preserved. Collapse any redundant separators
	// elsewhere: [MS-FSCC] 2.1.5 composes a pathname from one or more non-empty
	// components, so an empty component must not be sent over the wire.
	i := 0
	for i < len(path) && path[i] == '\\' {
		i++
	}
	prefix, rest := path[:i], path[i:]
	if !strings.Contains(rest, `\\`) && !strings.HasSuffix(rest, `\`) {
		return path
	}
	elems := strings.Split(rest, `\`)
	out := elems[:0]
	for _, elem := range elems {
		if elem != "" {
			out = append(out, elem)
		}
	}
	return prefix + strings.Join(out, `\`)
}

// ValidRelPath reports whether path is a valid share-relative path for encoding
// into an [MS-SMB2] CREATE name.
// It follows io/fs.ValidPath's rules with backslash separators, except that the
// root is represented by an empty string rather than ".".
func ValidRelPath(path string) bool {
	if !utf8.ValidString(path) {
		return false
	}
	if len(path) == 0 {
		return true
	}

	if path[0] == Separator {
		return false
	}

	// [MS-FSCC] 2.1.5.1 forbids sending "." or ".." components on the wire,
	// and [MS-SMB2] 2.2.13 requires the CREATE name to conform to that
	// pathname format.
	for {
		i := 0
		for i < len(path) && path[i] != Separator {
			i++
		}
		elem := path[:i]
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
		if i == len(path) {
			return true
		}
		path = path[i+1:]
	}
}

// NormalizeRelPath normalizes path and validates that it is a valid share-relative path.
func NormalizeRelPath(path string) (string, error) {
	path = Normalize(path)
	if !ValidRelPath(path) {
		return "", os.ErrInvalid
	}
	return path, nil
}

// ValidShareName reports whether name is a valid single share name component.
func ValidShareName(name string) bool {
	return validComponent(name, shareNameMaxLen)
}

// ----------------------------------------------------------------------------
// DFS referral paths
// ----------------------------------------------------------------------------

// ValidReferralPath reports whether path is a valid DFS referral RequestFileName
// ([MS-DFSC] 3.1.4.2): an empty path (DOMAIN), \<domain> or \\<domain> (DC),
// or \\<server>\<share>[\<path>...] (SYSVOL/ROOT/LINK).
func ValidReferralPath(path string) bool {
	if path == "" {
		return true
	}
	if path[0] != '\\' {
		return false
	}
	if strings.HasPrefix(path, `\\`) {
		if len(path) >= 3 && path[2] == '\\' {
			return false
		}
		for _, part := range strings.Split(path[2:], `\`) {
			if part == "" || strings.ContainsAny(part, `/:`) {
				return false
			}
		}
		return true
	}
	// Single leading backslash: exactly one non-empty component.
	part := path[1:]
	return part != "" && !strings.ContainsAny(part, `\/:`)
}

// CutPrefix reports whether path begins with prefix (component-wise, case-insensitively).
// If it does, suffix is the remainder including its leading separator; otherwise ok is false.
func CutPrefix(path, prefix string) (suffix string, ok bool) {
	p := strings.Trim(path, `\`)
	pref := strings.Trim(prefix, `\`)
	if pref == "" || len(p) < len(pref) || !strings.EqualFold(p[:len(pref)], pref) {
		return "", false
	}
	if len(p) == len(pref) {
		return "", true
	}
	if p[len(pref)] != '\\' {
		return "", false
	}
	return p[len(pref):], true
}
