package smb2

import (
	"os"
	"regexp"
	"strings"
)

const PathSeparator = '\\'

func IsPathSeparator(c uint8) bool {
	return c == '\\'
}

var (
	sharePathPattern = regexp.MustCompile(`^\\\\([^\\/]+)\\([^\\/]+)$`)
	// referralPathPattern matches a non-empty DFS referral RequestFileName
	// ([MS-DFSC] 3.1.4.2): \<domain> or \\<domain> (DC), or
	// \\<server>\<share>[\<path>...] (SYSVOL/ROOT/LINK).
	referralPathPattern = regexp.MustCompile(`^(?:\\[^\\/:]+|\\\\[^\\/:]+(?:\\[^\\/:]+)*)$`)
)

func base(path string) string {
	j := len(path)
	for j > 0 && IsPathSeparator(path[j-1]) {
		j--
	}

	if j == 0 {
		return ""
	}

	i := j - 1
	for i > 0 && !IsPathSeparator(path[i-1]) {
		i--
	}

	return path[i:j]
}

func dir(path string) string {
	if path == "" {
		return ""
	}

	i := len(path)
	for i > 0 && IsPathSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return "\\"
	}

	i--
	for i > 0 && !IsPathSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return ""
	}

	i--
	for i > 0 && IsPathSeparator(path[i-1]) {
		i--
	}

	if i == 0 {
		return "\\"
	}

	return path[:i]
}

// splitSharePath splits a \\<server>\<share> path into its components.
func splitSharePath(path string) (server, share string, err error) {
	m := sharePathPattern.FindStringSubmatch(path)
	if m == nil {
		return "", "", os.ErrInvalid
	}
	if err := validateShareName(m[2]); err != nil {
		return "", "", err
	}
	return m[1], m[2], nil
}

func normPath(path string) string {
	path = strings.ReplaceAll(path, `/`, `\`)
	for strings.HasPrefix(path, `.\`) {
		path = path[2:]
	}
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

func normPattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `/`, `\`)
	for strings.HasPrefix(pattern, `.\`) {
		pattern = pattern[2:]
	}
	return pattern
}

func join(elem ...string) string {
	return normPath(strings.Join(elem, string(PathSeparator)))
}

func split(path string) (dir, file string) {
	i := len(path) - 1
	for i >= 0 && !IsPathSeparator(path[i]) {
		i--
	}
	return path[:i+1], path[i+1:]
}

// ----------------------------------------------------------------------------
// Path validation
// ----------------------------------------------------------------------------

// validateReferralPath validates a DFS referral RequestFileName. An empty path
// is a DOMAIN referral.
func validateReferralPath(path string) error {
	if path == "" {
		return nil
	}
	if !referralPathPattern.MatchString(path) {
		return os.ErrInvalid
	}
	return nil
}

// validateShareName validates a single share name component.
func validateShareName(name string) error {
	if name == "" || strings.ContainsAny(name, `\\/`) || name == "." || name == ".." {
		return os.ErrInvalid
	}
	return nil
}

// validatePath validates a share-relative path for encoding into an [MS-SMB2]
// CREATE or QUERY_DIRECTORY name. allowAbs exempts symbolic-link targets and
// glob patterns, which may begin with a separator or a ".." component.
func validatePath(path string, allowAbs bool) error {
	if len(path) == 0 {
		return nil
	}

	if !allowAbs && path[0] == '\\' {
		return os.ErrInvalid
	}

	// [MS-FSCC] 2.1.5.1 forbids sending "." or ".." components on the wire
	// except in the explicitly allowed cases, and [MS-SMB2] 2.2.13 requires
	// the CREATE name to conform to that pathname format. Share-relative
	// CREATE names must therefore not contain such components.
	if !allowAbs {
		for _, elem := range strings.Split(path, `\`) {
			if elem == "." || elem == ".." {
				return os.ErrInvalid
			}
		}
	}

	return nil
}
