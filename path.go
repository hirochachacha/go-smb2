package smb2

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

const PathSeparator = '\\'

func IsPathSeparator(c uint8) bool {
	return c == '\\'
}

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

func validatePath(path string, allowAbs bool) error {
	if len(path) == 0 {
		return nil
	}

	if !allowAbs && path[0] == '\\' {
		return os.ErrInvalid
	}

	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
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

var mountPathPattern = regexp.MustCompile(`^\\\\[^\\/]+\\[^\\/]+$`)

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

func validateMountPath(path string) error {
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return os.ErrInvalid
	}

	if !mountPathPattern.MatchString(path) {
		return &os.PathError{Op: "mount", Path: path, Err: errors.New(`mount path must be a valid share name (\\<server>\<share>)`)}
	}
	return nil
}

func splitUNCShare(unc string) (server, share string, err error) {
	if err := validateMountPath(unc); err != nil {
		return "", "", err
	}
	parts := strings.Split(strings.TrimPrefix(unc, `\\`), `\`)
	return parts[0], parts[1], nil
}

func normPath(path string) string {
	path = strings.Replace(path, `/`, `\`, -1)
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
	pattern = strings.Replace(pattern, `/`, `\`, -1)
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
