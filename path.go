package smb2

import (
	"errors"
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

func validatePath(op string, path string, allowAbs bool) error {
	if len(path) == 0 {
		return nil
	}

	if !allowAbs && path[0] == '\\' {
		return &os.PathError{Op: op, Path: path, Err: errors.New("leading '\\' is not allowed in this operation")}
	}

	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return &os.PathError{Op: op, Path: path, Err: os.ErrInvalid}
	}

	return nil
}

var mountPathPattern = regexp.MustCompile(`^\\\\[^\\/]+\\[^\\/]+$`)

func validateMountPath(path string) error {
	if utf16le.EncodedStringLen(path) > math.MaxUint16 {
		return &os.PathError{Op: "mount", Path: path, Err: os.ErrInvalid}
	}

	if !mountPathPattern.MatchString(path) {
		return &os.PathError{Op: "mount", Path: path, Err: errors.New(`mount path must be a valid share name (\\<server>\<share>)`)}
	}
	return nil
}

// cleanShareRelativePath normalizes the target path of a relative symbolic
// link before it is reissued in an SMB2 CREATE request. [MS-SMB2] 2.2.2.2.1.1
// requires "." and ".." components to be eliminated, and [MS-FSCC] 2.1.5.1
// requires ".." at the root of a share to be treated as ".".
func cleanShareRelativePath(path string) string {
	path = strings.Replace(path, `/`, `\`, -1)

	elems := strings.Split(path, `\`)
	cleaned := make([]string, 0, len(elems))
	for _, elem := range elems {
		switch elem {
		case "", ".":
			continue
		case "..":
			if len(cleaned) > 0 {
				cleaned = cleaned[:len(cleaned)-1]
			}
		default:
			cleaned = append(cleaned, elem)
		}
	}

	return strings.Join(cleaned, `\`)
}

func normPath(path string) string {
	path = strings.Replace(path, `/`, `\`, -1)
	for strings.HasPrefix(path, `.\`) {
		path = path[2:]
	}
	if path == "." {
		return ""
	}
	return path
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
