package glob

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

// ErrBadPattern indicates a pattern was malformed.
var ErrBadPattern = errors.New("syntax error in pattern")

func normPattern(pattern string) string {
	if !smb2.NORMALIZE_PATH {
		return pattern
	}
	pattern = strings.ReplaceAll(pattern, `/`, `\`)
	for strings.HasPrefix(pattern, `.\`) {
		pattern = pattern[2:]
	}
	return pattern
}

func join(elem ...string) string {
	return strings.Join(elem, string(smb2.PathSeparator))
}

func split(path string) (dir, file string) {
	i := len(path) - 1
	for i >= 0 && !smb2.IsPathSeparator(path[i]) {
		i--
	}
	return path[:i+1], path[i+1:]
}

// Find should work like filepath.Glob.
func Find(fs *smb2.Share, pattern string) (matches []string, err error) {
	pattern = normPattern(pattern)

	if !hasMeta(pattern) {
		if _, err = fs.Lstat(pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}

	dir, file := split(pattern)

	dir = cleanGlobPath(dir)

	if !hasMeta(dir) {
		return glob(fs, dir, file, nil)
	}

	// Prevent infinite recursion.
	if dir == pattern {
		return nil, ErrBadPattern
	}

	var m []string
	m, err = Find(fs, dir)
	if err != nil {
		return
	}
	for _, d := range m {
		matches, err = glob(fs, d, file, matches)
		if err != nil {
			return
		}
	}
	return
}

// cleanGlobPath prepares path for glob matching.
func cleanGlobPath(path string) string {
	switch path {
	case "":
		return "."
	case string(smb2.PathSeparator):
		// do nothing to the path
		return path
	default:
		return path[0 : len(path)-1] // chop off trailing separator
	}
}

var characterRangePattern = regexp.MustCompile(`\[^?[^\[\]]+\]`)

func generalizePattern(pattern string) string {
	return characterRangePattern.ReplaceAllLiteralString(pattern, "?")
}

// glob searches for files matching pattern in the directory dir
// and appends them to matches. If the directory cannot be
// opened, it returns the existing matches. New matches are
// added in lexicographical order.
func glob(fs *smb2.Share, dir, pattern string, matches []string) (m []string, e error) {
	escapedPattern := strings.ReplaceAll(pattern, `\`, `\\`)
	dirents, err := fs.ReadDirPattern(dir, generalizePattern(pattern))
	for _, st := range dirents {
		name := st.Name()
		if ok, err := filepath.Match(escapedPattern, name); ok {
			matches = append(matches, join(dir, name))
		} else if err != nil {
			return matches, err
		}
	}

	sort.Strings(matches)

	return matches, err
}

// hasMeta reports whether path contains any of the magic characters
// recognized by Match.
func hasMeta(path string) bool {
	return strings.ContainsAny(path, `*?[`)
}
