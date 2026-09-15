package dfs

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type uncPath struct {
	server string
	share  string
	rest   string
}

func parseUNC(path string) (uncPath, error) {
	if path == "" || !strings.HasPrefix(path, `\\`) {
		return uncPath{}, fmt.Errorf("path must be an absolute UNC: %q", path)
	}
	p := strings.TrimLeft(path, `\`)
	parts := strings.Split(p, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return uncPath{}, fmt.Errorf("path must contain server and share: %q", path)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return uncPath{}, fmt.Errorf("invalid UNC component in %q", path)
		}
	}
	return uncPath{server: parts[0], share: parts[1], rest: strings.Join(parts[2:], `\`)}, nil
}

func makeUNC(server, share, rest string) string {
	server = strings.Trim(server, `\`)
	share = strings.Trim(share, `\`)
	rest = strings.Trim(rest, `\`)
	if rest == "" {
		return `\\` + server + `\` + share
	}
	return `\\` + server + `\` + share + `\` + rest
}

func normalizeTargetUNC(path string) (string, error) {
	p := strings.TrimLeft(path, `\`)
	if p == "" {
		return "", errors.New("empty DFS target")
	}
	parts := strings.Split(p, `\`)
	if len(parts) < 2 {
		return "", fmt.Errorf("DFS target is not a UNC: %q", path)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/:\x00") {
			return "", fmt.Errorf("invalid DFS target %q", path)
		}
	}
	return makeUNC(parts[0], parts[1], strings.Join(parts[2:], `\`)), nil
}

func componentParts(path string) []string {
	return strings.Split(strings.Trim(path, `\`), `\`)
}

func componentPrefix(prefix, path string) (string, bool) {
	a, b := componentParts(prefix), componentParts(path)
	if len(a) == 0 || len(a) > len(b) {
		return "", false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return "", false
		}
	}
	if len(a) == len(b) {
		return "", true
	}
	return `\` + strings.Join(b[len(a):], `\`), true
}

func operationError(op, path string, err error) error {
	if err == nil {
		return nil
	}
	return &os.PathError{Op: op, Path: path, Err: err}
}
