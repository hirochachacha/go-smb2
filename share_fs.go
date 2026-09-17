//go:build go1.16

package smb2

import "strings"

func escapeGlob(s string) string {
	if !strings.ContainsAny(s, `*?[`) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*', '?', '[':
			b.WriteByte('[')
			b.WriteRune(r)
			b.WriteByte(']')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cleanMatches(matches []string, root string) []string {
	if root != "" {
		prefix := root + `\`
		validMatches := matches[:0]
		for _, match := range matches {
			if rest, ok := strings.CutPrefix(match, prefix); ok {
				validMatches = append(validMatches, strings.ReplaceAll(rest, `\`, "/"))
			}
		}
		return validMatches
	}
	for i, match := range matches {
		matches[i] = strings.ReplaceAll(match, `\`, "/")
	}
	return matches
}
