// Original: src/path/filepath/match.go
//
// Copyright 2010 The Go Authors. All rights reserved.
// Portions Copyright 2021 Hiroshi Ioka. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package path

import (
	"context"
	"os"
	"strings"
)

// Glob expands an SMB pattern using lstat for literal paths and search for
// a single directory. Search appends full paths to its matches argument.
func Glob(ctx context.Context, pattern string, depth int, lstat func(context.Context, string) (os.FileInfo, error), search func(context.Context, string, string, []string) ([]string, error)) (matches []string, err error) {
	// Limit recursion to prevent stack exhaustion from deeply nested patterns,
	// following path/filepath.Glob (GO-2022-0522).
	if depth >= 10000 {
		return nil, ErrBadPattern
	}

	pattern = NormalizePattern(pattern)

	// Check pattern is well-formed.
	if _, err := Match(pattern, ""); err != nil {
		return nil, err
	}

	if !HasMeta(pattern) {
		if _, err = lstat(ctx, pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}

	dir, file := Split(pattern)

	dir = cleanGlobPath(dir)

	if !HasMeta(dir) {
		return search(ctx, dir, file, nil)
	}

	// Prevent infinite recursion. See issue 15879.
	if dir == pattern {
		return nil, ErrBadPattern
	}

	var m []string
	m, err = Glob(ctx, dir, depth+1, lstat, search)
	if err != nil {
		return
	}
	for _, d := range m {
		matches, err = search(ctx, d, file, matches)
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
	case string(Separator):
		// do nothing to the path
		return path
	default:
		if strings.HasSuffix(path, string(Separator)) {
			return path[:len(path)-1]
		}
		return path
	}
}

// HasMeta reports whether a pattern contains wildcard syntax.
func HasMeta(pattern string) bool { return strings.ContainsAny(pattern, "*?[") }

// EscapeGlob quotes wildcard characters in a literal path.
func EscapeGlob(s string) string {
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
