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

package smb2

import (
	"context"
	"errors"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
)

// Glob should work like filepath.Glob.
func (fs *Share) Glob(ctx context.Context, pattern string) (matches []string, err error) {
	return fs.globWithLimit(ctx, pattern, 0)
}

func (fs *Share) globWithLimit(ctx context.Context, pattern string, depth int) (matches []string, err error) {
	// Limit recursion to prevent stack exhaustion from deeply nested patterns,
	// following path/filepath.Glob (GO-2022-0522).
	if depth >= clientMaxGlobDepth {
		return nil, pathpkg.ErrBadPattern
	}

	pattern = pathpkg.NormalizePattern(pattern)

	// Check pattern is well-formed.
	if _, err := pathpkg.Match(pattern, ""); err != nil {
		return nil, err
	}

	if !hasMeta(pattern) {
		if _, err = fs.Lstat(ctx, pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}

	dir, file := pathpkg.Split(pattern)

	dir = cleanGlobPath(dir)

	if !hasMeta(dir) {
		return fs.glob(ctx, dir, file, nil)
	}

	// Prevent infinite recursion. See issue 15879.
	if dir == pattern {
		return nil, pathpkg.ErrBadPattern
	}

	var m []string
	m, err = fs.globWithLimit(ctx, dir, depth+1)
	if err != nil {
		return
	}
	for _, d := range m {
		matches, err = fs.glob(ctx, d, file, matches)
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
	case string(pathpkg.Separator):
		// do nothing to the path
		return path
	default:
		if strings.HasSuffix(path, string(pathpkg.Separator)) {
			return path[:len(path)-1]
		}
		return path
	}
}

// QUERY_DIRECTORY search patterns ([MS-SMB2] 2.2.33) do not support bracket
// classes: '[' is literal under [MS-FSA] 2.1.4.4 wildcard matching.
// Simplify every bracket class, including an escaped literal such as "[[]",
// to '?' so the server search stays a superset; the final pathpkg.Match still filters
// the returned names with the original class.
var characterRangePattern = regexp.MustCompile(`\[[^\]]+\]`)

func simplifyPattern(pattern string) string {
	return characterRangePattern.ReplaceAllLiteralString(pattern, "?")
}

// glob searches for files matching pattern in the directory dir
// and appends them to matches. If the directory cannot be
// opened, it returns the existing matches. New matches are
// added in lexicographical order.
func (fs *Share) glob(ctx context.Context, dir, pattern string, matches []string) (m []string, e error) {
	m = matches
	searchPattern := simplifyPattern(pattern)

	fi, err := fs.Stat(ctx, dir)
	if err != nil {
		return // ignore I/O error
	}
	if !fi.IsDir() {
		return // ignore I/O error
	}
	d, err := fs.Open(ctx, dir)
	if err != nil {
		return // ignore I/O error
	}
	defer d.Close(ctx)

	var names []string

L:
	for {
		dirents, err := d.fs.readdir(ctx, d.fd, searchPattern)
		for _, st := range dirents {
			names = append(names, st.Name())
		}
		if err != nil {
			if status, ok := errors.AsType[erref.NtStatus](err); ok {
				switch status {
				case erref.STATUS_NO_SUCH_FILE:
					break L
				case erref.STATUS_NO_MORE_FILES:
					break L
				}
			}
			return nil, &os.PathError{Op: "readdir", Path: d.name, Err: err}
		}
		if len(dirents) == 0 {
			break L
		}
	}

	for _, n := range names {
		matched, err := pathpkg.Match(pattern, n)
		if err != nil {
			return m, err
		}
		if matched {
			m = append(m, pathpkg.Join(dir, n))
		}
	}

	sort.Strings(m)

	return
}

// hasMeta reports whether path contains any of the magic characters
// recognized by pathpkg.Match.
func hasMeta(path string) bool {
	return strings.ContainsAny(path, `*?[`)
}
