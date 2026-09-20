package path

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGlobFSEscapes(t *testing.T) {
	tree := fstest.MapFS{
		"nested/file.txt": {}, "nested/fine.txt": {}, "nested/other.txt": {},
		"a[b]/file.txt": {}, "a-b.txt": {}, "a].txt": {}, "a*.txt": {}, "a?.txt": {},
	}
	for _, pattern := range []string{`n[e][s-s][\t][\e-\e]d/f\ile.txt`, `nested/[\f]i*.txt`, `a\[b]/*.txt`, `a\*.txt`, `a\?.txt`, `a[\-].txt`, `a[\]].txt`, `*/file.txt`, `missing`} {
		t.Run(pattern, func(t *testing.T) {
			got, err := GlobFS(pattern, func(name string) (fs.FileInfo, error) { return fs.Stat(tree, name) }, func(dir, pattern string) ([]string, error) {
				entries, err := fs.ReadDir(tree, dir)
				if err != nil {
					return nil, nil
				}
				var names []string
				// Simulate SMB filtering, then let GlobFS perform the exact match.
				for _, entry := range entries {
					match, err := Match(SMBSearchPattern(pattern), entry.Name())
					if err != nil {
						t.Fatal(err)
					}
					if match {
						names = append(names, entry.Name())
					}
				}
				return names, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want, err := fs.Glob(tree, pattern)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("GlobFS = %v, want %v", got, want)
			}
		})
	}
	for _, pattern := range []string{`[`, `abc\`, `dir/[\]`} {
		if _, err := GlobFS(pattern, nil, nil); !errors.Is(err, path.ErrBadPattern) {
			t.Fatalf("GlobFS(%q) = %v", pattern, err)
		}
	}
	if _, err := GlobFS(strings.Repeat("*/", 10000)+"file", nil, nil); !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("deep pattern = %v", err)
	}
}
