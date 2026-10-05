package path

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGlobFSLiteralLookupErrors(t *testing.T) {
	t.Parallel()
	for _, lookupErr := range []error{context.Canceled, context.DeadlineExceeded, os.ErrNotExist, os.ErrPermission} {
		t.Run(lookupErr.Error(), func(t *testing.T) {
			wrapped := &os.PathError{Op: "lstat", Path: "file", Err: lookupErr}
			matches, err := GlobFS("file", func(string) (fs.FileInfo, error) {
				return nil, wrapped
			}, nil)
			if lookupErr == context.Canceled || lookupErr == context.DeadlineExceeded {
				if !errors.Is(err, lookupErr) {
					t.Fatalf("GlobFS error = %v, want %v", err, lookupErr)
				}
			} else if err != nil {
				t.Fatalf("GlobFS must ignore filesystem lookup errors: %v", err)
			}
			if matches != nil {
				t.Fatalf("GlobFS matches = %v, want nil", matches)
			}
		})
	}
}

func TestGlobFSEscapes(t *testing.T) {
	t.Parallel()
	tree := fstest.MapFS{
		"nested/file.txt": {}, "nested/fine.txt": {}, "nested/other.txt": {},
		"a中.txt": {}, "a😀.txt": {}, "aab.txt": {},
		"a[b]/file.txt": {}, "a-b.txt": {}, "a].txt": {}, "a*.txt": {}, "a?.txt": {},
	}
	for _, pattern := range []string{`a?.txt`, `a??.txt`, `a[中😀].txt`, `a[^中].txt`, `a\😀.txt`, `n[e][s-s][\t][\e-\e]d/f\ile.txt`, `nested/[\f]i*.txt`, `a\[b]/*.txt`, `a\*.txt`, `a\?.txt`, `a[\-].txt`, `a[\]].txt`, `*/file.txt`, `missing`} {
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

func TestGlobFSInvalidConcretePathsStayInvalid(t *testing.T) {
	t.Parallel()
	tree := fstest.MapFS{"hello.txt": {}, "sub/hello.txt": {}}
	// Deliberately permissive callbacks model SMB adapters' normalization.
	// Glob must reject invalid lookup paths before they can be normalized.
	for _, pattern := range []string{"./*.txt", "./hello.txt", "./*/hello.txt", "./sub/*.txt", "sub//*.txt", "sub/./*.txt", "sub/../*.txt", "/*.txt", "../*.txt", "sub/"} {
		t.Run(pattern, func(t *testing.T) {
			got, err := GlobFS(pattern, func(name string) (fs.FileInfo, error) { return fs.Stat(tree, path.Clean(name)) }, func(dir, pattern string) ([]string, error) {
				entries, err := fs.ReadDir(tree, path.Clean(dir))
				if err != nil {
					return nil, nil
				}
				var names []string
				for _, entry := range entries {
					names = append(names, entry.Name())
				}
				return names, nil
			})
			want, wantErr := fs.Glob(struct{ fs.FS }{tree}, pattern)
			if err != wantErr || !reflect.DeepEqual(got, want) {
				t.Errorf("GlobFS(%q)=%q,%v; generic=%q,%v", pattern, got, err, want, wantErr)
			}
		})
	}
}
