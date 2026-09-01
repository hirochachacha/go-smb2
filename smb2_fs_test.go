//go:build go1.16
// +build go1.16

package smb2_test

import (
	"fmt"
	iofs "io/fs"
	"os"
	"path"
	"reflect"
	"testing"
)

func TestDirFS(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestDirFS", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	err = fs.WriteFile(path.Join(testDir, "hello.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.Mkdir(path.Join(testDir, "hello"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(path.Join(testDir, "hello", "hello2.txt"), []byte("hello world!"), 0444)
	if err != nil {
		t.Fatal(err)
	}

	{
		var entries []string

		iofs.WalkDir(fs.DirFS(testDir), ".", func(path string, d iofs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}

			entries = append(entries, path)

			return nil
		})

		if !reflect.DeepEqual(entries, []string{".", "hello", "hello/hello2.txt", "hello.txt"}) {
			t.Error("unexpected result")
		}
	}

	{
		var entries []string

		iofs.WalkDir(fs.DirFS(testDir), "hello", func(path string, d iofs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}

			entries = append(entries, path)

			return nil
		})

		if !reflect.DeepEqual(entries, []string{"hello", "hello/hello2.txt"}) {
			t.Error("unexpected result")
		}
	}
}

func TestGlobFS(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestGlobFS", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	err = fs.WriteFile(path.Join(testDir, "hello.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.Mkdir(path.Join(testDir, "hello"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(path.Join(testDir, "hello", "hello2.txt"), []byte("hello world!"), 0444)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		pattern  string
		expected []string
	}{
		{
			pattern:  "hello.txt",
			expected: []string{"hello.txt"},
		},
		{
			pattern:  "hel?o.txt",
			expected: []string{"hello.txt"},
		},
		{
			pattern:  "*",
			expected: []string{"hello", "hello.txt"},
		},
		{
			pattern:  "*/*",
			expected: []string{`hello\hello2.txt`},
		},
	}

	for _, tt := range cases {
		matches, err := iofs.Glob(fs.DirFS(testDir), tt.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(matches, tt.expected) {
			t.Errorf("Glob(%q) = %q, want %q", tt.pattern, matches, tt.expected)
			t.Error("unexpected result")
		}
	}
}

func TestDirFSEdgeCases(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestDirFSEdgeCases", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	err = fs.WriteFile(path.Join(testDir, "sample.txt"), []byte("sample content"), 0666)
	if err != nil {
		t.Fatal(err)
	}

	dirFS := fs.DirFS(testDir)

	// 1. Valid path open & read
	f, err := dirFS.Open("sample.txt")
	if err != nil {
		t.Fatalf("dirFS.Open sample.txt failed: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Name() != "sample.txt" {
		t.Errorf("expected sample.txt, got %s", fi.Name())
	}
	f.Close()

	// 2. Invalid path checks (leading slash, parent traversal ..)
	for _, invalidPath := range []string{"/sample.txt", "../sample.txt", "a/../../sample.txt"} {
		_, err := dirFS.Open(invalidPath)
		if err == nil {
			t.Errorf("expected error for invalid io/fs path %q, got nil", invalidPath)
		}
	}

	// 3. ReadFile on DirFS
	rf, ok := dirFS.(iofs.ReadFileFS)
	if ok {
		content, err := rf.ReadFile("sample.txt")
		if err != nil {
			t.Fatalf("ReadFileFS.ReadFile failed: %v", err)
		}
		if string(content) != "sample content" {
			t.Errorf("unexpected ReadFile content: %q", string(content))
		}
	}

	// 4. StatFS on DirFS
	sf, ok := dirFS.(iofs.StatFS)
	if ok {
		st, err := sf.Stat("sample.txt")
		if err != nil {
			t.Fatalf("StatFS.Stat failed: %v", err)
		}
		if st.Size() != int64(len("sample content")) {
			t.Errorf("unexpected stat size: %d", st.Size())
		}
	}
}
