// +build go1.6

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
	err = fs.WriteFile(path.Join(testDir, "hello.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.Mkdir(path.Join(testDir, "hello"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(path.Join(testDir, "hello", "hello.txt"), []byte("hello world!"), 0444)
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

		if !reflect.DeepEqual(entries, []string{".", "hello", "hello/hello.txt", "hello.txt"}) {
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

		if !reflect.DeepEqual(entries, []string{"hello", "hello/hello.txt"}) {
			t.Error("unexpected result")
		}
	}
}
