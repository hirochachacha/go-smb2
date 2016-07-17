package smb2

import (
	"testing"
)

var testBase = []struct {
	Path string
	Base string
}{
	{"", ""},
	{`\`, ""},
	{`\foo`, "foo"},
	{`\foo\bar`, "bar"},
	{`foo\bar`, "bar"},
	{`foo\bar\`, "bar"},
	{`foo\bar\\`, "bar"},
	{`foo`, "foo"},
}

func TestBase(t *testing.T) {
	for _, c := range testBase {
		if base(c.Path) != c.Base {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Base, base(c.Path))
		}
	}
}

var testDir = []struct {
	Path string
	Dir  string
}{
	{"", ""},
	{`\`, `\`},
	{`\foo`, `\`},
	{`\foo\bar`, `\foo`},
	{`foo\bar`, "foo"},
	{`foo\bar\`, "foo"},
	{`foo\bar\\`, "foo"},
	{`foo`, ""},
}

func TestDir(t *testing.T) {
	for _, c := range testDir {
		if dir(c.Path) != c.Dir {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Dir, base(c.Path))
		}
	}
}
