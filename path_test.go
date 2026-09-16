package smb2

import (
	"errors"
	"os"
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
	t.Parallel()
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
	t.Parallel()
	for _, c := range testDir {
		if dir(c.Path) != c.Dir {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Dir, base(c.Path))
		}
	}
}

var testSharePath = []struct {
	Path string
	Ok   bool
}{
	{`\\server\share`, true},
	{`\\server\share\`, false},
	{`\\server\share\file`, false},
	{`\\127.0.0.1\share`, true},
	{`\\[0:0:0:0:0:0:0:1]\share`, true},
}

func TestSplitSharePath(t *testing.T) {
	t.Parallel()
	for _, c := range testSharePath {
		if _, _, err := splitSharePath(c.Path); (err == nil) != c.Ok {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Ok, err)
		}
	}
}

func TestValidatePathRejectsDotComponents(t *testing.T) {
	t.Parallel()
	rejected := []string{".", "..", `.\x`, `..\x`, `a\.\b`, `a\..\b`}

	for _, path := range rejected {
		t.Run("reject/"+path, func(t *testing.T) {
			err := validatePath(path, false)

			if err != os.ErrInvalid {
				t.Errorf("expected os.ErrInvalid for %q, got %v", path, err)
			}
		})
	}

	// allowAbs is used for symbolic link targets and glob patterns, where a
	// leading ".." is meaningful and must not be rejected by this check.
	for _, path := range append([]string{"", ".hidden", "..."}, rejected...) {
		if err := validatePath(path, true); err != nil {
			t.Errorf("allowAbs=true must not reject %q: %v", path, err)
		}
	}

	for _, path := range []string{"", ".hidden", "..."} {
		if err := validatePath(path, false); err != nil {
			t.Errorf("validatePath must not reject %q: %v", path, err)
		}
	}
}

func TestValidatePathNormalizationDistinguishesDotComponents(t *testing.T) {
	t.Parallel()
	if got := normPath(`.\x`); got != "x" {
		t.Fatalf("normPath(%q) = %q, want %q", `.\x`, got, "x")
	}
	if err := validatePath(normPath(`.\x`), false); err != nil {
		t.Errorf("leading .\\ component is normalized away and must be accepted, got %v", err)
	}

	for _, path := range []string{`..\secret`, `dir\..\..\secret`, `a\.\b`} {
		normalized := normPath(path)
		if normalized != path {
			t.Fatalf("normPath(%q) = %q, want unchanged", path, normalized)
		}
		if err := validatePath(normalized, false); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("expected os.ErrInvalid for %q after normalization, got %v", path, err)
		}
	}
}

func TestNormPathCollapsesRedundantSeparators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{".", ""},
		{`.\x`, "x"},
		{`dir/`, "dir"},
		{`dir\`, "dir"},
		{`a//b`, `a\b`},
		{`a\\b`, `a\b`},
		{`a\b\`, `a\b`},
		{`a//b///c/`, `a\b\c`},
		// A leading run of separators marks UNC/absolute pathnames and is kept.
		{`\\server\share`, `\\server\share`},
		{`\\server\share\`, `\\server\share`},
		{`\\server\\share`, `\\server\share`},
		{`\dir`, `\dir`},
		{`\dir\`, `\dir`},
		{`\`, `\`},
		// Dot components are preserved so validatePath still rejects them.
		{`a\.\b`, `a\.\b`},
		{`..\secret`, `..\secret`},
		{`dir\..\..\secret`, `dir\..\..\secret`},
	}

	for _, test := range tests {
		if got := normPath(test.in); got != test.want {
			t.Errorf("normPath(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}
