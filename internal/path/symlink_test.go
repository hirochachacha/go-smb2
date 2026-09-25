package path

import (
	"testing"
)

func TestSplitSymlinkUNC(t *testing.T) {
	t.Parallel()

	validTests := []struct {
		input  string
		server string
		share  string
		rest   string
	}{
		{`\\server\share\file.txt`, "server", "share", "file.txt"},
		{`\\server\share\dir\file.txt`, "server", "share", `dir\file.txt`},
		{`\\server\share\`, "server", "share", ""},
		{`\\server\share`, "server", "share", ""},
	}

	for _, tt := range validTests {
		server, share, rest, ok := SplitSymlinkUNC(tt.input)
		if !ok {
			t.Errorf("SplitSymlinkUNC(%q) returned ok=false", tt.input)
			continue
		}
		if server != tt.server || share != tt.share || rest != tt.rest {
			t.Errorf("SplitSymlinkUNC(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, server, share, rest, tt.server, tt.share, tt.rest)
		}
	}

	invalidInputs := []string{
		"",
		`\server\share`,
		`server\share`,
		`\\server`,
		`\\\server\share`,
		`\\server\share\\file`,
		`\\\`,
		`\\`,
		`\\server\.`,
		`\\server\..`,
		`\\.\share`,
		`\\..\share`,
		`\\server\share\.\file`,
		`\\server\share\..\file`,
		`\\server\share\sub/dir`,
		`\\server\share\file:stream`,
		"\\\\server\\share\\file\x00name",
	}

	for _, input := range invalidInputs {
		if _, _, _, ok := SplitSymlinkUNC(input); ok {
			t.Errorf("SplitSymlinkUNC(%q) = ok=true, want false", input)
		}
	}
}

func TestNormalizeSymlinkUNC(t *testing.T) {
	t.Parallel()

	validTests := []struct {
		input string
		want  string
	}{
		{`\\server\share\dir\file.txt`, `\\server\share\dir\file.txt`},
		{`\\server\share\dir\..\file.txt`, `\\server\share\file.txt`},
		{`\\server\share\dir\.\file.txt`, `\\server\share\dir\file.txt`},
		// Clamping traversal at share root
		{`\\server\share\..\..\file.txt`, `\\server\share\file.txt`},
		{`\\server\share\`, `\\server\share`},
		{`\\server\share`, `\\server\share`},
	}

	for _, tt := range validTests {
		got, ok := NormalizeSymlinkUNC(tt.input)
		if !ok {
			t.Errorf("NormalizeSymlinkUNC(%q) returned ok=false", tt.input)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeSymlinkUNC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	invalidInputs := []string{
		"",
		`server\share`,
		`\\server`,
		`\\.\share`,
		`\\..\share`,
		`\\server\.`,
		`\\server\..`,
		`\\server\share:bad`,
		`\\server\share\bad:stream`,
		"\\\\server\\share\\bad\x00file",
		`\\server\share\bad/slash`,
	}

	for _, input := range invalidInputs {
		if _, ok := NormalizeSymlinkUNC(input); ok {
			t.Errorf("NormalizeSymlinkUNC(%q) = ok=true, want false", input)
		}
	}
}

func TestBuildSymlinkReparseNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target         string
		substituteName string
		printName      string
		relative       bool
		ok             bool
	}{
		{"", "", "", false, false},
		{"C:", "", "", false, false},
		{`C:\dir\file.txt`, `\??\C:\dir\file.txt`, `C:\dir\file.txt`, false, true},
		{`C:dir\file.txt`, `\??\C:dir\file.txt`, `C:dir\file.txt`, true, true},
		{`\\server\share\file`, `\??\UNC\server\share\file`, `\\server\share\file`, false, true},
		{`dir\file.txt`, `dir\file.txt`, `dir\file.txt`, true, true},
		{`\dir\file.txt`, `\dir\file.txt`, `\dir\file.txt`, false, true},
	}

	for _, tt := range tests {
		sub, printN, rel, ok := BuildSymlinkReparseNames(tt.target)
		if ok != tt.ok {
			t.Errorf("BuildSymlinkReparseNames(%q) ok = %v, want %v", tt.target, ok, tt.ok)
			continue
		}
		if !ok {
			continue
		}
		if sub != tt.substituteName || printN != tt.printName || rel != tt.relative {
			t.Errorf("BuildSymlinkReparseNames(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.target, sub, printN, rel, tt.substituteName, tt.printName, tt.relative)
		}
	}
}

func TestResolveRelativeSymlink(t *testing.T) {
	t.Parallel()

	// Normal relative resolution
	resolved, err := ResolveRelativeSymlink(`dir\sub\link`, `..\target.txt`, "")
	if err != nil {
		t.Fatalf("ResolveRelativeSymlink unexpected err: %v", err)
	}
	if resolved != `dir\target.txt` {
		t.Errorf("ResolveRelativeSymlink = %q, want dir\\target.txt", resolved)
	}

	// Suffix resolution
	resolved, err = ResolveRelativeSymlink(`link`, `target`, `sub\file.txt`)
	if err != nil {
		t.Fatalf("ResolveRelativeSymlink with suffix unexpected err: %v", err)
	}
	if resolved != `target\sub\file.txt` {
		t.Errorf("ResolveRelativeSymlink = %q, want target\\sub\\file.txt", resolved)
	}

	// Target escaping share root
	if _, err := ResolveRelativeSymlink(`dir\link`, `..\..\escaped`, ""); err == nil {
		t.Error("expected error for symlink target escaping share root")
	}

	// Suffix escaping share root
	if _, err := ResolveRelativeSymlink(`link`, `target`, `..\..`); err == nil {
		t.Error("expected error for symlink suffix escaping share root")
	}

	// Target with empty middle component
	if _, err := ResolveRelativeSymlink(`link`, `a\\b`, ""); err == nil {
		t.Error("expected error for empty target component")
	}

	// Target containing drive separator
	if _, err := ResolveRelativeSymlink(`link`, `C:file`, ""); err == nil {
		t.Error("expected error for drive separator in target")
	}

	// Suffix containing drive separator
	if _, err := ResolveRelativeSymlink(`link`, `target`, `C:file`); err == nil {
		t.Error("expected error for drive separator in suffix")
	}
}
