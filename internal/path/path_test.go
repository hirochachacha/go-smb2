package path

import (
	"errors"
	"os"
	"strings"
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
		if Base(c.Path) != c.Base {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Base, Base(c.Path))
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
		if Dir(c.Path) != c.Dir {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Dir, Base(c.Path))
		}
	}
}

var testUNC = []struct {
	Path   string
	Server string
	Share  string
	Rest   string
	Ok     bool
}{
	{`\\server\share`, "server", "share", "", true},
	{`\\server\share\`, "", "", "", false},
	{`\\server\share\file`, "server", "share", "file", true},
	{`\\server\share\dir\file`, "server", "share", `dir\file`, true},
	{`\\127.0.0.1\share`, "127.0.0.1", "share", "", true},
	{`\\[0:0:0:0:0:0:0:1]\share`, "[0:0:0:0:0:0:0:1]", "share", "", true},
	{`\\server\sh.are\a.b`, "server", "sh.are", "a.b", true},
	{`\\server\.hidden`, "server", ".hidden", "", true},
	{`\\server\share\.hidden`, "server", "share", ".hidden", true},
	{`\\server\共有\ファイル`, "server", "共有", "ファイル", true},
	{`\\server\share\日本語.txt`, "server", "share", "日本語.txt", true},
	{`\\server\share\file:stream`, "server", "share", "file:stream", true},
	{`\\server\share\file:stream:type`, "server", "share", "file:stream:type", true},
	{`\\server\share\file::type`, "server", "share", "file::type", true},
	{`\\server\share\file:`, "", "", "", false},
	{`\\server\share\file::`, "", "", "", false},
	{`\\server\share\file+name`, "server", "share", "file+name", true},
	{`\\server\share\file,name`, "server", "share", "file,name", true},
	{`\\server\`, "", "", "", false},
	{`\\server`, "", "", "", false},
	{`\server\share`, "", "", "", false},
	{`server\share`, "", "", "", false},
	{`\\server\\share`, "", "", "", false},
	{`\\server\share\\file`, "", "", "", false},
	{`\\server\share\file\`, "", "", "", false},
	{`\\server\..\file`, "", "", "", false},
	{`\\server\...\file`, "", "", "", false},
	{`\\server\share\..`, "", "", "", false},
	{`\\server\share\.`, "", "", "", false},
	{`\\server\sh*are`, "", "", "", false},
	{`\\server\share\file?name`, "", "", "", false},
	{`\\server\share\dir+name\file`, "server", "share", `dir+name\file`, true},
	{`\\server\share\dir?name\file`, "", "", "", false},
	{`\\server\share\dir:stream\file`, "", "", "", false},
	{`\\\server\share`, "", "", "", false},
	{`\\server\share\file:stream:type:extra`, "", "", "", false},
	{`\\serv er\share`, "", "", "", false},
}

func TestSplitUNC(t *testing.T) {
	t.Parallel()
	for _, c := range testUNC {
		server, share, rest, ok := SplitUNC(c.Path)
		if ok != c.Ok {
			t.Errorf("SplitUNC(%q) ok = %v, want %v", c.Path, ok, c.Ok)
			continue
		}
		if !c.Ok {
			continue
		}
		if server != c.Server || share != c.Share || rest != c.Rest {
			t.Errorf("SplitUNC(%q) = %q, %q, %q; want %q, %q, %q", c.Path, server, share, rest, c.Server, c.Share, c.Rest)
		}
		u, err := ParseUNC(c.Path)
		if err != nil || u.Server != server || u.Share != share || u.RelPath != rest {
			t.Errorf("ParseUNC(%q) = %#v, %v; want %q, %q, %q", c.Path, u, err, server, share, rest)
		}
		if err == nil && u.SharePath() != `\\`+server+`\`+share {
			t.Errorf("u.SharePath() = %q, want %q", u.SharePath(), `\\`+server+`\`+share)
		}
	}
}

func TestNormalizeUNC(t *testing.T) {
	t.Parallel()
	valid := []struct {
		in   string
		want string
	}{
		{`\\server\share`, `\\server\share`},
		{`//server/share`, `\\server\share`},
		{`//server/share/foo/bar`, `\\server\share\foo\bar`},
		{`\\server\share\dir\`, `\\server\share\dir`},
		{`\\server\\share`, `\\server\share`},
	}
	for _, tc := range valid {
		got, err := NormalizeUNC(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("NormalizeUNC(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}

	invalid := []string{"", "share", `\server`, `\\server`, `\\server\`, `\\server\share\..`}
	for _, in := range invalid {
		if _, err := NormalizeUNC(in); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("NormalizeUNC(%q) expected os.ErrInvalid, got %v", in, err)
		}
	}
}

func TestParseUNCLimits(t *testing.T) {
	t.Parallel()
	share80 := strings.Repeat("a", 80)
	share81 := strings.Repeat("a", 81)
	name255 := strings.Repeat("a", 255)
	name256 := strings.Repeat("a", 256)
	if _, err := ParseUNC(`\\s\` + share80); err != nil {
		t.Errorf("80-character share rejected: %v", err)
	}
	if _, _, _, ok := SplitUNC(`\\s\` + share80); !ok {
		t.Errorf("SplitUNC with 80-character share rejected")
	}
	if _, err := ParseUNC(`\\s\` + share81); err == nil {
		t.Error("81-character share accepted")
	}
	if _, _, _, ok := SplitUNC(`\\s\` + share81); ok {
		t.Error("SplitUNC with 81-character share accepted")
	}
	if _, err := ParseUNC(`\\s\sh\` + name255); err != nil {
		t.Errorf("255-character component rejected: %v", err)
	}
	if _, _, _, ok := SplitUNC(`\\s\sh\` + name255); !ok {
		t.Errorf("SplitUNC with 255-character component rejected")
	}
	if _, err := ParseUNC(`\\s\sh\` + name256); err == nil {
		t.Error("256-character component accepted")
	}
	if _, _, _, ok := SplitUNC(`\\s\sh\` + name256); ok {
		t.Error("SplitUNC with 256-character component accepted")
	}
}

func TestIsValidShareName(t *testing.T) {
	t.Parallel()
	valid := []string{"share", "sh.are", ".hidden", "print$", "共有", strings.Repeat("a", 80)}
	for _, name := range valid {
		if !IsValidShareName(name) {
			t.Errorf("IsValidShareName(%q) = false, want true", name)
		}
	}
	invalid := []string{"", ".", "..", "sh*are", "sh?are", "a:b", "a/b", `a\b`, strings.Repeat("a", 81)}
	for _, name := range invalid {
		if IsValidShareName(name) {
			t.Errorf("IsValidShareName(%q) = true, want false", name)
		}
	}
}

func TestIsValidRelPathRejectsDotComponents(t *testing.T) {
	t.Parallel()
	rejected := []string{".", "..", `.\x`, `..\x`, `a\.\b`, `a\..\b`, `\`, `\x`}

	for _, path := range rejected {
		t.Run("reject/"+path, func(t *testing.T) {
			if IsValidRelPath(path) {
				t.Errorf("expected IsValidRelPath=false for %q", path)
			}
		})
	}

	for _, path := range []string{"", ".hidden", "..."} {
		if !IsValidRelPath(path) {
			t.Errorf("IsValidRelPath must not reject %q", path)
		}
	}
}

func TestNormalizeDistinguishesDotComponents(t *testing.T) {
	t.Parallel()
	if got := Normalize(`.\x`); got != "x" {
		t.Fatalf("Normalize(%q) = %q, want %q", `.\x`, got, "x")
	}
	if !IsValidRelPath(Normalize(`.\x`)) {
		t.Errorf("leading .\\ component is normalized away and must be accepted")
	}

	for _, path := range []string{`..\secret`, `dir\..\..\secret`, `a\.\b`} {
		normalized := Normalize(path)
		if normalized != path {
			t.Fatalf("Normalize(%q) = %q, want unchanged", path, normalized)
		}
		if IsValidRelPath(normalized) {
			t.Errorf("expected IsValidRelPath=false for %q after normalization", path)
		}
	}
}

func TestNormalizeCollapsesRedundantSeparators(t *testing.T) {
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
		// Dot components are preserved so IsValidRelPath still rejects them.
		{`a\.\b`, `a\.\b`},
		{`..\secret`, `..\secret`},
		{`dir\..\..\secret`, `dir\..\..\secret`},
	}

	for _, test := range tests {
		if got := Normalize(test.in); got != test.want {
			t.Errorf("Normalize(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestNormalizeRelPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{".", "", false},
		{`.\x`, "x", false},
		{`dir/`, "dir", false},
		{`dir\`, "dir", false},
		{`a//b`, `a\b`, false},
		{`a\\b`, `a\b`, false},
		{`a\b\`, `a\b`, false},
		{`a//b///c/`, `a\b\c`, false},
		{".hidden", ".hidden", false},
		{"...", "...", false},
		{`\`, "", true},
		{`\dir`, "", true},
		{`\\server\share`, "", true},
		{`..`, "", true},
		{`..\secret`, "", true},
		{`dir\..\..\secret`, "", true},
		{`a\.\b`, "", true},
	}

	for _, tc := range tests {
		got, err := NormalizeRelPath(tc.in)
		if tc.wantErr {
			if !errors.Is(err, os.ErrInvalid) {
				t.Errorf("NormalizeRelPath(%q) err = %v, want os.ErrInvalid", tc.in, err)
			}
		} else {
			if err != nil || got != tc.want {
				t.Errorf("NormalizeRelPath(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
			}
		}
	}
}

func TestCutPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path       string
		prefix     string
		wantSuffix string
		wantOk     bool
	}{
		{`\\server\share\dir\file`, `\\server\share`, `\dir\file`, true},
		{`\\server\share`, `\\server\share`, "", true},
		{`\\SERVER\SHARE\dir`, `\\server\share`, `\dir`, true},
		{`\\domain\share`, `\domain`, `\share`, true},
		{`\domain\share`, `\\domain`, `\share`, true},
		{`\\server\share2`, `\\server\share`, "", false},
		{`\\server\sh`, `\\server\share`, "", false},
		{`\\other\share`, `\\server\share`, "", false},
		{`\\server\share`, "", "", false},
		{"", `\\server\share`, "", false},
	}

	for _, tc := range tests {
		suffix, ok := CutPrefix(tc.path, tc.prefix)
		if ok != tc.wantOk || suffix != tc.wantSuffix {
			t.Errorf("CutPrefix(%q, %q) = (%q, %v); want (%q, %v)", tc.path, tc.prefix, suffix, ok, tc.wantSuffix, tc.wantOk)
		}
	}
}

func TestJoinUNC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		server string
		share  string
		elem   []string
		want   string
	}{
		{"server", "share", nil, `\\server\share`},
		{"server", "share", []string{""}, `\\server\share`},
		{"server", "share", []string{"dir", "file"}, `\\server\share\dir\file`},
		{"server", "share", []string{`dir\file`}, `\\server\share\dir\file`},
		{"server", "share", []string{`\dir\file`}, `\\server\share\dir\file`},
		{"server", "share", []string{"dir/file"}, `\\server\share\dir\file`},
	}

	for _, tc := range tests {
		got := JoinUNC(tc.server, tc.share, tc.elem...)
		if got != tc.want {
			t.Errorf("JoinUNC(%q, %q, %v) = %q, want %q", tc.server, tc.share, tc.elem, got, tc.want)
		}
	}
}

func TestSplitAll(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{`\`, nil},
		{"/", nil},
		{`\\\`, nil},
		{`dir`, []string{"dir"}},
		{`a\b\c`, []string{"a", "b", "c"}},
		{`a/b/c`, []string{"a", "b", "c"}},
		{`\\server\share\dir\file`, []string{"server", "share", "dir", "file"}},
		{`a\\b///c\`, []string{"a", "b", "c"}},
	}

	for _, tc := range tests {
		got := SplitAll(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("SplitAll(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("SplitAll(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
