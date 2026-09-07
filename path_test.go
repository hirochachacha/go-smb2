package smb2

import (
	"errors"
	"math"
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

var testMountPath = []struct {
	Path string
	Ok   bool
}{
	{`\\server\share`, true},
	{`\\server\share\`, false},
	{`\\server\share\file`, false},
	{`\\127.0.0.1\share`, true},
	{`\\[0:0:0:0:0:0:0:1]\share`, true},
}

func TestValidateMountPath(t *testing.T) {
	for _, c := range testMountPath {
		if err := validateMountPath(c.Path); err == nil != c.Ok {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Ok, err == nil)
		}
	}
}

func TestValidatePathUTF16LELengthLimit(t *testing.T) {
	path := strings.Repeat("a", math.MaxUint16/2+1) // UTF-16LE encoded length exceeds 65,535 bytes

	err := validatePath("open", path, true)
	if err == nil {
		t.Fatal("expected an error for a path whose UTF-16LE encoded length exceeds 65,535 bytes")
	}
	if !errors.Is(err, os.ErrInvalid) {
		t.Errorf("expected os.ErrInvalid, got: %v", err)
	}

	path = strings.Repeat("a", math.MaxUint16/2) // within the limit

	if err := validatePath("open", path, true); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMountPathUTF16LELengthLimit(t *testing.T) {
	server := strings.Repeat("s", math.MaxUint16/2) // the encoded length of the mount path exceeds 65,535 bytes
	mountPath := `\\` + server + `\share` // UTF-16LE encoded length exceeds 65,535 bytes

	err := validateMountPath(mountPath)
	if err == nil {
		t.Fatal("expected an error for a mount path whose UTF-16LE encoded length exceeds 65,535 bytes")
	}
	if !errors.Is(err, os.ErrInvalid) {
		t.Errorf("expected os.ErrInvalid, got: %v", err)
	}
}
