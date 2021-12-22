package glob

import (
	"testing"
)

func TestSimplifyPattern(t *testing.T) {
	cases := [][2]string{
		{"test.ext", "test.ext"},
		{"ab[0-9].ext", "ab?.ext"},
		{"tes?", "tes?"},
	}

	for _, tt := range cases {
		if generalizePattern(tt[0]) != tt[1] {
			t.Errorf("generalizePattern(%q) = %q, want %q", tt[0], generalizePattern(tt[0]), tt[1])
		}
	}
}
