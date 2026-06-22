package classify

import (
	"testing"

	regexp "github.com/wasilibs/go-re2"
)

func TestPatternStringsCompile(t *testing.T) {
	for _, s := range append(MaskPatterns(), EnvRefPatterns()...) {
		if _, err := regexp.Compile(s); err != nil {
			t.Fatalf("pattern %q failed to compile under go-re2: %v", s, err)
		}
	}
}

func TestRecognizerShapes(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		name string
		in   string
		want bool
	}{
		{IsStripeObjectID, "stripe", "du_1TIUcBBrSQGfJTjiR3r4WQh4", true},
		{IsStripeObjectID, "stripe-no", "ghp_0123456789abcdef", false},
		{IsHex32, "hex32", "9e107d9d372bb6826bd81d3542a419d6", true},
		{IsHex32, "hex32-31", "9e107d9d372bb6826bd81d3542a419d", false},
		{IsExcludedEntropyValue, "uuid", "a4c123b1-612d-d272-d137-1c17149d4395", true},
		{IsExcludedEntropyValue, "hex64", repeat("a", 64), true},
		{IsExcludedEntropyValue, "hex32-not-excluded-here", "9e107d9d372bb6826bd81d3542a419d6", false},
		{IsSecretAlphabet, "secret-charset", "aB3=._-+/~@", true},
		{IsSecretAlphabet, "secret-charset-space", "aB3 x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(c.in); got != c.want {
				t.Fatalf("%s(%q) = %v, want %v", c.name, c.in, got, c.want)
			}
		})
	}
}

func TestLexiconAccessorsAreCopies(t *testing.T) {
	a := PlaceholderMarkers()
	a[0] = "MUTATED"
	if PlaceholderMarkers()[0] == "MUTATED" {
		t.Fatal("PlaceholderMarkers returned a mutable shared slice")
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
