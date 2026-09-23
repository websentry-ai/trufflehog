package classify

import (
	"fmt"
	"testing"
)

// IsLabelSeparatorByte is a hand-written copy of what the pattern accepts, and
// a copy can drift -- it already did once, over the vertical tab that Go's \s
// leaves out. Every byte is checked against the pattern itself so the two
// cannot disagree silently.
func TestLabelSeparatorByteMatchesThePattern(t *testing.T) {
	for c := 0; c < 256; c++ {
		b := byte(c)
		accepted := IsNonCredentialLabel(string(b) + "sha256=")
		if got := IsLabelSeparatorByte(b); got != accepted {
			t.Errorf("byte %#02x (%q): IsLabelSeparatorByte=%v, pattern accepts=%v",
				b, fmt.Sprintf("%c", b), got, accepted)
		}
	}
}
