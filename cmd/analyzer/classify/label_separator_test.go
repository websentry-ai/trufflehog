package classify

import (
	"testing"
)

// IsLabelSeparatorByte is a hand-written copy of what the pattern accepts, and
// a copy can drift -- it already did once, over the vertical tab that Go's \s
// leaves out. Every byte is checked against the pattern itself so the two
// cannot disagree silently.
//
// The byte goes in as []byte{b}: string(b) would convert it as a rune and turn
// anything above 0x7f into two UTF-8 bytes, testing a character the scanner
// never sees instead of the raw byte it reads out of the document.
func TestLabelSeparatorByteMatchesThePattern(t *testing.T) {
	for c := 0; c < 256; c++ {
		b := byte(c)
		accepted := IsNonCredentialLabel(string([]byte{b}) + "sha256=")
		if got := IsLabelSeparatorByte(b); got != accepted {
			t.Errorf("byte %#02x: IsLabelSeparatorByte=%v, pattern accepts=%v",
				b, got, accepted)
		}
	}
}
