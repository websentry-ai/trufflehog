package classify

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

var placeholderUnion = []string{
	"example",
	"redacted",
	"placeholder",
	"changeme",
	"change-me",
	"change_me",
	"do-not-use",
	"do_not_use",
	"your_",
	"your-",
	"yourkey",
	"yourtoken",
	"your_password",
	"yourpassword",
	"your_token",
	"dummy",
	"sample",
	"replace",
	"xxxx",
	"oauth",
}

var marshalPlaceholders = []string{
	"example",
	"redacted",
	"placeholder",
	"changeme",
	"change-me",
	"do-not-use",
	"do_not_use",
	"your_",
	"your-",
	"yourkey",
	"yourtoken",
	"dummy",
	"sample",
	"replace",
	"xxxx",
}

var excludeWords = []string{
	"changeme",
	"change_me",
	"example",
	"redacted",
	"placeholder",
	"your_password",
	"yourpassword",
	"dummy",
	"sample",
	"xxxx",
	"your_token",
	"oauth",
}

var entropyPlaceholders = []string{
	"example",
	"redacted",
	"xxxx",
	"do-not-use",
	"do_not_use",
	"changeme",
	"placeholder",
}

var keywords = []string{
	"password", "passwd", "pwd", "secret",
	"token", "credential", "apikey", "api_key", "auth",
}

var keywordStems = []string{
	"password", "passwd", "pwd", "secret", "token", "credential",
	"auth", "apikey", "api_key", "signing", "key", "cert",
	// bearer labels a credential on its own ("bearer=<token>") and was the one
	// gap the assignment carve-out could not reach: with no stem nearby the
	// proximity check never fires, so the value is invisible either way.
	"bearer",
}

func copyOf(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func PlaceholderMarkers() []string { return copyOf(marshalPlaceholders) }

func ExcludeWords() []string { return copyOf(excludeWords) }

func Keywords() []string { return copyOf(keywords) }

func KeywordStems() []string { return copyOf(keywordStems) }

// IsCredentialToken reports whether one label token is a credential word.
// Matched as a substring, the same way the proximity check reads a stem, so
// "x_auth" and "signing" count: over-reading here only keeps a finding.
func IsCredentialToken(tok string) bool {
	low := strings.ToLower(tok)
	for _, stem := range keywordStems {
		if strings.Contains(low, stem) {
			return true
		}
	}
	return false
}

func PlaceholderUnion() []string { return copyOf(placeholderUnion) }

func ContainsEntropyPlaceholder(lower string) bool {
	for _, w := range entropyPlaceholders {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func IsKnownFalsePositive(v string) bool {
	known, _ := detectors.IsKnownFalsePositive(v, detectors.DefaultFalsePositives, true)
	return known
}

func ShannonEntropy(v string) float64 {
	return detectors.StringShannonEntropy(v)
}
