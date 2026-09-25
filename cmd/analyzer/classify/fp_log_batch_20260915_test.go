package classify

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression cases from the 2026-09-15 judge-dismissed batch (48h, one org:
// 17 API Key findings, all entropy-secret or Box). Values below are synthetic
// analogs with the same shape as the real findings, never the real ones.

func TestExcludedEntropyValue_LogBatch20260915(t *testing.T) {
	excluded := []string{
		// grep -A/-B output prefixes each context line with "<file>-" and each
		// match line with "<file>:"; the whitespace tokenizer keeps the
		// separator glued to the filename.
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md-",
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md:",
		"notes_2026-09-01.log-",
		// Google Analytics client-id cookie: GA1.<n>.<random>.<unix ts>.
		"GA1.1.1234567890.1700000000",
		"GA1.2.987654321.1699999999",
		// Twilio resource SIDs: two-letter type prefix + 32 lowercase hex.
		// Application, Messaging service, Phone number, Call, Message, Media,
		// Channel, Identity service, Workspace -- all public identifiers.
		"AP0123456789abcdef0123456789abcdef",
		"MG0123456789abcdef0123456789abcdef",
		"PN0123456789abcdef0123456789abcdef",
	}
	for _, v := range excluded {
		require.True(t, IsExcludedEntropyValue(v), "expected excluded: %q", v)
	}

	// Recall guards. The AC/SK values are assembled at runtime so the file
	// never contains a literal that GitHub push protection reads as a real
	// Twilio account or API-key SID.
	twilioHex := strings.Repeat("0123456789abcdef", 2)
	real := []string{
		// Twilio AUTH TOKEN (bare 32 hex, no SID prefix) stays in scope for
		// the entropy detector -- it is the actual credential.
		"c0ffee0123456789abcdef0123456789",
		// Account SID and API Key SID are deliberately NOT excluded: AC pairs
		// with the auth token, SK pairs with its secret, and the paired Twilio
		// detectors need them visible.
		"AC" + twilioHex,
		"SK" + twilioHex,
		// Uppercase hex after a resource prefix is not a Twilio SID shape.
		"AP0123456789ABCDEF0123456789ABCDEF",
		// A GA-looking prefix on a random token is not a client id.
		"GA1.1.aB3xKp9Qm2Lr7TzWqDvNcEd",
		// A filename-shaped token with a trailing separator that is not a
		// grep separator keeps its usual treatment.
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md=",
		"aB3xKp9Qm2Lr7TzWqDvNcEd1.md-x",
	}
	for _, v := range real {
		require.False(t, IsExcludedEntropyValue(v), "must keep real secret: %q", v)
	}
}

func TestBenignIDContext_BareIDKey(t *testing.T) {
	yes := []string{
		`{"type": "WEB", "id": "`,
		`"id":"`,
		`'id': '`,
		`"requestId": "`,
	}
	for _, before := range yes {
		require.True(t, IsBenignIDContext(before), "expected benign id context: %q", before)
	}
	no := []string{
		`"client_id": "`, // not in the benign list on purpose: pairs with a secret
		`"api_key": "`,
		`"token": "`,
		`"valid": "`, // ends in "id" as letters, not the key "id"
		`id = `,      // bare word without quotes is not a JSON key
	}
	for _, before := range no {
		require.False(t, IsBenignIDContext(before), "must not be benign: %q", before)
	}
}

func TestGPGKeyIDInContext(t *testing.T) {
	cases := []struct {
		name, value, before string
		want                bool
	}{
		{"import-log-key-id", "7D3F0A91C4E2B685", "gpg: key ", true},
		{"import-log-lowercase", "7d3f0a91c4e2b685", "gpg: key ", true},
		{"fingerprint-40", "7D3F0A91C4E2B6857D3F0A91C4E2B6857D3F0A91", "gpg: key ", true},
		{"multi-space", "7D3F0A91C4E2B685", "gpg:   key ", true},
		{"not-hex", "aB3xKp9Qm2Lr7TzW", "gpg: key ", false},
		{"wrong-length-hex", "7D3F0A91C4E2", "gpg: key ", false},
		{"api-key-label-kept", "7D3F0A91C4E2B685", "api key ", false},
		{"generic-key-word-kept", "7D3F0A91C4E2B685", "the key ", false},
		{"gpg-passphrase-kept", "7D3F0A91C4E2B685", "gpg: passphrase ", false},
	}
	for _, c := range cases {
		if got := IsGPGKeyIDInContext(c.value, c.before); got != c.want {
			t.Errorf("%s: IsGPGKeyIDInContext(%q, %q)=%v want %v", c.name, c.value, c.before, got, c.want)
		}
	}
}
