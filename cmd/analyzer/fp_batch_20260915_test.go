package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

// End-to-end regressions for the 2026-09-15 judge-dismissed batch. Every
// document below is a synthetic analog of a real prompt fragment: same
// structure, same value shapes, invented values.

func scanEnforce(t *testing.T, doc string) []analyzeResult {
	t.Helper()
	cfg := defaultScannerConfig()
	cfg.entropyThreshold = 0.7 // prod setting
	cfg.mode = suppressionEnforce
	cfg.vendorMode = suppressionEnforce
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s.scan(context.Background(), []byte(doc), 0.45)
}

func TestGPGImportLogKeyIDsSuppressed(t *testing.T) {
	doc := "gpg: keybox '/root/.gnupg/pubring.kbx' created\n" +
		"gpg: /root/.gnupg/trustdb.gpg: trustdb created\n" +
		"gpg: key 7D3F0A91C4E2B685: public key \"Example Dev <dev@example.com>\" imported\n" +
		"gpg: key 7D3F0A91C4E2B685: secret key imported\n" +
		"gpg: key 2B6857D3F0A91C4E: public key \"Example SOPS QA (SOPS key for envs) <eng@example.com>\" imported\n" +
		"gpg: Total number processed: 2\n"
	sup, reason := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: "7D3F0A91C4E2B685"}, nil, []byte(doc))
	require.True(t, sup)
	require.Equal(t, reasonGPGKeyID, reason)
	require.Equal(t, 0, countEntity(scanEnforce(t, doc), customdetectors.EntropyName))

	// Recall guard: the same hex run under a credential label, elsewhere in the
	// document, keeps the finding.
	mixed := doc + "\nsigning_key = 7D3F0A91C4E2B685\n"
	sup, _ = decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: "7D3F0A91C4E2B685"}, nil, []byte(mixed))
	require.False(t, sup)
}

func TestGrepOutputFilenameNotFlagged(t *testing.T) {
	// grep -B/-A output: "<file>:" on the match line, "<file>-" on context lines.
	doc := "--- structured detections ---\n" +
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md:    keyMoments:\n" +
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md-      - name: next_gen\n" +
		"transcript_0f1e2d3c-4b5a-4c6d-8e7f-9a0b1c2d3e4f.md-        categories: []\n"
	require.Equal(t, 0, countEntity(scanEnforce(t, doc), customdetectors.EntropyName))
}

func TestGoogleAnalyticsCookieNotFlagged(t *testing.T) {
	doc := "curl 'https://app.example.com/api' -H 'content-type: application/json' \\\n" +
		"  -b '_ga_ABC123DEF4=GS2.1.s1700000000$o1$g1$t1700000100$j60$l0$h0; " +
		"_ga=GA1.1.1234567890.1700000000; session-token-dev=eyJhbGciOiJIUzI1NiJ9'\n"
	results := scanEnforce(t, doc)
	for _, r := range results {
		require.NotEqual(t, "GA1.1.1234567890.1700000000", r.raw, "GA client id must not be reported")
	}
}

func TestTwilioAppSIDNotFlaggedButAuthTokenIs(t *testing.T) {
	doc := `twilio_subaccount_token: "c0ffee0123456789abcdef0123456789", ` +
		`twilio_app_id: "AP0123456789abcdef0123456789abcdef", route_callbacks_to_main_number: nil`
	results := scanEnforce(t, doc)
	sawToken := false
	for _, r := range results {
		require.NotEqual(t, "AP0123456789abcdef0123456789abcdef", r.raw, "Twilio app SID must not be reported")
		if r.raw == "c0ffee0123456789abcdef0123456789" {
			sawToken = true
		}
	}
	require.True(t, sawToken, "the auth token next to the SID must still be reported")
}

func TestJSONBareIDKeySuppressed(t *testing.T) {
	v := "aqXbNRQUGH1_AgSAE9B54QAAByh"
	doc := `{"authnRequestId": "aqhJNRQUGH1_AgSAE9B54QAAByg", "requestId": "` + v + `", ` +
		`"dtHash": "abf5406ffad6f6886e453ca6646592cd3de4fbdc78304fac3ad74d92ca674a41", ` +
		`"action": {"type": "WEB", "id": "` + v + `", "details": {}}}`
	sup, reason := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: v}, nil, []byte(doc))
	require.True(t, sup)
	require.Equal(t, reasonBenignIDContext, reason)

	// Recall guard: one occurrence under a credential key keeps it.
	kept := doc + ` {"auth_token": "` + v + `"}`
	sup, _ = decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: v}, nil, []byte(kept))
	require.False(t, sup)
}

func TestBoxEmbeddedSuppression(t *testing.T) {
	hex32 := "0123456789abcdef0123456789abcdef"
	realTok := "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	cases := []struct {
		name    string
		raw     string
		doc     string
		wantSup bool
	}{
		// "Dropbox" carries the Box keyword; the 32-hex run is an app id glued
		// into "app-<hex>@host".
		{"app id in curated list", hex32,
			"- Maersk (app-fedcba9876543210fedcba9876543210@example-curated-remote)\n" +
				"- Dropbox (app-" + hex32 + "@example-curated-remote)\n", true},
		{"standalone token kept", realTok, "box access token " + realTok + " here", false},
		{"credential-assigned kept", realTok, "box_token=" + realTok, false},
		{"embedded plus standalone kept", realTok,
			"app-" + realTok + "@host and box token " + realTok, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := analyzeResult{EntityType: "Box", raw: tc.raw}
			sup, reason := decideVendorSuppression(f, []byte(tc.doc))
			require.Equal(t, tc.wantSup, sup)
			if tc.wantSup {
				require.Equal(t, reasonVendorStructuralEmbedded, reason)
			}
		})
	}
}
