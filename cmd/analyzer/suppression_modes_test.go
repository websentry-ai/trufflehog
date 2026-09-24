package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

func scanInMode(t *testing.T, doc string, mode suppressionMode) []analyzeResult {
	t.Helper()
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false
	cfg.entropyThreshold = 0.7
	cfg.mode = mode
	cfg.vendorMode = suppressionEnforce
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s.scan(context.Background(), []byte(doc), 0.45)
}

// Production runs enforce, but the binary accepts off and shadow, and the new
// rule sits on the same path as the others. Shadow exists to measure a rule
// before trusting it, which only works if the finding survives.
func TestTheNewRuleHonoursEverySuppressionMode(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const neighbour = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	doc := `{"api_key": "` + neighbour + `", "sha256": "` + secret + `"}`

	if reported(scanInMode(t, doc, suppressionEnforce), doc, secret) {
		t.Errorf("enforce: the digest was reported")
	}
	if !reported(scanInMode(t, doc, suppressionShadow), doc, secret) {
		t.Errorf("shadow: the digest was dropped, so the rule cannot be measured before it is trusted")
	}
	if !reported(scanInMode(t, doc, suppressionOff), doc, secret) {
		t.Errorf("off: the rule ran anyway")
	}
	for _, mode := range []suppressionMode{suppressionEnforce, suppressionShadow, suppressionOff} {
		if !reported(scanInMode(t, doc, mode), doc, neighbour) {
			t.Errorf("mode %v: the api_key was not reported", mode)
		}
	}
}

// The rule reports its own reason, so a suppressed digest is not counted as a
// benign id. The two are read separately when deciding what the judge sees.
func TestTheReasonReachesTheDecision(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const neighbour = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
	for _, c := range []struct{ doc, want string }{
		{`{"api_key": "` + neighbour + `", "sha256": "` + secret + `"}`, reasonNonCredentialLabel},
		{`{"api_key": "` + neighbour + `", "page_id": "` + secret + `"}`, reasonBenignIDContext},
	} {
		sup, reason := decideSuppression(res, map[string]int{}, []byte(c.doc))
		if !sup || reason != c.want {
			t.Errorf("%q -> suppressed=%v reason=%q, want %q", c.doc, sup, reason, c.want)
		}
	}
}
