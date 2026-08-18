package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// phase1Entities are the entity names the newly-enabled detectors report. Used
// both to assert the positives and to prove the negatives never reach them.
var phase1Entities = map[string]bool{
	"Pinecone": true, "SonarCloud": true, "OpenRouter": true, "PgAnalyzeReadKey": true,
	"DuffelToken": true, "Shippo": true, "GitLabOauth2": true, "NewRelicUserKey": true,
	"NewRelicBrowserKey": true, "NewRelicInsightsInsertKey": true,
	"NewRelicInsightsQueryKey": true, "NewRelicLicenseKey": true,
}

// Every fixture is split at its prefix boundary so no whole token exists as a
// contiguous literal here: GitHub push protection scans this file, and a value
// matching a vendor's published format is precisely what it blocks.
//
// Values are upstream's own detector fixtures wherever they survive our
// pipeline. Two do not: upstream's duffel and shippo fixtures are 43 'a's and
// 40 '1's, and scan() drops any value with a run of 8 identical characters as
// an obvious placeholder. That suppression is correct -- a real token is not a
// single repeated character -- so those two use a realistic value instead.
var phase1Positives = []struct {
	name, entity, text string
}{
	{"pinecone", "Pinecone",
		"PINECONE_API_KEY=pcsk" + "_T5Afk6_5qU9s3iLVFmaSaJtMat7gTHaT9fXa7ykiBk7iz4uUMuLGLemkdutTgwJevYhqtn"},
	{"sonarcloud-v2", "SonarCloud",
		"SONAR_TOKEN=sqco" + "_FbT1v5HrMX6qyKUkaoLQdYOniAVhbEccERraQABuhBayDOkyCZTa8TDQFRp"},
	{"openrouter", "OpenRouter",
		"OPENROUTER_KEY=sk-or-v1" + "-77a88b0afaf3531396a364bad7367d59c896f399541416d68f46c11203dbf19f"},
	{"pganalyze", "PgAnalyzeReadKey",
		"PGANALYZE_API_KEY=pgar" + "_123456789012345678901234567"},
	{"duffel", "DuffelToken",
		"DUFFEL_TOKEN=duffel_test" + "_aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4 "},
	{"shippo", "Shippo",
		"SHIPPO_TOKEN=shippo_live" + "_0123456789abcdef0123456789abcdef01234567"},
	// Paired: the secret alone yields nothing without a client id in range.
	{"gitlab-oauth2", "GitLabOauth2",
		"client_id = 763c4e64f4c40dd070010617639cc11e37bbaf1a798503dd96ee5e6852754862\n" +
			"client_secret = gloas" + "-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
	{"newrelic-user", "NewRelicUserKey", "NEW_RELIC_API_KEY=NRAK" + "-GDJSS4QZORUYIC1OGTRNGQMT5VH"},
	{"newrelic-browser", "NewRelicBrowserKey", "browserKey: NRBR" + "-cd83c5e6c53fe2edc1a"},
	{"newrelic-insights-insert", "NewRelicInsightsInsertKey", "insertKey=NRII" + "-d-2Vf-L1w-8B9Y_--6x8-_QjA"},
	// Paired: needs an account id in range.
	{"newrelic-insights-query", "NewRelicInsightsQueryKey",
		"relic account id 1234567\nqueryKey=NRIQ" + "-Xc_V8HruIZ271_l9FQm-_nJ7_"},
	{"newrelic-license", "NewRelicLicenseKey",
		"NEW_RELIC_LICENSE_KEY=72322bc2443d330cf29cde9f24fca105" + "FFFFNRAL"},
	{"newrelic-license-eu", "NewRelicLicenseKey",
		"NEW_RELIC_LICENSE_KEY=eu01xxb7e8b0dddc28ac051a64ffd583" + "FFFFNRAL"},
}

func TestPhase1FiresOnUpstreamFixtures(t *testing.T) {
	s := newBuiltScanner(t)
	for _, tc := range phase1Positives {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range s.scan(context.Background(), []byte(tc.text), 0.75) {
				if r.EntityType == tc.entity {
					if r.Score < 0.75 {
						t.Errorf("score %v below threshold", r.Score)
					}
					return
				}
				got = append(got, r.EntityType)
			}
			t.Fatalf("expected %s, got %v", tc.entity, got)
		})
	}
}

// Real key shapes from OTHER vendors. Several legitimately fire their own
// detector -- what must never happen is one being attributed to a detector
// this change enabled, which is how a rollout like this leaks FPs.
func TestPhase1NeverClaimsOtherVendorsKeys(t *testing.T) {
	others := map[string]string{
		"openai-project":  "OPENAI_API_KEY=sk-proj" + "-aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6b",
		"openai-service":  "OPENAI_KEY=sk-svcacct" + "-aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA",
		"fireworks":       "FIREWORKS_API_KEY=fw" + "_3ZL9kQ7pR2vN8wXt5Yc1dE4f",
		"perplexity":      "PPLX_API_KEY=pplx" + "-aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS",
		"tavily":          "TAVILY_API_KEY=tvly" + "-aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6",
		"google":          "GOOGLE_API_KEY=AIza" + "SyB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7m",
		"huggingface":     "HF_TOKEN=hf" + "_aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS",
		"databricks":      "DATABRICKS_TOKEN=dapi" + "0123456789abcdef0123456789abcdef",
		"replicate":       "REPLICATE_API_TOKEN=r8" + "_0123456789abcdef0123456789abcdef01234567",
		"together":        "TOGETHER_API_KEY=tok" + "_0123456789abcdef0123456789abcdef01234567",
		"groq":            "GROQ_API_KEY=gsk" + "_aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8d",
		"xai":             "XAI_API_KEY=xai" + "-aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM7nP9qR",
		"stripe-live":     "STRIPE_SECRET=sk_live" + "_aB3xK9mQ7pL2vN8wRt5Yc1dE",
		"stripe-test":     "STRIPE_TEST=sk_test" + "_aB3xK9mQ7pL2vN8wRt5Yc1dE",
		"github-pat":      "GITHUB_TOKEN=ghp" + "_0123456789abcdefghijklmnopqrstuvwxyz",
		"anthropic-shape": "ANTHROPIC_API_KEY=sk-ant-api03" + "-" + strings.Repeat("aB3xK9mQ7pL2vN8wRt5Yc1dE4f", 3) + "G6hJ0kS7mP9qT2vXAA",
	}
	s := newBuiltScanner(t)
	for name, text := range others {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if phase1Entities[r.EntityType] {
				t.Errorf("%s: %s wrongly claimed by newly-enabled detector %s",
					name, text[r.Start:r.End], r.EntityType)
			}
		}
	}
}

// Prose and documentation that names these vendors must stay silent.
func TestPhase1IgnoresProseAndPlaceholders(t *testing.T) {
	benign := []string{
		"def test_pinecone_client_returns_index_metadata(monkeypatch):",
		"const sonarToken = process.env.SONAR_TOKEN ?? 'sqco_placeholder'",
		"# openrouter docs: pass sk-or-v1-<your key here> in the Authorization header",
		"pgar_ is the prefix used by pganalyze read keys",
		"duffel_test_ and duffel_live_ tokens are 43 characters long",
		"shippo_live_ tokens are hex; see https://goshippo.com/docs/",
		"gloas- is the GitLab OAuth application secret prefix",
		"NRAK- keys authenticate against NerdGraph, see the docs",
		"New Relic license keys end with FFFFNRAL and are 40 characters",
		"var newRelicLicenseKey = os.Getenv(\"NEW_RELIC_LICENSE_KEY\")",
		"https://api.newrelic.com/v2/applications.json",
		"sk-or-v1-not-a-key",
		"pcsk_short_key",
	}
	s := newBuiltScanner(t)
	for _, text := range benign {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			t.Errorf("false positive: %s matched %q in %q", r.EntityType, text[r.Start:r.End], text)
		}
	}
}

type atomicBoolRef struct{ b *atomic.Bool }

// The flags are package-level vars only main.go sets, so a detector in the list
// is still deleted unless the flag is stored first. Toggling explicitly makes
// the count independent of whichever test ran before this one.
func TestPhase1EnablementAddsDetectors(t *testing.T) {
	flags := []*atomicBoolRef{
		{&feature.CloudflareApiTokenV2DetectorEnabled}, {&feature.CloudflareGlobalApiKeyV2DetectorEnabled},
		{&feature.PineconeDetectorEnabled}, {&feature.SonarCloudV2DetectorEnabled},
		{&feature.OpenRouterDetectorEnabled}, {&feature.PgAnalyzeReadKeyDetectorEnabled},
		{&feature.DuffelTokenDetectorEnabled}, {&feature.ShippoDetectorEnabled},
		{&feature.GitLabOAuthDetectorEnabled}, {&feature.NewRelicUserKeyDetectorEnabled},
		{&feature.NewRelicBrowserKeyDetectorEnabled}, {&feature.NewRelicInsightsInsertKeyDetectorEnabled},
		{&feature.NewRelicInsightsQueryKeyDetectorEnabled}, {&feature.NewRelicLicenseKeyDetectorEnabled},
	}
	for _, f := range flags {
		f.b.Store(false)
	}
	off := len(defaults.DefaultDetectors())
	for _, f := range flags {
		f.b.Store(true)
	}
	on := len(defaults.DefaultDetectors())
	if gained := on - off; gained != len(flags) {
		t.Fatalf("expected the gate to add %d detectors, got %d (%d -> %d)", len(flags), gained, off, on)
	}
	cfg, err := scannerConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	built, err := buildDetectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(built) < on {
		t.Fatalf("buildDetectors returned %d, fewer than the %d ungated defaults", len(built), on)
	}
	t.Logf("gated-off %d -> ungated %d (+%d) -> buildDetectors %d (+%d custom)",
		off, on, on-off, len(built), len(built)-on)
}
