package main

import (
	"context"
	"testing"
)

// Fixtures are upstream's own, split at their prefix so no whole token exists
// as a contiguous literal: GitHub push protection blocks a vendor's format.
var phase3Positives = []struct {
	name, entity, text string
}{
	{"kong-pat", "KongKonnect", "KONNECT_TOKEN=kpat" + "_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRB"},
	{"kong-spat", "KongKonnect", "KONNECT_TOKEN=spat" + "_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoDj"},
	{"newrelic-mobile", "NewRelicMobileAppToken", "NewRelic.withApplicationToken(\"AAcc7eb96551e8cd65818865695f35bb109455d623" + "-NRMA\")"},
	{"newrelic-mobile-eu", "NewRelicMobileAppToken", "token: eu01xxbfd4a807e4099453ba160493119a126319cb" + "-NRMA"},
	{"resend", "Resend", "RESEND_API_KEY=re" + "_1234abcd_aBcDeFgHiJkLmNoPqRsTuVwX"},
	{"wandb-v2", "WeightsAndBiases", "WANDB_API_KEY=wandb_v1" + "_5g4ZZhqo3nYfG8l9wB1YLtFEtF9_yY5hZB9yjfNf1JJyLpZmuhdA7z0Dw462k2R6UlAAHwP10Pezj"},
	{"teams-webhook-v2", "MicrosoftTeamsWebhook", "WEBHOOK=https://defaultabc123def456abc123def456ab.62.environment.api.powerplatform.com:443" +
		"/powerautomate/automations/direct/workflows/67b9621a4a744d4abc90035cb396b361/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
		"r2h9kxq06-gWOJ7QiEHNTxntTw11k2uJA3EZr0SIcIQ"},
}

func TestPhase3DetectorsFireOnTheirFormat(t *testing.T) {
	s := newBuiltScanner(t)
	for _, p := range phase3Positives {
		t.Run(p.name, func(t *testing.T) {
			for _, r := range s.scan(context.Background(), []byte(p.text), 0.75) {
				if r.EntityType == p.entity {
					return
				}
			}
			t.Fatalf("%s did not fire on %s's own format", p.entity, p.name)
		})
	}
}

// Prose naming these vendors, and one character short of each fixed width, stay
// silent: the lengths are exact, and a loose bound is how prose starts matching.
func TestPhase3IgnoresProseAndNearMisses(t *testing.T) {
	benign := []string{
		"kpat_ and spat_ prefix Kong Konnect personal and system access tokens",
		"KONNECT_TOKEN=kpat" + "_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRx_",
		"KONNECT_TOKEN=kpat" + "_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRR",
		"New Relic mobile tokens end in -NRMA; pass yours to withApplicationToken",
		"token: AAcc7eb96551e8cd65818865695f35bb109455d62" + "-NRMA",
		"re_ is the Resend API key prefix",
		"RESEND_API_KEY=re" + "_1234abcd_aBcDeFgHiJkLmNoPqRsTuVw",
		"wandb_v1_ keys replace the legacy 40-hex W&B keys",
		"https://defaultabc123def456abc123def456ab.62.environment.api.powerplatform.com:443" +
			"/powerautomate/automations/direct/workflows/67b9621a4a744d4abc90035cb396b361/triggers/manual/paths/invoke?api-version=1",
	}
	s := newBuiltScanner(t)
	for _, text := range benign {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "KongKonnect" || r.EntityType == "NewRelicMobileAppToken" || r.EntityType == "Resend" ||
				r.EntityType == "WeightsAndBiases" || r.EntityType == "MicrosoftTeamsWebhook" {
				t.Errorf("false positive: %s matched %q in %q", r.EntityType, text[r.Start:r.End], text)
			}
		}
	}
}
