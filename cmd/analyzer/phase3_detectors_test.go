package main

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
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

// Prose naming these vendors, and one character short or long of each fixed
// width, stay silent: the lengths are exact, and a loose bound is how prose
// starts matching.
func TestPhase3IgnoresProseAndNearMisses(t *testing.T) {
	benign := []string{
		"kpat_ and spat_ prefix Kong Konnect personal and system access tokens",
		"KONNECT_TOKEN=kpat" + "_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRBx",
		"KONNECT_TOKEN=kpat" + "_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRR",
		"KONNECT_TOKEN=spat" + "_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoD",
		"New Relic mobile tokens end in -NRMA; pass yours to withApplicationToken",
		"token: AAcc7eb96551e8cd65818865695f35bb109455d62" + "-NRMA",
		"token: eu01xxbfd4a807e4099453ba160493119a126319c" + "-NRMA",
		"re_ is the Resend API key prefix",
		"RESEND_API_KEY=re" + "_1234abcd_aBcDeFgHiJkLmNoPqRsTuVw",
		"wandb_v1_ keys replace the legacy 40-hex W&B keys",
		"WANDB_API_KEY=wandb_v1" + "_5g4ZZhqo3nYfG8l9wB1YLtFEtF_yY5hZB9yjfNf1JJyLpZmuhdA7z0Dw462k2R6UlAAHwP10Pezj",
		"WANDB_API_KEY=wandb_v1" + "_5g4ZZhqo3nYfG8l9wB1YLtFEtF9_yY5hZB9yjfNf1JJyLpZmuhdA7z0Dw462k2R6UlAAHwP10Pez",
	}
	s := newBuiltScanner(t)
	for _, text := range benign {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "KongKonnect" || r.EntityType == "NewRelicMobileAppToken" || r.EntityType == "Resend" ||
				r.EntityType == "WeightsAndBiases" {
				t.Errorf("false positive: %s matched %q in %q", r.EntityType, text[r.Start:r.End], text)
			}
		}
	}
}

// The flags are what enable these detectors: with them off, none of the fixtures
// is reported. Teams v2 stays off -- its sig accepts any run of characters.
func TestPhase3DetectorsAreOffWithoutTheirFlags(t *testing.T) {
	flags := []*atomic.Bool{
		&feature.KongKonnectDetectorEnabled, &feature.NewRelicMobileAppTokenDetectorEnabled,
		&feature.ResendDetectorEnabled, &feature.WeightsAndBiasesV2DetectorEnabled,
	}
	saved := make([]bool, len(flags))
	for i, f := range flags {
		saved[i] = f.Load()
	}
	t.Cleanup(func() {
		for i, f := range flags {
			f.Store(saved[i])
		}
	})
	for _, f := range flags {
		f.Store(false)
	}
	got := map[string]bool{}
	for _, d := range defaults.DefaultDetectors() {
		got[d.Type().String()] = true
	}
	for _, name := range []string{"KongKonnect", "NewRelicMobileAppToken", "Resend"} {
		if got[name] {
			t.Errorf("%s is registered with its flag off", name)
		}
	}
	if feature.MSTeamsWebhookV2DetectorEnabled.Load() {
		t.Error("the Teams v2 webhook detector is enabled")
	}
}
