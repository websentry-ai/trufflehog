package main

import (
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors/tokenizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

type scannerConfig struct {
	genericSecretsEnabled   bool
	genericSecretScore      float64
	privateKeyEnabled       bool
	entropyProximityEnabled bool
	entropyThreshold        float64
	tokenizerName           string
	mode                    suppressionMode
	vendorMode              suppressionMode
}

func defaultScannerConfig() scannerConfig {
	return scannerConfig{
		genericSecretsEnabled:   true,
		genericSecretScore:      defaultGenericSecretScore,
		privateKeyEnabled:       true,
		entropyProximityEnabled: true,
		entropyThreshold:        customdetectors.DefaultEntropyThreshold,
		tokenizerName:           "",
		mode:                    suppressionEnforce,
		vendorMode:              suppressionOff,
	}
}

func scannerConfigFromEnv() (scannerConfig, error) {
	cfg := scannerConfig{
		genericSecretsEnabled:   envEnabled("ENABLE_GENERIC_SECRETS"),
		genericSecretScore:      defaultGenericSecretScore,
		privateKeyEnabled:       envEnabledDefault("ENABLE_PRIVATE_KEY", true),
		entropyProximityEnabled: envEnabled("ENABLE_ENTROPY_PROXIMITY"),
		entropyThreshold:        customdetectors.DefaultEntropyThreshold,
		tokenizerName:           os.Getenv("ANALYZER_TOKENIZER"),
		mode:                    parseSuppressionMode(os.Getenv("FP_SUPPRESSION_MODE")),
		vendorMode:              parseVendorSuppressionMode(os.Getenv("VENDOR_STRUCTURAL_SUPPRESSION")),
	}
	if cfg.genericSecretsEnabled {
		score, err := parseGenericSecretScore(os.Getenv("GENERIC_SECRET_SCORE"))
		if err != nil {
			return cfg, fmt.Errorf("GENERIC_SECRET_SCORE: %w", err)
		}
		cfg.genericSecretScore = score
	}
	if cfg.entropyProximityEnabled {
		threshold, err := customdetectors.ParseEntropyThreshold(os.Getenv("ENTROPY_THRESHOLD"))
		if err != nil {
			return cfg, fmt.Errorf("ENTROPY_THRESHOLD: %w", err)
		}
		cfg.entropyThreshold = threshold
	}
	return cfg, nil
}

func envEnabled(name string) bool {
	switch os.Getenv(name) {
	case "true", "1":
		return true
	default:
		return false
	}
}

func envEnabledDefault(name string, def bool) bool {
	switch os.Getenv(name) {
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		return def
	}
}

// pairedLongForm are detectors that both match long secrets and require a second
// component. Giving one the whole request reopens the distant pairing this
// windowing removes, so they stay windowed -- their long secrets can be cut at a
// boundary as a result, which is the side of the trade to be on: a miss rather
// than a false finding.
var pairedLongForm = map[string]bool{
	"*auth0managementapitoken.Scanner": true,
}

// longFormDetectors picks the detectors that must see the whole request because
// their match can be longer than the peek and a window boundary would cut it.
func longFormDetectors(dets []detectors.Detector) []detectors.Detector {
	var out []detectors.Detector
	for _, d := range dets {
		if pairedLongForm[fmt.Sprintf("%T", d)] {
			continue
		}
		long := false
		if sz, ok := d.(interface{ MaxSecretSize() int64 }); ok && sz.MaxSecretSize() > scanWindowPeek {
			long = true
		}
		// The PEM block is matched by a custom regex, and every custom detector
		// reports the same fixed size whatever its pattern, so the declared size
		// does not describe this one. It has no upper bound at all.
		if cd, ok := d.(interface{ GetName() string }); ok && cd.GetName() == customdetectors.PrivateKeyName {
			long = true
		}
		if long {
			out = append(out, d)
		}
	}
	return out
}

func buildDetectors(cfg scannerConfig) ([]detectors.Detector, error) {
	// Upstream gates new detectors behind flags that default to false and are only
	// set by main.go, which this service never runs -- so DefaultDetectors() deletes
	// them. Must be set before it reads them.
	//
	// Enable one here only when its pattern pins both a literal and a fixed-width
	// body -- a vendor prefix like pcsk_ / NRAK-, the FFFFNRAL suffix, or Lob's
	// live_/test_ plus exactly 35 lowercase hex. Detectors matching only a keyword
	// near a generic run of characters need measuring on their own first.
	feature.CloudflareApiTokenV2DetectorEnabled.Store(true)
	feature.CloudflareGlobalApiKeyV2DetectorEnabled.Store(true)
	feature.PineconeDetectorEnabled.Store(true)
	feature.SonarCloudV2DetectorEnabled.Store(true)
	feature.OpenRouterDetectorEnabled.Store(true)
	feature.PgAnalyzeReadKeyDetectorEnabled.Store(true)
	feature.DuffelTokenDetectorEnabled.Store(true)
	feature.ShippoDetectorEnabled.Store(true)
	feature.GitLabOAuthDetectorEnabled.Store(true)
	feature.NewRelicUserKeyDetectorEnabled.Store(true)
	feature.NewRelicBrowserKeyDetectorEnabled.Store(true)
	feature.NewRelicInsightsInsertKeyDetectorEnabled.Store(true)
	feature.NewRelicInsightsQueryKeyDetectorEnabled.Store(true)
	feature.NewRelicLicenseKeyDetectorEnabled.Store(true)
	feature.LobDetectorEnabled.Store(true)

	dets := defaults.DefaultDetectors()
	if cfg.genericSecretsEnabled {
		gs, err := customdetectors.NewGenericSecret()
		if err != nil {
			return nil, err
		}
		dbURI, err := customdetectors.NewDBConnectionURI()
		if err != nil {
			return nil, err
		}
		dets = append(dets, gs, dbURI)
	}
	if cfg.privateKeyEnabled {
		privKey, err := customdetectors.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		dets = append(dets, privKey)
	}
	if cfg.entropyProximityEnabled {
		tok, err := tokenizer.Select(cfg.tokenizerName)
		if err != nil {
			return nil, err
		}
		dets = append(dets, customdetectors.NewEntropyProximityWithTokenizer(cfg.entropyThreshold, tok))
	}
	return dets, nil
}

func buildScanner(cfg scannerConfig) (*scanner, error) {
	dets, err := buildDetectors(cfg)
	if err != nil {
		return nil, err
	}
	longForm := longFormDetectors(dets)
	var longFormCore *ahocorasick.Core
	if len(longForm) > 0 {
		longFormCore = ahocorasick.NewAhoCorasickCore(longForm)
	}

	return &scanner{
		core:               ahocorasick.NewAhoCorasickCore(dets),
		longFormCore:       longFormCore,
		detectors:          len(dets),
		genericSecretScore: cfg.genericSecretScore,
		mode:               cfg.mode,
		vendorMode:         cfg.vendorMode,
	}, nil
}
