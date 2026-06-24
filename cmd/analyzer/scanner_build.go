package main

import (
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors/tokenizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

type scannerConfig struct {
	genericSecretsEnabled   bool
	genericSecretScore      float64
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

func buildDetectors(cfg scannerConfig) ([]detectors.Detector, error) {
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
		privKey, err := customdetectors.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		dets = append(dets, gs, dbURI, privKey)
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
	return &scanner{
		core:               ahocorasick.NewAhoCorasickCore(dets),
		detectors:          len(dets),
		genericSecretScore: cfg.genericSecretScore,
		mode:               cfg.mode,
		vendorMode:         cfg.vendorMode,
	}, nil
}
