package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// prodEnv is what k8s/prod/values.yaml sets on the analyzer container. The
// recall tables in this package build their config by hand and say they match
// production; this reads the deployment instead, so the claim is checked
// rather than asserted in a comment.
var prodEnv = map[string]string{
	"GENERIC_SECRET_SCORE":          "0.8",
	"ENTROPY_THRESHOLD":             "0.7",
	"ENABLE_GENERIC_SECRETS":        "false",
	"ENABLE_PRIVATE_KEY":            "true",
	"ENABLE_ENTROPY_PROXIMITY":      "true",
	"FP_SUPPRESSION_MODE":           "enforce",
	"VENDOR_STRUCTURAL_SUPPRESSION": "enforce",
}

var envPairPat = regexp.MustCompile(`(?m)^\s*-\s*name:\s*([A-Z0-9_]+)\s*\n\s*value:\s*"?([^"\n]*)"?\s*$`)

func readProdValues(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", "k8s", "prod", "values.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	found := map[string]string{}
	for _, m := range envPairPat.FindAllStringSubmatch(string(raw), -1) {
		found[m[1]] = m[2]
	}
	return found
}

// A2: the deployment still carries the values this package's tests assume.
func TestProdValuesCarryTheEnvTheSuiteAssumes(t *testing.T) {
	found := readProdValues(t)
	for name, want := range prodEnv {
		if got, ok := found[name]; !ok {
			t.Errorf("k8s/prod/values.yaml no longer sets %s", name)
		} else if got != want {
			t.Errorf("k8s/prod/values.yaml has %s=%q, the suite assumes %q", name, got, want)
		}
	}
}

// A1: the config the binary builds from those values is the config the recall
// tables scan with. Without this, every table in this package could be testing
// a scanner production does not run.
func TestScanProdMatchesTheDeployedConfiguration(t *testing.T) {
	for name, value := range prodEnv {
		t.Setenv(name, value)
	}
	t.Setenv("ANALYZER_TOKENIZER", "") // prod leaves it unset

	fromEnv, err := scannerConfigFromEnv()
	if err != nil {
		t.Fatalf("building config from the production env: %v", err)
	}

	// what scanProd hand-builds
	byHand := defaultScannerConfig()
	byHand.genericSecretsEnabled = false
	byHand.entropyThreshold = 0.7
	byHand.mode = suppressionEnforce
	byHand.vendorMode = suppressionEnforce

	if fromEnv != byHand {
		t.Errorf("the hand-built config has drifted from the deployed one:\n  from env  = %+v\n  scanProd  = %+v", fromEnv, byHand)
	}
}
