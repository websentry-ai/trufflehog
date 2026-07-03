package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

const testPEMPrivateKey = `is this ssh key private or public?
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDKDU7bIL1+s0Q7
lSS9Ei/9V26U8Q7ehMAJ4N7GnjVt+tkas6tPyK5cZMdvt3o62Jk3L75CyHox7WFJ
ulOI6hzl+WV5PtHOi/TQh8g=
-----END PRIVATE KEY-----`

func scanPEM(t *testing.T, cfg scannerConfig) []analyzeResult {
	t.Helper()
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s.scan(context.Background(), []byte(testPEMPrivateKey), 0.75)
}

func privateKeyBlock(results []analyzeResult) (analyzeResult, bool) {
	for _, r := range results {
		if r.EntityType == customdetectors.PrivateKeyName {
			return r, true
		}
	}
	return analyzeResult{}, false
}

func TestPrivateKeyDetectedWithGenericSecretsDisabled(t *testing.T) {
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false
	cfg.privateKeyEnabled = true
	cfg.entropyProximityEnabled = false

	block, ok := privateKeyBlock(scanPEM(t, cfg))
	require.True(t, ok, "private-key-block must fire even when generic secrets are disabled")

	captured := testPEMPrivateKey[block.Start:block.End]
	require.Contains(t, captured, "-----BEGIN PRIVATE KEY-----")
	require.Contains(t, captured, "-----END PRIVATE KEY-----")
}

func TestPrivateKeyNotDetectedWhenDisabled(t *testing.T) {
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false
	cfg.privateKeyEnabled = false
	cfg.entropyProximityEnabled = false

	_, ok := privateKeyBlock(scanPEM(t, cfg))
	require.False(t, ok, "private-key-block must not fire when ENABLE_PRIVATE_KEY is off")
}

func TestEnvEnabledDefault(t *testing.T) {
	t.Setenv("ENABLE_PRIVATE_KEY_TEST", "")
	require.True(t, envEnabledDefault("ENABLE_PRIVATE_KEY_TEST", true))
	require.False(t, envEnabledDefault("ENABLE_PRIVATE_KEY_TEST", false))
	t.Setenv("ENABLE_PRIVATE_KEY_TEST", "false")
	require.False(t, envEnabledDefault("ENABLE_PRIVATE_KEY_TEST", true))
	t.Setenv("ENABLE_PRIVATE_KEY_TEST", "1")
	require.True(t, envEnabledDefault("ENABLE_PRIVATE_KEY_TEST", false))
}
