package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAsanaToken is a synthetic token in the real "<n>/<id>:<secret>" shape,
// assembled at runtime so the source holds no token-shaped literal.
func fakeAsanaToken() string {
	return "1/" + "1203456789012345" + ":" + "0f1e2d3c4b5a6978" + "8796a5b4c3d2e1f0"
}

func TestAsanaOauthURLPathIsNotAToken(t *testing.T) {
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false
	cfg.mode = suppressionEnforce
	cfg.vendorMode = suppressionEnforce
	s, err := buildScanner(cfg)
	require.NoError(t, err)

	token := fakeAsanaToken()
	cases := []struct {
		name    string
		in      string
		flagged bool
	}{
		{"project link", "asana task https://app.asana.com/1/1209876543210/project/1209876543210987/list/x", false},
		{"link after a colon label", "see asana: https://app.asana.com/0/1209876543210/project/1209876543210987/list/9", false},
		{"labelled token", "ASANA_TOKEN=" + token, true},
		{"token in prose", "my asana token is " + token, true},
		{"token after the keyword", "asana pat " + token, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.scan(context.Background(), []byte(tc.in), 0.75)
			if tc.flagged {
				require.NotEmpty(t, got, "a real Asana token must still be flagged")
			} else {
				require.Empty(t, got, "an Asana link is not a secret")
			}
		})
	}
}

func TestAsanaOauthRuleKeepsColonTokens(t *testing.T) {
	sup, _ := decideVendorSuppression(analyzeResult{EntityType: "AsanaOauth", raw: fakeAsanaToken()}, nil)
	require.False(t, sup)
	sup, reason := decideVendorSuppression(analyzeResult{EntityType: "AsanaOauth", raw: "com/1/1209876543210/project/1209876543210987/list/x"}, nil)
	require.True(t, sup)
	require.Equal(t, reasonVendorStructuralNoise, reason)
}
