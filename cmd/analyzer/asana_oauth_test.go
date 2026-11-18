package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Synthetic tokens, assembled at runtime so the source holds no token-shaped
// literal. Only the PAT is also matched by AsanaPersonalAccessToken.
func fakeAsanaPAT() string {
	return "1/" + "1203456789012345" + ":" + "0f1e2d3c4b5a6978" + "8796a5b4c3d2e1f0"
}

func fakeAsanaOpaqueToken() string {
	return "0/" + "k3v9q2m7x1p8r4t6w0z5" + "b2n8c4h7j1l9f3d6s0g5" + "a8e2y7u4i"
}

func fakeAsanaSlashedToken() string {
	return "q5przi0tmp6xpo7rpsd0q" + ":kl0qg:" + "2gdj3jyumq04q9kcqk/qxdo"
}

func TestAsanaOauthLinkPathIsNotAToken(t *testing.T) {
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false
	cfg.mode = suppressionEnforce
	cfg.vendorMode = suppressionEnforce
	s, err := buildScanner(cfg)
	require.NoError(t, err)

	const oauth = "AsanaOauth"
	cases := []struct {
		name   string
		in     string
		entity string // "" means nothing may be flagged
	}{
		{"project link", "asana task https://app.asana.com/1/1209876543210/project/1209876543210987/list/x", ""},
		{"link after a colon label", "see asana: https://app.asana.com/0/1209876543210/project/1209876543210987/list/9", ""},
		{"numeric-only link", "asana https://app.asana.com/0/1209876543210987/1209876543210988/1209876543210989", ""},
		{"labelled opaque token", "ASANA_TOKEN=" + fakeAsanaOpaqueToken(), oauth},
		{"opaque token in prose", "my asana refresh token is " + fakeAsanaOpaqueToken(), oauth},
		{"token with a slash", "asana oauth " + fakeAsanaSlashedToken(), oauth},
		{"personal access token", "ASANA_TOKEN=" + fakeAsanaPAT(), "any"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.scan(context.Background(), []byte(tc.in), 0.75)
			switch tc.entity {
			case "":
				require.Empty(t, got, "an Asana link is not a secret")
			case "any":
				require.NotEmpty(t, got, "a real Asana token must still be flagged")
			default:
				var types []string
				for _, f := range got {
					types = append(types, f.EntityType)
				}
				require.Contains(t, types, tc.entity)
			}
		})
	}
}

func TestIsObjectLinkPath(t *testing.T) {
	for _, v := range []string{
		"com/1/1209876543210/project/1209876543210987/list/x",
		"com/0/1209876543210/1209876543210987/f",
		"/1209876543210987/1209876543210988/1209876543210989",
	} {
		require.True(t, isObjectLinkPath(v), v)
	}
	for _, v := range []string{
		fakeAsanaPAT(),
		fakeAsanaOpaqueToken(),
		fakeAsanaSlashedToken(),
		"2/1203456789012345/1209876543210987:0f1e2d3c4b5a69",
		"0/1209876543210/abc/k3v9q2m7x1p8r4t6w0z5b2n8",
	} {
		require.False(t, isObjectLinkPath(v), v)
	}
}
