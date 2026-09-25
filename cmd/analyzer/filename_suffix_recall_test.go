package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Exactly how prod is configured: generic secrets OFF, entropy proximity ON.
func scanProd(t *testing.T, doc string) []analyzeResult {
	t.Helper()
	cfg := defaultScannerConfig()
	cfg.genericSecretsEnabled = false // k8s/prod/values.yaml
	cfg.entropyThreshold = 0.7
	cfg.mode = suppressionEnforce
	cfg.vendorMode = suppressionEnforce
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s.scan(context.Background(), []byte(doc), 0.45)
}

// Runs with generic secrets OFF, matching k8s/prod/values.yaml. With them on
// that detector reports these values regardless, and the table passes while the
// entropy path prod actually runs is still dropping them.
//
// A real secret can coincidentally end in a known extension plus a grep
// separator. The filename exclusion must never drop such a value when its
// label marks it as a credential -- a missed secret is the one outcome this
// scanner cannot have.
//
// The carve-out reaches a label three ways, and each needed its own fix:
// "api_key=v" keeps the label on the value's token, "api_key: v" and
// {"api_key": "v"} leave it on the token before, and "api_key = v" puts a bare
// delimiter in between.
func TestFilenameSuffixNeverHidesALabelledSecret(t *testing.T) {
	const val = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh.md-"

	labels := []string{
		"api_key", "apikey", "apiKey", "API_KEY", "x-api-key",
		"key", "signing_key", "encryption_key", "ssh_key", "host_key",
		"master_key", "account_key", "consumer_key", "session_key", "public_key",
		"secret", "client_secret", "app_secret", "webhook_secret", "jwt_secret",
		"consumer_secret", "apiSecret", "clientSecret",
		"password", "passwd", "pwd", "db_password", "adminPassword",
		"token", "auth_token", "authToken", "access_token", "refresh_token",
		"sas_token", "bearer_token", "id_token", "githubToken",
		"credential", "credentials", "bearer", "authorization",
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_API_KEY",
		"private_key", "privateKey", "access_key",
	}
	syntaxes := []struct{ name, tmpl string }{
		{"equals", "config:\n  %s=%s\n"},
		{"colon", "config:\n  %s: %s\n"},
		{"spaced", "config:\n  %s = %s\n"},
		{"json", "{\n  \"%s\": \"%s\"\n}\n"},
		{"export", "export %s=%s\n"},
	}

	for _, sx := range syntaxes {
		for _, label := range labels {
			t.Run(sx.name+"/"+label, func(t *testing.T) {
				doc := fmt.Sprintf(sx.tmpl, label, val)
				require.NotEmpty(t, scanProd(t, doc),
					"a secret labelled %q in %s form was silently dropped for looking like a filename",
					label, sx.name)
			})
		}
	}
}

// The Box embedded-vendor rule exists for the Dropbox "app-<hex>@host"
// fragment. A Box token is 32 alphanumerics, so a hyphen beside it is an
// ordinary neighbour and must not delete the finding.
func TestBoxTokenSurvivesAHyphenNeighbour(t *testing.T) {
	const tok = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	for name, doc := range map[string]string{
		"assigned with a prefixed value": "box_token=app-" + tok + "\n",
		"hyphen immediately before":      "box-" + tok + "\n",
		"hyphenated suffix after":        "box access token " + tok + "-prod\n",
		"plain assignment":               "box_token=" + tok + "\n",
		"labelled dropbox fragment":      "box_token=app-" + tok + "@host\n",
		"space delimited":                "box access token " + tok + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, scanProd(t, doc), "a Box token was dropped: %s", name)
		})
	}
}
