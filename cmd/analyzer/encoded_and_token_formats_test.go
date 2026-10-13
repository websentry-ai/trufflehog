package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Tokens are split at their prefix so none exists as a contiguous literal.
const (
	testAWSID     = "AKIA" + "QYLPMN5HHHFPZAM2"
	testAWSSecret = "1tUm636uS1yOEcfP5pvfqJ/ml36mF7AkyHsEU0IU"
	testZendesk   = "Kq7xP2mR9vTw4yZ8bN3cL6fH1jD5gS0aEuWoYiXe"
	testGitHub    = "ghp_" + "Xq7Lm2Nk9Pv4Rs8Tw1Yz3Ab5Cd6Ef7Gh8Ij9K"
)

func spans(s *scanner, text string) []string {
	var out []string
	for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
		out = append(out, fmt.Sprintf("%s=%s", r.EntityType, string([]rune(text)[r.Start:r.End])))
	}
	return out
}

func hmacJWT(t *testing.T, claims string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." +
		enc([]byte("0123456789abcdef0123456789abcdef"))
}

// Every in-process custom detector shares one type, so the keyword index can
// only tell them apart by version. Two with the same version silently replace
// each other.
func TestCustomDetectorsHaveDistinctKeys(t *testing.T) {
	cfg, err := scannerConfigFromEnv()
	require.NoError(t, err)
	dets, err := buildDetectors(cfg)
	require.NoError(t, err)
	seen := map[ahocorasick.DetectorKey]string{}
	for _, d := range dets {
		key := ahocorasick.CreateDetectorKey(d)
		name := fmt.Sprintf("%T", d)
		require.NotContains(t, seen, key, "%s shares a detector key with %s", name, seen[key])
		seen[key] = name
	}
}

func TestZendeskTokenIsOneSecretIncludingItsEmail(t *testing.T) {
	s := prodScanner(t)
	login := "jane.doe@acme.com/token:" + testZendesk
	for _, text := range []string{
		login,
		"curl https://acme.zendesk.com/api/v2/tickets.json -u " + login,
		`{"username": "` + login + `"}`,
	} {
		require.Equal(t, []string{"zendesk-api-token=" + login}, spans(s, text), text)
	}
	for _, text := range []string{
		"jane.doe@acme.com/token:" + testZendesk[:39],
		"jane.doe@acme.com/token:" + testZendesk + "x",
		"see https://acme.zendesk.com/token: for details",
		"you@example.com/token:" + strings.Repeat("abcdefghij", 4),
	} {
		require.NotContains(t, strings.Join(spans(s, text), " "), "zendesk-api-token", text)
	}
}

func TestHMACJWTIsReportedUnlessExpired(t *testing.T) {
	s := prodScanner(t)
	live := hmacJWT(t, fmt.Sprintf(`{"sub":"svc","exp":%d}`, time.Now().Add(24*time.Hour).Unix()))
	noExp := hmacJWT(t, `{"sub":"svc","iat":1728000000}`)
	for _, tok := range []string{live, noExp} {
		require.Equal(t, []string{"JWT=" + tok}, spans(s, "Authorization: Bearer "+tok))
	}
	expired := hmacJWT(t, `{"sub":"svc","exp":1600000000}`)
	require.NotContains(t, strings.Join(spans(s, "Authorization: Bearer "+expired), " "), "JWT")
}

func TestEncodedCredentialsAreFoundAndNamed(t *testing.T) {
	s := prodScanner(t)
	b64 := base64.StdEncoding.EncodeToString
	pair := b64([]byte("AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret))
	gh := b64([]byte("GITHUB_TOKEN=" + testGitHub))
	dsn := b64([]byte("postgres://app:Hx7Qm2Vr9Lp4@db.acme.io:5432/main"))
	basic := b64([]byte("jane.doe@acme.com/token:" + testZendesk))
	cases := []struct{ text, want string }{
		{"echo " + pair + " | base64 -d", "AWS=" + pair},
		{"TOKEN_B64=" + gh, "Github=" + gh},
		{"kind: Secret\ndata:\n  DATABASE_URL: " + dsn, "Postgres=" + dsn},
		{"Authorization: Basic " + basic, "zendesk-api-token=" + basic},
		{"url-safe " + base64.URLEncoding.EncodeToString([]byte("GITHUB_TOKEN="+testGitHub)), ""},
	}
	for _, c := range cases {
		got := spans(s, c.text)
		if c.want == "" {
			require.Len(t, got, 1, c.text)
			require.True(t, strings.HasPrefix(got[0], "Github="), "%s: %v", c.text, got)
			continue
		}
		require.Equal(t, []string{c.want}, got, c.text)
	}
}

func TestEncodedRunsWithoutCredentialsStayQuiet(t *testing.T) {
	s := prodScanner(t)
	b64 := base64.StdEncoding.EncodeToString
	png := []byte{0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 1, 0, 0, 0, 1, 0, 8, 6, 0, 0, 0}
	for _, text := range []string{
		"msg: " + b64([]byte("hello world, this is a perfectly ordinary sentence")),
		"img: data:image/png;base64," + b64(png),
		"integrity: sha512-" + b64([]byte(strings.Repeat("\x01\x9f\xe2", 22))),
		"func handleIncomingWebhookPayloadForTenantProvisioning() {}",
		"placeholder: " + b64([]byte("AWS_ACCESS_KEY_ID=AKIA"+"EXAMPLEKEY123456")),
	} {
		require.Empty(t, spans(s, text), text)
	}
}
