package main

import (
	"context"
	"strings"
	"testing"
)

// Real token shapes the analyzer used to miss under prod's config, each checked
// for its exact span. Tokens are split at their prefix so none exists as a
// contiguous literal.
func TestRecallGapsReportTheToken(t *testing.T) {
	const pw = "Zq8Hk2Lm9Pq4Rs7Tv1Wx3Y"
	far := "\n" + strings.Repeat("# unrelated configuration line\n", 8)
	cases := []struct {
		name, entity, text, want string
	}{
		{"newrelic jp", "NewRelicMobileAppToken", "<string>jpxxbfd4a807e4099453ba160493119a126319cb27" + "-NRMA</string>", "jpxxbfd4a807e4099453ba160493119a126319cb27" + "-NRMA"},
		{"newrelic gov", "NewRelicMobileAppToken", "token: gov66xxfd4a807e4099453ba160493119a126319cb" + "-NRMA", "gov66xxfd4a807e4099453ba160493119a126319cb" + "-NRMA"},
		{"figma figd far from keyword", "FigmaPersonalAccessToken", "# figma" + far + "TOKEN=figd" + "_Ab3-Cd4_Ef5Gh6Jk7Mn8Pq9Rs2Tu3Vw4Xy5Za6Bc", "figd" + "_Ab3-Cd4_Ef5Gh6Jk7Mn8Pq9Rs2Tu3Vw4Xy5Za6Bc"},
		{"harness pat far from keyword", "Harness", "# harness" + far + "TOKEN=pat" + ".4oXWHvYFRNOGLVpFTZGGTA.68077fc826afe36865614d58.2fFEmr57WO3zPmev3jze", "pat" + ".4oXWHvYFRNOGLVpFTZGGTA.68077fc826afe36865614d58.2fFEmr57WO3zPmev3jze"},
		{"harness sat", "Harness", "token: sat" + ".YDfcEm2LT_OUZrFZv1WVlg.6a4f91eb79dfb04b036caf48.FrDL8MGzpMygCMzZv1Kq", "sat" + ".YDfcEm2LT_OUZrFZv1WVlg.6a4f91eb79dfb04b036caf48.FrDL8MGzpMygCMzZv1Kq"},
		{"docker user and password", "Docker", `{"auths":{"registry.acme.io":{"username":"bot","password":"` + pw + `"}}}`, pw},
		{"docker escaped in a k8s secret", "Docker", `.dockerconfigjson: "{\"auths\":{\"registry.acme.io\":{\"username\":\"bot\",\"password\":\"` + pw + `\"}}}"`, pw},
		{"docker user and password, pretty", "Docker", "{\n  \"auths\": {\n    \"registry.acme.io\": {\n      \"username\": \"bot\",\n      \"password\": \"" + pw + "\"\n    }\n  }\n}", pw},
		{"docker hub auth", "Docker", "{\n  \"auths\": {\n    \"https://index.docker.io/v1/\": {\n      \"auth\": \"Ym90OlpxOEhrMkxtOVBxNFJzN1R2MVd4M1k=\"\n    }\n  }\n}", "Ym90OlpxOEhrMkxtOVBxNFJzN1R2MVd4M1k="},
		{"docker short password lands on the config", "Docker", `the "k7Rm2q" host` + "\n" + `{"auths":{"registry.acme.io":{"username":"bot","password":"k7Rm2q"}}}`, "k7Rm2q"},
	}
	s := prodScanner(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, r := range s.scan(context.Background(), []byte(c.text), 0.75) {
				span := string([]rune(c.text)[r.Start:r.End])
				if r.EntityType == c.entity && span == c.want {
					if c.want == "k7Rm2q" && r.Start < strings.Index(c.text, `"password"`) {
						t.Fatalf("short password reported in the prose at %d, not in the config", r.Start)
					}
					return
				}
				got = append(got, r.EntityType+"="+span)
			}
			t.Fatalf("%s not reported over %q; got %v", c.entity, c.want, got)
		})
	}
}

// A commit hash in a repository URL is a revision, not a W&B key, even next to
// the word wandb. A labelled key still is one.
func TestCommitInRepositoryURLIsNotAKey(t *testing.T) {
	const sha = "4c2a9e1f0b7d3c6a8e5f2b1d9c0a7e3f6b8d2c4a"
	s := prodScanner(t)
	for _, text := range []string{
		"see https://github.com/wandb/terraform-aws-wandb/blob/" + sha + "/main.tf",
		"https://github.com/wandb/wandb/tree/" + sha + "/core",
		"pip install wandb git+https://github.com/wandb/wandb.git@" + sha,
		"https://gitlab.com/wandb/infra/-/commit/" + sha,
	} {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "WeightsAndBiases" {
				t.Errorf("commit hash reported as a W&B key in %q", text)
			}
		}
	}
	for _, text := range []string{"wandb login " + sha, "WANDB_API_KEY=" + sha} {
		found := false
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			found = found || r.EntityType == "WeightsAndBiases"
		}
		if !found {
			t.Errorf("labelled W&B key not reported in %q", text)
		}
	}
}

// An example registry config, a placeholder password in base64, stays quiet.
func TestDockerExampleConfigIsNotACredential(t *testing.T) {
	s := prodScanner(t)
	for _, text := range []string{
		`{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}}`,
		`{"auths":{"https://index.docker.io/v1/":{"username":"bot","password":"your_password"}}}`,
	} {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "Docker" {
				t.Errorf("example config reported as a Docker credential: %q", text)
			}
		}
	}
}
