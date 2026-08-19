package main

import (
	"context"
	"strings"
	"testing"
)

// paired detectors match two components -- a token and a vendor URL, or two
// halves of a credential -- and pair them anywhere within the data they are
// handed. Windowing the scan is what bounds that; these tests hold the bound.
var pairedDetectors = []struct {
	name string
	// the whole credential, as a careless paste would carry it
	adjacent string
	// the same components split by more than a window, as unrelated text
	scattered string
}{
	{"Cloudinary",
		"cloudinary_name = acme-prod\ncloudinary api key 218873249723411\ncloudinary api secret V-fwwRhcp3VrRPAqaFkLq3rpa60",
		"cloudinary_name = acme-prod\n%s\ncloudinary asset id 218873249723411\n%s\ncloudinary cache key V-fwwRhcp3VrRPAqaFkLq3rpa60"},
	{"Duo",
		"duo host api-123456.duosecurity.com\nduo ikey DIABCDEFGHIJKLMNOPQR\nduo skey CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe",
		"duo sso at api-123456.duosecurity.com\n%s\nduo ref DIABCDEFGHIJKLMNOPQR\n%s\nduo digest CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe"},
	{"HashiCorpVaultToken",
		"vault addr https://vault-cluster-abc123.hashicorp.cloud:8200\ntoken s.1234567890abcdefddd ",
		"vault addr https://vault-cluster-abc123.hashicorp.cloud:8200\n%s\nreturn s.gatewayMetricsServiceClient\n%s"},
	{"HashiCorpVaultBatchToken",
		"vault addr https://vault-cluster-abc123.hashicorp.cloud:8200\ntoken hvb.aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM7nP9qR ",
		"vault addr https://vault-cluster-abc123.hashicorp.cloud:8200\n%s\nhvb.aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM7nP9qR \n%s"},
	{"OctopusDeploy",
		"server = https://acme-deploy.octopus.app\napiKey = API-1234567890ABCDEFGHIJKLMNO1234",
		"docs at https://acme-deploy.octopus.app\n%s\nconst API-1234567890ABCDEFGHIJKLMNO1234 = x\n%s"},
	{"Rev",
		"rev userkey T5LJHzWwZzdpmNtxKDaDcDUlckU=\nrev clientkey utD8J485zVIeRCbHyU8yYfw55m2 \n",
		"review notes T5LJHzWwZzdpmNtxKDaDcDUlckU=\n%s\nrevision utD8J485zVIeRCbHyU8yYfw55m2 \n%s"},
	{"User",
		"endpoint https://testdetector.user.com\nuser token 9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf",
		"docs https://testdetector.user.com\n%s\nuser digest 9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf\n%s"},
}

func TestPairedDetectorsFireWhenAdjacent(t *testing.T) {
	s := newBuiltScanner(t)
	for _, d := range pairedDetectors {
		t.Run(d.name, func(t *testing.T) {
			for _, r := range s.scan(context.Background(), []byte(d.adjacent), 0.75) {
				if r.EntityType == d.name {
					return
				}
			}
			t.Fatalf("%s did not fire on a complete credential", d.name)
		})
	}
}

// The components sit further apart than a window, so they land in different
// scans and cannot combine. Without windowing every one of these fires.
func TestPairedDetectorsDoNotPairAcrossWindows(t *testing.T) {
	filler := strings.Repeat("The deployment guide covers rollout, monitoring and rollback procedures. ", 200)
	s := newBuiltScanner(t)
	for _, d := range pairedDetectors {
		t.Run(d.name, func(t *testing.T) {
			text := strings.ReplaceAll(d.scattered, "%s", filler)
			if len(text) <= scanWindowSize+scanWindowPeek {
				t.Fatalf("fixture is %d bytes, not wider than a window", len(text))
			}
			for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
				if r.EntityType == d.name {
					t.Errorf("%s paired across %d bytes", d.name, len(text))
				}
			}
		})
	}
}

func TestBraintrustFiresOnItsOwnFormat(t *testing.T) {
	text := "BRAINTRUST_API_KEY=sk" + "-76cnJ2Ns8wHZao70KdUdlZpBuSzej8gEokToNyeSPtd1RyZB"
	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(text), 0.75) {
		if r.EntityType == "BrainTrustApiKey" {
			return
		}
	}
	t.Fatal("expected BrainTrustApiKey")
}

func TestBraintrustIgnoresProse(t *testing.T) {
	benign := []string{
		"see the sk- prefix documentation for details",
		"braintrust keys are sk- followed by 48 characters",
		"sk-shortkey",
	}
	s := newBuiltScanner(t)
	for _, text := range benign {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			t.Errorf("false positive: %s matched %q in %q", r.EntityType, text[r.Start:r.End], text)
		}
	}
}
