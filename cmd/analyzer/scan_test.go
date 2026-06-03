package main

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

const fakeGithubPAT = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

var (
	testOnce sync.Once
	testScan *scanner
)

func newScanner() *scanner {
	testOnce.Do(func() {
		testScan = &scanner{core: ahocorasick.NewAhoCorasickCore(defaults.DefaultDetectors())}
	})
	return testScan
}

func TestScanDetectsGithubPAT(t *testing.T) {
	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	results := newScanner().scan(context.Background(), text, 0.75)

	var hit bool
	for _, r := range results {
		if string(text[r.Start:r.End]) == fakeGithubPAT {
			hit = true
			if r.Source != "trufflehog" {
				t.Errorf("expected source trufflehog, got %s", r.Source)
			}
			if r.EntityType == "" {
				t.Error("entity_type must not be empty")
			}
			if r.Score < 0.75 {
				t.Errorf("score %v below threshold", r.Score)
			}
		}
	}
	if !hit {
		t.Fatalf("no finding matched the token, got %d results", len(results))
	}
}

func TestScanIgnoresBenignText(t *testing.T) {
	results := newScanner().scan(context.Background(), []byte("the quick brown fox jumps"), 0.75)
	if len(results) != 0 {
		t.Fatalf("expected no findings, got %d", len(results))
	}
}

func TestScanRespectsThreshold(t *testing.T) {
	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	if results := newScanner().scan(context.Background(), text, 0.95); len(results) != 0 {
		t.Fatalf("expected threshold to filter finding, got %d", len(results))
	}
}

func TestScanResultNeverContainsRawSecret(t *testing.T) {
	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	for _, r := range newScanner().scan(context.Background(), text, 0.75) {
		if strings.Contains(r.EntityType, fakeGithubPAT) {
			t.Fatalf("raw secret leaked into result: %+v", r)
		}
	}
}

func TestOffsets(t *testing.T) {
	data := []byte("token " + fakeGithubPAT + " end")

	start, end, ok := offsets(data, []byte(fakeGithubPAT))
	if !ok || string(data[start:end]) != fakeGithubPAT {
		t.Fatalf("located match wrong: ok=%v span=%d:%d", ok, start, end)
	}
	if _, _, ok := offsets(data, []byte("not-in-text")); ok {
		t.Error("expected ok=false for absent raw")
	}
	if _, _, ok := offsets(data, nil); ok {
		t.Error("expected ok=false for empty raw")
	}
}
