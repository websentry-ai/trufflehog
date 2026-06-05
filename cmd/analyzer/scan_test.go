package main

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestLivenessAlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	liveness(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("liveness body unexpected: %s", rec.Body.String())
	}
}

func TestReadinessReadyWhenDetectorsLoaded(t *testing.T) {
	s := &scanner{core: ahocorasick.NewAhoCorasickCore(defaults.DefaultDetectors()), detectors: 1}
	rec := httptest.NewRecorder()
	s.readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness: want 200, got %d", rec.Code)
	}
}

func TestReadinessNotReadyWithoutDetectors(t *testing.T) {
	s := &scanner{} // no core, zero detectors
	rec := httptest.NewRecorder()
	s.readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness: want 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not ready") {
		t.Fatalf("readiness body unexpected: %s", rec.Body.String())
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

func TestParseGenericSecretScore(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    float64
		wantErr bool
	}{
		{name: "valid", raw: "0.85", want: 0.85},
		{name: "boundary low", raw: "0", want: 0.0},
		{name: "boundary high", raw: "1", want: 1.0},
		{name: "empty defaults", raw: "", want: defaultGenericSecretScore},
		{name: "not a number", raw: "abc", wantErr: true},
		{name: "nan", raw: "NaN", wantErr: true},
		{name: "inf", raw: "Inf", wantErr: true},
		{name: "above range", raw: "2", wantErr: true},
		{name: "below range", raw: "-0.1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGenericSecretScore(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.False(t, math.IsNaN(got) || math.IsInf(got, 0))
			require.Equal(t, tc.want, got)
		})
	}
}
