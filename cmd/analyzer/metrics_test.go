package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestDetectionsTotalIncremented(t *testing.T) {
	const entityType = "Github"
	before := testutil.ToFloat64(detectionsTotal.WithLabelValues(entityType))

	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	results := newScanner().scan(context.Background(), text, 0.75)
	if len(results) == 0 {
		t.Fatalf("expected at least one finding")
	}

	after := testutil.ToFloat64(detectionsTotal.WithLabelValues(entityType))
	if after <= before {
		t.Fatalf("detections_total{entity_type=%q} not incremented: before=%v after=%v", entityType, before, after)
	}
}

func TestMetricsEndpointExposesTruffleHogSeries(t *testing.T) {
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "trufflehog_") {
		t.Fatalf("/metrics body missing trufflehog_ series")
	}
}

func TestBuildInfoExposed(t *testing.T) {
	recordBuildInfo()

	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "trufflehog_build_info") {
		t.Fatalf("/metrics body missing trufflehog_build_info series")
	}
	if !strings.Contains(body, `version="`+version+`"`) {
		t.Fatalf("trufflehog_build_info missing version=%q label", version)
	}
}

// TestMetricsNeverLeakSecretValue is a smoke test for the non-negotiable that
// metrics must never carry secret material. It scans a real finding, then
// asserts that none of the actual matched raw values from the scan results — nor
// the planted token — appear anywhere in the /metrics body. It does not prove
// the property for every detector or future metric (that's a code-review
// invariant); it catches the common regression of piping a raw value into a label.
func TestMetricsNeverLeakSecretValue(t *testing.T) {
	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	results := newScanner().scan(context.Background(), text, 0.75)
	if len(results) == 0 {
		t.Fatalf("expected at least one finding to exercise the metric path")
	}

	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if strings.Contains(body, fakeGithubPAT) {
		t.Fatalf("/metrics body leaked the planted secret value into a metric series")
	}
	for _, r := range results {
		if r.raw != "" && strings.Contains(body, r.raw) {
			t.Fatalf("/metrics body leaked a matched raw secret value (entity=%s) into a metric series", r.EntityType)
		}
	}
}
