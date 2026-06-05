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
