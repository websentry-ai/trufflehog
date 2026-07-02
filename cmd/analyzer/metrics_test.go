package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("write histogram: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

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

func TestFindingsPerRequestObserved(t *testing.T) {
	before := histogramSampleCount(t, findingsPerRequest)

	text := []byte("export GITHUB_TOKEN=" + fakeGithubPAT)
	if len(newScanner().scan(context.Background(), text, 0.75)) == 0 {
		t.Fatalf("expected at least one finding to exercise the metric path")
	}

	if after := histogramSampleCount(t, findingsPerRequest); after != before+1 {
		t.Fatalf("findings_per_request sample count: want %d, got %d", before+1, after)
	}
}

func TestScanTimeoutCounted(t *testing.T) {
	before := testutil.ToFloat64(scanTimeoutsTotal)

	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	newScanner().scan(ctx, []byte("export GITHUB_TOKEN="+fakeGithubPAT), 0.75)

	if after := testutil.ToFloat64(scanTimeoutsTotal); after <= before {
		t.Fatalf("scan_timeouts_total not incremented on an expired-deadline scan: before=%v after=%v", before, after)
	}
}

func TestInflightGaugeNetsToZero(t *testing.T) {
	h := newScanner().analyzeHandler("test-key")

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(`{"text":"export GITHUB_TOKEN=`+fakeGithubPAT+`","score_threshold":0.75}`))
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/analyze: want 200, got %d", rec.Code)
	}
	if v := testutil.ToFloat64(inflightRequests); v != 0 {
		t.Fatalf("inflight_requests should net to 0 after a completed request, got %v", v)
	}
}
