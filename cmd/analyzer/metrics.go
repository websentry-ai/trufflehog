package main

import (
	"runtime"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsNamespace = "trufflehog"

// version and commit are stamped at build time via
// -ldflags "-X main.version=<ref> -X main.commit=<sha>" (see cmd/analyzer/Dockerfile,
// wired from CI in deploy-eks.yml). They default to "dev"/"unknown" for local builds.
// .dockerignore excludes .git, so the image has no VCS info to fall back on —
// the ldflag stamp is the source of truth in deployed builds.
var (
	version = "dev"
	commit  = "unknown"
)

var (
	analyzeRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "analyze_requests_total",
		Help:      "Total /analyze requests, labelled by HTTP status code.",
	}, []string{"status"})

	analyzeRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "analyze_request_duration_seconds",
		Help:      "Latency of the full /analyze handler.",
		Buckets:   prometheus.DefBuckets,
	})

	scanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "scan_duration_seconds",
		Help:      "Latency of the scan() call alone.",
		Buckets:   prometheus.DefBuckets,
	})

	// Labelled by detector/entity type only, never the secret value.
	detectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "detections_total",
		Help:      "Total emitted findings, labelled by entity type.",
	}, []string{"entity_type"})

	detectorErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "detector_errors_total",
		Help:      "Total detector FromData errors, labelled by detector.",
	}, []string{"detector"})

	placeholdersSuppressedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "placeholders_suppressed_total",
		Help:      "Total findings dropped as obvious placeholders, labelled by entity type.",
	}, []string{"entity_type"})

	findingsSuppressedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "findings_suppressed_total",
		Help:      "FP-gate suppression decisions, labelled by reason, detector, and mode (shadow counts would-be suppressions).",
	}, []string{"reason", "detector", "mode"})

	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "http_requests_total",
		Help:      "Total HTTP requests, labelled by method, route (bounded), and status.",
	}, []string{"method", "route", "status"})

	scannedBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "scanned_bytes",
		Help:      "Size of scanned request bodies in bytes.",
		Buckets:   prometheus.ExponentialBuckets(256, 2, 13),
	})

	// Static build metadata. Constant value 1; the deployed version/commit/go
	// version ride on the labels so a single board can show what's running in
	// each environment. Labels are build-time constants, never request data.
	buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "build_info",
		Help:      "Build metadata, constant 1, labelled by version, commit, and go_version.",
	}, []string{"version", "commit", "go_version"})
)

// recordBuildInfo sets the trufflehog_build_info gauge to 1 with the build's
// version, VCS commit, and Go runtime version. The commit prefers the ldflag
// stamp; for un-stamped local builds it falls back to the embedded VCS revision
// (`go build` from a git tree) and finally "unknown" (e.g. `go test`).
func recordBuildInfo() {
	c := commit
	if c == "unknown" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					c = s.Value
					break
				}
			}
		}
	}
	buildInfo.WithLabelValues(version, c, runtime.Version()).Set(1)
}
