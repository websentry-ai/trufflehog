package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsNamespace = "trufflehog"

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

	vendorFindingsEvaluatedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "vendor_findings_evaluated_total",
		Help:      "Curated-vendor findings evaluated by the structural gate, labelled by detector and mode (denominator for vendor suppression rate).",
	}, []string{"detector", "mode"})

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
)
