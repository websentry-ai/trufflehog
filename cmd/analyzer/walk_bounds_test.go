package main

import (
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

// Every backward scan is bounded, because the request is not. Blank lines were
// the shape that showed it: the enclosing-key walk read every earlier line, and
// the helper finding each line's last character crossed all the blank ones
// again, so one finding cost quadratic time. A fifth of the request limit took
// sixteen seconds, which the scan timeout cannot interrupt.
func TestABackwardScanCostsTheSameAtEverySize(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	shapes := map[string]func(n int) string{
		"blank lines":   func(n int) string { return "api_key=x\n" + strings.Repeat("\n", n) + `"sha256": "` + secret + `"` },
		"indented keys": func(n int) string { return strings.Repeat("a:\n  b: c\n", n/10) + "  sha256: " + secret },
		"open quotes":   func(n int) string { return strings.Repeat(`"`, n) + `sha256=` + secret },
		"nesting":       func(n int) string { return strings.Repeat("{", n) + `"sha256": "` + secret + `"` },
	}
	for name, build := range shapes {
		t.Run(name, func(t *testing.T) {
			var small, large time.Duration
			for _, c := range []struct {
				n int
				d *time.Duration
			}{{2000, &small}, {200000, &large}} {
				doc := []byte(build(c.n))
				res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
				start := time.Now()
				decideSuppression(res, map[string]int{}, doc)
				*c.d = time.Since(start)
			}
			// Reading the document is linear, so a hundredfold more input
			// costing a hundredfold more time is expected and fine. Quadratic
			// is what this catches: it would be ten thousandfold, and it was
			// sixteen seconds before the scans were bounded.
			if large > 500*time.Millisecond {
				t.Errorf("%s: one finding took %v on a 200k document", name, large)
			}
			if small > 0 && large > 500*small {
				t.Errorf("%s: cost grew %.0fx for 100x the input (%v -> %v), which is not linear",
					name, float64(large)/float64(small), small, large)
			}
		})
	}
}
