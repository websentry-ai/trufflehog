package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

type suppressionMode int

const (
	suppressionOff suppressionMode = iota
	suppressionShadow
	suppressionEnforce
)

const (
	bulkListMinCount = 20
	bulkShapeMinLen  = 8
)

const (
	reasonBulkList    = "bulk_list"
	reasonStripeObjID = "structural_stripe_object_id"
)

func parseSuppressionMode(raw string) suppressionMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "enforce":
		return suppressionEnforce
	case "off":
		return suppressionOff
	case "shadow":
		return suppressionShadow
	default:
		log.Printf("FP_SUPPRESSION_MODE=%q unrecognized; defaulting to enforce (valid: off, shadow, enforce)", raw)
		return suppressionEnforce
	}
}

func (m suppressionMode) String() string {
	switch m {
	case suppressionShadow:
		return "shadow"
	case suppressionEnforce:
		return "enforce"
	default:
		return "off"
	}
}

func lenBand(n int) byte {
	switch {
	case n < 12:
		return '0'
	case n <= 24:
		return '1'
	case n <= 48:
		return '2'
	default:
		return '3'
	}
}

func shapeKeyBytes(tok []byte) string {
	var word, dash, under, dot, other bool
	for _, b := range tok {
		switch {
		case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9'):
			word = true
		case b == '-':
			dash = true
		case b == '_':
			under = true
		case b == '.':
			dot = true
		default:
			other = true
		}
	}
	key := make([]byte, 0, 6)
	key = append(key, lenBand(len(tok)))
	for _, f := range []struct {
		set bool
		c   byte
	}{
		{word, 'w'}, {dash, '-'}, {under, '_'}, {dot, '.'}, {other, 'o'},
	} {
		if f.set {
			key = append(key, f.c)
		}
	}
	return string(key)
}

func shapeKey(tok string) string {
	return shapeKeyBytes([]byte(tok))
}

func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.' || b == '_' || b == '-' || b == '+' || b == '/' || b == '~' || b == '@':
		return true
	}
	return false
}

func documentShapes(data []byte) map[string]int {
	shapes := make(map[string]int)
	start := -1
	flush := func(end int) {
		if start >= 0 {
			if end-start >= bulkShapeMinLen {
				shapes[shapeKeyBytes(data[start:end])]++
			}
			start = -1
		}
	}
	for i := 0; i < len(data); i++ {
		if isTokenByte(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return shapes
}

func decideSuppression(entity, raw string, shapes map[string]int) (bool, string) {
	if !isGenericDetectorName(entity) {
		return false, ""
	}
	if customdetectors.IsStripeObjectID(raw) {
		return true, reasonStripeObjID
	}
	if len(raw) >= bulkShapeMinLen && shapes[shapeKey(raw)] >= bulkListMinCount {
		return true, reasonBulkList
	}
	return false, ""
}

func (s *scanner) applySuppression(ctx context.Context, in []analyzeResult, data []byte) []analyzeResult {
	if s.mode == suppressionOff {
		return in
	}
	gateable := false
	for _, f := range in {
		if isGenericDetectorName(f.EntityType) {
			gateable = true
			break
		}
	}
	if !gateable {
		return in
	}
	shapes := documentShapes(data)
	kept := make([]analyzeResult, 0, len(in))
	counts := map[string]int{}
	for _, f := range in {
		suppress, reason := decideSuppression(f.EntityType, f.raw, shapes)
		if !suppress {
			kept = append(kept, f)
			continue
		}
		findingsSuppressedTotal.WithLabelValues(reason, f.EntityType, s.mode.String()).Inc()
		counts[reason]++
		if s.mode == suppressionShadow {
			kept = append(kept, f)
		}
	}
	if len(counts) > 0 {
		total, summary := summarizeCounts(counts)
		log.Printf("scan suppressed req=%s mode=%s total=%d reasons=%s", reqIDFrom(ctx), s.mode, total, summary)
	}
	return kept
}

func summarizeCounts(counts map[string]int) (int, string) {
	keys := make([]string, 0, len(counts))
	total := 0
	for k, v := range counts {
		keys = append(keys, k)
		total += v
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, counts[k])
	}
	return total, strings.Join(parts, ",")
}
