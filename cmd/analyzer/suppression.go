package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
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
	reasonHexHash     = "structural_hex_hash"
	reasonHexTraceID  = "structural_hex_trace_id"
	reasonStructural  = "structural_nonsecret"
)

const hexIDContextWindow = 24

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

func parseVendorSuppressionMode(raw string) suppressionMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return suppressionOff
	case "shadow":
		return suppressionShadow
	case "enforce":
		return suppressionEnforce
	default:
		log.Printf("VENDOR_STRUCTURAL_SUPPRESSION=%q unrecognized; defaulting to off (valid: off, shadow, enforce)", raw)
		return suppressionOff
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

func decideSuppression(f analyzeResult, shapes map[string]int, data []byte) (bool, string) {
	if !isGenericDetectorName(f.EntityType) {
		return false, ""
	}
	if classify.IsStripeObjectID(f.raw) {
		return true, reasonStripeObjID
	}
	if len(f.raw) >= bulkShapeMinLen && shapes[shapeKey(f.raw)] >= bulkListMinCount {
		return true, reasonBulkList
	}
	if classify.IsHex32(f.raw) && contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		return isChecksumRowAt(d, s, len(f.raw))
	}) {
		return true, reasonHexHash
	}
	if classify.IsAllHex(f.raw) && len(f.raw) >= 16 && traceContextSuppressed(data, f.raw, func(d []byte, s int) bool {
		return hexInTraceContextAt(d, s, f.raw)
	}) {
		return true, reasonHexTraceID
	}
	if f.EntityType == customdetectors.GenericSecretName && classify.IsStructuralNonSecret(f.raw) {
		return true, reasonStructural
	}
	return false, ""
}

const (
	credentialContextWindow = 32
	credentialKeywordWindow = 16
)

func suppressByContext(data []byte, raw string, requireAll bool, benignAt func(data []byte, start int) bool) bool {
	rb := []byte(raw)
	if len(rb) == 0 {
		return false
	}
	anyBenign := false
	for off := 0; off+len(rb) <= len(data); {
		i := bytes.Index(data[off:], rb)
		if i < 0 {
			break
		}
		pos := off + i
		end := pos + len(rb)
		if (isAlnumByte(rb[0]) && pos > 0 && isAlnumByte(data[pos-1])) ||
			(isAlnumByte(rb[len(rb)-1]) && end < len(data) && isAlnumByte(data[end])) {
			off = pos + 1
			continue
		}
		lo := pos - credentialContextWindow
		if lo < 0 {
			lo = 0
		}
		if classify.IsCredentialAssignment(string(data[lo:pos])) {
			return false
		}
		klo := pos - credentialKeywordWindow
		if klo < 0 {
			klo = 0
		}
		if classify.IsCredentialContext(string(data[klo:pos])) {
			return false
		}
		if benignAt(data, pos) {
			anyBenign = true
		} else if requireAll {
			return false
		}
		off = pos + 1
	}
	return anyBenign
}

func contextSuppressed(data []byte, raw string, benignAt func(data []byte, start int) bool) bool {
	return suppressByContext(data, raw, true, benignAt)
}

func traceContextSuppressed(data []byte, raw string, benignAt func(data []byte, start int) bool) bool {
	return suppressByContext(data, raw, false, benignAt)
}

func isChecksumRowAt(data []byte, start, n int) bool {
	off := start + n
	if off > len(data) {
		return false
	}
	rest := data[off:]
	spaces := 0
	for spaces < len(rest) && (rest[spaces] == ' ' || rest[spaces] == '\t') {
		spaces++
	}
	if spaces == 0 {
		return false
	}
	rest = rest[spaces:]
	if len(rest) > 0 && rest[0] == '*' {
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && rest[end] != ' ' && rest[end] != '\t' && rest[end] != '\n' && rest[end] != '\r' {
		end++
	}
	token := rest[:end]
	return len(token) > 0 && (bytes.IndexByte(token, '/') >= 0 || bytes.IndexByte(token, '.') >= 0)
}

func hexInTraceContextAt(data []byte, start int, raw string) bool {
	lo := start - hexIDContextWindow
	if lo < 0 {
		lo = 0
	}
	if classify.IsHexIDInContext(raw, string(data[lo:start])) {
		return true
	}
	end := start + len(raw)
	return start > 0 && end < len(data) && data[start-1] == '-' && data[end] == '-' &&
		hexChainNeighbor(data, start-1, -1) && hexChainNeighbor(data, end, +1)
}

func isAlnumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexChainNeighbor(data []byte, dashPos, dir int) bool {
	i := dashPos + dir
	n := 0
	for i >= 0 && i < len(data) && isHexByte(data[i]) {
		n++
		i += dir
	}
	if n == 0 {
		return false
	}
	if i >= 0 && i < len(data) {
		c := data[i]
		if (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z') || c == '_' {
			return false
		}
	}
	return true
}

func (s *scanner) applySuppression(ctx context.Context, in []analyzeResult, data []byte) []analyzeResult {
	if s.mode == suppressionOff && s.vendorMode == suppressionOff {
		return in
	}
	var shapes map[string]int
	if s.mode != suppressionOff {
		shapes = documentShapes(data)
	}
	kept := make([]analyzeResult, 0, len(in))
	counts := map[string]int{}
	for _, f := range in {
		suppress, reason, mode := s.decideAny(f, shapes, data)
		if !suppress {
			kept = append(kept, f)
			continue
		}
		findingsSuppressedTotal.WithLabelValues(reason, f.EntityType, mode.String()).Inc()
		counts[reason]++
		if mode == suppressionShadow {
			kept = append(kept, f)
		}
	}
	if len(counts) > 0 {
		total, summary := summarizeCounts(counts)
		log.Printf("scan suppressed req=%s fp_mode=%s vendor_mode=%s total=%d reasons=%s", reqIDFrom(ctx), s.mode, s.vendorMode, total, summary)
	}
	return kept
}

func (s *scanner) decideAny(f analyzeResult, shapes map[string]int, data []byte) (bool, string, suppressionMode) {
	if s.mode != suppressionOff {
		if suppress, reason := decideSuppression(f, shapes, data); suppress {
			return true, reason, s.mode
		}
	}
	if s.vendorMode != suppressionOff && !isGenericDetectorName(f.EntityType) {
		if isCuratedVendor(f.EntityType) {
			vendorFindingsEvaluatedTotal.WithLabelValues(f.EntityType, s.vendorMode.String()).Inc()
		}
		if suppress, reason := decideVendorSuppression(f, data); suppress {
			return true, reason, s.vendorMode
		}
	}
	return false, "", suppressionOff
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
