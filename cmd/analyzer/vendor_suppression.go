package main

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
	reasonVendorStructuralDigest     = "vendor_structural_digest"
	reasonVendorStructuralEmbedded   = "vendor_structural_embedded"
)

const digestContextWindow = 16

type vendorRule struct {
	match  func(string) bool
	reason string
}

var vendorStructuralRules = map[string]vendorRule{
	"JiraToken": {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Atlassian": {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Azure":     {match: classify.IsCodeLike, reason: reasonVendorStructuralCode},
	"JDBC":      {match: classify.IsNonSecretConnString, reason: reasonVendorStructuralConnString},
}

func isCuratedVendor(entity string) bool {
	if entity == "FastlyPersonalToken" {
		return true
	}
	_, ok := vendorStructuralRules[entity]
	return ok
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func decideVendorSuppression(f analyzeResult, data []byte) (bool, string) {
	if contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		lo := s - digestContextWindow
		if lo < 0 {
			lo = 0
		}
		return classify.IsHexDigestInContext(f.raw, string(d[lo:s]))
	}) {
		return true, reasonVendorStructuralDigest
	}
	if f.EntityType == "FastlyPersonalToken" && contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		n := len(f.raw)
		left := s > 0 && isIdentByte(d[s-1])
		right := s+n < len(d) && isIdentByte(d[s+n])
		return left || right
	}) {
		return true, reasonVendorStructuralEmbedded
	}
	rule, ok := vendorStructuralRules[f.EntityType]
	if !ok {
		return false, ""
	}
	if rule.match(f.raw) {
		return true, rule.reason
	}
	return false, ""
}
