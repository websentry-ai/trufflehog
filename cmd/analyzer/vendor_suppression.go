package main

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
	reasonVendorStructuralDigest     = "vendor_structural_digest"
)

const digestContextWindow = 16

type vendorRule struct {
	match  func(string) bool
	reason string
}

var vendorStructuralRules = map[string]vendorRule{
	"JiraToken":           {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Atlassian":           {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Azure":               {match: classify.IsCodeLike, reason: reasonVendorStructuralCode},
	"JDBC":                {match: classify.IsNonSecretConnString, reason: reasonVendorStructuralConnString},
	"FastlyPersonalToken": {match: classify.ContainsNonAlphanumeric, reason: reasonVendorStructuralCode},
}

func isCuratedVendor(entity string) bool {
	_, ok := vendorStructuralRules[entity]
	return ok
}

func decideVendorSuppression(f analyzeResult, data []byte) (bool, string) {
	if classify.IsHexDigestInContext(f.raw, precedingContext(data, f, digestContextWindow)) {
		return true, reasonVendorStructuralDigest
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

func precedingContext(data []byte, f analyzeResult, n int) string {
	start := runeToByteOffset(data, f.Start)
	if start <= 0 {
		return ""
	}
	lo := start - n
	if lo < 0 {
		lo = 0
	}
	return string(data[lo:start])
}
