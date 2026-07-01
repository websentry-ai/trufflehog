package main

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
	reasonVendorStructuralDigest     = "vendor_structural_digest"
	reasonVendorStructuralWordy      = "vendor_structural_wordy"
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
	"FastlyPersonalToken": {match: classify.IsDashedLowercasePhrase, reason: reasonVendorStructuralWordy},
}

func isCuratedVendor(entity string) bool {
	_, ok := vendorStructuralRules[entity]
	return ok
}

func decideVendorSuppression(f analyzeResult, data []byte) (bool, string) {
	// Require the digest label at EVERY occurrence of the value, so a crafted
	// earlier duplicate next to a digest label cannot suppress a later real secret.
	if contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		lo := s - digestContextWindow
		if lo < 0 {
			lo = 0
		}
		return classify.IsHexDigestInContext(f.raw, string(d[lo:s]))
	}) {
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
