package main

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
)

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
	_, ok := vendorStructuralRules[entity]
	return ok
}

func decideVendorSuppression(f analyzeResult) (bool, string) {
	rule, ok := vendorStructuralRules[f.EntityType]
	if !ok {
		return false, ""
	}
	if rule.match(f.raw) {
		return true, rule.reason
	}
	return false, ""
}
