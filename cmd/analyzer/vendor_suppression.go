package main

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

const (
	reasonVendorStructuralUUID  = "vendor_structural_uuid"
	reasonVendorStructuralAzure = "vendor_structural_azure"
)

type vendorRule struct {
	match  func(string) bool
	reason string
}

var vendorStructuralRules = map[string]vendorRule{
	"JiraToken": {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Atlassian": {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID},
	"Azure":     {match: classify.HasNonAzureSecretChar, reason: reasonVendorStructuralAzure},
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
