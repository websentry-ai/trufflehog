package customdetectors

import "github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"

func IsStripeObjectID(s string) bool {
	return classify.IsStripeObjectID(s)
}
