package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const DBConnectionURIName = "db-connection-uri"

func NewDBConnectionURI() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name: DBConnectionURIName,
		Keywords: []string{
			"mysql", "mariadb", "redis", "postgres", "postgresql", "mongodb", "amqp",
		},
		Regex: map[string]string{
			"secret": `(?i)\b(?:mysql|mariadb|rediss?|postgres(?:ql)?|mongodb(?:\+srv)?|amqps?)://[^:@/\s]*:([^@/\s]{1,256})@`,
		},
		ExcludeRegexesCapture: append([]string{
			`^\$\{.*\}$`,
			`^\$[A-Za-z_][A-Za-z0-9_]*$`,
			`^\{\{.*\}\}$`,
			`^<.*>$`,
		}, maskPatterns...),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}
