package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
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
			"secret": `(?i)\b(?:mysql|mariadb|rediss?|postgres(?:ql)?|mongodb(?:\+srv)?|amqps?)://[^:@/\s]*:([^@/\s]{6,256})@`,
		},
		ExcludeRegexesCapture: dbConnectionURIExcludeRegexes(),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}

func dbConnectionURIExcludeRegexes() []string {
	out := []string{
		`^\$\{.*\}$`,
		`^\$[A-Za-z_][A-Za-z0-9_]*$`,
		`^\{\{.*\}\}$`,
		`^<.*>$`,
	}
	return append(out, classify.MaskPatterns()...)
}
