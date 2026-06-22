package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const GenericSecretName = "generic-secret"

func NewGenericSecret() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name: GenericSecretName,
		Keywords: []string{
			"password", "passwd", "pwd", "secret",
			"token", "credential", "apikey", "api_key", "auth",
		},
		Regex: map[string]string{
			"secret": `(?i)(?:password|passwd|pwd|secret(?:[_-]?key)?|api[_-]?key|auth(?:[_-]?token)?|access[_-]?token|token|credential)["'\]]*\s*[:=]\s*["']?([A-Za-z0-9._\-+/=~@]{4,64})`,
		},
		ExcludeWords: []string{
			"changeme", "change_me", "example", "redacted",
			"placeholder", "your_password", "yourpassword", "dummy", "sample",
			"xxxx", "your_token", "oauth",
		},
		ExcludeRegexesCapture: append([]string{
			`^\$\{.*\}$`,
			`^\$[A-Za-z_][A-Za-z0-9_]*$`,
			`^\$\(.*\)$`,
			`^\{\{.*\}\}$`,
			`^<.*>$`,
			`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`,
			`@[^/]+/.+`,
			`(?i)\.(git|com|net|org|io)$`,
			`^(?i)(true|false|none|null|undefined|nil)$`,
			`^[0-9][0-9.\-]*$`,
		}, maskPatterns...),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}
