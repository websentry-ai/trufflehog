package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const GenericSecretName = "generic-secret"

func NewGenericSecret() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name:     GenericSecretName,
		Keywords: classify.Keywords(),
		Regex: map[string]string{
			"secret": `(?i)(?:password|passwd|pwd|secret(?:[_-]?key)?|api[_-]?key|auth(?:[_-]?token)?|access[_-]?token|token|credential)["'\]]*\s*[:=]\s*["']?([A-Za-z0-9._\-+/=~@]{4,64})`,
		},
		ExcludeWords:          classify.ExcludeWords(),
		ExcludeRegexesCapture: genericSecretExcludeRegexes(),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}

func genericSecretExcludeRegexes() []string {
	out := classify.EnvRefPatterns()
	out = append(out,
		`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`,
		`@[^/]+/.+`,
		`(?i)\.(git|com|net|org|io)$`,
		`^(?i)(true|false|none|null|undefined|nil)$`,
		`^[0-9][0-9.\-]*$`,
	)
	return append(out, classify.MaskPatterns()...)
}
