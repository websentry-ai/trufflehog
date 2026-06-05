package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const PrivateKeyName = "private-key-block"

func NewPrivateKey() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name:     PrivateKeyName,
		Keywords: []string{"private key"},
		Regex: map[string]string{
			"secret": `(?i)(-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]+?-----END[A-Z0-9 ]{0,40}PRIVATE KEY-----)`,
		},
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}
