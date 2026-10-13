package customdetectors

import (
	"bytes"
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const EmailTokenLoginName = "email-token-login"

// An API-token login of the form "<agent email>/token:<40 alphanumerics>".
// The whole login is reported, so the address inside it is read as part of the
// credential rather than as an email of its own.
var emailTokenLoginRegex = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/token:[A-Za-z0-9]{40}\b`)

type emailTokenLoginDetector struct{}

func NewEmailTokenLogin() detectors.Detector { return emailTokenLoginDetector{} }

func (emailTokenLoginDetector) Keywords() []string { return []string{"/token:"} }

func (emailTokenLoginDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (emailTokenLoginDetector) Version() int { return 2 }

func (emailTokenLoginDetector) GetName() string { return EmailTokenLoginName }

func (emailTokenLoginDetector) Description() string {
	return "API token in its email/token login form."
}

func (emailTokenLoginDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range emailTokenLoginRegex.FindAllIndex(data, -1) {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: EmailTokenLoginName,
			Raw:          bytes.Clone(data[m[0]:m[1]]),
			SecretParts:  emailTokenSecretParts(data[m[0]:m[1]]),
		}
		r.SetChunkOffset(int64(m[0]))
		results = append(results, r)
	}
	return results, nil
}

func emailTokenSecretParts(login []byte) map[string]string {
	email, token, _ := bytes.Cut(login, []byte("/token:"))
	return map[string]string{"email": string(email), "token": string(token)}
}
