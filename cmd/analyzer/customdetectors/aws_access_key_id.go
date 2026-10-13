package customdetectors

import (
	"bytes"
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const AWSAccessKeyIDName = "aws-access-key-id"

// A long-term AWS access key ID on its own. It cannot authenticate without its
// secret, but it names the account and usually travels with that secret, so it
// is reported. Temporary ASIA IDs are left out: every CloudTrail event has one.
var awsAccessKeyIDRegex = regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)

type awsAccessKeyIDDetector struct{}

func NewAWSAccessKeyID() detectors.Detector { return awsAccessKeyIDDetector{} }

func (awsAccessKeyIDDetector) Keywords() []string { return []string{"AKIA"} }

func (awsAccessKeyIDDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (awsAccessKeyIDDetector) Version() int { return 4 }

func (awsAccessKeyIDDetector) GetName() string { return AWSAccessKeyIDName }

func (awsAccessKeyIDDetector) Description() string {
	return "Long-term AWS access key ID, with or without its secret."
}

func (awsAccessKeyIDDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range awsAccessKeyIDRegex.FindAllIndex(data, -1) {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: AWSAccessKeyIDName,
			Raw:          bytes.Clone(data[m[0]:m[1]]),
			SecretParts:  map[string]string{"key_id": string(data[m[0]:m[1]])},
		}
		r.SetChunkOffset(int64(m[0]))
		results = append(results, r)
	}
	return results, nil
}
