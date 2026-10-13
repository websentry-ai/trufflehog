package customdetectors

import (
	"bytes"
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const ZendeskAPITokenName = "zendesk-api-token"

// Zendesk's documented API-token login is "<agent email>/token:<40 alphanumerics>".
// The whole login is reported, so the address inside it is read as part of the
// credential rather than as an email of its own.
var zendeskTokenRegex = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/token:[A-Za-z0-9]{40}\b`)

type zendeskAPITokenDetector struct{}

func NewZendeskAPIToken() detectors.Detector { return zendeskAPITokenDetector{} }

func (zendeskAPITokenDetector) Keywords() []string { return []string{"/token:"} }

func (zendeskAPITokenDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (zendeskAPITokenDetector) Version() int { return 2 }

func (zendeskAPITokenDetector) GetName() string { return ZendeskAPITokenName }

func (zendeskAPITokenDetector) Description() string {
	return "Zendesk API token in its email/token login form."
}

func (zendeskAPITokenDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range zendeskTokenRegex.FindAllIndex(data, -1) {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: ZendeskAPITokenName,
			Raw:          bytes.Clone(data[m[0]:m[1]]),
		}
		r.SetChunkOffset(int64(m[0]))
		results = append(results, r)
	}
	return results, nil
}
