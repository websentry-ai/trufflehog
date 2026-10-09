package newrelicmobileapptoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// A token is 42 characters plus "-NRMA". US tokens are AA and 40 hex; other
	// regions put their code before a run of x's (eu01xx, jpxx, gov66xx), the way
	// the mobile agents parse it. The length is checked in FromData.
	keyPat = regexp.MustCompile(`\b((AA[0-9a-f]{40}|[a-z]{2,4}[0-9]{0,2}x{1,2}[0-9a-f]{30,40})-NRMA)\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"-nrma"} }

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicMobileAppToken
}

func (s Scanner) Description() string {
	return "A New Relic Mobile App Token is an authentication key used to send mobile application telemetry data (such as performance metrics, crashes, and events) from iOS and Android apps to New Relic for monitoring and analysis. It is specific to each mobile app and ensures secure data ingestion."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		if len(resMatch) != 42+len("-NRMA") {
			continue
		}

		region := "us"
		if !strings.HasPrefix(resMatch, "AA") {
			region = resMatch[:strings.IndexByte(resMatch, 'x')]
			if region == "eu01" {
				region = "eu"
			}
		}

		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(resMatch),
			Redacted:     resMatch[:8] + "...",
			SecretParts:  map[string]string{"key": resMatch, "region": region},
			ExtraData:    map[string]string{"region": region},
		}

		// Only the US and EU collectors are known, so other regions stay unverified.
		if verify && (region == "us" || region == "eu") {
			isVerified, verificationErr := s.verify(ctx, resMatch, s1.SecretParts["region"])
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verify checks if the provided key is valid by making a request to the New Relic Android Agent internal API.
// A POST request is made to the /mobile/v5/connect endpoint. If the response status code is 400,
// it indicates that the key is valid but the request is malformed (since we're not sending a proper payload),
// while a 401 status code indicates that the key is invalid. Any other status code is treated as an error.
// This API is not documented, and was discovered by digging into New Relic's Android agent SDK code:
// https://github.com/newrelic/newrelic-android-agent
func (s Scanner) verify(ctx context.Context, key, region string) (bool, error) {
	host := "https://mobile-collector.newrelic.com"

	if region == "eu" {
		// EU region keys have a different host
		host = "https://mobile-collector.eu01.nr-data.net"
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, host+"/mobile/v5/connect", http.NoBody)
	if err != nil {
		return false, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-App-License-Key", key)

	client := s.getClient()
	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusBadRequest:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
