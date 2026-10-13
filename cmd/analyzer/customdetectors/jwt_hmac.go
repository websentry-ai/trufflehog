package customdetectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// JWTName matches the upstream JWT detector, so a token reads the same whichever
// detector found it.
const JWTName = "JWT"

var jwtRegex = regexp.MustCompile(`\b(?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{12,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{12,}={0,2}\.[A-Za-z0-9_-]{12,}\b`)

// The upstream JWT detector skips HMAC-signed tokens because it cannot verify
// them. This one reports them, since a bearer token is a credential whether or
// not its signature can be checked. Expired tokens are left out.
type jwtHMACDetector struct{ now func() time.Time }

func NewJWTHMAC() detectors.Detector { return jwtHMACDetector{now: time.Now} }

func (jwtHMACDetector) Keywords() []string { return []string{"eyJ", "ewogIC", "ewoid"} }

func (jwtHMACDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (jwtHMACDetector) Version() int { return 3 }

func (jwtHMACDetector) GetName() string { return JWTName }

func (jwtHMACDetector) Description() string { return "HMAC-signed JSON Web Token." }

func (d jwtHMACDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range jwtRegex.FindAllIndex(data, -1) {
		tok := data[m[0]:m[1]]
		if !d.liveHMAC(tok) {
			continue
		}
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: JWTName,
			Raw:          bytes.Clone(tok),
		}
		r.SetChunkOffset(int64(m[0]))
		results = append(results, r)
	}
	return results, nil
}

func (d jwtHMACDetector) liveHMAC(tok []byte) bool {
	parts := bytes.Split(tok, []byte("."))
	if len(parts) != 3 {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if !decodeSegment(parts[0], &header) {
		return false
	}
	switch header.Alg {
	case "HS256", "HS384", "HS512":
	default:
		return false
	}
	var claims struct {
		Exp *float64 `json:"exp"`
	}
	if !decodeSegment(parts[1], &claims) {
		return false
	}
	if claims.Exp != nil && time.Unix(int64(*claims.Exp), 0).Before(d.now()) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(parts[2], "=")))
	return err == nil && len(sig) >= 32
}

func decodeSegment(seg []byte, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(seg, "=")))
	return err == nil && json.Unmarshal(raw, v) == nil
}
