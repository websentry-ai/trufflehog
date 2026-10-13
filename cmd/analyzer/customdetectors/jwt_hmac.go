package customdetectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// JWTName matches the upstream JWT detector, so a token reads the same whichever
// detector found it.
const JWTName = "JWT"

// Each JSON segment starts with "{" and then a quote, whitespace or "}", which
// base64 writes as "e" followed by w, y or 3; the header and signature checks
// below keep the match strict. A signature can end in '-', which \b cannot
// follow, so the token ends at a non-token byte instead.
var jwtRegex = regexp.MustCompile(`\b(e[wy][A-Za-z0-9_-]{12,}={0,2}\.e[wy3][A-Za-z0-9_-]*={0,2}\.[A-Za-z0-9_-]{12,}={0,2})(?:[^A-Za-z0-9_=-]|\z)`)

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

// MaxSecretSize puts the detector in the whole-request pass, so a token with a
// large claim set is not cut in two by a window boundary.
func (jwtHMACDetector) MaxSecretSize() int64 { return 8192 }

func (d jwtHMACDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range jwtRegex.FindAllSubmatchIndex(data, -1) {
		tok := data[m[2]:m[3]]
		if !d.liveHMAC(tok) {
			continue
		}
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: JWTName,
			Raw:          bytes.Clone(tok),
			SecretParts:  map[string]string{"key": string(tok)},
		}
		r.SetChunkOffset(int64(m[2]))
		results = append(results, r)
	}
	return results, nil
}

func (d jwtHMACDetector) liveHMAC(tok []byte) bool {
	parts := bytes.Split(tok, []byte("."))
	if len(parts) != 3 {
		return false
	}
	// Maps, not structs: JSON claim names are case-sensitive, and struct decoding
	// would let a custom "EXP" or "ALG" stand in for "exp" or "alg".
	var header, claims map[string]json.RawMessage
	if !decodeSegment(parts[0], &header) || !decodeSegment(parts[1], &claims) {
		return false
	}
	var alg string
	if json.Unmarshal(header["alg"], &alg) != nil {
		return false
	}
	switch alg {
	case "HS256", "HS384", "HS512":
	default:
		return false
	}
	// Issuers write exp as a number or a numeric string; any other shape cannot
	// show the token expired, so it is still reported.
	if exp, err := strconv.ParseFloat(strings.Trim(string(claims["exp"]), `"`), 64); err == nil &&
		time.Unix(int64(exp), 0).Before(d.now()) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(parts[2], "=")))
	return err == nil && len(sig) >= 32
}

func decodeSegment(seg []byte, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(seg, "=")))
	return err == nil && json.Unmarshal(raw, v) == nil
}
