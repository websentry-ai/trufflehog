package customdetectors

import (
	"bytes"
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const StrongLabelSecretName = "strong-label-secret"

// "salt `Xk9$...`", "the DB password is `...`", "secret: '...'": a strong secret word, an
// optional ":", "=" or "is", then one whitespace-free value inside backticks or quotes.
// key/token are left out on purpose; they precede code names constantly.
var strongLabelRegex = regexp.MustCompile("(?i)\\b(password|passwd|pwd|passphrase|secret|salt)\\b[ \\t]*(?:[:=]|\\bis\\b)?[ \\t]*[`'\"]([^`'\"\\s]{6,64})[`'\"]")

var (
	nameShapedPat  = regexp.MustCompile(`^[A-Za-z][A-Za-z._/-]*$`)
	capsEnvNamePat = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	strongExcludes = compileAll(append(classify.EnvRefPatterns(), classify.MaskPatterns()...)...)
)

func compileAll(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

type strongLabelSecretDetector struct{}

func NewStrongLabelSecret() detectors.Detector { return strongLabelSecretDetector{} }

func (strongLabelSecretDetector) Keywords() []string {
	return []string{"password", "passwd", "pwd", "passphrase", "secret", "salt"}
}

func (strongLabelSecretDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

// Keep version 3: type+version form the detector key, and 0 would collide with the entropy detector.
func (strongLabelSecretDetector) Version() int { return 3 }

func (strongLabelSecretDetector) Description() string {
	return "Quoted value directly after a strong secret word (password, secret, salt, ...)."
}

func (strongLabelSecretDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, m := range strongLabelRegex.FindAllSubmatchIndex(data, -1) {
		// A label that is itself quoted (`password` field) is a code name, not a label.
		if m[0] > 0 && bytes.IndexByte([]byte("`'\""), data[m[0]-1]) >= 0 {
			continue
		}
		v := string(data[m[4]:m[5]])
		if !isStrongLabelValue(v) {
			continue
		}
		// "secret `name`" usually names a k8s/vault secret; only a digit or symbol makes it a value.
		if strings.EqualFold(string(data[m[2]:m[3]]), "secret") && nameShapedPat.MatchString(v) {
			continue
		}
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: StrongLabelSecretName,
			Raw:          []byte(v),
		}
		r.SetChunkOffset(int64(m[4]))
		results = append(results, r)
	}
	return results, nil
}

func isStrongLabelValue(v string) bool {
	hasDigitOrSymbol := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			hasDigitOrSymbol = true
			break
		}
	}
	if !hasDigitOrSymbol || capsEnvNamePat.MatchString(v) {
		return false
	}
	if classify.IsPlaceholderPassword(v) || classify.ContainsEntropyPlaceholder(strings.ToLower(v)) {
		return false
	}
	for _, re := range strongExcludes {
		if re.MatchString(v) {
			return false
		}
	}
	return !classify.IsExcludedEntropyValueInContext(v, true)
}
