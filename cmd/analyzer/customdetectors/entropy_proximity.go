package customdetectors

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const EntropyName = "entropy-secret"

const (
	defaultEntropyThreshold = 3.0
	entropyMinLen           = 16
	entropyMaxLen           = 80
	entropyWindow           = 5
	entropyCancelStride     = 64
)

var keywordStems = []string{
	"password", "passwd", "pwd", "secret", "token", "credential",
	"auth", "apikey", "api_key", "signing", "key", "cert",
}

var entropyPlaceholderWords = []string{"example", "redacted", "xxxx", "do-not-use", "do_not_use", "changeme", "placeholder"}

var maskPatterns = []string{
	`^[\*x•]+$`,
	`^[A-Za-z]{1,4}-?x{8,}$`,
	`^.{0,4}(x{8,}|\*{8,}|0{8,}|\.{8,})$`,
}

var (
	entropyTrimCutset = "\"'`.,;:()[]{}<>"

	uuidPat     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexHashPat  = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	decimalPat  = regexp.MustCompile(`^[0-9][0-9.\-]*$`)
	hostPathPat = regexp.MustCompile(`^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(/.*)?$`)
	datetimePat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}`)
	schemePat   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)
	maskPat     = regexp.MustCompile(strings.Join(maskPatterns, "|"))
)

func isSecretAlphabet(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '+' || r == '/' || r == '=' || r == '~' || r == '@':
		default:
			return false
		}
	}
	return true
}

func hasPlaceholderWord(lower string) bool {
	for _, w := range entropyPlaceholderWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

type entropyProximityDetector struct {
	threshold float64
}

var _ detectors.Detector = (*entropyProximityDetector)(nil)

func NewEntropyProximity(threshold float64) detectors.Detector {
	return entropyProximityDetector{threshold: threshold}
}

func (d entropyProximityDetector) Keywords() []string {
	return []string{
		"password", "passwd", "pwd", "secret", "token", "credential",
		"apikey", "api_key", "auth", "signing", "private_key", "access_key",
	}
}

func (d entropyProximityDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (d entropyProximityDetector) Description() string {
	return "Heuristic detector for high-entropy secrets located near a credential keyword."
}

type entropyToken struct {
	candidate        string
	keyword          string
	keywordFromIdent bool
}

func (d entropyProximityDetector) FromData(ctx context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	tokens := tokenize(string(data))
	var results []detectors.Result

	for i, tok := range tokens {
		if i%entropyCancelStride == 0 {
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}

		v := tok.candidate
		if len(v) < entropyMinLen || len(v) > entropyMaxLen {
			continue
		}
		if !isSecretAlphabet(v) {
			continue
		}
		if !hasLetterAndDigit(v) {
			continue
		}
		if detectors.StringShannonEntropy(v) < d.threshold {
			continue
		}
		if isExcludedEntropyValue(v) || hasPlaceholderWord(strings.ToLower(v)) {
			continue
		}
		if !hasNearbyKeyword(tokens, i) {
			continue
		}

		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: EntropyName,
			Raw:          []byte(v),
		})
	}

	return results, nil
}

var identPrefixPat = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*[=:]`)

func tokenize(data string) []entropyToken {
	fields := strings.Fields(data)
	tokens := make([]entropyToken, 0, len(fields))
	for _, f := range fields {
		core := strings.Trim(f, entropyTrimCutset)
		if core == "" {
			continue
		}
		candidate, keyword := core, core
		var keywordFromIdent bool
		if loc := identPrefixPat.FindStringIndex(core); loc != nil {
			candidate = core[loc[1]:]
			keyword = core[:loc[1]]
			keywordFromIdent = true
		}
		tokens = append(tokens, entropyToken{
			candidate:        candidate,
			keyword:          strings.ToLower(keyword),
			keywordFromIdent: keywordFromIdent,
		})
	}
	return tokens
}

func hasNearbyKeyword(tokens []entropyToken, idx int) bool {
	lo := idx - entropyWindow
	if lo < 0 {
		lo = 0
	}
	hi := idx + entropyWindow
	if hi >= len(tokens) {
		hi = len(tokens) - 1
	}
	for j := lo; j <= hi; j++ {
		if j == idx && !tokens[j].keywordFromIdent {
			continue
		}
		neighbor := reduceToAlnumUnderscore(tokens[j].keyword)
		for _, stem := range keywordStems {
			if strings.Contains(neighbor, stem) {
				return true
			}
		}
	}
	return false
}

func isExcludedEntropyValue(v string) bool {
	return uuidPat.MatchString(v) ||
		hexHashPat.MatchString(v) ||
		decimalPat.MatchString(v) ||
		hostPathPat.MatchString(v) ||
		datetimePat.MatchString(v) ||
		schemePat.MatchString(v) ||
		maskPat.MatchString(v)
}

func hasLetterAndDigit(s string) bool {
	var letter, digit bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letter = true
		}
		if letter && digit {
			return true
		}
	}
	return false
}

func reduceToAlnumUnderscore(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ParseEntropyThreshold(raw string) (float64, error) {
	if raw == "" {
		return defaultEntropyThreshold, nil
	}
	threshold, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0.0 || threshold > 8.0 {
		return 0, fmt.Errorf("threshold %q out of range (0, 8]", raw)
	}
	return threshold, nil
}
