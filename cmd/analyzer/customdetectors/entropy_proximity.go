package customdetectors

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors/tokenizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const EntropyName = "entropy-secret"

const DefaultEntropyThreshold = 3.0

const (
	entropyMinLen           = 16
	entropyMaxLen           = 128
	entropyWindow           = 5
	entropyCancelStride     = 64
)

var keywordStems = classify.KeywordStems()

type entropyProximityDetector struct {
	threshold float64
	tok       tokenizer.Tokenizer
}

var _ detectors.Detector = (*entropyProximityDetector)(nil)

func NewEntropyProximity(threshold float64) detectors.Detector {
	return entropyProximityDetector{threshold: threshold, tok: whitespaceTokenizer()}
}

func NewEntropyProximityWithTokenizer(threshold float64, tok tokenizer.Tokenizer) detectors.Detector {
	return entropyProximityDetector{threshold: threshold, tok: tok}
}

func whitespaceTokenizer() tokenizer.Tokenizer {
	tok, err := tokenizer.Select(tokenizer.Whitespace)
	if err != nil {
		panic("entropy-proximity: whitespace tokenizer unavailable: " + err.Error())
	}
	return tok
}

func (d entropyProximityDetector) Keywords() []string {
	return []string{
		"password", "passwd", "pwd", "secret", "token", "credential",
		"auth", "signing", "key", "cert",
	}
}

func (d entropyProximityDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (d entropyProximityDetector) Description() string {
	return "Heuristic detector for high-entropy secrets located near a credential keyword."
}

func (d entropyProximityDetector) FromData(ctx context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	tokens := d.tok.Tokenize(ctx, string(data))
	var results []detectors.Result

	for i, tok := range tokens {
		if i%entropyCancelStride == 0 {
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}

		v := tok.Candidate
		if len(v) < entropyMinLen || len(v) > entropyMaxLen {
			continue
		}
		if !classify.IsSecretAlphabet(v) {
			continue
		}
		if !hasLetterAndDigit(v) {
			continue
		}
		if classify.ShannonEntropy(v) < d.threshold {
			continue
		}
		if classify.IsExcludedEntropyValue(v) || classify.ContainsEntropyPlaceholder(strings.ToLower(v)) {
			continue
		}
		if classify.IsKnownFalsePositive(v) {
			continue
		}
		words := nearbyKeywords(tokens, i)
		if len(words) == 0 {
			continue
		}

		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: EntropyName,
			Raw:          []byte(v),
			ExtraData:    map[string]string{"support_words": strings.Join(words, ",")},
		})
	}

	return results, nil
}

func hasNearbyKeyword(tokens []tokenizer.Token, idx int) bool {
	return len(nearbyKeywords(tokens, idx)) > 0
}

func nearbyKeywords(tokens []tokenizer.Token, idx int) []string {
	lo := idx - entropyWindow
	if lo < 0 {
		lo = 0
	}
	hi := idx + entropyWindow
	if hi >= len(tokens) {
		hi = len(tokens) - 1
	}
	var words []string
	seen := make(map[string]struct{})
	for j := lo; j <= hi; j++ {
		if j == idx && !tokens[j].KeywordFromIdent {
			continue
		}
		neighbor := reduceToAlnumUnderscore(tokens[j].Keyword)
		for _, stem := range keywordStems {
			if strings.Contains(neighbor, stem) {
				if _, ok := seen[stem]; !ok {
					seen[stem] = struct{}{}
					words = append(words, stem)
				}
				break
			}
		}
	}
	return words
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
		return DefaultEntropyThreshold, nil
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
