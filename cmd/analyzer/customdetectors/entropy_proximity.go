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
	entropyMinLen       = 16
	entropyMaxLen       = 128
	entropyWindow       = 5
	entropyCancelStride = 64
)

var keywordStems = classify.KeywordStems()

var counterParams = map[string]struct{}{
	"max_tokens":                  {},
	"max_completion_tokens":       {},
	"max_output_tokens":           {},
	"prompt_tokens":               {},
	"completion_tokens":           {},
	"input_tokens":                {},
	"output_tokens":               {},
	"total_tokens":                {},
	"cached_tokens":               {},
	"reasoning_tokens":            {},
	"cache_read_input_tokens":     {},
	"cache_creation_input_tokens": {},
	"prompt_token_count":          {},
	"candidates_token_count":      {},
	"total_token_count":           {},
	"maxtokens":                   {},
	"maxcompletiontokens":         {},
	"maxoutputtokens":             {},
	"prompttokens":                {},
	"completiontokens":            {},
	"inputtokens":                 {},
	"outputtokens":                {},
	"totaltokens":                 {},
}

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
		words, score := nearbyKeywords(tokens, i)
		if len(words) == 0 {
			continue
		}
		if isHexString(v) && nearHashLabel(tokens, i, len(v)) {
			continue
		}

		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: EntropyName,
			Raw:          []byte(v),
			ExtraData: map[string]string{
				"support_words":   strings.Join(words, ","),
				"proximity_score": strconv.FormatFloat(score, 'f', 2, 64),
			},
		})
	}

	return results, nil
}

func hasNearbyKeyword(tokens []tokenizer.Token, idx int) bool {
	words, _ := nearbyKeywords(tokens, idx)
	return len(words) > 0
}

func nearbyKeywords(tokens []tokenizer.Token, idx int) ([]string, float64) {
	lo := idx - entropyWindow
	if lo < 0 {
		lo = 0
	}
	hi := idx + entropyWindow
	if hi >= len(tokens) {
		hi = len(tokens) - 1
	}
	var words []string
	var score float64
	seen := make(map[string]struct{})
	for j := lo; j <= hi; j++ {
		if j == idx && !tokens[j].KeywordFromIdent {
			continue
		}
		neighbor := reduceToAlnumUnderscore(strings.ToLower(tokens[j].Keyword))
		if _, denied := counterParams[neighbor]; denied {
			continue
		}
		stem := matchingStem(neighbor)
		if stem == "" {
			continue
		}
		if w := proximityWeight(idx, j); w > score {
			score = w
		}
		if _, ok := seen[stem]; !ok {
			seen[stem] = struct{}{}
			words = append(words, stem)
		}
	}
	return words, score
}

func matchingStem(neighbor string) string {
	for _, stem := range keywordStems {
		if strings.Contains(neighbor, stem) {
			return stem
		}
	}
	return ""
}

func proximityWeight(idx, j int) float64 {
	d := idx - j
	if d < 0 {
		d = -d
	}
	return 1.0 / float64(1+d)
}

var hashLabelStems = []string{
	"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3",
	"blake2", "blake3", "ripemd", "crc32", "digest", "checksum",
	"etag", "integrity", "fingerprint",
}

var fixedHashHexLen = map[string]int{
	"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128, "ripemd": 40,
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func nearHashLabel(tokens []tokenizer.Token, idx, hexLen int) bool {
	lo := idx - entropyWindow
	if lo < 0 {
		lo = 0
	}
	for j := lo; j <= idx; j++ {
		neighbor := reduceToAlnumUnderscore(strings.ToLower(tokens[j].Keyword))
		for _, stem := range hashLabelStems {
			if !strings.Contains(neighbor, stem) {
				continue
			}
			if want, fixed := fixedHashHexLen[stem]; !fixed || want == hexLen {
				return true
			}
		}
	}
	return false
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
