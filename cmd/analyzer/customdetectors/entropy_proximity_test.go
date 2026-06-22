package customdetectors

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors/tokenizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func runEntropyDetector(t *testing.T, input string) []detectors.Result {
	t.Helper()
	d := NewEntropyProximity(DefaultEntropyThreshold)
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	data := []byte(input)

	matches := core.FindDetectorMatches(data)
	if len(matches) == 0 {
		return nil
	}

	var results []detectors.Result
	for _, match := range matches {
		found, err := match.FromData(context.Background(), false, data)
		require.NoError(t, err)
		results = append(results, found...)
	}
	return results
}

func filterByName(results []detectors.Result, name string) []detectors.Result {
	var out []detectors.Result
	for _, r := range results {
		if r.DetectorName == name {
			out = append(out, r)
		}
	}
	return out
}

func TestEntropyProximityDetector_ImplementsDetectorInterface(t *testing.T) {
	d := NewEntropyProximity(DefaultEntropyThreshold)
	require.NotEmpty(t, d.Keywords(), "Keywords() must return a non-empty slice")
}

func TestEntropyProximity_Positive_KeywordInline(t *testing.T) {
	input := `rotate this secret: aB3xKp9Qm2Lr7TzWqDv`
	data := []byte(input)
	want := []byte("aB3xKp9Qm2Lr7TzWqDv")

	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.NotEmpty(t, results, "expected an entropy-secret finding near 'secret:'; got zero")

	var found bool
	for _, r := range results {
		if bytes.Equal(r.Raw, want) {
			found = true
			require.GreaterOrEqual(t, bytes.Index(data, r.Raw), 0,
				"Raw %q must be locatable in input via bytes.Index", string(r.Raw))
		}
	}
	require.True(t, found, "expected Raw == %q; got: %v", string(want), entropyRawStrings(results))
}

func TestEntropyProximity_Positive_DetectorName(t *testing.T) {
	input := `rotate this secret: aB3xKp9Qm2Lr7TzWqDv`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.NotEmpty(t, results, "need at least one result to check DetectorName")
	for _, r := range results {
		require.Equal(t, EntropyName, r.DetectorName,
			"DetectorName must equal EntropyName (%q)", EntropyName)
	}
}

func TestEntropyProximity_Positive_BracketAssignment(t *testing.T) {
	input := `config['SECRET_KEY'] = "aB3xKp9Qm2Lr7TzWqDvNm"`
	data := []byte(input)
	want := []byte("aB3xKp9Qm2Lr7TzWqDvNm")

	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.NotEmpty(t, results,
		"expected an entropy-secret finding for bracket assignment; got zero")

	var found bool
	for _, r := range results {
		if bytes.Equal(r.Raw, want) {
			found = true
			require.GreaterOrEqual(t, bytes.Index(data, r.Raw), 0,
				"Raw %q must be locatable in input via bytes.Index", string(r.Raw))
		}
	}
	require.True(t, found,
		"expected Raw == %q; got: %v", string(want), entropyRawStrings(results))
}

func TestEntropyProximity_Negative_NoNearbyKeyword(t *testing.T) {
	input := `the build artifact aB3xKp9Qm2Lr7TzWqDv shipped`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"no keyword near token — must produce zero findings; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_GitSHA40NearKey(t *testing.T) {
	input := `cache key a3f9c1e8b2d47f6093a1c5e2d8b4f0a7c6e3d9b1`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"40-hex git SHA near 'key' must not produce a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_SHA256NearKey(t *testing.T) {
	sha256 := "a3f9c1e8b2d47f6093a1c5e2d8b4f0a7c6e3d9b1a3f9c1e8b2d47f6093a1c5e2"
	input := "signing key " + sha256
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"64-hex SHA-256 near 'signing key' must not produce a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_LowEntropyNearKeyword(t *testing.T) {
	input := `the password is hello`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"low-entropy / too-short value near 'password' must not produce a finding; got: %v",
		entropyRawStrings(results))
}

func TestEntropyProximity_Negative_UUIDNearSecret(t *testing.T) {
	input := `secret id 550e8400-e29b-41d4-a716-446655440000`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"UUID near 'secret' must not produce a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_URLPathNearAuthHeader(t *testing.T) {
	input := "GET /api/v1/account/profile HTTP/1.1\nAuthorization: Bearer abc"
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"URL path near 'Authorization' must not produce a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_SchemeStrippedURLNearKey(t *testing.T) {
	input := "deploy --discovery-key 499376eb6d1519fb07e837efc4e0fb750ae02b55 --gateway-url https://gateway-11237-048bf90a-7vu3lqds.onporter.run/"
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	for _, r := range results {
		require.NotContains(t, string(r.Raw), "onporter.run",
			"a URL value near 'key' must not be reported as a secret; got: %v", entropyRawStrings(results))
	}
}

func TestEntropyProximity_Negative_ModelNameNearKey(t *testing.T) {
	for _, input := range []string{
		`OPENAI_API_KEY config uses model text-embedding-3-small here`,
		`anthropic api key with model claude-3-5-sonnet-latest set`,
	} {
		results := filterByName(runEntropyDetector(t, input), EntropyName)
		require.Empty(t, results,
			"a dictionary-word model name near a key must not be a finding; input=%q got: %v",
			input, entropyRawStrings(results))
	}
}

func TestEntropyProximity_Negative_OpenAIOrgIDNearKey(t *testing.T) {
	input := `OPENAI_API_KEY set; org-9fK2mQ7vX1pLrA is the org`
	results := filterByName(runEntropyDetector(t, input), EntropyName)
	require.Empty(t, results,
		"an OpenAI org identifier near 'key' must not be a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Negative_MongoObjectIDNearKey(t *testing.T) {
	input := `api key lookup _id 6512ab34cd56ef78ab90cd12 in mongo`
	results := filterByName(runEntropyDetector(t, input), EntropyName)
	require.Empty(t, results,
		"a 24-hex Mongo ObjectId near 'key' must not be a finding; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Positive_LongHexCLIKey(t *testing.T) {
	key := "233338fa7422c031c2a4c3f3ddcb39f2e16e13f21b97f7692e8dc384e12c1151c71b555c19b6235dcd3cf776590f3f71"
	input := "sudo onboard --api-key " + key + " --backfill"
	data := []byte(input)

	results := filterByName(runEntropyDetector(t, input), EntropyName)

	var found bool
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte(key)) {
			found = true
			require.GreaterOrEqual(t, bytes.Index(data, r.Raw), 0)
		}
	}
	require.True(t, found,
		"96-char hex key after --api-key must be detected; got: %v", entropyRawStrings(results))
}

func TestEntropyProximity_Positive_IdentPrefixSelfKeyword(t *testing.T) {
	input := `API_KEY=aB3xKp9Qm2Lr7TzWqDv`
	data := []byte(input)
	want := []byte("aB3xKp9Qm2Lr7TzWqDv")

	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.NotEmpty(t, results,
		"expected an entropy-secret finding for API_KEY=<highentropy>; got zero")

	var found bool
	for _, r := range results {
		if bytes.Equal(r.Raw, want) {
			found = true
			require.GreaterOrEqual(t, bytes.Index(data, r.Raw), 0,
				"Raw %q must be locatable in input via bytes.Index", string(r.Raw))
		}
	}
	require.True(t, found, "expected Raw == %q; got: %v", string(want), entropyRawStrings(results))
}

func TestEntropyProximity_Negative_ValueContainsStemSelfTrigger(t *testing.T) {
	input := `xKeyAb3xKp9Qm2Lr7TzWqDv`
	results := filterByName(runEntropyDetector(t, input), EntropyName)

	require.Empty(t, results,
		"high-entropy token containing a stem must not self-trigger; got: %v", entropyRawStrings(results))
}

func TestHasNearbyKeyword_NoSelfTriggerFromValue(t *testing.T) {
	valueOnly := []tokenizer.Token{{
		Candidate:        "xKeyAb3xKp9Qm2Lr7TzWqDv",
		Keyword:          "xkeyab3xkp9qm2lr7tzwqdv",
		KeywordFromIdent: false,
	}}
	require.False(t, hasNearbyKeyword(valueOnly, 0),
		"value-derived keyword must not satisfy a token's own proximity requirement")

	fromIdent := []tokenizer.Token{{
		Candidate:        "aB3xKp9Qm2Lr7TzWqDv",
		Keyword:          "api_key=",
		KeywordFromIdent: true,
	}}
	require.True(t, hasNearbyKeyword(fromIdent, 0),
		"IDENT-derived keyword must satisfy a token's own proximity requirement")
}

func TestStringShannonEntropy_KnownValues(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "16_unique_chars_equals_4_bits",
			input:   "abcdefghijklmnop",
			wantMin: 4.0,
			wantMax: 4.0,
		},
		{
			name:    "all_same_char_zero_entropy",
			input:   "aaaaaaaaaaaaaaaa",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "single_char_zero_entropy",
			input:   "a",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "high_variability_above_4_bits",
			input:   "aB3xKp9Qm2Lr7TzWqDv",
			wantMin: 4.0,
			wantMax: 5.0,
		},
		{
			name:    "above_entropy_threshold",
			input:   "aB3xKp9Qm2Lr7TzWqDv",
			wantMin: DefaultEntropyThreshold,
			wantMax: math.MaxFloat64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectors.StringShannonEntropy(tc.input)
			require.False(t, math.IsNaN(got), "entropy must not be NaN")
			require.False(t, math.IsInf(got, 0), "entropy must not be Inf")
			require.GreaterOrEqual(t, got, tc.wantMin,
				"entropy of %q: got %.4f, want >= %.4f", tc.input, got, tc.wantMin)
			if tc.wantMax < math.MaxFloat64 {
				require.LessOrEqual(t, got, tc.wantMax,
					"entropy of %q: got %.4f, want <= %.4f", tc.input, got, tc.wantMax)
			}
		})
	}
}

func TestParseEntropyThreshold(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    float64
		wantErr bool
	}{
		{name: "empty_defaults", raw: "", want: DefaultEntropyThreshold},
		{name: "explicit_value", raw: "3.5", want: 3.5},
		{name: "boundary_high", raw: "8", want: 8.0},
		{name: "zero", raw: "0", wantErr: true},
		{name: "negative", raw: "-1", wantErr: true},
		{name: "above_range", raw: "9", wantErr: true},
		{name: "nan", raw: "NaN", wantErr: true},
		{name: "inf", raw: "Inf", wantErr: true},
		{name: "not_a_number", raw: "high", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEntropyThreshold(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.False(t, math.IsNaN(got) || math.IsInf(got, 0))
			require.Equal(t, tc.want, got)
		})
	}
}

func runEntropyDetectorTok(t *testing.T, tok tokenizer.Tokenizer, input string) []detectors.Result {
	t.Helper()
	d := NewEntropyProximityWithTokenizer(DefaultEntropyThreshold, tok)
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	data := []byte(input)

	matches := core.FindDetectorMatches(data)
	if len(matches) == 0 {
		return nil
	}

	var results []detectors.Result
	for _, match := range matches {
		found, err := match.FromData(context.Background(), false, data)
		require.NoError(t, err)
		results = append(results, found...)
	}
	return results
}

func entropyRawSet(results []detectors.Result) map[string]bool {
	out := make(map[string]bool, len(results))
	for _, r := range results {
		out[string(r.Raw)] = true
	}
	return out
}

// TestEntropyProximity_StructuralExercisedThroughFromData drives the structural
// tokenizer through the real detector FromData path (not just isolated unit
// tests) and asserts the Raw==substring invariant holds on its findings.
func TestEntropyProximity_StructuralExercisedThroughFromData(t *testing.T) {
	st, err := tokenizer.Select(tokenizer.Structural)
	require.NoError(t, err)

	// JSON shape that the whitespace tokenizer cannot split into key/value but
	// the structural tokenizer can. The high-entropy value sits inside quotes.
	input := `{"api_key":"aB3xKp9Qm2Lr7TzWqDv"}`
	data := []byte(input)
	want := "aB3xKp9Qm2Lr7TzWqDv"

	results := filterByName(runEntropyDetectorTok(t, st, input), EntropyName)
	require.NotEmpty(t, results,
		"structural tokenizer must yield an entropy finding through FromData for JSON pair; got zero")

	var found bool
	for _, r := range results {
		require.GreaterOrEqual(t, bytes.Index(data, r.Raw), 0,
			"Raw %q must be locatable in input via bytes.Index (substring invariant)", string(r.Raw))
		if string(r.Raw) == want {
			found = true
		}
	}
	require.True(t, found,
		"expected structural path to surface %q from JSON pair; got: %v", want, entropyRawStrings(results))
}

// TestEntropyProximity_StructuralFindingsSupersetOfWhitespace asserts the recall
// floor AT THE DETECTOR LEVEL: every finding the default (whitespace) path
// produces must also be produced by the structural path. This complements the
// tokenizer-package candidate-level superset test by verifying the property
// survives all of FromData's downstream filtering.
func TestEntropyProximity_StructuralFindingsSupersetOfWhitespace(t *testing.T) {
	ws := whitespaceTokenizer()
	st, err := tokenizer.Select(tokenizer.Structural)
	require.NoError(t, err)

	inputs := []string{
		`rotate this secret: aB3xKp9Qm2Lr7TzWqDv`,
		`API_KEY=aB3xKp9Qm2Lr7TzWqDv`,
		`config['SECRET_KEY'] = "aB3xKp9Qm2Lr7TzWqDvNm"`,
		`{"api_key":"aB3xKp9Qm2Lr7TzWqDv"}`,
		`DATABASE_PASSWORD=s3cr3tValue99Xyz0`,
		`the build artifact aB3xKp9Qm2Lr7TzWqDv shipped`, // negative: neither path fires
	}

	for _, in := range inputs {
		wsSet := entropyRawSet(filterByName(runEntropyDetectorTok(t, ws, in), EntropyName))
		stSet := entropyRawSet(filterByName(runEntropyDetectorTok(t, st, in), EntropyName))
		for raw := range wsSet {
			require.True(t, stSet[raw],
				"structural detector findings must be a superset of whitespace findings: missing %q for input %q", raw, in)
		}
	}
}

func entropyRawStrings(results []detectors.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = string(r.Raw)
	}
	return out
}
