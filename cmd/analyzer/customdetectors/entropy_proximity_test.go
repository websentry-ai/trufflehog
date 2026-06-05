package customdetectors

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func runEntropyDetector(t *testing.T, input string) []detectors.Result {
	t.Helper()
	d := NewEntropyProximity(defaultEntropyThreshold)
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
	var d detectors.Detector = NewEntropyProximity(defaultEntropyThreshold)
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
	valueOnly := []entropyToken{{
		candidate:        "xKeyAb3xKp9Qm2Lr7TzWqDv",
		keyword:          "xkeyab3xkp9qm2lr7tzwqdv",
		keywordFromIdent: false,
	}}
	require.False(t, hasNearbyKeyword(valueOnly, 0),
		"value-derived keyword must not satisfy a token's own proximity requirement")

	fromIdent := []entropyToken{{
		candidate:        "aB3xKp9Qm2Lr7TzWqDv",
		keyword:          "api_key=",
		keywordFromIdent: true,
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
			wantMin: defaultEntropyThreshold,
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
		{name: "empty_defaults", raw: "", want: defaultEntropyThreshold},
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

func entropyRawStrings(results []detectors.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = string(r.Raw)
	}
	return out
}
