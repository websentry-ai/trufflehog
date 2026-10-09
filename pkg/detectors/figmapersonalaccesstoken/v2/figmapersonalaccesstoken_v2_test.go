package figmapersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "Figma",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"figma_secret": "figr_EZe7plhYvN92IyiDCjkvTcbNVZsuRVpDcHOwNNP1"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "figr_EZe7plhYvN92IyiDCjkvTcbNVZsuRVpDcHOwNNP1"
	figd   = "figd" + "_Ab3-Cd4_Ef5Gh6Jk7Mn8Pq9Rs2Tu3Vw4Xy5Za6Bc" // split so no token is a contiguous literal
)

func TestFigmaPersonalAccessToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{secret},
		},
		{
			name:  "valid pattern - figd_ with no keyword",
			input: "export TOKEN=" + figd,
			want:  []string{figd},
		},
		{
			name:  "valid pattern - figd_ next to figma reported once",
			input: "figma token: " + figd,
			want:  []string{figd},
		},
		{
			name:  "valid pattern - figd_ ending in a hyphen",
			input: "TOKEN=\"" + figd[:len(figd)-1] + "-\"",
			want:  []string{figd[:len(figd)-1] + "-"},
		},
		{
			name:  "invalid pattern - figd_ one long",
			input: "export TOKEN=" + figd + "x",
			want:  []string{},
		},
		{
			name:  "invalid pattern - figd_ one short",
			input: "export TOKEN=" + figd[:len(figd)-1],
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
