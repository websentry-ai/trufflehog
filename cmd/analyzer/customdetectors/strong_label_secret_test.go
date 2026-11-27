package customdetectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestStrongLabelSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"salt backticked", "salt `Acme9Auction$2026`", "Acme9Auction$2026"},
		{"password backticked", "password `Summer(2024)!`", "Summer(2024)!"},
		{"password is", "the DB password is `Solut10nSt@r`", "Solut10nSt@r"},
		{"secret colon", "secret: `aB3xY9kLmN2pQ7`", "aB3xY9kLmN2pQ7"},
		{"quoted label", "the `password` field", ""},
		{"redacted", "password `REDACTED`", ""},
		{"angle placeholder", "password `<your-password>`", ""},
		{"changeme", "password `changeme`", ""},
		{"none", "password `None`", ""},
		{"mask", "password `***`", ""},
		{"caps env name", "secret `MY_SECRET_NAME`", ""},
		{"env ref", "password `$DB_PASSWORD`", ""},
		{"template ref", "secret `{{ secrets.API }}`", ""},
		{"algorithm name", "salt `bcrypt`", ""},
		{"command", "secret `kubectl get secret -n prod`", ""},
		{"password prefix word", "passwordless `login`", ""},
		{"vault path", "secret `prod/payments/db-creds`", ""},
	}
	d := NewStrongLabelSecret()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := runDetector(t, d, tc.in)
			if tc.want == "" {
				require.Empty(t, rawStrings(results))
				return
			}
			require.Equal(t, []string{tc.want}, rawStrings(results))
		})
	}
}

func TestStrongLabelSecretCoexistsWithEntropyDetector(t *testing.T) {
	data := []byte("password `Summer(2024)!`\napi_key = aB3xKp9Qm2Lr7TzWqDvNcEdF")
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{NewStrongLabelSecret(), NewEntropyProximity(3.0)})
	found := map[string]bool{}
	for _, match := range core.FindDetectorMatches(data) {
		results, err := match.FromData(context.Background(), false, data)
		require.NoError(t, err)
		for _, r := range results {
			found[r.DetectorName] = true
		}
	}
	require.True(t, found[StrongLabelSecretName], "strong-label detector must report in a shared scan")
	require.True(t, found[EntropyName], "entropy detector must still report in a shared scan")
}
