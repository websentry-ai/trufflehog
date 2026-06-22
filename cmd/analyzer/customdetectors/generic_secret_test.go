package customdetectors

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func buildGenericSecretDetector(t *testing.T) detectors.Detector {
	t.Helper()
	d, err := NewGenericSecret()
	require.NoError(t, err, "NewGenericSecret() must not return an error")
	return d
}

func runDetector(t *testing.T, d detectors.Detector, input string) []detectors.Result {
	t.Helper()
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

func TestGenericSecretDetector_Positive_PasswordEqualsRoot(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `password = root`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for 'password = root'")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("root")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'root', got results: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_EnvStyleAssignment(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `DATABASE_PASSWORD=hunter2`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for DATABASE_PASSWORD=hunter2")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("hunter2")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'hunter2', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_YAMLQuotedPassword(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `db_password: "SuperSecret123"`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for db_password: \"SuperSecret123\"")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("SuperSecret123")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'SuperSecret123', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_APIKey(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `API_KEY=fakeKey1234567890abc`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for API_KEY=fakeKey1234567890abc")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("fakeKey1234567890abc")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'fakeKey1234567890abc', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_HTTPHeader(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `X-Internal-Token: abc123deadbeef99`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for X-Internal-Token: abc123deadbeef99")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("abc123deadbeef99")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'abc123deadbeef99', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_BracketIndexedAssignment(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `app.config['SECRET_KEY'] = "aB3xKp9Qm2Lr7TzWqDvNm"`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for bracket-indexed SECRET_KEY assignment")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("aB3xKp9Qm2Lr7TzWqDvNm")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'aB3xKp9Qm2Lr7TzWqDvNm', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Positive_BracketIndexedColon(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `obj["token"]: "abc123def456ghi"`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected a finding for bracket-indexed token with colon separator")

	found := false
	for _, r := range results {
		if bytes.Equal(r.Raw, []byte("abc123def456ghi")) {
			found = true
			break
		}
	}
	require.True(t, found, "expected Raw == 'abc123def456ghi', got: %v", rawStrings(results))
}

func TestGenericSecretDetector_DetectorName(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `password = root`
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "need at least one result to check DetectorName")
	for _, r := range results {
		require.Equal(t, GenericSecretName, r.DetectorName,
			"DetectorName must equal GenericSecretName (%q)", GenericSecretName)
	}
}

func TestGenericSecretDetector_RawIsLocatableInInput(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `db_password: "SuperSecret123"`
	data := []byte(input)
	results := runDetector(t, d, input)

	require.NotEmpty(t, results, "expected at least one result")
	for _, r := range results {
		idx := bytes.Index(data, r.Raw)
		require.GreaterOrEqual(t, idx, 0,
			"Raw %q must be locatable in input via bytes.Index (offsets() contract)", string(r.Raw))
	}
}

func TestGenericSecretDetector_Negative_ExcludeWord_Changeme(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `password = changeme`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"'changeme' is an ExcludeWord — must not produce a finding; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_EnvRefCurly(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `password = ${DB_PASSWORD}`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"env-ref '${DB_PASSWORD}' must be excluded; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_EnvRefBare(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `token = $SECRET_ENV`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"bare env-ref '$SECRET_ENV' must be excluded; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_TemplateRef(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `apiKey = {{.Values.secret}}`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"Helm-style template '{{.Values.secret}}' must be excluded; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_MaskedValue(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `secret = ********`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"masked value '********' must be excluded; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_BooleanValue(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `password = true`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"boolean 'true' must be excluded; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_NoCredentialKeyword_Mode(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `MODE = production`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"non-credential key 'MODE' must not trigger; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_NoCredentialKeyword_Type(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `type = string`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"non-credential key 'type' must not trigger; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_Negative_NoCredentialKeyword_Region(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `region = us-east-1`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"non-credential key 'region' must not trigger; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_ConstructorSucceeds(t *testing.T) {
	_, err := NewGenericSecret()
	require.NoError(t, err, "NewGenericSecret() must not error on the built-in config")
}

func TestGenericSecretDetector_FP_GitURLMaskedCredential(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `x-access-token: ***@github.com/acme/infra.git`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"masked git URL credential must not produce a finding; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_FP_OAuthStrategyIdentifier(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `"authId": "google-oauth2|user_01JC9WRVMWHDTHS8T58ZKHGAKY"`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"oauth strategy identifier must not produce a finding; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_FP_OsEnvironCodeFragment(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `key = os.environ[`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"os.environ code fragment must not produce a finding; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_FP_SkPlaceholderAPIKey(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"sk-xxxx placeholder must not produce a finding; got: %v", rawStrings(results))
}

func TestGenericSecretDetector_FP_CodeFragmentSpecialChars(t *testing.T) {
	d := buildGenericSecretDetector(t)
	input := `secret = S+')`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"code fragment with shell metachars must not produce a finding; got: %v", rawStrings(results))
}

func rawStrings(results []detectors.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = string(r.Raw)
	}
	return out
}
