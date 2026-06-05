package customdetectors

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func buildDBConnectionURIDetector(t *testing.T) detectors.Detector {
	t.Helper()
	d, err := NewDBConnectionURI()
	require.NoError(t, err, "NewDBConnectionURI() must not return an error")
	return d
}

func TestDBConnectionURIDetector_Positive(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		password string
	}{
		{
			name:     "mysql with user and port",
			input:    `mysql://root:rootpassword@mysql.example.com:3306/app`,
			password: "rootpassword",
		},
		{
			name:     "redis empty user",
			input:    `redis://:redispassword@redis.example.com:6379`,
			password: "redispassword",
		},
		{
			name:     "mongodb srv scheme",
			input:    `mongodb+srv://fakeuser:fakepassword@cluster0.example.mongodb.net/test`,
			password: "fakepassword",
		},
		{
			name:     "postgresql mixed-case password",
			input:    `postgresql://admin:SuperSecretPassword123@db.example.com:5432/appdb`,
			password: "SuperSecretPassword123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := buildDBConnectionURIDetector(t)
			results := runDetector(t, d, tc.input)

			require.Len(t, results, 1, "expected exactly one finding; got: %v", rawStrings(results))
			r := results[0]

			require.Equal(t, []byte(tc.password), r.Raw,
				"Raw must equal the embedded password")
			require.Equal(t, DBConnectionURIName, r.DetectorName,
				"DetectorName must equal DBConnectionURIName (%q)", DBConnectionURIName)

			idx := bytes.Index([]byte(tc.input), r.Raw)
			require.GreaterOrEqual(t, idx, 0,
				"Raw %q must be locatable in input via bytes.Index (offsets() contract)", string(r.Raw))
		})
	}
}

func TestDBConnectionURIDetector_Negative(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		reason string
	}{
		{
			name:   "env ref password",
			input:  `redis://:${REDIS_PASSWORD}@host`,
			reason: "captured ${REDIS_PASSWORD} matches the env-ref exclude",
		},
		{
			name:   "template ref password",
			input:  `postgres://user:{{ .Values.pw }}@host`,
			reason: "captured {{ .Values.pw }} matches the template exclude",
		},
		{
			name:   "plain url no credentials",
			input:  `https://api.example.com/v1`,
			reason: "no scheme keyword and no user:pass@ authority",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := buildDBConnectionURIDetector(t)
			results := runDetector(t, d, tc.input)
			require.Empty(t, results,
				"%s — must not produce a finding; got: %v", tc.reason, rawStrings(results))
		})
	}
}

func TestDBConnectionURIDetector_ConstructorSucceeds(t *testing.T) {
	_, err := NewDBConnectionURI()
	require.NoError(t, err, "NewDBConnectionURI() must not error on the built-in config")
}
