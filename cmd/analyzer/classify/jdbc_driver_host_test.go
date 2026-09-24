package classify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Drivers that never adopted jdbc:driver://host. A local test connection is
// usually written this way, and requiring "://" excluded every one of them.
func TestIsNonSecretConnString_DriverHostForm(t *testing.T) {
	nonSecret := []struct{ name, v string }{
		{"aerospike local", `jdbc:aerospike:localhost:3000/test?sendKey=true`},
		{"aerospike with benign params", `jdbc:aerospike:localhost:3000/test?timeout=5000&sockettimeout=1000`},
		{"host and port only", `jdbc:aerospike:db.internal:3000`},
		{"no port", `jdbc:h2:localhost/testdb`},
	}
	for _, tc := range nonSecret {
		t.Run(tc.name, func(t *testing.T) {
			require.True(t, IsNonSecretConnString(tc.v),
				"a location with no credential is not a secret")
		})
	}
}

// The guards that make this safe. Each one is the reason a credential-bearing
// string stays a finding, so each is asserted rather than assumed.
func TestIsNonSecretConnString_DriverHostFormKeepsSecrets(t *testing.T) {
	secret := []struct{ name, v, why string }{
		{"oracle thin with credentials", `jdbc:oracle:thin:scott/tiger@dbhost:1521:orcl`,
			"an @ means credentials ride in front of the host"},
		{"password parameter", `jdbc:aerospike:localhost:3000/test?password=hunter2`,
			"password is not a benign connection key"},
		{"authority form with credentials", `jdbc:postgresql://host/db?user=u&password=p`,
			"unchanged behaviour for the :// form"},
		{"sqlserver password", `jdbc:sqlserver://host;databaseName=db;password=s3cret`,
			"semicolon-delimited password is still a password"},
	}
	for _, tc := range secret {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, IsNonSecretConnString(tc.v), tc.why)
		})
	}
}

// The authority form must behave exactly as before.
func TestIsNonSecretConnString_AuthorityFormUnchanged(t *testing.T) {
	require.True(t, IsNonSecretConnString(`jdbc:postgresql://localhost:5432/test?ssl=false`))
	require.False(t, IsNonSecretConnString(`postgres://user:pw@host/db`), "not a jdbc string")
	require.False(t, IsNonSecretConnString(`jdbc:`), "too short to be a location")
}

// A4: shapes at the edge of the pattern. Each is reachable in a real prompt.
func TestIsNonSecretConnString_EdgeShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    string
		want bool
	}{
		{"scheme only", `jdbc:`, false},
		{"driver but no host", `jdbc:aerospike:`, false},
		{"port out of range keeps the shape", `jdbc:aerospike:localhost:999999/test`, false},
		{"host with dots and dashes", `jdbc:aerospike:db-1.eu-west.internal:3000/test`, true},
		{"unicode host is not a host", `jdbc:aerospike:höst:3000/test`, false},
		{"uppercase scheme", `JDBC:AEROSPIKE:localhost:3000/test`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsNonSecretConnString(tc.v))
		})
	}
}

// A5: a value that merely looks like a location must not become a way to carry
// a secret past the rule. The param check is what stops it, so it is asserted
// on the shapes an attacker would reach for.
func TestIsNonSecretConnString_SecretSmuggledIntoALocation(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?tok=AKIAR7Q3XZ9MNP4HT2VK`,
		`jdbc:aerospike:localhost:3000/test?apikey=sk-live-9xKq2vRt`,
		`jdbc:aerospike:localhost:3000/test?sendKey=true&secret=hunter2xyz`,
		`jdbc:h2:mem:testdb;USER=sa;PASSWORD=s3cretvalue`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"an unrecognised parameter must keep the string a secret: %s", v)
	}
}

// A6: the keys that must never be treated as benign, whatever else changes.
func TestIsNonSecretConnString_SecretBearingKeysNeverBenign(t *testing.T) {
	for _, key := range []string{"password", "pwd", "passwd", "secret", "token", "apikey", "accesskey"} {
		v := `jdbc:aerospike:localhost:3000/test?` + key + `=somevalue123`
		require.False(t, IsNonSecretConnString(v),
			"%q must not be a benign connection key", key)
	}
}

// A benign key name must not be usable to carry a credential. Cursor found this
// hole: the rule read parameter names only, so any allowlisted key laundered
// whatever value it held.
func TestIsNonSecretConnString_BenignKeyCannotLaunderASecret(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?timeout=AKIAR7Q3XZ9MNP4HT2VK`,
		`jdbc:aerospike:localhost:3000/test?sendKey=sk-live-9xKq2vRt8mNp`,
		`jdbc:postgresql://host:5432/db?ssl=ghp_0123456789abcdefghijklmnop`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"a benign key holding a credential-shaped value is not a location: %s", v)
	}
}

// The settings those keys really carry stay recognised.
func TestIsNonSecretConnString_BenignKeysWithRealSettings(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?timeout=5000&sendKey=true`,
		`jdbc:aerospike:localhost:3000/test?authMode=INTERNAL&useBoolBin=false`,
		`jdbc:postgresql://localhost:5432/test?ssl=false`,
	} {
		require.True(t, IsNonSecretConnString(v), "a plain setting is still a setting: %s", v)
	}
}

// Ordinary settings run long without being random. Both review engines found
// these being re-reported when the value check was only length plus entropy.
func TestIsNonSecretConnString_OrdinarySettingsStaySuppressed(t *testing.T) {
	for _, v := range []string{
		`jdbc:sqlserver://localhost;applicationName=customer-order-service;encrypt=true`,
		`jdbc:sqlserver://x.database.windows.net:1433;database=db;encrypt=true;hostNameInCertificate=*.database.windows.net;loginTimeout=30`,
		`jdbc:aerospike:localhost:3000/test?timeout=5000&sendKey=true`,
	} {
		require.True(t, IsNonSecretConnString(v),
			"a long setting value is still a setting: %s", v)
	}
}
