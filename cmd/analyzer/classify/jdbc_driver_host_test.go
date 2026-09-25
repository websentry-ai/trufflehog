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

// Shapes at the edge of the pattern. Each is reachable in a real prompt.
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

// A value that merely looks like a location must not carry a secret past the
// rule. The param check is what stops it.
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

// The keys that must never be treated as benign, whatever else changes.
func TestIsNonSecretConnString_SecretBearingKeysNeverBenign(t *testing.T) {
	for _, key := range []string{"password", "pwd", "passwd", "secret", "token", "apikey", "accesskey"} {
		v := `jdbc:aerospike:localhost:3000/test?` + key + `=somevalue123`
		require.False(t, IsNonSecretConnString(v),
			"%q must not be a benign connection key", key)
	}
}

// Reading parameter names alone would let any allowlisted key launder whatever
// value it held.
func TestIsNonSecretConnString_BenignKeyCannotLaunderASecret(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?timeout=AKIAR7Q3XZ9MNP4HT2VK`,
		`jdbc:aerospike:localhost:3000/test?sendKey=pk_test_9QrLmTvXbNhKdWzYpFcJaGsE`,
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

// The authority form keeps the behaviour it had, so what was suppressed before
// still is. It does not classify its values: OrderProcessingService and
// CorrectHorseBatteryStaple both measure 3.5, so entropy cannot tell an
// identifier from a passphrase.
func TestIsNonSecretConnString_AuthorityFormSettingsStaySuppressed(t *testing.T) {
	for _, v := range []string{
		`jdbc:sqlserver://localhost;applicationName=customer-order-service;encrypt=true`,
		`jdbc:sqlserver://x.database.windows.net:1433;database=db;encrypt=true;hostNameInCertificate=*.database.windows.net;loginTimeout=30`,
		`jdbc:mysql://db.prod.internal:3306/app?serverTimezone=America/New_York&useSSL=false`,
		`jdbc:postgresql://localhost:5432/app?currentSchema=reporting_schema&sslmode=require`,
		`jdbc:sqlserver://localhost;applicationName=OrderProcessingService;encrypt=true`,
	} {
		require.True(t, IsNonSecretConnString(v),
			"an authority-form setting is still a setting: %s", v)
	}
}

// Shape, not entropy: a real AWS access-key id measures 3.8, under any threshold
// that leaves hostnames suppressed.
func TestIsNonSecretConnString_VendorFormatIsNeverASetting(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?timeout=AKIASP2TPHJSQH3FJRUX`,
		`jdbc:postgresql://host:5432/db?user=AKIASP2TPHJSQH3FJRUX`,
		`jdbc:postgresql://host:5432/db?ssl=glpat-x1Y2z3A4b5C6d7E8`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"a credential-shaped value is not a setting: %s", v)
	}
}

// The driver-host form has no prior behaviour to preserve, so its values must
// positively look like settings. That is what catches a laundered passphrase.
func TestIsNonSecretConnString_DriverHostFormRequiresPlainSettings(t *testing.T) {
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?user=MyCompanyPassword2024`,
		`jdbc:aerospike:localhost:3000/test?user=CorrectHorseBatteryStaple`,
		`jdbc:aerospike:localhost:3000/test?user=PasswordPassword1234`,
		`jdbc:aerospike:localhost:3000/test?timeout=hunter2hunter2`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"only a flag, a count or a named mode is a setting here: %s", v)
	}
	// Upper-casing a passphrase must not turn it into a mode. An open word shape
	// cannot be told from a password, so the modes are listed rather than matched.
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?user=PASSWORD`,
		`jdbc:aerospike:localhost:3000/test?timeout=HUNTER2`,
		`jdbc:aerospike:localhost:3000/test?user=MYCOMPANYPASSWORD2024`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"an unlisted word is not a mode: %s", v)
	}
	// A digit string is a count on a key that takes one, and a password anywhere
	// else, so the option decides rather than the shape.
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?user=123456`,
		`jdbc:aerospike:localhost:3000/test?sendKey=12345678`,
		`jdbc:aerospike:localhost:3000/test?authMode=12345678`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"a count on a key that takes no count is not a setting: %s", v)
	}
	// Both bounds are the real ones -- the port range, and the Java int a driver
	// count is -- so each edge is pinned rather than left to a digit length.
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?port=65536`,
		`jdbc:aerospike:localhost:3000/test?port=123456`,
		`jdbc:aerospike:localhost:3000/test?portNumber=999999`,
		`jdbc:aerospike:localhost:3000/test?port=0`,
		`jdbc:aerospike:localhost:3000/test?timeout=2147483648`,
		`jdbc:aerospike:localhost:3000/test?timeout=12345678901`,
		`jdbc:aerospike:localhost:3000/test?timeout=-1`,
	} {
		require.False(t, IsNonSecretConnString(v), "outside the real bound: %s", v)
	}
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?port=5432`,
		`jdbc:aerospike:localhost:3000/test?portNumber=65535`,
		`jdbc:aerospike:localhost:3000/test?timeout=600000`,
		`jdbc:aerospike:localhost:3000/test?timeout=3600000`,
		`jdbc:aerospike:localhost:3000/test?socketTimeout=2147483647`,
		// Aerospike and the MySQL and Postgres drivers all read 0 as no time limit.
		`jdbc:aerospike:localhost:3000/test?timeout=0`,
		`jdbc:aerospike:localhost:3000/test?socketTimeout=0`,
	} {
		require.True(t, IsNonSecretConnString(v), "a real port or timeout is a setting: %s", v)
	}
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?timeout=5000&sendKey=true`,
		`jdbc:aerospike:localhost:3000/test?useBoolBin=false&authMode=INTERNAL`,
		`jdbc:aerospike:localhost:3000/test?authMode=EXTERNAL_INSECURE`,
		// The same options with the namespace left off.
		`jdbc:aerospike:localhost:3000?sendKey=true&timeout=5000&authMode=INTERNAL`,
	} {
		require.True(t, IsNonSecretConnString(v), "a driver option is a setting: %s", v)
	}
}

// A vendor prefix must be specific enough not to collide with a setting value.
// A wide "sk-" arm matched applicationName=sk-payments-worker and reported an
// authority-form string that was suppressed before.
func TestIsNonSecretConnString_VendorPrefixDoesNotCollideWithSettings(t *testing.T) {
	for _, v := range []string{
		`jdbc:sqlserver://localhost;applicationName=sk-payments-worker;encrypt=true`,
		`jdbc:sqlserver://localhost;applicationName=sk-billing-api;encrypt=true`,
		// The named variants allow hyphens, so they must be long enough that a
		// service name cannot reach them.
		`jdbc:sqlserver://localhost;applicationName=sk-admin-billing-service-prod;encrypt=true`,
	} {
		require.True(t, IsNonSecretConnString(v),
			"a hyphenated service name is not an api key: %s", v)
	}
	for _, v := range []string{
		`jdbc:postgresql://host:5432/db?ssl=sk-abcdefghijklmnopqrstuvwxyz0123456789`,
		`jdbc:postgresql://host:5432/db?ssl=sk-proj-NOT-A-REAL-KEY-0000000000000000000000000000000`,
	} {
		require.False(t, IsNonSecretConnString(v), "a real key shape is not a setting: %s", v)
	}
}

// Some drivers write parameters after a colon rather than a ";" or "&" -- DB2's
// /db:prop=val; -- and the parameter scan starts at those delimiters, so it would
// never read one. A colon past the host means unread parameters on either shape.
func TestIsNonSecretConnString_ColonParametersAreNeverUnread(t *testing.T) {
	for _, v := range []string{
		`jdbc:db2:host:50000/db:password=secret;`,
		`jdbc:db2://host:50000/db:password=secret;`,
		`jdbc:db2:host:50000/db:user=admin:password=AKIASP2TPHJSQH3FJRUX;`,
		`jdbc:aerospike:localhost:3000/test:password=hunter2`,
		`jdbc:postgresql://host:5432/db:password=secret`,
		// No path at all, so looking only past one missed it.
		`jdbc:db2://host:50000:password=secret`,
		`jdbc:db2:host:50000:password=secret`,
		// An Oracle SID is written the same way and is reported with them.
		`jdbc:oracle:thin://host:1521:ORCL`,
	} {
		require.False(t, IsNonSecretConnString(v),
			"a parameter the scan cannot read is not a setting: %s", v)
	}
	// A colon in the authority is the port, and is read as one.
	for _, v := range []string{
		`jdbc:aerospike:localhost:3000/test?sendKey=true&timeout=5000`,
		`jdbc:postgresql://localhost:5432/app?sslmode=require`,
		`jdbc:sqlserver://x.database.windows.net:1433;database=db;encrypt=true`,
	} {
		require.True(t, IsNonSecretConnString(v), "a port is not a parameter: %s", v)
	}
}
