package customdetectors

import (
	"context"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// pseudoSecret is deterministic and has no repeat runs, so the placeholder
// filters downstream never mistake it for a dummy value.
func pseudoSecret(n int, seed int64) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func urlLoginRaws(t *testing.T, input string) []string {
	t.Helper()
	d, err := NewURLLoginCredential()
	require.NoError(t, err)
	results, err := d.FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)
	var raws []string
	for _, r := range results {
		raws = append(raws, string(r.Raw))
	}
	return raws
}

func TestURLLoginCredential_ReportsThePassword(t *testing.T) {
	pw := pseudoSecret(40, 1)
	for _, scheme := range []string{"https", "http", "ssh", "git", "git+ssh", "sftp", "svn+ssh",
		"wss", "postgres", "postgresql", "mysql", "mariadb", "redis", "rediss", "mongodb+srv",
		"amqps", "ldap", "smtps", "imap", "HTTPS"} {
		input := scheme + "://svc:" + pw + "@host.acme.io/repo"
		require.Equal(t, []string{pw}, urlLoginRaws(t, input), input)
	}
}

func TestURLLoginCredential_AnyLength(t *testing.T) {
	// The vendor URI detector stops at 50; a long token as the password is the
	// case that was reaching nothing.
	for _, n := range []int{3, 50, 51, 120, 500, 1000, 1500, 3000} {
		pw := pseudoSecret(n, int64(n))
		input := "pip install --index-url https://svc:" + pw + "@pkg.acme.io/simple/ requests"
		require.Equal(t, []string{pw}, urlLoginRaws(t, input), n)
	}
}

func TestURLLoginCredential_IgnoresWhatIsNotALogin(t *testing.T) {
	for _, input := range []string{
		"https://jane@acme.io/dashboard",              // a username, no password
		"https://app.acme.com/u/jane@gmail.com",       // an address in the path
		"https://acme.com?user:jane@acme.com",         // "?" ends the authority
		"https://acme.com#user:jane@acme.com",         // so does "#"
		"https://svc:pw@pkg.acme.io/simple/",          // two characters is not a password
		"https://svc:${INDEX_PASSWORD}@pkg.acme.io",   // a template placeholder
		"x://svc:" + pseudoSecret(40, 9) + "@acme.io", // not a scheme that carries logins
	} {
		require.Empty(t, urlLoginRaws(t, input), input)
	}
}
