package classify

import (
	"testing"

	regexp "github.com/wasilibs/go-re2"
)

func TestPatternStringsCompile(t *testing.T) {
	for _, s := range append(MaskPatterns(), EnvRefPatterns()...) {
		if _, err := regexp.Compile(s); err != nil {
			t.Fatalf("pattern %q failed to compile under go-re2: %v", s, err)
		}
	}
}

func TestRecognizerShapes(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		name string
		in   string
		want bool
	}{
		{IsStripeObjectID, "stripe", "du_1TIUcBBrSQGfJTjiR3r4WQh4", true},
		{IsStripeObjectID, "stripe-no", "ghp_0123456789abcdef", false},
		{IsHex32, "hex32", "9e107d9d372bb6826bd81d3542a419d6", true},
		{IsHex32, "hex32-31", "9e107d9d372bb6826bd81d3542a419d", false},
		{IsExcludedEntropyValue, "uuid", "a4c123b1-612d-d272-d137-1c17149d4395", true},
		{IsExcludedEntropyValue, "hex64", repeat("a", 64), true},
		{IsExcludedEntropyValue, "hex32-not-excluded-here", "9e107d9d372bb6826bd81d3542a419d6", false},
		{IsExcludedEntropyValue, "rel-path", "webapp/api/v1/routes.py", true},
		{IsExcludedEntropyValue, "rel-path-dir", "api/v1/payments/", true},
		{IsExcludedEntropyValue, "base64-with-slash-not-path", "YWxhZGRpbg/c2VzYW1l", false},
		{IsExcludedEntropyValue, "npm-scoped", "@auth0/auth0-mcp-server", true},
		{IsExcludedEntropyValue, "npm-uppercase-not-excluded", "@AbC0/Xy9Z-Kp7Q", false},
		{IsExcludedEntropyValue, "mixed-case-slash-secret-not-excluded", "aB3x/Kp9Q/m2Lr7TzWqDvN", false},
		{IsExcludedEntropyValue, "secret-trailing-slash-not-excluded", "aB3xKp9Qm2Lr7Tz/", false},
		{IsExcludedEntropyValue, "secret-dotted-tail-not-excluded", "aB3xKp9Q/m2Lr7Tz.WqDvNcEdF", false},
		{IsExcludedEntropyValue, "mixed-case-2seg-trailing-slash-not-excluded", "aB3xKp9Q/m2Lr7TzWqDv/", false},
		{IsSecretAlphabet, "secret-charset", "aB3=._-+/~@", true},
		{IsSecretAlphabet, "secret-charset-space", "aB3 x", false},
		{IsUUIDish, "uuid-canonical", "a1d976ec-a095-46eb-a163-2256ab8c9def", true},
		{IsUUIDish, "uuid-truncated-trailing-dash", "a1d976ec-a095-46eb-a163-", true},
		{IsUUIDish, "uuid-four-groups", "a1d976ec-a095-46eb-a163", true},
		{IsUUIDish, "jira-opaque-token-not-uuid", "n27p22cchdt2k3kxabcd1234", false},
		{IsUUIDish, "atatt-token-not-uuid", "ATATT3xFfGF0abcdefghij=A", false},
		{IsUUIDish, "hex-but-wrong-layout", "a1d976eca09546eba1632256", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(c.in); got != c.want {
				t.Fatalf("%s(%q) = %v, want %v", c.name, c.in, got, c.want)
			}
		})
	}
}

func TestLexiconAccessorsAreCopies(t *testing.T) {
	a := PlaceholderMarkers()
	a[0] = "MUTATED"
	if PlaceholderMarkers()[0] == "MUTATED" {
		t.Fatal("PlaceholderMarkers returned a mutable shared slice")
	}
}

func TestIsStructuralNonSecret(t *testing.T) {
	noise := []string{
		"a4b3b545-24ec-11f0-9f57-2256ab8c9def",
		"a4b3b545-24ec-11f0-9f57-22",
		"a4b3b545-24ec-11f0-9f57",
		"org-AbC123XyZ",
		"/v1/users/list",
		"webapp/api/v1/routes.py",
		"webapp/services/organization_service.py",
		"aigateway/settings.py",
		"api/v1/payments/",
		"provider_api/migrations/",
		"@auth0/auth0-mcp-server",
		"@modelcontextprotocol/server-slack",
		"@aikidosec/mcp",
		"@browserstack/mcp-server",
		"2026-06-22T10",
		"2026-06-22",
		"1234567890",
	}
	for _, v := range noise {
		if !IsStructuralNonSecret(v) {
			t.Errorf("expected %q to be structural non-secret", v)
		}
	}
	secrets := []string{
		"aB3xKp9Qm2Lr7TzWqDvNcEdF",
		"rtcYDmAEwtsYXT7O5H5rtcReJ5SPCjdlqFF5yD",
		"9e107d9d372bb6826bd81d3542a419d6",
		"YWxhZGRpbg/c2VzYW1l",
		"my/secret/path",
		"webapp/api/v1",
		"aB3x/Kp9Q/m2Lr7TzWqDvN",
		"@AbC0/Xy9Z-Kp7Q",
		"@scope/UPPER-not-npm",
		"aB3xKp9Qm2Lr7Tz/",
		"Zm9vYmFyc2VjcmV0dG9rZW4/",
		"aB3xKp9Q/m2Lr7Tz.WqDvNcEdF",
		"aB3xKp9Q/m2Lr7TzWqDv/",
		"A1B2C3D4/E5F6G7H8/",
		"foo/",
	}
	for _, v := range secrets {
		if IsStructuralNonSecret(v) {
			t.Errorf("expected %q NOT to be structural non-secret", v)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
