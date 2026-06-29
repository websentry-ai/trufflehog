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
		{IsUUIDish, "uuid-four-groups-no-dash", "a1d976ec-a095-46eb-a163", false},
		{IsUUIDish, "jira-opaque-token-not-uuid", "n27p22cchdt2k3kxabcd1234", false},
		{IsUUIDish, "atatt-token-not-uuid", "ATATT3xFfGF0abcdefghij=A", false},
		{IsUUIDish, "hex-but-wrong-layout", "a1d976eca09546eba1632256", false},
		{IsCodeLike, "code-backslash-escape", "sameShapeToken(i))\\n\\t}\\n\\treturn", true},
		{IsCodeLike, "code-spaces-and-braces", "map[string]string{ continue }", true},
		{IsCodeLike, "code-dotted-selector-trailing-comma", "customdetectors.GenericSecretName,", true},
		{IsCodeLike, "code-dotted-selector", "customdetectors.GenericSecretName", true},
		{IsCodeLike, "code-angle-generics", "List<String>", true},
		{IsCodeLike, "code-quoted-string", "value=\"foo\"", true},
		{IsCodeLike, "azure-v1-punctuation-secret-kept", "Abc@def*ghi;jkl:mno[pqr]stu^vwx1", false},
		{IsCodeLike, "base64-secret-kept", "YWxhZGRpbg/c2VzYW1l", false},
		{IsCodeLike, "single-token-kept", "GenericSecretName", false},
		{IsCodeLike, "mixed-charset-secret-kept", "aB3xKp9Qm2Lr7Tz.WqDvNc~ef-12", false},
		{IsExcludedEntropyValue, "lower-ref-path", "dawidjancen/fe-1799/tags", true},
		{IsExcludedEntropyValue, "lower-path-3seg", "registry/org/image", true},
		{IsExcludedEntropyValue, "mixed-case-slash-secret-still-kept", "aB3x/Kp9Q/m2Lr7TzWqDvN", false},
		{IsExcludedEntropyValue, "field-ref-consecutive-dots", "txJourneyAggregated...psd2Recommendation.rule_category", true},
		{IsExcludedEntropyValue, "camelcase-english-identifier", "psd2RecommendationPerAcquirer", true},
		{IsExcludedEntropyValue, "camelcase-english-identifier-2", "txJourneyAggregated2Decision", true},
		{IsExcludedEntropyValue, "random-secret-low-vowel-kept", "aB3xKp9Qm2Lr7TzWqDv", false},
		{IsExcludedEntropyValue, "random-secret-mixed-kept", "0TJ13irg9mdPi9XuKVvg3gyDXPcUiqk3cYAmZZ", false},
		{IsExcludedEntropyValue, "random-secret-long-consonant-run-kept", "rtcYDmAEwtsYXT7O5H5rtcReJ5SPCjdlqFF5yD", false},
		{IsExcludedEntropyValue, "digit-free-passphrase-kept", "CorrectHorseBatteryStaple", false},
		{IsExcludedEntropyValue, "digit-free-identifier-kept", "getUserAuthTokenById", false},
		{IsExcludedEntropyValue, "filename-sql", "0004_hardening.sql", true},
		{IsExcludedEntropyValue, "filename-yaml", "application-prod.yaml", true},
		{IsExcludedEntropyValue, "okta-group-id", "00g1llyjisuNcGj420x8", true},
		{IsExcludedEntropyValue, "okta-user-id", "00u17b72efigJqKEG0x8", true},
		{IsExcludedEntropyValue, "okta-shape-uppercase-prefix-not-excluded", "00G1llyjisuNcGj420x8", false},
		{IsExcludedEntropyValue, "anthropic-tool-id", "toolu_01YXrC1ZjRxiouSyo3pTshgj", true},
		{IsExcludedEntropyValue, "anthropic-msg-id", "msg_01YXrC1ZjRxiouSyo3pTshgj", true},
		{IsExcludedEntropyValue, "openai-chatcmpl-id", "chatcmpl-8P20za0jPV7KbW5zQW5", true},
		{IsExcludedEntropyValue, "openai-assistant-id", "asst_abc1234567890CDEF9012", true},
		{IsExcludedEntropyValue, "openai-thread-id", "thread_AbC123dEf456GhI789Jk", true},
		{IsExcludedEntropyValue, "openai-file-id", "file-9aBcDeFgHiJkLmNoPq", true},
		{IsExcludedEntropyValue, "openai-sk-proj-secret-kept", "sk-proj-Ab3xKp9Qm2Lr7TzWqDvNc", false},
		{IsExcludedEntropyValue, "aws-access-key-id-not-ai-prefix-kept", "AKIANZHP27R2JXHL67Q7", false},
		{IsExcludedEntropyValue, "long-hex-key-kept-not-treated-as-digest", repeat("a3f9c1e8b2d47f60", 6), false},
		{IsExcludedEntropyValue, "snake-ident-with-digit", "vault_kv_secret_v2", true},
		{IsExcludedEntropyValue, "snake-ident-no-digit-passphrase-kept", "correct_horse_battery_staple", false},
		{IsExcludedEntropyValue, "snake-ident-two-seg-kept", "secret_v2", false},
		{IsExcludedEntropyValue, "mixed-case-secret-kept", "aB3xKp9Qm2Lr7TzWqDv", false},
		{IsNonSecretConnString, "jdbc-benign-params-localhost", "jdbc:sqlserver://localhost:2500;databaseName=Hounds;encrypt=true", true},
		{IsNonSecretConnString, "jdbc-benign-params-any-host", "jdbc:sqlserver://aao-st-elydb.io.thehut.local;databaseName=Hounds;applicationName=Hounds;encrypt=true;trustServerCertificate=true", true},
		{IsNonSecretConnString, "jdbc-benign-params-public-host", "jdbc:sqlserver://db.prod.example.com:1433;databaseName=app;encrypt=true", true},
		{IsNonSecretConnString, "jdbc-no-params", "jdbc:postgresql://10.0.0.5:5432/app", true},
		{IsNonSecretConnString, "jdbc-benign-long-value-still-suppressed", "jdbc:sqlserver://localhost;applicationName=Production2024;encrypt=true", true},
		{IsNonSecretConnString, "jdbc-unknown-key-short-value-kept", "jdbc:mysql://localhost/db?x=abc123", false},
		{IsNonSecretConnString, "jdbc-unknown-key-public-kept", "jdbc:mysql://db.prod/db?x=aB3xKp9Qm2Lr7", false},
		{IsNonSecretConnString, "jdbc-password-key-kept", "jdbc:sqlserver://localhost:1;password=hunter2", false},
		{IsNonSecretConnString, "jdbc-token-key-kept", "jdbc:mysql://localhost/db?accessToken=Ab3xKp9Q", false},
		{IsNonSecretConnString, "jdbc-userinfo-password-kept", "jdbc:postgresql://app:s3cretP4ss@localhost:5432", false},
		{IsNonSecretConnString, "jdbc-oracle-userinfo-slash-kept", "jdbc:oracle:thin:scott/tiger@localhost:1521:db", false},
		{IsNonSecretConnString, "bare-password-not-connstring-kept", "hunter2", false},
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
