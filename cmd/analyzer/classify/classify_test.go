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
		{IsExcludedEntropyValue, "short-pronounceable-password-kept", "Vobat3Limuk", false},
		{IsExcludedEntropyValue, "short-pronounceable-password-kept-2", "Reki8Fugo2Mab", false},
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
		{IsExcludedEntropyValue, "twentychar-uppercase-id-not-ai-prefix-kept", "AK1ANZHP27R2JXHL67Q7", false},
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
		{IsNonSecretConnString, "jdbc-oracle-userinfo-at-kept", "jdbc:oracle:thin:scott/tiger@localhost:1521:db", false},
		{IsNonSecretConnString, "jdbc-oracle-positional-slash-kept", "jdbc:oracle:thin:scott/tiger/localhost:1521/db", false},
		{IsNonSecretConnString, "jdbc-no-url-scheme-kept", "jdbc:sqlite:/var/data/app.db", false},
		{IsNonSecretConnString, "jdbc-hyphen-cred-key-kept", "jdbc:mysql://db.prod/app?api-key=sk_live_xxx&encrypt=true", false},
		{IsNonSecretConnString, "jdbc-dotted-unknown-key-kept", "jdbc:oracle:thin://h/db?oracle.net.authentication=x", false},
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

func TestStructuredIdentifierFalsePositives(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		name string
		in   string
		want bool
	}{
		// composite resource identifiers (word + structural segments)
		{IsExcludedEntropyValue, "k8s-pod-name", "ai-platform-85f44d9c8f-hxf2l", true},
		{IsExcludedEntropyValue, "env-resource-name", "salesloft-us3-prod", true},
		{IsExcludedEntropyValue, "cli-flag-fragment", "--i-generative-600", true},
		// RECALL GUARD: a short high-entropy (upper+lower+digit) segment between words
		// is NOT benign structure — the value must stay scannable
		{IsExcludedEntropyValue, "composite-with-hi-entropy-short-seg-kept", "admin-Xk9f2-service-Qp7Zt", false},
		// AI model / build identifiers ending in a release date -> excluded
		{IsExcludedEntropyValue, "model-claude-datestamp", "claude-3-5-sonnet-20241022", true},
		{IsExcludedEntropyValue, "model-gpt-iso-date", "gpt-4o-2024-08-06", true},
		{IsExcludedEntropyValue, "model-claude-sonnet4", "claude-sonnet-4-20250514", true},
		{IsExcludedEntropyValue, "model-claude-opus-date", "claude-3-opus-20240229", true},
		// RECALL GUARD: a mixed-case high-entropy secret ending in digits stays flagged
		{IsExcludedEntropyValue, "secret-ending-in-digits-kept", "aB3xKp9Qm2Lr7Tz-20241022", false},
		{IsExcludedEntropyValue, "secret-uppercase-datestamp-kept", "Kj8N2mP9xL5vR7-20240806", false},
		// datetime-prefixed log id
		{IsExcludedEntropyValue, "datetime-id", "2026-06-29T071742863-7a34fad0-v2", true},
		{IsExcludedEntropyValue, "iso-timestamp-z", "2026-06-29T12:30:42.322Z", true},
		// uuid with a short trailing suffix
		{IsExcludedEntropyValue, "uuid-with-suffix", "1521378b-c34c-4b6a-b668-ccefe8dce535/b2l1", true},
		// document filename
		{IsExcludedEntropyValue, "pdf-filename", "OneTrust_ContrastV3.pdf", true},
		// ULIDs
		{IsExcludedEntropyValue, "ulid-canonical", "01ARZ3NDEKTSV4RRFFQ69G5FAV", true},
		{IsExcludedEntropyValue, "ulid-noncrockford-U-kept", "01J8XK3QF7M2N9P0R1S2T3U4V5", false},
		// Okta object ids
		{IsExcludedEntropyValue, "okta-app-id", "0oa3nnalkuvPcIl642z0", true},
		{IsExcludedEntropyValue, "okta-factor-id", "fwf5pmzjl2OkAb912c3d", true},
		{IsExcludedEntropyValue, "okta-authz-server-id", "aus6qqsoMxYzWvUtSr98", true},
		// JWT header/payload (base64url that decodes to JSON)
		{IsExcludedEntropyValue, "jwt-header", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", true},
		{IsExcludedEntropyValue, "jwt-payload", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", true},
		// padded hex digest (go.sum style)
		{IsExcludedEntropyValue, "padded-hex-sha1", "a3f9c1e8b2d47f6093a1c5e2d8b4f0a7c6e3d9b1=", true},

		// RECALL GUARDS — must NOT be excluded
		{IsExcludedEntropyValue, "diceware-passphrase-kept", "correct_horse_battery_staple", false},
		{IsExcludedEntropyValue, "dash-passphrase-kept", "correct-horse-battery-staple", false},
		{IsExcludedEntropyValue, "embedded-secret-after-prefix-kept", "prod-aB3xKp9Qm2Lr7TzWqDvNc", false},
		{IsExcludedEntropyValue, "embedded-secret-in-path-kept", "aB3x/Kp9Q/m2Lr7TzWqDvN", false},
		{IsExcludedEntropyValue, "jwt-signature-kept", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV", false},
		{IsExcludedEntropyValue, "plain-32hex-kept", "9e107d9d372bb6826bd81d3542a419d6", false},
		{IsExcludedEntropyValue, "ulid-lowercase-secret-kept", "01arz3ndektsv4rrffq69g5fav", false},
		// date-PREFIXED secret with a long random segment must NOT be dropped as a datetime id
		{IsExcludedEntropyValue, "date-prefixed-secret-kept", "2026-06-29T07-aB3xKp9Qm2Lr7TzWqDvNc", false},
		{IsExcludedEntropyValue, "date-prefixed-secret-nodash-kept", "2026-06-29T07aB3xKp9Qm2Lr7TzWqDvNc", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%s(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestBase64EncodedTextClassifier(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// k8s configmap base64 JSON blob chunks (iac04)
		{"b64-complete-json-object", "eyJlbnYiOiJwcm9kIiwidGllciI6Mn0=", true},
		{"b64-complete-json-array", "eyJyb3V0ZXMiOlt7Im1vZGVsIjoiZ3B0LTRvIn1dfQ==", true},
		{"b64-json-partial-head-kept", "eyJyb3V0ZXMiOlt7Im1vZGVsIjoiZ3B0LTRvIiwid2VpZ2h0IjowLjZ9LHsibW9k", false},
		{"b64-json-partial-mid-kept", "ZWwiOiJjbGF1ZGUtb3B1cyIsIndlaWdodCI6MC40fV0sImZhbGxiYWNrIjoiY2xh", false},
		// RECALL GUARDS — random base64 secrets decode to non-printable bytes -> kept
		{"random-b64-secret-kept", "vO7GdEdFrPo+2vrsz643CaG7gdHjbi6gaTlBst/mZq19Kp", false},
		{"random-b64-secret-kept-2", "s4ZxwIhq7loRJF+DKJfsMiOBF73ldjUr7a5M2SJhWk73Lr", false},
		{"basic-auth-b64-kept", "dXNlcjpwYXNzd29yZA==", false}, // user:password, printable but no JSON marker
		{"sendgrid-like-kept", "SG.nE8knNywwT9DmLHtadE5XL.nwI05iEXn69jxFD2R", false},
	}
	for _, c := range cases {
		if got := IsBase64EncodedText(c.in); got != c.want {
			t.Errorf("IsBase64EncodedText(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCryptoAndTraceRecognizers(t *testing.T) {
	cases := []struct {
		name, in string
		want     bool
	}{
		{"eth-address-lower", "0x71c7656ec7ab88b098defb751b7401b5f6d8976f", true},
		{"eth-address-checksum", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", true},
		{"cert-serial-0x", "0x3a4b5c6d7e8f9012", true},
		{"btc-bech32", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", true},
		{"w3c-traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", true},
		// recall guards
		{"secret-with-0x-substr-kept", "key0xAb3xKp9Qm2Lr7TzWqDvNc", false},
		{"random-secret-kept", "aB3xKp9Qm2Lr7TzWqDvNcEdFgHiJ", false},
	}
	for _, c := range cases {
		if got := IsExcludedEntropyValue(c.in); got != c.want {
			t.Errorf("IsExcludedEntropyValue(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestRelayGlobalIDs(t *testing.T) {
	cases := []struct {
		name, in string
		want     bool
	}{
		// "name:value" base64 is NO LONGER suppressed (ambiguous with basic-auth) — recall wins
		{"relay-user-now-kept", "VXNlcjoxMjM0NTY3ODkw", false}, // User:1234567890
		{"relay-product-now-kept", "UHJvZHVjdDo5ODc2NTQzMjEw", false},
		// recall guards: base64 basic-auth (word / hex / numeric password) must be KEPT
		{"basic-auth-word-kept", "dXNlcjpwYXNzd29yZA==", false},       // user:password
		{"basic-auth-symbol-kept", "YWRtaW46czNjcjN0UEBzcw==", false}, // admin:s3cr3tP@ss
		{"basic-auth-hex-kept", "dXNlcjpkZWFkYmVlZg==", false},        // user:deadbeef (Greptile)
		{"basic-auth-hex-kept-2", "dXNlcjpjYWZlYmFiZQ==", false},      // user:cafebabe (Greptile)
	}
	for _, c := range cases {
		if got := IsBase64EncodedText(c.in); got != c.want {
			t.Errorf("IsBase64EncodedText(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestDashedLowercasePhrase(t *testing.T) {
	cases := []struct {
		name, in string
		want     bool
	}{
		// k8s pod/service name fragment the Fastly detector mis-fires on
		{"fastly-pod-name-fragment", "-prometheus-exporter-prometheus-", true},
		{"service-phrase", "auth-gateway-service", true},
		// RECALL GUARDS — a real Fastly token (mixed case + digits) must stay flagged
		{"real-fastly-token-kept", "TVAWji0p7uDI6OP9DyWvmV-vgoUoXIuf", false},
		{"real-token-no-sep-kept", "xY3kP9mQ2rT7wL5nA8bC4dE6fG0hJ1kM", false},
		{"hex-token-kept", "9e107d9d372bb6826bd81d3542a419d6", false},
		{"single-word-kept", "prometheus", false},
		{"digity-phrase-kept", "worker-01-abc9", false},
	}
	for _, c := range cases {
		if got := IsDashedLowercasePhrase(c.in); got != c.want {
			t.Errorf("IsDashedLowercasePhrase(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestHexIDInContext(t *testing.T) {
	cases := []struct {
		name, value, before string
		want                bool
	}{
		// distributed-tracing / observability hex IDs preceded by their label -> suppressed
		{"w3c-span-id", "00f067aa0ba902b7", "the api_key call shows span_id=", true},
		{"w3c-trace-id", "4bf92f3577b34da6a3ce929d0e0e4736", "under trace ", true},
		{"sentry-event-id", "fedcba0987654321fedcba0987654321", "event_id: ", true},
		{"sourcemap-build-hash", "7a8b9c0d1e2f3a4b", "build hash: ", true},
		{"xray-self-segment", "2d8b4f0a7c6e3d9b1", "  Self=", true},
		{"correlation-id", "a1b2c3d4e5f6a7b8", "correlation_id=", true},
		// RECALL GUARDS — a real credential label must NOT be treated as a trace label
		{"api-key-hex-kept", "4bf92f3577b34da6a3ce929d0e0e4736", "API_KEY=", false},
		{"secret-hex-kept", "9e107d9d372bb6826bd81d3542a419d6", "client_secret: ", false},
		{"root-token-hex-kept", "9e107d9d372bb6826bd81d3542a419d6", "root_token=", false},
		{"non-hex-value-kept", "Kj8n2mP9xL5vR7tYqZ", "span_id=", false},
		{"too-short-kept", "00f067aa", "span_id=", false},
		{"no-label-kept", "4bf92f3577b34da6a3ce929d0e0e4736", "the value is ", false},
	}
	for _, c := range cases {
		if got := IsHexIDInContext(c.value, c.before); got != c.want {
			t.Errorf("%s: IsHexIDInContext(%q, %q)=%v want %v", c.name, c.value, c.before, got, c.want)
		}
	}
}
