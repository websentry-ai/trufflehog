package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The exact shape a customer disputed: a local Aerospike location with driver
// options and no credential, reported five times from one prompt.
const aerospikeLocal = `jdbc:aerospike:localhost:3000/test?sendKey=true&timeout=5000&` +
	`totalTimeout=10000&recordsetTimeoutMs=2000&refuseScan=true&useBoolBin=false&` +
	`useServicesAlternate=true&authMode=INTERNAL`

func jdbcFindings(t *testing.T, text string) []analyzeResult {
	t.Helper()
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "enforce")
	var out []analyzeResult
	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(text), 0.75) {
		if r.EntityType == "JDBC" {
			out = append(out, r)
		}
	}
	return out
}

func TestJDBC_LocalDriverHostLocationSuppressed(t *testing.T) {
	require.Empty(t, jdbcFindings(t, aerospikeLocal),
		"a JDBC location with no credential must not be reported")
}

func TestJDBC_CredentialBearingStillReported(t *testing.T) {
	// The guards that keep this narrow, each through the real pipeline.
	for _, tc := range []struct{ name, text string }{
		{"credentials before host", `jdbc:oracle:thin:scott/tiger@dbhost:1521:orcl`},
		{"password parameter", `jdbc:aerospike:localhost:3000/test?sendKey=true&password=hunter2xyz`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEmpty(t, jdbcFindings(t, tc.text),
				"a JDBC string carrying a credential must still be reported")
		})
	}
}

// Suppression is opt-in in code, but staging and prod already run it as enforce,
// so this ships on deploy rather than waiting on a flag.
func TestJDBC_SuppressionIsOptIn(t *testing.T) {
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "off")
	var found bool
	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(aerospikeLocal), 0.75) {
		if r.EntityType == "JDBC" {
			found = true
		}
	}
	require.True(t, found,
		"with suppression off the finding must still be reported -- enabling the "+
			"mode is a separate, deliberate step")
}

// The only production door: the handler ai-gateway posts to, where auth and
// marshalling live.
func TestJDBC_ThroughAnalyzeHandler(t *testing.T) {
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "enforce")
	s := newBuiltScanner(t)
	const apiKey = "test-analyzer-key"
	h := s.analyzeHandler(apiKey)

	post := func(text string) []analyzeResult {
		body, err := json.Marshal(analyzeRequest{Text: text, ScoreThreshold: 0.75})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		h(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var out []analyzeResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		return out
	}

	hasJDBC := func(rs []analyzeResult) bool {
		for _, r := range rs {
			if r.EntityType == "JDBC" {
				return true
			}
		}
		return false
	}

	require.False(t, hasJDBC(post(aerospikeLocal)),
		"the disputed string must not be reported over HTTP")
	require.True(t, hasJDBC(post(`jdbc:oracle:thin:scott/tiger@dbhost:1521:orcl`)),
		"a credential-bearing string must still be reported over HTTP")
}

// Enabling the mode turns on every rule in the vendor table, not just JDBC.
func TestJDBC_OtherVendorRulesUnaffected(t *testing.T) {
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "enforce")
	// Each matcher runs on a value it must suppress and one it must not, so a
	// change to a shared classifier fails here, not just a change to the table.
	for _, tc := range []struct {
		entity, suppressed, reported string
	}{
		{"JiraToken", `deadbeefcafe0123456789ab`, `ATATT3xFfGF0T4ABCDEF`},
		{"Atlassian", `order-service-payment-gateway`, `ATATT3xFfGF0T4ABCDEF`},
		{"Privacy", `3f2504e0-4f89-11d3-9a0c-0305e82c3301`, `AKIASP2TPHJSQH3FJRUX`},
		{"Onesignal", `3f2504e0-4f89-11d3-9a0c-0305e82c3301`, `AKIASP2TPHJSQH3FJRUX`},
		{"URI", `postgres://user:password@host:5432/db`, `postgres://admin:9xKq2vRt8mNp@host:5432/db`},
		{"Azure", `webapp.config.connectionString`, `9xKq2vRt8mNpQrLwZbNh`},
	} {
		rule, ok := vendorStructuralRules[tc.entity]
		require.True(t, ok, "%s must remain in the vendor table", tc.entity)
		require.NotNil(t, rule.match, "%s must keep its matcher", tc.entity)
		require.True(t, rule.match(tc.suppressed),
			"%s must still suppress %q", tc.entity, tc.suppressed)
		require.False(t, rule.match(tc.reported),
			"%s must still report %q", tc.entity, tc.reported)
	}
	require.Len(t, vendorStructuralRules, 7,
		"a rule was added or removed; enabling the mode affects all of them, "+
			"so the set is part of the deploy decision")
}
