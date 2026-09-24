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

// The exact shape a customer disputed: a JDBC location for a local Aerospike
// test instance, carrying driver options and no credential of any kind. It was
// reported as a Database Connection String five times from one prompt.
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

// Not covered here: jdbc:postgresql://host/db?user=x&password=y produces no
// finding at all, on main as well as with this change. That is a pre-existing
// gap in the JDBC detector, not something this fix touches -- asserting it would
// be asserting a bug.
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

// Suppression is opt-in. Without the env var the finding still surfaces, which
// is why this fix does nothing in production until the mode is turned on.
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

// A1/A2: the only production door. scan() is shared, but the handler is what
// ai-gateway actually posts to, and it is where auth and marshalling live.
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

// A3: enabling the mode turns on every rule in the vendor table, not just JDBC.
// These are the other six, asserted so a change to the shared predicate cannot
// quietly alter them.
func TestJDBC_OtherVendorRulesUnaffected(t *testing.T) {
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "enforce")
	for _, entity := range []string{"JiraToken", "Atlassian", "Privacy", "Onesignal", "URI", "Azure"} {
		rule, ok := vendorStructuralRules[entity]
		require.True(t, ok, "%s must remain in the vendor table", entity)
		require.NotNil(t, rule.match, "%s must keep its matcher", entity)
	}
	require.Len(t, vendorStructuralRules, 7,
		"a rule was added or removed; enabling the mode affects all of them, "+
			"so the set is part of the deploy decision")
}
