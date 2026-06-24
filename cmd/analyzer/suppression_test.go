package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

func heuristicScanner(t *testing.T, mode suppressionMode) *scanner {
	t.Helper()
	cfg := defaultScannerConfig()
	cfg.entropyThreshold = 0.7
	cfg.mode = mode
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s
}

func sameShapeToken(i int) string {
	b := []byte("aB3xKp9Qm2Lr7TzW")
	b[1] = byte('A' + i%26)
	b[2] = byte('0' + i%10)
	b[4] = byte('a' + (i/10)%26)
	b[7] = byte('A' + (i/3)%26)
	return string(b)
}

func bulkDoc(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "secret = %s\n", sameShapeToken(i))
	}
	return sb.String()
}

func countEntity(results []analyzeResult, entity string) int {
	c := 0
	for _, r := range results {
		if r.EntityType == entity {
			c++
		}
	}
	return c
}

func TestParseSuppressionMode(t *testing.T) {
	require.Equal(t, suppressionEnforce, parseSuppressionMode(""))
	require.Equal(t, suppressionEnforce, parseSuppressionMode("nonsense"))
	require.Equal(t, suppressionEnforce, parseSuppressionMode("enforce"))
	require.Equal(t, suppressionShadow, parseSuppressionMode("shadow"))
	require.Equal(t, suppressionShadow, parseSuppressionMode("  SHADOW "))
	require.Equal(t, suppressionOff, parseSuppressionMode("off"))
	require.Equal(t, suppressionOff, parseSuppressionMode(" OFF "))
	require.Equal(t, "off", suppressionOff.String())
	require.Equal(t, "shadow", suppressionShadow.String())
	require.Equal(t, "enforce", suppressionEnforce.String())
}

func TestShapeKey(t *testing.T) {
	require.Equal(t, "1w", shapeKey("n27p22cchdt2k3kx"))
	require.Equal(t, "1w-", shapeKey("PP-R-HHU-624544734"))
	require.Equal(t, "2w_", shapeKey("du_1TIUcBBrSQGfJTjiR3r4WQh4"))
	require.Equal(t, shapeKey("n27p22cchdt2k3kx"), shapeKey("abcdefghijklmnop"), "alnum tokens of equal length group regardless of digit presence")
}

func TestDocumentShapes(t *testing.T) {
	shapes := documentShapes([]byte(bulkDoc(25)))
	require.Equal(t, 25, shapes["1w"])
	require.NotContains(t, shapes, shapeKey("secret"))
}

func TestDecideSuppression(t *testing.T) {
	bulkShapes := map[string]int{"1w": bulkListMinCount}
	belowShapes := map[string]int{"1w": bulkListMinCount - 1}

	hex32 := "9e107d9d372bb6826bd81d3542a419d6"
	cases := []struct {
		name       string
		entity     string
		raw        string
		doc        string
		shapes     map[string]int
		wantSup    bool
		wantReason string
	}{
		{"vendor bypass", "Github", "ghp_0123456789abcdefghijklmnopqrstuvwxyz", "", bulkShapes, false, ""},
		{"private key bypass", customdetectors.PrivateKeyName, "private-key-material-test", "", bulkShapes, false, ""},
		{"stripe object id", customdetectors.EntropyName, "du_1TIUcBBrSQGfJTjiR3r4WQh4", "", nil, true, reasonStripeObjID},
		{"bulk list at threshold", customdetectors.EntropyName, "n27p22cchdt2k3kx", "", bulkShapes, true, reasonBulkList},
		{"bulk list below threshold", customdetectors.EntropyName, "n27p22cchdt2k3kx", "", belowShapes, false, ""},
		{"lone generic secret", customdetectors.GenericSecretName, "aB3xKp9Qm2Lr7TzWqDvNcEdF", "", map[string]int{}, false, ""},
		{"short secret not bulk-suppressed", customdetectors.GenericSecretName, "aB3x9", "", map[string]int{shapeKey("aB3x9"): bulkListMinCount}, false, ""},
		{"hex32 checksum row suppressed", customdetectors.EntropyName, hex32, hex32 + "  vendor/lib.js", map[string]int{}, true, reasonHexHash},
		{"hex32 value of api_key kept", customdetectors.GenericSecretName, hex32, "api_key = " + hex32, map[string]int{}, false, ""},
		{"hex32 value of secret kept", customdetectors.EntropyName, hex32, "signing_secret: " + hex32, map[string]int{}, false, ""},
		{"hex32 uri password kept", customdetectors.EntropyName, hex32, "mongodb://svc:" + hex32 + "@db.internal:27017/app", map[string]int{}, false, ""},
		{"hex32 far from keyword kept", customdetectors.GenericSecretName, hex32, "the api token for the service is finally " + hex32, map[string]int{}, false, ""},
		{"hex32 newline credential kept", customdetectors.GenericSecretName, hex32, "config:\n  password:\n    " + hex32, map[string]int{}, false, ""},
		{"generic full uuid suppressed", customdetectors.GenericSecretName, "a4b3b545-24ec-11f0-9f57-2256ab8c9def", "", map[string]int{}, true, reasonStructural},
		{"generic truncated uuid suppressed", customdetectors.GenericSecretName, "a4b3b545-24ec-11f0-9f57-22", "", map[string]int{}, true, reasonStructural},
		{"generic org id suppressed", customdetectors.GenericSecretName, "org-AbC123XyZ", "", map[string]int{}, true, reasonStructural},
		{"generic url path suppressed", customdetectors.GenericSecretName, "/v1/users/list", "", map[string]int{}, true, reasonStructural},
		{"generic date suppressed", customdetectors.GenericSecretName, "2026-06-22T10", "", map[string]int{}, true, reasonStructural},
		{"generic mixed alnum secret kept", customdetectors.GenericSecretName, "aB3xKp9Qm2Lr7TzWqDvNcEdF", "", map[string]int{}, false, ""},
		{"generic weak alpha password kept", customdetectors.GenericSecretName, "changeme", "", map[string]int{}, false, ""},
		{"db uri not structurally suppressed", customdetectors.DBConnectionURIName, "postgres://app:s3cretP4ss@db.prod:5432/billing", "", map[string]int{}, false, ""},
		{"entropy uuid not gated here", customdetectors.EntropyName, "a4b3b545-24ec-11f0-9f57-2256ab8c9def", "", map[string]int{}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.doc)
			start, end := -1, -1
			if byteStart := strings.Index(tc.doc, tc.raw); byteStart >= 0 {
				start = utf8.RuneCountInString(tc.doc[:byteStart])
				end = start + utf8.RuneCountInString(tc.raw)
			}
			f := analyzeResult{EntityType: tc.entity, raw: tc.raw, Start: start, End: end}
			sup, reason := decideSuppression(f, tc.shapes, data)
			require.Equal(t, tc.wantSup, sup)
			require.Equal(t, tc.wantReason, reason)
		})
	}
}

func TestScanOffEmitsBulkList(t *testing.T) {
	doc := []byte(bulkDoc(25))
	results := heuristicScanner(t, suppressionOff).scan(context.Background(), doc, 0.75)
	require.Greater(t, len(results), bulkListMinCount-1, "off mode must emit the bulk findings unchanged")
}

func TestScanEnforceSuppressesBulkList(t *testing.T) {
	doc := []byte(bulkDoc(25))
	results := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
	require.Equal(t, 0, len(results), "enforce mode must suppress the entire same-shape bulk list")
}

func TestScanShadowEmitsSameAsOff(t *testing.T) {
	doc := []byte(bulkDoc(25))
	off := heuristicScanner(t, suppressionOff).scan(context.Background(), doc, 0.75)
	shadow := heuristicScanner(t, suppressionShadow).scan(context.Background(), doc, 0.75)
	require.Equal(t, len(off), len(shadow), "shadow mode must emit the same findings as off mode")
}

func TestScanBulkListBoundary(t *testing.T) {
	below := heuristicScanner(t, suppressionEnforce).scan(context.Background(), []byte(bulkDoc(bulkListMinCount-1)), 0.75)
	require.Greater(t, len(below), 0, "below threshold must not be treated as a bulk list")

	at := heuristicScanner(t, suppressionEnforce).scan(context.Background(), []byte(bulkDoc(bulkListMinCount)), 0.75)
	require.Equal(t, 0, len(at), "at threshold the bulk list must be suppressed")
}

func TestScanVendorSurvivesInBulkList(t *testing.T) {
	doc := bulkDoc(25) + "export GITHUB_TOKEN=" + fakeGithubPAT + "\n"
	results := heuristicScanner(t, suppressionEnforce).scan(context.Background(), []byte(doc), 0.75)
	require.Equal(t, 1, countEntity(results, "Github"), "vendor finding must bypass the bulk-list gate")
}

func TestScanLoneHeuristicSecretSurvivesEnforce(t *testing.T) {
	doc := []byte("api_key = aB3xKp9Qm2Lr7TzWqDvNcEdFgHiJ")
	results := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
	require.Greater(t, len(results), 0, "a lone heuristic secret must not be suppressed")
}

func TestScanSuppressesStructuralLocators(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"relative path near keyword", "secret config: cat webapp/api/v1/routes.py"},
		{"service path near keyword", "api key file webapp/services/organization_service.py"},
		{"npm scoped package near keyword", "auth token package @auth0/auth0-mcp-server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(tc.doc)
			off := heuristicScanner(t, suppressionOff).scan(context.Background(), doc, 0.75)
			enforce := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
			require.GreaterOrEqual(t, len(off), len(enforce))
			require.Equal(t, 0, len(enforce), "structural locator must not be reported as a secret")
		})
	}
}

func TestScanKeepsSlashSecretNearKeyword(t *testing.T) {
	doc := []byte("secret key aB3x/Kp9Q/m2Lr7TzWqDvNcEd here")
	results := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
	require.Greater(t, len(results), 0, "a mixed-case slash secret must still be detected")
}

func TestScanSuppressesSingleStripeObjectID(t *testing.T) {
	doc := []byte("the dispute token is du_1TIUcBBrSQGfJTjiR3r4WQh4 ok")
	off := heuristicScanner(t, suppressionOff).scan(context.Background(), doc, 0.75)
	require.Greater(t, len(off), 0, "the Stripe object id should be detected before suppression")
	enforce := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
	require.Equal(t, 0, len(enforce), "a lone Stripe object id must be suppressed structurally")
}
