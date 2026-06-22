package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

func heuristicScanner(t *testing.T, mode suppressionMode) *scanner {
	t.Helper()
	dets := defaults.DefaultDetectors()
	gs, err := customdetectors.NewGenericSecret()
	require.NoError(t, err)
	dbu, err := customdetectors.NewDBConnectionURI()
	require.NoError(t, err)
	pk, err := customdetectors.NewPrivateKey()
	require.NoError(t, err)
	dets = append(dets, gs, dbu, pk, customdetectors.NewEntropyProximity(0.7))
	return &scanner{
		core:               ahocorasick.NewAhoCorasickCore(dets),
		detectors:          len(dets),
		genericSecretScore: defaultGenericSecretScore,
		mode:               mode,
	}
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

	cases := []struct {
		name       string
		entity     string
		raw        string
		shapes     map[string]int
		wantSup    bool
		wantReason string
	}{
		{"vendor bypass", "Github", "ghp_0123456789abcdefghijklmnopqrstuvwxyz", bulkShapes, false, ""},
		{"private key bypass", customdetectors.PrivateKeyName, "private-key-material-test", bulkShapes, false, ""},
		{"stripe object id", customdetectors.EntropyName, "du_1TIUcBBrSQGfJTjiR3r4WQh4", nil, true, reasonStripeObjID},
		{"bulk list at threshold", customdetectors.EntropyName, "n27p22cchdt2k3kx", bulkShapes, true, reasonBulkList},
		{"bulk list below threshold", customdetectors.EntropyName, "n27p22cchdt2k3kx", belowShapes, false, ""},
		{"lone generic secret", customdetectors.GenericSecretName, "aB3xKp9Qm2Lr7TzWqDvNcEdF", map[string]int{}, false, ""},
		{"short secret not bulk-suppressed", customdetectors.GenericSecretName, "aB3x9", map[string]int{shapeKey("aB3x9"): bulkListMinCount}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sup, reason := decideSuppression(tc.entity, tc.raw, tc.shapes)
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

func TestScanSuppressesSingleStripeObjectID(t *testing.T) {
	doc := []byte("the dispute token is du_1TIUcBBrSQGfJTjiR3r4WQh4 ok")
	off := heuristicScanner(t, suppressionOff).scan(context.Background(), doc, 0.75)
	require.Greater(t, len(off), 0, "the Stripe object id should be detected before suppression")
	enforce := heuristicScanner(t, suppressionEnforce).scan(context.Background(), doc, 0.75)
	require.Equal(t, 0, len(enforce), "a lone Stripe object id must be suppressed structurally")
}
