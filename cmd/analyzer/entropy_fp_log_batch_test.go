package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

func TestInsidePublicPEMBlock(t *testing.T) {
	line := "MIIEbTCCA1WgAwIBAgIUfC5Og8k8UclBy1/I1IRqonlmc64wDQYJKoZIhvcNAQEL"
	// Truncated certificate (no END marker) must still be recognized as public.
	cert := []byte("k: -----BEGIN CERTIFICATE-----\\n" + line + "\\nBQAwgaMxJTAj")
	require.True(t, insidePublicPEMBlock(cert, line))

	// Private key material must never be treated as public.
	priv := []byte("-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw")
	require.False(t, insidePublicPEMBlock(priv, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw"))

	// No PEM armor at all.
	require.False(t, insidePublicPEMBlock([]byte("plain text "+line), line))

	// A stray/truncated public header must NOT suppress an unrelated secret that
	// follows it through non-base64 prose (bypass guard).
	bypass := []byte("-----BEGIN CERTIFICATE-----\\nnote to self: AKIAIOSFODNN7EXAMPLE")
	require.False(t, insidePublicPEMBlock(bypass, "AKIAIOSFODNN7EXAMPLE"))

	// Even a base64-only token right after a stray header is kept unless the body
	// begins with a DER SEQUENCE ('M'); a real secret rarely does.
	nonDER := []byte("-----BEGIN CERTIFICATE-----\\nAKIAIOSFODNN7EXAMPLE")
	require.False(t, insidePublicPEMBlock(nonDER, "AKIAIOSFODNN7EXAMPLE"))

	// If the same base64 string appears inside the cert AND again outside it,
	// suppression must NOT fire (the out-of-armor occurrence keeps recall).
	dup := []byte("k: -----BEGIN CERTIFICATE-----\\n" + line + "\\n also seen here: " + line)
	require.False(t, insidePublicPEMBlock(dup, line))
}

func TestDecideSuppression_EntropyStructural(t *testing.T) {
	cuid := "cmpy0w18v00086207kor30ub0"

	sup, reason := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: cuid},
		nil, []byte("LANGFUSE_PROJECT_ID = "+cuid+" (no secrets)"))
	require.True(t, sup)
	require.Equal(t, reasonStructuralVetoable, reason)

	// Credential assignment vetoes suppression -> recall preserved.
	supVeto, _ := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: cuid},
		nil, []byte("api_key="+cuid))
	require.False(t, supVeto)

	// Benign identifier field context.
	pid := "1TAFEVDZE1zIdiWBuey9z218nxxpbW5nt"
	supID, reasonID := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: pid},
		nil, []byte(`{"parentId": "`+pid+`"}`))
	require.True(t, supID)
	require.Equal(t, reasonBenignIDContext, reasonID)

	// A real high-entropy token near a credential keyword is kept.
	tok := "s3cretV4lueX9kQwErTyUiOpAsDf12"
	supTok, _ := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: tok},
		nil, []byte("api_key="+tok))
	require.False(t, supTok)

	// A structural value labelled by a credential-suffix field is kept.
	label := "eks-use1-dev-gen-a"
	supBenign, _ := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: label},
		nil, []byte("envs (`"+label+"`)"))
	require.True(t, supBenign)
	supLabelled, _ := decideSuppression(
		analyzeResult{EntityType: customdetectors.EntropyName, raw: label},
		nil, []byte("cluster_key="+label))
	require.False(t, supLabelled)
}

func TestVendorVetoAtlassianHex(t *testing.T) {
	hex := "620b8b51eb29780068913b4d" // 24-hex, matches IsAtlassianNoise
	// Benign actionerId url param (the corpus FP) -> suppressed.
	sup, _ := decideVendorSuppression(analyzeResult{EntityType: "Atlassian", raw: hex}, []byte("?actionerId="+hex))
	require.True(t, sup)
	// Credential-suffix label -> kept (could be a real hex token).
	supKey, _ := decideVendorSuppression(analyzeResult{EntityType: "Atlassian", raw: hex}, []byte("jira_token="+hex))
	require.False(t, supKey)
}

func TestVendorVetoPrivacy(t *testing.T) {
	uuid := "0d4cd6d5-0b95-49af-9e47-0687c26f8bf7"
	// Benign identifier label -> suppressed (the corpus FP: "Jira Cloud ID: <uuid>").
	sup, _ := decideVendorSuppression(analyzeResult{EntityType: "Privacy", raw: uuid}, []byte("- Jira Cloud ID: "+uuid))
	require.True(t, sup)
	// Credential-suffix label -> kept (a real Privacy key).
	supKey, _ := decideVendorSuppression(analyzeResult{EntityType: "Privacy", raw: uuid}, []byte("privacy_key="+uuid))
	require.False(t, supKey)
	// Standard credential assignment -> kept.
	supStd, _ := decideVendorSuppression(analyzeResult{EntityType: "Privacy", raw: uuid}, []byte("api_key: "+uuid))
	require.False(t, supStd)
}
