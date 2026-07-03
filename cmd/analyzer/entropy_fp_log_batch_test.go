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
}
