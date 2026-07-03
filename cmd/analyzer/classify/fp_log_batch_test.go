package classify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAtlassianNoise_LogBatch(t *testing.T) {
	noise := []string{
		"searchJiraIssuesUsingJql",             // dictionary camelCase method name
		"620b8b51eb29780068913b4d",             // 24-hex mongo object id
		"disable-model-invocation",             // kebab config key
		"-06199307-69e4-4b96-9556",             // uuid fragment with dashes
		"0d4cd6d5-0b95-49af-9e47-0687c26f8bf7", // full uuid
	}
	for _, v := range noise {
		require.True(t, IsAtlassianNoise(v), "expected noise: %q", v)
	}
	// Recall guards: real random 24-char tokens must survive.
	real := []string{
		"n27p22cchdt2k3kxabcd1234",
		"aB3xKp9Qm2Lr7TzWqDvNcEd1",
	}
	for _, v := range real {
		require.False(t, IsAtlassianNoise(v), "must keep real token: %q", v)
	}
}

func TestExcludedEntropyValue_LogBatch(t *testing.T) {
	excluded := []string{
		"ravi.raj89@thg.com",                         // email
		"anthropic.claude-sonnet-4-5@20250929",       // model id @ version
		"mcp-proxy-for-aws@1.6.0",                    // package @ semver
		"--since=2025-04-01",                         // cli date flag
		"--until=2025-06-30",                         // cli date flag
		"pk-lf-2c4e6731-06e5-4bee-9ee3-ee4fc5576866", // langfuse public key
	}
	for _, v := range excluded {
		require.True(t, IsExcludedEntropyValue(v), "expected excluded: %q", v)
	}
	// Recall guards: real secrets must NOT be excluded.
	real := []string{
		"Kx9Qm2Lr7TzWqDvNcEd-Ab3xKp8Ss4Nm1LdE", // hyphenated high-entropy token, not a vendor format
		"UY4UtWrY9Tp7zZoS-xye3QX8VIaCJOzChp8gCiBMYjk",
		"15UBVwRGHLYKhr6G_4353cSEe4OfQQ01P",
		"3be99690b46828acf0a50b21e67c8ef687783c7f995e91cec060a13a072bd4c248427b000e1a86b56e415ad9127868a9",
	}
	for _, v := range real {
		require.False(t, IsExcludedEntropyValue(v), "must keep real secret: %q", v)
	}
}

func TestIsVetoableStructural_LogBatch(t *testing.T) {
	yes := []string{
		"cmpy0w18v00086207kor30ub0",                     // cuid
		"eks-use1-dev-gen-a",                            // hyphenated resource label
		"grc-audit-LEAA720",                             // hyphenated label
		"inc.-7c2e4e83c93c51c941cb5fc8d4846aa2796673ae", // org-prefixed sha1 digest
		"a-3d5b717a-1749-4e34-890f-b033dadd8af9",        // affixed uuid
	}
	for _, v := range yes {
		require.True(t, IsVetoableStructural(v), "expected vetoable: %q", v)
	}
	no := []string{
		"UY4UtWrY9Tp7zZoS-xye3QX8VIaCJOzChp8gCiBMYjk", // real token, long segments
		"svc-tok-api03-9aQxYzLongRandomSecretValue00", // vendor-key style, long final segment
		"3be99690b46828acf0a50b21e67c8ef687783c7f9",   // bare 40-hex, no word prefix
	}
	for _, v := range no {
		require.False(t, IsVetoableStructural(v), "must keep: %q", v)
	}
}

func TestIsBenignIDContext_LogBatch(t *testing.T) {
	yes := []string{
		`"parentId": "`,
		"fileId=",
		`"objectId": `,
		"/drive/v3/files/",
		"/drive/v3/files/' + '",
	}
	for _, v := range yes {
		require.True(t, IsBenignIDContext(v), "expected benign id context: %q", v)
	}
	no := []string{
		`"apiKey": "`,
		"password = ",
		"Authorization: Bearer ",
	}
	for _, v := range no {
		require.False(t, IsBenignIDContext(v), "must not treat as benign: %q", v)
	}
}

func TestHexIDInContext_RequestID(t *testing.T) {
	reqID := "9dd7bd5199480207c738ac321062ae96"
	require.True(t, IsHexIDInContext(reqID, "x-request-id\n"))
	require.False(t, IsHexIDInContext(reqID, "api_key = "))
}

func TestIsPlaceholderURI_LogBatch(t *testing.T) {
	require.True(t, IsPlaceholderURI("https://user:pass@host"))
	require.True(t, IsPlaceholderURI("http://username:password@localhost"))
	require.False(t, IsPlaceholderURI("https://admin:S3cr3tP4ss@db.prod.internal:5432"))
}
