package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Tokens are split at their prefix so none exists as a contiguous literal.
const (
	testAWSID      = "AKIA" + "QYLPMN5HHHFPZAM2"
	testAWSSecret  = "1tUm636uS1yOEcfP5pvfqJ/ml36mF7AkyHsEU0IU"
	testLoginToken = "Kq7xP2mR9vTw4yZ8bN3cL6fH1jD5gS0aEuWoYiXe"
	testGitHub     = "ghp_" + "Xq7Lm2Nk9Pv4Rs8Tw1Yz3Ab5Cd6Ef7Gh8Ij9K"
)

func spans(s *scanner, text string) []string {
	var out []string
	for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
		out = append(out, fmt.Sprintf("%s=%s", r.EntityType, string([]rune(text)[r.Start:r.End])))
	}
	return out
}

func hmacJWT(t *testing.T, claims string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." +
		enc([]byte("0123456789abcdef0123456789abcdef"))
}

// Every in-process custom detector shares one type, so the keyword index can
// only tell them apart by version. Two with the same version silently replace
// each other.
func TestCustomDetectorsHaveDistinctKeys(t *testing.T) {
	for _, k := range []string{"ENABLE_GENERIC_SECRETS", "ENABLE_PRIVATE_KEY", "ENABLE_ENTROPY_PROXIMITY"} {
		t.Setenv(k, "true")
	}
	cfg, err := scannerConfigFromEnv()
	require.NoError(t, err)
	dets, err := buildDetectors(cfg)
	require.NoError(t, err)
	seen := map[ahocorasick.DetectorKey]string{}
	for _, d := range dets {
		key := ahocorasick.CreateDetectorKey(d)
		name := fmt.Sprintf("%T", d)
		require.NotContains(t, seen, key, "%s shares a detector key with %s", name, seen[key])
		seen[key] = name
	}
}

func TestNewDetectorsFillSecretParts(t *testing.T) {
	ctx := context.Background()
	login := "jane.doe@acme.com/token:" + testLoginToken
	zd, err := customdetectors.NewEmailTokenLogin().FromData(ctx, false, []byte(login))
	require.NoError(t, err)
	require.Len(t, zd, 1)
	require.Equal(t, map[string]string{"email": "jane.doe@acme.com", "token": testLoginToken}, zd[0].SecretParts)
	tok := hmacJWT(t, `{"sub":"svc"}`)
	jw, err := customdetectors.NewJWTHMAC().FromData(ctx, false, []byte("Bearer "+tok))
	require.NoError(t, err)
	require.Len(t, jw, 1)
	require.Equal(t, map[string]string{"key": tok}, jw[0].SecretParts)
}

func TestEmailTokenLoginIsOneSecretIncludingItsEmail(t *testing.T) {
	s := prodScanner(t)
	login := "jane.doe@acme.com/token:" + testLoginToken
	for _, text := range []string{
		login,
		"curl https://support.acme.io/api/v2/tickets.json -u " + login,
		`{"username": "` + login + `"}`,
	} {
		require.Equal(t, []string{"email-token-login=" + login}, spans(s, text), text)
	}
	// Only the token decides whether a login is a placeholder, not the address.
	sample := "jane.sample@acme.com/token:" + testLoginToken
	require.Equal(t, []string{"email-token-login=" + sample}, spans(s, sample))
	encoded := base64.StdEncoding.EncodeToString([]byte(sample))
	require.Equal(t, []string{"email-token-login=" + encoded}, spans(s, "Authorization: Basic "+encoded))

	for _, text := range []string{
		"jane.doe@acme.com/token:" + testLoginToken[:39],
		"jane.doe@acme.com/token:" + testLoginToken + "x",
		"see https://support.acme.io/token: for details",
		"you@acme.com/token:" + strings.Repeat("x", 40),
		"you@acme.com/token:" + strings.Repeat("exampletoken", 4)[:40],
	} {
		require.NotContains(t, strings.Join(spans(s, text), " "), "email-token-login", text)
	}
}

func TestHMACJWTIsReportedUnlessExpired(t *testing.T) {
	s := prodScanner(t)
	live := hmacJWT(t, fmt.Sprintf(`{"sub":"svc","exp":%d}`, time.Now().Add(24*time.Hour).Unix()))
	noExp := hmacJWT(t, `{"sub":"svc","iat":1728000000}`)
	for _, tok := range []string{live, noExp} {
		require.Equal(t, []string{"JWT=" + tok}, spans(s, "Authorization: Bearer "+tok))
	}
	for _, claims := range []string{`{"sub":"svc","exp":1600000000}`, `{"sub":"svc","exp":"1600000000"}`} {
		expired := hmacJWT(t, claims)
		require.NotContains(t, strings.Join(spans(s, "Authorization: Bearer "+expired), " "), "JWT", claims)
	}
	// Claim names are case-sensitive: a custom "EXP" is not the expiry.
	for _, claims := range []string{fmt.Sprintf(`{"sub":"svc","exp":"%d"}`, time.Now().Add(time.Hour).Unix()), `{"sub":"svc","exp":{"at":"later"}}`,
		`{"sub":"svc","exp":4102444800,"EXP":1600000000}`} {
		tok := hmacJWT(t, claims)
		require.Equal(t, []string{"JWT=" + tok}, spans(s, "Authorization: Bearer "+tok), claims)
	}

	enc := base64.RawURLEncoding.EncodeToString
	hyphenEnd := enc([]byte(`{"alg":"HS384","typ":"JWT"}`)) + "." + enc([]byte(`{"sub":"svc"}`)) + "." +
		"49O0ZGaFZBRrev0Xy1HC9L5dFlnJEafXpCm1BmI-CaJBfFwGRbyypuPQzVcQS---"
	require.Equal(t, []string{"JWT=" + hyphenEnd}, spans(s, `"token": "`+hyphenEnd+`"`))

	// The header is JSON, so the algorithm name may be escaped.
	escaped := enc([]byte(`{"alg":"HS\u0032\u0035\u0036"}`)) + "." + enc([]byte(`{"sub":"svc"}`)) + "." +
		strings.Split(hmacJWT(t, `{"sub":"svc"}`), ".")[2]
	require.Equal(t, []string{"JWT=" + escaped}, spans(s, "token: "+escaped))

	for _, claims := range []string{`{"uid":1}`, `{}`, `{ "sub":"svc"}`, `{ }`, "{\n  \"sub\": \"svc\"\n}", "{\t\"sub\":\"svc\"}"} {
		tok := hmacJWT(t, claims)
		require.Equal(t, []string{"JWT=" + tok}, spans(s, "token: "+tok), claims)
	}
	spacedHeader := enc([]byte(`{ "alg": "HS256" }`)) + "." + enc([]byte(`{"sub":"svc"}`)) + "." +
		enc([]byte("0123456789abcdef0123456789abcdef"))
	require.Equal(t, []string{"JWT=" + spacedHeader}, spans(s, "token: "+spacedHeader))
	sig := enc([]byte("0123456789abcdef0123456789abcdef"))
	for _, pair := range [][2]string{
		{`{ "alg": "HS256" }`, `{ "sub": "svc" }`},
		{"{\n  \"alg\": \"HS256\"\n}", "{\n  \"sub\": \"svc\"\n}"},
		{"{\t\"alg\":\"HS256\"}", "{\t\"sub\":\"svc\"}"},
		{"{\r\n  \"alg\": \"HS256\"\r\n}", "{\r\n  \"sub\": \"svc\"\r\n}"},
	} {
		tok := enc([]byte(pair[0])) + "." + enc([]byte(pair[1])) + "." + sig
		require.Equal(t, []string{"JWT=" + tok}, spans(s, "token: "+tok), pair[0])
	}
	padded := hmacJWT(t, `{"sub":"svc"}`) + "="
	require.Equal(t, []string{"JWT=" + padded}, spans(s, `"token": "`+padded+`"`))

	// Large enough that no single scan window holds it whole.
	big := hmacJWT(t, `{"sub":"svc","roles":"`+strings.Repeat("reader,", 260)+`"}`)
	text := strings.Repeat("log line before the token\n", 70) + "Authorization: Bearer " + big
	require.Greater(t, len(big), scanWindowPeek)
	require.Contains(t, spans(s, text), "JWT="+big)
}

func TestEncodedCredentialsAreFoundAndNamed(t *testing.T) {
	s := prodScanner(t)
	b64 := base64.StdEncoding.EncodeToString
	pair := b64([]byte("AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret))
	gh := b64([]byte("GITHUB_TOKEN=" + testGitHub))
	dsn := b64([]byte("postgres://app:Hx7Qm2Vr9Lp4@db.acme.io:5432/main"))
	basic := b64([]byte("jane.doe@acme.com/token:" + testLoginToken))
	cases := []struct{ text, want string }{
		{"echo " + pair + " | base64 -d", "AWS=" + pair},
		{"TOKEN_B64=" + gh, "Github=" + gh},
		{"kind: Secret\ndata:\n  DATABASE_URL: " + dsn, "Postgres=" + dsn},
		{"Authorization: Basic " + basic, "email-token-login=" + basic},
		{"url-safe " + base64.URLEncoding.EncodeToString([]byte("GITHUB_TOKEN="+testGitHub)), ""},
	}
	for _, c := range cases {
		got := spans(s, c.text)
		if c.want == "" {
			require.Len(t, got, 1, c.text)
			require.True(t, strings.HasPrefix(got[0], "Github="), "%s: %v", c.text, got)
			continue
		}
		require.Equal(t, []string{c.want}, got, c.text)
	}
}

// Runs a named finding already covers, such as the segments of a JWT, do not
// spend the decode budget, so a prompt full of tokens cannot hide an encoded key.
func TestCoveredRunsDoNotSpendTheDecodeBudget(t *testing.T) {
	s := prodScanner(t)
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("Authorization: Bearer " + hmacJWT(t, fmt.Sprintf(`{"sub":"svc-%d"}`, i)) + "\n")
	}
	pair := base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret))
	b.WriteString("echo " + pair + " | base64 -d\n")
	require.Contains(t, spans(s, b.String()), "AWS="+pair)
}

// Every long identifier or path is a candidate run. Counting each one's offset
// from the start of the request made a 1 MB prompt of them take seconds.
func TestDecodePassStaysLinearOnManyCandidateRuns(t *testing.T) {
	s := prodScanner(t)
	var b strings.Builder
	for i := 0; b.Len() < 1_000_000; i++ {
		fmt.Fprintf(&b, "handleIncomingWebhookPayloadForTenant%dProvisioning ", i)
	}
	text := []byte(b.String()[:1_000_000])
	t0 := time.Now()
	s.scan(context.Background(), text, 0.75)
	require.Less(t, time.Since(t0), 2*time.Second)
}

// Readable runs that hold nothing cannot push a later key out of the decode
// pass: the budget is the decoded size, not the number of runs.
func TestHarmlessEncodedRunsDoNotHideALaterKey(t *testing.T) {
	s := prodScanner(t)
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString(base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("log line %06d ok", i))) + "\n")
	}
	pair := base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret))
	b.WriteString("echo " + pair + " | base64 -d\n")
	require.Contains(t, spans(s, b.String()), "AWS="+pair)
}

// GNU base64 and MIME wrap their output at 76 or 64 characters; the wrapped
// lines are one value. Unrelated lines that follow a run are not glued on.
func TestWrappedBase64IsDecodedAsOneValue(t *testing.T) {
	s := prodScanner(t)
	pair := base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret))
	for _, width := range []int{76, 64} {
		var lines []string
		for rest := pair; rest != ""; {
			n := min(width, len(rest))
			lines = append(lines, rest[:n])
			rest = rest[n:]
		}
		wrapped := strings.Join(lines, "\n")
		require.Contains(t, spans(s, "$ base64 creds.env\n"+wrapped+"\n$ "), "AWS="+wrapped, "width %d", width)
	}
	dsn := base64.StdEncoding.EncodeToString([]byte("postgres://app:Hx7Qm2Vr9Lp4@db.acme.io:5432/main"))
	text := "data:\n  DATABASE_URL: " + dsn + "\nAPI_KEY_NAME_FOR_THE_BILLING_SERVICE: unset"
	require.Contains(t, spans(s, text), "Postgres="+dsn)

	// A full-width line that is a whole value on its own: padded, or followed by
	// text that does not continue it.
	padded := base64.StdEncoding.EncodeToString([]byte("postgres://app:Hx7Qm2Vr9Lp4@db.acme.io:5432/mai"))
	require.Len(t, padded, 64)
	require.Contains(t, spans(s, padded+"\necho done"), "Postgres="+padded)
	require.Len(t, dsn, 64)
	require.Contains(t, spans(s, dsn+"\necho done"), "Postgres="+dsn)

	// Two full 76-character lines of one value, then an unrelated line.
	env := "AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret + "\nregion=us-e1"
	enc := base64.StdEncoding.EncodeToString([]byte(env))
	require.Len(t, enc, 152)
	twoLines := enc[:76] + "\n" + enc[76:]
	require.Contains(t, spans(s, twoLines+"\necho done"), "AWS="+twoLines)

	// A full-width line that decodes to nothing readable, then a key on its own line.
	binary := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x01\x9f\xe2", 19)))
	require.Len(t, binary, 76)
	gh := base64.StdEncoding.EncodeToString([]byte("GITHUB_TOKEN=" + testGitHub))
	require.Contains(t, spans(s, binary+"\n"+gh), "Github="+gh)

	// The same binary line, then a key wrapped over two lines.
	require.Contains(t, spans(s, binary+"\n"+twoLines), "AWS="+twoLines)

	// A multi-byte character split across the wrap still reads as text.
	accented := base64.StdEncoding.EncodeToString([]byte("#" + strings.Repeat("a", 55) + "é\n" + env))
	require.Equal(t, byte(0xc3), base64Decode(t, accented[:76])[56])
	wrappedAccented := accented[:76] + "\n" + accented[76:152] + "\n" + accented[152:]
	require.Contains(t, spans(s, binary+"\n"+wrappedAccented), "AWS="+wrappedAccented)

	// A last line holding only the rest of that character.
	pairNL := "AWS_ACCESS_KEY_ID=" + testAWSID + "\nAWS_SECRET_ACCESS_KEY=" + testAWSSecret + "\n"
	tail := base64.StdEncoding.EncodeToString([]byte(pairNL + strings.Repeat("x", 113-len(pairNL)) + "é"))
	require.Len(t, base64Decode(t, tail[152:]), 1)
	wrappedTail := tail[:76] + "\n" + tail[76:152] + "\n" + tail[152:]
	require.Contains(t, spans(s, binary+"\n"+wrappedTail), "AWS="+wrappedTail)

	// URL-safe base64 keeps its continuation lines.
	urlSafe := base64.URLEncoding.EncodeToString([]byte("#" + strings.Repeat("a", 46) + "\npostgres://app:Q7mN~~~2vRt9@db.acme.io:5432/main"))
	require.Contains(t, urlSafe[64:], "-")
	wrappedURLSafe := urlSafe[:64] + "\n" + urlSafe[64:]
	require.Contains(t, spans(s, wrappedURLSafe), "Postgres="+wrappedURLSafe)
}

func base64Decode(t *testing.T, s string) []byte {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	require.NoError(t, err)
	return b
}

func TestEncodedRunsWithoutCredentialsStayQuiet(t *testing.T) {
	s := prodScanner(t)
	b64 := base64.StdEncoding.EncodeToString
	png := []byte{0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 1, 0, 0, 0, 1, 0, 8, 6, 0, 0, 0}
	for _, text := range []string{
		"msg: " + b64([]byte("hello world, this is a perfectly ordinary sentence")),
		"img: data:image/png;base64," + b64(png),
		"integrity: sha512-" + b64([]byte(strings.Repeat("\x01\x9f\xe2", 22))),
		"func handleIncomingWebhookPayloadForTenantProvisioning() {}",
		"placeholder: " + b64([]byte("AWS_ACCESS_KEY_ID=AKIA"+"EXAMPLEKEY123456")),
	} {
		require.Empty(t, spans(s, text), text)
	}
}
