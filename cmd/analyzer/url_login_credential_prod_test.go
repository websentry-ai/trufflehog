package main

import (
	"context"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// prodScanner builds the scanner from the environment prod runs with
// (k8s/prod/values.yaml), through the same constructor the service uses.
func prodScanner(t *testing.T) *scanner {
	t.Helper()
	for k, v := range map[string]string{
		"ENTROPY_THRESHOLD": "0.7", "ENABLE_GENERIC_SECRETS": "false",
		"ENABLE_PRIVATE_KEY": "true", "ENABLE_ENTROPY_PROXIMITY": "true",
		"FP_SUPPRESSION_MODE": "enforce", "VENDOR_STRUCTURAL_SUPPRESSION": "enforce",
	} {
		t.Setenv(k, v)
	}
	cfg, err := scannerConfigFromEnv()
	require.NoError(t, err)
	s, err := buildScanner(cfg)
	require.NoError(t, err)
	return s
}

func fakePassword(n int, seed int64) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// entitiesOver returns the entity types reported on [start, end) at the
// threshold the gateway sends.
func entitiesOver(t *testing.T, s *scanner, text, secret string) []string {
	t.Helper()
	ps := strings.Index(text, secret)
	pe := ps + len(secret)
	var got []string
	for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
		if r.Start < pe && r.End > ps {
			got = append(got, r.EntityType)
		}
	}
	return got
}

// Every scheme the email recognizer treats as a login slot, at every length.
// Under prod's configuration most of these reported nothing at all -- ssh, git,
// sftp and the SQL schemes at any length, everything else past 50 or 60.
func TestURLLogin_EveryLoginSchemeIsCaughtUnderProdConfig(t *testing.T) {
	s := prodScanner(t)
	schemes := []string{"https", "http", "wss", "ftp", "sftp", "ssh", "git", "svn",
		"postgres", "postgresql", "mysql", "mariadb", "redis", "rediss", "mongodb",
		"amqp", "ldap", "smtp", "imap"}
	for i, scheme := range schemes {
		for _, n := range []int{8, 30, 60, 120, 900} {
			pw := fakePassword(n, int64(i*1000+n))
			text := scheme + "://svc:" + pw + "@host.acme.io/repo/simple/"
			require.NotEmpty(t, entitiesOver(t, s, text, pw), "%s password of %d", scheme, n)
		}
	}
}

// The reported shape: an HS256 JWT as the password. The JWT detector skips
// HMAC tokens by design, so nothing else reports it.
func TestURLLogin_AnHS256TokenInTheLoginIsCaught(t *testing.T) {
	s := prodScanner(t)
	enc := base64.RawURLEncoding.EncodeToString
	jwt := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"sub":"SVC_API_KEY","exp":1891521431,"jti":"`+fakePassword(43, 7)+`"}`)) + "." +
		fakePassword(43, 8)
	text := "pip install --index-url https://artifactory:" + jwt + "@pkg.acme.io/repo/api/pypi/pypi/simple/ requests"
	require.Equal(t, []string{"url-login-credential"}, entitiesOver(t, s, text, jwt))
}

// Where a vendor detector already fires, it keeps its specific name. Each of
// them reports the whole URL, which is wider than the password this one
// reports, so they win the overlap at equal score.
func TestURLLogin_VendorDetectorsKeepTheirNames(t *testing.T) {
	s := prodScanner(t)
	for scheme, want := range map[string]string{
		"https": "URI", "ftp": "FTP", "redis": "Redis", "mongodb": "MongoDB", "amqp": "RabbitMQ",
	} {
		pw := fakePassword(20, 11)
		text := scheme + "://svc:" + pw + "@host.acme.io/repo"
		require.Equal(t, []string{want}, entitiesOver(t, s, text, pw), scheme)
	}
}

// A login longer than the window overlap is missed by every window when it
// starts in the gap between where one window can hold it and the next begins,
// so only the long-form pass reports it there.
func TestURLLogin_ALoginLongerThanTheWindowOverlapIsCaught(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(1500, 21)
	login := "https://svc:" + pw + "@pkg.acme.io"
	// A window starting at 0 holds the match only if it starts by
	// size+peek-len(login); the next window starts at size.
	gapStart := scanWindowSize + scanWindowPeek - len(login)
	require.Less(t, gapStart, scanWindowSize, "the login must outgrow the overlap")
	for _, at := range []int{gapStart + 1, (gapStart + scanWindowSize) / 2, scanWindowSize - 1} {
		text := strings.Repeat(" ", at) + login + "/simple/"
		require.NotEmpty(t, entitiesOver(t, s, text, pw), "login starting at %d", at)
	}
}

// Real addresses near a URL stay out of the secrets path.
func TestURLLogin_AddressesAreNotCredentials(t *testing.T) {
	s := prodScanner(t)
	for _, text := range []string{
		"unsubscribe at https://app.acme.com/u/jane@gmail.com please",
		"https://acme.com/invite?to=jane@gmail.com",
		"https://jane@acme.io/dashboard",
	} {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			require.NotEqual(t, "url-login-credential", r.EntityType, text)
		}
	}
}

// The dummy logins that fill READMEs and compose files are not credentials. None
// of these was blocked before the detector existed -- the email recognizer drops
// localhost and example.com -- so reporting them would be a new false positive.
func TestURLLogin_PlaceholderPasswordsAreNotReported(t *testing.T) {
	s := prodScanner(t)
	for _, text := range []string{
		"DATABASE_URL=postgres://user:password@localhost:5432/db",
		"REDIS_URL=redis://:password@localhost:6379",
		"mysql://root:root@127.0.0.1:3306/app",
		"https://user:pass@example.com/api",
		"amqp://guest:guest@localhost:5672/",
		"https://deploy:changeme@git.acme.io/team/repo.git",
		"postgres://postgres:postgres@localhost:5432/postgres",
		"mysql://root:mysql@127.0.0.1:3306/app",
		"ftp://anonymous:anonymous@ftp.acme.org/pub/",
		`url = f"postgresql://{user}:{password}@{host}/{db}"`,
		`"postgres://{0}:{1}@{2}/db".format(user, pw, host)`,
		`"mysql://%(user)s:%(password)s@%(host)s/app" % cfg`,
		"redis://:$(REDIS_PASS)@cache.acme.io:6379",
		"postgres://user:your_password@localhost:5432/db",
		"https://deploy:my-dummy-pass@git.acme.io/team/repo.git",
		"mysql://app:REDACTED@db.acme.io/app",
		"https://u:change-me@pkg.acme.io/simple/",
		`fmt.Sprintf("postgres://%s:%s@%s/db", u, p, h)`,
	} {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			require.NotEqual(t, "url-login-credential", r.EntityType, text)
		}
	}
}

// It keys on the password, never the host: a real one on localhost still reports.
func TestURLLogin_ARealPasswordOnALocalHostIsStillReported(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 31)
	for _, host := range []string{"localhost:5432", "127.0.0.1:3306", "db.example.com"} {
		text := "postgres://app:" + pw + "@" + host + "/prod"
		require.Equal(t, []string{"url-login-credential"}, entitiesOver(t, s, text, pw), host)
	}
}

// The filter runs through vendor suppression, so it follows that mode: off, the
// placeholder is reported.
func TestURLLogin_PlaceholderFilterFollowsTheSuppressionMode(t *testing.T) {
	s := prodScanner(t)
	t.Setenv("VENDOR_STRUCTURAL_SUPPRESSION", "off")
	cfg, err := scannerConfigFromEnv()
	require.NoError(t, err)
	off, err := buildScanner(cfg)
	require.NoError(t, err)
	text := "postgres://user:password@localhost:5432/db"
	require.Empty(t, entitiesOver(t, s, text, "password"))
	require.Equal(t, []string{"url-login-credential"}, entitiesOver(t, off, text, "password"))
}

// The span is the password inside the login, not an earlier copy of the same
// value: the redaction has to land on the credential.
func TestURLLogin_TheSpanIsThePasswordInTheLogin(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 41)
	for _, text := range []string{
		"rotated " + pw + " today; git clone ssh://svc:" + pw + "@git.acme.io/team/repo.git",
		"mysql://" + pw + ":" + pw + "@db.acme.io/app",
	} {
		want := strings.Index(text, ":"+pw+"@") + 1
		var spans [][2]int
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "url-login-credential" {
				spans = append(spans, [2]int{r.Start, r.End})
			}
		}
		require.Equal(t, [][2]int{{want, want + len(pw)}}, spans, text)
	}
}

func TestURLLogin_AnIPv6HostIsCaught(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 51)
	for _, host := range []string{"[::1]:5432", "[2001:db8::5]", "[fe80::1%25en0]:22"} {
		text := "postgres://app:" + pw + "@" + host + "/prod"
		require.Equal(t, []string{"url-login-credential"}, entitiesOver(t, s, text, pw), host)
	}
}

// A login pasted twice is reported twice, each copy on its own span: redaction
// works by span, so a collapsed second copy would stay visible.
func TestURLLogin_EachCopyOfARepeatedLoginIsReported(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 61)
	for _, text := range []string{
		"ssh://svc:" + pw + "@one.acme.io/a and ssh://svc:" + pw + "@two.acme.io/b",
		"ssh://svc:" + pw + "@git.acme.io/a and again ssh://svc:" + pw + "@git.acme.io/a",
	} {
		var want, got [][2]int
		for i, rest := 0, text; ; {
			j := strings.Index(rest, ":"+pw+"@")
			if j < 0 {
				break
			}
			want = append(want, [2]int{i + j + 1, i + j + 1 + len(pw)})
			i, rest = i+j+1, rest[j+1:]
		}
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "url-login-credential" {
				got = append(got, [2]int{r.Start, r.End})
			}
		}
		require.Len(t, want, 2)
		require.Equal(t, want, got, text)
	}
}

// SQLAlchemy names the driver after a "+".
func TestURLLogin_ADriverSuffixedSchemeIsCaught(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 71)
	for _, scheme := range []string{"postgresql+psycopg2", "postgres+asyncpg", "mysql+pymysql", "mariadb+mariadbconnector"} {
		text := scheme + "://app:" + pw + "@db.acme.io/prod"
		require.Equal(t, []string{"url-login-credential"}, entitiesOver(t, s, text, pw), scheme)
	}
}

// On the same span as a vendor detector, the vendor's specific name wins.
func TestURLLogin_AVendorTokenInTheLoginKeepsItsName(t *testing.T) {
	s := prodScanner(t)
	text := "git clone ssh://x-access-token:" + fakeGithubPAT + "@github.com/acme/repo.git"
	for range 20 {
		require.Equal(t, []string{"Github"}, entitiesOver(t, s, text, fakeGithubPAT))
	}
}

// A vendor that wins the password's span and is then dropped as noise must not
// take the login with it: in a login slot the value is a credential.
func TestURLLogin_AUUIDPasswordUnderAVendorKeywordIsReported(t *testing.T) {
	s := prodScanner(t)
	const uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	for _, user := range []string{"privacy", "onesignal"} {
		text := "ssh://" + user + ":" + uuid + "@host.acme.io/repo"
		require.NotEmpty(t, entitiesOver(t, s, text, uuid), user)
	}
}

// A shorter scheme inside a longer one ("ssh" in "git+ssh") is the same text;
// each login is still reported on its own password.
func TestURLLogin_ANestedSchemeDoesNotStealTheSpan(t *testing.T) {
	s := prodScanner(t)
	pw := fakePassword(24, 81)
	for _, text := range []string{
		"git+ssh://svc:" + pw + "@a.acme.io/x then ssh://svc:" + pw + "@b.acme.io/y",
		"sftp://u:" + pw + "@a.acme.io/x then ftp://u:" + pw + "@b.acme.io/y",
	} {
		var got []int
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.End-r.Start == len(pw) && text[r.Start:r.End] == pw {
				got = append(got, r.Start)
			}
		}
		require.Len(t, got, 2, text)
	}
}

// Dummy logins ahead of a real one do not use up a match budget.
func TestURLLogin_ARealLoginAfterManyDummiesIsReported(t *testing.T) {
	s := prodScanner(t)
	dummies := strings.Repeat("ssh://u:pass@h\n", 100)
	for _, n := range []int{24, 3000} {
		pw := fakePassword(n, int64(91+n))
		text := dummies + "ssh://svc:" + pw + "@real.acme.io/repo"
		require.NotEmpty(t, entitiesOver(t, s, text, pw), "password of %d", n)
	}
}

// A vendor match on part of the password that is then dropped as an identifier
// fragment must not take the login with it.
func TestURLLogin_ASuppressedVendorFragmentDoesNotDropTheLogin(t *testing.T) {
	s := prodScanner(t)
	for _, pw := range []string{
		"Abcdefghij1234567890KLMNOPQRSTuv-more",
		"app-0123456789abcdef0123456789abcdef",
	} {
		for _, user := range []string{"fastly", "box"} {
			text := "ssh://" + user + ":" + pw + "@host.acme.io/x"
			require.NotEmpty(t, entitiesOver(t, s, text, pw), text)
		}
	}
}

// A vendor match on only part of the password gives way to the whole login, or
// the rest of the password would stay visible.
func TestURLLogin_APartialVendorMatchDoesNotTruncateTheSpan(t *testing.T) {
	s := prodScanner(t)
	pw := fakeGithubPAT + "-Q7mN2vRt9"
	text := "ssh://svc:" + pw + "@host.acme.io/repo"
	want := strings.Index(text, pw)
	var spans [][2]int
	for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
		if r.Start < want+len(pw) && r.End > want {
			spans = append(spans, [2]int{r.Start, r.End})
		}
	}
	require.Equal(t, [][2]int{{want, want + len(pw)}}, spans)
}

// A username that reads like a checksum label does not make the password one.
func TestURLLogin_ADigestLookingPasswordIsReported(t *testing.T) {
	s := prodScanner(t)
	const hex64 = "233338fa7422c031c2a4c3f3ddcb39f2e16e13f21b97f7692e8dc384e12c1151"
	for _, user := range []string{"sha256", "md5", "checksum"} {
		text := "ssh://" + user + ":" + hex64 + "@host.acme.io/repo"
		require.NotEmpty(t, entitiesOver(t, s, text, hex64), user)
	}
}

// Placing logins stays near-linear, so a request full of them cannot hold a
// scan far past its deadline. Four times the logins must cost well under the
// sixteen times a quadratic pass would; a ratio holds on a slow runner too.
func TestURLLogin_ManyLoginsScanQuickly(t *testing.T) {
	s := prodScanner(t)
	took := func(n int) time.Duration {
		text := []byte(strings.Repeat("ssh://u:aB7x@h\n", n))
		best := time.Duration(1 << 62)
		for range 2 {
			start := time.Now()
			require.Len(t, s.scan(context.Background(), text, 0.75), n)
			best = min(best, time.Since(start))
		}
		return best
	}
	small, large := took(12500), took(50000)
	require.Less(t, large, 8*small, "12.5k logins took %v, 50k took %v", small, large)
}

// The shared placeholder filter is for tokens in free text; a real login password
// that contains a repeat run or a marker inside a word is still reported.
func TestURLLogin_ARealPasswordWithAPlaceholderLookIsReported(t *testing.T) {
	s := prodScanner(t)
	for _, pw := range []string{"Q7mN2vRt00000000Z9kP", "Xexample9Kq2Lm", "pReplace7Qz4mW"} {
		text := "ssh://svc:" + pw + "@host.acme.io/repo"
		require.NotEmpty(t, entitiesOver(t, s, text, pw), pw)
	}
}
