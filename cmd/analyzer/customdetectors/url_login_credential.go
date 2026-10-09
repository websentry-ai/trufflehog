package customdetectors

import (
	"bytes"
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const URLLoginCredentialName = "url-login-credential"

// The user and password hold only RFC 3986 login characters, less "," and ";",
// so the match cannot run across JSON or CSV fields into a later address. The
// password is unbounded, since a long token is the case this exists for, and the
// match ends at "@" so any host shape counts, IPv6 brackets included.
var urlLoginRegex = regexp.MustCompile(`(?i)\b(?:https?|wss?|s?ftps?|ssh|git(?:\+\w+)?|svn(?:\+\w+)?|rediss?|amqps?` +
	`|mongodb(?:\+srv)?|cloudinary|mqtts?|nats|rtsps?|ldaps?|smtps?|imaps?` +
	`|(?:postgres(?:ql)?|mysql|mariadb|oracle|mssql|sqlserver|clickhouses?|snowflake)(?:\+\w+)?)` +
	`://[A-Za-z0-9\-._~%!$&'()*+=]*:([A-Za-z0-9\-._~%!$&'()*+=:]{3,})@`)

// A port glued to an address ("db.acme.io:5432&jane@acme.com") reads like a
// password starting with digits; only a host with a path or port after it, as
// in a real URL, makes it a login.
var (
	portShaped   = regexp.MustCompile(`^\d+[^A-Za-z0-9]`)
	hostThenPath = regexp.MustCompile(`^(?:\[[^\]\s]*\]|[A-Za-z0-9.-]+)(?:/|:\d)`)
)

// urlLoginDetector reports the password in scheme://user:password@host, which
// vendor detectors mostly miss (URI caps it at 50 characters, JWT skips HS256).
// Its schemes are the ones the email recognizer treats as a login slot. It is
// not a custom-regex detector because that framework keeps only the first 100
// matches and drops where each one was; this reports every login's offset.
type urlLoginDetector struct{ exclude []*regexp.Regexp }

func NewURLLoginCredential() (detectors.Detector, error) {
	var d urlLoginDetector
	// Code that builds the URL leaves a template field in the password slot.
	templates := []string{`^\{[^{}]*\}$`, `^%\([^)]*\)s$`, `^\$\(.*\)$`, `^%s$`}
	for _, p := range append(dbConnectionURIExcludeRegexes(), templates...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		d.exclude = append(d.exclude, re)
	}
	return d, nil
}

func (urlLoginDetector) Keywords() []string {
	return []string{
		"http", "ws", "ftp", "ssh", "git", "svn", "redis", "amqp", "mongodb",
		"postgres", "mysql", "mariadb", "ldap", "smtp", "imap", "oracle", "mssql",
		"sqlserver", "clickhouse", "snowflake", "cloudinary", "mqtt", "nats", "rtsp",
	}
}

func (urlLoginDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

// Version keeps its detector key apart from the entropy detector's, the other
// custom-typed detector outside the regex framework.
func (urlLoginDetector) Version() int { return 1 }

func (urlLoginDetector) GetName() string { return URLLoginCredentialName }

func (urlLoginDetector) Description() string {
	return "Password in the login slot of a URL."
}

func (d urlLoginDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
Logins:
	for _, m := range urlLoginRegex.FindAllSubmatchIndex(data, -1) {
		pw := data[m[2]:m[3]]
		if portShaped.Match(pw) && !hostThenPath.Match(data[m[1]:]) {
			continue
		}
		for _, re := range d.exclude {
			if re.Match(pw) {
				continue Logins
			}
		}
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: URLLoginCredentialName,
			Raw:          bytes.Clone(pw),
		}
		r.SetChunkOffset(int64(m[2]))
		results = append(results, r)
	}
	return results, nil
}
