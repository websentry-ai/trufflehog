package customdetectors

import (
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const URLLoginCredentialName = "url-login-credential"

// "?" and "#" end the authority. The password is unbounded, since a long token is
// the case this exists for, and the match ends at "@" so any host shape counts,
// IPv6 brackets included.
const urlLoginPattern = `(?i)\b(?:https?|wss?|s?ftps?|ssh|git(?:\+\w+)?|svn(?:\+\w+)?|rediss?|amqps?` +
	`|mongodb(?:\+srv)?|(?:postgres(?:ql)?|mysql|mariadb)(?:\+\w+)?|ldaps?|smtps?|imaps?)` +
	`://[^\s/?#@:]*:([^\s/?#@]{3,})@`

var urlLoginRegex = regexp.MustCompile(urlLoginPattern)

// IsURLLoginPassword reports whether raw is the password of a URL login in data.
func IsURLLoginPassword(data []byte, raw string) bool {
	for _, m := range urlLoginRegex.FindAllSubmatch(data, -1) {
		if string(m[1]) == raw {
			return true
		}
	}
	return false
}

// NewURLLoginCredential reports the password in scheme://user:password@host,
// which vendor detectors mostly miss (URI caps it at 50 characters, JWT skips
// HS256). Its schemes are the ones the email recognizer treats as a login slot.
func NewURLLoginCredential() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name: URLLoginCredentialName,
		Keywords: []string{
			"http", "ws", "ftp", "ssh", "git", "svn", "redis", "amqp", "mongodb",
			"postgres", "mysql", "mariadb", "ldap", "smtp", "imap",
		},
		Regex:                 map[string]string{"secret": urlLoginPattern},
		ExcludeRegexesCapture: dbConnectionURIExcludeRegexes(),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}
