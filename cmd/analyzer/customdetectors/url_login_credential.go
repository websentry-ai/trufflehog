package customdetectors

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

const URLLoginCredentialName = "url-login-credential"

// NewURLLoginCredential reports the password in scheme://user:password@host.
//
// The vendor detectors leave most of this uncovered: URI caps the password at 50
// characters, JWT skips HS256 tokens, and nothing covers ssh, git, sftp or the
// SQL schemes. The scheme list is the one the email recognizer treats as a login
// slot, so whatever it stops calling an address is reported here instead.
func NewURLLoginCredential() (detectors.Detector, error) {
	pb := &custom_detectorspb.CustomRegex{
		Name: URLLoginCredentialName,
		Keywords: []string{
			"http", "ws", "ftp", "ssh", "git", "svn", "redis", "amqp", "mongodb",
			"postgres", "mysql", "mariadb", "ldap", "smtp", "imap",
		},
		Regex: map[string]string{
			// "?" and "#" end the authority, so neither the user nor the password
			// may contain them. The password has no upper bound: a long token is
			// the case this exists for, and the long-form pass sees it whole. The
			// match ends at "@", so any host shape counts, IPv6 brackets included.
			"secret": `(?i)\b(?:https?|wss?|s?ftps?|ssh|git(?:\+\w+)?|svn(?:\+\w+)?|rediss?|amqps?` +
				`|mongodb(?:\+srv)?|(?:postgres(?:ql)?|mysql|mariadb)(?:\+\w+)?|ldaps?|smtps?|imaps?)` +
				`://[^\s/?#@:]*:([^\s/?#@]{3,})@`,
		},
		ExcludeRegexesCapture: dbConnectionURIExcludeRegexes(),
	}
	return custom_detectors.NewWebhookCustomRegex(pb)
}
