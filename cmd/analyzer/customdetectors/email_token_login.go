package customdetectors

import (
	"bytes"
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const EmailTokenLoginName = "email-token-login"

// An API-token login of the form "<agent email>/token:<40 alphanumerics>".
// The whole login is reported, so the address inside it is read as part of the
// credential rather than as an email of its own.
var emailTokenLoginRegex = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/token:[A-Za-z0-9]{40}\b`)

// LoginContextBytes is how far before a login its auth context may start.
const LoginContextBytes = 80

// A login is reported only when an auth header, a curl -u/--user, or a
// credential-like key comes shortly before it, so one quoted in prose is left
// alone. Whole words count, with keys split at "_", "-" and camelCase, so
// SUPPORT_AUTH and authToken do and "author" does not.
var (
	camelBreak       = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	contextWord      = regexp.MustCompile(`[A-Za-z]+`)
	curlUserFlag     = regexp.MustCompile(`(?:^|\s)-u\b`)
	loginContextWord = map[string]bool{
		"authorization": true, "bearer": true, "basic": true, "auth": true, "token": true,
		"key": true, "apikey": true, "password": true, "passwd": true, "pwd": true,
		"credential": true, "credentials": true, "secret": true, "login": true,
		"user": true, "username": true, "curl": true, "signing": true, "cert": true,
	}
)

// lookBehind is the text a login reads its context from, without a word the
// window cuts in half ("monkey" read as "key"). When midText, data was cut from
// longer text, so a word at its start may be cut too.
func lookBehind(data []byte, at int, midText bool) []byte {
	from := max(0, at-LoginContextBytes)
	before := data[from:at]
	if from > 0 && isLetter(data[from-1]) || from == 0 && midText {
		for len(before) > 0 && isLetter(before[0]) {
			before = before[1:]
		}
	}
	return before
}

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

type leadKey struct{}

// lead is what comes before the text a detector is given.
type lead int

const (
	leadNone lead = iota
	leadAuth      // auth context just before decoded text
	leadText      // more of the same text, before a later scan window
)

// WithLoginContextBefore records whether the words just before decoded text
// carry auth context, as in "Authorization: Basic <base64 login>".
func WithLoginContextBefore(ctx context.Context, before bool) context.Context {
	if before {
		return context.WithValue(ctx, leadKey{}, leadAuth)
	}
	return context.WithValue(ctx, leadKey{}, leadNone)
}

// WithTextBefore marks a window cut from longer text: it may start mid-word,
// and context before the decoded text does not reach it.
func WithTextBefore(ctx context.Context) context.Context {
	return context.WithValue(ctx, leadKey{}, leadText)
}

// HasLoginContextBefore reports whether auth context comes shortly before at.
func HasLoginContextBefore(data []byte, at int) bool {
	return hasLoginContext(lookBehind(data, at, false))
}

func hasLoginContext(before []byte) bool {
	if curlUserFlag.Match(before) {
		return true
	}
	for _, w := range contextWord.FindAll(camelBreak.ReplaceAll(before, []byte("$1 $2")), -1) {
		if loginContextWord[strings.ToLower(string(w))] {
			return true
		}
	}
	return false
}

type emailTokenLoginDetector struct{}

func NewEmailTokenLogin() detectors.Detector { return emailTokenLoginDetector{} }

func (emailTokenLoginDetector) Keywords() []string { return []string{"/token:"} }

func (emailTokenLoginDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (emailTokenLoginDetector) Version() int { return 2 }

func (emailTokenLoginDetector) GetName() string { return EmailTokenLoginName }

func (emailTokenLoginDetector) Description() string {
	return "API token in its email/token login form."
}

func (emailTokenLoginDetector) FromData(ctx context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	before, _ := ctx.Value(leadKey{}).(lead)
	var results []detectors.Result
	for _, m := range emailTokenLoginRegex.FindAllIndex(data, -1) {
		// Context before the text counts for a login the text starts with.
		fromOutside := before == leadAuth && m[0] == 0
		if !fromOutside && !hasLoginContext(lookBehind(data, m[0], before == leadText)) {
			continue
		}
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: EmailTokenLoginName,
			Raw:          bytes.Clone(data[m[0]:m[1]]),
			SecretParts:  emailTokenSecretParts(data[m[0]:m[1]]),
		}
		r.SetChunkOffset(int64(m[0]))
		results = append(results, r)
	}
	return results, nil
}

func emailTokenSecretParts(login []byte) map[string]string {
	email, token, _ := bytes.Cut(login, []byte("/token:"))
	return map[string]string{"email": string(email), "token": string(token)}
}
