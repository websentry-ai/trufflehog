package classify

import (
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

type Recognizer struct {
	Name string
	pat  *regexp.Regexp
}

func (r Recognizer) Match(v string) bool { return r.pat.MatchString(v) }

var maskPatternStrings = []string{
	`^[\*x•]+$`,
	`^[A-Za-z]{1,4}-?x{8,}$`,
	`^.{0,4}(x{8,}|\*{8,}|0{8,}|\.{8,})$`,
}

var envRefPatternStrings = []string{
	`^\$\{.*\}$`,
	`^\$[A-Za-z_][A-Za-z0-9_]*$`,
	`^\$\(.*\)$`,
	`^\{\{.*\}\}$`,
	`^<.*>$`,
}

var (
	uuidPat       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{1,12})?$`)
	hexHashPat    = regexp.MustCompile(`^[0-9a-fA-F]{24}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	hex32Pat      = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	decimalPat    = regexp.MustCompile(`^[0-9][0-9.\-]*$`)
	hostPathPat   = regexp.MustCompile(`^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(/.*)?$`)
	urlPathPat    = regexp.MustCompile(`^/[A-Za-z0-9._~%-]+(/[A-Za-z0-9._~%-]+)*/?$`)
	urlishPat     = regexp.MustCompile(`^//|://`)
	orgIDPat      = regexp.MustCompile(`^org-[A-Za-z0-9]+$`)
	datetimePat   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}`)
	datePrefixPat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}(?::\d{2}){0,2})?$`)
	schemePat     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)
	maskPat       = regexp.MustCompile(strings.Join(maskPatternStrings, "|"))
	stripeObjPat  = regexp.MustCompile(`^(?:du|dp|pi|ch|in|re|txn|cus|sub|evt|po|tr|seti|price|prod|card|ba|src|tok|il|inv|cs|qt|cn|cr|or|py|ipi|rcpt)_[A-Za-z0-9]{12,}$`)
	secretCharPat = regexp.MustCompile(`^[A-Za-z0-9._\-+/=~@]+$`)
)

var genericStructuralRecognizers = []Recognizer{
	{"uuid", uuidPat},
	{"date", datePrefixPat},
	{"decimal", decimalPat},
	{"host_path", hostPathPat},
	{"url_path", urlPathPat},
	{"urlish", urlishPat},
	{"org_id", orgIDPat},
	{"scheme", schemePat},
	{"mask", maskPat},
}

var entropyExclusionRecognizers = []Recognizer{
	{"uuid", uuidPat},
	{"hex_hash", hexHashPat},
	{"decimal", decimalPat},
	{"host_path", hostPathPat},
	{"url_path", urlPathPat},
	{"urlish", urlishPat},
	{"org_id", orgIDPat},
	{"datetime", datetimePat},
	{"scheme", schemePat},
	{"mask", maskPat},
}

func MaskPatterns() []string { return copyOf(maskPatternStrings) }

func EnvRefPatterns() []string { return copyOf(envRefPatternStrings) }

func EntropyExclusionRecognizers() []Recognizer {
	out := make([]Recognizer, len(entropyExclusionRecognizers))
	copy(out, entropyExclusionRecognizers)
	return out
}

func IsExcludedEntropyValue(v string) bool {
	for _, r := range entropyExclusionRecognizers {
		if r.Match(v) {
			return true
		}
	}
	return false
}

func IsStructuralNonSecret(v string) bool {
	for _, r := range genericStructuralRecognizers {
		if r.Match(v) {
			return true
		}
	}
	return false
}

func IsStripeObjectID(s string) bool { return stripeObjPat.MatchString(s) }

func IsHex32(s string) bool { return hex32Pat.MatchString(s) }

func IsSecretAlphabet(s string) bool { return secretCharPat.MatchString(s) }
