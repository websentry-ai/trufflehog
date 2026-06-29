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
	uuidPat         = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{1,12})?$`)
	hexHashPat      = regexp.MustCompile(`^[0-9a-fA-F]{24}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	hex32Pat        = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	uuidishPat      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{0,12}$`)
	decimalPat      = regexp.MustCompile(`^[0-9][0-9.\-]*$`)
	hostPathPat     = regexp.MustCompile(`^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(/.*)?$`)
	urlPathPat      = regexp.MustCompile(`^/[A-Za-z0-9._~%-]+(/[A-Za-z0-9._~%-]+)*/?$`)
	relPathPat      = regexp.MustCompile(`^(?:[A-Za-z0-9._~%@-]+/)+[A-Za-z0-9._~%@-]*\.(?:py|js|ts|jsx|tsx|mjs|cjs|go|rs|rb|java|kt|kts|c|h|hpp|hh|cc|cpp|cxx|cs|php|sh|bash|zsh|ps1|json|yaml|yml|toml|ini|cfg|conf|xml|html|htm|css|scss|sass|less|md|mdx|rst|txt|sql|graphql|proto|tf|tfvars|lock|mod|sum|gradle|swift|scala|clj|cljs|ex|exs|erl|vue|svelte|env|properties|csv|tsv|log)$|^(?:[a-z0-9._-]+/){2,}$`)
	npmScopedPat    = regexp.MustCompile(`^@[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9._-]*$`)
	urlishPat       = regexp.MustCompile(`^//|://`)
	orgIDPat        = regexp.MustCompile(`^org-[A-Za-z0-9]+$`)
	datetimePat     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}`)
	datePrefixPat   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}(?::\d{2}){0,2})?$`)
	schemePat       = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)
	maskPat         = regexp.MustCompile(strings.Join(maskPatternStrings, "|"))
	stripeObjPat    = regexp.MustCompile(`^(?:du|dp|pi|ch|in|re|txn|cus|sub|evt|po|tr|seti|price|prod|card|ba|src|tok|il|inv|cs|qt|cn|cr|or|py|ipi|rcpt)_[A-Za-z0-9]{12,}$`)
	secretCharPat   = regexp.MustCompile(`^[A-Za-z0-9._\-+/=~@]+$`)
	codeDelimPat    = regexp.MustCompile("[\\s\\\\(){}<>,\"'" + "`" + "]")
	filenamePat     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:py|js|ts|jsx|tsx|mjs|cjs|go|rs|rb|java|kt|kts|c|h|hpp|hh|cc|cpp|cxx|cs|php|sh|bash|zsh|ps1|json|yaml|yml|toml|ini|cfg|conf|xml|html|htm|css|scss|sass|less|md|mdx|rst|txt|sql|graphql|proto|tf|tfvars|lock|mod|sum|gradle|swift|scala|clj|cljs|ex|exs|erl|vue|svelte|env|properties|csv|tsv|log)$`)
	lowerPathPat    = regexp.MustCompile(`^(?:[a-z0-9._~@-]+/){2,}[a-z0-9._~@-]*$`)
	oktaIDPat       = regexp.MustCompile(`^00[a-z][a-zA-Z0-9]{17}$`)
	aiObjectIDPat   = regexp.MustCompile(`^(?:chatcmpl|cmpl|asst|assistant|thread|run|step|msg|message|toolu|call|resp|file|ftjob|batch|vs|proj)[-_][A-Za-z0-9]{6,}$`)
	snakeIdentPat   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+){2,}$`)
	connParamKeyPat = regexp.MustCompile(`(?i)[;?&]\s*([a-z][a-z0-9_.\-]*)\s*=`)
	dottedIdentPat  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)
)

var genericStructuralRecognizers = []Recognizer{
	{"uuid", uuidPat},
	{"date", datePrefixPat},
	{"decimal", decimalPat},
	{"host_path", hostPathPat},
	{"url_path", urlPathPat},
	{"rel_path", relPathPat},
	{"npm_pkg", npmScopedPat},
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
	{"rel_path", relPathPat},
	{"npm_pkg", npmScopedPat},
	{"urlish", urlishPat},
	{"org_id", orgIDPat},
	{"datetime", datetimePat},
	{"scheme", schemePat},
	{"mask", maskPat},
	{"filename", filenamePat},
	{"lower_path", lowerPathPat},
	{"okta_id", oktaIDPat},
	{"ai_object_id", aiObjectIDPat},
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
	return IsSnakeCaseIdentifier(v) || IsWordyIdentifier(v) || strings.Contains(v, "..")
}

func IsWordyIdentifier(v string) bool {
	var letters, vowels, digits, run, maxRun int
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' ||
			c == 'A' || c == 'E' || c == 'I' || c == 'O' || c == 'U':
			letters++
			vowels++
			run = 0
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letters++
			run++
			if run > maxRun {
				maxRun = run
			}
		case c >= '0' && c <= '9':
			digits++
			run = 0
		default:
			run = 0
		}
	}
	if digits == 0 || letters < 18 {
		return false
	}
	if digits*4 > letters {
		return false
	}
	if maxRun > 4 {
		return false
	}
	return vowels*10 >= letters*3
}

func IsSnakeCaseIdentifier(v string) bool {
	if !snakeIdentPat.MatchString(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			return true
		}
	}
	return false
}

var connBenignKeys = map[string]bool{
	"databasename": true, "applicationname": true, "encrypt": true,
	"trustservercertificate": true, "hostnameincertificate": true,
	"integratedsecurity": true, "instancename": true, "servername": true,
	"portnumber": true, "applicationintent": true, "multisubnetfailover": true,
	"logintimeout": true, "connecttimeout": true, "sockettimeout": true,
	"ssl": true, "sslmode": true, "usessl": true, "requiressl": true,
	"verifyservercertificate": true, "tlsversion": true, "tcpkeepalive": true,
	"servertimezone": true, "timezone": true, "characterencoding": true,
	"charset": true, "encoding": true, "useunicode": true,
	"autoreconnect": true, "allowpublickeyretrieval": true, "readonly": true,
	"targetservertype": true, "currentschema": true, "schema": true,
	"user": true, "username": true, "uid": true, "host": true, "port": true,
	"database": true, "db": true, "protocol": true, "driver": true,
}

func IsNonSecretConnString(v string) bool {
	if !strings.HasPrefix(strings.ToLower(v), "jdbc:") {
		return false
	}
	if !strings.Contains(v, "://") {
		return false
	}
	if strings.Contains(v, "@") {
		return false
	}
	for _, m := range connParamKeyPat.FindAllStringSubmatch(v, -1) {
		if !connBenignKeys[strings.ToLower(m[1])] {
			return false
		}
	}
	return true
}

func IsCodeLike(v string) bool {
	return codeDelimPat.MatchString(v) || dottedIdentPat.MatchString(v)
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

func IsUUIDish(s string) bool { return uuidishPat.MatchString(s) }

func IsSecretAlphabet(s string) bool { return secretCharPat.MatchString(s) }
