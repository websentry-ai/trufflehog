package classify

import (
	"encoding/base64"
	"encoding/json"
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

const fileExtGroup = `py|js|ts|jsx|tsx|mjs|cjs|go|rs|rb|java|kt|kts|c|h|hpp|hh|cc|cpp|cxx|cs|php|sh|bash|zsh|ps1|json|yaml|yml|toml|ini|cfg|conf|xml|html|htm|css|scss|sass|less|md|mdx|rst|txt|sql|graphql|proto|tf|tfvars|lock|mod|sum|gradle|swift|scala|clj|cljs|ex|exs|erl|vue|svelte|env|properties|csv|tsv|log|pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|png|jpg|jpeg|gif|bmp|svg|webp|ico|tiff|heic|mp3|mp4|mov|avi|mkv|wav|flac|ogg|webm|zip|tar|gz|tgz|bz2|xz|7z|rar|jar|war|dll|so|dylib|exe|pkg|dmg|iso|woff|woff2|ttf|otf|eot|bin|dat|bak`

var (
	uuidPat         = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{1,12})?$`)
	uuidSuffixPat   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:[/_:.-][A-Za-z0-9._~%@-]{1,12})+$`)
	ulidPat         = regexp.MustCompile(`^[0-7][0-9A-Z]{25}$`)
	datetimeIDPat   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}`)
	hexLiteralPat   = regexp.MustCompile(`^0[xX][0-9a-fA-F]{8,}$`)
	bech32Pat       = regexp.MustCompile(`^(?:bc1|tb1|bcrt1|ltc1|tltc1)[ac-hj-np-z02-9]{20,87}$`)
	traceparentPat  = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
	hexHashPat      = regexp.MustCompile(`^[0-9a-fA-F]{24}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	hex32Pat        = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	uuidishPat      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{0,12}$`)
	decimalPat      = regexp.MustCompile(`^[0-9][0-9.\-]*$`)
	hostPathPat     = regexp.MustCompile(`^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(/.*)?$`)
	urlPathPat      = regexp.MustCompile(`^/[A-Za-z0-9._~%-]+(/[A-Za-z0-9._~%-]+)*/?$`)
	relPathPat      = regexp.MustCompile(`^(?:[A-Za-z0-9._~%@-]+/)+[A-Za-z0-9._~%@-]*\.(?:` + fileExtGroup + `)$|^(?:[a-z0-9._-]+/){2,}$`)
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
	filenamePat     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:` + fileExtGroup + `)$`)
	lowerPathPat    = regexp.MustCompile(`^(?:[a-z0-9._~@-]+/){2,}[a-z0-9._~@-]*$`)
	oktaIDPat       = regexp.MustCompile(`^(?:0[0o][a-z]|aus|fwf)[a-zA-Z0-9]{17}$`)
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
	{"uuid_suffix", uuidSuffixPat},
	{"ulid", ulidPat},
	{"datetime_id", datetimeIDPat},
	{"hex_literal", hexLiteralPat},
	{"bech32_address", bech32Pat},
	{"traceparent", traceparentPat},
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
	if IsSnakeCaseIdentifier(v) || IsWordyIdentifier(v) || strings.Contains(v, "..") {
		return true
	}
	return IsCompositeIdentifier(v) || IsJWTComponent(v) || IsPaddedHexDigest(v) || IsBase64EncodedText(v)
}

func IsCompositeIdentifier(v string) bool {
	segs := strings.FieldsFunc(v, isIdentDelimiter)
	if len(segs) < 3 {
		return false
	}
	hasWord, hasStructural := false, false
	for _, s := range segs {
		switch {
		case isWordSegment(s):
			hasWord = true
		case isAllDigits(s), len(s) <= 6, isHexSegment(s):
			hasStructural = true
		default:
			return false
		}
	}
	return hasWord && hasStructural
}

func ContainsNonAlphanumeric(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum {
			return true
		}
	}
	return false
}

func isIdentDelimiter(r rune) bool {
	switch r {
	case '-', '_', '/', '.', ':', '+':
		return true
	}
	return false
}

func isWordSegment(s string) bool {
	if len(s) < 3 {
		return false
	}
	var letters, vowels, digits, run, maxRun int
	for i := 0; i < len(s); i++ {
		c := s[i]
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
	if letters < 4 || vowels == 0 || maxRun > 4 {
		return false
	}
	if vowels*4 < letters {
		return false
	}
	return digits*2 <= letters
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexSegment(s string) bool {
	if len(s) == 0 || len(s) > 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func IsJWTComponent(v string) bool {
	if !strings.HasPrefix(v, "eyJ") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return false
	}
	return len(decoded) > 0 && decoded[0] == '{' && json.Valid(decoded)
}

var jsonTextMarkers = []string{`{"`, `":"`, `","`, `":[`, `":{`, `"}`, `null`, `true`, `false`}

var relayIDPat = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*:(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func IsBase64EncodedText(v string) bool {
	if len(v) < 16 {
		return false
	}
	decoded := decodeBase64Best(v)
	if decoded == nil || !mostlyPrintable(decoded) {
		return false
	}
	s := string(decoded)
	if relayIDPat.MatchString(s) {
		return true
	}
	for _, m := range jsonTextMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func decodeBase64Best(v string) []byte {
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding,
		base64.RawURLEncoding, base64.URLEncoding,
	} {
		if d, err := enc.DecodeString(v); err == nil {
			return d
		}
	}
	return nil
}

func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}

func IsPaddedHexDigest(v string) bool {
	trimmed := strings.TrimRight(v, "=")
	if trimmed == v {
		return false
	}
	return hexHashPat.MatchString(trimmed)
}

var hexDigestLabelPat = regexp.MustCompile(`(?i)(?:md5|sha-?(?:1|224|256|384|512)|sha3-?(?:224|256|384|512)?|blake2[bs]?|blake3|ripemd-?160)[:=-] ?$`)

func IsHexDigestInContext(value, before string) bool {
	if len(value) < 16 || !isAllHex(value) {
		return false
	}
	return hexDigestLabelPat.MatchString(before)
}

func isAllHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
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
