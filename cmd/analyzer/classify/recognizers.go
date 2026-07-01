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
	ulidPat         = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	modelIDPat      = regexp.MustCompile(`^[a-z]{2,}(?:[.-][a-z0-9]{1,8})*[.-](?:20\d{2}-\d{2}-\d{2}|20\d{6})$`)
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
	datetimePat     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$`)
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
	{"model_id", modelIDPat},
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
	return IsCompositeIdentifier(v) || IsDatetimePrefixedID(v) || IsJWTComponent(v) || IsPaddedHexDigest(v) || IsBase64EncodedText(v)
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
		case isAllDigits(s), isShortStructuralSegment(s), isHexSegment(s):
			hasStructural = true
		default:
			return false
		}
	}
	return hasWord && hasStructural
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

func isShortStructuralSegment(s string) bool {
	if len(s) == 0 || len(s) > 6 {
		return false
	}
	var upper, lower, digit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return !upper || !lower || !digit
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

var datetimeIDAnchorPat = regexp.MustCompile(`^\d{4}-(?:0\d|1[0-2])-(?:[0-2]\d|3[01])(?:[T ]|[-_/]|$)`)

func isDatetimeIshSegment(s string) bool {
	if s == "" {
		return false
	}
	onlyDigitsAndISO, hasDigit := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == 'T' || c == 'Z':
		default:
			onlyDigitsAndISO = false
		}
	}
	if onlyDigitsAndISO && hasDigit {
		return true
	}
	return isHexSegment(s) || isShortStructuralSegment(s)
}

func IsDatetimePrefixedID(v string) bool {
	if !datetimeIDAnchorPat.MatchString(v) {
		return false
	}
	segs := strings.FieldsFunc(v, isIdentDelimiter)
	if len(segs) < 3 {
		return false
	}
	for _, s := range segs {
		if !isDatetimeIshSegment(s) {
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
	return len(decoded) > 0 && decoded[0] == '{' && json.Valid(decoded) &&
		!hasLongToken(decoded) && !jsonHasCredentialValue(decoded)
}

var jsonCredentialFieldPat = regexp.MustCompile(`(?i)"(?:api[_-]?key|apikey|secret|token|password|passwd|passphrase|credential|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|bearer)"\s*:\s*"([^"]{8,})"`)

func jsonHasCredentialValue(b []byte) bool {
	for _, m := range jsonCredentialFieldPat.FindAllSubmatch(b, -1) {
		v := m[1]
		var letter, digit bool
		for _, c := range v {
			switch {
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				letter = true
			case c >= '0' && c <= '9':
				digit = true
			}
		}
		if (letter && digit) || len(v) >= 16 {
			return true
		}
	}
	return false
}

func IsBase64EncodedText(v string) bool {
	if len(v) < 16 {
		return false
	}
	decoded := decodeBase64Best(v)
	if len(decoded) == 0 {
		return false
	}
	if decoded[0] != '{' && decoded[0] != '[' {
		return false
	}
	return json.Valid(decoded) && !hasLongToken(decoded) && !jsonHasCredentialValue(decoded)
}

func hasLongToken(b []byte) bool {
	run := 0
	for _, c := range b {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '_' || c == '=':
			run++
			if run >= 20 {
				return true
			}
		default:
			run = 0
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

func IsPaddedHexDigest(v string) bool {
	trimmed := strings.TrimRight(v, "=")
	if trimmed == v {
		return false
	}
	return hexHashPat.MatchString(trimmed)
}

var hexDigestLabelPat = regexp.MustCompile(`(?i)(md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-?224|sha3-?256|sha3-?384|sha3-?512|sha3|blake2b|blake2s|blake3|ripemd-?160)[:=-] ?$`)

var digestHexLen = map[string]int{
	"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128,
	"sha3224": 56, "sha3256": 64, "sha3384": 96, "sha3512": 128,
	"blake2b": 128, "blake2s": 64, "blake3": 64, "ripemd160": 40,
}

func IsHexDigestInContext(value, before string) bool {
	if len(value) < 16 || !isAllHex(value) {
		return false
	}
	m := hexDigestLabelPat.FindStringSubmatch(before)
	if m == nil {
		return false
	}
	algo := strings.ReplaceAll(strings.ToLower(m[1]), "-", "")
	want, known := digestHexLen[algo]
	if !known {
		return true
	}
	return len(value) == want
}

var hexIDLabelPat = regexp.MustCompile(`(?i)(?:span[_-]?id|trace(?:parent|state)?|trace[_-]?id|parent[_-]?id|segment[_-]?id|correlation[_-]?id|event[_-]?id|session[_-]?id|x-?ray|x-amzn-trace(?:[_-]?id)?|build ?hash|content[_-]?hash|debug[_-]?id)[\s=:@/-]*$|(?i)(?:self|root)\s*=\s*$`)

var credentialAssignPat = regexp.MustCompile("(?i)(?:api[_-]?key|secret|passwd|password|token|credential|access[_-]?key|private[_-]?key|client[_-]?secret)[\"'`\\] ]*[:=]\\s*[\"'`]?\\s*$")

func IsCredentialAssignment(before string) bool {
	return credentialAssignPat.MatchString(before)
}

var credentialContextPat = regexp.MustCompile("(?i)\\b(?:secret|api[_-]?key|apikey|password|passwd|private[_-]?key|signing|credential|access[_-]?key|auth[_-]?token|bearer|keys?)\\b")

func IsCredentialContext(before string) bool {
	return credentialContextPat.MatchString(before)
}

func IsHexIDInContext(value, before string) bool {
	if len(value) < 16 || !isAllHex(value) {
		return false
	}
	return hexIDLabelPat.MatchString(before)
}

func IsAllHex(s string) bool {
	return isAllHex(s)
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
