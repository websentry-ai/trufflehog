package main

import (
	"bytes"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
	reasonVendorStructuralDigest     = "vendor_structural_digest"
	reasonVendorStructuralEmbedded   = "vendor_structural_embedded"
	reasonVendorStructuralNoise      = "vendor_structural_noise"
	reasonVendorStructuralInURL      = "vendor_structural_in_url"
)

const digestContextWindow = 48

// A JSON key can arrive quoted and backslash-escaped several levels deep (\\\"sha\\\":\\\"<hex>).
var quoteStripper = strings.NewReplacer("\\", "", "\"", "", "'", "")

type vendorRule struct {
	match  func(string) bool
	reason string
	// vetoable rules match a shape that can overlap a real credential for that
	// detector (Privacy keys are UUIDs by design; an Atlassian token can be an
	// all-hex run), so they suppress only outside a credential context / label.
	// Rules whose shape is decisively non-secret (code fragments, benign conn
	// strings, placeholder URIs) are unconditional.
	vetoable bool
}

var vendorStructuralRules = map[string]vendorRule{
	"JiraToken":                            {match: classify.IsAtlassianNoise, reason: reasonVendorStructuralNoise, vetoable: true},
	"Atlassian":                            {match: classify.IsAtlassianNoise, reason: reasonVendorStructuralNoise, vetoable: true},
	"Privacy":                              {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID, vetoable: true},
	"Onesignal":                            {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID, vetoable: true},
	"URI":                                  {match: classify.IsPlaceholderURI, reason: reasonVendorStructuralNoise},
	customdetectors.URLLoginCredentialName: {match: classify.IsPlaceholderPassword, reason: reasonVendorStructuralNoise},
	"Azure":                                {match: classify.IsCodeLike, reason: reasonVendorStructuralCode},
	"JDBC":                                 {match: classify.IsNonSecretConnString, reason: reasonVendorStructuralConnString},
	"Docker":                               {match: classify.IsPlaceholderBasicAuth, reason: reasonVendorStructuralNoise},
	"AsanaOauth":                           {match: isObjectLinkPath, reason: reasonVendorStructuralNoise},
}

// isObjectLinkPath reports whether v is a link path such as
// "com/0/<id>/project/<id>/list/": every segment a number or a word, with a long
// numeric object id. A token always has a segment mixing letters and digits.
func isObjectLinkPath(v string) bool {
	if strings.Count(v, "/") < 3 {
		return false
	}
	id := false
	for _, seg := range strings.Split(v, "/") {
		switch {
		case strings.Trim(seg, "0123456789") == "":
			id = id || len(seg) >= 10
		case strings.Trim(seg, "abcdefghijklmnopqrstuvwxyz") != "":
			return false
		}
	}
	return id
}

// embeddedVendors are detectors whose real token is always a standalone run, so
// a match glued to an identifier byte on either side ("app-<hex>@host",
// "fastly-<tok>-exporter") is a fragment of a larger identifier, not the token.
// Box is here because its keyword "box" also matches inside "Dropbox",
// "sandbox" and "inbox", and its 32-alphanumeric shape is any hex32 id.
var embeddedVendors = map[string]bool{
	"FastlyPersonalToken": true,
	"Box":                 true,
}

func isCuratedVendor(entity string) bool {
	if embeddedVendors[entity] {
		return true
	}
	_, ok := vendorStructuralRules[entity]
	return ok
}

// "_" and "-" are word characters to \b, so box_token= hides "token" from the
// context pattern. Split them before matching.
func labelSeparatorsToSpace(s string) string {
	return strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(s)
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func decideVendorSuppression(f analyzeResult, data []byte) (bool, string) {
	// A login's password is a credential by its position, so the context rules
	// below, written for tokens in free text, don't apply; only its own rule does.
	if f.EntityType == customdetectors.URLLoginCredentialName {
		if rule := vendorStructuralRules[f.EntityType]; rule.match(f.raw) {
			return true, rule.reason
		}
		return false, ""
	}
	digestAt := func(d []byte, s int) bool {
		lo := s - digestContextWindow
		if lo < 0 {
			lo = 0
		}
		return classify.IsHexDigestInContext(f.raw, quoteStripper.Replace(string(d[lo:s])))
	}
	if contextSuppressed(data, f.raw, digestAt) {
		return true, reasonVendorStructuralDigest
	}
	// A UUID is never reported, even when labelled as a key: UUID-shaped vendor keys are deliberately not detected.
	if classify.IsUUIDish(f.raw) {
		return true, reasonVendorStructuralUUID
	}
	if !strings.Contains(f.raw, "://") && !hasDistinctiveKeyPrefix(f.raw) && allOccurrences(data, f.raw, func(d []byte, s int) bool {
		return (inHTTPURL(d, s) && !inUserinfoAt(d, s, len(f.raw))) || digestAt(d, s)
	}) {
		return true, reasonVendorStructuralInURL
	}
	if embeddedVendors[f.EntityType] && contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		n := len(f.raw)
		if f.EntityType == "Box" {
			// A bare hyphen is not enough for Box: its token is 32 alphanumerics,
			// so "box_token=app-<tok>" and "<tok>-prod" are ordinary credentials
			// with a neighbour. Only the Dropbox app-id fragment, "app-<hex>@",
			// is a non-secret -- and not even that when a credential label
			// introduces it, which the shared veto cannot see because its window
			// ends inside the "app-" prefix.
			if s < 4 || !strings.EqualFold(string(d[s-4:s]), "app-") ||
				s+n >= len(d) || d[s+n] != '@' {
				return false
			}
			lo := s - 4 - credentialContextWindow
			if lo < 0 {
				lo = 0
			}
			before := string(d[lo : s-4])
			return !classify.IsCredentialContext(labelSeparatorsToSpace(before)) &&
				!classify.IsCredentialAssignment(before)
		}
		left := s > 0 && isIdentByte(d[s-1])
		right := s+n < len(d) && isIdentByte(d[s+n])
		return left || right
	}) {
		return true, reasonVendorStructuralEmbedded
	}
	rule, ok := vendorStructuralRules[f.EntityType]
	if !ok {
		return false, ""
	}
	if !rule.match(f.raw) {
		return false, ""
	}
	if rule.vetoable {
		if !contextSuppressed(data, f.raw, alwaysBenignAt) || credentialSuffixLabeled(data, f.raw) {
			return false, ""
		}
	}
	return true, rule.reason
}

// credentialSuffixLabeled reports whether any occurrence of raw is preceded by a
// credential-suffix label (privacy_key=, lithic_token:) that the standalone-word
// credential checks miss. Used to keep vendor UUID findings that are labelled as
// a real key.
func credentialSuffixLabeled(data []byte, raw string) bool {
	rb := []byte(raw)
	if len(rb) == 0 {
		return false
	}
	for off := 0; off+len(rb) <= len(data); {
		i := bytes.Index(data[off:], rb)
		if i < 0 {
			break
		}
		pos := off + i
		lo := pos - credentialContextWindow
		if lo < 0 {
			lo = 0
		}
		if classify.IsCredentialSuffixLabel(string(data[lo:pos])) {
			return true
		}
		off = pos + 1
	}
	return false
}

// distinctiveKeyPrefixes mark keys that cannot be an ID or SHA, so a URL cannot
// hide them: an agent sending one out in a query string is still a leak.
var distinctiveKeyPrefixes = []string{
	"AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxr-", "xoxe", "dop_v1_", "doo_v1_", "dor_v1_",
	"shpat_", "shpca_", "shppa_", "shpss_", "sk-", "sk_live_", "rk_live_", "AIza", "glpat-", "npm_",
}

func hasDistinctiveKeyPrefix(raw string) bool {
	for _, p := range distinctiveKeyPrefixes {
		if strings.HasPrefix(raw, p) {
			return true
		}
	}
	return false
}

// allOccurrences reports whether benign holds at every occurrence of raw. The
// in-URL rule uses it, with no credential-label veto: nobody plants a secret in a URL.
func allOccurrences(data []byte, raw string, benign func(data []byte, pos int) bool) bool {
	rb := []byte(raw)
	if len(rb) == 0 {
		return false
	}
	found := false
	for off := 0; off+len(rb) <= len(data); {
		i := bytes.Index(data[off:], rb)
		if i < 0 {
			break
		}
		pos := off + i
		if !benign(data, pos) {
			return false
		}
		found = true
		off = pos + 1
	}
	return found
}

// inUserinfoAt is the credential slot of https://<user>[:<password>]@host, where a leaked clone token sits.
func inUserinfoAt(data []byte, pos, n int) bool {
	for i := pos + n; i < len(data); i++ {
		switch data[i] {
		case '@':
			return true
		case ':':
			continue
		case '/', '?', '#', ' ', '\t', '\r', '\n', '"', '\'', '`', '<', '>':
			return false
		}
		if i == pos+n {
			return false
		}
	}
	return false
}

func inHTTPURL(data []byte, pos int) bool {
	start := pos
	for start > 0 && !strings.ContainsRune(" \t\r\n\"'`<>()[]{},;|", rune(data[start-1])) {
		start--
	}
	prefix := strings.ToLower(string(data[start:pos]))
	return strings.Contains(prefix, "http://") || strings.Contains(prefix, "https://")
}
