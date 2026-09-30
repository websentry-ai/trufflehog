package main

import (
	"bytes"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
)

const (
	reasonVendorStructuralUUID       = "vendor_structural_uuid"
	reasonVendorStructuralCode       = "vendor_structural_code"
	reasonVendorStructuralConnString = "vendor_structural_connstring"
	reasonVendorStructuralDigest     = "vendor_structural_digest"
	reasonVendorStructuralEmbedded   = "vendor_structural_embedded"
	reasonVendorStructuralNoise      = "vendor_structural_noise"
)

const digestContextWindow = 16

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
	"JiraToken": {match: classify.IsAtlassianNoise, reason: reasonVendorStructuralNoise, vetoable: true},
	"Atlassian": {match: classify.IsAtlassianNoise, reason: reasonVendorStructuralNoise, vetoable: true},
	"Privacy":   {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID, vetoable: true},
	"Onesignal": {match: classify.IsUUIDish, reason: reasonVendorStructuralUUID, vetoable: true},
	"URI":       {match: classify.IsPlaceholderURI, reason: reasonVendorStructuralNoise},
	"Azure":     {match: classify.IsCodeLike, reason: reasonVendorStructuralCode},
	"JDBC":      {match: classify.IsNonSecretConnString, reason: reasonVendorStructuralConnString},
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
	if contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		lo := s - digestContextWindow
		if lo < 0 {
			lo = 0
		}
		return classify.IsHexDigestInContext(f.raw, string(d[lo:s]))
	}) {
		return true, reasonVendorStructuralDigest
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
