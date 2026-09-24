package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

type suppressionMode int

const (
	suppressionOff suppressionMode = iota
	suppressionShadow
	suppressionEnforce
)

const (
	bulkListMinCount = 20
	bulkShapeMinLen  = 8
)

const (
	reasonBulkList           = "bulk_list"
	reasonStripeObjID        = "structural_stripe_object_id"
	reasonHexHash            = "structural_hex_hash"
	reasonHexTraceID         = "structural_hex_trace_id"
	reasonStructural         = "structural_nonsecret"
	reasonPemPublicBlock     = "structural_pem_public_block"
	reasonStructuralVetoable = "structural_vetoable_id"
	reasonBenignIDContext    = "structural_benign_id_context"
	reasonNonCredentialLabel = "structural_non_credential_label"
	reasonGPGKeyID           = "structural_gpg_key_id"
)

const gpgKeyLabelWindow = 16

const benignIDContextWindow = 24

const hexIDContextWindow = 24

func parseSuppressionMode(raw string) suppressionMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "enforce":
		return suppressionEnforce
	case "off":
		return suppressionOff
	case "shadow":
		return suppressionShadow
	default:
		log.Printf("FP_SUPPRESSION_MODE=%q unrecognized; defaulting to enforce (valid: off, shadow, enforce)", raw)
		return suppressionEnforce
	}
}

func parseVendorSuppressionMode(raw string) suppressionMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return suppressionOff
	case "shadow":
		return suppressionShadow
	case "enforce":
		return suppressionEnforce
	default:
		log.Printf("VENDOR_STRUCTURAL_SUPPRESSION=%q unrecognized; defaulting to off (valid: off, shadow, enforce)", raw)
		return suppressionOff
	}
}

func (m suppressionMode) String() string {
	switch m {
	case suppressionShadow:
		return "shadow"
	case suppressionEnforce:
		return "enforce"
	default:
		return "off"
	}
}

func lenBand(n int) byte {
	switch {
	case n < 12:
		return '0'
	case n <= 24:
		return '1'
	case n <= 48:
		return '2'
	default:
		return '3'
	}
}

func shapeKeyBytes(tok []byte) string {
	var word, dash, under, dot, other bool
	for _, b := range tok {
		switch {
		case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9'):
			word = true
		case b == '-':
			dash = true
		case b == '_':
			under = true
		case b == '.':
			dot = true
		default:
			other = true
		}
	}
	key := make([]byte, 0, 6)
	key = append(key, lenBand(len(tok)))
	for _, f := range []struct {
		set bool
		c   byte
	}{
		{word, 'w'}, {dash, '-'}, {under, '_'}, {dot, '.'}, {other, 'o'},
	} {
		if f.set {
			key = append(key, f.c)
		}
	}
	return string(key)
}

func shapeKey(tok string) string {
	return shapeKeyBytes([]byte(tok))
}

func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.' || b == '_' || b == '-' || b == '+' || b == '/' || b == '~' || b == '@':
		return true
	}
	return false
}

func documentShapes(data []byte) map[string]int {
	shapes := make(map[string]int)
	start := -1
	flush := func(end int) {
		if start >= 0 {
			if end-start >= bulkShapeMinLen {
				shapes[shapeKeyBytes(data[start:end])]++
			}
			start = -1
		}
	}
	for i := 0; i < len(data); i++ {
		if isTokenByte(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return shapes
}

func decideSuppression(f analyzeResult, shapes map[string]int, data []byte) (bool, string) {
	if !isGenericDetectorName(f.EntityType) {
		return false, ""
	}
	if classify.IsStripeObjectID(f.raw) {
		return true, reasonStripeObjID
	}
	if len(f.raw) >= bulkShapeMinLen && shapes[shapeKey(f.raw)] >= bulkListMinCount {
		return true, reasonBulkList
	}
	if classify.IsHex32(f.raw) && contextSuppressed(data, f.raw, func(d []byte, s int) bool {
		return isChecksumRowAt(d, s, len(f.raw))
	}) {
		return true, reasonHexHash
	}
	if classify.IsAllHex(f.raw) && len(f.raw) >= 16 && traceContextSuppressed(data, f.raw, func(d []byte, s int) bool {
		return hexInTraceContextAt(d, s, f.raw)
	}) {
		return true, reasonHexTraceID
	}
	if f.EntityType == customdetectors.GenericSecretName && classify.IsStructuralNonSecret(f.raw) {
		return true, reasonStructural
	}
	if f.EntityType == customdetectors.EntropyName {
		if insidePublicPEMBlock(data, f.raw) {
			return true, reasonPemPublicBlock
		}
		if gpgKeyIDSuppressed(data, f.raw) {
			return true, reasonGPGKeyID
		}
		if classify.IsVetoableStructural(f.raw) && contextSuppressed(data, f.raw, alwaysBenignAt) &&
			!credentialSuffixLabeled(data, f.raw) {
			return true, reasonStructuralVetoable
		}
		if contextSuppressed(data, f.raw, nonCredentialLabelAt) {
			return true, reasonNonCredentialLabel
		}
		if contextSuppressed(data, f.raw, benignIDContextAt) {
			return true, reasonBenignIDContext
		}
	}
	return false, ""
}

// gpgKeyIDSuppressed reports whether EVERY occurrence of raw sits directly after
// gpg's "gpg: key " log label. It does not go through suppressByContext because
// that label contains the word "key", which the credential-context veto there
// would read as a credential assignment; instead every occurrence must carry the
// label, so a key id that also appears under a real credential label elsewhere
// in the document is kept.
func gpgKeyIDSuppressed(data []byte, raw string) bool {
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
		end := pos + len(rb)
		if (pos > 0 && isHexByte(data[pos-1])) || (end < len(data) && isHexByte(data[end])) {
			// Part of a longer hex run; not this value.
			off = pos + 1
			continue
		}
		lo := pos - gpgKeyLabelWindow
		if lo < 0 {
			lo = 0
		}
		if !classify.IsGPGKeyIDInContext(raw, string(data[lo:pos])) {
			return false
		}
		found = true
		off = pos + 1
	}
	return found
}

func benignIDContextAt(data []byte, start int) bool {
	lo := start - benignIDContextWindow
	if lo < 0 {
		lo = 0
	}
	return classify.IsBenignIDContext(string(data[lo:start]))
}

// nonCredentialLabelAt reports whether the value at start is assigned to a
// label whose name can never hold a secret. The assignment has to appear
// within the context window, but the name itself, and the text that proves
// where it begins, are read from the document without that limit -- otherwise
// the answer changes with where the window's edge happens to fall.
func nonCredentialLabelAt(data []byte, start int) bool {
	lo := start - benignIDContextWindow
	if lo < 0 {
		lo = 0
	}
	name, ok := labelNameBefore(data, start, lo)
	return ok && classify.IsNonCredentialLabelName(name)
}

// labelNameBefore returns the complete name that assigns the value at end,
// reporting false when no assignment sits within the window starting at lo.
func labelNameBefore(data []byte, end, lo int) (string, bool) {
	i := end
	for i > lo && (isAssignSpace(data[i-1]) || isQuoteByte(data[i-1])) {
		i-- // the value's opening quote and the space around it
	}
	if i <= lo || (data[i-1] != ':' && data[i-1] != '=') {
		return "", false
	}
	i--
	for i > lo && isAssignSpace(data[i-1]) {
		i--
	}
	if i <= lo {
		return "", false
	}
	if q := data[i-1]; isQuoteByte(q) {
		j := i - 1
		k := j - 1
		for k >= 0 && data[k] != q {
			k--
		}
		if k < 0 || !quotedKeyStandsAlone(data, k) {
			return "", false
		}
		return string(data[k+1 : j]), true
	}
	j := i
	for j > 0 && !classify.IsLabelSeparatorByte(data[j-1]) {
		j--
	}
	if j == i || !startsAName(data, j) {
		return "", false
	}
	return string(data[j:i]), true
}

// startsAName reports whether the name beginning at j is the whole label
// rather than the last word of a longer one. Unquoted text separates tokens on
// spaces, so "signing checksum=" would otherwise read as "checksum". A name
// may follow punctuation or the start of the document; another bare word in
// front of it means the two belong together.
func startsAName(data []byte, j int) bool {
	k := j
	for k > 0 && (data[k-1] == ' ' || data[k-1] == '\t') {
		k-- // only along the line: a newline in front of the name ends it
	}
	if k == 0 {
		return true
	}
	switch data[k-1] {
	case ':', '=', ';', '?', '&':
		// These sit inside one line, where the token in front decides what
		// follows: "Cookie:" and "a=1&" list assignments, while "auth:" and
		// "signing?" name the credential the value belongs to.
		return !credentialIntroducerBefore(data, k-1)
	case '"', '\'', '`', ',', '{', '[', '(':
		// Transparent: whatever introduced the bracket or quote introduces the
		// name too. A key in {"sha256": …} is read before this point, while
		// password = "{sha256=…}" only wraps a value the name is part of.
		return startsAName(data, k-1)
	case '\n', '\r':
		return !introducedByCredentialWord(data, k-1)
	}
	return false
}

// quotedKeyStandsAlone reports whether the quote at the given index opens a
// key of its own rather than continuing a longer name. A dotted assignment
// such as signing."sha256" puts a name byte right against the quote, and a
// bare word in front of it joins the two the same way it does unquoted.
func quotedKeyStandsAlone(data []byte, quote int) bool {
	if quote == 0 {
		return true
	}
	if !classify.IsLabelSeparatorByte(data[quote-1]) {
		return false
	}
	p := quote - 1
	for p > 0 && (data[p] == ' ' || data[p] == '\t') {
		p--
	}
	if data[p] == ' ' || data[p] == '\t' {
		return true // only blank space back to the start
	}
	switch data[p] {
	case ':', '=', ';', '?', '&':
		return !credentialIntroducerBefore(data, p)
	case ',', '{', '[', '(', '\n', '\r':
		return !introducedByCredentialWord(data, p)
	case '"', '\'', '`':
		return true
	}
	return false
}

// introducedByCredentialWord reports whether a credential word stands in front
// of the list or bracket at p. A quote there is left alone: from the right a
// value's closing quote looks exactly like a key's opening one, and reading
// past it would give up the form this rule exists for.
func introducedByCredentialWord(data []byte, p int) bool {
	q := p
	if q < len(data) && (data[q] == '\n' || data[q] == '\r') {
		q = lineEndBeforeComment(data, q)
	}
	for q > 0 {
		switch c := data[q-1]; {
		case c == ' ' || c == '\t' || c == ',' || c == '{' || c == '[' || c == '(':
			q-- // nesting and indentation say nothing; keep looking
		case c == '\n' || c == '\r':
			r := lastNonBlank(data, lineEndBeforeComment(data, q-1))
			if r < 0 {
				return false
			}
			switch data[r] {
			case '{', '[', '(', ',':
				q = r + 1 // the line before ended inside a structure
			case ':', '=':
				return credentialIntroducerBefore(data, r) // assignment wrapped
			default:
				return false // a complete line, so the name starts fresh
			}
		case c == ':' || c == '=' || c == ';' || c == '?' || c == '&':
			return credentialIntroducerBefore(data, q-1)
		case isQuoteByte(c):
			return false
		default:
			return credentialIntroducerBefore(data, q)
		}
	}
	return false
}

// lineEndBeforeComment returns end, or the start of a trailing comment on the
// line ending there. A "password = { # note" line still opens a structure, and
// reading the comment instead of the brace would lose the word that opened it.
// A marker inside a string only ends the line early, which keeps a finding.
func lineEndBeforeComment(data []byte, end int) int {
	start := end
	for start > 0 && data[start-1] != '\n' && data[start-1] != '\r' {
		start--
	}
	for i := start; i < end; i++ {
		if data[i] == '#' || (data[i] == '/' && i+1 < end && data[i+1] == '/') {
			return i
		}
	}
	return end
}

// lastNonBlank returns the index of the last byte before end that is not
// blank, or -1 when there is none.
func lastNonBlank(data []byte, end int) int {
	i := end
	for i > 0 && (data[i-1] == ' ' || data[i-1] == '\t' || data[i-1] == '\n' || data[i-1] == '\r') {
		i--
	}
	return i - 1
}

// credentialIntroducerBefore reports whether the token ending just before the
// separator at sep is a credential word.
func credentialIntroducerBefore(data []byte, sep int) bool {
	e := sep
	// Punctuation can stack up ("auth?:"), and the word is behind all of it.
	for e > 0 && (data[e-1] == ' ' || data[e-1] == '\t' || data[e-1] == ':' ||
		data[e-1] == '=' || data[e-1] == ';' || data[e-1] == '?' || data[e-1] == '&' ||
		isQuoteByte(data[e-1])) {
		e-- // a quoted key closes before its colon: "password": sits between
	}
	s := e
	for s > 0 && !classify.IsLabelSeparatorByte(data[s-1]) &&
		data[s-1] != ':' && data[s-1] != '=' && data[s-1] != ';' &&
		data[s-1] != '?' && data[s-1] != '&' {
		s--
	}
	return s < e && classify.IsCredentialToken(string(data[s:e]))
}

func isAssignSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isQuoteByte(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func alwaysBenignAt(_ []byte, _ int) bool { return true }

// insidePublicPEMBlock reports whether raw is a base64 body line of a public PEM
// armor (CERTIFICATE / PUBLIC KEY) and never a PRIVATE KEY. To avoid a stray or
// truncated "-----BEGIN CERTIFICATE-----" header suppressing an unrelated secret
// that happens to follow it, the token itself must be pure base64 and everything
// between the header and the token must be PEM body (base64 + line separators).
func insidePublicPEMBlock(data []byte, raw string) bool {
	rb := []byte(raw)
	if len(rb) == 0 || !isBase64Body(rb) {
		return false
	}
	// Require EVERY occurrence to sit inside a public PEM body. If the same
	// base64 string also appears elsewhere (e.g. as a real secret, or before the
	// armor), we do not suppress — the identical value at a non-PEM position keeps
	// recall intact.
	found := false
	for off := 0; off+len(rb) <= len(data); {
		i := bytes.Index(data[off:], rb)
		if i < 0 {
			break
		}
		pos := off + i
		if !publicPEMAt(data, pos) {
			return false
		}
		found = true
		off = pos + 1
	}
	return found
}

func publicPEMAt(data []byte, pos int) bool {
	beginMarker := []byte("-----BEGIN ")
	b := bytes.LastIndex(data[:pos], beginMarker)
	if b < 0 {
		return false
	}
	if bytes.Contains(data[b:pos], []byte("-----END ")) {
		return false
	}
	labelStart := b + len(beginMarker)
	dash := bytes.Index(data[labelStart:], []byte("-----"))
	if dash < 0 {
		return false
	}
	label := strings.ToUpper(string(data[labelStart : labelStart+dash]))
	if strings.Contains(label, "PRIVATE") {
		return false
	}
	if !strings.Contains(label, "CERTIFICATE") && !strings.Contains(label, "PUBLIC KEY") {
		return false
	}
	bodyStart := labelStart + dash + len("-----")
	if bodyStart > pos {
		return false
	}
	if !isPEMBodySpan(data[bodyStart:pos]) {
		return false
	}
	return pemBodyStartsWithDERSequence(data, bodyStart)
}

// pemBodyStartsWithDERSequence checks that the armor body begins with 'M', the
// base64 encoding of an ASN.1 SEQUENCE tag (0x30). Every real X.509 certificate
// and SubjectPublicKeyInfo public key is a DER SEQUENCE, so this rejects a stray
// public header followed by a non-DER base64 secret.
func pemBodyStartsWithDERSequence(data []byte, bodyStart int) bool {
	for i := bodyStart; i < len(data); {
		c := data[i]
		if c == '\n' || c == '\r' {
			i++
			continue
		}
		if c == '\\' && i+1 < len(data) && (data[i+1] == 'n' || data[i+1] == 'r') {
			i += 2
			continue
		}
		return c == 'M'
	}
	return false
}

func isBase64Body(b []byte) bool {
	for _, c := range b {
		if !isBase64Byte(c) {
			return false
		}
	}
	return len(b) > 0
}

func isBase64Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
}

// isPEMBodySpan reports whether s is genuine PEM armor body between the header and
// the candidate: base64-only lines of at most 64 chars, delimited by newlines (real
// or the literal "\n"/"\r" escapes present in JSON-encoded prompts), with at least
// one separator so the header is newline-terminated. This rejects prose (spaces,
// punctuation) and un-wrapped runs, so a crafted PEM-like block cannot hide a secret.
func isPEMBodySpan(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	lineLen := 0
	sawSeparator := false
	for i := 0; i < len(s); {
		c := s[i]
		if c == '\n' || c == '\r' {
			lineLen, sawSeparator = 0, true
			i++
			continue
		}
		if c == '\\' && i+1 < len(s) && (s[i+1] == 'n' || s[i+1] == 'r') {
			lineLen, sawSeparator = 0, true
			i += 2
			continue
		}
		if !isBase64Byte(c) {
			return false
		}
		lineLen++
		if lineLen > 64 {
			return false
		}
		i++
	}
	return sawSeparator
}

const (
	credentialContextWindow = 32
	credentialKeywordWindow = 16
)

func suppressByContext(data []byte, raw string, requireAll bool, benignAt func(data []byte, start int) bool) bool {
	rb := []byte(raw)
	if len(rb) == 0 {
		return false
	}
	anyBenign := false
	for off := 0; off+len(rb) <= len(data); {
		i := bytes.Index(data[off:], rb)
		if i < 0 {
			break
		}
		pos := off + i
		end := pos + len(rb)
		if (isAlnumByte(rb[0]) && pos > 0 && isAlnumByte(data[pos-1])) ||
			(isAlnumByte(rb[len(rb)-1]) && end < len(data) && isAlnumByte(data[end])) {
			off = pos + 1
			continue
		}
		lo := pos - credentialContextWindow
		if lo < 0 {
			lo = 0
		}
		if classify.IsCredentialAssignment(string(data[lo:pos])) {
			return false
		}
		klo := pos - credentialKeywordWindow
		if klo < 0 {
			klo = 0
		}
		if classify.IsCredentialContext(string(data[klo:pos])) {
			return false
		}
		if benignAt(data, pos) {
			anyBenign = true
		} else if requireAll {
			return false
		}
		off = pos + 1
	}
	return anyBenign
}

func contextSuppressed(data []byte, raw string, benignAt func(data []byte, start int) bool) bool {
	return suppressByContext(data, raw, true, benignAt)
}

func traceContextSuppressed(data []byte, raw string, benignAt func(data []byte, start int) bool) bool {
	return suppressByContext(data, raw, false, benignAt)
}

func isChecksumRowAt(data []byte, start, n int) bool {
	off := start + n
	if off > len(data) {
		return false
	}
	rest := data[off:]
	spaces := 0
	for spaces < len(rest) && (rest[spaces] == ' ' || rest[spaces] == '\t') {
		spaces++
	}
	if spaces == 0 {
		return false
	}
	rest = rest[spaces:]
	if len(rest) > 0 && rest[0] == '*' {
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && rest[end] != ' ' && rest[end] != '\t' && rest[end] != '\n' && rest[end] != '\r' {
		end++
	}
	token := rest[:end]
	return len(token) > 0 && (bytes.IndexByte(token, '/') >= 0 || bytes.IndexByte(token, '.') >= 0)
}

func hexInTraceContextAt(data []byte, start int, raw string) bool {
	lo := start - hexIDContextWindow
	if lo < 0 {
		lo = 0
	}
	if classify.IsHexIDInContext(raw, string(data[lo:start])) {
		return true
	}
	end := start + len(raw)
	return start > 0 && end < len(data) && data[start-1] == '-' && data[end] == '-' &&
		hexChainNeighbor(data, start-1, -1) && hexChainNeighbor(data, end, +1)
}

func isAlnumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexChainNeighbor(data []byte, dashPos, dir int) bool {
	i := dashPos + dir
	n := 0
	for i >= 0 && i < len(data) && isHexByte(data[i]) {
		n++
		i += dir
	}
	if n == 0 {
		return false
	}
	if i >= 0 && i < len(data) {
		c := data[i]
		if (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z') || c == '_' {
			return false
		}
	}
	return true
}

// shapes counts token shapes across the WHOLE request, not the window being
// scanned: bulk-list suppression asks whether a value is one of many alike in
// the document, and a window cannot answer that.
func (s *scanner) applySuppression(ctx context.Context, in []analyzeResult, data []byte, shapes map[string]int) []analyzeResult {
	if s.mode == suppressionOff && s.vendorMode == suppressionOff {
		return in
	}
	// A nil map means the caller has no wider view than the data it passed.
	if shapes == nil && s.mode != suppressionOff {
		shapes = documentShapes(data)
	}
	kept := make([]analyzeResult, 0, len(in))
	counts := map[string]int{}
	for _, f := range in {
		suppress, reason, mode := s.decideAny(f, shapes, data)
		if !suppress {
			kept = append(kept, f)
			continue
		}
		findingsSuppressedTotal.WithLabelValues(reason, f.EntityType, mode.String()).Inc()
		counts[reason]++
		if mode == suppressionShadow {
			kept = append(kept, f)
		}
	}
	if len(counts) > 0 {
		total, summary := summarizeCounts(counts)
		log.Printf("scan suppressed req=%s fp_mode=%s vendor_mode=%s total=%d reasons=%s", reqIDFrom(ctx), s.mode, s.vendorMode, total, summary)
	}
	return kept
}

func (s *scanner) decideAny(f analyzeResult, shapes map[string]int, data []byte) (bool, string, suppressionMode) {
	if s.mode != suppressionOff {
		if suppress, reason := decideSuppression(f, shapes, data); suppress {
			return true, reason, s.mode
		}
	}
	if s.vendorMode != suppressionOff && !isGenericDetectorName(f.EntityType) {
		if isCuratedVendor(f.EntityType) {
			vendorFindingsEvaluatedTotal.WithLabelValues(f.EntityType, s.vendorMode.String()).Inc()
		}
		if suppress, reason := decideVendorSuppression(f, data); suppress {
			return true, reason, s.vendorMode
		}
	}
	return false, "", suppressionOff
}

func summarizeCounts(counts map[string]int) (int, string) {
	keys := make([]string, 0, len(counts))
	total := 0
	for k, v := range counts {
		keys = append(keys, k)
		total += v
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, counts[k])
	}
	return total, strings.Join(parts, ",")
}
