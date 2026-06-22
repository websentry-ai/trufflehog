package tokenizer

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rivo/uniseg"
)

const (
	maxTokens         = 1 << 20
	cancelCheckStride = 64 << 10
)

type structuralTokenizer struct{}

var _ Tokenizer = structuralTokenizer{}

type emitter struct {
	data   string
	tokens []Token
	last   Token
	hasOne bool
}

func (e *emitter) capped() bool {
	return len(e.tokens) >= maxTokens
}

func (e *emitter) emit(start, end int, keyword string, fromIdent bool) {
	if e.capped() || start >= end {
		return
	}
	candidate := e.data[start:end]
	if candidate == "" {
		return
	}
	tok := Token{Candidate: candidate, Keyword: keyword, KeywordFromIdent: fromIdent}
	if e.hasOne && e.last == tok {
		return
	}
	e.tokens = append(e.tokens, tok)
	e.last = tok
	e.hasOne = true
}

func (structuralTokenizer) Tokenize(ctx context.Context, data string) []Token {
	e := &emitter{data: data, tokens: make([]Token, 0, 16)}

	nextCancelCheck := cancelCheckStride
	pos := 0
	n := len(data)

	for pos < n {
		if pos >= nextCancelCheck {
			if ctx.Err() != nil {
				return e.tokens
			}
			nextCancelCheck += cancelCheckStride
		}

		r, size := utf8.DecodeRuneInString(data[pos:])
		if isFieldSpace(r) {
			pos += size
			continue
		}

		fieldStart := pos
		for pos < n {
			r, size := utf8.DecodeRuneInString(data[pos:])
			if isFieldSpace(r) {
				break
			}
			pos += size
		}
		fieldEnd := pos

		if e.capped() {
			break
		}
		emitField(e, fieldStart, fieldEnd)
		e.hasOne = false
	}

	return e.tokens
}

func isFieldSpace(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	return unicode.IsSpace(r)
}

func emitField(e *emitter, start, end int) {
	cs, ce := trimRange(e.data, start, end)
	if cs >= ce {
		return
	}

	emitStructured(e, start, end)
	emitWhitespaceEquivalent(e, cs, ce)

	if isProse(e.data[cs:ce]) {
		emitWords(e, cs, ce)
	}
}

func emitWhitespaceEquivalent(e *emitter, start, end int) {
	core := e.data[start:end]
	if loc := identPrefixPat.FindStringIndex(core); loc != nil {
		keyEnd := start + loc[1]
		e.emit(keyEnd, end, lowerSlice(e.data, start, keyEnd), true)
		return
	}
	e.emit(start, end, lowerSlice(e.data, start, end), false)
}

func emitStructured(e *emitter, start, end int) {
	inner := skipOpenBrackets(e.data, start, end)

	if schemeEnd, ok := matchScheme(e.data[inner:end]); ok {
		emitURL(e, end, inner+schemeEnd)
		return
	}

	if emitJSONPair(e, inner, end) {
		return
	}

	field := e.data[inner:end]
	if loc := identPrefixPat.FindStringIndex(field); loc != nil {
		keyEnd := inner + loc[1]
		keyword := lowerSlice(e.data, inner, keyEnd)
		valStart, valEnd := unquoteRange(e.data, keyEnd, end)
		e.emit(valStart, valEnd, keyword, true)
	}
}

func skipOpenBrackets(data string, start, end int) int {
	for start < end {
		switch data[start] {
		case '{', '[', '(', '<':
			start++
		default:
			return start
		}
	}
	return start
}

func emitJSONPair(e *emitter, start, end int) bool {
	keyStart, keyEnd, sep, ok := scanQuotedKey(e.data, start, end)
	if !ok {
		return false
	}
	valStart, valEnd := unquoteRange(e.data, sep, end)
	keyword := lowerSlice(e.data, keyStart, keyEnd)
	e.emit(valStart, valEnd, keyword, true)
	return true
}

func scanQuotedKey(data string, start, end int) (int, int, int, bool) {
	if start >= end || data[start] != '"' {
		return 0, 0, 0, false
	}
	keyStart := start + 1
	pos := keyStart
	for pos < end && data[pos] != '"' {
		pos++
	}
	if pos >= end {
		return 0, 0, 0, false
	}
	keyEnd := pos
	pos++
	if pos >= end || data[pos] != ':' {
		return 0, 0, 0, false
	}
	if keyEnd <= keyStart {
		return 0, 0, 0, false
	}
	return keyStart, keyEnd, pos + 1, true
}

func emitURL(e *emitter, end, afterScheme int) {
	authEnd := afterScheme
	for authEnd < end {
		c := e.data[authEnd]
		if c == '/' || c == '?' || c == '#' {
			break
		}
		authEnd++
	}

	if at := strings.LastIndexByte(e.data[afterScheme:authEnd], '@'); at >= 0 {
		credEnd := afterScheme + at
		if colon := strings.IndexByte(e.data[afterScheme:credEnd], ':'); colon >= 0 {
			passStart := afterScheme + colon + 1
			userStart := afterScheme
			userEnd := afterScheme + colon
			e.emit(passStart, credEnd, lowerSlice(e.data, userStart, userEnd), true)
		}
	}

	if q := strings.IndexByte(e.data[authEnd:end], '?'); q >= 0 {
		emitQuery(e, authEnd+q+1, end)
	}
}

func emitQuery(e *emitter, start, end int) {
	pos := start
	for pos < end {
		pairEnd := pos
		for pairEnd < end && e.data[pairEnd] != '&' {
			pairEnd++
		}
		if eq := strings.IndexByte(e.data[pos:pairEnd], '='); eq >= 0 {
			keyStart := pos
			keyEnd := pos + eq
			valStart := pos + eq + 1
			e.emit(valStart, pairEnd, lowerSlice(e.data, keyStart, keyEnd), true)
		}
		pos = pairEnd + 1
	}
}

func emitWords(e *emitter, start, end int) {
	field := e.data[start:end]
	pos := start
	state := -1
	rest := field
	for len(rest) > 0 {
		if e.capped() {
			return
		}
		var word string
		word, rest, state = uniseg.FirstWordInString(rest, state)
		wStart := pos
		wEnd := pos + len(word)
		if hasLetterOrDigit(word) {
			e.emit(wStart, wEnd, lowerSlice(e.data, wStart, wEnd), false)
		}
		pos = wEnd
	}
}

func trimRange(data string, start, end int) (int, int) {
	for start < end {
		r, size := utf8.DecodeRuneInString(data[start:end])
		if !isCutset(r) {
			break
		}
		start += size
	}
	for end > start {
		r, size := utf8.DecodeLastRuneInString(data[start:end])
		if !isCutset(r) {
			break
		}
		end -= size
	}
	return start, end
}

func unquoteRange(data string, start, end int) (int, int) {
	if end-start >= 2 {
		first := data[start]
		last := data[end-1]
		if (first == '"' || first == '\'' || first == '`') && first == last {
			return start + 1, end - 1
		}
	}
	return trimRange(data, start, end)
}

func isCutset(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	return strings.ContainsRune(trimCutset, r)
}

func matchScheme(field string) (int, bool) {
	i := 0
	n := len(field)
	if i >= n || !isAlpha(field[i]) {
		return 0, false
	}
	i++
	for i < n {
		c := field[i]
		if isAlpha(c) || isDigit(c) || c == '+' || c == '.' || c == '-' {
			i++
			continue
		}
		break
	}
	if i+3 <= n && field[i] == ':' && field[i+1] == '/' && field[i+2] == '/' {
		return i + 3, true
	}
	return 0, false
}

func isProse(s string) bool {
	var letters int
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsSpace(r):
		case isStructuralMarker(r):
			return false
		}
	}
	return letters > 0
}

func isStructuralMarker(r rune) bool {
	switch r {
	case '=', ':', '/', '@', '?', '&', '"', '\'', '`', '\\', ';', '{', '}', '[', ']', '<', '>':
		return true
	}
	return false
}

func hasLetterOrDigit(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func lowerSlice(data string, start, end int) string {
	return strings.ToLower(data[start:end])
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
