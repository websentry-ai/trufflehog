package tokenizer

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

const trimCutset = "\"'`.,;:()[]{}<>"

var identPrefixPat = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*[=:]`)

type whitespaceTokenizer struct{}

var _ Tokenizer = whitespaceTokenizer{}

func (whitespaceTokenizer) Tokenize(_ context.Context, data string) []Token {
	fields := strings.Fields(data)
	tokens := make([]Token, 0, len(fields))
	for _, f := range fields {
		core := strings.Trim(f, trimCutset)
		if core == "" {
			continue
		}
		candidate, keyword := core, core
		var keywordFromIdent bool
		if loc := identPrefixPat.FindStringIndex(core); loc != nil {
			candidate = core[loc[1]:]
			keyword = core[:loc[1]]
			keywordFromIdent = true
		}
		tokens = append(tokens, Token{
			Candidate:        candidate,
			Keyword:          strings.ToLower(keyword),
			KeywordFromIdent: keywordFromIdent,
		})
	}
	return tokens
}
