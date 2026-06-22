package tokenizer

import (
	"context"
	"fmt"
)

type Token struct {
	Candidate        string
	Keyword          string
	KeywordFromIdent bool
}

type Tokenizer interface {
	Tokenize(ctx context.Context, data string) []Token
}

const (
	Whitespace = "whitespace"
	Structural = "structural"
	Default    = Whitespace
)

func Select(name string) (Tokenizer, error) {
	switch name {
	case "", Whitespace:
		return whitespaceTokenizer{}, nil
	case Structural:
		return structuralTokenizer{}, nil
	default:
		return nil, fmt.Errorf("unknown tokenizer %q (valid: %q, %q)", name, Whitespace, Structural)
	}
}
