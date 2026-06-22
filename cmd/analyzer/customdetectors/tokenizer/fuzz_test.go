package tokenizer

import (
	"context"
	"strings"
	"testing"
)

func FuzzTokenize(f *testing.F) {
	seeds := []string{
		`unterminated "quote aB3xKp9Qm2Lr7TzWqDv`,
		strings.Repeat("=", 1<<20),
		strings.Repeat("a", 1<<20),
		"\xff\xfe\xff\xfe\xff\xfe invalid",
		"\xed\xa0\x80 lone surrogate bytes",
		"é́́́́́́́́ combining flood",
		strings.Repeat("👩‍💻", 4096),
		`API_KEY=aB3xKp9Qm2Lr7TzWqDv`,
		`postgres://u:p@h/db?a=b&c=d`,
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	tk := structuralTokenizer{}
	f.Fuzz(func(t *testing.T, data string) {
		tokens := tk.Tokenize(context.Background(), data)
		for _, tok := range tokens {
			if tok.Candidate == "" {
				t.Fatalf("empty candidate for input %q", data)
			}
			if !strings.Contains(data, tok.Candidate) {
				t.Fatalf("candidate %q not a substring of input %q", tok.Candidate, data)
			}
		}
	})
}
