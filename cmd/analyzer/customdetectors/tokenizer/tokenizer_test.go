package tokenizer

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func candidateSet(tokens []Token) map[string]bool {
	out := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		out[t.Candidate] = true
	}
	return out
}

func keywordFor(tokens []Token, candidate string) (string, bool) {
	for _, t := range tokens {
		if t.Candidate == candidate {
			return t.Keyword, true
		}
	}
	return "", false
}

var goldenInputs = map[string]string{
	"key_equals_value":   `API_KEY=aB3xKp9Qm2Lr7TzWqDv`,
	"key_colon_space":    `secret: aB3xKp9Qm2Lr7TzWqDv`,
	"json_pair":          `{"api_key":"aB3xKp9Qm2Lr7TzWqDv"}`,
	"json_unquoted_key":  `api_key:"aB3xKp9Qm2Lr7TzWqDv"`,
	"env_line":           `DATABASE_PASSWORD=s3cr3tValue99Xy`,
	"url_with_creds":     `postgres://admin:s3cr3tValue99Xy@db.example.com:5432/app`,
	"url_query":          `https://host/cb?token=aB3xKp9Qm2Lr7TzWqDv&state=xyz123abc456`,
	"authorization":      `Authorization: Bearer aB3xKp9Qm2Lr7TzWqDv`,
	"prose":              `please rotate the production credential before friday`,
	"multibyte_cafe":     `café résumé naïve`,
	"emoji_zwj":          `hello 👩‍💻 world`,
	"combining_marks":    `élément value`,
}

func TestTokenizers_GoldenCandidates(t *testing.T) {
	cases := []struct {
		name      string
		tokenizer Tokenizer
		input     string
		want      []string
		wantKey   map[string]string
	}{
		{
			name:      "whitespace_key_equals_value",
			tokenizer: whitespaceTokenizer{},
			input:     goldenInputs["key_equals_value"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
			wantKey:   map[string]string{"aB3xKp9Qm2Lr7TzWqDv": "api_key="},
		},
		{
			name:      "whitespace_key_colon_space",
			tokenizer: whitespaceTokenizer{},
			input:     goldenInputs["key_colon_space"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
		},
		{
			name:      "structural_key_equals_value",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["key_equals_value"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
			wantKey:   map[string]string{"aB3xKp9Qm2Lr7TzWqDv": "api_key="},
		},
		{
			name:      "structural_json_pair",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["json_pair"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
			wantKey:   map[string]string{"aB3xKp9Qm2Lr7TzWqDv": "api_key"},
		},
		{
			name:      "structural_json_unquoted_key",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["json_unquoted_key"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
			wantKey:   map[string]string{"aB3xKp9Qm2Lr7TzWqDv": "api_key:"},
		},
		{
			name:      "structural_url_with_creds",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["url_with_creds"],
			want:      []string{"s3cr3tValue99Xy"},
			wantKey:   map[string]string{"s3cr3tValue99Xy": "admin"},
		},
		{
			name:      "structural_url_query",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["url_query"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv", "xyz123abc456"},
			wantKey:   map[string]string{"aB3xKp9Qm2Lr7TzWqDv": "token", "xyz123abc456": "state"},
		},
		{
			name:      "structural_authorization",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["authorization"],
			want:      []string{"aB3xKp9Qm2Lr7TzWqDv"},
		},
		{
			name:      "structural_prose_words",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["prose"],
			want:      []string{"rotate", "production", "credential"},
		},
		{
			name:      "structural_multibyte",
			tokenizer: structuralTokenizer{},
			input:     goldenInputs["multibyte_cafe"],
			want:      []string{"café", "résumé", "naïve"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokens := tc.tokenizer.Tokenize(context.Background(), tc.input)
			set := candidateSet(tokens)
			for _, w := range tc.want {
				require.True(t, set[w], "expected candidate %q in %v", w, candidatesOf(tokens))
			}
			for cand, key := range tc.wantKey {
				got, ok := keywordFor(tokens, cand)
				require.True(t, ok, "candidate %q missing", cand)
				require.Equal(t, key, got, "keyword for %q", cand)
			}
		})
	}
}

func candidatesOf(tokens []Token) []string {
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = t.Candidate
	}
	return out
}

func TestSubstringSafety_AllFixtures(t *testing.T) {
	adversarial := []string{
		`unterminated "quote here aB3xKp9Qm2Lr7TzWqDv`,
		strings.Repeat("=", 4096),
		strings.Repeat("a", 100000),
		"\xff\xfe\xfd invalid utf8 aB3xKp9Qm2Lr7TzWqDv",
		"👩‍👩‍👧‍👦 family aB3xKp9Qm2Lr7TzWqDv",
		"é́́́ combining aB3xKp9Qm2Lr7TzWqDv",
		"=value:other@host?a=b&c=d",
		"",
		"   \t\n   ",
	}

	var inputs []string
	for _, v := range goldenInputs {
		inputs = append(inputs, v)
	}
	inputs = append(inputs, adversarial...)

	tokenizers := []Tokenizer{whitespaceTokenizer{}, structuralTokenizer{}}
	for _, tk := range tokenizers {
		for _, in := range inputs {
			tokens := tk.Tokenize(context.Background(), in)
			for _, tok := range tokens {
				require.NotEmpty(t, tok.Candidate, "empty candidate for input %q", in)
				require.True(t, strings.Contains(in, tok.Candidate),
					"candidate %q not a substring of input %q", tok.Candidate, in)
			}
		}
	}
}

func TestStructuralIsSupersetOfWhitespace(t *testing.T) {
	inputs := []string{
		goldenInputs["key_equals_value"],
		goldenInputs["key_colon_space"],
		goldenInputs["env_line"],
		goldenInputs["url_with_creds"],
		goldenInputs["url_query"],
		goldenInputs["authorization"],
		goldenInputs["prose"],
		goldenInputs["json_pair"],
		`rotate this secret: aB3xKp9Qm2Lr7TzWqDv`,
		`config['SECRET_KEY'] = "aB3xKp9Qm2Lr7TzWqDvNm"`,
	}

	ws := whitespaceTokenizer{}
	st := structuralTokenizer{}
	for _, in := range inputs {
		wsSet := candidateSet(ws.Tokenize(context.Background(), in))
		stSet := candidateSet(st.Tokenize(context.Background(), in))
		for cand := range wsSet {
			require.True(t, stSet[cand],
				"structural set missing whitespace candidate %q for input %q", cand, in)
		}
	}
}

func TestSelect(t *testing.T) {
	cases := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{name: "", want: Whitespace},
		{name: Whitespace, want: Whitespace},
		{name: Structural, want: Structural},
		{name: "bogus", wantErr: true},
	}
	for _, tc := range cases {
		tok, err := Select(tc.name)
		if tc.wantErr {
			require.Error(t, err)
			require.Nil(t, tok)
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, tok)
	}
}

func TestStructuralRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tokens := structuralTokenizer{}.Tokenize(ctx, strings.Repeat("token=value ", 100000))
	require.LessOrEqual(t, len(tokens), maxTokens)
}

func TestStructuralTokenCap(t *testing.T) {
	tokens := structuralTokenizer{}.Tokenize(context.Background(), strings.Repeat("a ", maxTokens+1000))
	require.LessOrEqual(t, len(tokens), maxTokens)
}
