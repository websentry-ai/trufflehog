package main

import (
	"context"
	"testing"
)

// detectors.PrefixRegex matches a keyword anywhere, with no word boundary, so a
// keyword that is a fragment of an ordinary word reaches the key pattern on
// prose alone. These two were the cases that showed up: "tly" ends recently and
// currently, "wit" starts with and width.
func TestKeywordBleedStaysSilent(t *testing.T) {
	prose := []string{
		"recently rotated: aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM",
		"currently set to aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM",
		"exactly one of aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS7mP9qT2vX4zA6bC8dF1gH3jK5lM",
		"with the header X ABCDEFGH12345678IJKLMNOP90QRSTUV set",
		"width of ABCDEFGH12345678IJKLMNOP90QRSTUV pixels",
		"without ABCDEFGH12345678IJKLMNOP90QRSTUV configured",
		// "wit" is also a word in its own right, so a bare space after the
		// keyword is not enough to tell config from prose.
		"the wit and wisdom of ABCDEFGH12345678IJKLMNOP90QRSTUV in review",
		"wit is required: ABCDEFGH12345678IJKLMNOP90QRSTUV",
		"a quick wit, see ABCDEFGH12345678IJKLMNOP90QRSTUV",
	}
	s := newBuiltScanner(t)
	for _, text := range prose {
		for _, r := range s.scan(context.Background(), []byte(text), 0.75) {
			if r.EntityType == "TLy" || r.EntityType == "Wit" {
				t.Errorf("%s fired on prose: %q in %q", r.EntityType, text[r.Start:r.End], text)
			}
		}
	}
}

// The keyword still has to be recognised where it is genuinely written.
func TestKeywordStillMatchesRealConfig(t *testing.T) {
	cases := []struct{ name, entity, text string }{
		{"tly underscore", "TLy", "TLY_API_KEY=VLmhHAQq7kjrhxrt7x07pJjnafVRara2aoqPndSOepXH2MOY3CcloWwG6ZcD"},
		{"tly colon", "TLy", "tly: VLmhHAQq7kjrhxrt7x07pJjnafVRara2aoqPndSOepXH2MOY3CcloWwG6ZcD"},
		{"tly spaced", "TLy", "tly api key VLmhHAQq7kjrhxrt7x07pJjnafVRara2aoqPndSOepXH2MOY3CcloWwG6ZcD"},
		{"wit underscore", "Wit", "WIT_AI_TOKEN=ABCDEFGH12345678IJKLMNOP90QRSTUV"},
		{"wit dotted", "Wit", "wit.ai token ABCDEFGH12345678IJKLMNOP90QRSTUV"},
		{"wit assigned", "Wit", "wit token = 'ABCDEFGH12345678IJKLMNOP90QRSTUV'"},
	}
	s := newBuiltScanner(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, r := range s.scan(context.Background(), []byte(c.text), 0.75) {
				if r.EntityType == c.entity {
					return
				}
			}
			t.Fatalf("%s did not fire on %q", c.entity, c.text)
		})
	}
}
