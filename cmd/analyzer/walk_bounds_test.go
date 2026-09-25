package main

import (
	"strings"
	"testing"
)

// The work one finding may spend looking for the word that introduces its
// label is capped, and the cap is shared by the whole walk. Bounding each scan
// on its own was not enough: the recursive steps restarted the count, so a
// document with enough nesting spent it again at every level.
//
// Asserted on the budget rather than on a clock, so it cannot flake and does
// not care how loaded the machine is.
func TestOneFindingCannotReadTheWholeRequest(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	pathological := map[string]string{
		"blank lines":     "api_key=x\n" + strings.Repeat("\n", 200000) + `"sha256": "` + secret + `"`,
		"nested brackets": strings.Repeat("[\n", 100000) + `{"sha256": "` + secret + `", "api_key": "x"}` + strings.Repeat("]", 100000),
		"open quotes":     strings.Repeat(`"`, 200000) + `sha256=` + secret,
		"indented keys":   strings.Repeat("a:\n  b: c\n", 20000) + "  sha256: " + secret,
	}
	for name, doc := range pathological {
		t.Run(name, func(t *testing.T) {
			data := []byte(doc)
			start := strings.Index(doc, secret)
			b := newWalkBudget()
			introducedByCredentialWord(data, start-1, b)
			if b.remaining > 0 {
				return // it answered without needing the whole budget, which is fine
			}
			// It ran out, which is the point: it stopped rather than reading on.
			if b.remaining < -credentialWalkBudget {
				t.Errorf("%s: overspent the budget by %d bytes", name, -b.remaining)
			}
		})
	}
}

// Running out of context keeps the finding. The rule only removes one when it
// is sure, and it cannot be sure about text it never read -- so an exhausted
// budget has to answer the way a credential word would, not the way silence
// would. The two coming out alike is how a bound turns into a missed secret.
func TestAnExhaustedBudgetKeepsTheFinding(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	doc := `{"webhook_secret": {` +
		strings.Repeat(`"pad": "`+strings.Repeat("x", 80)+`", `, 200) +
		`"sha256": "` + secret + `"}}`
	data := []byte(doc)
	b := newWalkBudget()
	introduced := introducedByCredentialWord(data, strings.Index(doc, secret)-1, b)
	if b.remaining > 0 {
		t.Fatalf("the document no longer exhausts the budget (%d left), so this proves nothing", b.remaining)
	}
	if !introduced {
		t.Errorf("an exhausted budget answered as though no credential word were there")
	}
}
