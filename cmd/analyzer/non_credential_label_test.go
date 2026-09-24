package main

import (
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
)

// found reports the entity types the scanner assigned to the given value.
func found(t *testing.T, doc, value string) []string {
	t.Helper()
	var hits []string
	for _, r := range scanProd(t, doc) {
		if r.Start >= 0 && r.End <= len(doc) && doc[r.Start:r.End] == value {
			hits = append(hits, r.EntityType)
		}
	}
	return hits
}

// A digest or an analytics cookie carries no credential keyword of its own, so
// the entropy detector only reaches it by borrowing one from a neighbouring
// field. The label on the value itself settles it: nothing under sha256 or _ga
// is a secret, however close the next line's api_key sits.
func TestABorrowedKeywordDoesNotFlagANonCredentialLabel(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	cases := []struct {
		name      string
		doc       string
		alsoKeeps string // the real credential in the same document
	}{
		{
			name: "sha256 beside apiKey",
			doc: `{
  "apiKey": "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
  "sha256": "` + benign + `"
}`,
			alsoKeeps: "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
		},
		{
			name: "md5 beside a token",
			doc: `token: Wx2Yv6Bn3Kc8Jd5Hf1Gp0SQz7Lm4Rt9
md5: ` + benign,
			alsoKeeps: "Wx2Yv6Bn3Kc8Jd5Hf1Gp0SQz7Lm4Rt9",
		},
		{
			name: "checksum beside a password",
			doc: `password = Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S
checksum = ` + benign,
			alsoKeeps: "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
		},
		{
			name:      "_ga in a cookie header beside authorization",
			doc:       "curl 'https://app.example.com/v2/report' \\\n  -H 'authorization: Bearer Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S' \\\n  -H 'cookie: _ga=" + benign + "'",
			alsoKeeps: "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
		},
		{
			name:      "_uetvid in a cookie beside a bearer token",
			doc:       "Authorization: Bearer Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S\nCookie: _uetvid=" + benign,
			alsoKeeps: "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
		},
		{
			name: "digest beside a client secret",
			doc: `client_secret: Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S
digest: ` + benign,
			alsoKeeps: "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hits := found(t, c.doc, benign); len(hits) > 0 {
				t.Errorf("value under a non-credential label was reported as %v", hits)
			}
			if len(found(t, c.doc, c.alsoKeeps)) == 0 {
				t.Errorf("the real credential in the same document was not reported")
			}
		})
	}
}

// The labels above are matched whole, so a longer name that merely contains
// one still reports. Each case puts a credential keyword in the next field,
// which is the only reason the detector reaches the value at all.
func TestALabelThatMerelyContainsADigestWordIsStillRaised(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const neighbour = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	labels := []string{
		// carry a credential word of their own
		"sha256_key", "md5_secret", "checksum_token", "digest_password",
		"uet_api_key", "ga_api_key", "app_secret", "signing_digest_key",
		// carry none, so only the whole-label matching keeps them
		"my_sha256", "prev_checksum", "content_md5", "signing_digest",
	}
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			doc := `{"api_key": "` + neighbour + `", "` + label + `": "` + secret + `"}`
			if len(found(t, doc, secret)) == 0 {
				t.Errorf("a secret under %q was not reported", label)
			}
		})
	}
}

// A value whose own label is benign stays benign, but the credential beside it
// must still be reported even when the two share a line.
func TestBenignAndCredentialLabelsOnOneLine(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	doc := `{"sha256": "` + benign + `", "api_key": "` + secret + `"}`
	if hits := found(t, doc, benign); len(hits) > 0 {
		t.Errorf("the digest was reported as %v", hits)
	}
	if len(found(t, doc, secret)) == 0 {
		t.Errorf("the api_key on the same line was not reported")
	}
	if strings.Count(doc, benign) != 1 {
		t.Fatal("fixture no longer holds one copy of each value")
	}
}

// These name a row, not a credential, so a neighbouring api_key must not drag
// their value into a finding. Each is the label the judge kept dismissing.
func TestIdentifierLabelsAreNotDraggedInByANeighbour(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	labels := []string{
		"action_id", "actioner_id", "actionerId", "error_id", "page_id",
		"project_id", "langfuse_project_id", "subaccount_id", "account_id",
		"visitor_id", "device_id", "tenant_id",
	}
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			doc := `{"api_key": "` + secret + `", "` + label + `": "` + benign + `"}`
			if hits := found(t, doc, benign); len(hits) > 0 {
				t.Errorf("the identifier was reported as %v", hits)
			}
			if len(found(t, doc, secret)) == 0 {
				t.Errorf("the api_key beside it was not reported")
			}
		})
	}
}

// The boundary of the list above, kept deliberately narrow. Each of these
// names one half of a credential pair or a bearer value in its own right, so
// they stay reportable; widening the list to cover them needs its own argument.
func TestIdentifierLabelsThatStayReportable(t *testing.T) {
	const value = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	for _, label := range []string{"client_id", "app_id", "twilio_app_id", "session_id", "user_id"} {
		t.Run(label, func(t *testing.T) {
			doc := `{"api_key": "` + secret + `", "` + label + `": "` + value + `"}`
			if len(found(t, doc, value)) == 0 {
				t.Errorf("%q is outside the benign list and must stay reportable", label)
			}
		})
	}
}

// The header spelling of a digest. `x-sha256:` and `sha-256:` name the same
// thing as `sha256:` and are suppressed with it.
func TestHyphenatedDigestLabels(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	for _, label := range []string{"x-sha256", "sha-256", "x-checksum", "sha-1"} {
		t.Run(label, func(t *testing.T) {
			doc := "authorization: Bearer " + secret + "\n" + label + ": " + benign
			if hits := found(t, doc, benign); len(hits) > 0 {
				t.Errorf("the digest header was reported as %v", hits)
			}
			if len(found(t, doc, secret)) == 0 {
				t.Errorf("the bearer token was not reported")
			}
		})
	}
}

// The identifier prefixes carry no left boundary, matching the list they were
// added to, so a longer word ending in one of them is benign as well. These
// are all row identifiers, so that is the intended reach rather than an
// accident of the pattern.
func TestIdentifierPrefixesHaveNoLeftBoundary(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	for _, label := range []string{"transaction_id", "interaction_id", "service_account_id"} {
		t.Run(label, func(t *testing.T) {
			doc := `{"api_key": "` + secret + `", "` + label + `": "` + benign + `"}`
			if hits := found(t, doc, benign); len(hits) > 0 {
				t.Errorf("the identifier was reported as %v", hits)
			}
			if len(found(t, doc, secret)) == 0 {
				t.Errorf("the api_key beside it was not reported")
			}
		})
	}
}

// A suppressed checksum must not be counted as a benign id: the two rules
// answer different questions and the counters are read separately.
func TestSuppressionReasonsAreDistinct(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	digest := analyzeResult{EntityType: customdetectors.EntropyName, raw: benign}
	doc := []byte(`{"api_key": "` + secret + `", "sha256": "` + benign + `"}`)
	suppressed, reason := decideSuppression(digest, map[string]int{}, doc)
	if !suppressed || reason != reasonNonCredentialLabel {
		t.Errorf("digest suppressed=%v reason=%q, want %q", suppressed, reason, reasonNonCredentialLabel)
	}
	idDoc := []byte(`{"api_key": "` + secret + `", "page_id": "` + benign + `"}`)
	suppressed, reason = decideSuppression(digest, map[string]int{}, idDoc)
	if !suppressed || reason != reasonBenignIDContext {
		t.Errorf("identifier suppressed=%v reason=%q, want %q", suppressed, reason, reasonBenignIDContext)
	}
}

// The window only starts on a real label if the byte it cut after is one the
// pattern accepts as a separator. Any other byte means it landed inside a
// longer name, and its tail must not be read as a whole label -- swept over
// every separator, digest word and offset, because each example pins only one
// cut.
func TestNoSeparatorLetsALabelTailBeReadAsAWholeLabel(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	// ; ? and & are left out: they separate cookies and query parameters, so
	// a name after one of them is its own name. That is asserted separately.
	seps := []string{"/", "|", "@", "#", "$", "%", "*", "+", "=", ":",
		"<", ">", "!", "~", "^", "\\", ".", "_", "-", "\v", "\x00", "\x7f"}
	words := []string{"sha256", "digest", "md5", "checksum", "sha-256", "_ga"}
	for _, sep := range seps {
		for _, word := range words {
			label := "team" + sep + word
			for pad := 0; pad <= 40; pad++ {
				doc := []byte("api_key=x\n" + label + "=" + strings.Repeat(" ", pad) + secret)
				res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
				sup, reason := decideSuppression(res, map[string]int{}, doc)
				if sup && reason == reasonNonCredentialLabel {
					t.Fatalf("%q with %d spaces was read as a whole benign label", label, pad)
				}
			}
		}
	}
}

// The context window is a fixed byte count, so it can begin partway through a
// longer label. Whitespace between the label and its value shifts where the
// cut falls, and at one offset "signing_digest=" presented the recognizer with
// "digest=" -- a credential dropped under a label that only ends in a digest
// word. Every offset is swept because a single example only pins one cut.
func TestALongerLabelSurvivesEveryContextWindowOffset(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const neighbour = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	labels := []string{
		"signing_digest", "my_sha256", "prev_checksum", "content_md5",
		"x-request-digest", "backup_sha256", "sha256_key", "md5_secret",
		"checksum_token", "digest_password", "uet_api_key", "app_secret",
	}
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			for pad := 0; pad <= 40; pad++ {
				doc := "api_key=" + neighbour + "\n" + label + "=" + strings.Repeat(" ", pad) + secret
				if len(found(t, doc, secret)) == 0 {
					t.Fatalf("a secret under %q was dropped with %d spaces before it", label, pad)
				}
			}
		})
	}
}

// labelForms spells one key/value pair the ways a request actually carries it.
var labelForms = []func(key, value string) string{
	func(k, v string) string { return `{"` + k + `": "` + v + `"}` },
	func(k, v string) string { return k + `=` + v },
	func(k, v string) string { return k + `: ` + v },
	func(k, v string) string { return `'` + k + `': '` + v + `'` },
	func(k, v string) string { return "cfg:\n  " + k + " = " + v },
}

// Only the complete name counts. A key that merely ends in a digest word --
// whether joined by a space inside quotes, by punctuation, or by nothing at
// all -- names something else, and its value stays reportable.
func TestOnlyACompleteNameSuppresses(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	quals := []string{"signing", "api", "token", "secret", "auth", "my", "prev", "content", "apikey", "password"}
	seps := []string{" ", "_", "-", "/", ".", ":", "|", "@", "\t"}
	words := []string{"sha256", "digest", "md5", "checksum", "_ga", "x-sha256", "sha-256"}
	for _, qual := range quals {
		for _, sep := range seps {
			for _, word := range words {
				key := qual + sep + word
				for _, form := range labelForms {
					doc := []byte(form(key, secret))
					res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
					if sup, reason := decideSuppression(res, map[string]int{}, doc); sup && reason == reasonNonCredentialLabel {
						t.Fatalf("%q was read as a whole benign name in %q", key, doc)
					}
				}
			}
		}
	}
}

// The other direction: the names themselves must still suppress, in each form.
func TestACompleteNameSuppressesInEveryForm(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	for _, word := range []string{"sha256", "digest", "md5", "checksum", "_ga", "x-sha256", "sha-256"} {
		t.Run(word, func(t *testing.T) {
			for _, form := range labelForms {
				doc := []byte(form(word, secret))
				res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
				sup, reason := decideSuppression(res, map[string]int{}, doc)
				if !sup || reason != reasonNonCredentialLabel {
					t.Errorf("%q not suppressed: suppressed=%v reason=%q", doc, sup, reason)
				}
			}
		})
	}
}

// Padding between the label and its value moves the context window's edge, and
// the answer must not move with it. Without this, a qualified name lands back
// on the benign list at whichever offset puts the window's start inside it.
func TestPaddingCannotTurnAQualifiedNameIntoABenignOne(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	keys := []string{
		"signing checksum", "signing sha256", "secret checksum", "password checksum",
		"signing\tchecksum", "api sha256", "token digest", "my_sha256", "team/digest",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			for pad := 0; pad <= 40; pad++ {
				for _, gap := range []string{" ", "\t"} {
					doc := []byte(key + "=" + strings.Repeat(gap, pad) + secret)
					res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
					if sup, reason := decideSuppression(res, map[string]int{}, doc); sup && reason == reasonNonCredentialLabel {
						t.Fatalf("%q was read as a whole benign name with %d gaps", key, pad)
					}
				}
			}
		})
	}
}

// The same padding must not stop a real name from suppressing, for as long as
// its assignment is still inside the window. Past that the label is out of
// view and the finding is raised, which is the safe way to run out of context.
func TestPaddingDoesNotStopACompleteNameSuppressing(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	for _, name := range []string{"sha256", "checksum", "md5", "_ga", "x-sha256"} {
		t.Run(name, func(t *testing.T) {
			for pad := 0; pad+1 < benignIDContextWindow; pad++ {
				doc := []byte("cfg:\n  " + name + "=" + strings.Repeat(" ", pad) + secret)
				res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
				if sup, reason := decideSuppression(res, map[string]int{}, doc); !sup || reason != reasonNonCredentialLabel {
					t.Fatalf("%q with %d spaces was not suppressed (%v %q)", name, pad, sup, reason)
				}
			}
			// once the assignment falls outside the window, the value is kept
			doc := []byte("cfg:\n  " + name + "=" + strings.Repeat(" ", benignIDContextWindow) + secret)
			res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
			if sup, _ := decideSuppression(res, map[string]int{}, doc); sup {
				t.Errorf("%q was suppressed with its assignment out of view", name)
			}
		})
	}
}

// A cookie after another cookie is still a cookie.
func TestASemicolonSeparatesCookies(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const token = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	doc := "Authorization: Bearer " + token + "\nCookie: consent=yes; _ga=" + secret
	if hits := found(t, doc, secret); len(hits) > 0 {
		t.Errorf("the analytics cookie was reported as %v", hits)
	}
	if len(found(t, doc, token)) == 0 {
		t.Errorf("the bearer token was not reported")
	}
}

// A cookie header and a query string pack several assignments onto one line,
// so a semicolon, a question mark and an ampersand each end a name whether or
// not a space follows. Without this the whole run reads as one name, and the
// analytics value it ends with is reported.
func TestCookieAndQuerySeparatorsEndAName(t *testing.T) {
	const benign = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const secret = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	suppressed := []string{
		"Authorization: Bearer " + secret + "\nCookie: consent=yes;_ga=" + benign,
		"api_key=" + secret + "\nurl=https://site/?_ga=" + benign,
		"api_key=" + secret + "\nurl=https://site/?a=1&_ga=" + benign,
		"api_key=" + secret + "\nx=1;sha256=" + benign,
	}
	for _, doc := range suppressed {
		res := analyzeResult{EntityType: customdetectors.EntropyName, raw: benign}
		if sup, reason := decideSuppression(res, map[string]int{}, []byte(doc)); !sup || reason != reasonNonCredentialLabel {
			t.Errorf("not suppressed (%v %q): %s", sup, reason, doc)
		}
	}
	// The same separators must not hand a credential's own name to the rule.
	kept := []string{
		"https://site/?api_key=" + benign,
		"a=1&secret=" + benign,
		"x=1;token=" + benign,
		"url=https://site/?signing_sha256=" + benign,
		"url=https://site/?my sha256=" + benign,
	}
	for _, doc := range kept {
		res := analyzeResult{EntityType: customdetectors.EntropyName, raw: benign}
		if sup, reason := decideSuppression(res, map[string]int{}, []byte(doc)); sup && reason == reasonNonCredentialLabel {
			t.Errorf("suppressed but must be kept: %s", doc)
		}
	}
}

// On one line the token in front of a name says what the name is. A container
// lists assignments, so the name after it stands alone; a credential word
// names what the value is, and a digest word after it belongs to that value
// rather than labelling it.
func TestACredentialWordCannotIntroduceAName(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	kept := []string{
		"auth: md5=" + secret,
		"authorization: sha256=" + secret,
		"token=sha256=" + secret,
		"password=sha256=" + secret,
		"x_auth: checksum=" + secret,
		"signing? checksum=" + secret,
		"apikey&sha256=" + secret,
		"secret;digest=" + secret,
	}
	for _, doc := range kept {
		res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
		if sup, reason := decideSuppression(res, map[string]int{}, []byte(doc)); sup && reason == reasonNonCredentialLabel {
			t.Errorf("a credential word introduced the name, so this must be kept: %s", doc)
		}
	}
	suppressed := []string{
		"cookie: _ga=" + secret,
		"Cookie: consent=yes;_ga=" + secret,
		"x=1;sha256=" + secret,
		"url=https://site/?_ga=" + secret,
		"url=https://site/?a=1&_ga=" + secret,
	}
	for _, doc := range suppressed {
		res := analyzeResult{EntityType: customdetectors.EntropyName, raw: secret}
		if sup, reason := decideSuppression(res, map[string]int{}, []byte(doc)); !sup || reason != reasonNonCredentialLabel {
			t.Errorf("a container introduced the name, so this must be suppressed (%v %q): %s", sup, reason, doc)
		}
	}
}
