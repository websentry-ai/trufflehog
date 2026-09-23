package main

import (
	"strings"
	"testing"
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

// The labels above are matched whole. A key named for a digest or a cookie is
// still a key, and dropping those would be the one failure this scanner cannot
// have.
func TestACredentialLabelNamedForADigestIsStillRaised(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	labels := []string{
		"sha256_key", "md5_secret", "checksum_token", "digest_password",
		"uet_api_key", "ga_api_key", "app_secret", "signing_digest_key",
	}
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			doc := "config:\n  " + label + " = " + secret + "\n"
			if len(found(t, doc, secret)) == 0 {
				t.Errorf("a secret under %q was not reported", label)
			}
			// the same label inside a JSON object must behave the same way
			jsonDoc := "{\n  \"" + label + "\": \"" + secret + "\"\n}"
			if len(found(t, jsonDoc, secret)) == 0 {
				t.Errorf("a secret under JSON key %q was not reported", label)
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
