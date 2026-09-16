package classify

import "testing"

// A filename-shaped value must NOT be excluded on shape alone when it is
// credential-assigned: a real high-entropy secret can coincidentally end in a
// known extension plus a grep separator (e.g. "<secret>.md-"). Guards the
// false-negative Greptile flagged on PR #43. The carve-out is filename-only —
// every other value-only exclusion still fires even under a credential.
func TestIsExcludedEntropyValueInContext_FilenameSuffix(t *testing.T) {
	const filenameShaped = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh.md-"
	const uuidShaped = "550e8400-e29b-41d4-a716-446655440000"

	cases := []struct {
		name       string
		value      string
		credential bool
		want       bool
	}{
		{"filename value, plain context -> excluded", filenameShaped, false, true},
		{"filename value, credential-assigned -> kept (surfaced)", filenameShaped, true, false},
		{"uuid value, credential-assigned -> still excluded (carve-out is filename-only)", uuidShaped, true, true},
		{"uuid value, plain context -> excluded", uuidShaped, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsExcludedEntropyValueInContext(c.value, c.credential); got != c.want {
				t.Fatalf("IsExcludedEntropyValueInContext(%q, credential=%v) = %v, want %v",
					c.value, c.credential, got, c.want)
			}
		})
	}
}
