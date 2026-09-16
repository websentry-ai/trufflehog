package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func hasRaw(results []analyzeResult, raw string) bool {
	for _, r := range results {
		if r.raw == raw {
			return true
		}
	}
	return false
}

// Recall guard for the filename-suffix suppression (Greptile P1 on PR #43):
// a real secret assigned to a credential key must still be reported even when
// its text ends in a known extension plus a grep separator. Before the fix the
// value-only filename shape dropped it before proximity analysis (false
// negative).
func TestCredentialAssignedFilenameSuffixStillFlagged(t *testing.T) {
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh.md-"
	results := scanEnforce(t, "api_key="+secret+"\n")
	require.True(t, hasRaw(results, secret),
		"a credential-assigned secret ending in .md- must be reported, not dropped as a filename; got %d results", len(results))
}

// Narrowness guard: the carve-out is scoped to credential ASSIGNMENT, not mere
// credential proximity. A filename-shaped high-entropy value that only sits near
// a credential word (grep/prose context, not assigned to a credential key) must
// stay suppressed — otherwise the fix would reopen the grep-output false
// positive it was meant to keep closed.
func TestFilenameSuffixNearKeywordButNotAssignedStaysSuppressed(t *testing.T) {
	const val = "report_aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh.md-"
	results := scanEnforce(t, "commit token log: "+val+"\n")
	require.False(t, hasRaw(results, val),
		"filename-shaped value with credential proximity but no assignment must stay suppressed")
}
