package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEvalCorpus is the analyzer's precision/recall gate. It drives scan() in
// enforce mode over a labelled corpus and fails if recall regresses below the
// pinned baseline or false positives rise above it. Positives are generated at
// runtime (format-valid, never committed) so no secret literals live in the repo;
// negatives are the committed FP-prone fixtures under eval/corpus/negatives.
//
// Run: make eval   (or: go test ./cmd/analyzer/ -run TestEvalCorpus -v)
func TestEvalCorpus(t *testing.T) {
	const (
		baselineRecall           = 1.0 // every detectable positive must be found
		baselineNegativeFindings = 0  // pinned ceiling of FP findings over the negative corpus
	)

	s := heuristicScanner(t, suppressionEnforce)
	ctx := context.Background()

	// ---- positives: realistic scenarios with synthetic but format-valid secrets ----
	rng := rand.New(rand.NewSource(20260622))
	alnum := func(n int) string {
		const pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, n)
		for i := range b {
			b[i] = pool[rng.Intn(len(pool))]
		}
		return string(b)
	}
	type pos struct{ name, text, secret string }
	ghp := "ghp_" + alnum(36)
	akid := "AKIA" + strings.ToUpper(alnum(16))
	asec := alnum(40)
	stripe := "sk_live_" + alnum(24)
	openai := "sk-proj-" + alnum(48)
	generic := alnum(40)
	dbpw := alnum(20)
	dbURI := "postgres://app:" + dbpw + "@db.prod.internal:5432/billing"
	positives := []pos{
		{"github_pat_ci", "env:\n  GITHUB_TOKEN: " + ghp + "\nrun: ./deploy.sh", ghp},
		{"aws_keys_tfvars", "access_key = \"" + akid + "\"\nsecret_key = \"" + asec + "\"", akid},
		{"stripe_live", "stripe.api_key = \"" + stripe + "\"", stripe},
		{"openai_env", "OPENAI_API_KEY=" + openai + "\nMODEL=gpt-4o", openai},
		{"generic_apikey", "billing_api_key = \"" + generic + "\"", generic},
		{"postgres_uri", "DATABASE_URL=" + dbURI, dbURI},
	}

	overlaps := func(a0, a1, b0, b1 int) bool { return a0 < b1 && b0 < a1 }

	var tp, fn int
	var missed []string
	for _, p := range positives {
		res := s.scan(ctx, []byte(p.text), 0.75)
		gi := strings.Index(p.text, p.secret)
		g0, g1 := gi, gi+len(p.secret)
		hit := false
		for _, f := range res {
			if overlaps(f.Start, f.End, g0, g1) {
				hit = true
				break
			}
		}
		if hit {
			tp++
		} else {
			fn++
			missed = append(missed, p.name)
		}
	}

	// ---- negatives: committed FP-prone fixtures (no real secrets) ----
	negFiles, err := filepath.Glob("eval/corpus/negatives/*.txt")
	if err != nil || len(negFiles) == 0 {
		t.Fatalf("no negative corpus found (glob err=%v, n=%d)", err, len(negFiles))
	}
	sort.Strings(negFiles)
	var falseFindings, tn, fp int
	for _, fpath := range negFiles {
		data, err := os.ReadFile(fpath)
		if err != nil {
			t.Fatalf("read %s: %v", fpath, err)
		}
		res := s.scan(ctx, data, 0.75)
		falseFindings += len(res)
		if len(res) == 0 {
			tn++
		} else {
			fp++
			ents := map[string]int{}
			for _, f := range res {
				ents[f.EntityType]++
			}
			t.Logf("negative %-28s -> %d findings %v", filepath.Base(fpath), len(res), ents)
		}
	}

	recall := float64(tp) / float64(tp+fn)
	specificity := float64(tn) / float64(tn+fp)
	t.Logf("positives: %d/%d detected (recall=%.1f%%)  missed=%v", tp, tp+fn, recall*100, missed)
	t.Logf("negatives: %d files, %d clean, %d flagged, %d total false findings (specificity=%.1f%%)",
		len(negFiles), tn, fp, falseFindings, specificity*100)

	if recall < baselineRecall {
		t.Fatalf("RECALL REGRESSION: %.3f < baseline %.3f (missed: %s)", recall, baselineRecall, strings.Join(missed, ", "))
	}
	if falseFindings > baselineNegativeFindings {
		t.Fatalf("FP REGRESSION: %d false findings over negatives > baseline %d", falseFindings, baselineNegativeFindings)
	}
	fmt.Printf("eval OK: recall=%.1f%% specificity=%.1f%% false_findings=%d\n", recall*100, specificity*100, falseFindings)
}
