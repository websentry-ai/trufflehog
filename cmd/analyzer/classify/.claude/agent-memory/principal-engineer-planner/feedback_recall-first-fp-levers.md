---
name: recall-first-fp-levers
description: Recall is the cardinal metric for the secret analyzer — FP-reduction levers must be provably recall-safe or shadow-mode gated
metadata:
  type: feedback
---

A false negative (missed real secret) is the cardinal sin for the entropy/secret analyzer; false positives are annoying but survivable.

**Why:** User stated this as the #1 non-negotiable when evaluating FP-reduction proposals (2026-07-02, entropy-proximity planning). The product's value is catching leaked secrets in AI-agent traffic.

**How to apply:** When planning any suppression/scoring/threshold change: (a) prefer deterministic structural recognition of NON-secrets (UUIDs, vendor object IDs) over probabilistic demotion of candidates; (b) anything probabilistic ships shadow-mode first with an explicit e2e eval gate proving 0 recall loss; (c) every plan needs recall-guard tests (e.g., real secret at keyword-window edge must still fire). See [[entropy-fp-hybrid-plan]].
