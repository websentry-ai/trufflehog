---
name: entropy-fp-hybrid-plan
description: 2026-07-02 decision — entropy-proximity FP reduction goes hybrid (structural recognizers first, keyword denylist second, distance scoring shadow-only); distance-scoring-as-gate was falsified by fp15
metadata:
  type: project
---

Decision (2026-07-02): reduce entropy-proximity FPs via (1) narrow structural recognizer extensions — prefixed-UUID (`pj-<uuidv4>`) and `toolu_bdrk_`-style provider-infix AI object IDs in `classify/recognizers.go`; (2) curated LLM token-counter parameter denylist (`max_tokens`, `prompt_tokens`, ...) in `nearbyKeywords`; (3) distance-proximity scoring emitted SHADOW-ONLY in ExtraData, never gating.

**Why:** The user's distance-scoring proposal was partially falsified by ground truth: fp15's support word `token` comes from `max_tokens` sitting IMMEDIATELY adjacent to the value — no distance weighting can demote it. Both prod FPs (fp14 `pj-`UUID, fp15 `toolu_bdrk_`) are deterministic structural misses by one-regex-clause gaps. Recall is the #1 non-negotiable ([[recall-first-fp-levers]]); structural non-secret recognition is recall-safe, score thresholds are not.

**How to apply:** In future FP work on this detector, reach for structural recognition and keyword-quality fixes before probabilistic scoring. Any scoring/threshold lever must ship shadow-mode behind the `code_playground/secrets_eval` e2e gate with a recall (TP) corpus, and must never solo-suppress a high-entropy value adjacent to a real credential keyword. Note: `strings.Contains(neighbor, stem)` matching is load-bearing for recall (`access_token`, `api_token`) — never replace it with plain word-boundary matching; only deny exact known counter identifiers.
