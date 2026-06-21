# L3 habits — design notes (decisions, attacked approaches, honest edges)

Branch `presence/l3-habits` (base `presence/l2-profile` → `presence/s5-memory`).
Status: BUILT, 45 habit tests + 148 presence-suite tests green, 0 regressions.
**Not merged.** The orchestrator reconciles at final merge (order S5 → L1 → L2 → L3).

## The one job, restated
Let Tex *notice* recurring patterns in a tenant's **own sealed history** and *offer*
them as hypotheses ("I've noticed you forbid every offshore wire — make it a rule?")
that a human confirms before anything changes. A pattern is a HYPOTHESIS carrying
its supporting sealed records; it changes nothing until a human seals it, which then
flows to the L2 profile (+ L1 calibration via L2's route).

This is the most hallucination-prone session: a "noticed pattern" is exactly where a
model starts asserting things it cannot prove. So the whole design is built so the
**pattern can only come from a deterministic count over sealed records**, never from a
generator, and so a thin/noisy history surfaces **nothing**.

---

## Approach 1 (CHOSEN) — deterministic categorical miner + Bonferroni-Wilson gate
Group a tenant's sealed observations by the **exact normalised `subject_key`** L2 keys
corrections on. For each subject, find the dominant outcome and surface it *only* when
it clears three floors: support (`n ≥ 5`), observed rate (`≥ 0.8`), and a
**Bonferroni-corrected one-sided Wilson lower bound** (`≥ 0.55`). A confirmed habit is
ONE `ProfileMemory.apply_correction` — faithfully representable in L2 because the
subject and the action (a tier ceiling) are exactly what L2 stores.

**Why it wins:** every step is a count compared to a computed statistic, reproducible
to the bit; the action maps 1:1 onto L2 with no new influence path; and the
multiplicity correction is a real defence against the multiple-comparisons trap (see
"the attack" below).

**Attacked:**
- *Multiple comparisons.* Scanning many subjects and surfacing any that crosses a
  fixed bar is p-hacking: among 20 subjects with 5 coin-flip outcomes each, ~1 is
  "5/5" by luck. **Defence:** Bonferroni — `alpha_eff = alpha_family / m`, where `m`
  is the number of subjects eligible by support. This drops a lone 5/5's Wilson lower
  bound from 0.75 (m=1) to 0.43 (m=20), below the floor → suppressed. Verified in
  `test_redteam.py::test_spurious_clean_subject_among_noise_is_suppressed_by_multiplicity`.
- *Idempotent re-seal inflation.* S5 records are content-addressed, so re-sealing the
  identical fact yields the same `record_id`. An adversary (or a bug) re-submitting one
  record many times must not manufacture support. **Defence:** dedupe by
  `(dimension, subject, record_id)` before counting
  (`test_redteam.py::test_reseal_flood_cannot_manufacture_a_pattern`).
- *Inflation.* A "you always permit X" pattern is real but turning it into a rule would
  RAISE confidence. **Defence:** the outcome→action map covers only cautionary outcomes
  (forbid/abstain → tighten); a non-cautionary dominance surfaces nothing
  (`test_miner.py::test_non_cautionary_dominance_is_never_offered_as_a_rule`). And the
  action type itself refuses a `SEALED` proposal, and L2's write-gate refuses it again
  (defence in depth, two tests).

## Approach 2 (REJECTED) — value-threshold mining ("forbid wires over $X")
Mine a numeric split point `t` such that outcomes are cautious above `t` and not below,
with min support on each side and a separating margin — the literal flagship example.

**Why rejected (honesty, not effort):** L2's tier ceiling is **unconditional per
subject** (`profile/types.py::tier_ceiling` has no value-conditioning). A confirmed
"forbid over $X" rule could therefore **not be enforced** through the profile — Tex
would *say* it learned a threshold rule it cannot actually apply. That is precisely the
nanozk failure mode (a name/promise the body does not deliver), and the worst possible
place to commit it (a user-facing "I've noticed" the operator trusts). So V1 does **not**
offer value-conditional rules. If the gate mints `claim_id`s that encode value buckets
(e.g. `govern:wire:offshore:over-10k`), a threshold-like rule emerges *for free* as a
categorical pattern over that subject — but L3 does not invent the bucketing (out of
lane). A real value-conditional habit would need a new conditional-rule substrate +
its own monotone influence fold; that is a documented follow-up, not V1.

## Approach 3 (REJECTED for the multiplicity correction) — Benjamini–Hochberg FDR
BH (control the false *discovery* rate) is more powerful than Bonferroni (control the
family-wise error rate) and is the data-mining default for "many discoveries."

**Why rejected:** FDR *tolerates* a fraction of false discoveries among those surfaced.
For a trust-critical "I've noticed…" surface, even one false pattern erodes the core
promise (Tex only says what it can support), so FWER control aligns better here:
control the probability of *any* false suggestion. BH also needs a contestable null
rate `p0` (what is "chance" across 3 governance verdicts?), and small-`n` discrete
binomial p-values are lumpy. The cost is recall: with many simultaneous small-`n`
patterns, Bonferroni stays quiet (favouring precision). We treat "when in doubt, stay
quiet" as a feature and disclose it. The bar **scales with evidence** — 10/10 clears
even at `m=20` (`test_miner.py::test_strong_pattern_clears_even_in_a_large_family...`),
so the conservativeness asks for more support, not a looser standard.

---

## Honest edges (baked in; never overclaimed)
- **A hypothesis is not a fact.** It carries its supporting sealed records and a
  computed confidence; it asserts nothing and changes nothing until a human confirms.
- **Confidence is a heuristic screen, not coverage.** The Wilson bound assumes
  exchangeable Bernoulli trials; a tenant's sealed records are a *selection-biased*
  population (their own prior decisions; cf. arXiv:2403.03868, the same caveat S5's
  calibration feed carries). The number governs *whether to ask a human*, never what
  Tex asserts. Stamped `CONSISTENCY_LABEL` on every `PatternConfidence`.
- **Sequential / optional-stopping limitation.** Re-mining across sessions is
  sequential; the per-call Bonferroni-Wilson bound is a *fixed-sample* statistic, not
  anytime-valid. An e-value / betting bound (the codebase's e-value lineage) is the
  documented upgrade path.
- **Recall window.** The S5 source sees a tenant's ≤20 most-recent sealed records
  (`SealedPresenceMemory._RECALL_CAP`). Strong recent habits are detectable; it is not a
  full-history scan. Lifting it needs a `list_records(tenant)` on S5 (out of lane) or an
  orchestrator-injected `IterableHistorySource` over the full store.
- **Per-tenant only.** Every source and the miner take the tenant explicitly; no
  cross-customer learning. Isolation is application-layer (same posture as S5/L2).
- **L1 calibration is L2's route's job.** L3 lacks the `Decision.final_score`, so it does
  NOT feed L1 itself — it passes `decision_id` into the L2 correction and lets L2's
  server-side route feed L1 (faking the feed with a value it cannot read would be
  overclaim).
- **The generator is never the fact-source.** The default phrasing is a pure function of
  mined fields; an LLM phraser (seam only in V1) receives only those fields and the
  structured hypothesis (numbers + receipts) stays the source of truth — a lying phraser
  changes only cosmetic prose (`test_redteam.py::test_adversarial_phraser...`).

## File ownership
Own: `src/tex/presence/habits/**`, `tests/presence/habits/**`, and the thin tex-systems
surface (`PRESENCE_HABITS_UI.md` + its own JS/JSX files). Consume L2's `ProfileMemory`
(duck-typed; `src` imports only the frozen contract). Do NOT edit `main.py` /
`voice_ask.py` / `pdp.py` / L2's package — the orchestrator wires `build_habit_surface`.
