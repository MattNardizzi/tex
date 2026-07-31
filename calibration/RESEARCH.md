# L1 Calibration Flywheel — frontier survey (June 2026)

> Written BEFORE coding, per the session brief. Every citation below was
> retrieved and read **this session** (web fetch of the arXiv abstract page).
> Anything I could not retrieve is labelled `UNVERIFIED-FROM-MEMORY` or dropped.
> The job this informs: wire sealed human resolutions → a per-tenant conformal
> calibration set, and flip Session-2's DERIVED floor from `transductive`
> (approximate) to `calibrated` once enough labels accrue — **without overclaiming
> the coverage we actually earn.**

## 1. The papers (retrieved + verified this session)

| arXiv | Title / authors | Date | What it gives us |
|---|---|---|---|
| [2604.27914](https://arxiv.org/abs/2604.27914) | *Geometry-Calibrated Conformal Abstention for Language Models* | 2026-04-30 | Conformal Abstention (CA): finite-sample guarantees on **both** the probability of *participation* (not abstaining) and the probability the answer is *correct*. Confirms the design pattern Tex already runs — abstain is the safe floor, and the abstain boundary itself can carry a conformal guarantee. |
| [2604.13991](https://arxiv.org/abs/2604.13991) | *Adaptive Conformal Prediction for Improving Factuality of Generations by LLMs* — Rubashevskii, Piatrashyn, Nakov, Panov | 2026-04-15 | **Adaptive** (input-/prompt-dependent) calibration: keeps **marginal** coverage while improving **conditional** coverage. The abstract states **no minimum calibration size** — silent on `min_n`. Supports per-tenant (input-stratified) calibration as a principled refinement, not a hack. |
| [2403.03868](https://arxiv.org/abs/2403.03868) | *Confidence on the Focal: Conformal Prediction with Selection-Conditional Coverage* — Ying Jin, Zhimei Ren | 2024 | **The load-bearing caveat.** Marginally-valid CP intervals **can fail** to cover when the test unit was *selected* by a data-driven rule (top-K, optimization, conformal-p-value). Proposes prediction sets with finite-sample coverage **conditional on selection**; generalizes Mondrian CP to multiple test units + arbitrary permutation-invariant selection rules. |

Additional adaptive/drift work surfaced while searching (read at abstract level
only; used for the drift discussion in §4, not relied on for a guarantee):
[DASC, 2606.15953](https://arxiv.org/abs/2606.15953) (drift-aware spectral CP for
non-exchangeable streams); [Online Shift Detection, 2606.11949](https://arxiv.org/abs/2606.11949)
(KS-window shift alarm → conformal abstention reweight); Gibbs & Candès **ACI**
(Adaptive Conformal Inference) for non-stationary streams, referenced via
[2601.00908](https://arxiv.org/abs/2601.00908).

## 2. The calibrated-floor formula (confirmed against the live code)

Split-conformal threshold, as implemented in
`tex/causal/conformal_attribution.py::_compute_threshold_calibrated`:

    q̂ = the ⌈(n+1)(1−α)⌉-th smallest calibration score   (1-indexed)

with target coverage `1 − α` (Tex default α = 0.1 → 0.90). Under exchangeability
of the calibration scores with the test score, the standard split-CP result holds:

    P[ y* ∈ C(x; q̂) ] ≥ 1 − α

The *realized* coverage is Beta-distributed (Vovk; Lei et al. 2018; Angelopoulos &
Bates 2023): `Coverage ~ Beta(n+1−l, l)` with `l = ⌊(n+1)α⌋`, mean ≥ 1−α and
spread shrinking like ~1/n. Tex's threshold matches the formula in the paper
([2605.06788](https://arxiv.org/abs/2605.06788), Feng et al.) — confirmed by reading the code, not assumed.

## 3. `min_n` for a *non-vacuous* floor

The rank `⌈(n+1)(1−α)⌉` must be ≤ n or the threshold saturates at the max score
(an effectively vacuous / always-includes bound):

    ⌈(n+1)(1−α)⌉ ≤ n   ⟺   n ≥ 1/α − 1

For α = 0.1 that is **n ≥ 9**. So 9 is the hard floor for "the quantile is even
defined." Tex's `MIN_CALIBRATION_N = 30` (in `presence/memory/calibration.py`) sits
comfortably above it: the rank is well-defined (28th of 31) and the realized-coverage
Beta spread is bounded (σ ≈ 0.05 at n=30). **30 is a practical minimum, not a
luxury** — below it a handful of selection-biased points must not pose as a formal
guarantee, so the writer withholds the scores file and the gate stays transductive.
(Many CP practitioners prefer n in the hundreds; 30 is the defensible *floor* given
we are NOT claiming marginal coverage anyway — see §4.)

## 4. Exchangeability — what we assume, and how it degrades (the honesty that is the moat)

The calibration labels are **a tenant's confirmed-true decisive errors** — the
`final_score` of `refused` human-resolved HELD decisions. This sample is **selected**:
it is the ambiguous tail the gate escalated, then a human confirmed. Consequences,
stated precisely so no code overclaims:

1. **NOT marginal coverage over all queries.** Held/refused decisions are not an
   i.i.d. draw from the tenant's full traffic. By Jin & Ren ([2403.03868](https://arxiv.org/abs/2403.03868)),
   feeding selected data into *standard* split-CP and reporting *marginal* coverage
   is exactly the failure mode. We must not call this "marginal coverage."

2. **What we DO claim:** approximate coverage **over the same escalated/held
   sub-population**, under a *within-stratum* exchangeability assumption (successive
   held→refused decisions for one tenant are exchangeable among themselves — a
   Mondrian / stratified-CP intuition). This is weaker than marginal and weaker
   than Jin–Ren's *formal* selection-conditional sets.

3. **We do NOT implement Jin–Ren's construction.** We run plain split-CP on the
   stratum and **disclose** the gap rather than borrow their guarantee. S5's stored
   label `"selection-conditional, per-tenant"` should be read as *"conditional on
   the selected stratum, approximately"* — continuity with S5, but the code claims
   no formal selection-conditional coverage. (If we ever want the real guarantee,
   2403.03868 is the construction to implement; out of this session's lane.)

4. **Degrades under drift.** Within-stratum exchangeability breaks when the tenant's
   agent behaviour shifts (new tools, new policies, attack-pattern change). ACI
   (Gibbs & Candès), DASC ([2606.15953](https://arxiv.org/abs/2606.15953)), and online
   shift detection ([2606.11949](https://arxiv.org/abs/2606.11949)) are the principled
   responses (online α-adjustment / drift-weighted calibration). Tex does **none** of
   these yet: the floor is a static split-CP quantile that silently assumes no drift.
   This is a named, owned limitation — V1 ships the honest static floor + the
   disclosure, not an adaptive one.

## 5. Design consequences for this session

- **min_n floor stays writer-side (S5).** Below 30 labels → no scores file → loader
  returns None → gate stays `transductive` and SAYS approximate. The consumer
  (`conformal_attribution`) enforces no n-check; the floor holds only because this
  feed is the sole producer of a tenant's path (pinned by S5's
  `test_min_n_floor_is_writer_side_only`).
- **Mode-selection moves INTO the gate** (`presence/gate/`), not the orchestrator.
  S5's plan asked main.py to wrap each gate call in `tenant_calibration_env`; if the
  orchestrator forgot, the gate would silently never calibrate. L1 makes the gate
  itself point at the tenant's file, so the flywheel can't be defeated by a missing
  wrap. The legacy `tenant=None` + global-env path is preserved unchanged.
- **Calibration is a CAUTION-ONLY signal** (Tex doctrine: signals may only lower a
  verdict toward ABSTAIN). The gate computes a transductive baseline AND the
  tenant-calibrated result, then combines monotonically: more labels may *tighten*
  (DERIVED→ABSTAIN) or *upgrade honesty* (transductive→calibrated at the same 1−α
  floor), but may **never** make the gate speak where the baseline was silent and
  may never raise the tier. This is structural (it survives a future swap of the CP
  algorithm), not an incidental property of two-way filtration.
- **"The floor refines" = the coverage MODE upgrades** (approximate → formal), and
  the threshold becomes tenant-calibrated. The floor *number* stays 1−α (0.9) — we
  do not inflate it. The verdict exposes the active `coverage_mode` AND the label
  count `calibration_n` for audit.
- **The flywheel is inert without real usage.** No resolutions → no labels → nothing
  to calibrate. V1's honest claim is "the gate *provably tightens as holds are
  resolved*," NOT "the gate has learned X."
