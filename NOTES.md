# NOTES — W3/L1: a real ZK proof replaces the L1 stand-in

**Branch:** `track/w3-l1-zkproof` · **Maturity:** `research-early` · **Date:** 2026-06-14

## TL;DR

The L1 "zero-knowledge proof" was a **keyed-hash stand-in** (a symmetric MAC tag
from `deterministic-shim-v1`): not hiding, no soundness against a holder of the
dev key — gated `green_test_mode` behind `TEX_ZKPDP_ALLOW_SHIM=1`.

This branch ships the **first wired, runnable, non-shim L1 backend**:
`schnorr-fuse-zk-v1`. It is a **real** discrete-log zero-knowledge proof of the
PDP **decision-relation fuse kernel** — pure Python, runs offline today, no
binary, no SRS ceremony, no enclave, no blockchain. With it the arbiter reports
`stand_in=False` + `regulator_grade=True` and **L1 reaches `green` without the
shim flag** (proven in `tests/zkpdp/test_arbiter_zk_backend.py`).

It is **not faked anywhere**. Where it does not yet apply (the flagship
capstone's own decision is a *structural-floor FORBID*, which has no fuse), L1
keeps its honest `green_test_mode` label and the shim stays. See
[§4](#4-the-capstone-stays-green_test_mode--why-precisely).

## 1. The defensible kernel (what is proven, and why it is NOT the prior art)

`tex/zkprov/zk_fuse.py` proves exactly this statement:

```
PUBLIC :  policy weights wᵢ, the public fused score fused_q, scale
PRIVATE:  the per-stream risk scores sᵢ (which specialist flagged what)
CLAIM  :  fused_q == clamp(round(Σ wᵢ·sᵢ / scale))  over in-range private sᵢ
```

This is the **verdict COMPUTATION** — the fuse step of the arbitration relation
(`arbiter.canonical_fuse`) — proven over *private* inputs. It is deliberately
**not**:

- **attribute-eligibility** ("a subject's attributes satisfy a predicate") —
  the on-chain private-attribute XACML / ZKP-CapBAC line (Di Francesco Maesa et
  al., JNCA 2023; ZKP-CapBAC, May 2025 — both retrieved this session). That
  proves a *predicate over attributes*; we prove the *decision arithmetic*.
- a **generic "a computation ran correctly" SNARK** (Nchain US12273324B2) — the
  statement, the public inputs, and the binding are all PDP-decision-relation
  specific (the policy-weighted fusion → `fused_q`), not a general VM.
- a differentiator built on three-valued PERMIT/ABSTAIN/FORBID — that's standard
  XACML and is not claimed as novel.

The **two properties L1 must preserve are preserved**: the proof is
**offline-verifiable with no blockchain** (pure integer modexp + SHA-3, no live
chain) and has **no TEE / hardware-root dependency** (it does not touch the L2
enclave; verification is software-only).

## 2. What is real and runnable today (the receipts)

`tex/zkprov/schnorr_group.py` — Pedersen commitments over the **RFC 3526 MODP
Group 14** 2048-bit safe prime (fetched from rfc-editor.org this session;
primality + safe-primality **re-checked live** with `sympy.isprime` in
`tests/zkprov/test_schnorr_group.py`, never trusted from memory), Fiat–Shamir
(128-bit challenges), CDS OR-proofs, bit-decomposition range proofs. A fixed-base
comb makes 2048-bit modexp tractable in pure Python and is **pinned bit-identical
to `pow`** so the optimization cannot corrupt a result.

Earned (all run in CI, none `RUNTIME-DEPENDENT`):

| Property | Where |
|---|---|
| 2048-bit safe-prime group, subgroup generators, NUMS `h` (no trusted setup) | `test_schnorr_group.py::test_group_is_a_2048_bit_safe_prime…` |
| completeness — mid / low-clamp / high-clamp / zero-weight-skip | `test_zk_fuse.py` |
| **soundness** — every forged `fused_q` rejected; prover refuses a false statement; tampered commitment/proof rejected | `test_zk_fuse.py`, `test_schnorr_group.py` |
| **hiding** — two distinct witnesses, same public `fused_q`, both verify, commitments differ | `test_zk_fuse.py::test_distinct_witnesses_same_verdict_both_verify_and_hide` |
| arbiter green via the real backend, **no shim flag**; shim hard-gate intact | `tests/zkpdp/test_arbiter_zk_backend.py` |

Perf (this machine, pure-Python 2048-bit): ~1.7 s (4-stream) – ~6.6 s (7-stream)
to prove; ~0.3 s/verify. Proofs are ~hundreds of KB (bit-decomposition is
verbose). It is **not** a succinct SNARK — see §5.

## 3. Wiring (minimal, structure-preserving)

- `ProofBackendId.SCHNORR_FUSE_ZK_V1` added; `SchnorrFuseZkBackend` added;
  dispatcher (`get_proof_backend`) wired; added to `_REGULATOR_GRADE` (the
  non-shim *tier* — see the honest caveat in its docstring; "regulator-grade"
  names the tier, NOT a completed Article-53 certification).
- **The arbiter needed zero logic changes.** The existing
  dispatch-through-backend design already accommodates a real backend: a
  non-shim backend has `stand_in=False`, so it bypasses the
  `TEX_ZKPDP_ALLOW_SHIM` hard gate naturally and `verify_arbitration` reports
  `regulator_grade=True`. Only docstrings/notes were updated (and the now-false
  "no wired backend can produce a real ZK proof today" lines in
  `arbiter.py` / `zkpdp/__init__.py` were corrected).
- The fuse backend applies to the **fuse path only**: a `router_skipped`
  (structural short-circuit) statement has no fuse, and `prove` **refuses** it
  rather than fabricating a proof.

## 4. The capstone stays `green_test_mode` — why, precisely

The flagship `scripts/capstone_demo.py` keeps L1 at `green_test_mode` (shim),
the manifest honesty pins are untouched, and the demo still exits 0. This is a
**surfaced, characterized blocker, not a silent descope.** Two concrete reasons
a genuine capstone `green` is *more* than swapping the backend:

1. **The capstone's headline decision has no fuse.** Probed this session: the
   capstone's L1 decision is `router_skipped=True`, `deny_floor=True`,
   `claimed_verdict=FORBID`, all scores 0, `fused_q` *pinned* to SCALE (not
   computed). It is a **structural-floor FORBID** — its correctness is a
   deterministic public structural fact, not a fused computation over private
   scores. The fuse ZK proof is *inapplicable* to it (and the backend correctly
   refuses it). A capstone that wanted L1 `green` would have to compose a
   **fuse-path** decision (a threshold PERMIT/ABSTAIN/FORBID).

2. **The capstone bundle publishes the raw scores.** `zkpdp_statement.json`
   contains `stream_scores_q` in the clear, so even on a fuse-path decision the
   *hiding* property — the whole point of "over PRIVATE inputs" — would **not be
   realized**. A genuine, hiding `green` requires a **hiding deployment**: the
   published statement must omit the raw scores and carry only the commitments,
   with `evaluate_relation`'s public fuse-check (C1) replaced by the ZK proof.
   That is a statement-shape change touching the seal binding, the 10k
   differential test, and the capstone manifest — deliberately **not rushed**
   here, because the capstone's deliberate honesty pins (`_l1_promoted` and
   `_l1_not_stand_in` are *unconstructible*; the phrase "zk proof of the
   verdict" is *banned*) are the flagship's product and must only change when the
   underlying truth changes.

**Exact remaining work to promote the capstone bundle to a genuine `green`**
(scoped, not done):
  - compose a fuse-path decision for the L1 row (or add a second, fuse-path L1
    artifact);
  - introduce a hiding `ArbitrationStatement` variant that publishes
    commitments, not raw scores; route C1 through the ZK proof when scores are
    omitted;
  - rewrite the `CapstoneVerdict` L1 validator from "must be
    `green_test_mode` + `stand_in=True`" to a **consistency** rule
    (`green_test_mode ↔ stand_in=True,reg=False` **OR** `green ↔
    stand_in=False,reg=True`) — this *preserves* the existing over-claim pins
    (they stay unconstructible) and is self-guarded by
    `tests/capstone/test_honesty_pins.py`;
  - update `verify.py` L1 classification, the `honest_split` pin, and the L1
    caveat/title — without ever using the banned "zk proof of the verdict"
    (the honest caveat is "DLog proof of the fuse relation; hiding realized when
    scores are omitted").

## 5. Honest maturity & residuals (falsify-your-own-claims)

- **Hand-rolled, UNAUDITED.** Soundness rests on standard primitives (Pedersen,
  Schnorr/Fiat–Shamir, CDS OR, bit-range proofs — citations
  `UNVERIFIED-FROM-MEMORY`) AND on my implementation being correct. It is
  adversarially tested (forgeries, tampering, out-of-range all rejected) but not
  audited. Do **not** cite it as production/certified.
- **Pre-quantum.** 2048-bit discrete log (~112-bit classical) falls to Shor. A
  PQ commitment (lattice/hash) is future work; not claimed.
- **Not succinct.** Proofs are ~hundreds of KB and prove time is seconds — this
  is a Σ-protocol, not a SNARK. The succinct/audited path remains the ezkl/Halo2
  backend, which is still **RUNTIME-DEPENDENT / BLOCKED on the out-of-tree
  circuit artifact** (`Halo2IpaBackend` raises `BackendUnavailable`). That is
  the *one missing runtime artifact* for a succinct, audited L1 — this branch
  did not fake it; it built a different, real, non-succinct proof instead.
- **Fuse kernel only.** The proof covers the weighted-fusion arithmetic →
  `fused_q`. The threshold map, structural deny-floor, quarantine pin and
  monotone-lowering chain stay PUBLIC and are checked by
  `arbiter.evaluate_relation`. This is **not** a ZK proof of the whole verdict,
  and the code/labels say so.
- **Score-range over-approximation.** Per-score commitments are range-proven to
  `[0, 2^14) ⊇ [0, scale]`; the verdict-critical rounding window IS tight, so the
  looseness can never change a verdict (tightening to exactly `[0, scale]` is
  one `prove_window` call away).
- **Hiding on the arbiter's all-public statement is moot** (scores are published
  there); hiding is realized only in a deployment that omits them (§4). On the
  all-public path the deterministic relation re-eval remains the load-bearing
  verdict check; the ZK proof is the binding a hiding deployment would rely on.

## 6. Files & how to run

New: `src/tex/zkprov/schnorr_group.py`, `src/tex/zkprov/zk_fuse.py`,
`tests/zkprov/test_schnorr_group.py`, `tests/zkprov/test_zk_fuse.py`,
`tests/zkpdp/test_arbiter_zk_backend.py`, this file.
Changed: `src/tex/zkprov/backends.py` (id/class/dispatcher/tier),
`src/tex/zkpdp/arbiter.py` + `src/tex/zkpdp/__init__.py` (corrected docstrings +
an honest success note). No engine/pdp/main changes.

```bash
PYTHONPATH=src python -m pytest tests/zkprov/test_schnorr_group.py \
  tests/zkprov/test_zk_fuse.py tests/zkpdp/ -q          # the receipts
PYTHONPATH=src python scripts/capstone_demo.py          # acceptance: exit 0
# NOTES — certifying L4.certificate and L12.robustness (field-corpus path)

**Track:** `track/w3-l4l12-certify` · **Maturity:** the *path* is `research-solid`
(crypto production, wiring newly built + dry-run-proven); the *certificates* stay
`certified=False` in everything shipped, which is the correct state.

## TL;DR

The full field-corpus path is built and proven end-to-end with **simulated**
field fixtures: collection format → provenance sealing → loader gate →
`certify_*` wiring → offline re-check. **Given a sealed field corpus, the L4 and
L12 certificates read `certified=True` and an auditor re-checks them offline.**

What is *not* done is the one thing code cannot do: **a real field corpus does
not exist yet.** Certifying for real is BLOCKED on a human data-collection act,
not on engineering. Everything buildable today is `synthetic` and certifies
nothing — by design (the honesty gate). This file specifies the *exact* corpus
(size, labels, holdout) that a real collection must produce to flip the bit
honestly.

The shipped capstone (`scripts/capstone_demo.py`) therefore stays
`certified=False` for L4.certificate and L12.robustness, and `estimate_only` for
L12.qif. Those are the honesty pins (`capstone/manifest.py` `_enforce_honesty_pins`,
`engine/verdict_certificate.py` `qif_certified: Literal[False]`) — **not touched.**

## The path (what is wired, where)

| Stage | Where | Status |
|---|---|---|
| Collection format (canonical JSONL + manifest) | `bench/wave2_corpus/loaders.py::write_corpus` | built |
| Provenance sealing (named collector attests; ECDSA/composite-ML-DSA seal) | `bench/wave2_corpus/provenance.py::attest_field_provenance`, `seal_provenance` | built |
| Loader gate (`field` earned only on sealed + **pinned** + digest-bound provenance) | `bench/wave2_corpus/loaders.py::load_corpus` | built |
| L4 certify (kind flows from the gate; ≥20-holdout-miss tripwire) | `loaders.py::certify_action_class_corpus` → `contracts/action_class.py::certify_action_class` | built |
| L4 offline re-check (from files, no runtime) | `loaders.py::certify_action_class_from_artifact` | **new** |
| L12 certify (field entry point; family from sealed provenance) | `bench/wave2_corpus/field_trial.py::run_field_neighborhood_trial` → `engine/verdict_certificate.py::certify_verdict` | built |
| Certifiable-regime L4 corpus generator | `contracts/action_class.py::build_certifiable_action_class_corpus` | **new** |
| L4 dry run (certified=True) | `tests/bench/test_wave2_corpus.py::test_l4_field_corpus_certifies_through_earned_label` | **new** |
| L12 dry run (certified=True) | `tests/bench/test_wave2_corpus.py::test_field_trial_end_to_end_against_live_runtime` | pre-existing |

"New" = added by this track. The L12 robustness path already reached
`certified=True` through the earned label before this track; this track adds the
missing **L4** analog (a certifiable-regime corpus generator + the dry run that
flips L4 to `certified=True`), plus the L4 offline re-check entry point.

The seal proves **authorship + integrity** of the provenance *claim*, never the
claim's *truth*. A key-holder can still attest falsely — but the false
attestation is then a sealed, attributable, non-repudiable record signed by a
named identity. That is the strongest property any provenance system can offer;
it is not a guarantee the data is real.

---

## L4 — under-classification certificate (`ActionClassCertificate`)

**What it bounds:** the rate at which the *fixed* reversibility×blast-radius floor
**fails to FORBID** an action whose ground truth is must-FORBID (because the
declared features under-state the truth). One-sided, distribution-free
Hoeffding–Bentkus UCB on a bounded i.i.d. loss (Bates/Angelopoulos et al., RCPS,
JACM 2021) — the single-hypothesis (no-λ-selection) case, since the floor is
fixed. **Standard method, not a Tex novelty.**

**Each labelled case** = `ActionClassCase(declared_steps, ground_truth_must_forbid)`:

- `declared_steps`: the `(reversibility, blast_radius)` tuples the agent **declares**
  for each step of the action — the *only* thing the lattice reads. Collected from
  the real action envelope the agent emitted.
- `ground_truth_must_forbid`: the hidden truth — was the action *actually*
  irreversible **and** public-blast? Collected **independently** of the declaration:
  incident-outcome review, human adjudication, post-hoc audit. Deriving it from the
  declared bits is the circular sin that fabricates a ~0.0198 bound for free; the
  loader's tripwire and the corpus's latent-truth construction guard against it.

### The two gates pull in opposite directions

L4 certifies only when **both** clear, and they fight each other:

1. **Bound gate** — `hoeffding_bentkus_ucb(under_rate, n_calibration, δ) ≤ α`.
   Wants a **low** under-classification rate and **enough** calibration samples.
2. **Anti-vacuity tripwire** — `≥ 20` genuine under-classification events in the
   **holdout** (`loaders.py::MIN_HOLDOUT_MISSES`). Wants **enough absolute misses**
   that the bound is not measuring an empty set.

At a low rate, accumulating 20 absolute holdout misses needs a **large** holdout;
the calibration must also be large enough that the UCB clears α *despite* sampling
variance. **There is no small certifiable L4 corpus** — that is the honest finding.

### Minimum sizes (α = δ = 0.05, computed against the in-tree bound)

`min n_calibration` such that `hoeffding_bentkus_ucb(r, n, 0.05) ≤ 0.05` at empirical
under-rate `r`:

| under-rate `r` | min `n_calibration` | holdout `n` for ≥20 misses (`≈ 20/r`) |
|---|---|---|
| 0.000 | 78  | n/a (zero-miss holdout is refused as vacuous) |
| 0.010 | 150 | ≥ 2000 |
| 0.015 | 181 | ≥ 1334 |
| 0.020 | 240 | ≥ 1000 |
| 0.025 | 349 | ≥ 800 |
| 0.030 | 529 | ≥ 667 |

The product (n_cal + n_hold) is minimized around `r ≈ 0.02–0.025` at **≈ 1100–1250
total**, but that sits *on* the UCB boundary (no margin against variance). For a
robust certificate, collect with margin:

> **L4 field-corpus spec to certify (recommended):**
> - **under-classification rate ≤ ~0.02** (the floor must catch ≳ 90% of
>   must-FORBID actions in your traffic);
> - **n_calibration ≥ 500**, **n_holdout ≥ 2000** (total ≥ 2500);
> - **≥ 20 genuine under-classification events in the holdout** (the tripwire);
> - labels: declared steps from the real envelope + ground-truth must-FORBID from
>   independent incident/human review;
> - α = δ = 0.05.
>
> A zero-miss field corpus is **refused** (`certify_action_class_corpus` raises) —
> "the floor never missed" over too few must-FORBID cases is vacuous, not certified.

### Dry run (proves the wiring today, with simulated labels)

`build_certifiable_action_class_corpus(seed=20260618, n_calibration=500,
n_holdout=2000, p_under=0.055)` → calibration UCB **0.0269 ≤ 0.05**, **44** genuine
holdout misses → `certify_action_class_from_artifact(...).certified is True`
through the earned `field` label. Across a 60-seed scan in this regime, **59/60**
seeds certify (the one failure is honest sampling variance, not a bug); the pinned
seed sits in the representative middle (UCB ≈ 0.027, calibration under-rate 0.012 —
not a lucky-low outlier). The labels are simulated — a real collection replaces them.

---

## L12 — robustness lower confidence bound (`VerdictCertificate`, robustness half)

**What it bounds:** with confidence 1−δ, at least `p_low` of the named neighborhood
distribution maps to the target verdict (FORBID). Randomized-smoothing-style
certification of a deterministic system by input sampling + a one-sided lower
confidence bound (Cohen/Rosenfeld/Kolter, ICML 2019), reusing the in-tree
Hoeffding–Bentkus complement: `p_low = 1 − UCB(instability_rate, n, δ)`.
**Distributional, not worst-case/adversarial. Standard method, not a Tex novelty.**

**Each sample** = one real attacker paraphrase of a fixed must-FORBID request,
evaluated **once** through the live PDP; the implicit label is "did the verdict stay
FORBID?". The certificate's `family` string is derived from the corpus's **sealed
provenance** (collector/method/window/source), never the synthetic ops string.

### Minimum size (α = δ = 0.05)

`minimum_field_corpus_size(0.05, 0.05) = 78` at **zero** observed instability:
`hoeffding_bentkus_ucb(0, 78, 0.05) = 0.04994 ≤ 0.05` (and `n = 77` fails at
0.05057, so `p_low = 0.950062 ≥ 0.95`). **Any** observed verdict flip raises the
requirement quickly — size up per the instability you actually observe.
(Clopper–Pearson would need only 59 at zero failures, ~32% fewer; the certificate
deliberately uses the in-tree bound, so 78 is the number — see
`field_trial.clopper_pearson_minimum_n`, documented for sizing only.)

> **L12 field-corpus spec to certify:**
> - **n ≥ 78** real attacker paraphrases of a fixed must-FORBID request, **zero**
>   verdict flips (or size up: each flip pushes n up sharply);
> - each evaluated once through the live PDP;
> - δ ≤ α = 0.05 (the gate requires `delta ≤ alpha`).

### Dry run (already passing)

`test_field_trial_end_to_end_against_live_runtime` builds 78 paraphrases; the
structural action graph forces FORBID on every one (content-invariant), so 78/78
stable → stored `p_low = 0.950062 ≥ 0.95` → `certified=True` through the earned
`field` label.

---

## L12 — QIF leakage (`VerdictCertificate`, QIF half) — FROZEN estimate-only

`qif_certified: Literal[False]`, `qif_estimate_only: Literal[True]` — structurally
unconstructible to certify this wave (min-entropy leakage, Smith FoSSaCS 2009; a
plug-in **point estimate**, never a finite-sample guarantee). The word "bound" is
contractually banned from its vocabulary. A finite-sample QIF leakage *guarantee*
is the L12 North-Star and explicitly FUTURE. **Not touched by this track. Do not
flip it.** No size gate exists because no certified path exists; more samples only
shrink the plug-in bias.

---

## How to actually certify (the collection protocol)

1. **Collect** real labelled data meeting the spec above (the genuinely BLOCKED
   step — needs a human collector and a real labelling process).
2. **Write** the canonical artifact: `write_corpus(points, consumer=..., corpus_id=...,
   path=..., n_calibration=...)` → returns the SHA-256 the provenance binds to.
3. **Attest** as a named act: `attest_field_provenance(collector=<named human>,
   collection_method=<real process, NOT the reserved synthetic string>, window_*=...,
   source_description=..., corpus_sha256=<from step 2>, ...)`. This is unreachable
   from any builder path (tested) — fabricating a field record requires this explicit
   call **plus** the signing key, and leaves a sealed record of who attested what.
4. **Seal**: `seal_provenance(prov, signer=<Tex evidence signer>, bundle_path=...)`.
5. **Certify + re-check offline**:
   - L4: `certify_action_class_from_artifact(corpus_path, provenance_bundle=...,
     pinned_public_key_b64=<Tex pin>)` → `(loaded, cert)`; `cert.certified is True`
     iff the bound clears and the kind is `field`. Deterministic — any auditor with
     the same bytes + bundle + pin recomputes the identical bit.
   - L12: `run_field_neighborhood_trial(runtime, corpus=load_corpus(...))` →
     `result.certificate.certified`. Re-verification re-runs the **deterministic**
     PDP over the same texts (same verdicts → same `p_low`).

## Why the capstone manifest still says `certified=False`

`capstone/manifest.py::_enforce_honesty_pins` hard-requires L4.certificate =
`uncertified` and L12.robustness = `uncertified`, and `test_honesty_pins.py`
asserts a bare `certified=True` flip is **unconstructible**. That is correct and
intentional **while no real field corpus exists**. Wiring a *verified* field
certificate into the capstone manifest is a deliberate FUTURE step, gated on real
collected data; at that time the manifest pins become **conditional** ("certified
is constructible only when backed by a field certificate that itself re-verifies
offline"), never an unconditional flip. Until then the capstone is honestly
synthetic/uncertified, and the field path lives in the corpus tooling + the dry
runs above — fully exercised, never over-claimed.

## Verify

```bash
PYTHONPATH=src python -m pytest \
  tests/test_action_class.py tests/test_verdict_certificate.py \
  tests/bench/test_wave2_corpus.py tests/capstone/test_honesty_pins.py -q
PYTHONPATH=src python scripts/capstone_demo.py    # exit 0; L4/L12 stay uncertified
```
