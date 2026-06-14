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
```
