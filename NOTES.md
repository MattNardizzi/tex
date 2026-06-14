# Wave 3 / L11 — the entailment half (BLOCKED → machinery green-ready, label stays BLOCKED)

**Track:** `track/w3-l11-entailment`. **Status of the half:** still **BLOCKED** in the
live capstone — *honestly* — because the two real prerequisites are absent in this
environment. What changed is that the **machinery to flip it green is now built,
wired end to end, and validated on synthetic data**; the label is no longer
hard-coded, it is **derived** from the sealed commitment.

This applies the **established** method — Mohri & Hashimoto, "Language Models with
Conformal Factuality Guarantees," ICML 2024 ([arXiv:2402.10978](https://arxiv.org/abs/2402.10978),
re-fetched 2026-06-14): correctness ≡ an entailment-set uncertainty-quantification
problem; conformal prediction is a back-off that filters claims until the retained
output is factual w.p. ≥ 1−α. It is **not** a Tex novelty. Tex's value is the
integration (the λ̂ is sealed into the ECDSA voice chain and the capstone derives a
machine-readable half from it).

## What is BLOCKED on, verified this session

1. **The real cross-encoder cannot run.** `torch 2.7.1` and `numpy 2.3.2` import, but
   `import transformers` raises:
   ```
   ImportError: tokenizers>=0.11.1,!=0.11.3,<0.14 is required ... but found tokenizers==0.21.2
   ```
   So `NeuralNLIScorer.load()` returns `False`, `.score()` returns `None`, `.entails()`
   returns `None` — fail-closed, unchanged from the seal half. (M0c's `probe_torch_nli`
   stays `available=False`; the off-and-honest pin `test_neural_scorer_is_off_and_honest`
   stays green.)
2. **No labelled FIELD NLI corpus exists.** `bench/wave2_corpus/builders.build_nli_pairs`
   produces a **synthetic** corpus by construction. A conformal λ̂ from synthetic
   calibration is a real quantile of the *synthetic* distribution — it certifies nothing
   about real spoken answers, and the certified-NLI limit
   ([arXiv:2512.15068](https://arxiv.org/abs/2512.15068)) shows the field guarantee
   collapses anyway. So **synthetic alone cannot certify honestly.**

Either gap ⇒ the live commitment is the **absence** (`lambda_hat=None`,
`calibrated=False`, `model_loaded=False`) ⇒ the derived half is **blocked**.

## What was built (the green-ready machinery)

- **`voice/voice_gate.py`**
  - `NeuralNLIScorer` now has a real implementation: `load()` constructs a transformers
    sequence-classification cross-encoder (imports alone are never "available" — the M0c
    bar); `score(premise, hypothesis)` returns P(entailment) via softmax over the model's
    own label map (`_entailment_label_index` reads `config.label2id`, never a hard-coded
    index); `entails()` thresholds `score ≥ λ̂` once a λ̂ is set, else `None`. Every path
    fail-closed: no transformers ⇒ `None`/`False`. It can only ever lower a verdict.
  - `conformal_lambda_hat(nonconformity, alpha)` — the split-conformal quantile: the
    `⌈(n+1)(1-α)⌉`-th order statistic, `1.0` when that rank exceeds `n` (maximally
    conservative). Pure order statistic, no numpy (the `crc_gate.py` exact-math discipline).
  - `calibrate(scorer, pairs, *, alpha, model_id)` — runs the scorer over labelled
    `(premise, hypothesis, entailed)` pairs. Nonconformity = the per-example back-off:
    a not-entailed pair contributes its entailment score (the threshold λ̂ must exceed to
    drop it), an entailed pair contributes `0.0`. Returns a `Calibration` recording λ̂, α,
    n, the scorer backend, and `model_loaded` (True **only** for the real neural backend).
- **`voice/entailment_cert.py`** — schema **v2** (`tex.voice/entailment_commitment.v2`).
  `lambda_hat: float|None` and `calibrated: bool` are now constructible, plus
  `scorer_backend` / `calibration_alpha` / `calibration_n`, and the `"field"` corpus kind
  is admissible. A `model_validator` enforces **coherence** so no incoherent over-claim can
  be built: `calibrated ⟺ λ̂ ⟺ backend ⟺ α ⟺ n`; a calibrated commitment must name its
  corpus; `model_loaded ⟺ scorer_backend == neural`; λ̂∈[0,1], α∈(0,1), n≥1; and **the
  load-bearing pin: `calibration_corpus_kind=="field"` is constructible only behind a
  loaded neural calibration** — a stub or synthetic "field" binding is unconstructible.
  `commitment_from_calibration()` seals a `Calibration` into a commitment;
  `entailment_half_status()` is the **single shared rule** (green ⟺ calibrated ∧
  model_loaded ∧ neural backend ∧ field corpus).
- **`capstone/{compose,manifest,verify}.py`** — the L11 entailment half is **derived**
  from the commitment via `entailment_half_status`, never hard-coded. The manifest
  validator is now a **coherence check** (blocked ⟹ absence fields; green ⟹ real
  field-calibration fields), and the offline verifier **independently re-derives** the
  half from the chain-sealed commitment bytes and cross-checks it against the manifest's
  claim — so a green claim is not forgeable above the sealed commitment.

## Exactly what flips it green (the day the prereqs land)

1. Fix the env so `import transformers` works (a `tokenizers<0.14` / matching transformers
   pin), so `NeuralNLIScorer.load()` returns `True` and `.score()` runs.
2. Collect a **labelled field NLI corpus** and seal it through
   `bench/wave2_corpus/loaders.load_corpus` (pinned field provenance ⇒ `kind="field"`).
3. `cal = calibrate(NeuralNLIScorer(), field_pairs, alpha=…, model_id=…)` →
   `commitment_from_calibration(cal, …, calibration_corpus_kind="field")`.
4. Seal that commitment in the voice chain (the existing `seal_entailment_commitment`).
   `compose` derives `entailment="green"`; the manifest validator accepts it; the offline
   verifier re-derives green from the sealed bytes. No further code change required.

## Honesty self-audit (the claims an adversary attacks first)

- *"You sealed a synthetic λ̂ — the nanozk move in a commitment."* No: the live capstone
  seals the **absence**, not a synthetic λ̂. A synthetic/stub λ̂ **is** constructible (to
  validate the pipeline) but self-labels (`model_loaded=False`, `scorer_backend=stub`,
  `corpus_kind=synthetic`) and the derived half is **blocked**. The name `lambda_hat`
  matches the thing — it is a real conformal quantile of *that* scorer over *that* corpus;
  what it is NOT (a field guarantee) is recorded structurally, not hidden.
- *"A stub can fake field green."* Unconstructible: `field ⟹ neural backend ∧ model_loaded`
  in the schema validator, and `model_loaded ⟺ neural backend`. A stub is
  `model_loaded=False`. Pinned by `test_a_field_kind_is_unconstructible_without_the_real_loaded_model`
  and the capstone `_l11_green_but_not_loaded` mutation.
- *"The vocabulary leaks a coverage claim."* The calibrated threshold label is
  vocabulary-clean ("marginal validity over the calibration distribution only"), and the
  sealed-vocabulary scan still passes. The named guarantee is **marginal**,
  exchangeability-dependent, distribution-bound — never "coverage"/"guarantee"/"1-alpha".
- **Residual (documented, not fixed):** the schema enforces *coherence*, not *truth*. A
  key-holder can `model_construct`/hand-build a coherent green commitment with fabricated
  neural+field fields and sign it — attributable and tamper-evident, not impossible (the
  same residual as every provenance system; cf. M0b). The live `flow.py` builds the
  commitment from the live scorer (`model_loaded=False`), so the **product** never emits a
  false green; an incoherent forge is caught at replay (`model_validate`).

## Evidence (this session)

- `scripts/capstone_demo.py` → **exit 0**; the honest split prints `blocked: L11.entailment`
  (derived), all 11 tamper rows caught, both sub-demos pass.
- `tests/voice/` + `tests/capstone/` → **115 passed**; `tests/pqcrypto/test_backend_probe.py`
  L11 probe green. (The one failing probe test, `probe_ml_dsa_backend`, is a **pre-existing**
  environment artifact — cryptography ≥48 ships a native ML-DSA backend on this box — and
  fails identically with these changes stashed; it is unrelated to L11.)
- New: `tests/voice/test_voice_conformal.py` (conformal math + end-to-end calibration over
  the real synthetic corpus with a deterministic, label-blind stub).
