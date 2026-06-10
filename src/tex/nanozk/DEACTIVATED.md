# NanoZK — DEACTIVATED placeholder (read this first)

**Status: research-early, deactivated, kept in-tree on purpose.**

This package is **not** a working cryptographic proof system. It computes
keyed-hash (HMAC / SHA-256) **stand-ins** and wraps them in the *shape* of a
zero-knowledge / lattice proving pipeline. The type and symbol names
(`ajtai_commitment`, `running_l2_norm_bound`, `verify_layer_proof_set`, …)
describe the **intended future backend**, not what the code does today. Nothing
here is cryptographically binding.

## Why it is still here
It is a **structural scaffold** — the interfaces, the proof-set wire format, the
backend dispatcher, and the test harness a real prover would slot into. We keep
it so that the day there is a real backend (or a customer who needs one), the
wiring point already exists. The full implementation also lives in git history,
so deleting it would not have lost anything either; this is the explicit
"keep it parked, ready to wire" choice.

## How it is deactivated (the safety property)
`verify_layer_proof_set()` is **hard-gated**: it returns `is_valid=False`
(reason `nanozk_deactivated_placeholder_not_a_real_proof`) **unless**
`TEX_NANOZK_ALLOW_SHIM=1` is set. That env var is set only by the scaffold's
own tests (`tests/nanozk/conftest.py`). Consequence:

- In production, flipping `TEX_FRONTIER_NANOZK=1` **cannot** cause a stand-in to
  be trusted as a real proof — the evidence verifier
  (`tex.evidence.attribution_zk`) gets `is_valid=False` and stays fail-closed.
- `tests/nanozk/test_deactivated.py` is the regression guard for this.

## What "wiring it up for real" would mean
Not flipping a flag — replacing the computation. The honest path is to integrate
an existing, audited zkML backend rather than the bespoke pipeline here:

- **Lagrange DeepProve** — production-grade zkML, proves small-model inference
  (GPT-2 scale today). <https://lagrange.dev/blog/deepprove-zkml>
- **EZKL** — the most mature open-source zkML toolkit (still beta).
- The paper this scaffold is *named after* is real:
  **NANOZK: Layerwise Zero-Knowledge Proofs for Verifiable LLM Inference**,
  arXiv:2603.18046. The scaffold cites it; it does **not** implement it.

## Market note (as of 2026-06)
zero-knowledge ML is real but concentrated in crypto/on-chain contexts and small
models; frontier-LLM proofs at interactive latency are not a shipping product.
The EU AI Act Art. 53 training-data obligation is a *disclosure* requirement, not
a ZK one. AI-agent-governance buyers (Zenity, Noma, …) procure identity / runtime
defense / lineage, not ZK proofs. So there is **no current client need** — wire a
real backend only when a named customer requires verifiable-inference-under-secrecy.
