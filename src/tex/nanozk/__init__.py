"""
NANOZK: Layerwise Zero-Knowledge Proofs for Judge Inference
============================================================

Cryptographically proves that a Tex specialist judge produced its output
by running the claimed model. Defends against silent model substitution,
quantization, and cached-response attacks.

Reference
---------
arxiv 2603.18046 — "NANOZK: Layerwise Zero-Knowledge Proofs for Verifiable
Large Language Model Inference", Wang, March 2026.

Performance (per paper, GPT-2 scale)
------------------------------------
- Proof generation: 43 seconds
- Proof size: 6.9 KB constant
- Verification: 23 ms
- 52x speedup over EZKL

Use case for Tex
----------------
Apply to specialist JUDGES (small classifier models), not the main reasoning
LLM. "Tex's specialist judges produce ZK proofs of correct execution" —
no competitor has this.

Priority
--------
P2 spike — start exploring in days 90+. Begin with Fisher-information-guided
verification (prove only highest-impact layers).
"""

__all__ = []
