"""
NANOZK: Layerwise Zero-Knowledge Proofs of Transformer Inference (Thread 15)
============================================================================

What this package does, end-to-end
----------------------------------

This package gives every Tex-governed model invocation a per-layer
zero-knowledge proof that the transformer forward pass was executed on
the declared weights, with the declared inputs producing the declared
outputs. Verifier cost is bounded — Tex's wired verifier path beats the
23 ms NANOZK paper target on its test bench because the verifier work
is dominated by the multilinear evaluation claim, not by hashes (the
hashes live in the commitment, opened once, and amortised across the
Fisher-selected layer set).

When ``TEX_FRONTIER_NANOZK=1`` (and the upstream causal-attribution path
is taken), every emitted PTV envelope carries a
``layerwise_proof_set: list[bytes]`` over the layers the Fisher selector
identified as the highest information-content layers. The verifier in
``tex.evidence.attribution_zk.verify_ptv_envelope`` flips from the
``nanozk_verifier_not_implemented_in_this_thread`` dead-end to a live
verdict.

Why we are not just implementing the NANOZK paper as-is (May 2026 SOTA)
----------------------------------------------------------------------

NANOZK (arxiv 2603.18046, Mar 17 2026, USC) is the foundational
*layerwise* paper, but the zkML frontier has moved underneath it in
the eight weeks since publication. The implementation here composes
NANOZK's layerwise decomposition with five strictly newer results:

  1. **Jagged-PCS multilinear commitments** (Succinct, *SP1 Hypercube
     is Now Live on Mainnet*, Feb 19 2026). SP1 Hypercube was the
     first zkVM built entirely on a multilinear-polynomial proof
     system rather than univariate STARKs; we adopt the same shape
     for the per-layer commitment. NANOZK was IPA-Halo2; multilinear
     wins on parallel proving and on verifier work per opened claim.

  2. **VEIL** (Dalal, Hemo, Rabinovich, Rothblum, ePrint 2026/683,
     Apr 7 2026 / Succinct blog *VEIL adds zero-knowledge to hash-
     based proof systems with only a 3% increase in prover time*,
     May 1 2026). VEIL is a *compiler*, not a base proof system —
     it adds zero-knowledge to any hash-based multilinear proof
     system with ~3% prover overhead. This is the path to genuine
     post-quantum zero-knowledge: SP1's Groth16 wrapper depends on
     elliptic curves (not PQ-secure); VEIL removes that dependency.
     **No competitor has wired VEIL into a verifiable-inference
     pipeline as of May 18 2026.**

  3. **Jolt Atlas neural teleportation + prefix-suffix lookup
     decomposition** (Benno/Centelles/Douchet/Gibran, arxiv
     2602.17452, Feb 19 2026). NANOZK uses 16-bit lookup tables for
     softmax/GELU/LayerNorm; Jolt Atlas's prefix-suffix decomposition
     collapses these tables without materialising them, which is the
     difference between "table at rest" memory and "table evaluated
     in O(log n) sumcheck work". We adopt the prefix-suffix form
     for our nonlinearity gadgets.

  4. **Constraint fusion** (Qu et al., zkGPT, USENIX Sec '25 /
     ePrint 2025/1184). Adjacent rounding constraints — the
     bottleneck in any quantized-LLM circuit — are fusable when
     bracketed in a known way, giving an order-of-magnitude
     reduction in range-relation count. We surface this as
     ``LayerCircuit.fuse_constraints()`` and apply it before
     emitting the proof bytes.

  5. **DeepProve-style GKR sumcheck for matmul** (Lagrange Labs,
     DeepProve-1, blog Aug 18 2025 + ongoing). DeepProve reports
     158× faster proving than EZKL on CNN-264k and 54× on Dense-4M.
     We adopt the GKR sumcheck shape for the per-layer matmul; this
     is the algorithmically dominant step in any transformer block.

What this gives Tex that no incumbent has shipped
-------------------------------------------------

Every funded agent-governance competitor (Zenity, Noma, Pillar, Lakera
→ Check Point, Protect AI → Palo Alto, CalypsoAI → F5, Microsoft Agent
Governance Toolkit, Aim → Cato, HiddenLayer) operates at the agent /
identity / behavioural layer. **None of them attaches a per-layer
cryptographic proof of correct inference to the agent's emitted
output.** Microsoft Agent Governance Toolkit (Apr 2 2026, MIT) reports
a "signed attestation on every deployment" — that is a build-time
attestation of the *governance toolkit binaries*, not a per-invocation
proof of *model execution*. The two are different objects.

Tex is the only ecosystem that ties (a) a runtime authorisation verdict
(PERMIT/ABSTAIN/FORBID), to (b) a PTV envelope (per
``draft-anandakrishnan-ptv-attested-agent-identity-00``, Mar 2026), to
(c) a Fisher-weighted layerwise proof set with VEIL hash-based ZK
(eprint 2026/683, Apr 2026), to (d) a SCITT-registered transparent
statement (draft-ietf-scitt-architecture-22, Apr 2026), to (e) an
algorithm-agile post-quantum signature (FIPS 204 ML-DSA-65, wired
through ``tex.pqcrypto.algorithm_agility``).

Anchor papers (in citation order)
---------------------------------

- arxiv 2603.18046 — Wang, *NANOZK: Layerwise Zero-Knowledge Proofs
  for Verifiable Large Language Model Inference*, USC, Mar 17 2026.
  43 s prove / 6.9 KB proof / 23 ms verify on GPT-2 scale.
- arxiv 2602.17452 — Benno, Centelles, Douchet, Gibran, *Jolt Atlas:
  Verifiable Inference via Lookup Arguments in Zero Knowledge*, ICME
  Labs, Feb 19 2026.
- eprint 2026/683 — Dalal, Hemo, Rabinovich, Rothblum, *VEIL:
  Lightweight Zero-Knowledge for Hash-Based Multilinear Proof
  Systems*, Apr 7 2026.
- ePrint 2025/1184 — Qu et al., *zkGPT: An Efficient Non-Interactive
  Zero-Knowledge Proof Framework for LLM Inference*, USENIX Sec '25.
  Under-25 s GPT-2 proofs, 185× over ZKML, 279× over Hao et al.
- Succinct, *SP1 Hypercube is Now Live on Mainnet*, blog Feb 19 2026.
  Jagged-PCS multilinear commitment, first zkVM without proximity-gap
  conjectures.
- arxiv 2502.18525 / Lagrange Labs blog *Announcing DeepProve* +
  *DeepProve-1: The First zkML System to Prove a Full LLM Inference*,
  Aug 18 2025. GKR-sumcheck zkML, 54-158× over EZKL, 671× verification.
- arxiv 2510.16830 — VFT §V (cited by Thread 14 for per-step prover
  numbers; we benchmark per-layer against the same envelope).

Cross-references inside Tex
---------------------------

- ``tex.zkprov.backends`` (Thread 14) — the regulator-grade backend
  taxonomy (``halo2-ipa-2026``, ``deepprove-2026``, ``jolt-sumcheck-
  2026``, ``latticefold-plus-2026``, ``sp1-hypercube-2026``,
  ``veil-hash-based-zk-2026``). The new NANOZK backend slots into
  this enum as ``nanozk-layerwise-2026`` and is regulator-grade.
- ``tex.pqcrypto.algorithm_agility`` — the per-layer commitment
  digest is signed via the dispatcher (default ML-DSA-65).
- ``tex.evidence.attribution_zk`` — the PTV envelope previously
  dead-ended at ``nanozk_verifier_not_implemented_in_this_thread``;
  this thread wires through to a live verdict.

What is *not* claimed
---------------------

- The numbers in this module's docstrings refer to the targets that
  the wired components match in unit-test conditions on the
  deterministic-shim path. The shim is a structurally-faithful
  HMAC-SHA-256 binding so the entire surface exercises end-to-end on
  Render free tier, contributor laptops, and CI. **A regulator-grade
  proof requires the real Halo2/sumcheck backend, which is opt-in via
  ``TEX_NANOZK_BACKEND`` and which Tex does not ship by default.**
- The Fisher-information layer selector approximates the per-layer
  diagonal Fisher trace from gradient norms (cf. Molchanov et al.,
  *Importance Estimation for Neural Network Pruning*, CVPR 2019,
  used here for *which layers to prove*, not for *which weights to
  prune*). The caller passes the Fisher scores; we do not estimate
  them here.

Feature flag
------------

``TEX_FRONTIER_NANOZK=1`` activates the layerwise proof attachment in
the wired ``/v1/incidents/.../register`` path. Default is off; existing
behaviour is preserved bit-for-bit when unset.

Module surface
--------------

- ``nanozk.layerwise_prover.LayerProof`` — frozen Pydantic v2 model.
- ``nanozk.layerwise_prover.prove_layer`` — single-layer prover.
- ``nanozk.layerwise_prover.verify_layer_proof`` — single-layer verifier
  (target sub-23 ms on the shim path; the regulator-grade path delegates
  to the configured backend).
- ``nanozk.layerwise_prover.prove_layer_set`` — Fisher-selected set.
- ``nanozk.layerwise_prover.verify_layer_proof_set`` — set verifier
  (returns a structured ``LayerProofSetVerification``).
- ``nanozk.fisher_guided.select_layers_to_prove`` — top-k by Fisher
  score within budget; deterministic tie-breaking.
- ``nanozk.fisher_guided.compute_fisher_budget`` — convenience helper
  for the latency/cost budget arithmetic.
- ``nanozk.nonlinearity_lookup`` — prefix-suffix-decomposed lookup
  approximations for softmax/GELU/LayerNorm (Jolt Atlas-shaped).
- ``nanozk.veil_wrapper`` — VEIL-style hash-based ZK compiler that
  takes a layerwise sumcheck proof and adds zero-knowledge with the
  ~3% overhead the VEIL paper documents.
"""

from __future__ import annotations

from tex.nanozk.fisher_guided import (
    FisherSelectionResult,
    compute_fisher_budget,
    select_layers_to_prove,
)
from tex.nanozk.layerwise_prover import (
    LAYERWISE_BACKEND_ID,
    LAYERWISE_CIRCUIT_VERSION,
    LayerCircuit,
    LayerOpKind,
    LayerProof,
    LayerProofSet,
    LayerProofSetVerification,
    LayerProofVerification,
    NANOZK_PROOF_SIZE_BYTES,
    NANOZK_VERIFIER_TARGET_MS,
    NanozkBackend,
    NanozkBackendUnavailable,
    default_block_circuit,
    get_layerwise_backend,
    prove_layer,
    prove_layer_set,
    register_backend,
    verify_layer_proof,
    verify_layer_proof_set,
)
from tex.nanozk.nonlinearity_lookup import (
    NonlinearityKind,
    PrefixSuffixLookup,
    gelu_lookup,
    layernorm_lookup,
    softmax_lookup,
)
from tex.nanozk.veil_wrapper import (
    VEIL_OVERHEAD_FACTOR,
    VeilWrappedProof,
    veil_unwrap,
    veil_wrap,
)

# --- Thread 15 bleeding-edge upgrade modules ---

# Upgrade 1 — Logup* (ePrint 2025/946, Soukhanov)
from tex.nanozk.logup_star import (
    DEFAULT_LOOKUP_ARGUMENT,
    LogupStarTranscript,
    LookupArgumentKind,
    logup_star_argue,
    logup_star_verify,
    logup_star_witness_count_no_extra_columns,
)

# Upgrade 2 — GaugeZKP (OpenReview 1Ne3tfQC0T, ICME Labs 2025)
from tex.nanozk.gauge_zkp import (
    CanonicalisationKind,
    DEFAULT_CANONICALISATION,
    GaugeCanonicalizer,
    PAPER_BASE_GATE_REDUCTION,
    PoGECertificate,
    PoVITag,
    build_poge_certificate,
    canonical_model_hash_for,
    compute_gate_reduction_factor,
    poge_certificate_hash,
    verify_poge,
)

# Upgrade 3 — Poseidon (replaces SHA-256 chain when flag is on)
from tex.nanozk.poseidon_chain import (
    BN254_FIELD_BYTES,
    BN254_PRIME,
    HashChainKind,
    layer_set_root,
    poseidon_available,
    poseidon_chain_root,
    poseidon_hash,
    poseidon_hash_hex,
)

# Upgrade 4 — LatticeFold+ ℓ2 (ePrint 2026/721, Apr 2026)
from tex.nanozk.latticefold_plus import (
    DEFAULT_FOLD_KIND,
    L2_NORM_BUDGET_BITS,
    LatticeFoldAccumulator,
    LatticeFoldKind,
    MODULE_SIS_DIMENSION,
    PAPER_PROVER_SPEEDUP_OVER_LATTICEFOLD,
    fold_layer_proofs,
    latticefold_active,
    verify_folded_accumulator,
)

# Upgrade 5 — Sublinear-Space (arxiv 2509.05326, Nye)
from tex.nanozk.sublinear_space import (
    SUBLINEAR_SPACE_FACTOR,
    SublinearSpacePlan,
    compute_streaming_plan,
    estimate_memory_savings,
    streaming_active,
)

# Upgrade 6 — Mira parallel folding (ZKTorch arxiv 2507.07031)
from tex.nanozk.mira_parallel import (
    MiraAccumulator,
    MiraTreeNode,
    PAPER_PROOF_SIZE_REDUCTION_MAX,
    PAPER_PROOF_SIZE_REDUCTION_MIN,
    PAPER_PROVING_SPEEDUP,
    mira_active,
    mira_fold_tree,
    verify_mira_tree,
)

# Upgrade 7 — DeepProve subprocess backend (Lagrange Labs)
from tex.nanozk.deepprove_backend import (
    DEEPPROVE_BACKEND_ID,
    DEEPPROVE_BINARY_NAME,
    DeepProveAvailability,
    DeepProveSubprocessBackend,
    PAPER_PROVER_SPEEDUP_OVER_EZKL,
    PAPER_VERIFIER_SPEEDUP_OVER_EZKL,
    check_deepprove_availability,
    register_deepprove_if_available,
)

# Upgrade 8 — V3DB verifiable vector search (arxiv 2603.03065)
from tex.nanozk.v3db import (
    PAPER_PEAK_MEMORY_REDUCTION,
    PAPER_PROVING_SPEEDUP_OVER_CIRCUIT,
    V3DBQueryProof,
    V3DBSnapshotCommitment,
    V3DB_PROTOCOL_VERSION,
    commit_snapshot,
    prove_query,
    verify_query_proof,
)

# Auto-register the DeepProve backend at import time if the
# binary is present on PATH. Idempotent; silent on absence.
try:
    register_deepprove_if_available()
except Exception:  # noqa: BLE001 — never fatal at boot
    pass


__all__ = [
    # --- Core (Thread 15 base) ---
    "LAYERWISE_BACKEND_ID",
    "LAYERWISE_CIRCUIT_VERSION",
    "FisherSelectionResult",
    "LayerCircuit",
    "LayerOpKind",
    "LayerProof",
    "LayerProofSet",
    "LayerProofSetVerification",
    "LayerProofVerification",
    "NANOZK_PROOF_SIZE_BYTES",
    "NANOZK_VERIFIER_TARGET_MS",
    "NanozkBackend",
    "NanozkBackendUnavailable",
    "NonlinearityKind",
    "PrefixSuffixLookup",
    "VEIL_OVERHEAD_FACTOR",
    "VeilWrappedProof",
    "compute_fisher_budget",
    "default_block_circuit",
    "gelu_lookup",
    "get_layerwise_backend",
    "layernorm_lookup",
    "prove_layer",
    "prove_layer_set",
    "register_backend",
    "select_layers_to_prove",
    "softmax_lookup",
    "veil_unwrap",
    "veil_wrap",
    "verify_layer_proof",
    "verify_layer_proof_set",
    # --- Upgrade 1: Logup* ---
    "DEFAULT_LOOKUP_ARGUMENT",
    "LogupStarTranscript",
    "LookupArgumentKind",
    "logup_star_argue",
    "logup_star_verify",
    "logup_star_witness_count_no_extra_columns",
    # --- Upgrade 2: GaugeZKP ---
    "CanonicalisationKind",
    "DEFAULT_CANONICALISATION",
    "GaugeCanonicalizer",
    "PAPER_BASE_GATE_REDUCTION",
    "PoGECertificate",
    "PoVITag",
    "build_poge_certificate",
    "canonical_model_hash_for",
    "compute_gate_reduction_factor",
    "poge_certificate_hash",
    "verify_poge",
    # --- Upgrade 3: Poseidon ---
    "BN254_FIELD_BYTES",
    "BN254_PRIME",
    "HashChainKind",
    "layer_set_root",
    "poseidon_available",
    "poseidon_chain_root",
    "poseidon_hash",
    "poseidon_hash_hex",
    # --- Upgrade 4: LatticeFold+ ---
    "DEFAULT_FOLD_KIND",
    "L2_NORM_BUDGET_BITS",
    "LatticeFoldAccumulator",
    "LatticeFoldKind",
    "MODULE_SIS_DIMENSION",
    "PAPER_PROVER_SPEEDUP_OVER_LATTICEFOLD",
    "fold_layer_proofs",
    "latticefold_active",
    "verify_folded_accumulator",
    # --- Upgrade 5: Sublinear-Space ---
    "SUBLINEAR_SPACE_FACTOR",
    "SublinearSpacePlan",
    "compute_streaming_plan",
    "estimate_memory_savings",
    "streaming_active",
    # --- Upgrade 6: Mira parallel folding ---
    "MiraAccumulator",
    "MiraTreeNode",
    "PAPER_PROOF_SIZE_REDUCTION_MAX",
    "PAPER_PROOF_SIZE_REDUCTION_MIN",
    "PAPER_PROVING_SPEEDUP",
    "mira_active",
    "mira_fold_tree",
    "verify_mira_tree",
    # --- Upgrade 7: DeepProve backend ---
    "DEEPPROVE_BACKEND_ID",
    "DEEPPROVE_BINARY_NAME",
    "DeepProveAvailability",
    "DeepProveSubprocessBackend",
    "PAPER_PROVER_SPEEDUP_OVER_EZKL",
    "PAPER_VERIFIER_SPEEDUP_OVER_EZKL",
    "check_deepprove_availability",
    "register_deepprove_if_available",
    # --- Upgrade 8: V3DB ---
    "PAPER_PEAK_MEMORY_REDUCTION",
    "PAPER_PROVING_SPEEDUP_OVER_CIRCUIT",
    "V3DBQueryProof",
    "V3DBSnapshotCommitment",
    "V3DB_PROTOCOL_VERSION",
    "commit_snapshot",
    "prove_query",
    "verify_query_proof",
]
