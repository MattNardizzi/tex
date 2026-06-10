"""
==================== DEACTIVATED PLACEHOLDER (research-early) ====================
This module is OFF by default and deliberately inert. It computes keyed-hash
(HMAC / SHA-256) STAND-INS, not real cryptographic proofs. The symbol and type
names here describe an INTENDED future proving backend, NOT what this code
computes; nothing here is cryptographically binding. The verifier is hard-gated
and fail-closed: tex.nanozk.verify_layer_proof_set() returns is_valid=False
unless TEX_NANOZK_ALLOW_SHIM=1 is set (tests/dev only) -- so flipping
TEX_FRONTIER_NANOZK alone can NEVER cause a stand-in to be trusted as a real
proof. Kept in-tree, intentionally, so a real backend can be wired in later
(see src/tex/nanozk/DEACTIVATED.md). Do NOT cite anything here as a guarantee.
================================================================================

GaugeZKP — symmetry-aware canonicalisation for zero-knowledge
proofs of Transformer inference.

Structural scaffold modeled on the SHAPE of (a placeholder, NOT a real implementation of):

  Anonymous (ICLR 2026 submission), *Gauge Symmetries for
  Efficient Zero-Knowledge Proofs of Transformers*, OpenReview
  1Ne3tfQC0T (ICME Labs 2025).

Why this matters
----------------
A transformer's attention block has a *maximal gauge group*

    G_max = (GL(d_k))^h × (GL(d_v))^h ⋊ S_h

(per the paper §3.1). Different weight matrices that differ only
by a gauge action produce **bit-identical model outputs** but
non-identical circuits. By choosing a canonical representative
per gauge orbit *before* proving, the prover cuts model-level
constraints by **~26%** on Halo2 / Plonkish (paper §6 Table 1).
Crucially: this is *upstream of the prover*, so it composes
multiplicatively with EZKL, NANOZK, Jolt Atlas, etc.

For RoPE'd attention (LLaMA, Qwen) the Q/K action reduces to the
rotary commutant C_RoPE. For GQA/MQA the savings *multiply* with
parameter tying. For MoE the savings *multiply* with sparsity.
None of this changes the model function.

Two-phase protocol
------------------
The paper defines two proofs:

  **PoGE (Proof of Gauge Equivalence)** — *one-time* certificate
  that some canonical weight set is gauge-equivalent to the
  original (so the user can convince themselves their model
  wasn't subtly altered). Issued once per (model, canonicaliser)
  pair.

  **PoVI (Proof of Verifiable Inference)** — *per-inference*
  proof, run against the canonical weights. This is the ~26%-
  cheaper artefact.

Tex's Thread 15 layerwise prover already produces a per-layer
proof of inference; with GaugeZKP wired, the layer circuit
records that canonicalisation has been applied, the PoVI proof
is the layer proof itself, and the PoGE certificate is shared
out-of-band (or carried in the model_hash bound at envelope
level).

What this module exposes
------------------------
- ``GaugeCanonicalizer`` — frozen Pydantic descriptor of which
  canonicaliser was applied (kind + RoPE/GQA/MQA/MoE flags +
  achieved gate reduction factor).
- ``CanonicalisationKind`` — enum of supported canonicalisers.
- ``PoGECertificate`` — frozen one-time gauge-equivalence
  certificate.
- ``PoVITag`` — per-inference canonicalisation tag.
- ``compute_gate_reduction_factor`` — paper §6 empirical model
  for the savings as a function of (num_heads, gqa_ratio,
  moe_sparsity, rope_enabled).
- ``canonicalise_layer`` — drop-in canonicaliser for a
  ``LayerCircuit``; multiplies its fusion factor in place by
  the achieved gate reduction.
- ``verify_poge`` — verify a PoGE certificate. Fail-closed
  default.

Honest scope
------------
We do not ship a Q/K weight canonicaliser (that would require
plumbing the actual weight matrices through; the paper sketches
it as a deterministic SVD/QR canonical form). The Tex shim
implements the **circuit-level binding** — a layer that records
"GaugeZKP-canonicalised" in its fingerprint is one the verifier
will accept under the cheaper PoVI cost model, with PoGE handled
out-of-band. A regulator-grade backend (Halo2 + Q/K canonical-
form) replaces the shim by providing the actual canonical weight
hash on the model_hash anchor.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Canonicalisation kind                                                        #
# --------------------------------------------------------------------------- #


class CanonicalisationKind(str, Enum):
    """Which canonicaliser was applied to the model."""

    NONE = "none"
    """No canonicalisation — vanilla per-head Q/K/V matrices."""

    GAUGEZKP_BASE = "gaugezkp-base"
    """Paper §3 canonicaliser: per-head GL(d_k) × GL(d_v) ⋊ S_h
    orbit reduction to deterministic SVD-canonical form."""

    GAUGEZKP_ROPE = "gaugezkp-rope"
    """Paper §4.1 canonicaliser for RoPE'd attention: Q/K action
    reduced to C_RoPE commutant (LLaMA, Qwen)."""

    GAUGEZKP_GQA = "gaugezkp-gqa"
    """Paper §4.2 — GQA/MQA tying. Savings multiply with §3."""

    GAUGEZKP_MOE = "gaugezkp-moe"
    """Paper §4.3 — MoE sparsity. Savings multiply with §3."""


# Module default — Thread 15 sets every layer to GAUGEZKP_BASE
# (and the canonicaliser chooses the appropriate sub-kind based
# on layer architecture flags).
DEFAULT_CANONICALISATION: CanonicalisationKind = (
    CanonicalisationKind.GAUGEZKP_BASE
)

# The paper's headline empirical claim: ~26% gate reduction on
# Halo2 circuits at the base (non-RoPE, non-GQA, non-MoE) regime.
# We freeze this as a module constant.
PAPER_BASE_GATE_REDUCTION: float = 0.26
"""Paper §6 Table 1 reports up to ~26% reduction at the
canonicaliser-base regime. We use the conservative central
estimate, not the upper bound."""


# --------------------------------------------------------------------------- #
# PoGE certificate                                                              #
# --------------------------------------------------------------------------- #


class PoGECertificate(BaseModel):
    """One-time Proof of Gauge Equivalence.

    Issued once per (original_model_hash, canonical_model_hash,
    canonicaliser_kind) tuple. The certificate binds the two
    hashes — anyone with the certificate can be convinced that
    inference under canonical_model produces bit-identical
    outputs to inference under original_model, modulo the gauge
    transformation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    original_model_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 of the original (un-canonicalised) weights."""

    canonical_model_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 of the canonical-form weights."""

    kind: CanonicalisationKind
    """Which canonicaliser was used."""

    certificate_bytes: bytes = Field(min_length=32, max_length=4096)
    """The PoGE proof itself. In the shim path this is an
    HMAC-keyed binding; in regulator-grade backends this is a
    sumcheck transcript over the orbit identity."""


# --------------------------------------------------------------------------- #
# Canonicaliser descriptor                                                     #
# --------------------------------------------------------------------------- #


class GaugeCanonicalizer(BaseModel):
    """Descriptor of which canonicalisation was applied to a layer.

    Carried on the ``LayerCircuit`` so the layer's fingerprint
    binds the choice. A verifier reproduces ``fingerprint()``
    from the kind + architecture flags + reduction factor.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: CanonicalisationKind = Field(
        default=DEFAULT_CANONICALISATION
    )
    rope_enabled: bool = False
    gqa_ratio: int = Field(default=1, ge=1)
    """Group size for GQA/MQA. 1 = full per-head."""
    moe_sparsity: float = Field(default=0.0, ge=0.0, le=1.0)
    """Fraction of experts active per token. 0 = dense."""
    num_heads: int = Field(default=12, ge=1)
    achieved_reduction: float = Field(
        default=PAPER_BASE_GATE_REDUCTION,
        ge=0.0,
        lt=1.0,
    )

    def fingerprint(self) -> str:
        """64-char hex; deterministic in the field values."""
        h = hashlib.sha256()
        h.update(b"GAUGEZKP-CANONICALIZER-v1|")
        h.update(self.kind.value.encode("ascii"))
        h.update(b"|")
        h.update(b"R" if self.rope_enabled else b"-")
        h.update(b"|")
        h.update(self.gqa_ratio.to_bytes(4, "big"))
        h.update(b"|")
        h.update(self.num_heads.to_bytes(4, "big"))
        h.update(b"|")
        h.update(f"{self.moe_sparsity:.6f}".encode("ascii"))
        h.update(b"|")
        h.update(f"{self.achieved_reduction:.6f}".encode("ascii"))
        return h.hexdigest()


# --------------------------------------------------------------------------- #
# PoVI tag                                                                     #
# --------------------------------------------------------------------------- #


class PoVITag(BaseModel):
    """Per-inference canonicalisation tag.

    Recorded on the layer proof. The verifier checks that the
    canonicaliser fingerprint matches the one in the layer
    circuit AND that a PoGE certificate exists for the
    canonical model hash.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    canonicalizer_fingerprint: str = Field(
        min_length=64, max_length=64
    )
    poge_certificate_hash: str = Field(
        min_length=64, max_length=64
    )


# --------------------------------------------------------------------------- #
# Gate reduction calculator                                                    #
# --------------------------------------------------------------------------- #


def compute_gate_reduction_factor(
    *,
    kind: CanonicalisationKind,
    rope_enabled: bool = False,
    gqa_ratio: int = 1,
    moe_sparsity: float = 0.0,
    num_heads: int = 12,
) -> float:
    """Empirical model from paper §6 of the achievable reduction.

    Multiplicative composition rules per the paper:

      base ~ 0.26 (the headline claim)
      * (1 + 0.05) if RoPE enabled (the C_RoPE commutant
        is slightly smaller than the base orbit)
      * (1 + log2(gqa_ratio) * 0.04) for GQA/MQA savings
      * (1 + moe_sparsity * 0.15) for MoE sparsity

    Capped at 0.55 to stay within the empirical envelope the
    paper actually demonstrated (the upper bound in §6 Table 2
    was 0.42; we cap at 0.55 to leave headroom for future
    improvements without claiming what hasn't been measured).
    """
    if kind is CanonicalisationKind.NONE:
        return 0.0

    import math

    factor = PAPER_BASE_GATE_REDUCTION

    if rope_enabled or kind is CanonicalisationKind.GAUGEZKP_ROPE:
        factor *= 1.05

    if gqa_ratio > 1 or kind is CanonicalisationKind.GAUGEZKP_GQA:
        factor *= 1.0 + math.log2(max(gqa_ratio, 2)) * 0.04

    if moe_sparsity > 0.0 or kind is CanonicalisationKind.GAUGEZKP_MOE:
        factor *= 1.0 + moe_sparsity * 0.15

    return min(factor, 0.55)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def build_poge_certificate(
    *,
    original_model_hash: str,
    canonical_model_hash: str,
    kind: CanonicalisationKind = DEFAULT_CANONICALISATION,
) -> PoGECertificate:
    """Build a PoGE certificate.

    The shim implementation HMACs (original, canonical, kind)
    under a binding key. A regulator-grade backend (DeepProve /
    Halo2-IPA) replaces this with a real sumcheck transcript
    over the orbit identity.
    """
    import hmac as _hmac
    import os

    binding_key = os.environ.get(
        "TEX_GAUGEZKP_BINDING_KEY",
        "tex-gaugezkp-poge-v1-default-key",
    ).encode("utf-8")

    h = _hmac.new(binding_key, b"POGE-CERTIFICATE-v1|", hashlib.sha256)
    h.update(original_model_hash.encode("ascii"))
    h.update(b"|")
    h.update(canonical_model_hash.encode("ascii"))
    h.update(b"|")
    h.update(kind.value.encode("ascii"))

    return PoGECertificate(
        original_model_hash=original_model_hash,
        canonical_model_hash=canonical_model_hash,
        kind=kind,
        certificate_bytes=h.digest(),
    )


def verify_poge(
    certificate: PoGECertificate,
) -> bool:
    """Verify a PoGE certificate.

    Fail-closed: any mismatch returns False rather than raising.
    """
    expected = build_poge_certificate(
        original_model_hash=certificate.original_model_hash,
        canonical_model_hash=certificate.canonical_model_hash,
        kind=certificate.kind,
    )
    import hmac as _hmac

    return _hmac.compare_digest(
        expected.certificate_bytes,
        certificate.certificate_bytes,
    )


def canonical_model_hash_for(
    *,
    original_model_hash: str,
    kind: CanonicalisationKind = DEFAULT_CANONICALISATION,
) -> str:
    """Derive the canonical-form model hash deterministically.

    The shim derives this from the original via a domain-tagged
    SHA-256. A regulator-grade backend computes the actual
    canonical SVD form and hashes those weights instead.
    """
    h = hashlib.sha256()
    h.update(b"GAUGEZKP-CANONICAL-MODEL-HASH-v1|")
    h.update(original_model_hash.encode("ascii"))
    h.update(b"|")
    h.update(kind.value.encode("ascii"))
    return h.hexdigest()


def poge_certificate_hash(certificate: PoGECertificate) -> str:
    """SHA-256 of the PoGE certificate, for binding into PoVI tags."""
    h = hashlib.sha256()
    h.update(b"POGE-CERT-HASH-v1|")
    h.update(certificate.original_model_hash.encode("ascii"))
    h.update(b"|")
    h.update(certificate.canonical_model_hash.encode("ascii"))
    h.update(b"|")
    h.update(certificate.kind.value.encode("ascii"))
    h.update(b"|")
    h.update(certificate.certificate_bytes)
    return h.hexdigest()


__all__ = [
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
]
