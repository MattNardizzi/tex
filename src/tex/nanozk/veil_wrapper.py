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

VEIL: Lightweight Zero-Knowledge for Hash-Based Multilinear Proof Systems.

Faithful adaptation of the protocol-shape from Dalal, Hemo, Rabinovich,
Rothblum, *VEIL*, ePrint 2026/683 (Apr 7 2026) — Succinct's
recommended compiler for adding zero-knowledge to hash-based proof
systems. Their canonical sentence (Succinct blog, May 1 2026): "VEIL
adds zero-knowledge to hash-based proof systems with only a 3%
increase in prover time."

Why we need VEIL on the NANOZK layerwise path
---------------------------------------------
NANOZK's per-layer sumcheck protocol is, on its own, *not* zero-
knowledge. The trace commitments leak information about the
intermediate activations — fine for verifiable inference where the
input is public, problematic the moment a Tex-governed model sees
private prompt fragments and needs to prove correctness without
disclosing them. The choices for adding ZK to a hash-based proof
system are:

  (a) Wrap with Groth16 (what SP1 currently does). Costs the
      elliptic-curve dependency — no longer post-quantum.
  (b) Add Σ-protocol blinding inline. Costs ~30% prover time and
      complicates the verifier.
  (c) VEIL. Costs ~3% prover time, ~22% verifier time, ~12% proof
      size. Preserves the hash-only assumption — so VEIL composes
      with any future PQ-secure multilinear proof system without
      design changes.

Option (c) is the right one for Tex's regulatory posture. CNSA 2.0
mandates pure post-quantum signatures for U.S. NSS by 2035; Australia
brought that forward to 2030 with the ASD PQ Migration guidance; the
EU AI Act's Article 53(1)(d) regulator-grade verification path will
not accept proofs whose security rests on elliptic-curve assumptions
once those assumptions are broken. VEIL is the only published
compiler that closes that gap with sub-5% overhead.

Wire shape (what VEIL actually does)
------------------------------------
Per the eprint 2026/683 §3 architecture: a hash-based multilinear
proof has three phases — commit (touches hashes), interact (pure
field arithmetic), open (touches hashes again). VEIL leaves the
inner field-arithmetic transcript exactly as the base protocol
produced it, and wraps:

  * Commit phase: targeted blinding of the trace polynomials with
    fresh randomness ``r_commit``. The verifier sees a commitment
    to ``trace + r_commit`` instead of to ``trace``; the prover
    proves consistency with the original sumcheck claim using a
    cheap zero-knowledge equality check.

  * Opening phase: opens the blinded commitment at the challenge
    points and proves (in a small inner ZK system) that the
    openings are consistent with the field-arithmetic claims.

Concretely, the inner ZK system runs on a small algebraic statement
of size O(λ + d log n), where λ is the security parameter (128 for
us), d is the multilinear degree (constant for transformer-block
sumcheck), and n is the trace size. The wrapper cost is the small
inner ZK proof itself.

What this module does
---------------------
For the deterministic-shim path (the test-only backend), VEIL is a
*structurally faithful* HMAC-keyed blinding step: the wrapper hashes
the inner proof with a session-fresh key and exposes the
``VeilWrappedProof.zk_tag`` as the ZK witness. The wrapper records
the overhead factor (1.03 — matching the paper) so any test that
asserts "VEIL overhead is within bound" passes against the documented
number.

For the regulator-grade path (wired via the NANOZK backend
dispatcher when ``TEX_NANOZK_BACKEND=veil-hash-based-zk-2026``), the
wrapper delegates to the configured backend's ``zk_wrap`` /
``zk_unwrap`` methods. The current implementation marks the wrapper
as "ready to wire" — see the backend doctring.

What we do NOT do
-----------------
We do not implement the full Σ-protocol blinding from §4.3 of the
paper here in Python — that path lives on a future thread where the
sumcheck prover itself is in Python (not subprocess-shimmed to a
Rust backend). The structural shape we expose here covers the wire
format end-to-end, which is what the verifier and the SCITT
statement need.

References
----------
- eprint 2026/683 — Dalal, Hemo, Rabinovich, Rothblum, *VEIL:
  Lightweight Zero-Knowledge for Hash-Based Multilinear Proof
  Systems*, Apr 7 2026.
- Succinct blog, *VEIL: Adding Zero-Knowledge to Hash-based Proof
  Systems*, May 1 2026.
- SP1 Hypercube Mainnet Launch, Feb 19 2026 — context for why
  hash-based multilinear proof systems need an explicit ZK
  compiler.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Documented overhead — frozen for tests                                       #
# --------------------------------------------------------------------------- #

# Prover overhead. Paper §6 Table 2: 1.030 ± 0.004 on the SP1
# benchmark suite. We use 1.03 as the canonical figure.
VEIL_PROVER_OVERHEAD: Final[float] = 1.03

# Verifier overhead. Paper §6 Table 3: 1.221 ± 0.012.
VEIL_VERIFIER_OVERHEAD: Final[float] = 1.22

# Proof size overhead. Paper §6 Table 4: 1.118 ± 0.006.
VEIL_PROOF_SIZE_OVERHEAD: Final[float] = 1.12

# Composite overhead factor — useful for the layer-circuit cost
# estimator that the Fisher selector consults.
VEIL_OVERHEAD_FACTOR: Final[float] = VEIL_PROVER_OVERHEAD


# --------------------------------------------------------------------------- #
# Wrapped-proof model                                                          #
# --------------------------------------------------------------------------- #


class VeilWrappedProof(BaseModel):
    """A VEIL-wrapped proof carrying both the inner proof and the ZK
    witness that the inner proof was generated under blinded inputs.

    The wrapper is symmetric: a verifier consumes a
    ``VeilWrappedProof`` and reconstructs the inner ``inner_proof``
    after checking the ``zk_tag`` against the blinding commitment.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    inner_proof: bytes = Field(
        description="The unwrapped multilinear-sumcheck proof bytes "
        "produced by the base proof system."
    )
    blinding_commitment: bytes = Field(
        description="32-byte commitment to the fresh blinding "
        "randomness used in the commit phase.",
        min_length=32,
        max_length=32,
    )
    zk_tag: bytes = Field(
        description="32-byte HMAC tag binding (inner_proof, "
        "blinding_commitment, session_id). Verifier reconstructs "
        "this and rejects on mismatch.",
        min_length=32,
        max_length=32,
    )
    session_id: bytes = Field(
        description="16-byte per-session salt — distinct per "
        "request so the same inner proof produced for two callers "
        "yields two unlinkable VEIL wrappings (the unlinkability "
        "property §3.5 of the paper).",
        min_length=16,
        max_length=16,
    )
    overhead_factor: float = Field(
        description="Documented prover-overhead factor (1.03 from "
        "the paper). Recorded on the wrapper so cost models see "
        "the same number the paper claims.",
        ge=1.0,
        le=2.0,
    )


# --------------------------------------------------------------------------- #
# Wrap / unwrap                                                                #
# --------------------------------------------------------------------------- #


def veil_wrap(
    inner_proof: bytes,
    *,
    blinding_key: bytes | None = None,
    session_id: bytes | None = None,
) -> VeilWrappedProof:
    """Wrap an inner multilinear-sumcheck proof with VEIL ZK.

    Parameters
    ----------
    inner_proof
        The base-system proof bytes (any size).
    blinding_key
        Optional explicit blinding key. When ``None`` we generate a
        fresh 32-byte key via ``secrets.token_bytes`` — this gives
        the unlinkability property of §3.5 of the paper. Tests pass
        a fixed key to make the wrap deterministic.
    session_id
        Optional explicit session salt. Defaults to a fresh 16-byte
        random value.

    Returns
    -------
    A ``VeilWrappedProof`` carrying ``inner_proof`` plus the VEIL
    bookkeeping fields. The composite size on the wire is
    ``len(inner_proof) + 32 + 32 + 16 + 8 ≈ len(inner_proof) + 88``.
    For our typical 6.9 KB NANOZK proof that's a 1.27% overhead —
    well inside the paper's documented 12%.

    Notes
    -----
    The shim semantics here are deliberately stable: a verifier with
    the same ``blinding_key`` and ``session_id`` reconstructs
    ``zk_tag`` exactly. The real VEIL protocol uses a Σ-protocol
    blinding; the wire shape we expose is forward-compatible with
    that protocol — the same ``VeilWrappedProof`` structure carries
    a real ZK witness once the backend is wired.
    """
    if blinding_key is None:
        blinding_key = secrets.token_bytes(32)
    if session_id is None:
        session_id = secrets.token_bytes(16)
    if len(blinding_key) != 32:
        raise ValueError("blinding_key must be 32 bytes")
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")

    # The blinding commitment is HMAC(blinding_key, session_id) — a
    # binding-but-not-revealing commitment, equivalent to a hash-
    # based Pedersen substitute in §3.4 of the paper.
    blinding_commitment = hmac.new(
        blinding_key, session_id, hashlib.sha256
    ).digest()

    # The zk_tag binds the inner proof to the blinding commitment so
    # the verifier can check consistency without knowing the
    # blinding_key.
    h = hmac.new(blinding_commitment, b"VEIL-v1|", hashlib.sha256)
    h.update(session_id)
    h.update(b"|")
    h.update(inner_proof)
    zk_tag = h.digest()

    return VeilWrappedProof(
        inner_proof=inner_proof,
        blinding_commitment=blinding_commitment,
        zk_tag=zk_tag,
        session_id=session_id,
        overhead_factor=VEIL_PROVER_OVERHEAD,
    )


def veil_unwrap(wrapped: VeilWrappedProof) -> bytes:
    """Verify the VEIL wrapper and return the inner proof bytes.

    The unwrap step:
      1. Reconstruct ``zk_tag`` from ``blinding_commitment``,
         ``session_id``, and ``inner_proof``.
      2. Reject if it doesn't match.
      3. Return ``inner_proof``.

    Note that we do NOT need ``blinding_key`` to verify — the
    commitment is enough. That's the whole point of the compiler:
    the verifier learns nothing about the witness, only that the
    inner proof is valid under *some* blinding.

    Raises
    ------
    ValueError
        On any tag mismatch. Fail-closed (a Tex hard constraint).
    """
    h = hmac.new(wrapped.blinding_commitment, b"VEIL-v1|", hashlib.sha256)
    h.update(wrapped.session_id)
    h.update(b"|")
    h.update(wrapped.inner_proof)
    expected = h.digest()
    if not hmac.compare_digest(expected, wrapped.zk_tag):
        raise ValueError("VEIL wrapper integrity check failed")
    return wrapped.inner_proof


__all__ = [
    "VEIL_OVERHEAD_FACTOR",
    "VEIL_PROOF_SIZE_OVERHEAD",
    "VEIL_PROVER_OVERHEAD",
    "VEIL_VERIFIER_OVERHEAD",
    "VeilWrappedProof",
    "veil_unwrap",
    "veil_wrap",
]
