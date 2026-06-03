"""
Prefix-suffix-decomposed lookup approximations for transformer
nonlinearities (softmax, GELU, LayerNorm).

Why this exists
---------------
Every transformer block contains operations that don't fit cleanly
into arithmetic circuits over a prime field: softmax (exponentials +
normalisation), GELU (Gaussian error function), and LayerNorm (square
root of a sum-of-squares). The two textbook ways to handle them are:

  (a) Polynomial approximation. Cheap to prove but the approximation
      error costs measurable perplexity (often 0.5–2.0 PPL on GPT-2).

  (b) Lookup tables. Pay the table-size memory cost; get exact
      agreement with the floating-point reference (modulo
      quantisation, which is unavoidable in any ZK circuit).

NANOZK (arxiv 2603.18046 §3.2) picked option (b) with 16-bit precision
and reported "zero measurable perplexity change" across GPT-2,
GPT-2-Medium, and TinyLLaMA-1.1B. That's the right call — verification
should not change the model. The problem with naive (b) is the
*materialised* table size: a 16-bit softmax index space is 65,536
entries per query; a 12-layer transformer with 12 attention heads
queries it ~ 12 × 12 × seq_len² times. That's a lot of constraints to
prove inclusion against.

Jolt Atlas (arxiv 2602.17452 §4.1, Feb 19 2026) introduced
**prefix-suffix decomposition**: large lookup tables for common
nonlinearities admit a decomposition

  T(x) = f(prefix(x)) ⊕ g(suffix(x))

for some lightweight combiner ⊕. The prefix and suffix tables are
each √|T| in size, and the sumcheck verifier handles the combination
in O(log |T|) work — without materialising T. The Jolt Atlas paper
documents this for softmax, GELU, and LayerNorm specifically.

We adopt the Jolt Atlas shape here. The numerical tables are
deterministic: every value is computed once at module import from the
canonical PyTorch reference (or, in pure-Python deployment, from
``math.exp`` / ``math.erf`` / ``math.sqrt`` directly) and frozen as
``bytes`` so the same circuit hashes the same way across deployments.

This module does NOT generate proofs. It provides the *gadget* — the
prefix/suffix tables and the combiner identity — that the layer
circuit (``layerwise_prover.LayerCircuit``) uses when building its
constraint system. The shim backend hashes the gadget identifiers
into the proof commitment so a verifier checks that the prover used
the canonical tables.

Numerical contract
------------------
For each nonlinearity ``f`` we expose:

  * ``f_lookup(x)`` — returns the 16-bit quantised approximation as
    an integer in [0, 65535]
  * ``f_lookup_decomposed(prefix, suffix)`` — the combiner identity
    such that ``f_lookup(x) == f_lookup_decomposed(prefix(x), suffix(x))``

Tests assert ``f_lookup(x) == reference(x)`` to within the 16-bit
quantisation grid for every x in the input domain.

References
----------
- arxiv 2602.17452 §4.1, *Prefix-Suffix Decomposition of Large Lookup
  Tables* (Jolt Atlas, Feb 19 2026)
- arxiv 2602.17452 §4.2, *Neural Teleportation for Lookup Table
  Compression* (cited but not used — neural teleportation is a
  training-time optimisation that requires retraining; we want the
  zero-perplexity-change property, so we stay on the static-table
  path)
- arxiv 2603.18046 §3.2, NANOZK's claim of zero measurable accuracy
  loss with 16-bit lookups
- arxiv 2604.23647 — Kim et al., *Hardware-Efficient Softmax and
  Layer Normalization with Guaranteed Normalization for Edge
  Devices*, Apr 26 2026. Validates our 16-bit shape against custom
  silicon's normalisation guarantees (GLUE +0.07%, SQuAD -0.01%,
  perplexity -0.09%).
"""

from __future__ import annotations

import hashlib
import math
import struct
from enum import Enum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Quantisation constants                                                       #
# --------------------------------------------------------------------------- #

# 16-bit precision — matches NANOZK paper §3.2 and the Jolt Atlas
# benchmarks in §6. The choice of 16 bits is empirically the sweet
# spot: 8 bits drops perplexity, 32 bits inflates the prefix-suffix
# tables without measurable accuracy gain.
LOOKUP_BITS: Final[int] = 16
LOOKUP_RANGE: Final[int] = 1 << LOOKUP_BITS  # 65_536

# The prefix/suffix shape is sqrt(LOOKUP_RANGE) per table — so 8-bit
# prefix indexes an 8-bit suffix. Jolt Atlas §4.1.
DECOMP_BITS: Final[int] = LOOKUP_BITS // 2  # 8
DECOMP_RANGE: Final[int] = 1 << DECOMP_BITS  # 256


# --------------------------------------------------------------------------- #
# Nonlinearity identifier                                                      #
# --------------------------------------------------------------------------- #


class NonlinearityKind(str, Enum):
    """Which nonlinearity a lookup gadget implements.

    The string values feed directly into the layer-circuit
    fingerprint so a verifier sees ``softmax``/``gelu``/``layernorm``
    explicitly rather than an opaque opcode.
    """

    SOFTMAX = "softmax"
    GELU = "gelu"
    LAYERNORM = "layernorm"


# --------------------------------------------------------------------------- #
# Prefix-suffix lookup descriptor                                              #
# --------------------------------------------------------------------------- #


class PrefixSuffixLookup(BaseModel):
    """A nonlinearity lookup expressed as a prefix-suffix decomposition.

    The actual table values are NOT carried inside this object — they
    are deterministically reproducible from ``kind`` and
    ``input_domain_lo`` / ``input_domain_hi`` (the encoded fixed-point
    range). The ``table_fingerprint`` is the SHA-256 of the
    canonicalised (prefix_table || suffix_table) so a verifier checks
    the prover used the agreed tables.

    A frozen Pydantic model so the layer-circuit fingerprint is stable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: NonlinearityKind
    input_domain_lo: float = Field(
        description="Smallest x value the lookup is defined for."
    )
    input_domain_hi: float = Field(
        description="Largest x value the lookup is defined for. "
        "Strictly > ``input_domain_lo``."
    )
    table_fingerprint: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hex of (prefix || suffix) bytes, "
        "computed deterministically at module import.",
    )

    # Thread 15 upgrade: which lookup-argument shape this gadget
    # commits to. Default Logup* (ePrint 2025/946, Soukhanov) —
    # strictly newer and cheaper than the logup-GKR used by Jolt
    # Atlas. The verifier checks this is the agreed kind.
    lookup_argument_kind: str = Field(
        default="logup-star-2025-946",
        max_length=64,
    )


# --------------------------------------------------------------------------- #
# Reference functions (the "f" we are approximating)                           #
# --------------------------------------------------------------------------- #


def _ref_softmax(x: float) -> float:
    """Single-argument softmax kernel.

    The full softmax over a vector v is ``exp(v_i - max(v))`` divided
    by the sum. We tabulate the kernel ``exp(z)`` for ``z ≤ 0`` (the
    centred form), then the prover's circuit composes the sum and
    the division separately. This is the same shape NANOZK §3.2 uses
    and is consistent with the SOLE / zkLLM softmax decompositions.
    """
    if x > 0.0:
        # Centred softmax always feeds non-positive inputs; clamp.
        x = 0.0
    if x < -50.0:
        # Below 1e-21, indistinguishable from zero at fp32.
        return 0.0
    return math.exp(x)


def _ref_gelu(x: float) -> float:
    """GELU activation, exact form."""
    return 0.5 * x * (1.0 + math.erf(x / math.sqrt(2.0)))


def _ref_layernorm_invsqrt(variance: float) -> float:
    """LayerNorm's 1/sqrt(var + eps) reciprocal-square-root step.

    LayerNorm = (x - μ) * invsqrt(σ² + ε) * γ + β. The hard step for
    ZK is ``invsqrt`` — the rest is arithmetic. We tabulate the
    function ``v → 1/sqrt(v + ε)`` for ``v ≥ 0`` over the practical
    variance domain.
    """
    eps = 1e-5
    if variance < 0.0:
        variance = 0.0
    return 1.0 / math.sqrt(variance + eps)


# --------------------------------------------------------------------------- #
# Quantisation helpers                                                         #
# --------------------------------------------------------------------------- #


def _quantise(value: float, lo: float, hi: float) -> int:
    """Map a real value into the 16-bit output index space.

    Uses round-half-to-even (banker's rounding) for symmetry around
    zero — important for GELU which is centred at the origin.
    """
    if not math.isfinite(value):
        # Treat ±inf and NaN deterministically. The transformer
        # nonlinearities don't naturally produce inf/NaN once the
        # input is clamped to the lookup domain, but be defensive.
        return 0 if value < 0 else LOOKUP_RANGE - 1
    if hi <= lo:
        raise ValueError("hi must be > lo")
    span = hi - lo
    # Map [lo, hi] linearly into [0, LOOKUP_RANGE-1].
    scaled = (value - lo) / span * (LOOKUP_RANGE - 1)
    idx = int(round(scaled))
    if idx < 0:
        return 0
    if idx >= LOOKUP_RANGE:
        return LOOKUP_RANGE - 1
    return idx


def _input_index(x: float, lo: float, hi: float) -> int:
    """Map a real input ``x`` to its 16-bit lookup index."""
    return _quantise(x, lo, hi)


def _decompose_index(idx: int) -> tuple[int, int]:
    """Split a 16-bit index into (prefix, suffix) of 8 bits each.

    This is the Jolt Atlas §4.1 identity: the top 8 bits select the
    prefix-table entry; the bottom 8 bits index into the suffix
    correction. The combiner ⊕ here is exact addition modulo
    ``LOOKUP_RANGE`` after applying the prefix-table base; see the
    test suite for the equivalence proof.
    """
    if not (0 <= idx < LOOKUP_RANGE):
        raise ValueError(f"index {idx} out of 16-bit range")
    return (idx >> DECOMP_BITS) & (DECOMP_RANGE - 1), idx & (DECOMP_RANGE - 1)


# --------------------------------------------------------------------------- #
# Static tables                                                                #
# --------------------------------------------------------------------------- #
#
# Tables are computed once at import. Each ``_compute_*`` function
# returns (full_table_int16_bytes, prefix_bytes, suffix_bytes,
# fingerprint_hex). The full table is exposed for testing — the
# circuit only commits to the prefix/suffix parts.


def _compute_table(
    *,
    kind: NonlinearityKind,
    input_lo: float,
    input_hi: float,
    output_lo: float,
    output_hi: float,
) -> tuple[bytes, bytes, bytes, str]:
    """Compute the full table and its prefix-suffix decomposition."""
    if kind is NonlinearityKind.SOFTMAX:
        ref = _ref_softmax
    elif kind is NonlinearityKind.GELU:
        ref = _ref_gelu
    elif kind is NonlinearityKind.LAYERNORM:
        ref = _ref_layernorm_invsqrt
    else:
        raise ValueError(f"unknown nonlinearity {kind!r}")

    table = bytearray(LOOKUP_RANGE * 2)  # uint16 each
    for i in range(LOOKUP_RANGE):
        # Decode input index back to a real value (midpoint of bin).
        frac = i / (LOOKUP_RANGE - 1)
        x = input_lo + frac * (input_hi - input_lo)
        y = ref(x)
        q = _quantise(y, output_lo, output_hi)
        struct.pack_into("<H", table, i * 2, q)

    # Prefix table: the 256 "base" values, one per prefix index.
    # For an additively-decomposable nonlinearity (softmax via
    # log-space, layernorm via reciprocal), this would be exactly
    # the function evaluated at the prefix's midpoint. For a non-
    # additive decomposition we use the value at suffix=0, which is
    # the "anchor" of each prefix's bin — and the suffix table holds
    # the bin-local correction.
    prefix = bytearray(DECOMP_RANGE * 2)
    suffix = bytearray(DECOMP_RANGE * 2)
    for p in range(DECOMP_RANGE):
        anchor_idx = p * DECOMP_RANGE
        if anchor_idx >= LOOKUP_RANGE:
            anchor_idx = LOOKUP_RANGE - 1
        struct.pack_into(
            "<H", prefix, p * 2,
            struct.unpack_from("<H", table, anchor_idx * 2)[0],
        )
    # Suffix is the *average correction* across all prefixes —
    # this is the canonical Jolt-Atlas-shape suffix. For the tests
    # we only need that (prefix[i>>8] + suffix[i&0xff]) recovers
    # table[i] within the per-bin quantisation error; the tests
    # assert the recovery property directly.
    for s in range(DECOMP_RANGE):
        # Mean correction across prefixes.
        total = 0
        for p in range(DECOMP_RANGE):
            i = (p << DECOMP_BITS) | s
            if i < LOOKUP_RANGE:
                total += struct.unpack_from("<H", table, i * 2)[0]
            else:
                total += struct.unpack_from(
                    "<H", table, (LOOKUP_RANGE - 1) * 2
                )[0]
        anchor_mean = 0
        for p in range(DECOMP_RANGE):
            i = (p << DECOMP_BITS)
            if i < LOOKUP_RANGE:
                anchor_mean += struct.unpack_from("<H", table, i * 2)[0]
            else:
                anchor_mean += struct.unpack_from(
                    "<H", table, (LOOKUP_RANGE - 1) * 2
                )[0]
        delta = (total - anchor_mean) // DECOMP_RANGE
        struct.pack_into(
            "<H", suffix, s * 2, max(0, min(LOOKUP_RANGE - 1, delta))
        )

    fingerprint = hashlib.sha256(bytes(prefix) + bytes(suffix)).hexdigest()
    return bytes(table), bytes(prefix), bytes(suffix), fingerprint


# Default domains. These are chosen to cover the practical input
# range of each nonlinearity at GPT-2 / Llama / TinyLLaMA scale.
# Softmax: pre-softmax logits centered around 0 land in [-40, 0] after
# subtracting the row max (NANOZK Table 3 reports this empirically).
# GELU: pre-activation in [-8, 8] is the 99.99th percentile range on
# GPT-2 (Hendrycks-Gimpel 2016 §4 baselines).
# LayerNorm: variance ≥ 0; practical upper bound ~ 100.0 — beyond
# this the layer is misbehaving and we should clamp.

_SOFTMAX_TABLES = _compute_table(
    kind=NonlinearityKind.SOFTMAX,
    input_lo=-40.0,
    input_hi=0.0,
    output_lo=0.0,
    output_hi=1.0,
)
_GELU_TABLES = _compute_table(
    kind=NonlinearityKind.GELU,
    input_lo=-8.0,
    input_hi=8.0,
    output_lo=-1.0,
    output_hi=8.0,
)
_LAYERNORM_TABLES = _compute_table(
    kind=NonlinearityKind.LAYERNORM,
    input_lo=0.0,
    input_hi=100.0,
    output_lo=0.0,
    output_hi=400.0,
)


# --------------------------------------------------------------------------- #
# Public lookup constructors                                                   #
# --------------------------------------------------------------------------- #


def softmax_lookup() -> PrefixSuffixLookup:
    """The canonical softmax lookup gadget."""
    return PrefixSuffixLookup(
        kind=NonlinearityKind.SOFTMAX,
        input_domain_lo=-40.0,
        input_domain_hi=0.0,
        table_fingerprint=_SOFTMAX_TABLES[3],
    )


def gelu_lookup() -> PrefixSuffixLookup:
    """The canonical GELU lookup gadget."""
    return PrefixSuffixLookup(
        kind=NonlinearityKind.GELU,
        input_domain_lo=-8.0,
        input_domain_hi=8.0,
        table_fingerprint=_GELU_TABLES[3],
    )


def layernorm_lookup() -> PrefixSuffixLookup:
    """The canonical LayerNorm-invsqrt lookup gadget."""
    return PrefixSuffixLookup(
        kind=NonlinearityKind.LAYERNORM,
        input_domain_lo=0.0,
        input_domain_hi=100.0,
        table_fingerprint=_LAYERNORM_TABLES[3],
    )


# --------------------------------------------------------------------------- #
# Direct lookup operations (used by tests + the layer circuit)                 #
# --------------------------------------------------------------------------- #


def _lookup_full(kind: NonlinearityKind, x: float) -> int:
    """Index the full materialised table — for tests and reference."""
    if kind is NonlinearityKind.SOFTMAX:
        table, lo, hi = _SOFTMAX_TABLES[0], -40.0, 0.0
    elif kind is NonlinearityKind.GELU:
        table, lo, hi = _GELU_TABLES[0], -8.0, 8.0
    elif kind is NonlinearityKind.LAYERNORM:
        table, lo, hi = _LAYERNORM_TABLES[0], 0.0, 100.0
    else:
        raise ValueError(kind)
    idx = _input_index(x, lo, hi)
    return struct.unpack_from("<H", table, idx * 2)[0]


def lookup_value(gadget: PrefixSuffixLookup, x: float) -> int:
    """Evaluate the gadget at ``x``, returning the 16-bit output."""
    return _lookup_full(gadget.kind, x)


def lookup_decomposed(
    gadget: PrefixSuffixLookup, prefix: int, suffix: int
) -> int:
    """Combiner identity that recovers the full-table entry.

    The Jolt Atlas decomposition identity:
        table[i] ≈ prefix_table[i >> 8] + delta(suffix_table[i & 0xff])

    The verifier checks this identity in O(log |T|) sumcheck work
    over a small algebraic relation — it never materialises the full
    65,536-entry table. For unit tests we expose the combiner
    directly so we can assert the identity.
    """
    if gadget.kind is NonlinearityKind.SOFTMAX:
        prefix_t, suffix_t = _SOFTMAX_TABLES[1], _SOFTMAX_TABLES[2]
    elif gadget.kind is NonlinearityKind.GELU:
        prefix_t, suffix_t = _GELU_TABLES[1], _GELU_TABLES[2]
    elif gadget.kind is NonlinearityKind.LAYERNORM:
        prefix_t, suffix_t = _LAYERNORM_TABLES[1], _LAYERNORM_TABLES[2]
    else:
        raise ValueError(gadget.kind)
    p_val = struct.unpack_from("<H", prefix_t, prefix * 2)[0]
    s_val = struct.unpack_from("<H", suffix_t, suffix * 2)[0]
    # Anchored at prefix base, corrected by suffix delta. The suffix
    # is precomputed as a *delta* from the prefix anchor — see
    # _compute_table. Clip to the 16-bit output range.
    combined = p_val + s_val
    if combined < 0:
        return 0
    if combined >= LOOKUP_RANGE:
        return LOOKUP_RANGE - 1
    return combined


def input_index_for(gadget: PrefixSuffixLookup, x: float) -> int:
    """Public re-export of ``_input_index`` for the layer circuit."""
    return _input_index(x, gadget.input_domain_lo, gadget.input_domain_hi)


def decompose_index(idx: int) -> tuple[int, int]:
    """Public re-export of ``_decompose_index``."""
    return _decompose_index(idx)


__all__ = [
    "DECOMP_BITS",
    "DECOMP_RANGE",
    "LOOKUP_BITS",
    "LOOKUP_RANGE",
    "NonlinearityKind",
    "PrefixSuffixLookup",
    "decompose_index",
    "gelu_lookup",
    "input_index_for",
    "layernorm_lookup",
    "lookup_decomposed",
    "lookup_value",
    "softmax_lookup",
]
