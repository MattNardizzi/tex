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

Sublinear-space proving mode for layer proofs.

Structural scaffold modeled on the prover-SHAPE of (a placeholder, NOT a real implementation of):

  Logan Nye, *Zero-Knowledge Proofs in Sublinear Space*,
  arxiv 2509.05326 (Aug 30 2025; v2 Sep 17 2025; HAL deposit
  hal-05157224).

Reference Rust prototype (KZG/BN254 streaming prover with
blocked IFFT and aggregate-only Fiat-Shamir):
  github.com/logannye/space-efficient-zero-knowledge-proofs

Why this matters
----------------
Standard PCS-based SNARK provers materialise the full execution
trace — O(T) memory for trace length T. Nye's construction
reframes proof generation as **Tree Evaluation** and uses the
Cook-Mertz space-efficient algorithm to stream the prover with
**O(√T · log T · log log T)** memory while producing **bit-
identical** proofs and verification (for linear PCSs like KZG
and IPA).

At GPT-2 scale this barely matters (the prover already fits in a
few hundred MB). At Llama-70B-scale or for **edge proving on
mobile / embedded** it's the difference between proving locally
and not proving at all. The paper's worked example: 1 billion
trace steps drop from **34 GB to 0.64 MB** of prover memory —
fitting trivially on a smartphone.

What this module exposes
------------------------
- ``SublinearSpacePlan`` — frozen Pydantic descriptor of how
  the prover will stream a trace: block size √T, expected
  memory footprint, and the Cook-Mertz tree depth.
- ``compute_streaming_plan`` — given a trace length T, compute
  the optimal block size and memory budget. Implements the
  paper's Theorem 2 cost model.
- ``SUBLINEAR_SPACE_FACTOR`` — the asymptotic improvement
  (√T) frozen as a callable for clarity.
- ``streaming_active`` — env flag check.
- ``estimate_memory_savings`` — given a trace length, return
  (linear_bytes, sublinear_bytes, savings_factor) — useful for
  dashboards and the FRONTIER_DELTA brief's perf table.

Composition with Thread 15
--------------------------
Per-layer NANOZK proofs target the layerwise prover; the
trace per layer is moderate (~10^7 rows for GPT-2). The
streaming mode is exposed for callers that want to prove **the
entire model in one shot** without a layerwise decomposition,
e.g. a regulator running an offline batch validation.

The shim doesn't actually stream — it pretends to, recording
the plan in metadata. A regulator-grade backend (the reference
Rust impl) honours the plan literally.

Honest scope
------------
We provide the **plan + bookkeeping**; the actual sublinear-
space trace streaming requires the Cook-Mertz algorithm wired
into the prover's polynomial commitment scheme — that's a
sizable Rust crate, not a Python shim. The plan API is what a
caller (Tex's batch validator) uses to decide whether to enable
the mode and on which backend.
"""

from __future__ import annotations

import math
import os

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


# Theoretical asymptotic improvement: O(T) → O(√T · log T · log log T).
def SUBLINEAR_SPACE_FACTOR(T: int) -> float:
    """The factor by which sublinear-space prover memory is
    smaller than the linear-space baseline for trace length T."""
    if T <= 1:
        return 1.0
    return T / max(1.0, math.sqrt(T) * math.log2(T) * math.log2(math.log2(T) + 2))


# Bytes-per-field-element for KZG/BN254 (the reference impl uses
# this). 32 bytes per scalar / commitment.
BYTES_PER_FIELD_ELEMENT: int = 32


# --------------------------------------------------------------------------- #
# Streaming plan                                                               #
# --------------------------------------------------------------------------- #


class SublinearSpacePlan(BaseModel):
    """Frozen plan describing how the streaming prover will run.

    Drop into a prover backend's config; the prover honors the
    block size and aggregates the Fiat-Shamir transcript to
    match the baseline.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    trace_length: int = Field(ge=1)
    block_size: int = Field(ge=1)
    """Per-block working set size (√T, rounded up to power of 2
    for IFFT alignment)."""

    num_blocks: int = Field(ge=1)
    cook_mertz_tree_depth: int = Field(ge=1)
    estimated_memory_bytes: int = Field(ge=1)
    estimated_passes: int = Field(ge=1)
    """Number of streaming passes the prover makes over the
    trace. Paper Theorem 5 — O(log T) passes."""

    aggregate_only_fiat_shamir: bool = True
    """When True, the FS transcript hashes only aggregate
    commitments per block (not per-block artefacts). This is
    the property that makes the streaming prover produce
    bit-identical proofs to the linear baseline (paper §3.2)."""


# --------------------------------------------------------------------------- #
# Plan computation                                                             #
# --------------------------------------------------------------------------- #


def _next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def compute_streaming_plan(
    *,
    trace_length: int,
    bytes_per_element: int = BYTES_PER_FIELD_ELEMENT,
) -> SublinearSpacePlan:
    """Compute the optimal block size and memory budget.

    Paper Theorem 2: memory = O(√T · log T · log log T) field
    elements. We pick block_size = next_power_of_two(√T) for
    IFFT alignment.
    """
    if trace_length < 1:
        raise ValueError("trace_length must be >= 1")

    raw_block_size = max(1, int(math.ceil(math.sqrt(trace_length))))
    block_size = _next_power_of_two(raw_block_size)
    num_blocks = max(1, (trace_length + block_size - 1) // block_size)
    tree_depth = max(1, int(math.ceil(math.log2(max(2, num_blocks)))))

    # Memory: working set of one block + log T overhead.
    log_t = max(1, int(math.ceil(math.log2(max(2, trace_length)))))
    log_log_t = max(1, int(math.ceil(math.log2(max(2, log_t)))))
    estimated_elements = block_size * log_t * log_log_t
    estimated_memory_bytes = estimated_elements * bytes_per_element

    # Paper Theorem 5: a constant number of passes (O(log T)
    # depth-bounded by the Cook-Mertz tree).
    estimated_passes = tree_depth + 1

    return SublinearSpacePlan(
        trace_length=trace_length,
        block_size=block_size,
        num_blocks=num_blocks,
        cook_mertz_tree_depth=tree_depth,
        estimated_memory_bytes=estimated_memory_bytes,
        estimated_passes=estimated_passes,
    )


# --------------------------------------------------------------------------- #
# Savings calculator (dashboard)                                               #
# --------------------------------------------------------------------------- #


def estimate_memory_savings(
    trace_length: int,
    *,
    bytes_per_element: int = BYTES_PER_FIELD_ELEMENT,
) -> dict[str, int | float]:
    """Return (linear_bytes, sublinear_bytes, savings_factor).

    Used by ``FRONTIER_DELTA_thread_15.md`` and Tex's audit
    dashboards to surface the savings.

    Paper worked example (Scenario 2 from §4 "Performance"):
        T = 2^30 ≈ 1 billion
        linear-space prover: ≈ 34.4 GB
        sublinear-space:    ≈ ~20,000 elements ≈ 0.64 MB
        savings factor:     ≈ 50,000×

    Our model:
        linear_bytes = T * bytes_per_element
        sublinear_bytes = √T * log T * log log T * bytes_per_element
        savings = linear / sublinear
    """
    if trace_length < 1:
        raise ValueError("trace_length must be >= 1")

    linear_bytes = trace_length * bytes_per_element

    plan = compute_streaming_plan(
        trace_length=trace_length, bytes_per_element=bytes_per_element
    )

    sublinear_bytes = plan.estimated_memory_bytes
    savings_factor = (
        linear_bytes / max(1, sublinear_bytes)
    )

    return {
        "trace_length": trace_length,
        "linear_bytes": linear_bytes,
        "sublinear_bytes": sublinear_bytes,
        "savings_factor": savings_factor,
        "block_size": plan.block_size,
        "num_blocks": plan.num_blocks,
        "tree_depth": plan.cook_mertz_tree_depth,
        "expected_passes": plan.estimated_passes,
    }


# --------------------------------------------------------------------------- #
# Env-flag dispatch                                                            #
# --------------------------------------------------------------------------- #


def streaming_active() -> bool:
    """Opt-in env flag. Off by default."""
    if os.environ.get("TEX_NANOZK_SUBLINEAR", "0") == "1":
        return True
    if os.environ.get("TEX_FRONTIER_NANOZK", "0") == "1":
        # Frontier flag implies sublinear *eligibility* but does
        # not auto-activate (the mode adds passes; only enable
        # when the caller has memory pressure).
        return os.environ.get(
            "TEX_NANOZK_SUBLINEAR", "auto"
        ) == "auto_force"
    return False


__all__ = [
    "BYTES_PER_FIELD_ELEMENT",
    "SUBLINEAR_SPACE_FACTOR",
    "SublinearSpacePlan",
    "compute_streaming_plan",
    "estimate_memory_savings",
    "streaming_active",
]
