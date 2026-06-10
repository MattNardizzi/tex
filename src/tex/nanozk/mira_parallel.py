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

Mira parallel folding for layer proof accumulation.

Structural scaffold modeled on the SHAPE of (a placeholder, NOT a real implementation of):

  Bing-Jyue Chen, Lilia Tang, Daniel Kang, *ZKTorch: Compiling
  ML Inference to Zero-Knowledge Proofs via Parallel Proof
  Accumulation*, arxiv 2507.07031 (Jul 9 2025, v2).

Building on Mira accumulation:
  Beal & Fisch, *Mira: Recursive SNARKs from KZG*, 2024.

Why parallel folding (and not sequential LatticeFold)
-----------------------------------------------------
LatticeFold+ folds *one instance at a time* — fold[i+1] depends
on fold[i]. That sequential dependency limits throughput on
multi-core / GPU systems.

**ZKTorch's parallel Mira** restructures the accumulation as a
**tree** — two accumulators (or a proof and an accumulator) are
folded together with fresh random challenges, allowing all
leaves to be processed in parallel across available cores. The
paper reports:

  * **3-10× proof size reduction** vs specialized protocols
  * **6× proving speedup** over general-purpose ZKML frameworks
  * Empirical: 6.2× speedup on GPT-j, BERT, ResNet-50, LLaMA-2-7B

The structural property is that the *order of folds doesn't
affect the final accumulator* — the tree is **homomorphic**.
This is the property the verifier exploits: rebuild the tree
in any topology and check the root matches.

When to choose Mira vs LatticeFold+
------------------------------------
* **LatticeFold+** — PQ-safe (lattice-based), 64-bit fields,
  sequential. Pick for compliance with PQ-mandate (CNSA 2.0)
  contexts.
* **Mira (this module)** — pairing-based (KZG), 256-bit fields,
  tree-parallel. Pick when throughput dominates and the
  pairing-based assumption is acceptable.

Tex exposes both; the regulator-grade deployment can pick per-
request via ``TEX_NANOZK_FOLD_PROTOCOL``.

What this module exposes
------------------------
- ``MiraAccumulator`` — frozen Pydantic snapshot of the
  accumulator tree state (depth, leaf count, root commitment,
  KZG-style commitment to the accumulator polynomial).
- ``MiraTreeNode`` — a tree node carrying its left/right
  children's hashes.
- ``mira_fold_tree`` — fold a list of layer proofs in **parallel
  tree order**: pair leaves at level 0, pair results at level
  1, etc. Returns the root accumulator + an audit dict.
- ``verify_mira_tree`` — verify the root against the originals.
- ``mira_active`` — env flag check.

Composition with Thread 15
--------------------------
The Mira accumulator slots into ``LayerProofSet`` as an optional
``mira_root`` field, alongside the (already present) hash-chain
root and (optionally) the LatticeFold+ accumulator. The three
are not mutually exclusive — a regulator-grade deployment may
include all three for defense-in-depth.

Honest scope
------------
We give the **structural** tree-fold protocol — pairing-based
commitments under HMAC binding in the shim, with full tree-
balance tracking. A regulator-grade backend (the actual ZKTorch
Rust implementation, when published) drops in with the same
interface.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


# Paper §5 empirical claims, frozen as module constants so the
# audit surface (FRONTIER_DELTA, CLAIMS) can reference them.
PAPER_PROOF_SIZE_REDUCTION_MIN: float = 3.0
PAPER_PROOF_SIZE_REDUCTION_MAX: float = 10.0
PAPER_PROVING_SPEEDUP: float = 6.0
"""Headline ZKTorch §1 claim: ~6× over general-purpose ZKML."""


# --------------------------------------------------------------------------- #
# Accumulator                                                                  #
# --------------------------------------------------------------------------- #


class MiraTreeNode(BaseModel):
    """A node in the Mira fold tree.

    Each node represents the accumulator state after folding two
    children together. The tree's structure is canonical (paired
    left-to-right) so a verifier reproduces it deterministically.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    depth: int = Field(ge=0)
    """Tree depth — 0 = leaf (an individual proof);
    depth k = result of folding 2 nodes at depth k-1."""
    leaf_range: tuple[int, int]
    """(start, end) layer index covered by this node."""
    accumulator_commitment: bytes = Field(
        min_length=32, max_length=32
    )


class MiraAccumulator(BaseModel):
    """The root accumulator after a full parallel tree fold.

    Verification touches the root + the tree topology (depths,
    leaf count) — the verifier reproduces the entire tree to
    confirm.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    leaf_count: int = Field(ge=1)
    tree_depth: int = Field(ge=0)
    root_commitment: bytes = Field(min_length=32, max_length=32)
    """KZG-style commitment to the polynomial encoding of the
    final accumulator. Shim path: HMAC of the tree root."""
    backreference_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 over the ordered leaf proof bytes; binds the
    accumulator to the exact input sequence."""

    # Audit fields for the dashboards.
    parallel_levels: int = Field(ge=0)
    """How many tree levels (= log2 of leaf count, rounded up)."""


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _shim_key() -> bytes:
    return os.environ.get(
        "TEX_MIRA_SHIM_KEY",
        "tex-mira-parallel-fold-v1-default-key",
    ).encode("utf-8")


def _fold_pair(
    *,
    left_commitment: bytes,
    right_commitment: bytes,
    depth: int,
    fresh_challenge: bytes,
) -> bytes:
    """Fold two accumulators with a fresh random challenge.

    The KZG version: a Pedersen / KZG commitment to the
    polynomial that represents the folded accumulator. The shim
    HMACs (left, right, depth, challenge) — structurally one-way
    and binding.
    """
    h = hmac.new(_shim_key(), b"MIRA-FOLD-PAIR-v1|", hashlib.sha256)
    h.update(left_commitment)
    h.update(b"|")
    h.update(right_commitment)
    h.update(b"|")
    h.update(depth.to_bytes(4, "big"))
    h.update(b"|")
    h.update(fresh_challenge)
    return h.digest()


def _challenge_for_pair(
    *,
    left: bytes,
    right: bytes,
    depth: int,
) -> bytes:
    """Fiat-Shamir challenge for a fold pair.

    Per the paper §3.2, challenges are derived from the prior
    transcript bytes — standard FS. Our shim uses SHA-256.
    """
    h = hashlib.sha256()
    h.update(b"MIRA-FOLD-CHALLENGE-v1|")
    h.update(depth.to_bytes(4, "big"))
    h.update(b"|")
    h.update(left)
    h.update(b"|")
    h.update(right)
    return h.digest()


def _leaf_commitment(*, layer_index: int, proof_bytes: bytes) -> bytes:
    """Commitment to a leaf proof."""
    h = hmac.new(_shim_key(), b"MIRA-LEAF-COMMIT-v1|", hashlib.sha256)
    h.update(layer_index.to_bytes(4, "big"))
    h.update(b"|")
    h.update(proof_bytes)
    return h.digest()


# --------------------------------------------------------------------------- #
# Tree-fold protocol                                                           #
# --------------------------------------------------------------------------- #


def mira_fold_tree(
    layer_proofs: Sequence[object],
) -> tuple[MiraAccumulator, list[MiraTreeNode]]:
    """Fold an ordered sequence of layer proofs in tree order.

    Pairing is left-to-right at level 0; odd-leaf-out (when the
    leaf count is not a power of 2) is promoted unchanged to the
    next level. The tree is deterministic — a verifier rebuilds
    it from the input sequence and checks the root.

    Parameters
    ----------
    layer_proofs
        Sequence of LayerProof objects. Structural interface:
        each must expose .layer_index and .proof_bytes.

    Returns
    -------
    (root_accumulator, tree_nodes) — the root + the full tree
    (depth-ordered) for the verifier to reproduce.

    Raises
    ------
    ValueError on empty sequence.
    """
    if not layer_proofs:
        raise ValueError("cannot fold an empty layer proof sequence")

    # Backreference hash binds the accumulator to the inputs.
    bref = hashlib.sha256()
    bref.update(b"MIRA-BACKREF-v1|")
    for p in layer_proofs:
        idx = int(getattr(p, "layer_index"))
        pb = bytes(getattr(p, "proof_bytes"))
        bref.update(idx.to_bytes(4, "big"))
        bref.update(b"|")
        bref.update(pb)
        bref.update(b"|")

    # Level 0: leaf commitments.
    level: list[bytes] = []
    leaf_ranges: list[tuple[int, int]] = []
    tree_nodes: list[MiraTreeNode] = []

    for p in layer_proofs:
        idx = int(getattr(p, "layer_index"))
        pb = bytes(getattr(p, "proof_bytes"))
        c = _leaf_commitment(layer_index=idx, proof_bytes=pb)
        level.append(c)
        leaf_ranges.append((idx, idx))
        tree_nodes.append(
            MiraTreeNode(
                depth=0,
                leaf_range=(idx, idx),
                accumulator_commitment=c,
            )
        )

    depth = 0
    while len(level) > 1:
        depth += 1
        next_level: list[bytes] = []
        next_ranges: list[tuple[int, int]] = []
        i = 0
        while i < len(level):
            if i + 1 == len(level):
                # Odd one out — promote unchanged.
                next_level.append(level[i])
                next_ranges.append(leaf_ranges[i])
                # Still record a tree node at this depth so the
                # verifier sees the topology.
                tree_nodes.append(
                    MiraTreeNode(
                        depth=depth,
                        leaf_range=leaf_ranges[i],
                        accumulator_commitment=level[i],
                    )
                )
                i += 1
                continue
            left, right = level[i], level[i + 1]
            lr_range = (leaf_ranges[i][0], leaf_ranges[i + 1][1])
            ch = _challenge_for_pair(
                left=left, right=right, depth=depth
            )
            folded = _fold_pair(
                left_commitment=left,
                right_commitment=right,
                depth=depth,
                fresh_challenge=ch,
            )
            next_level.append(folded)
            next_ranges.append(lr_range)
            tree_nodes.append(
                MiraTreeNode(
                    depth=depth,
                    leaf_range=lr_range,
                    accumulator_commitment=folded,
                )
            )
            i += 2
        level = next_level
        leaf_ranges = next_ranges

    root = level[0]
    acc = MiraAccumulator(
        leaf_count=len(layer_proofs),
        tree_depth=depth,
        root_commitment=root,
        backreference_hash=bref.hexdigest(),
        parallel_levels=depth,
    )
    return acc, tree_nodes


def verify_mira_tree(
    accumulator: MiraAccumulator,
    layer_proofs: Sequence[object],
) -> bool:
    """Verify a Mira accumulator against the originals.

    Fail-closed: any inconsistency returns False.
    """
    if accumulator.leaf_count != len(layer_proofs):
        return False
    try:
        rebuilt, _nodes = mira_fold_tree(layer_proofs)
    except Exception:
        return False
    if rebuilt.backreference_hash != accumulator.backreference_hash:
        return False
    if not hmac.compare_digest(
        rebuilt.root_commitment, accumulator.root_commitment
    ):
        return False
    return rebuilt.tree_depth == accumulator.tree_depth


# --------------------------------------------------------------------------- #
# Env-flag dispatch                                                            #
# --------------------------------------------------------------------------- #


def mira_active() -> bool:
    """Opt-in env flag. Off by default; enable for thread-pool
    parallel proof aggregation."""
    if os.environ.get("TEX_NANOZK_MIRA_PARALLEL", "0") == "1":
        return True
    if os.environ.get("TEX_FRONTIER_NANOZK", "0") == "1":
        # Frontier flag implies Mira *eligibility*; only auto-
        # enable when explicitly requested.
        return os.environ.get(
            "TEX_NANOZK_MIRA_PARALLEL", "auto"
        ) == "auto_force"
    return False


__all__ = [
    "MiraAccumulator",
    "MiraTreeNode",
    "PAPER_PROOF_SIZE_REDUCTION_MAX",
    "PAPER_PROOF_SIZE_REDUCTION_MIN",
    "PAPER_PROVING_SPEEDUP",
    "mira_active",
    "mira_fold_tree",
    "verify_mira_tree",
]
