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

Poseidon-based hash chain for layer proof set roots.

Why Poseidon instead of SHA-256
-------------------------------
The Thread 15 ``LayerProofSet.set_root`` was originally SHA-256
hash-chained. SHA-256 is a fine *external* commitment scheme, but
it has a problem when the set root needs to be opened *inside a
SNARK circuit*: SHA-256's bit-level operations cost ~30,000
constraints per block in a Plonkish circuit. Poseidon, designed
specifically for SNARK-internal use, costs ~250 constraints per
block — a **120× reduction**.

This matters for two regulator-grade composition patterns:

  1. **Recursive verification.** When a verifier wants to prove
     "I verified this layer proof set" inside *another* SNARK
     (e.g. an aggregation circuit that combines many verdicts
     into one), the set root must be openable in the outer
     circuit. With SHA-256, the outer circuit pays 30k * N
     constraints; with Poseidon, 250 * N.

  2. **SCITT registration with Merkle proofs.** SCITT's
     ``draft-ietf-cose-merkle-tree-proofs`` accommodates
     SNARK-friendly hashes. A Poseidon-rooted set is the
     SNARK-natural fit.

Parameters
----------
We use the BN254 field prime with security_level=128,
alpha=5, input_rate=3, t=4. These are the standard parameters
from the Poseidon paper for the Pairing-Friendly BN254 curve,
matching the parameters used by Plonky2, Halo2, and the major
production zkRollup deployments.

Backward-compatible default
---------------------------
The set root computation routes through ``layer_set_root`` which
checks ``TEX_NANOZK_POSEIDON_ROOT``:
  * ``"0"`` or unset → legacy SHA-256 chain (backward-compat)
  * ``"1"`` → Poseidon chain (Thread 15 frontier flag)

The flag composes with ``TEX_FRONTIER_NANOZK``; turning that on
implies Poseidon by default.

What this module exposes
------------------------
- ``poseidon_hash`` — wraps the poseidon-hash library's
  Poseidon over BN254. Takes a list of integers and returns a
  single field element (also as an integer).
- ``poseidon_hash_hex`` — convenience wrapper returning the
  64-char hex of the integer output (padded to BN254 width).
- ``poseidon_chain_root`` — given an iterable of leaves
  (each a hex-or-bytes commitment), produce the Poseidon
  hash-chain root. Sequential: chain[0] = H(leaves[0]);
  chain[i] = H(chain[i-1], leaves[i]); root = chain[-1].
- ``layer_set_root`` — the actual call site used by
  ``LayerProofSet``. Routes between Poseidon and SHA-256 based
  on the env flag. Always falls back to SHA-256 if the
  poseidon library is unavailable so CI works without the
  optional dep.
- ``HashChainKind`` — enum carried on the set so a verifier
  knows which hash to reproduce.

Performance notes
-----------------
The Python ``poseidon`` library performs roughly 1ms per hash —
fine for the per-layer set sizes we care about (≤96 layers
covers Llama-70B). The Rust regulator-grade backends will swap
in a native Poseidon hasher (Plonky2's Poseidon2 is the
~5 µs/hash reference).
"""

from __future__ import annotations

import hashlib
import os
from enum import Enum
from typing import Sequence


# --------------------------------------------------------------------------- #
# Identifier                                                                    #
# --------------------------------------------------------------------------- #


class HashChainKind(str, Enum):
    """Which hash drives the layer set's chain root."""

    SHA256_LEGACY = "sha256-legacy"
    """Pre-Thread-15 default. Bytes-oriented, SNARK-unfriendly."""

    POSEIDON_BN254 = "poseidon-bn254"
    """Thread 15 default. SNARK-natural over BN254."""


def _poseidon_active() -> bool:
    """Flag check. Returns True iff Poseidon should be used."""
    val = os.environ.get("TEX_NANOZK_POSEIDON_ROOT", "0")
    if val == "1":
        return True
    # Compose with the master Thread 15 flag.
    if os.environ.get("TEX_FRONTIER_NANOZK", "0") == "1":
        # Master flag implies Poseidon unless explicitly disabled.
        return val != "0_explicit"
    return False


# --------------------------------------------------------------------------- #
# Poseidon primitive                                                            #
# --------------------------------------------------------------------------- #


_POSEIDON_INSTANCE = None


def _get_poseidon():
    """Lazy-load a Poseidon-over-BN254 instance.

    Returns None if the poseidon library is missing — callers
    must then fall back to SHA-256.
    """
    global _POSEIDON_INSTANCE
    if _POSEIDON_INSTANCE is not None:
        return _POSEIDON_INSTANCE
    try:
        from poseidon import Poseidon, prime_254

        _POSEIDON_INSTANCE = Poseidon(
            p=prime_254,
            security_level=128,
            alpha=5,
            input_rate=3,
            t=4,
        )
        return _POSEIDON_INSTANCE
    except Exception:  # pragma: no cover — only on missing dep
        return None


# BN254 modulus and bit width.
BN254_PRIME: int = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
BN254_FIELD_BYTES: int = 32


def poseidon_hash(elements: Sequence[int]) -> int:
    """Compute Poseidon-BN254 hash of a list of field elements.

    Each element is reduced mod the BN254 prime if larger. Raises
    ``RuntimeError`` if the poseidon library is unavailable (the
    caller should have checked via ``poseidon_available`` first).
    """
    p = _get_poseidon()
    if p is None:
        raise RuntimeError(
            "poseidon library unavailable; install poseidon-hash"
        )
    reduced = [int(e) % BN254_PRIME for e in elements]
    result = p.run_hash(reduced)
    return int(result)


def poseidon_available() -> bool:
    """Cheap check for whether Poseidon is wired up."""
    return _get_poseidon() is not None


def _hex_or_bytes_to_int(value: bytes | str) -> int:
    """Coerce a hex string or bytes commitment to an int mod BN254."""
    if isinstance(value, str):
        return int(value, 16) % BN254_PRIME
    return int.from_bytes(value, "big") % BN254_PRIME


def poseidon_hash_hex(elements: Sequence[bytes | str | int]) -> str:
    """Poseidon hash returning a hex string of length 64.

    Convenience wrapper around ``poseidon_hash`` that accepts
    mixed (bytes, hex-string, int) inputs. Output is zero-padded
    to 64 hex chars so it's drop-in compatible with the SHA-256
    chain.
    """
    ints: list[int] = []
    for e in elements:
        if isinstance(e, int):
            ints.append(e % BN254_PRIME)
        else:
            ints.append(_hex_or_bytes_to_int(e))
    out = poseidon_hash(ints)
    return f"{out:064x}"


# --------------------------------------------------------------------------- #
# Chain root                                                                   #
# --------------------------------------------------------------------------- #


def poseidon_chain_root(leaves: Sequence[bytes | str]) -> str:
    """Sequential Poseidon hash chain.

    chain[0] = H(leaf_0)
    chain[i] = H(chain[i-1], leaf_i)  for i >= 1
    root     = chain[-1]

    Returns the 64-char hex of the final chain head. Raises
    ``ValueError`` on empty leaf set (no defensible root).
    """
    if not leaves:
        raise ValueError("cannot compute chain root over empty leaf set")
    chain = poseidon_hash_hex([leaves[0]])
    for leaf in leaves[1:]:
        chain = poseidon_hash_hex([chain, leaf])
    return chain


def _sha256_chain_root(leaves: Sequence[bytes | str]) -> str:
    """Legacy SHA-256 fallback, kept bit-identical to the
    pre-Thread-15 implementation."""
    if not leaves:
        raise ValueError("cannot compute chain root over empty leaf set")
    chain = b""
    for leaf in leaves:
        leaf_bytes = (
            bytes.fromhex(leaf) if isinstance(leaf, str) else leaf
        )
        h = hashlib.sha256()
        h.update(b"NANOZK-SET-CHAIN-v1|")
        h.update(chain)
        h.update(b"|")
        h.update(leaf_bytes)
        chain = h.digest()
    return chain.hex()


def layer_set_root(
    leaves: Sequence[bytes | str],
    *,
    force_kind: HashChainKind | None = None,
) -> tuple[str, HashChainKind]:
    """Compute the layer-set root, honoring the env flag.

    Parameters
    ----------
    leaves
        Per-layer commitments to chain.
    force_kind
        Override the env-based dispatch. Useful for tests.

    Returns
    -------
    (root_hex, kind) — the root and which hash was used. The
    ``LayerProofSet`` carries both so the verifier reproduces
    bit-for-bit.

    Behaviour
    ---------
    * force_kind=POSEIDON_BN254 → Poseidon (raises if missing).
    * force_kind=SHA256_LEGACY → SHA-256.
    * force_kind=None →
        - if env flag selects Poseidon and the library is
          available, use Poseidon;
        - else fall back to SHA-256 with the legacy kind.
      This fallback preserves CI on systems without the
      poseidon dep, AT the cost of a weaker (non-SNARK-friendly)
      chain. The verifier checks the kind so this can't be
      spoofed.
    """
    if force_kind is HashChainKind.POSEIDON_BN254:
        return poseidon_chain_root(leaves), HashChainKind.POSEIDON_BN254
    if force_kind is HashChainKind.SHA256_LEGACY:
        return _sha256_chain_root(leaves), HashChainKind.SHA256_LEGACY

    # Auto dispatch.
    if _poseidon_active() and poseidon_available():
        return (
            poseidon_chain_root(leaves),
            HashChainKind.POSEIDON_BN254,
        )
    return _sha256_chain_root(leaves), HashChainKind.SHA256_LEGACY


__all__ = [
    "BN254_FIELD_BYTES",
    "BN254_PRIME",
    "HashChainKind",
    "layer_set_root",
    "poseidon_available",
    "poseidon_chain_root",
    "poseidon_hash",
    "poseidon_hash_hex",
]
