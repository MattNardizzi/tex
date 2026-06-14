"""
Self-contained discrete-log Σ-protocol toolkit (Pedersen + Fiat–Shamir).

Why this module exists
----------------------
The L1 arbiter (``tex.zkpdp.arbiter``) historically had only ONE artifact it
could mint: a keyed-hash STAND-IN (HMAC over the statement) from the
``deterministic-shim-v1`` backend. An HMAC tag is symmetric — it adds **no
soundness against a holder of the dev key** and is **not hiding** (verifying it
needs the witness). That is the nanozk failure mode: a crypto-sounding name
with none of the property.

This module is the real primitive underneath the first **non-shim** L1 backend.
It is a textbook combination — nothing here is novel cryptography, and that is
deliberate: the novelty in Tex is the *statement* (the PDP decision-relation
fuse kernel, ``tex.zkprov.zk_fuse``), not the proof system. Everything here is:

  * **Pedersen commitments** ``C = g^v · h^r`` over the order-``q`` subgroup of
    ``Z_p^*`` for the RFC 3526 MODP Group 14 safe prime ``p = 2q+1`` (Pedersen,
    CRYPTO'91 — UNVERIFIED-FROM-MEMORY). Perfectly hiding (``h`` a generator,
    ``r`` uniform), computationally binding under discrete log.
  * **Fiat–Shamir** (CRYPTO'86 — UNVERIFIED-FROM-MEMORY) turning interactive
    Σ-protocols non-interactive. Every challenge binds the full public context,
    so a proof is publicly verifiable offline with **no shared secret** (the
    asymmetry the HMAC shim lacked) and **no trusted setup** (``g`` and ``h``
    are nothing-up-my-sleeve — see ``_derive_h``; no SRS ceremony, unlike
    KZG/ezkl).
  * **OR proofs** (Cramer–Damgård–Schoenmakers, CRYPTO'94 —
    UNVERIFIED-FROM-MEMORY) for "this commitment opens to 0 or 1", composed into
    **bit-decomposition range proofs**.

Performance: pure-Python 2048-bit modexp is slow, so the two fixed generators
use a precomputed fixed-base comb (``_FixedBase``) and Fiat–Shamir challenges
are 128 bits (knowledge/soundness error 2^-128) with the OR-split taken mod
2^128 so both variable-base exponentiations stay 128-bit. The comb is checked
against generic ``pow`` in the test suite, so the optimization cannot silently
corrupt a result.

Honesty boundary (read before citing):
  * Security is the 2048-bit RFC 3526 group → ~112-bit classical security.
    This is **pre-quantum**; discrete log falls to Shor. A PQ replacement
    (lattice/hash commitment) is future work and is NOT claimed here. Maturity:
    ``research-early`` — a hand-rolled, **unaudited** implementation. It is
    structurally a real ZK proof (unlike HMAC), but "audited / certified" is NOT
    claimed.
  * Integer modexp only (no float side channel), but not hardened against
    timing side channels and does not claim to be.

The group constants are re-derived and primality-checked live by
``tests/zkprov/test_schnorr_group.py`` (``sympy.isprime`` on ``p`` and ``q``)
so a transcription error in the prime fails closed instead of silently
weakening the group.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# ── Group: RFC 3526 MODP Group 14 (2048-bit safe prime p = 2q + 1) ───────────
# The most widely transcribed safe prime in deployed cryptography (IKE/IPsec,
# SSH). Fetched from rfc-editor.org/rfc/rfc3526.txt this session; primality and
# safe-primality are re-checked in the test suite, never trusted from memory.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P: int = int(_P_HEX, 16)
Q: int = (P - 1) // 2  # prime (safe prime); checked in tests

# g = 4 = 2^2 is a quadratic residue (a perfect square) and ≠ 1, so for the safe
# prime p it generates the prime-order-q subgroup of QRs (any non-identity QR
# does, since q is prime). The witness/commitment exponents live in Z_q.
G: int = 4

# 128-bit Fiat–Shamir challenge space. Soundness/knowledge error 2^-128.
CHALLENGE_BITS = 128
_CHALLENGE_MOD = 1 << CHALLENGE_BITS


def _derive_h() -> int:
    """Second generator with **unknown** discrete log to ``G`` (no trusted
    setup): hash a fixed domain string into ``Z_p`` and square it into the
    order-``q`` QR subgroup. Squaring guarantees membership; the hash origin
    guarantees nobody knows ``log_G(H)``. Retries on the (negligible) chance of
    landing on 0/1/G."""
    counter = 0
    while True:
        seed = hashlib.shake_256(
            b"tex/zkprov/schnorr-group/pedersen-h/v1\x00"
            + counter.to_bytes(4, "big")
        ).digest(2 * (P.bit_length() // 8 + 1))
        candidate = pow(int.from_bytes(seed, "big") % P, 2, P)
        if candidate not in (0, 1, G):
            return candidate
        counter += 1


H: int = _derive_h()

_BYTE_LEN = (P.bit_length() + 7) // 8


# ── Fixed-base comb (precomputed windows for the two fixed generators) ───────


class _FixedBase:
    """Windowed fixed-base exponentiation: ``base^e mod p`` in ~``ceil(bits/W)``
    multiplications instead of a full modexp. Correctness is identical to
    ``pow(base, e, p)`` (asserted in the tests); only speed differs.

    The window table (~2.4s to build for both generators) is computed lazily on
    first use, so merely importing this module — e.g. when the shim backend is
    the one in play — costs nothing."""

    __slots__ = ("_base", "_table", "_window")

    def __init__(self, base: int, window: int = 8) -> None:
        self._base = base % P
        self._window = window
        self._table: list[list[int]] | None = None

    def _build(self) -> list[list[int]]:
        digits = 1 << self._window
        rows = (Q.bit_length() + self._window) // self._window + 1
        table: list[list[int]] = []
        row_base = self._base
        for _ in range(rows):
            row = [1]
            acc = 1
            for _ in range(digits - 1):
                acc = (acc * row_base) % P
                row.append(acc)
            table.append(row)
            for _ in range(self._window):  # row_base **= 2^window
                row_base = (row_base * row_base) % P
        self._table = table
        return table

    def exp(self, e: int) -> int:
        e %= Q
        table = self._table if self._table is not None else self._build()
        window = self._window
        mask = (1 << window) - 1
        result = 1
        i = 0
        while e:
            digit = e & mask
            if digit:
                result = (result * table[i][digit]) % P
            e >>= window
            i += 1
        return result


_G_BASE = _FixedBase(G)
_H_BASE = _FixedBase(H)


def g_exp(e: int) -> int:
    return _G_BASE.exp(e)


def h_exp(e: int) -> int:
    return _H_BASE.exp(e)


# ── primitives ───────────────────────────────────────────────────────────────


def rand_scalar() -> int:
    """Uniform non-zero element of ``Z_q`` (commitment / nonce randomness)."""
    return 1 + secrets.randbelow(Q - 1)


def commit(value: int, randomness: int) -> int:
    """Pedersen commitment ``g^value · h^randomness mod p``.

    ``value`` is reduced mod ``q``; honest callers pass small non-negative
    integers. Hiding is perfect; binding holds under discrete log.
    """
    return (g_exp(value % Q) * h_exp(randomness % Q)) % P


def _i2b(x: int) -> bytes:
    return (x % P).to_bytes(_BYTE_LEN, "big")


def fs_challenge(context: bytes, label: bytes, *points: int) -> int:
    """Fiat–Shamir challenge in ``[0, 2^128)``.

    Binds the full public ``context`` (group params + statement + every
    top-level commitment) plus this sub-proof's ``label`` and first-flow
    ``points``. Because ``context`` appears in *every* challenge, the sub-proofs
    are bound together: a prover cannot swap one commitment without changing all
    downstream challenges.
    """
    hasher = hashlib.shake_256()
    hasher.update(b"tex/zkprov/schnorr-group/fs/v1\x00")
    hasher.update(len(context).to_bytes(8, "big"))
    hasher.update(context)
    hasher.update(b"\x00")
    hasher.update(label)
    hasher.update(b"\x00")
    for p in points:
        hasher.update(_i2b(p))
    return int.from_bytes(hasher.digest(CHALLENGE_BITS // 8), "big")


# ── Schnorr proof of knowledge of dlog base h ────────────────────────────────
# Used as the "equality of committed g-value" sub-proof: a commitment is in the
# subgroup <h> (i.e. its g-exponent is 0) iff the prover knows its dlog base h.


@dataclass(frozen=True, slots=True)
class DlogProof:
    a: int
    z: int

    def as_list(self) -> list[int]:
        return [self.a, self.z]

    @classmethod
    def from_list(cls, raw: list[int]) -> "DlogProof":
        return cls(a=int(raw[0]), z=int(raw[1]))


def prove_dlog_h(y: int, x: int, context: bytes, label: bytes) -> DlogProof:
    """Prove knowledge of ``x`` with ``y = h^x mod p`` (Schnorr base ``h``)."""
    k = rand_scalar()
    a = h_exp(k)
    e = fs_challenge(context, label, y, a)
    z = (k + e * x) % Q
    return DlogProof(a=a, z=z)


def verify_dlog_h(y: int, proof: DlogProof, context: bytes, label: bytes) -> bool:
    e = fs_challenge(context, label, y, proof.a)
    return h_exp(proof.z) == (proof.a * pow(y, e, P)) % P


# ── OR proof: commitment opens to 0 or 1 ─────────────────────────────────────
# Statement: C = g^b h^r with b ∈ {0,1}. Equivalent to: dlog_h(C) known (b=0)
# OR dlog_h(C·g^-1) known (b=1). CDS OR of two base-h Schnorr proofs. The split
# e0 + e1 ≡ e is taken mod 2^128 so BOTH branch challenges stay 128-bit and the
# two variable-base exponentiations y^e are cheap.


@dataclass(frozen=True, slots=True)
class BitProof:
    a0: int
    a1: int
    e0: int
    e1: int
    z0: int
    z1: int

    def as_list(self) -> list[int]:
        return [self.a0, self.a1, self.e0, self.e1, self.z0, self.z1]

    @classmethod
    def from_list(cls, raw: list[int]) -> "BitProof":
        return cls(*(int(v) for v in raw))


_G_INV = pow(G, Q - 1, P)  # g^-1 in the order-q subgroup (g^q = 1)


def _rand_challenge() -> int:
    return secrets.randbelow(_CHALLENGE_MOD)


def prove_bit(
    commitment: int, bit: int, randomness: int, context: bytes, label: bytes
) -> BitProof:
    """Prove ``commitment = g^bit · h^randomness`` with ``bit ∈ {0,1}``,
    revealing neither ``bit`` nor ``randomness``."""
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    y0 = commitment % P                 # = h^r   iff bit == 0
    y1 = (commitment * _G_INV) % P      # = h^r   iff bit == 1

    if bit == 0:
        # real branch 0 (we know r); simulate branch 1.
        k0 = rand_scalar()
        a0 = h_exp(k0)
        e1 = _rand_challenge()
        z1 = rand_scalar()
        a1 = (h_exp(z1) * pow(y1, -e1, P)) % P
        e = fs_challenge(context, label, commitment, a0, a1)
        e0 = (e - e1) % _CHALLENGE_MOD
        z0 = (k0 + e0 * randomness) % Q
    else:
        # real branch 1 (we know r); simulate branch 0.
        k1 = rand_scalar()
        a1 = h_exp(k1)
        e0 = _rand_challenge()
        z0 = rand_scalar()
        a0 = (h_exp(z0) * pow(y0, -e0, P)) % P
        e = fs_challenge(context, label, commitment, a0, a1)
        e1 = (e - e0) % _CHALLENGE_MOD
        z1 = (k1 + e1 * randomness) % Q

    return BitProof(a0=a0, a1=a1, e0=e0, e1=e1, z0=z0, z1=z1)


def verify_bit(commitment: int, proof: BitProof, context: bytes, label: bytes) -> bool:
    if not (0 <= proof.e0 < _CHALLENGE_MOD and 0 <= proof.e1 < _CHALLENGE_MOD):
        return False
    y0 = commitment % P
    y1 = (commitment * _G_INV) % P
    e = fs_challenge(context, label, commitment, proof.a0, proof.a1)
    if (proof.e0 + proof.e1) % _CHALLENGE_MOD != e:
        return False
    if h_exp(proof.z0) != (proof.a0 * pow(y0, proof.e0, P)) % P:
        return False
    if h_exp(proof.z1) != (proof.a1 * pow(y1, proof.e1, P)) % P:
        return False
    return True


# ── Range proof: a fixed commitment opens to a value in [0, 2^bits) ──────────
# General form (works for any commitment whose opening the prover knows): commit
# the bits afresh, OR-prove each, then prove (via base-h PoK) that the bit
# product Π D_j^{2^j} commits to the SAME g-value as the target commitment.


@dataclass(frozen=True, slots=True)
class RangeProof:
    bit_commitments: tuple[int, ...]
    bit_proofs: tuple[BitProof, ...]
    equality: DlogProof
    bits: int

    def as_dict(self) -> dict:
        return {
            "bits": self.bits,
            "bit_commitments": [int(c) for c in self.bit_commitments],
            "bit_proofs": [bp.as_list() for bp in self.bit_proofs],
            "equality": self.equality.as_list(),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "RangeProof":
        return cls(
            bits=int(raw["bits"]),
            bit_commitments=tuple(int(c) for c in raw["bit_commitments"]),
            bit_proofs=tuple(BitProof.from_list(b) for b in raw["bit_proofs"]),
            equality=DlogProof.from_list(raw["equality"]),
        )


def prove_range(
    value: int,
    randomness: int,
    bits: int,
    context: bytes,
    label: bytes,
) -> RangeProof:
    """Prove the commitment ``commit(value, randomness)`` opens to a value in
    ``[0, 2^bits)``. ``value`` must already be in range (else the bit
    decomposition would not reconstruct it and verification fails — the prover
    cannot mint a proof for an out-of-range value)."""
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"value {value} not in [0, 2^{bits})")
    target = commit(value, randomness)
    bit_commitments: list[int] = []
    bit_proofs: list[BitProof] = []
    rho_combined = 0
    for j in range(bits):
        b = (value >> j) & 1
        rho = rand_scalar()
        cj = commit(b, rho)
        bit_commitments.append(cj)
        bit_proofs.append(
            prove_bit(cj, b, rho, context, label + b"|bit|" + str(j).encode())
        )
        rho_combined = (rho_combined + (rho * (1 << j))) % Q
    # target / Π D_j^{2^j} = h^(randomness - Σ 2^j ρ_j): prove g-values match.
    delta_r = (randomness - rho_combined) % Q
    product = 1
    for j, cj in enumerate(bit_commitments):
        product = (product * pow(cj, 1 << j, P)) % P
    residual = (target * pow(product, Q - 1, P)) % P  # target · product^-1
    equality = prove_dlog_h(residual, delta_r, context, label + b"|eq")
    return RangeProof(
        bit_commitments=tuple(bit_commitments),
        bit_proofs=tuple(bit_proofs),
        equality=equality,
        bits=bits,
    )


def verify_range(
    target_commitment: int,
    proof: RangeProof,
    context: bytes,
    label: bytes,
) -> bool:
    """Verify ``target_commitment`` opens to a value in ``[0, 2^proof.bits)``."""
    if len(proof.bit_commitments) != proof.bits:
        return False
    if len(proof.bit_proofs) != proof.bits:
        return False
    product = 1
    for j, (cj, bp) in enumerate(zip(proof.bit_commitments, proof.bit_proofs)):
        if not verify_bit(cj, bp, context, label + b"|bit|" + str(j).encode()):
            return False
        product = (product * pow(cj, 1 << j, P)) % P
    residual = (target_commitment * pow(product, Q - 1, P)) % P
    return verify_dlog_h(residual, proof.equality, context, label + b"|eq")


__all__ = [
    "P",
    "Q",
    "G",
    "H",
    "CHALLENGE_BITS",
    "g_exp",
    "h_exp",
    "rand_scalar",
    "commit",
    "fs_challenge",
    "DlogProof",
    "prove_dlog_h",
    "verify_dlog_h",
    "BitProof",
    "prove_bit",
    "verify_bit",
    "RangeProof",
    "prove_range",
    "verify_range",
]
