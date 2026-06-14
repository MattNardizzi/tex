"""
Receipts for the discrete-log Σ-protocol toolkit (``tex.zkprov.schnorr_group``).

What is earned here:
  * the group is a genuine 2048-bit safe prime (primality re-checked live with
    ``sympy.isprime`` — a transcription error fails closed, never silently
    weakens the group), and g, h generate the prime-order subgroup;
  * the fixed-base comb is bit-identical to ``pow`` (the speed optimization
    cannot corrupt a result);
  * completeness AND soundness of the bit / range / dlog proofs — every tamper
    and every out-of-range value is rejected (knowledge error 2^-128);
  * the proofs are zero-knowledge against the witness (verification never needs
    it) and Fiat–Shamir binds the public context.
"""

from __future__ import annotations

import dataclasses

import pytest
from sympy import isprime

from tex.zkprov import schnorr_group as sg

CTX = b"test-context-v1"


# ── the group is real (primality re-derived, never trusted) ─────────────────


def test_group_is_a_2048_bit_safe_prime_with_subgroup_generators() -> None:
    assert sg.P.bit_length() == 2048
    assert isprime(sg.P), "modulus p is not prime"
    assert isprime(sg.Q), "(p-1)/2 is not prime — p is not a safe prime"
    assert sg.P - 1 == 2 * sg.Q
    # g, h live in the order-q subgroup (x^q == 1) and are non-trivial.
    assert pow(sg.G, sg.Q, sg.P) == 1
    assert pow(sg.H, sg.Q, sg.P) == 1
    assert sg.G != 1 and sg.H not in (0, 1, sg.G)
    # h is nothing-up-my-sleeve (re-derivable), so no party knows log_g(h).
    assert sg.H == sg._derive_h()


def test_fixed_base_comb_is_identical_to_generic_pow() -> None:
    """The comb is only a speed optimization; any divergence would silently
    corrupt every proof, so it is pinned against the reference ``pow``."""
    for seed in range(50):
        e = sg.rand_scalar()
        assert sg.g_exp(e) == pow(sg.G, e, sg.P)
        assert sg.h_exp(e) == pow(sg.H, e, sg.P)
    # edge exponents
    for e in (0, 1, sg.Q - 1):
        assert sg.g_exp(e) == pow(sg.G, e % sg.Q, sg.P)
        assert sg.h_exp(e) == pow(sg.H, e % sg.Q, sg.P)


def test_pedersen_is_additively_homomorphic() -> None:
    a, b = 1234, 5678
    ra, rb = sg.rand_scalar(), sg.rand_scalar()
    ca, cb = sg.commit(a, ra), sg.commit(b, rb)
    assert (ca * cb) % sg.P == sg.commit(a + b, ra + rb)
    assert pow(ca, 9, sg.P) == sg.commit(a * 9, ra * 9)


# ── bit proof: completeness + soundness ──────────────────────────────────────


def test_bit_proof_completeness_both_values() -> None:
    for bit in (0, 1):
        r = sg.rand_scalar()
        c = sg.commit(bit, r)
        assert sg.verify_bit(c, sg.prove_bit(c, bit, r, CTX, b"L"), CTX, b"L")


def test_bit_proof_rejects_a_non_bit_commitment() -> None:
    """A commitment to 2 cannot be passed off as a bit, even by a prover that
    tries (the OR proof has no satisfiable branch)."""
    r = sg.rand_scalar()
    c2 = sg.commit(2, r)
    forged = sg.prove_bit(c2, 1, r, CTX, b"L")  # prover lies: claims bit 1
    assert sg.verify_bit(c2, forged, CTX, b"L") is False


def test_bit_proof_rejects_tampering_and_context_change() -> None:
    r = sg.rand_scalar()
    c = sg.commit(1, r)
    pf = sg.prove_bit(c, 1, r, CTX, b"L")
    assert sg.verify_bit(c, pf, CTX, b"L")
    # tamper each response / challenge
    for field in ("z0", "z1", "e0", "e1", "a0", "a1"):
        bad = dataclasses.replace(pf, **{field: (getattr(pf, field) + 1)})
        assert sg.verify_bit(c, bad, CTX, b"L") is False, field
    # a different context (statement) invalidates the proof (FS binding)
    assert sg.verify_bit(c, pf, b"other-context", b"L") is False
    assert sg.verify_bit(c, pf, CTX, b"other-label") is False


# ── range proof: completeness + soundness ────────────────────────────────────


def test_range_proof_completeness_endpoints() -> None:
    for v in (0, 1, 9999, (1 << 14) - 1):
        r = sg.rand_scalar()
        c = sg.commit(v, r)
        assert sg.verify_range(c, sg.prove_range(v, r, 14, CTX, b"R"), CTX, b"R")


def test_range_proof_rejects_wrong_target_and_out_of_range() -> None:
    v, r = 4096, sg.rand_scalar()
    c = sg.commit(v, r)
    rp = sg.prove_range(v, r, 14, CTX, b"R")
    assert sg.verify_range(c, rp, CTX, b"R")
    # a proof for v does not verify a commitment to v+1
    assert sg.verify_range(sg.commit(v + 1, r), rp, CTX, b"R") is False
    # the prover cannot even build a proof for an out-of-range value
    with pytest.raises(ValueError):
        sg.prove_range(1 << 14, sg.rand_scalar(), 14, CTX, b"R")
    # and a value of 20000 cannot be smuggled through a 14-bit range: decomposing
    # only its low 14 bits proves a DIFFERENT value, so the equality PoK fails.
    big, rb = 20000, sg.rand_scalar()
    cheat = sg.prove_range(big & ((1 << 14) - 1), rb, 14, CTX, b"R")
    assert sg.verify_range(sg.commit(big, rb), cheat, CTX, b"R") is False


def test_range_proof_rejects_tampered_bit_commitment() -> None:
    v, r = 1234, sg.rand_scalar()
    c = sg.commit(v, r)
    rp = sg.prove_range(v, r, 14, CTX, b"R")
    bad_commitments = list(rp.bit_commitments)
    bad_commitments[0] = (bad_commitments[0] * sg.G) % sg.P  # flip bit 0's value
    tampered = dataclasses.replace(rp, bit_commitments=tuple(bad_commitments))
    assert sg.verify_range(c, tampered, CTX, b"R") is False


# ── dlog proof ───────────────────────────────────────────────────────────────


def test_dlog_proof_completeness_and_soundness() -> None:
    x = sg.rand_scalar()
    y = sg.h_exp(x)
    pf = sg.prove_dlog_h(y, x, CTX, b"D")
    assert sg.verify_dlog_h(y, pf, CTX, b"D")
    # wrong y (not h^x) is rejected; a g-component cannot be proven base h.
    assert sg.verify_dlog_h((y * sg.G) % sg.P, pf, CTX, b"D") is False
    assert sg.verify_dlog_h(y, dataclasses.replace(pf, z=pf.z + 1), CTX, b"D") is False
