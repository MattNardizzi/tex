"""Tests for ``tex.nanozk.veil_wrapper``.

Covers:
  * Wrap/unwrap round-trip
  * Tamper detection on every wrapper field
  * Documented overhead constants match the VEIL paper (eprint 2026/683)
  * Determinism when seeds are pinned
  * Unlinkability when seeds are random (two wraps of same proof differ)
"""

from __future__ import annotations

import pytest

from tex.nanozk.veil_wrapper import (
    VEIL_OVERHEAD_FACTOR,
    VEIL_PROOF_SIZE_OVERHEAD,
    VEIL_PROVER_OVERHEAD,
    VEIL_VERIFIER_OVERHEAD,
    VeilWrappedProof,
    veil_unwrap,
    veil_wrap,
)


# --------------------------------------------------------------------------- #
# Documented overhead constants                                                #
# --------------------------------------------------------------------------- #


class TestDocumentedOverhead:
    def test_prover_overhead_matches_paper(self) -> None:
        # ePrint 2026/683 §6 Table 2: 1.030 ± 0.004.
        assert VEIL_PROVER_OVERHEAD == 1.03

    def test_verifier_overhead_matches_paper(self) -> None:
        # §6 Table 3: 1.221 ± 0.012.
        assert VEIL_VERIFIER_OVERHEAD == 1.22

    def test_proof_size_overhead_matches_paper(self) -> None:
        # §6 Table 4: 1.118 ± 0.006.
        assert VEIL_PROOF_SIZE_OVERHEAD == 1.12

    def test_overhead_factor_alias(self) -> None:
        assert VEIL_OVERHEAD_FACTOR == VEIL_PROVER_OVERHEAD


# --------------------------------------------------------------------------- #
# Wrap / unwrap                                                                #
# --------------------------------------------------------------------------- #


class TestWrapUnwrap:
    def test_round_trip_recovers_inner(self) -> None:
        inner = b"the inner sumcheck proof"
        wrapped = veil_wrap(inner)
        assert veil_unwrap(wrapped) == inner

    def test_round_trip_with_empty_inner(self) -> None:
        wrapped = veil_wrap(b"")
        assert veil_unwrap(wrapped) == b""

    def test_round_trip_with_large_inner(self) -> None:
        inner = b"x" * 100_000
        wrapped = veil_wrap(inner)
        assert veil_unwrap(wrapped) == inner

    def test_returns_veilwrappedproof(self) -> None:
        wrapped = veil_wrap(b"abc")
        assert isinstance(wrapped, VeilWrappedProof)

    def test_wrapper_is_frozen(self) -> None:
        wrapped = veil_wrap(b"abc")
        with pytest.raises(Exception):
            wrapped.inner_proof = b"different"  # type: ignore[misc]

    def test_overhead_recorded_on_wrapper(self) -> None:
        wrapped = veil_wrap(b"abc")
        assert wrapped.overhead_factor == VEIL_PROVER_OVERHEAD


# --------------------------------------------------------------------------- #
# Determinism                                                                  #
# --------------------------------------------------------------------------- #


class TestDeterminism:
    def test_pinned_seeds_yield_identical_wrappers(self) -> None:
        # Pinning both blinding_key and session_id makes the wrap
        # bit-exactly deterministic — important for CI.
        k = b"a" * 32
        s = b"b" * 16
        w1 = veil_wrap(b"proof", blinding_key=k, session_id=s)
        w2 = veil_wrap(b"proof", blinding_key=k, session_id=s)
        assert w1.zk_tag == w2.zk_tag
        assert w1.blinding_commitment == w2.blinding_commitment
        assert w1.session_id == w2.session_id

    def test_random_seeds_yield_distinct_wrappers(self) -> None:
        # Without seeds, two wraps of the same inner proof must
        # differ — the unlinkability property of §3.5.
        w1 = veil_wrap(b"proof")
        w2 = veil_wrap(b"proof")
        # session_id and tag should differ; vanishingly unlikely to
        # collide.
        assert w1.session_id != w2.session_id
        assert w1.zk_tag != w2.zk_tag


# --------------------------------------------------------------------------- #
# Tamper detection                                                             #
# --------------------------------------------------------------------------- #


class TestTamperDetection:
    def test_tamper_inner_proof_rejected(self) -> None:
        wrapped = veil_wrap(b"original inner")
        bad = wrapped.model_copy(
            update={"inner_proof": b"tampered inner"}
        )
        with pytest.raises(ValueError, match="integrity"):
            veil_unwrap(bad)

    def test_tamper_zk_tag_rejected(self) -> None:
        wrapped = veil_wrap(b"original")
        bad = wrapped.model_copy(update={"zk_tag": b"x" * 32})
        with pytest.raises(ValueError, match="integrity"):
            veil_unwrap(bad)

    def test_tamper_blinding_commitment_rejected(self) -> None:
        wrapped = veil_wrap(b"original")
        bad = wrapped.model_copy(
            update={"blinding_commitment": b"y" * 32}
        )
        with pytest.raises(ValueError, match="integrity"):
            veil_unwrap(bad)

    def test_tamper_session_id_rejected(self) -> None:
        wrapped = veil_wrap(b"original")
        bad = wrapped.model_copy(update={"session_id": b"z" * 16})
        with pytest.raises(ValueError, match="integrity"):
            veil_unwrap(bad)


# --------------------------------------------------------------------------- #
# Input validation                                                             #
# --------------------------------------------------------------------------- #


class TestInputValidation:
    def test_short_blinding_key_rejected(self) -> None:
        with pytest.raises(ValueError):
            veil_wrap(b"x", blinding_key=b"too short")

    def test_long_blinding_key_rejected(self) -> None:
        with pytest.raises(ValueError):
            veil_wrap(b"x", blinding_key=b"a" * 64)

    def test_short_session_id_rejected(self) -> None:
        with pytest.raises(ValueError):
            veil_wrap(b"x", session_id=b"short")

    def test_long_session_id_rejected(self) -> None:
        with pytest.raises(ValueError):
            veil_wrap(b"x", session_id=b"a" * 32)
