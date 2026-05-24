"""Tests for tex.nanozk.latticefold_plus."""

from __future__ import annotations

import pytest

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


class _LayerProofStub:
    """Minimal structural duck for fold_layer_proofs."""

    def __init__(self, layer_index: int, proof_bytes: bytes) -> None:
        self.layer_index = layer_index
        self.proof_bytes = proof_bytes


class TestConstants:
    def test_default_is_2026_l2(self) -> None:
        assert DEFAULT_FOLD_KIND == LatticeFoldKind.LF_PLUS_L2

    def test_lattice_dim_is_1024(self) -> None:
        assert MODULE_SIS_DIMENSION == 1024

    def test_l2_budget_is_16_bits(self) -> None:
        assert L2_NORM_BUDGET_BITS == 16

    def test_paper_speedup_is_2x(self) -> None:
        assert PAPER_PROVER_SPEEDUP_OVER_LATTICEFOLD == 2.0


class TestFoldLayerProofs:
    def test_fold_returns_accumulator(self) -> None:
        proofs = [_LayerProofStub(i, b"proof" + bytes([i])) for i in range(4)]
        acc, audit = fold_layer_proofs(proofs)
        assert isinstance(acc, LatticeFoldAccumulator)
        assert acc.instances_folded == 4
        assert audit["instances_folded"] == 4

    def test_fold_deterministic(self) -> None:
        proofs = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        a, _ = fold_layer_proofs(proofs)
        b, _ = fold_layer_proofs(
            [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        )
        assert a == b

    def test_fold_changes_with_proof_bytes(self) -> None:
        a, _ = fold_layer_proofs([_LayerProofStub(0, b"a")])
        b, _ = fold_layer_proofs([_LayerProofStub(0, b"b")])
        assert a.ajtai_commitment != b.ajtai_commitment

    def test_fold_changes_with_order(self) -> None:
        ab, _ = fold_layer_proofs(
            [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        )
        ba, _ = fold_layer_proofs(
            [_LayerProofStub(1, b"b"), _LayerProofStub(0, b"a")]
        )
        assert ab.backreference_hash != ba.backreference_hash

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            fold_layer_proofs([])

    def test_kind_none_raises(self) -> None:
        with pytest.raises(ValueError):
            fold_layer_proofs(
                [_LayerProofStub(0, b"a")], kind=LatticeFoldKind.NONE
            )

    def test_audit_reports_lattice_params(self) -> None:
        _acc, audit = fold_layer_proofs([_LayerProofStub(0, b"a")])
        assert audit["lattice_dimension"] == MODULE_SIS_DIMENSION
        assert audit["l2_budget"] == (1 << L2_NORM_BUDGET_BITS)


class TestVerifyFoldedAccumulator:
    def test_round_trip(self) -> None:
        proofs = [_LayerProofStub(i, b"p" + bytes([i])) for i in range(3)]
        acc, _ = fold_layer_proofs(proofs)
        assert verify_folded_accumulator(acc, proofs) is True

    def test_fails_on_mismatched_proofs(self) -> None:
        proofs = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        acc, _ = fold_layer_proofs(proofs)
        tampered = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"c")]
        assert verify_folded_accumulator(acc, tampered) is False

    def test_fails_on_wrong_count(self) -> None:
        proofs = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        acc, _ = fold_layer_proofs(proofs)
        assert verify_folded_accumulator(acc, proofs[:1]) is False

    def test_fails_on_kind_none(self) -> None:
        proofs = [_LayerProofStub(0, b"a")]
        acc, _ = fold_layer_proofs(proofs)
        bad = acc.model_copy(update={"kind": LatticeFoldKind.NONE})
        assert verify_folded_accumulator(bad, proofs) is False

    def test_fails_on_tampered_commitment(self) -> None:
        proofs = [_LayerProofStub(0, b"a")]
        acc, _ = fold_layer_proofs(proofs)
        bad = acc.model_copy(update={"ajtai_commitment": b"\xff" * 32})
        assert verify_folded_accumulator(bad, proofs) is False


class TestLatticeFoldActive:
    def test_default_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEX_NANOZK_LATTICEFOLD", raising=False)
        monkeypatch.delenv("TEX_FRONTIER_NANOZK", raising=False)
        assert latticefold_active() is False

    def test_env_flag_activates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_NANOZK_LATTICEFOLD", "1")
        assert latticefold_active() is True

    def test_frontier_flag_implies_active(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEX_NANOZK_LATTICEFOLD", raising=False)
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        assert latticefold_active() is True

    def test_explicit_off_overrides_frontier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        monkeypatch.setenv("TEX_NANOZK_LATTICEFOLD", "0_explicit")
        assert latticefold_active() is False
