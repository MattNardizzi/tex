"""Tests for tex.nanozk.mira_parallel."""

from __future__ import annotations

import pytest

from tex.nanozk.mira_parallel import (
    MiraTreeNode,
    PAPER_PROOF_SIZE_REDUCTION_MAX,
    PAPER_PROOF_SIZE_REDUCTION_MIN,
    PAPER_PROVING_SPEEDUP,
    mira_active,
    mira_fold_tree,
    verify_mira_tree,
)


class _LayerProofStub:
    def __init__(self, layer_index: int, proof_bytes: bytes) -> None:
        self.layer_index = layer_index
        self.proof_bytes = proof_bytes


class TestConstants:
    def test_paper_reduction_bounds(self) -> None:
        assert PAPER_PROOF_SIZE_REDUCTION_MIN == 3.0
        assert PAPER_PROOF_SIZE_REDUCTION_MAX == 10.0

    def test_paper_speedup(self) -> None:
        assert PAPER_PROVING_SPEEDUP == 6.0


class TestMiraFoldTree:
    def test_fold_single_leaf(self) -> None:
        proofs = [_LayerProofStub(0, b"a")]
        acc, nodes = mira_fold_tree(proofs)
        assert acc.leaf_count == 1
        assert acc.tree_depth == 0
        assert len(nodes) == 1
        assert nodes[0].depth == 0

    def test_fold_four_leaves_balanced(self) -> None:
        proofs = [_LayerProofStub(i, b"p" + bytes([i])) for i in range(4)]
        acc, nodes = mira_fold_tree(proofs)
        assert acc.leaf_count == 4
        # 4 leaves -> 2 levels of folding -> depth 2
        assert acc.tree_depth == 2
        # 4 leaves + 2 mid + 1 root = 7 nodes
        depths = [n.depth for n in nodes]
        assert depths.count(0) == 4
        assert depths.count(1) == 2
        assert depths.count(2) == 1

    def test_fold_three_leaves_odd(self) -> None:
        proofs = [_LayerProofStub(i, b"p" + bytes([i])) for i in range(3)]
        acc, nodes = mira_fold_tree(proofs)
        # 3 leaves -> depth 2 (odd-leaf-out promoted)
        assert acc.leaf_count == 3
        assert acc.tree_depth == 2

    def test_fold_deterministic(self) -> None:
        proofs = [_LayerProofStub(i, b"p") for i in range(4)]
        a, _ = mira_fold_tree(proofs)
        b, _ = mira_fold_tree(
            [_LayerProofStub(i, b"p") for i in range(4)]
        )
        assert a == b

    def test_fold_changes_with_proof_bytes(self) -> None:
        a, _ = mira_fold_tree([_LayerProofStub(0, b"a")])
        b, _ = mira_fold_tree([_LayerProofStub(0, b"b")])
        assert a.root_commitment != b.root_commitment

    def test_fold_changes_with_order(self) -> None:
        a, _ = mira_fold_tree(
            [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        )
        b, _ = mira_fold_tree(
            [_LayerProofStub(1, b"b"), _LayerProofStub(0, b"a")]
        )
        assert a.backreference_hash != b.backreference_hash

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            mira_fold_tree([])

    def test_root_commitment_is_32_bytes(self) -> None:
        acc, _ = mira_fold_tree([_LayerProofStub(0, b"a")])
        assert len(acc.root_commitment) == 32


class TestVerifyMiraTree:
    def test_round_trip(self) -> None:
        proofs = [_LayerProofStub(i, b"p" + bytes([i])) for i in range(4)]
        acc, _ = mira_fold_tree(proofs)
        assert verify_mira_tree(acc, proofs) is True

    def test_fails_on_tampered_proof(self) -> None:
        proofs = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"b")]
        acc, _ = mira_fold_tree(proofs)
        tampered = [_LayerProofStub(0, b"a"), _LayerProofStub(1, b"c")]
        assert verify_mira_tree(acc, tampered) is False

    def test_fails_on_wrong_leaf_count(self) -> None:
        proofs = [_LayerProofStub(i, b"p") for i in range(4)]
        acc, _ = mira_fold_tree(proofs)
        assert verify_mira_tree(acc, proofs[:3]) is False

    def test_fails_on_tampered_root(self) -> None:
        proofs = [_LayerProofStub(0, b"a")]
        acc, _ = mira_fold_tree(proofs)
        bad = acc.model_copy(update={"root_commitment": b"\xff" * 32})
        assert verify_mira_tree(bad, proofs) is False

    def test_fails_on_tampered_backreference(self) -> None:
        proofs = [_LayerProofStub(0, b"a")]
        acc, _ = mira_fold_tree(proofs)
        bad = acc.model_copy(update={"backreference_hash": "f" * 64})
        assert verify_mira_tree(bad, proofs) is False


class TestTreeNode:
    def test_node_frozen(self) -> None:
        node = MiraTreeNode(
            depth=0,
            leaf_range=(0, 0),
            accumulator_commitment=b"\x00" * 32,
        )
        with pytest.raises(Exception):
            node.depth = 1  # type: ignore[misc]

    def test_node_validates_size(self) -> None:
        with pytest.raises(Exception):
            MiraTreeNode(
                depth=0,
                leaf_range=(0, 0),
                accumulator_commitment=b"\x00" * 31,
            )


class TestMiraActive:
    def test_default_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEX_NANOZK_MIRA_PARALLEL", raising=False)
        monkeypatch.delenv("TEX_FRONTIER_NANOZK", raising=False)
        assert mira_active() is False

    def test_env_flag_activates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_NANOZK_MIRA_PARALLEL", "1")
        assert mira_active() is True

    def test_frontier_alone_does_not_activate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEX_NANOZK_MIRA_PARALLEL", raising=False)
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        assert mira_active() is False

    def test_frontier_plus_auto_force(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        monkeypatch.setenv("TEX_NANOZK_MIRA_PARALLEL", "auto_force")
        assert mira_active() is True
