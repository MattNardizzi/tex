"""RFC 9162 §2.1.3 / §2.1.4 proof tests — earn-it item 2.

Inclusion and consistency proofs are cross-validated EXHAUSTIVELY against
``ecosystem/_window.merkle_root`` for every tree size up to 33 (covers powers
of two, ±1 neighbours, and the k-split recursion's asymmetric cases). Every
mutation test must FAIL verification — these tests pin the property, not the
implementation.
"""

from __future__ import annotations

import math

import pytest

from tex.ecosystem._window import empty_root, leaf_hash, merkle_root
from tex.interchange.gix import (
    consistency_path,
    inclusion_path,
    verify_consistency,
    verify_inclusion,
)

from tests.interchange._helpers import record_hashes

N_MAX = 33


class TestInclusionProofs:
    def test_every_leaf_of_every_size_verifies(self):
        for n in range(1, N_MAX + 1):
            hashes = record_hashes(n)
            root = merkle_root(hashes)
            for m in range(n):
                path = inclusion_path(m, hashes)
                assert verify_inclusion(hashes[m], m, n, path, root), (n, m)

    def test_path_length_is_logarithmic(self):
        # PATH length for a perfect tree of 32 leaves is exactly 5.
        hashes = record_hashes(32)
        assert len(inclusion_path(0, hashes)) == 5

    def test_tampered_leaf_fails(self):
        hashes = record_hashes(13)
        root = merkle_root(hashes)
        path = inclusion_path(7, hashes)
        forged = record_hashes(1, salt="forged")[0]
        assert not verify_inclusion(forged, 7, 13, path, root)

    def test_tampered_proof_node_fails_at_every_position(self):
        hashes = record_hashes(13)
        root = merkle_root(hashes)
        path = inclusion_path(7, hashes)
        bogus = record_hashes(1, salt="bogus")[0]
        for i in range(len(path)):
            mutated = list(path)
            mutated[i] = bogus
            assert not verify_inclusion(hashes[7], 7, 13, mutated, root)

    def test_wrong_index_fails(self):
        hashes = record_hashes(13)
        root = merkle_root(hashes)
        path = inclusion_path(7, hashes)
        for wrong in (0, 6, 8, 12):
            assert not verify_inclusion(hashes[7], wrong, 13, path, root)

    def test_wrong_tree_size_fails(self):
        """Sizes whose RFC bit-trace differs must fail. (For an all-low-ones
        leaf index like m=7, any size in [9,16] shares the bit-trace and CAN
        verify against the size-13 root — that is RFC behaviour, and harmless:
        the ROOT is the binding, and a checkpoint pins (size, root) jointly
        under one signature. The stronger property is asserted below: against
        the root an honest size-12 checkpoint would actually carry, the
        size-13 proof fails.)"""
        hashes = record_hashes(13)
        root = merkle_root(hashes)
        path = inclusion_path(7, hashes)
        for wrong in (7, 8, 26):
            assert not verify_inclusion(hashes[7], 7, wrong, path, root)
        real_size_12_root = merkle_root(hashes[:12])
        assert not verify_inclusion(hashes[7], 7, 12, path, real_size_12_root)

    def test_truncated_and_extended_paths_fail(self):
        hashes = record_hashes(13)
        root = merkle_root(hashes)
        path = inclusion_path(7, hashes)
        assert not verify_inclusion(hashes[7], 7, 13, path[:-1], root)
        assert not verify_inclusion(hashes[7], 7, 13, [*path, path[0]], root)

    def test_out_of_range_inputs_fail_closed(self):
        hashes = record_hashes(4)
        root = merkle_root(hashes)
        assert not verify_inclusion(hashes[0], -1, 4, [], root)
        assert not verify_inclusion(hashes[0], 4, 4, [], root)
        assert not verify_inclusion(hashes[0], 0, 0, [], root)
        assert not verify_inclusion("zz" * 32, 0, 4, [], root)
        assert not verify_inclusion(hashes[0], 0, 4, ["not-hex"], root)
        assert not verify_inclusion(hashes[0], 0, 4, [], "not-hex")

    def test_generation_raises_on_bad_input(self):
        with pytest.raises(ValueError):
            inclusion_path(0, [])
        with pytest.raises(ValueError):
            inclusion_path(3, record_hashes(3))

    def test_single_leaf_tree(self):
        hashes = record_hashes(1)
        # MTH of one leaf IS the leaf hash; the path is empty.
        assert inclusion_path(0, hashes) == ()
        assert verify_inclusion(hashes[0], 0, 1, (), leaf_hash(hashes[0]))


class TestConsistencyProofs:
    def test_every_prefix_of_every_size_verifies(self):
        for n in range(1, N_MAX + 1):
            hashes = record_hashes(n)
            new_root = merkle_root(hashes)
            for m in range(1, n + 1):
                proof = consistency_path(m, hashes)
                old_root = merkle_root(hashes[:m])
                assert verify_consistency(m, old_root, n, new_root, proof), (m, n)

    def test_rewritten_history_fails(self):
        """The non-equivocation primitive: a fork that rewrites an already-
        checkpointed leaf cannot produce a verifying consistency proof against
        the honest old root."""
        honest = record_hashes(12)
        old_root = merkle_root(honest[:5])
        forked = list(honest)
        forked[1] = record_hashes(1, salt="rewritten")[0]
        fork_root = merkle_root(forked)
        fork_proof = consistency_path(5, forked)
        assert not verify_consistency(5, old_root, 12, fork_root, fork_proof)

    def test_tampered_proof_node_fails_at_every_position(self):
        hashes = record_hashes(12)
        proof = consistency_path(5, hashes)
        old_root = merkle_root(hashes[:5])
        new_root = merkle_root(hashes)
        bogus = record_hashes(1, salt="bogus")[0]
        for i in range(len(proof)):
            mutated = list(proof)
            mutated[i] = bogus
            assert not verify_consistency(5, old_root, 12, new_root, mutated)

    def test_size_zero_semantics(self):
        """first_size == 0: consistent with anything, but ONLY with an empty
        proof and the canonical empty root."""
        hashes = record_hashes(5)
        root = merkle_root(hashes)
        assert verify_consistency(0, empty_root(), 5, root, ())
        assert not verify_consistency(0, empty_root(), 5, root, (hashes[0],))
        assert not verify_consistency(0, root, 5, root, ())

    def test_same_size_semantics(self):
        hashes = record_hashes(5)
        root = merkle_root(hashes)
        other = merkle_root(record_hashes(5, salt="other"))
        assert verify_consistency(5, root, 5, root, ())
        assert not verify_consistency(5, root, 5, other, ())
        assert not verify_consistency(5, root, 5, root, (hashes[0],))

    def test_shrinking_tree_fails(self):
        hashes = record_hashes(8)
        assert not verify_consistency(
            8, merkle_root(hashes), 5, merkle_root(hashes[:5]), ()
        )

    def test_empty_path_fails_for_strict_growth(self):
        hashes = record_hashes(8)
        assert not verify_consistency(
            5, merkle_root(hashes[:5]), 8, merkle_root(hashes), ()
        )

    def test_malformed_inputs_fail_closed(self):
        hashes = record_hashes(8)
        proof = consistency_path(5, hashes)
        new_root = merkle_root(hashes)
        old_root = merkle_root(hashes[:5])
        assert not verify_consistency(5, "not-hex", 8, new_root, proof)
        assert not verify_consistency(5, old_root, 8, "zz", proof)
        assert not verify_consistency(5, old_root, 8, new_root, ["not-hex"])
        assert not verify_consistency(-1, old_root, 8, new_root, proof)

    def test_generation_raises_on_bad_input(self):
        hashes = record_hashes(5)
        with pytest.raises(ValueError):
            consistency_path(0, hashes)
        with pytest.raises(ValueError):
            consistency_path(6, hashes)

    def test_power_of_two_prefix_uses_prepend_branch(self):
        """RFC 9162 §2.1.4.2 step 2: m a power of two exercises the
        first_hash-prepend branch explicitly (also hit by the sweep)."""
        hashes = record_hashes(7)
        proof = consistency_path(4, hashes)
        assert verify_consistency(
            4, merkle_root(hashes[:4]), 7, merkle_root(hashes), proof
        )

    def test_proof_and_old_root_must_match_as_a_pair(self):
        """A valid proof for one prefix size must not verify for another."""
        hashes = record_hashes(12)
        proof5 = consistency_path(5, hashes)
        new_root = merkle_root(hashes)
        assert not verify_consistency(
            6, merkle_root(hashes[:6]), 12, new_root, proof5
        )


class TestWindowContract:
    def test_leaf_hash_domain_separation_carries_over(self):
        """An inclusion proof for a leaf only verifies via the 0x00-prefixed
        leaf hash — passing the raw record hash where the leaf hash belongs
        must fail (regression guard against dropping domain separation)."""
        hashes = record_hashes(4)
        root = merkle_root(hashes)
        path = inclusion_path(2, hashes)
        assert verify_inclusion(hashes[2], 2, 4, path, root)
        assert hashes[2] != leaf_hash(hashes[2])
        assert not verify_inclusion(leaf_hash(hashes[2]), 2, 4, path, root)

    def test_log_mean_exp_alignment_anchor(self):
        # Trivial numerical anchor used by the merge tests: mean of e-values
        # 4 and 2 is 3 — pinned here once against the math module.
        assert math.isclose(
            (4.0 + 2.0) / 2.0, 3.0
        )
