"""Tests for tex.nanozk.v3db — verifiable vector search."""

from __future__ import annotations

import pytest

from tex.nanozk.v3db import (
    PAPER_PEAK_MEMORY_REDUCTION,
    PAPER_PROVING_SPEEDUP_OVER_CIRCUIT,
    V3DBQueryProof,
    V3DBSnapshotCommitment,
    V3DB_PROTOCOL_VERSION,
    commit_snapshot,
    prove_query,
    verify_query_proof,
)


def _example_snapshot() -> V3DBSnapshotCommitment:
    return commit_snapshot(
        snapshot_id="test-2026-05-21",
        centroids=[[0.1, 0.2], [0.3, 0.4]],
        posting_lists=[[0, 1], [2]],
        payloads=[b"doc-0", b"doc-1", b"doc-2"],
        pq_codebook=[[1, 2], [3, 4], [5, 6]],
        embedding_dim=2,
    )


class TestConstants:
    def test_protocol_version_pinned(self) -> None:
        assert V3DB_PROTOCOL_VERSION == "v3db-2026-03-05"

    def test_paper_proving_speedup(self) -> None:
        assert PAPER_PROVING_SPEEDUP_OVER_CIRCUIT == 22.0

    def test_paper_memory_reduction(self) -> None:
        assert PAPER_PEAK_MEMORY_REDUCTION == 0.40


class TestCommitSnapshot:
    def test_returns_snapshot(self) -> None:
        snap = _example_snapshot()
        assert isinstance(snap, V3DBSnapshotCommitment)
        assert snap.snapshot_id == "test-2026-05-21"
        assert snap.num_centroids == 2
        assert snap.num_items == 3
        assert snap.embedding_dim == 2

    def test_snapshot_deterministic(self) -> None:
        a = _example_snapshot()
        b = _example_snapshot()
        assert a == b

    def test_snapshot_changes_with_centroids(self) -> None:
        a = _example_snapshot()
        b = commit_snapshot(
            snapshot_id="test-2026-05-21",
            centroids=[[0.5, 0.5], [0.3, 0.4]],
            posting_lists=[[0, 1], [2]],
            payloads=[b"doc-0", b"doc-1", b"doc-2"],
            pq_codebook=[[1, 2], [3, 4], [5, 6]],
            embedding_dim=2,
        )
        assert a.centroid_commitment != b.centroid_commitment

    def test_centroid_dim_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            commit_snapshot(
                snapshot_id="bad",
                centroids=[[0.1, 0.2, 0.3]],  # dim 3
                posting_lists=[[0]],
                payloads=[b"d"],
                pq_codebook=[[1]],
                embedding_dim=2,  # expected dim 2
            )


class TestProveQuery:
    def test_returns_proof(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        assert isinstance(proof, V3DBQueryProof)
        assert proof.protocol_version == V3DB_PROTOCOL_VERSION

    def test_proof_records_five_step_transcript(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0, 1],
            candidate_count=3,
            pq_distances=[0.1, 0.2, 0.3],
            topk_indices=[0, 1],
            payloads=[b"doc-0", b"doc-1"],
        )
        # Step 1: centroids
        assert proof.step1_probed_centroids == (0, 1)
        # Step 2: candidate count
        assert proof.step2_candidate_count == 3
        # Step 3: distance commitment
        assert len(proof.step3_distance_commitment) == 32
        # Step 4: topk
        assert proof.step4_topk_indices == (0, 1)
        # Step 5: payload hashes
        assert len(proof.step5_payload_hashes) == 2

    def test_proof_deterministic(self) -> None:
        snap = _example_snapshot()
        kwargs = dict(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        a = prove_query(**kwargs)
        b = prove_query(**kwargs)
        assert a == b


class TestVerifyQueryProof:
    def test_round_trip(self) -> None:
        snap = _example_snapshot()
        kwargs = dict(
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        proof = prove_query(snapshot=snap, **kwargs)
        result = verify_query_proof(
            proof,
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            pq_distances=[0.1, 0.5],
            payloads=[b"doc-0"],
        )
        assert result is True

    def test_fails_on_wrong_snapshot(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        other_snap = commit_snapshot(
            snapshot_id="other",
            centroids=[[0.9, 0.9]],
            posting_lists=[[0]],
            payloads=[b"x"],
            pq_codebook=[[9]],
            embedding_dim=2,
        )
        assert verify_query_proof(
            proof,
            snapshot=other_snap,
            query_embedding=[0.1, 0.2],
            pq_distances=[0.1, 0.5],
            payloads=[b"doc-0"],
        ) is False

    def test_fails_on_tampered_query(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        # Tamper with the query embedding.
        assert verify_query_proof(
            proof,
            snapshot=snap,
            query_embedding=[0.5, 0.5],
            pq_distances=[0.1, 0.5],
            payloads=[b"doc-0"],
        ) is False

    def test_fails_on_tampered_payloads(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        assert verify_query_proof(
            proof,
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            pq_distances=[0.1, 0.5],
            payloads=[b"WRONG-PAYLOAD"],
        ) is False

    def test_fails_on_tampered_distances(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        assert verify_query_proof(
            proof,
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            pq_distances=[0.9, 0.5],
            payloads=[b"doc-0"],
        ) is False

    def test_fails_on_wrong_protocol_version(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=2,
            pq_distances=[0.1, 0.5],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        bad = proof.model_copy(update={"protocol_version": "fake-1.0"})
        assert verify_query_proof(
            bad,
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            pq_distances=[0.1, 0.5],
            payloads=[b"doc-0"],
        ) is False


class TestSnapshotFrozen:
    def test_snapshot_frozen(self) -> None:
        snap = _example_snapshot()
        with pytest.raises(Exception):
            snap.snapshot_id = "different"  # type: ignore[misc]

    def test_proof_frozen(self) -> None:
        snap = _example_snapshot()
        proof = prove_query(
            snapshot=snap,
            query_embedding=[0.1, 0.2],
            probed_centroids=[0],
            candidate_count=1,
            pq_distances=[0.1],
            topk_indices=[0],
            payloads=[b"doc-0"],
        )
        with pytest.raises(Exception):
            proof.snapshot_commitment_hash = "x" * 64  # type: ignore[misc]
