"""Tests for tex.vet.selective_disclosure."""

from __future__ import annotations

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.vet.selective_disclosure import (
    _merkle_root_and_proofs,
    _verify_merkle_inclusion,
    derive_presentation,
    issue_credential,
    verify_base_proof,
    verify_presentation,
)


class TestMerkleTree:
    """RFC 6962-style binary Merkle tree with odd-leaf duplication."""

    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 12, 17, 33, 100])
    def test_proofs_verify_at_arbitrary_size(self, n: int) -> None:
        hexes = [f"{i:062x}" + "00" for i in range(n)]
        root, proofs = _merkle_root_and_proofs(hexes)
        assert len(proofs) == n
        for i in range(n):
            assert _verify_merkle_inclusion(hexes[i], i, n, proofs[i], root)

    def test_tampered_leaf_fails_inclusion(self) -> None:
        hexes = [f"{i:062x}" + "00" for i in range(5)]
        root, proofs = _merkle_root_and_proofs(hexes)
        tampered = "ff" * 32
        assert not _verify_merkle_inclusion(tampered, 0, 5, proofs[0], root)

    def test_wrong_index_fails(self) -> None:
        hexes = [f"{i:062x}" + "00" for i in range(5)]
        root, proofs = _merkle_root_and_proofs(hexes)
        # Index 1 with proof for leaf 0 must fail
        assert not _verify_merkle_inclusion(hexes[1], 1, 5, proofs[0], root)


class TestCredentialRoundTrip:
    """Base proof issuance + verification + selective presentation."""

    def test_simple_credential_issues_and_verifies(self) -> None:
        subject = {"agent_id": "a-1", "tier": "high", "compliance": ["SOC2"]}
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        assert verify_base_proof(bp) is True
        assert bp.cryptosuite == "bbs-2023-shape-ed25519"

    def test_selective_presentation_reveals_only_requested(self) -> None:
        subject = {
            "agent_id": "a-1",
            "tier": "high",
            "compliance": ["SOC2"],
            "secret_quota": 999,
        }
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        pres = derive_presentation(
            bp, ["/compliance"], presentation_header=b"aud=x"
        )
        ok = verify_presentation(pres, expected_presentation_header=b"aud=x")
        assert ok is True
        revealed_names = {c.claim_name for c in pres.revealed}
        assert revealed_names == {"compliance"}

    def test_tampered_commitment_fails_verification(self) -> None:
        subject = {"agent_id": "a-1", "tier": "low"}
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        tampered = bp.model_copy(
            update={
                "commitments": (
                    bp.commitments[0].model_copy(update={"claim_value": "tampered"}),
                    *bp.commitments[1:],
                )
            }
        )
        assert verify_base_proof(tampered) is False

    def test_replay_attack_against_wrong_audience_fails(self) -> None:
        subject = {"agent_id": "a-1", "tier": "high"}
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        pres = derive_presentation(
            bp, ["/tier"], presentation_header=b"aud=alice"
        )
        # Different audience -> verification fails
        assert (
            verify_presentation(pres, expected_presentation_header=b"aud=bob") is False
        )

    def test_present_without_header_check_still_validates_proof(self) -> None:
        subject = {"agent_id": "a-1"}
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        pres = derive_presentation(bp, ["/agent_id"])
        # No expected_presentation_header -> skip the binding check
        assert verify_presentation(pres) is True

    def test_nested_claims_flatten_correctly(self) -> None:
        subject = {
            "agent_id": "a-1",
            "policy": {"version": "1.0", "tier": "high"},
        }
        bp = issue_credential(subject, algorithm=SignatureAlgorithm.ED25519)
        assert verify_base_proof(bp) is True
        # The nested fields should expand into /policy/version and /policy/tier
        pointers = {c.claim_pointer for c in bp.commitments}
        assert "/policy/version" in pointers
        assert "/policy/tier" in pointers
