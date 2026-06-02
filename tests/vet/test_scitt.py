"""Tests for tex.vet.scitt — SCITT Signed Statements + Transparency Service + COSE Receipts."""

from __future__ import annotations

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider
from tex.vet.scitt import (
    ArpReconciliationRequest,
    ArpReconciliationResponse,
    InMemoryTransparencyService,
    SCITT_SUBJECT_AID_PREFIX,
    SCITT_SUBJECT_DECISION_PREFIX,
    VDS_RFC9162_SHA256,
    ScittIssuer,
    arp_canonicalize_claim,
    arp_project_claim,
    register_decision,
    sign_statement,
    verify_receipt,
    verify_signed_statement,
    verify_transparent_statement,
)


def _make_issuer_and_kp(
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
) -> tuple[ScittIssuer, object]:
    provider = get_signature_provider(algorithm)
    kp = provider.generate_keypair("scitt-test-iss")
    issuer = ScittIssuer(
        uri="did:tex:issuer:tenant-1",
        signing_key_id="scitt-test-iss",
        algorithm=algorithm,
    )
    return issuer, kp


class TestSignedStatement:
    """COSE_Sign1-shape Signed Statement issuance + verification."""

    def test_round_trip(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        stmt = sign_statement(
            payload={"decision_id": "d-1", "verdict": "PERMIT"},
            issuer=issuer,
            signing_keypair=kp,
            subject="tex:decision:d-1",
        )
        r = verify_signed_statement(stmt)
        assert r.valid is True
        assert r.statement_signature_valid is True
        assert r.statement_issuer == "did:tex:issuer:tenant-1"

    def test_subject_prefix_pinning(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        stmt = sign_statement(
            payload={"x": 1}, issuer=issuer, signing_keypair=kp,
            subject="tex:decision:d-1",
        )
        ok = verify_signed_statement(
            stmt, expected_subject_prefix="tex:decision"
        )
        bad = verify_signed_statement(
            stmt, expected_subject_prefix="tex:aid"
        )
        assert ok.valid is True
        assert bad.valid is False
        assert "sub" in bad.reason

    def test_issuer_pinning(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        stmt = sign_statement(
            payload={"x": 1}, issuer=issuer, signing_keypair=kp,
            subject="tex:decision:d-1",
        )
        bad = verify_signed_statement(stmt, expected_issuer="did:tex:other")
        assert bad.valid is False
        assert "iss" in bad.reason

    def test_tampered_payload_detected(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        stmt = sign_statement(
            payload={"x": 1}, issuer=issuer, signing_keypair=kp,
            subject="tex:decision:d-1",
        )
        # Tamper the payload but keep the digest unchanged
        tampered = stmt.model_copy(update={"payload_b64u": "YWFhYQ=="})  # 'aaaa'
        r = verify_signed_statement(tampered)
        assert r.valid is False
        assert "digest" in r.reason

    def test_expired_statement_rejected(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        stmt = sign_statement(
            payload={"x": 1}, issuer=issuer, signing_keypair=kp,
            subject="tex:decision:d-1",
            expires_in_seconds=1,
        )
        import time
        r = verify_signed_statement(stmt, now_epoch=int(time.time()) + 10)
        assert r.valid is False
        assert "expired" in r.reason


class TestTransparencyService:
    """SCITT TS append-only log + Merkle inclusion proofs."""

    def test_register_returns_receipt_at_tree_size_1(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        result = register_decision(
            decision_payload={"verdict": "PERMIT"},
            issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        assert result.receipt.tree_size == 1
        assert result.receipt.leaf_index == 0
        assert len(result.receipt.inclusion_path_b64u) == 0
        assert result.receipt.verifiable_data_structure == VDS_RFC9162_SHA256

    def test_growing_log_growing_paths(self) -> None:
        """Each new entry grows the tree; later refetched receipts
        for earlier entries should reflect the new tree_size."""
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        results = []
        for i in range(7):
            r = register_decision(
                decision_payload={"i": i, "verdict": "PERMIT"},
                issuer=issuer, signing_keypair=kp,
                decision_id=f"d-{i}", ts=ts,
            )
            results.append(r)

        assert len(ts) == 7
        # Refetch receipt for entry 0 — should now be at tree_size=7
        fresh = ts.get_receipt(results[0].entry_id)
        assert fresh is not None
        assert fresh.tree_size == 7
        assert fresh.leaf_index == 0
        # Path length grows with the log depth (log2 of 7 ≈ 3)
        assert len(fresh.inclusion_path_b64u) == 3

    def test_get_receipt_unknown_entry_returns_none(self) -> None:
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        assert ts.get_receipt("nonexistent-id") is None

    def test_list_entries_iterates_in_order(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        for i in range(3):
            register_decision(
                decision_payload={"i": i}, issuer=issuer, signing_keypair=kp,
                decision_id=f"d-{i}", ts=ts,
            )
        entries = list(ts.list_entries())
        assert len(entries) == 3
        subjects = [stmt.claims.sub for _, stmt in entries]
        assert subjects == [
            "tex:decision:d-0",
            "tex:decision:d-1",
            "tex:decision:d-2",
        ]


class TestReceiptVerification:
    """COSE Receipt verification (TS signature + Merkle inclusion proof)."""

    def test_valid_receipt_verifies(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        result = register_decision(
            decision_payload={"verdict": "PERMIT"},
            issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        r = verify_receipt(
            result.receipt,
            expected_statement_digest_hex=result.receipt.statement_digest_hex,
            expected_ts_uri=ts.ts_uri,
        )
        assert r.valid is True
        assert r.inclusion_proof_valid is True
        assert r.receipt_signature_valid is True

    def test_wrong_statement_digest_fails(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        result = register_decision(
            decision_payload={"verdict": "PERMIT"},
            issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        r = verify_receipt(
            result.receipt,
            expected_statement_digest_hex="0" * 64,
        )
        assert r.valid is False
        assert "digest" in r.reason

    def test_tampered_inclusion_path_fails(self) -> None:
        """Verifies that swapping a sibling-hash in the inclusion path
        breaks the proof — even with valid TS signature elsewhere."""
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        # Need at least 2 entries so the path has something to tamper
        register_decision(
            decision_payload={"i": 0}, issuer=issuer, signing_keypair=kp,
            decision_id="d-0", ts=ts,
        )
        result = register_decision(
            decision_payload={"i": 1}, issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        import base64
        bogus_sibling_b64u = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
        tampered_receipt = result.receipt.model_copy(
            update={"inclusion_path_b64u": (bogus_sibling_b64u,)}
        )
        r = verify_receipt(
            tampered_receipt,
            expected_statement_digest_hex=result.receipt.statement_digest_hex,
        )
        assert r.valid is False


class TestTransparentStatement:
    """End-to-end Transparent Statement verification."""

    def test_full_verify_passes(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        result = register_decision(
            decision_payload={"verdict": "PERMIT"},
            issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        r = verify_transparent_statement(
            result.transparent_statement,
            expected_issuer="did:tex:issuer:tenant-1",
            expected_subject_prefix="tex:decision",
        )
        assert r.valid is True
        assert r.statement_signature_valid is True
        assert r.receipt_signature_valid is True
        assert r.inclusion_proof_valid is True

    def test_mismatched_subject_prefix_fails(self) -> None:
        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        result = register_decision(
            decision_payload={"verdict": "PERMIT"},
            issuer=issuer, signing_keypair=kp,
            decision_id="d-1", ts=ts,
        )
        r = verify_transparent_statement(
            result.transparent_statement,
            expected_subject_prefix=SCITT_SUBJECT_AID_PREFIX,  # wrong
        )
        assert r.valid is False


class TestArp:
    """ARP (Attestation Reconciliation Protocol) primitives."""

    def test_canonicalize_is_deterministic(self) -> None:
        a = arp_canonicalize_claim({"y": 1, "x": [1, 2, 3]})
        b = arp_canonicalize_claim({"x": [1, 2, 3], "y": 1})
        assert a == b

    def test_project_differs_per_target(self) -> None:
        claim = {"risk_tier": "high", "region": "EU"}
        p_eu = arp_project_claim(claim, target_register="https://aiact.eu/article-50")
        p_nist = arp_project_claim(claim, target_register="https://nist.gov/ai-rmf")
        assert p_eu != p_nist
        # Per-target projections are stable
        p_eu_2 = arp_project_claim(claim, target_register="https://aiact.eu/article-50")
        assert p_eu == p_eu_2

    def test_unknown_projection_function_rejected(self) -> None:
        with pytest.raises(ValueError):
            arp_project_claim({"x": 1}, target_register="a", projection_function="zzz")


class TestScittIntegration:
    """SCITT attachment to decision payloads via tex.vet.integration."""

    def test_attach_and_verify_decision_payload(self) -> None:
        from tex.vet.integration import (
            PAYLOAD_KEY_SCITT_RECEIPT,
            PAYLOAD_KEY_SCITT_TRANSPARENT,
            attach_scitt_to_decision_payload,
            verify_payload_scitt_transparent,
        )

        issuer, kp = _make_issuer_and_kp()
        ts = InMemoryTransparencyService(algorithm=SignatureAlgorithm.ED25519)
        payload = {"decision_id": "d-1", "verdict": "PERMIT", "agent_id": "a-1"}
        new_payload, result = attach_scitt_to_decision_payload(
            payload, decision_id="d-1", issuer=issuer, signing_keypair=kp, ts=ts,
        )
        assert PAYLOAD_KEY_SCITT_RECEIPT in new_payload
        assert PAYLOAD_KEY_SCITT_TRANSPARENT in new_payload
        assert result is not None

        v = verify_payload_scitt_transparent(
            new_payload,
            expected_issuer="did:tex:issuer:tenant-1",
            expected_decision_id="d-1",
        )
        assert v.valid is True

    def test_verify_without_attached_proof_fails(self) -> None:
        from tex.vet.integration import verify_payload_scitt_transparent

        v = verify_payload_scitt_transparent({"only": "this"})
        assert v.valid is False
        assert "no SCITT" in v.reason
