"""Tests for the smaller VET modules: PTV, AIVS-Micro, Txn-Tokens, SD-JWT VC, registry, integration."""

from __future__ import annotations

import time

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider
from tex.vet.agent_identity_document import (
    AidIssuanceRequest,
    AidStatus,
    issue,
)
from tex.vet.aivs_micro import emit_aivs_micro, verify_aivs_micro
from tex.vet.integration import (
    PAYLOAD_KEY_WEB_PROOF,
    attach_web_proof_to_payload,
    verify_payload_web_proof,
)
from tex.vet.ptv_attestation import (
    PtvAttestationMethod,
    generate_ptv_attestation,
    verify_ptv_attestation,
)
from tex.vet.registry import InMemoryAidRegistry
from tex.vet.sd_jwt_vc import (
    SdJwtClaimVisibility,
    issue_sd_card,
    issue_sd_jwt_vc,
    present_sd_jwt_vc,
    verify_sd_jwt_vc,
    verify_sd_jwt_vc_presentation,
)
from tex.vet.txn_tokens import (
    TxnTokenScope,
    issue_txn_token,
    verify_txn_token,
)
from tex.vet.web_proofs import WebProofMode, notarize_session


SAMPLE_SESSION = b"HTTP/1.1 200 OK\r\n\r\nhello"


# --------------------------------------------------------------------------- #
# PTV attestation                                                              #
# --------------------------------------------------------------------------- #


class TestPtv:
    def test_round_trip(self) -> None:
        ptv = generate_ptv_attestation(
            agent_id="a-1",
            model_measurement="sha256:m",
            software_stack_measurement="sha256:s",
            method=PtvAttestationMethod.SCHNORR_ED25519_BRIDGE,
        )
        r = verify_ptv_attestation(ptv, expected_agent_id="a-1")
        assert r.valid is True
        assert r.method is PtvAttestationMethod.SCHNORR_ED25519_BRIDGE

    def test_tampering_detected(self) -> None:
        ptv = generate_ptv_attestation(
            agent_id="a-1", model_measurement="sha256:m",
            software_stack_measurement="sha256:s",
            method=PtvAttestationMethod.SCHNORR_ED25519_BRIDGE,
        )
        # Flip a character somewhere in the signature
        idx = len(ptv) - 5
        tampered = ptv[:idx] + ("A" if ptv[idx] != "A" else "B") + ptv[idx + 1:]
        r = verify_ptv_attestation(tampered)
        assert r.valid is False

    def test_pinned_agent_id_mismatch(self) -> None:
        ptv = generate_ptv_attestation(
            agent_id="a-1", model_measurement="sha256:m",
            software_stack_measurement="sha256:s",
            method=PtvAttestationMethod.SCHNORR_ED25519_BRIDGE,
        )
        r = verify_ptv_attestation(ptv, expected_agent_id="other")
        assert r.valid is False
        assert "agent_id" in r.reason

    def test_pinned_model_hash_mismatch(self) -> None:
        ptv = generate_ptv_attestation(
            agent_id="a-1", model_measurement="sha256:m",
            software_stack_measurement="sha256:s",
            method=PtvAttestationMethod.SCHNORR_ED25519_BRIDGE,
        )
        r = verify_ptv_attestation(ptv, expected_model_hash="0" * 64)
        assert r.valid is False
        assert "model_hash" in r.reason


# --------------------------------------------------------------------------- #
# AIVS-Micro                                                                   #
# --------------------------------------------------------------------------- #


class TestAivsMicro:
    def test_round_trip(self) -> None:
        m = emit_aivs_micro(agent_id="a-1", session_root_hex="ab" * 32)
        r = verify_aivs_micro(m)
        assert r.valid is True

    def test_tamper_detection(self) -> None:
        import base64
        import json

        m = emit_aivs_micro(agent_id="a-1", session_root_hex="ab" * 32)
        decoded = base64.urlsafe_b64decode(m + "=" * (-len(m) % 4))
        record = json.loads(decoded)
        record["sr"] = "cc" * 32
        tampered = base64.urlsafe_b64encode(
            json.dumps(record).encode()
        ).rstrip(b"=").decode()
        r = verify_aivs_micro(tampered)
        assert r.valid is False


# --------------------------------------------------------------------------- #
# Txn-Tokens                                                                   #
# --------------------------------------------------------------------------- #


class TestTxnTokens:
    def test_round_trip_ed25519(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("iss")
        scope = TxnTokenScope(
            audience="https://payments.example.com",
            http_method="POST", http_path="/transfer",
            request_body_hash_hex="a" * 64,
        )
        artifact = issue_txn_token(
            iss="https://txn.texaegis.com",
            sub="did:tex:user:alice",
            act="did:tex:agent:007",
            aud="https://payments.example.com",
            scope=scope, signing_keypair=kp,
            algorithm=SignatureAlgorithm.ED25519,
        )
        r = verify_txn_token(
            artifact.token,
            expected_audience="https://payments.example.com",
            issuer_public_key=kp.public_key,
            expected_act="did:tex:agent:007",
        )
        assert r.valid is True

    def test_wrong_audience(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("iss")
        scope = TxnTokenScope(
            audience="https://payments.example.com",
            http_method="POST", http_path="/p", request_body_hash_hex="a" * 64,
        )
        artifact = issue_txn_token(
            iss="x", sub="y", act="z",
            aud="https://payments.example.com", scope=scope,
            signing_keypair=kp, algorithm=SignatureAlgorithm.ED25519,
        )
        r = verify_txn_token(
            artifact.token,
            expected_audience="https://evil.example.com",
            issuer_public_key=kp.public_key,
        )
        assert r.valid is False

    def test_expired_token_rejected(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("iss")
        scope = TxnTokenScope(
            audience="https://api.example.com",
            http_method="POST", http_path="/x", request_body_hash_hex="a" * 64,
        )
        artifact = issue_txn_token(
            iss="x", sub="y", act="z", aud="https://api.example.com", scope=scope,
            ttl_seconds=1, signing_keypair=kp, algorithm=SignatureAlgorithm.ED25519,
        )
        # Simulate clock forward by 100 seconds.
        r = verify_txn_token(
            artifact.token,
            expected_audience="https://api.example.com",
            issuer_public_key=kp.public_key,
            now_epoch=int(time.time()) + 100,
        )
        assert r.valid is False
        assert "expired" in r.reason


# --------------------------------------------------------------------------- #
# SD-JWT VC + SD-Card                                                          #
# --------------------------------------------------------------------------- #


class TestSdJwtVc:
    def test_issue_and_verify(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("issuer")
        sd = issue_sd_jwt_vc(
            issuer="did:tex:issuer",
            subject="did:tex:agent:007",
            vct="https://w3id.org/tex/v1/vet/aid",
            claims={"tier": "high", "region": "us-east-1"},
            issuer_keypair=kp,
            algorithm=SignatureAlgorithm.ED25519,
        )
        assert verify_sd_jwt_vc(sd, issuer_public_key=kp.public_key) is True

    def test_selective_presentation(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("issuer")
        sd = issue_sd_jwt_vc(
            issuer="did:tex:issuer", subject="agent",
            vct="vct:x",
            claims={"a": 1, "b": 2, "c": 3},
            issuer_keypair=kp, algorithm=SignatureAlgorithm.ED25519,
        )
        pres = present_sd_jwt_vc(
            sd, reveal_claim_names=["a"], audience="https://verifier.example.com"
        )
        ok, revealed = verify_sd_jwt_vc_presentation(
            pres,
            issuer_public_key=kp.public_key,
            expected_audience="https://verifier.example.com",
        )
        assert ok is True
        assert "a" in revealed
        assert "b" not in revealed
        assert "c" not in revealed

    def test_sd_card_issuance(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.ED25519)
        kp = provider.generate_keypair("issuer")
        card = issue_sd_card(
            issuer="did:tex:issuer",
            agent_did="did:tex:agent:007",
            agent_card_claims={"name": "my-agent", "skills": ["search", "summarize"]},
            issuer_keypair=kp, algorithm=SignatureAlgorithm.ED25519,
        )
        assert card.typ == "sd-card+sd-jwt"
        assert verify_sd_jwt_vc(
            card,
            issuer_public_key=kp.public_key,
            expected_vct="https://datatracker.ietf.org/doc/draft-nandakumar-agent-sd-jwt/#sd-card",
        ) is True


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #


class TestRegistry:
    def test_register_and_get(self) -> None:
        registry = InMemoryAidRegistry()
        aid = issue(
            request=AidIssuanceRequest(
                agent_id="a-1", issuer_did="iss",
                model_measurement="m", software_stack_measurement="s",
                algorithm=SignatureAlgorithm.ED25519,
            )
        )
        registry.register(aid)
        assert registry.get("a-1") is not None
        assert registry.get("a-1").agent_id == "a-1"

    def test_revoke_changes_status(self) -> None:
        registry = InMemoryAidRegistry()
        aid = issue(
            request=AidIssuanceRequest(
                agent_id="a-1", issuer_did="iss",
                model_measurement="m", software_stack_measurement="s",
                algorithm=SignatureAlgorithm.ED25519,
            )
        )
        registry.register(aid)
        assert registry.revoke("a-1") is True
        assert registry.get("a-1").status is AidStatus.REVOKED

    def test_list_active_excludes_revoked(self) -> None:
        registry = InMemoryAidRegistry()
        for i in range(3):
            aid = issue(
                request=AidIssuanceRequest(
                    agent_id=f"a-{i}", issuer_did="iss",
                    model_measurement="m", software_stack_measurement="s",
                    algorithm=SignatureAlgorithm.ED25519,
                )
            )
            registry.register(aid)
        registry.revoke("a-1")
        active = list(registry.list_active())
        active_ids = sorted(a.agent_id for a in active)
        assert active_ids == ["a-0", "a-2"]


# --------------------------------------------------------------------------- #
# Integration hook                                                             #
# --------------------------------------------------------------------------- #


class TestIntegration:
    def test_attach_and_verify_round_trip(self) -> None:
        proof = notarize_session(
            target_host="api.openai.com", session_log=SAMPLE_SESSION,
            response_body=b'{"x":1}', mode=WebProofMode.ZKTLS_RECLAIM,
        )
        payload = {"decision_id": "abc", "verdict": "PERMIT"}
        new_payload = attach_web_proof_to_payload(payload, web_proof=proof)
        assert PAYLOAD_KEY_WEB_PROOF in new_payload
        ok = verify_payload_web_proof(
            new_payload,
            expected_target_host="api.openai.com",
            expected_response_hash=proof.response_commitment,
            allow_stub=True,
        )
        assert ok is True

    def test_payload_without_proof_fails_verification(self) -> None:
        ok = verify_payload_web_proof(
            {"some": "payload"},
            expected_target_host="api.openai.com",
            expected_response_hash="0" * 64,
        )
        assert ok is False
