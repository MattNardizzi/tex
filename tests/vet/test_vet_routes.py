"""Integration tests for /v1/vet/* routes via TestClient."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    from tex.main import create_app

    return TestClient(create_app())


class TestAidRoutes:
    def test_issue_get_present_verify_round_trip(self, client: TestClient) -> None:
        # Issue
        r = client.post(
            "/v1/vet/issue-aid",
            json={
                "agent_id": "rt-agent-1",
                "issuer_did": "did:tex:issuer:tenant-1",
                "model_measurement": "sha256:gpt-4o",
                "software_stack_measurement": "sha256:tex-1.0",
                "supported_proof_systems": ["tee-tdx", "zktls-reclaim"],
                "compliance_assertions": ["SOC2", "HIPAA"],
                "algorithm": "ed25519",
                "include_aivs_micro": True,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["aid"]["agent_id"] == "rt-agent-1"
        assert data["vc_2_0"]["proof"]["type"] == "DataIntegrityProof"

        # GET
        r2 = client.get("/v1/vet/aid/rt-agent-1")
        assert r2.status_code == 200

        # Present (selective disclosure)
        r3 = client.post(
            "/v1/vet/present-aid?agent_id=rt-agent-1",
            json={
                "reveal": ["compliance_assertions"],
                "audience": "https://verifier.example.com",
                "nonce": "n-1",
            },
        )
        assert r3.status_code == 200
        envelope = r3.json()["envelope"]

        # Verify
        r4 = client.post(
            "/v1/vet/verify-presentation",
            json={
                "envelope": envelope,
                "expected_audience": "https://verifier.example.com",
                "expected_nonce": "n-1",
                "expected_agent_id": "rt-agent-1",
            },
        )
        assert r4.status_code == 200
        result = r4.json()["result"]
        assert result["valid"] is True
        assert "compliance_assertions" in result["revealed_claims"]
        assert "model_measurement" not in result["revealed_claims"]

    def test_present_unknown_agent_returns_404(self, client: TestClient) -> None:
        r = client.post(
            "/v1/vet/present-aid?agent_id=does-not-exist",
            json={
                "reveal": ["compliance_assertions"],
                "audience": "https://x.example.com",
            },
        )
        assert r.status_code == 404

    def test_replay_attack_against_wrong_audience(self, client: TestClient) -> None:
        client.post(
            "/v1/vet/issue-aid",
            json={
                "agent_id": "replay-test",
                "issuer_did": "did:tex:issuer:t",
                "model_measurement": "m",
                "software_stack_measurement": "s",
                "algorithm": "ed25519",
            },
        )
        r = client.post(
            "/v1/vet/present-aid?agent_id=replay-test",
            json={
                "reveal": ["compliance_assertions"],
                "audience": "https://legit.example.com",
            },
        )
        envelope = r.json()["envelope"]
        r2 = client.post(
            "/v1/vet/verify-presentation",
            json={
                "envelope": envelope,
                "expected_audience": "https://evil.example.com",
            },
        )
        assert r2.status_code == 200
        assert r2.json()["result"]["valid"] is False


class TestWebProofRoutes:
    def test_notarize_and_verify(self, client: TestClient) -> None:
        body_b64u = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
        r = client.post(
            "/v1/vet/notarize",
            json={
                "target_host": "api.openai.com",
                "response_body_b64u": body_b64u,
                "session_log_b64u": body_b64u,
                "mode": "zktls-reclaim",
            },
        )
        assert r.status_code == 200
        proof = r.json()["proof"]
        assert r.json()["is_stub"] is True  # no live attestor in test

        # Verify rejects stub by default
        r2 = client.post(
            "/v1/vet/verify-web-proof",
            json={
                "proof": proof,
                "expected_target_host": "api.openai.com",
                "expected_response_hash_hex": proof["response_commitment"],
            },
        )
        assert r2.status_code == 200
        assert r2.json()["valid"] is False  # default allow_stub=False

        # Verify accepts stub when allow_stub=True
        r3 = client.post(
            "/v1/vet/verify-web-proof",
            json={
                "proof": proof,
                "expected_target_host": "api.openai.com",
                "expected_response_hash_hex": proof["response_commitment"],
                "allow_stub": True,
            },
        )
        assert r3.status_code == 200
        assert r3.json()["valid"] is True

    def test_wrong_host_fails(self, client: TestClient) -> None:
        body_b64u = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
        r = client.post(
            "/v1/vet/notarize",
            json={
                "target_host": "api.openai.com",
                "response_body_b64u": body_b64u,
                "session_log_b64u": body_b64u,
                "mode": "zktls-reclaim",
            },
        )
        proof = r.json()["proof"]
        r2 = client.post(
            "/v1/vet/verify-web-proof",
            json={
                "proof": proof,
                "expected_target_host": "api.anthropic.com",
                "expected_response_hash_hex": proof["response_commitment"],
                "allow_stub": True,
            },
        )
        assert r2.json()["valid"] is False


class TestTxnTokenRoutes:
    def test_issue_and_verify(self, client: TestClient) -> None:
        r = client.post(
            "/v1/vet/issue-txn-token",
            json={
                "iss": "https://txn.texaegis.com",
                "sub": "did:tex:user:alice",
                "act": "did:tex:agent:007",
                "aud": "https://payments.example.com",
                "scope": {
                    "audience": "https://payments.example.com",
                    "http_method": "POST",
                    "http_path": "/v1/transfer",
                    "request_body_hash_hex": "a" * 64,
                },
                "ttl_seconds": 60,
                "algorithm": "ed25519",
            },
        )
        assert r.status_code == 200
        data = r.json()
        token = data["artifact"]["token"]
        issuer_pub = data["issuer_public_key_b64u"]

        r2 = client.post(
            "/v1/vet/verify-txn-token",
            json={
                "token": token,
                "expected_audience": "https://payments.example.com",
                "issuer_public_key_b64u": issuer_pub,
                "expected_act": "did:tex:agent:007",
            },
        )
        assert r2.status_code == 200
        assert r2.json()["result"]["valid"] is True
