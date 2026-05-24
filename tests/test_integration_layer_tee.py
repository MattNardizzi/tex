"""
Integration tests for Thread 12 — composite TEE attestation wired into
the live ``/v1/guardrail`` request path AND verifiable via the new
``/v1/tee/verify`` endpoint.

These tests live in tests/ at the top level (rather than in
``frontier_thread_12_tee/``) because they are the end-to-end proof
required by the Thread 12 acceptance criterion: "a single curl request
produces a verdict whose evidence record demonstrates the new
capability."

What this proves
----------------
1. When ``TEX_TEE_MODE=1`` is set, a ``/v1/guardrail`` request causes
   composite TEE attestation to be composed and embedded inside the
   evidence record's metadata, hash-chained through the existing
   SHA-256 chain.
2. The embedded ITA JWT round-trips through ``/v1/tee/verify`` with
   ``ok=True`` (test-mode) and returns the full AR4SI trustworthiness
   vector.
3. When ``TEX_TEE_MODE`` is unset, the existing request path is
   bit-identical (zero metadata pollution).
4. When ``/v1/tee/verify`` is called with a mismatched nonce, it
   returns ``ok=False, reason='nonce_mismatch'`` — fail-closed.
5. The ``/v1/tee/status`` endpoint reports capability state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient


def _payload() -> dict[str, Any]:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": (
            "Hi Jordan, saw you're hiring for revops — happy to share what's "
            "working for similar teams. Worth a 15-min call next week?"
        ),
        "source": "tee_integration_test",
    }


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def tee_evidence_path(tmp_path):
    return tmp_path / "tee_evidence.jsonl"


@pytest.fixture
def tee_mode_client(monkeypatch, tee_evidence_path):
    """A Tex app with TEX_TEE_MODE=1 and TEX_TEE_ATTESTATION_MODE=test."""
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    monkeypatch.setenv("TEX_TEE_MODE", "1")
    monkeypatch.setenv("TEX_TEE_ATTESTATION_MODE", "test")

    from tex.main import create_app

    return TestClient(create_app(evidence_path=tee_evidence_path))


@pytest.fixture
def no_tee_evidence_path(tmp_path):
    return tmp_path / "no_tee_evidence.jsonl"


@pytest.fixture
def no_tee_client(monkeypatch, no_tee_evidence_path):
    """A Tex app with TEE mode disabled — establishes the zero-cost baseline."""
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    monkeypatch.delenv("TEX_TEE_MODE", raising=False)

    from tex.main import create_app

    return TestClient(create_app(evidence_path=no_tee_evidence_path))


# --------------------------------------------------------------------------- #
# /v1/tee/status                                                              #
# --------------------------------------------------------------------------- #


class TestTeeStatusEndpoint:
    def test_status_reports_tee_mode_on(self, tee_mode_client):
        resp = tee_mode_client.get("/v1/tee/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tee_mode_enabled"] is True
        assert body["attestation_mode"] == "test"

    def test_status_reports_tee_mode_off(self, no_tee_client):
        resp = no_tee_client.get("/v1/tee/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tee_mode_enabled"] is False

    def test_status_reports_capability_booleans(self, tee_mode_client):
        resp = tee_mode_client.get("/v1/tee/status")
        body = resp.json()
        # In a CI container neither will be present.
        assert isinstance(body["tdx_capable"], bool)
        assert isinstance(body["gpu_cc_capable"], bool)


# --------------------------------------------------------------------------- #
# /v1/tee/verify                                                              #
# --------------------------------------------------------------------------- #


class TestTeeVerifyEndpoint:
    def test_verify_endpoint_accepts_dev_mode_jwt(self, tee_mode_client):
        # Build a test-mode JWT directly to verify
        from tex.tee import compose_attestation

        env = compose_attestation(decision_id="d-direct-1", request_id="r-1")
        resp = tee_mode_client.post(
            "/v1/tee/verify",
            json={"jwt": env.ita_jwt, "expected_nonce": env.nonce},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["reason"] == "ok_test_mode"
        assert body["test_mode"] is True
        assert body["cpu_tee_type"] == "intel-tdx"
        assert body["gpu_tee_type"] == "nvidia-hopper-cc"
        # Trustworthiness vector (draft-ietf-rats-ear-03)
        assert body["trustworthiness"]["configuration"] == "affirming"
        assert body["trustworthiness"]["hardware"] == "affirming"

    def test_verify_endpoint_fail_closed_on_wrong_nonce(self, tee_mode_client):
        from tex.tee import compose_attestation

        env = compose_attestation(decision_id="d-direct-2")
        resp = tee_mode_client.post(
            "/v1/tee/verify",
            json={"jwt": env.ita_jwt, "expected_nonce": "WRONG"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["reason"] == "nonce_mismatch"

    def test_verify_endpoint_pinned_eat_ai_match(self, tee_mode_client):
        from tex.tee import EatAiClaims, EatAiDigest, compose_attestation

        env = compose_attestation(
            decision_id="d-eat-1",
            eat_ai_claims=EatAiClaims(
                ai_model_id="urn:dev:texaegis.com:guardrail-fusion-v1",
                ai_model_hash=EatAiDigest(alg="SHA-384", hash_b64="aGVsbG8="),
            ),
        )
        resp = tee_mode_client.post(
            "/v1/tee/verify",
            json={
                "jwt": env.ita_jwt,
                "expected_nonce": env.nonce,
                "expected_measurements": {
                    "eat_ai_model_id": "urn:dev:texaegis.com:guardrail-fusion-v1",
                    "eat_ai_model_hash_b64": "aGVsbG8=",
                },
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert "ai_model_id" in body["eat_ai_subjects"]
        assert "ai_model_hash" in body["eat_ai_subjects"]

    def test_verify_endpoint_pinned_eat_ai_mismatch(self, tee_mode_client):
        from tex.tee import EatAiClaims, compose_attestation

        env = compose_attestation(
            decision_id="d-eat-2",
            eat_ai_claims=EatAiClaims(ai_model_id="urn:dev:correct"),
        )
        resp = tee_mode_client.post(
            "/v1/tee/verify",
            json={
                "jwt": env.ita_jwt,
                "expected_nonce": env.nonce,
                "expected_measurements": {"eat_ai_model_id": "urn:dev:wrong"},
            },
        )
        body = resp.json()
        assert body["ok"] is False
        assert body["reason"] == "eat_ai_model_id_mismatch"


# --------------------------------------------------------------------------- #
# /v1/guardrail with TEE attestation embedded in evidence                     #
# --------------------------------------------------------------------------- #


class TestGuardrailWithTeeBinding:
    """The headline integration test — composite TEE attestation rides
    on every decision evidence record when TEX_TEE_MODE=1."""

    def test_guardrail_succeeds_with_tee_mode(self, tee_mode_client):
        resp = tee_mode_client.post("/v1/guardrail", json=_payload())
        assert resp.status_code == 200
        body = resp.json()
        # The clean payload should still PERMIT (or ABSTAIN)
        assert body["verdict"] in ("PERMIT", "ABSTAIN")
        assert body.get("decision_id")

    def test_no_tee_mode_baseline_unaffected(self, no_tee_client):
        """When TEX_TEE_MODE is unset, the request path is unchanged."""
        resp = no_tee_client.post("/v1/guardrail", json=_payload())
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] in ("PERMIT", "ABSTAIN")
        assert body.get("decision_id")

    def test_tee_attestation_embedded_in_evidence_payload(
        self, tee_mode_client, tee_evidence_path
    ):
        """Evidence record carries the composite TEE attestation envelope.

        The envelope is embedded inside metadata.tee_composite_attestation
        and is cryptographically bound to the evidence record via the
        existing SHA-256 payload chain — no schema change required.
        """
        # Make a request
        resp = tee_mode_client.post("/v1/guardrail", json=_payload())
        assert resp.status_code == 200
        decision_id = resp.json()["decision_id"]

        # Read the evidence file
        assert tee_evidence_path.exists(), "evidence file should exist"
        records = [
            json.loads(line)
            for line in tee_evidence_path.read_text().splitlines()
            if line.strip()
        ]
        assert records, "evidence file should have records"

        # Find the decision record for our request
        decision_records = [
            r for r in records if r.get("record_type") == "decision"
        ]
        assert decision_records, "should have at least one decision record"

        # Find the record matching our decision_id
        matching = [
            r for r in decision_records
            if json.loads(r["payload_json"]).get("decision_id") == decision_id
        ]
        assert matching, f"no decision record matched {decision_id}"

        decision_record = matching[0]
        payload = json.loads(decision_record["payload_json"])

        # The TEE attestation lives under metadata.tee_composite_attestation
        metadata = payload.get("metadata") or {}
        tee_block = metadata.get("tee_composite_attestation")
        assert tee_block is not None, (
            "TEE composite attestation must be present in evidence metadata "
            "when TEX_TEE_MODE=1"
        )

        # Validate the structure
        assert tee_block["ita_attest_type"] == "tdx+nvgpu"
        assert tee_block["cpu_tee_type"] == "intel-tdx"
        assert tee_block["gpu_tee_type"] == "nvidia-hopper-cc"
        assert tee_block["test_mode"] is True
        assert tee_block["ita_jwt"]  # full JWT carried by default
        assert tee_block["ita_jwt_sha256"]
        assert len(tee_block["ita_jwt_sha256"]) == 64  # hex SHA-256
        assert tee_block["tdx_mrtd"]  # parsed out
        assert tee_block["gpu_overall_result"] is True

    def test_baseline_evidence_has_no_tee_block(
        self, no_tee_client, no_tee_evidence_path
    ):
        """Without TEX_TEE_MODE=1, evidence records are clean."""
        resp = no_tee_client.post("/v1/guardrail", json=_payload())
        assert resp.status_code == 200

        assert no_tee_evidence_path.exists()
        records = [
            json.loads(line)
            for line in no_tee_evidence_path.read_text().splitlines()
            if line.strip()
        ]
        decision_records = [
            r for r in records if r.get("record_type") == "decision"
        ]
        assert decision_records

        for rec in decision_records:
            payload = json.loads(rec["payload_json"])
            metadata = payload.get("metadata") or {}
            assert "tee_composite_attestation" not in metadata, (
                "tee_composite_attestation must be absent when TEX_TEE_MODE "
                "is unset"
            )


# --------------------------------------------------------------------------- #
# Round-trip: extract JWT from evidence, verify via /v1/tee/verify             #
# --------------------------------------------------------------------------- #


class TestEndToEndRoundTrip:
    """The full demo: guardrail call -> evidence carries JWT ->
    /v1/tee/verify confirms it. This is the live demo a buyer sees."""

    def test_extracted_jwt_verifies(self, tee_mode_client, tee_evidence_path):
        # Step 1: make a guardrail call.
        guardrail_resp = tee_mode_client.post("/v1/guardrail", json=_payload())
        assert guardrail_resp.status_code == 200
        decision_id = guardrail_resp.json()["decision_id"]

        # Step 2: read evidence, find this decision's TEE attestation.
        records = [
            json.loads(line)
            for line in tee_evidence_path.read_text().splitlines()
            if line.strip()
        ]
        matching = [
            r for r in records
            if r.get("record_type") == "decision"
            and json.loads(r["payload_json"]).get("decision_id") == decision_id
        ]
        assert matching
        tee_block = json.loads(matching[0]["payload_json"])["metadata"][
            "tee_composite_attestation"
        ]

        # Step 3: verify the extracted JWT via /v1/tee/verify.
        verify_resp = tee_mode_client.post(
            "/v1/tee/verify",
            json={"jwt": tee_block["ita_jwt"], "expected_nonce": tee_block["nonce"]},
        )
        assert verify_resp.status_code == 200
        verify_body = verify_resp.json()
        assert verify_body["ok"] is True
        assert verify_body["reason"] == "ok_test_mode"
        # AR4SI trustworthiness vector populated
        assert verify_body["trustworthiness"]["hardware"] == "affirming"
        assert verify_body["trustworthiness"]["configuration"] == "affirming"
