"""Tenant-isolation hardening — the cross-tenant BLOCK properties.

Pins the security fixes for the V1 close-out audit's tenant-isolation findings:
a decision belongs to the tenant that created it, and a scoped key from another
tenant can neither replay nor seal it. The single-tenant / operator (default)
path is unaffected (covered by the existing integration tests).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _payload() -> dict:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": "Hi Jordan — sharing what's working for similar teams. 15-min call next week?",
        "source": "tenant_isolation_test",
    }


@pytest.fixture
def authed_client(monkeypatch):
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme,key_globex:globex")
    from tex.main import create_app

    return TestClient(create_app())


def _make_decision(client: TestClient, key: str) -> str:
    resp = client.post(
        "/v1/guardrail", json=_payload(), headers={"Authorization": f"Bearer {key}"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["decision_id"]


def test_owner_can_replay_its_own_decision(authed_client):
    decision_id = _make_decision(authed_client, "key_acme")
    resp = authed_client.get(
        f"/decisions/{decision_id}/replay",
        headers={"Authorization": "Bearer key_acme"},
    )
    assert resp.status_code == 200


def test_cross_tenant_replay_is_blocked(authed_client):
    # acme creates a decision; globex must NOT be able to replay it by id.
    decision_id = _make_decision(authed_client, "key_acme")
    resp = authed_client.get(
        f"/decisions/{decision_id}/replay",
        headers={"Authorization": "Bearer key_globex"},
    )
    assert resp.status_code == 403


def test_cross_tenant_seal_is_blocked(authed_client):
    # acme creates a decision; globex must NOT be able to seal it by id.
    decision_id = _make_decision(authed_client, "key_acme")
    resp = authed_client.post(
        f"/decisions/{decision_id}/seal",
        json={"verdict": "approved", "resolved_by": "attacker@globex.example"},
        headers={"Authorization": "Bearer key_globex"},
    )
    assert resp.status_code == 403


def test_cross_tenant_evidence_bundle_is_blocked(authed_client):
    decision_id = _make_decision(authed_client, "key_acme")
    resp = authed_client.get(
        f"/decisions/{decision_id}/evidence-bundle",
        headers={"Authorization": "Bearer key_globex"},
    )
    assert resp.status_code == 403


def test_evidence_export_requires_write_scope(authed_client):
    # Default-scoped keys (no evidence:write) cannot bulk-export the chain.
    resp = authed_client.post(
        "/evidence/export",
        json={"path": "bundle.json", "export_format": "json"},
        headers={"Authorization": "Bearer key_acme"},
    )
    assert resp.status_code == 403
