"""
Smoke tests for the public API surface.

Covers basic shape of the existing /evaluate, /health, and /decisions
routes. Detailed integration coverage lives in test_integration_layer.py.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from tex.main import create_app
    return TestClient(create_app())


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_root_metadata(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Tex"
    assert body["status"] == "ok"
    assert "active_policy_version" in body
    assert "integrations" in body


def test_evaluate_clean_action(client):
    resp = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "channel": "email",
            "environment": "production",
            "content": "Hi Jordan, following up on our chat last week.",
            "recipient": "jordan@example.com",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] in ("PERMIT", "ABSTAIN", "FORBID")
    assert "decision_id" in body


def test_evaluate_blocks_secret_leak(client):
    resp = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "channel": "email",
            "environment": "production",
            "content": "Use API key sk-proj-abc1234567890XYZ to deploy.",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] in ("ABSTAIN", "FORBID")


def test_evaluate_rejects_blank_content(client):
    resp = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "channel": "email",
            "environment": "production",
            "content": "",
        },
    )
    assert resp.status_code == 422


def test_replay_unknown_decision(client):
    resp = client.get(f"/decisions/{uuid4()}/replay")
    assert resp.status_code == 404


def test_evidence_bundle_unknown_decision(client):
    resp = client.get(f"/decisions/{uuid4()}/evidence-bundle")
    assert resp.status_code == 404
