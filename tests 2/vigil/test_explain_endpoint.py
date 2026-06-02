"""
Endpoint posture for POST /v1/vigil/explain.

The explainer surfaces sealed evidence detail, so it requires BOTH
decision:read and evidence:read. The response always carries the structured
facts + anchors (grounded), regardless of whether prose came from a model or
the deterministic floor.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.main import create_app


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_keyless_explain_returns_grounded(client, monkeypatch) -> None:
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    r = client.post("/v1/vigil/explain", json={"dimension": "evidence"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["grounded"] is True
    assert body["generator"] == "deterministic"  # no provider in test env
    assert body["mode"] in {"default_fallback", "failure_fallback"}
    assert "facts" in body and body["facts"]["dimension"] == "evidence"


def test_explain_requires_evidence_read_scope(client, monkeypatch) -> None:
    # Key has decision:read but NOT evidence:read.
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read")
    r = client.post(
        "/v1/vigil/explain",
        json={"dimension": "evidence"},
        headers={"Authorization": "Bearer key_acme"},
    )
    assert r.status_code == 403, r.text
    assert "evidence:read" in r.text


def test_explain_allows_both_read_scopes(client, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read+evidence:read")
    r = client.post(
        "/v1/vigil/explain",
        json={"dimension": "evidence"},
        headers={"Authorization": "Bearer key_acme"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["grounded"] is True


def test_explain_rejects_cross_tenant(client, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read+evidence:read")
    r = client.post(
        "/v1/vigil/explain",
        json={"dimension": "evidence", "tenant_id": "globex"},
        headers={"Authorization": "Bearer key_acme"},
    )
    assert r.status_code == 403, r.text


def test_explain_missing_key_is_401(client, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read+evidence:read")
    r = client.post("/v1/vigil/explain", json={"dimension": "evidence"})
    assert r.status_code == 401, r.text
