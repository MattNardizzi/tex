"""
Endpoint wiring + auth posture for GET /v1/vigil.

Resolves, against the real auth middleware, the question that was open
before the code was read:

  * keyless backend  -> anonymous principal, 200 (frontend works in dev),
  * keyed backend, no key presented -> 401 (findings are not leaked),
  * keyed backend, key WITHOUT decision:read -> 403,
  * keyed backend, key WITH decision:read -> 200,
  * scoped key querying another tenant -> 403.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.main import create_app


@pytest.fixture()
def app():
    return create_app()


def test_keyless_backend_serves_vigil_anonymously(app, monkeypatch) -> None:
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
    client = TestClient(app)
    r = client.get("/v1/vigil")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["standing"] in {"Absolute", "Open"}
    assert "utterances" in body
    # The full ladder is injected at construction, so the capability field
    # now reports the highest live rung.
    assert body["meta"]["selector_version"] == "v5"


def test_keyed_backend_rejects_missing_key(app, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read+evidence:read")
    client = TestClient(app)
    r = client.get("/v1/vigil")
    assert r.status_code == 401, r.text


def test_keyed_backend_rejects_wrong_scope(app, monkeypatch) -> None:
    # Key exists but only has policy:read, not decision:read.
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:policy:read")
    client = TestClient(app)
    r = client.get("/v1/vigil", headers={"X-Tex-API-Key": "key_acme"})
    assert r.status_code == 403, r.text


def test_keyed_backend_allows_decision_read(app, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read+evidence:read")
    client = TestClient(app)
    r = client.get("/v1/vigil", headers={"Authorization": "Bearer key_acme"})
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == "acme"


def test_scoped_key_cannot_read_other_tenant(app, monkeypatch) -> None:
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:acme:decision:read")
    client = TestClient(app)
    r = client.get(
        "/v1/vigil",
        params={"tenant_id": "globex"},
        headers={"Authorization": "Bearer key_acme"},
    )
    assert r.status_code == 403, r.text
