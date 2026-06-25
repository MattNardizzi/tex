"""Tests for the wired /v1/govern/local-forbid-set route — the HMAC-signed feed
the in-kernel local-action PEP (pep/kernel/localpep) polls. Default-OFF and
fail-closed: inert without a secret, empty signed set without a wired source."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.governance.local_forbid_source import LocalForbidSource

SECRET = "shared-local-pep-secret"


def _client(local_source: object | None) -> TestClient:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    app.state.standing_governance = object()  # non-None precondition
    app.state.local_forbid_source = local_source
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:read"}),
    )
    return TestClient(app)


def test_inert_without_secret(monkeypatch) -> None:
    # Default-OFF: no TEX_LOCAL_PEP_SECRET configured -> inert envelope; the
    # loader rejects the empty signature and applies nothing (revoke-wins).
    monkeypatch.delenv("TEX_LOCAL_PEP_SECRET", raising=False)
    src = LocalForbidSource()
    src.add("agent-x", "/data/payroll.db", tenant="acme")
    resp = _client(src).get("/v1/govern/local-forbid-set")
    assert resp.status_code == 200
    assert resp.json() == {"set_canonical": "", "sig": "", "inert": True}


def test_signed_set_verifies_and_carries_the_forbid(monkeypatch) -> None:
    monkeypatch.setenv("TEX_LOCAL_PEP_SECRET", SECRET)
    src = LocalForbidSource()
    src.add("agent-x", "/data/payroll.db", tenant="acme")
    resp = _client(src).get("/v1/govern/local-forbid-set")
    assert resp.status_code == 200
    env = resp.json()
    assert set(env.keys()) == {"set_canonical", "sig"}
    # The loader's own verifier accepts it (HMAC binds the exact bytes).
    parsed = LocalForbidSource.verify_signed(env, secret=SECRET)
    assert parsed is not None
    assert parsed["tenant"] == "acme"
    assert {"agent_id": "agent-x", "path": "/data/payroll.db"} in parsed["forbid"]
    # A wrong secret fails closed at the enforcement point.
    assert LocalForbidSource.verify_signed(env, secret="wrong") is None
    # Tampering the signed bytes fails closed.
    tampered = dict(env, set_canonical=env["set_canonical"].replace("payroll", "salary"))
    assert LocalForbidSource.verify_signed(tampered, secret=SECRET) is None


def test_empty_signed_set_when_source_unwired(monkeypatch) -> None:
    # Secret set but no source attached -> a valid, signed, EMPTY set: the loader
    # verifies it and warms nothing. Never fail-open.
    monkeypatch.setenv("TEX_LOCAL_PEP_SECRET", SECRET)
    resp = _client(None).get("/v1/govern/local-forbid-set")
    assert resp.status_code == 200
    parsed = LocalForbidSource.verify_signed(resp.json(), secret=SECRET)
    assert parsed is not None
    assert parsed["forbid"] == []


def test_tenant_scoping(monkeypatch) -> None:
    monkeypatch.setenv("TEX_LOCAL_PEP_SECRET", SECRET)
    src = LocalForbidSource()
    src.add("agent-acme", "/data/acme.db", tenant="acme")
    src.add("agent-other", "/data/other.db", tenant="globex")
    parsed = LocalForbidSource.verify_signed(
        _client(src).get("/v1/govern/local-forbid-set").json(), secret=SECRET
    )
    paths = {e["path"] for e in parsed["forbid"]}
    assert "/data/acme.db" in paths
    assert "/data/other.db" not in paths  # tenant-scoped to the principal (acme)
