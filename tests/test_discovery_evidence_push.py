"""
Remote evidence-push ingress (``POST /v1/discovery/evidence``) + the tenant
isolation the public surface requires.

The route is the front door discovery was missing: a cooperating vantage on an
estate Tex cannot reach pushes gate-shaped / OTel-GenAI events, which land in the
SAME in-process ring the gate feeds, so a pushed span self-discovers its agent on
the next P11 sweep. These tests pin the two invariants that make a SHARED buffer
safe as a PUBLIC endpoint:

  1. tenant is server-authoritative — a client cannot push into a tenant its key
     is not scoped to, and a client-supplied per-event ``tenant`` is overwritten;
  2. the sweep scopes to its tenant — one tenant's pushed evidence never mints
     into another tenant's estate — while a legacy row with NO tenant stamp still
     mints (lenient, so the pre-tenant behavior is preserved).

Plus the end-to-end proof: push → sweep → the agent is minted into the registry.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Binds SieveEntity output-boundary methods used by run_planes' ADAPT stage.
from tex.discovery.engine import adapter  # noqa: F401
from tex.discovery.engine.pipeline import run_planes
from tex.discovery.engine.sensors.governance_stream import (
    _LIVE_DECISIONS,
    live_decisions,
    record_decision,
)
from tex.api.discovery_evidence_routes import build_discovery_evidence_router
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

_P11_FLAG = "TEX_SIEVE_P11_OTEL"


@pytest.fixture(autouse=True)
def _clean_buffer():
    """The evidence buffer is module-global; isolate it per test."""
    _LIVE_DECISIONS.clear()
    yield
    _LIVE_DECISIONS.clear()


def _anon_client() -> TestClient:
    """A bare app with only the evidence router. No keys configured → the
    principal is anonymous (dev posture): every scope granted, tenant 'default'."""
    app = FastAPI()
    app.include_router(build_discovery_evidence_router())
    return TestClient(app)


def _keyed_client(monkeypatch, key: str, tenant: str, scopes: str) -> TestClient:
    """A bare app under real auth, one API key scoped to ``tenant``/``scopes``."""
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    monkeypatch.setenv("TEX_API_KEYS", f"{key}:{tenant}:{scopes}")
    app = FastAPI()
    app.include_router(build_discovery_evidence_router())
    return TestClient(app)


def _span(agent: str, tool: str = "search") -> dict:
    """An OTel-GenAI-shaped event a collector would ship (alias vocab)."""
    return {"agent_name": agent, "otel_trace_id": f"trace-{agent}", "operation": tool}


def _ignite(registry, ledger, tenant: str):
    """Run the P11 plane exactly as ignite does: flag on, live ring-buffer
    source, tenant threaded so the sweep scopes to this estate."""
    return run_planes(
        env={_P11_FLAG: "1"},
        registry=registry,
        ledger=ledger,
        tenant_id=tenant,
    )


# ---------------------------------------------------------------------------
# The route accepts a batch and lands it in the buffer.
# ---------------------------------------------------------------------------


def test_push_accepts_batch_and_buffers_it() -> None:
    client = _anon_client()
    r = client.post(
        "/v1/discovery/evidence",
        json={"events": [_span("Scout"), _span("Ranger")]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 0
    assert body["tenant"] == "default"
    # Both landed in the shared buffer, stamped with the resolved tenant.
    rows = live_decisions()
    assert len(rows) == 2
    assert all(row["tenant"] == "default" for row in rows)


def test_push_rejects_non_dict_events_without_failing_the_batch() -> None:
    client = _anon_client()
    r = client.post(
        "/v1/discovery/evidence",
        json={"events": [_span("Scout"), "not-a-dict", 42]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 2


def test_push_truncates_beyond_cap_and_reports_it() -> None:
    from tex.api.discovery_evidence_routes import _MAX_EVENTS_PER_PUSH

    client = _anon_client()
    over = _MAX_EVENTS_PER_PUSH + 25
    r = client.post(
        "/v1/discovery/evidence",
        json={"events": [_span(f"A{i}") for i in range(over)]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == _MAX_EVENTS_PER_PUSH
    assert body["truncated"] == 25


# ---------------------------------------------------------------------------
# Tenant is server-authoritative — the isolation guarantee.
# ---------------------------------------------------------------------------


def test_client_supplied_event_tenant_is_overwritten(monkeypatch) -> None:
    """A key scoped to 'acme' cannot smuggle evidence into 'globex' by stamping
    the event — the server overwrites tenant with the principal's."""
    client = _keyed_client(monkeypatch, "k_acme", "acme", "decision:write")
    r = client.post(
        "/v1/discovery/evidence",
        headers={"Authorization": "Bearer k_acme"},
        json={"events": [{"agent_name": "Mole", "tenant": "globex"}]},
    )
    assert r.status_code == 200
    assert r.json()["tenant"] == "acme"
    rows = live_decisions()
    assert len(rows) == 1
    assert rows[0]["tenant"] == "acme"  # NOT the smuggled 'globex'


def test_push_strips_all_client_tenant_aliases(monkeypatch) -> None:
    """Defense-in-depth: a client cannot leave a stale foreign tenant in the row
    via ANY alias. Both ``tenant`` and ``tenant_id`` are stripped server-side
    before the authoritative stamp, so the buffered row carries exactly one
    tenant field — the principal's — and nothing the sweep could misread."""
    client = _keyed_client(monkeypatch, "k_acme", "acme", "decision:write")
    r = client.post(
        "/v1/discovery/evidence",
        headers={"Authorization": "Bearer k_acme"},
        json={"events": [{"agent_name": "Mole", "tenant": "x", "tenant_id": "globex"}]},
    )
    assert r.status_code == 200
    row = live_decisions()[0]
    assert row["tenant"] == "acme"
    assert "tenant_id" not in row  # no stale alias survives


def test_push_without_write_scope_is_forbidden(monkeypatch) -> None:
    client = _keyed_client(monkeypatch, "k_ro", "acme", "discovery:read")
    r = client.post(
        "/v1/discovery/evidence",
        headers={"Authorization": "Bearer k_ro"},
        json={"events": [_span("Scout")]},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# The sweep scopes to its tenant — end-to-end push → mint, with isolation.
# ---------------------------------------------------------------------------


def test_pushed_evidence_mints_the_agent_on_sweep() -> None:
    record_decision({**_span("PushedBot"), "tenant": "acme"})

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    _ignite(registry, ledger, tenant="acme")

    names = {a.name for a in registry.list_all()}
    assert "PushedBot" in names


def test_one_tenants_push_never_mints_into_anothers_estate() -> None:
    record_decision({**_span("AcmeBot"), "tenant": "acme"})
    record_decision({**_span("GlobexBot"), "tenant": "globex"})

    acme_reg = InMemoryAgentRegistry()
    _ignite(acme_reg, InMemoryDiscoveryLedger(), tenant="acme")
    acme_names = {a.name for a in acme_reg.list_all()}
    assert "AcmeBot" in acme_names
    assert "GlobexBot" not in acme_names  # isolation

    globex_reg = InMemoryAgentRegistry()
    _ignite(globex_reg, InMemoryDiscoveryLedger(), tenant="globex")
    globex_names = {a.name for a in globex_reg.list_all()}
    assert "GlobexBot" in globex_names
    assert "AcmeBot" not in globex_names  # isolation, both directions


def test_untenanted_legacy_row_still_mints_under_any_tenant() -> None:
    """Lenient scoping: a row with NO tenant stamp (a legacy/internal source
    predating attribution) stays in cohort, so the pre-tenant behavior is not
    silently dropped."""
    record_decision(_span("LegacyBot"))  # no tenant key

    registry = InMemoryAgentRegistry()
    _ignite(registry, InMemoryDiscoveryLedger(), tenant="acme")
    assert "LegacyBot" in {a.name for a in registry.list_all()}
