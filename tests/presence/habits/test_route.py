"""The L3 habit surface backend route — end-to-end via a FastAPI TestClient over a
REAL SealedPresenceMemory + the faithful L2 profile stub.

Proves: the route mounts and surfaces a real mined hypothesis (read-only); an
empty surface for a tenant with no history is honest (not an error); a confirm
re-derives the hypothesis server-side and seals ONE tightening L2 correction that
caps the subject; an unknown hypothesis_id is 404'd; per-tenant isolation holds
(the tenant is the principal's, never the body).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None  # type: ignore

from tex.api.presence_habits_routes import build_presence_habits_router
from tex.domain.verdict import Verdict
from tex.presence.contract import PresenceTier
from tex.presence.habits.hooks import build_habit_surface

from .conftest import seal_governed

pytestmark = pytest.mark.skipif(TestClient is None, reason="starlette TestClient unavailable")


def _client(mem, profile) -> TestClient:
    app = FastAPI()
    app.include_router(build_presence_habits_router())
    app.state.presence_habits = build_habit_surface(memory=mem, profile=profile)
    app.state.presence_profile = profile
    return TestClient(app)


def test_surface_confirm_and_isolation(mem, profile):
    # A clear repeated pattern → a real, statistically-supported hypothesis.
    seal_governed(mem, tenant="acme", claim_id="offshore_wire", governance_verdict=Verdict.FORBID, n=6)
    client = _client(mem, profile)

    # 1. GET surfaces the offered hypothesis with its receipts (read-only).
    r = client.get("/v1/presence/habits?tenant_id=acme")
    assert r.status_code == 200, r.text
    body = r.json()
    wire = next(h for h in body["habits"] if h["subject_key"] == "offshore_wire")
    assert wire["proposed_tier"] == "abstain"        # a habit only ever tightens
    assert wire["supporting_count"] == 6
    assert wire["phrasing"].startswith("I've noticed")
    hid = wire["hypothesis_id"]

    # 2. Honest empty: a tenant with no sealed history surfaces nothing (not an error).
    assert client.get("/v1/presence/habits?tenant_id=globex").json()["count"] == 0

    # 3. An unknown/stale hypothesis id cannot be confirmed.
    bad = client.post(
        "/v1/presence/habits/confirm?tenant_id=acme",
        json={"hypothesis_id": "hh-does-not-exist", "operator": "alice"},
    )
    assert bad.status_code == 404

    # 4. Confirm re-derives the hypothesis server-side and seals ONE L2 correction.
    ok = client.post(
        "/v1/presence/habits/confirm?tenant_id=acme",
        json={"hypothesis_id": hid, "operator": "alice"},
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["store"] == "presence_profile" and ok.json()["subject_key"] == "offshore_wire"

    # 5. The correction took effect: acme's subject is now capped to ABSTAIN,
    #    and globex (a different tenant) is untouched.
    assert profile.recall_profile(tenant="acme").tier_ceiling("offshore_wire") is PresenceTier.ABSTAIN
    assert profile.recall_profile(tenant="globex").tier_ceiling("offshore_wire") is None


def test_decline_writes_nothing(mem, profile):
    seal_governed(mem, tenant="acme", claim_id="offshore_wire", governance_verdict=Verdict.FORBID, n=6)
    client = _client(mem, profile)
    hid = client.get("/v1/presence/habits?tenant_id=acme").json()["habits"][0]["hypothesis_id"]

    r = client.post(
        "/v1/presence/habits/decline?tenant_id=acme",
        json={"hypothesis_id": hid, "operator": "alice"},
    )
    assert r.status_code == 200 and r.json()["written"] is False
    # nothing was written: the subject is still uncapped.
    assert profile.recall_profile(tenant="acme").tier_ceiling("offshore_wire") is None
