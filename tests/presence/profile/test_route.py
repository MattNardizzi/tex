"""The confirm/correct backend route — end-to-end via a FastAPI TestClient with a
real SealedProfileMemory and a fake calibration sink + decision store.

Proves: a correction is a sealed, citable receipt; an upward correction is 422'd;
a decision-backed correction feeds calibration from the SERVER-looked-up Decision;
revoke pulls the calibration contribution (cross-substrate); a confirmation does
NOT feed the refused-only floor; the tenant comes from the request, never a body.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None  # type: ignore

from tex.api.presence_profile_routes import build_presence_profile_router
from tex.presence.profile import build_profile_memory

pytestmark = pytest.mark.skipif(TestClient is None, reason="starlette TestClient unavailable")


class _FakeFeed:
    def __init__(self) -> None:
        self.fed: list[tuple[str, str]] = []
        self.forgot: list[tuple[str, str]] = []

    def record_resolution(self, *, tenant, decision, human_verdict):
        if human_verdict == "refused" and getattr(decision, "final_score", None) is not None:
            self.fed.append((tenant, str(decision.decision_id)))
            return True
        return False

    def forget_resolution(self, *, tenant, decision_id):
        self.forgot.append((tenant, str(decision_id)))
        return True


class _FakeDecisions:
    def get(self, decision_id):
        return SimpleNamespace(decision_id=str(decision_id), final_score=0.81)


@pytest.fixture
def client_and_feed():
    app = FastAPI()
    app.include_router(build_presence_profile_router())
    app.state.presence_profile = build_profile_memory()
    feed = _FakeFeed()
    app.state.presence_calibration = feed
    app.state.decision_store = _FakeDecisions()
    return TestClient(app), feed


def test_correct_seals_and_feeds_calibration(client_and_feed):
    client, feed = client_and_feed
    r = client.post(
        "/v1/presence/profile/correct?tenant_id=acme",
        json={
            "claim_id": "agent_status:abc", "corrected_tier": "abstain",
            "operator": "ceo@acme.com", "original_tier": "sealed", "decision_id": "dec-1",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "correction"
    assert body["corrected_tier"] == "abstain"
    assert body["calibration_fed"] is True
    assert body["anchor_sha256"] and body["store"] == "presence_profile"
    assert feed.fed == [("acme", "dec-1")]


def test_upward_correction_is_422(client_and_feed):
    client, _ = client_and_feed
    r = client.post(
        "/v1/presence/profile/correct?tenant_id=acme",
        json={"claim_id": "x", "corrected_tier": "sealed", "operator": "ceo@acme.com"},
    )
    assert r.status_code == 422
    assert "upward correction" in r.json()["detail"]


def test_confirm_does_not_feed_floor(client_and_feed):
    client, feed = client_and_feed
    r = client.post(
        "/v1/presence/profile/confirm?tenant_id=acme",
        json={"claim_id": "forbid_count", "tier": "sealed", "operator": "ceo@acme.com"},
    )
    assert r.status_code == 201
    assert r.json()["calibration_fed"] is False
    assert feed.fed == []


def test_recall_and_revoke_cross_substrate(client_and_feed):
    client, feed = client_and_feed
    rec = client.post(
        "/v1/presence/profile/correct?tenant_id=acme",
        json={"claim_id": "forbid_count", "corrected_tier": "abstain",
              "operator": "ceo@acme.com", "decision_id": "dec-1"},
    ).json()["record_id"]

    # recall sees it
    assert client.get("/v1/presence/profile?tenant_id=acme").json()["count"] == 1
    # a different tenant sees nothing (isolation)
    assert client.get("/v1/presence/profile?tenant_id=globex").json()["count"] == 0

    # revoke pulls the calibration contribution too
    rv = client.delete(f"/v1/presence/profile/{rec}?tenant_id=acme").json()
    assert rv["revoked"] is True and rv["calibration_forgotten"] is True
    assert feed.forgot == [("acme", "dec-1")]
    assert client.get("/v1/presence/profile?tenant_id=acme").json()["count"] == 0


def test_503_when_profile_not_configured():
    app = FastAPI()
    app.include_router(build_presence_profile_router())
    client = TestClient(app)
    r = client.post(
        "/v1/presence/profile/correct?tenant_id=acme",
        json={"claim_id": "x", "corrected_tier": "abstain", "operator": "ceo@acme.com"},
    )
    assert r.status_code == 503
