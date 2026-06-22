"""The seal route → L1 calibration wire (presence/s9-calibration).

Drives ``POST /decisions/{id}/seal`` through the REAL app and pins the flywheel's
seal-channel fuel + its fail-closed presence-origin gate:

  * a PRESENCE-ORIGIN (``metadata["dimension"]=="presence"``) ``refused`` seal lands
    ONE per-tenant calibration label, tagged ``channel="seal"``;
  * a GOVERNANCE hold (no presence marker) ``refused`` seal records NOTHING — the gate
    is require-marker-to-feed, so governance holds never poison the presence floor;
  * ``approved``/``held`` never record a label (only a confirmed-true error feeds);
  * the label lands under the AUTHENTICATED principal's tenant, not a foreign one.

HONEST EDGE pinned by construction: no production producer stamps
``metadata["dimension"]=="presence"`` onto a ``decision_store`` Decision yet (a
presence ABSTAIN is raised only as a ``tex.provenance.feed.HeldDecision`` in the
``HeldDecisionSink`` at ``/held``, never a stored Decision the seal route can
resolve). So this channel is fail-closed INERT in production until that producer is
built. These tests construct the presence-origin Decision directly to prove the
WIRE + GATE — which is exactly the unit under test. The reader fixture is the shared
``calib_dir`` from ``conftest.py``, which routes both the seal hook's default feed
and any reader to one tmp dir via ``TEX_PRESENCE_CALIBRATION_DIR`` (path agreement).
"""

from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.main import create_app
from tex.presence.memory import (
    PresenceCalibrationFeed,
    is_presence_origin_decision,
)


def _decision(verdict: Verdict, *, presence: bool, score: float = 0.5) -> Decision:
    """A persistable Decision; ``presence`` stamps the presence-origin marker into the
    one extensible field (metadata) the gate keys on, else plain governance metadata."""
    meta = {"dimension": "presence"} if presence else {"pdp": {"pdp_version": "v3"}}
    return Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=score if verdict is not Verdict.PERMIT else 0.1,
        action_type="send_email",
        channel="email",
        environment="production",
        content_excerpt="hello",
        content_sha256="a" * 64,
        policy_version="v1",
        reasons=(["needs human"] if verdict is not Verdict.PERMIT else []),
        uncertainty_flags=(["low_conf"] if verdict is Verdict.ABSTAIN else []),
        metadata=meta,
    )


def _seal(client: TestClient, decision: Decision, *, verdict: str, headers=None):
    client.app.state.decision_store.save(decision)
    return client.post(
        f"/decisions/{decision.decision_id}/seal",
        json={"verdict": verdict, "resolved_by": "operator@example.com", "note": "r"},
        headers=headers or {},
    )


# --------------------------------------------------------------------------- #
# 1. Presence-origin refused → one label, tagged channel="seal"
# --------------------------------------------------------------------------- #


def test_presence_origin_refused_seal_lands_a_label(calib_dir):
    client = TestClient(create_app())
    held = _decision(Verdict.ABSTAIN, presence=True, score=0.73)

    resp = _seal(client, held, verdict="refused")
    assert resp.status_code == 201
    body = resp.json()
    # The seal succeeds AND surfaces that the calibration label was recorded.
    assert body["calibration_fed"] is True
    assert len(body["anchor_sha256"]) == 64  # the seal itself is intact

    # The label lands in the AUTHENTICATED tenant's (anonymous dev ⇒ "default") set,
    # at the very dir the gate's reader resolves to (path agreement via env).
    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))
    assert feed.label_count("default") == 1

    # And it carries the real score, the channel tag, and decision context.
    ledgers = list(calib_dir.glob("*.calib.jsonl"))
    assert len(ledgers) == 1
    entry = json.loads(ledgers[0].read_text().splitlines()[0])
    assert entry["final_score"] == 0.73
    assert entry["human_verdict"] == "refused"
    assert entry["channel"] == "seal"
    assert entry["decision_verdict"] == "ABSTAIN"
    assert entry["decision_confidence"] == 0.9
    assert entry["decision_id"] == str(held.decision_id)


# --------------------------------------------------------------------------- #
# 2. Governance hold refused → records NOTHING (require-marker-to-feed)
# --------------------------------------------------------------------------- #


def test_governance_refused_seal_records_nothing(calib_dir):
    client = TestClient(create_app())
    gov = _decision(Verdict.ABSTAIN, presence=False, score=0.73)

    resp = _seal(client, gov, verdict="refused")
    assert resp.status_code == 201
    assert resp.json()["calibration_fed"] is False

    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))
    assert feed.label_count("default") == 0
    # No ledger file is even created for a non-presence hold.
    assert list(calib_dir.glob("*.calib.jsonl")) == []


# --------------------------------------------------------------------------- #
# 3. approved / held never feed (only a confirmed-true error does)
# --------------------------------------------------------------------------- #


def test_presence_approved_and_held_seals_record_no_label(calib_dir):
    client = TestClient(create_app())
    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))

    approved = _decision(Verdict.ABSTAIN, presence=True)
    r1 = _seal(client, approved, verdict="approved")
    assert r1.status_code == 201
    assert r1.json()["calibration_fed"] is False

    held = _decision(Verdict.ABSTAIN, presence=True)
    r2 = _seal(client, held, verdict="held")
    assert r2.status_code == 201
    assert r2.json()["calibration_fed"] is False

    assert feed.label_count("default") == 0


# --------------------------------------------------------------------------- #
# 4. The label lands under the AUTHENTICATED tenant, never a foreign one
# --------------------------------------------------------------------------- #


def test_label_lands_under_authenticated_tenant_only(calib_dir, monkeypatch):
    # A tenant-scoped key ⇒ principal.tenant == "acme"; the calibration label must be
    # filed under "acme", never "default" or any other tenant.
    monkeypatch.setenv("TEX_API_KEYS", "k_acme:acme:decision:write+decision:read")
    client = TestClient(create_app())

    held = _decision(Verdict.ABSTAIN, presence=True)
    resp = _seal(
        client, held, verdict="refused", headers={"Authorization": "Bearer k_acme"}
    )
    assert resp.status_code == 201
    assert resp.json()["calibration_fed"] is True

    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))
    assert feed.label_count("acme") == 1
    assert feed.label_count("default") == 0
    assert feed.label_count("other") == 0


# --------------------------------------------------------------------------- #
# 5. The presence-origin predicate contract (cheap, pins the marker)
# --------------------------------------------------------------------------- #


def test_is_presence_origin_decision_contract():
    assert is_presence_origin_decision(_decision(Verdict.ABSTAIN, presence=True)) is True
    assert is_presence_origin_decision(_decision(Verdict.ABSTAIN, presence=False)) is False
    # Duck-typed on a dict; only the exact top-level marker counts.
    assert is_presence_origin_decision({"metadata": {"dimension": "presence"}}) is True
    assert is_presence_origin_decision({"metadata": {"dimension": "execution"}}) is False
    assert is_presence_origin_decision({"metadata": {"pdp": {"x": 1}}}) is False
    assert is_presence_origin_decision({"metadata": None}) is False
    assert is_presence_origin_decision({}) is False
    assert is_presence_origin_decision(None) is False
