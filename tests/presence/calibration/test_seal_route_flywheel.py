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
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.main import create_app
from tex.presence.contract import ClaimKind, PresenceClaim
from tex.presence.gate import PresenceTelemetry, PresenceTruthGate, run_presence
from tex.presence.memory import (
    PresenceCalibrationFeed,
    is_presence_origin_decision,
)
from tex.provenance.feed import HeldDecisionSink


class _AbstainBrain:
    """A brain that proposes a claim the gate cannot ground → an answer-level
    presence ABSTAIN, which is what triggers the producer."""

    def propose(self, *, question, tenant, facts, tools):
        return "nonsense", (PresenceClaim("meaning_of_life", "42", ClaimKind.AGGREGATE),)


def _decision(
    verdict: Verdict, *, presence: bool, score: float = 0.5, tenant: str | None = None
) -> Decision:
    """A persistable Decision; ``presence`` stamps the presence-origin marker into the
    one extensible field (metadata) the gate keys on, else plain governance metadata.

    ``tenant`` stamps ``metadata["tenant_id"]`` so the decision belongs to a specific
    tenant — required now that the seal route is tenant-scoped (a scoped key may only
    seal its own tenant's decision), mirroring the real flow where a tenant's presence
    hold is stamped with that tenant.

    A presence-origin Decision must ALSO affirm ``presence_calibration_eligible=True``
    to feed the conformal floor — the fail-closed marker that says "my final_score IS a
    real confirmed decisive-step score" (the producer in presence/gate/compose.py mints
    answer-level abstains with it set False, which never feed; see the dedicated test
    below). These wire+gate tests model the legitimate decisive-step case, so they set
    it True."""
    meta = (
        {"dimension": "presence", "presence_calibration_eligible": True}
        if presence
        else {"pdp": {"pdp_version": "v3"}}
    )
    if tenant is not None:
        meta["tenant_id"] = tenant
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

    # The decision belongs to the acme tenant (as a real acme-session presence
    # hold would be stamped), so the acme key sealing it is a same-tenant act.
    held = _decision(Verdict.ABSTAIN, presence=True, tenant="acme")
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


# --------------------------------------------------------------------------- #
# 6. FAIL-CLOSED: a presence-origin Decision that does NOT affirm a real
#    decisive-step score (the producer's answer-abstain shape) feeds NOTHING
# --------------------------------------------------------------------------- #


def test_presence_origin_without_eligibility_marker_does_not_feed(calib_dir):
    """A presence-origin Decision with ``presence_calibration_eligible`` absent/False —
    the shape the producer mints for an answer-level ABSTAIN (no decisive-step score) —
    SEALS fine but feeds NO calibration label. This is option (C) made structural: the
    seal-route conformal channel never fabricates a score from a credibility abstain."""
    client = TestClient(create_app())
    d = Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.ABSTAIN,
        confidence=0.0,
        final_score=0.0,
        action_type="presence_answer",
        channel="voice",
        environment="presence",
        content_excerpt="x",
        content_sha256="a" * 64,
        policy_version="presence-gate",
        reasons=["presence could not ground the spoken answer"],
        uncertainty_flags=["presence_ungrounded_no_fused_risk"],
        metadata={"dimension": "presence", "presence_calibration_eligible": False},
    )
    resp = _seal(client, d, verdict="refused")
    assert resp.status_code == 201  # the human act IS sealed
    assert resp.json()["calibration_fed"] is False  # but NO fabricated label

    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))
    assert feed.label_count("default") == 0
    assert list(calib_dir.glob("*.calib.jsonl")) == []


# --------------------------------------------------------------------------- #
# 7. END-TO-END: the producer makes a /held presence card sealable, and sealing
#    it succeeds WITHOUT fabricating a calibration label
# --------------------------------------------------------------------------- #


def test_producer_makes_held_card_sealable_end_to_end(calib_dir):
    """run_presence → answer-level ABSTAIN → producer persists a presence-origin
    Decision + stamps decision_id onto the /held card → POST /decisions/{id}/seal
    resolves it (201, human act sealed), and calibration is honestly NOT fed."""
    client = TestClient(create_app())
    sink = HeldDecisionSink()
    # request double whose app.state IS the running app's — so the producer saves into
    # the very decision_store the seal route resolves.
    req = SimpleNamespace(app=client.app)

    env = run_presence(
        gate=PresenceTruthGate(),
        request=req,
        tenant=None,
        brain=_AbstainBrain(),
        transcript="what is the meaning of life?",
        facts=None,
        templated_abstain="I can't ground that, so I won't say it.",
        telemetry=PresenceTelemetry(),
        held_sink=sink,
    )
    assert env is not None and env.verdicts == ()  # answer-level abstain

    held = sink.peek()
    assert len(held) == 1
    decision_id = held[0].decision_id
    assert decision_id is not None  # the card is now SEALABLE (stamped)

    # The producer persisted an HONEST presence-origin ABSTAIN Decision — no fake score.
    stored = client.app.state.decision_store.get(UUID(decision_id))
    assert stored is not None
    assert stored.verdict is Verdict.ABSTAIN
    assert stored.metadata["dimension"] == "presence"
    assert stored.metadata["presence_calibration_eligible"] is False
    assert stored.final_score == 0.0  # NO fabricated risk score

    # Seal the /held card end-to-end: the human act is sealed; no label is fabricated.
    resp = client.post(
        f"/decisions/{decision_id}/seal",
        json={"verdict": "refused", "resolved_by": "operator@example.com", "note": "r"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert len(body["anchor_sha256"]) == 64  # the seal itself is intact
    assert body["calibration_fed"] is False  # honest: no decisive-step score to feed

    feed = PresenceCalibrationFeed(base_dir=str(calib_dir))
    assert feed.label_count("default") == 0
