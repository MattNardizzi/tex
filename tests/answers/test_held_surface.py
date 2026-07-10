"""Restart-proof /held surface — the durable floor unioned with the live sink.

Covers the fresh-deploy case (sink empty, durable rows still surface), dedup
when the same decision_id lives in both, sealed decisions excluded, and the
mapped-shape contract the frontend renders (WHO in detail.agent_name, WHAT in
detail.content_excerpt, the real sealable decision_id).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tex.answers import held_surface
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.provenance.feed import HeldDecision
from tex.stores.decision_store import InMemoryDecisionStore


def _sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _abstain(
    *,
    tenant: str = "acme",
    agent: str = "atlas-pay",
    seed: str = "w1",
    decided_at: datetime | None = None,
    dimension: str | None = None,
) -> Decision:
    metadata: dict = {"tenant_id": tenant, "agent": agent}
    if dimension is not None:
        metadata["dimension"] = dimension
    return Decision(
        request_id=uuid4(),
        verdict=Verdict.ABSTAIN,
        confidence=0.9,
        final_score=0.1,
        action_type="send_email",
        channel="api",
        environment="prod",
        content_excerpt="please wire $2,000,000",
        content_sha256=_sha(seed),
        policy_version="v1",
        decided_at=decided_at or datetime.now(UTC),
        uncertainty_flags=["low_confidence"],
        metadata=metadata,
    )


class _FakeResolutions:
    """Duck-types the evidence recorder's batch seal lookup."""

    def __init__(self, resolved) -> None:
        self._resolved = {str(x) for x in resolved}

    def resolved_decision_ids(self, candidate_ids=None) -> set[str]:
        if candidate_ids is None:
            return set(self._resolved)
        return {str(c) for c in candidate_ids if str(c) in self._resolved}


# ─────────────────────────────────── the fresh-deploy case: sink empty, durable
def test_held_returns_durable_rows_when_sink_is_empty():
    store = InMemoryDecisionStore()
    d = _abstain(agent="atlas-pay", seed="d1")
    store.save(d)

    items = held_surface.union_held(store, "acme", None, sink_items=[])

    assert len(items) == 1
    row = items[0]
    # Real sealable id — the queue walks this through POST /decisions/{id}/seal.
    assert row["decision_id"] == str(d.decision_id)
    # WHO / WHAT ride the detail exactly as a live sink item's to_jsonable does.
    assert row["detail"]["agent_name"] == "atlas-pay"
    assert row["detail"]["content_excerpt"] == "please wire $2,000,000"
    assert row["detail"]["action_type"] == "send_email"
    assert row["kind"] == "held_waiting"


def test_durable_shape_matches_sink_jsonable_keys():
    store = InMemoryDecisionStore()
    store.save(_abstain(seed="k1"))
    durable = held_surface.union_held(store, "acme", None, sink_items=[])[0]

    sink_ref = HeldDecision(
        agent_id=uuid4(),
        kind="held_waiting",
        confidence=0.0,
        note="x",
        detail={},
        decision_id=str(uuid4()),
    ).to_jsonable()

    assert set(durable.keys()) == set(sink_ref.keys())


# ─────────────────────────────────────────────────────────── dedup + ordering
def test_dedup_prefers_sink_on_same_decision_id():
    store = InMemoryDecisionStore()
    d = _abstain(agent="atlas-pay", seed="dup")
    store.save(d)

    # The live sink carries the SAME decision, enriched with a Hold sentence.
    sink_item = HeldDecision(
        agent_id=uuid4(),
        kind="held_waiting",
        confidence=0.0,
        note="I'm holding this one. Live copy.",
        detail={"agent_name": "atlas-pay"},
        hold={"sentence": "live"},
        decision_id=str(d.decision_id),
        tenant_id="acme",
    )

    items = held_surface.union_held(store, "acme", None, sink_items=[sink_item])

    assert len(items) == 1  # one row, not two
    # Sink wins the collision — it carries the live Hold object.
    assert items[0]["hold"] == {"sentence": "live"}
    assert items[0]["note"] == "I'm holding this one. Live copy."


def test_union_is_newest_first():
    store = InMemoryDecisionStore()
    now = datetime.now(UTC)
    old = _abstain(seed="old", decided_at=now - timedelta(days=3))
    new = _abstain(seed="new", decided_at=now - timedelta(hours=1))
    store.save(old)
    store.save(new)

    items = held_surface.union_held(store, "acme", None, sink_items=[])
    ids = [it["decision_id"] for it in items]
    assert ids == [str(new.decision_id), str(old.decision_id)]


# ──────────────────────────────────────────────────────── sealed are excluded
def test_sealed_decisions_excluded_from_durable_floor():
    store = InMemoryDecisionStore()
    keep = _abstain(agent="keep", seed="keep")
    sealed = _abstain(agent="sealed", seed="sealed")
    store.save(keep)
    store.save(sealed)

    resolutions = _FakeResolutions([sealed.decision_id])
    items = held_surface.union_held(store, "acme", resolutions, sink_items=[])

    ids = {it["decision_id"] for it in items}
    assert str(keep.decision_id) in ids
    assert str(sealed.decision_id) not in ids


# ─────────────────────────────── presence reviews are tagged, not miscounted
def test_presence_origin_abstain_is_tagged_presence_abstain():
    store = InMemoryDecisionStore()
    store.save(_abstain(seed="p1", dimension="presence"))
    store.save(_abstain(seed="g1"))  # a governance hold

    items = held_surface.union_held(store, "acme", None, sink_items=[])
    kinds = sorted(it["kind"] for it in items)
    # Both surface on /held (still sealable), but the presence review carries the
    # tag the vigil headline filters on so it never inflates the waiting count.
    assert kinds == ["held_waiting", "presence_abstain"]


def test_empty_store_and_empty_sink_is_empty():
    store = InMemoryDecisionStore()
    assert held_surface.union_held(store, "acme", None, sink_items=[]) == []
    # A missing store degrades to just the (empty) sink.
    assert held_surface.union_held(None, "acme", None, sink_items=[]) == []
