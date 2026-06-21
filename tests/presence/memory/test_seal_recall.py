"""seal → recall round-trip, content-anchor honesty, idempotency."""

from __future__ import annotations

import pytest

from tex.presence.contract import PresenceMemory, PresenceTier
from tex.presence.memory import SealedPresenceMemory

from .conftest import make_claim_verdict


def test_store_is_a_presence_memory(mem: SealedPresenceMemory):
    # runtime_checkable Protocol — guards against an accidental method rename.
    assert isinstance(mem, PresenceMemory)


def test_seal_then_recall_round_trip(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count", value=3)
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)

    assert ref.store == "presence_memory"
    assert len(ref.record_hash) == 64
    assert ref.prior_link_witness is None  # content anchor, not a chain proof

    hits = mem.recall(tenant="acme", query="how many forbid")
    assert ref in hits
    # The full body is fetchable for the brain to ground against.
    body = mem.get(tenant="acme", record_id=ref.record_id)
    assert body is not None
    assert body.content_payload["verdict"]["recomputed_value"] == 3
    assert body.content_payload["verdict"]["evidence"][0]["store"] == "decision_store"


def test_recall_empty_query_returns_recent(mem: SealedPresenceMemory):
    a, av = make_claim_verdict("forbid_count", value=1)
    b, bv = make_claim_verdict("agent_count", value=2, text_span="how many agents")
    mem.seal(tenant="acme", claim=a, verdict=av)
    mem.seal(tenant="acme", claim=b, verdict=bv)
    refs = mem.recall(tenant="acme", query="")
    assert len(refs) == 2  # both, most-recent-first


def test_recall_is_lexical_and_misses_unrelated(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    mem.seal(tenant="acme", claim=claim, verdict=verdict)
    # A query sharing no token with the record returns nothing (the safe
    # direction — the gate re-derives / ABSTAINs rather than speaking).
    assert mem.recall(tenant="acme", query="quarterly revenue projection") == ()


def test_seal_is_idempotent_by_content(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count", value=3)
    ref1 = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    ref2 = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    assert ref1.record_id == ref2.record_id  # content-addressed
    # Exactly one record, not two.
    assert len(mem.recall(tenant="acme", query="")) == 1


def test_distinct_tier_yields_distinct_record(mem: SealedPresenceMemory):
    sealed_c, sealed_v = make_claim_verdict("forbid_count", tier=PresenceTier.SEALED)
    derived_c, derived_v = make_claim_verdict(
        "forbid_count", tier=PresenceTier.DERIVED, correctness_floor=0.9, coverage_mode="transductive"
    )
    r1 = mem.seal(tenant="acme", claim=sealed_c, verdict=sealed_v)
    r2 = mem.seal(tenant="acme", claim=derived_c, verdict=derived_v)
    # Tier is part of the content anchor → different verdicts never collide.
    assert r1.record_id != r2.record_id


def test_content_anchor_verifies_and_tamper_is_detected(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count", value=3)
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    rec = mem.get(tenant="acme", record_id=ref.record_id)
    assert mem.verify(rec) is True

    # Mutate the payload under the same hash → verify must fail (tamper-evident).
    import dataclasses

    tampered = dataclasses.replace(
        rec,
        content_payload={**rec.content_payload, "verdict": {**rec.content_payload["verdict"], "recomputed_value": 9999}},
    )
    assert mem.verify(tampered) is False


def test_recall_requires_tenant(mem: SealedPresenceMemory):
    with pytest.raises(ValueError):
        mem.recall(tenant="", query="x")
