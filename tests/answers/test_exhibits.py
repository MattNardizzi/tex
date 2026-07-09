"""Tests for the four query buttons — the exhibits layer.

These prove the doctrine, not just the mechanics: a zero count is sealed (not an
error), a None tenant raises, HELD normalizes to ABSTAIN, tenant isolation never
counts another tenant's rows, and the UTC→local window boundary is honoured
(a decision at 03:00 UTC reads as the prior local evening, so it is NOT "today").
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tex.answers.exhibits import (
    count_decisions,
    count_held_waiting,
    get_decision_record,
    list_decisions,
    list_held_waiting,
)
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore


# ───────────────────────────────────────────────────────────────── fixtures
def _sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _decision(
    *,
    verdict: Verdict,
    tenant: str | None = "acme",
    decided_at: datetime | None = None,
    agent: str | None = "billing-bot",
    seed: str | None = None,
) -> Decision:
    """Build a valid Decision honouring the domain's verdict-consistency rules:
    FORBID needs a risk signal, ABSTAIN needs an uncertainty flag."""
    seed = seed or f"{verdict.value}-{tenant}-{decided_at}"
    metadata: dict = {}
    if tenant is not None:
        metadata["tenant_id"] = tenant
    if agent is not None:
        metadata["agent"] = agent

    kwargs: dict = {
        "request_id": uuid4(),
        "verdict": verdict,
        "confidence": 0.9,
        "final_score": 0.1,
        "action_type": "send_email",
        "channel": "api",
        "environment": "prod",
        "content_excerpt": "hello",
        "content_sha256": _sha(seed),
        "policy_version": "v1",
        "decided_at": decided_at or datetime.now(UTC),
        "metadata": metadata,
    }
    if verdict is Verdict.FORBID:
        kwargs["final_score"] = 0.95
        kwargs["reasons"] = ["blocked by policy"]
    if verdict is Verdict.ABSTAIN:
        kwargs["uncertainty_flags"] = ["low_confidence"]
    return Decision(**kwargs)


@pytest.fixture
def store() -> InMemoryDecisionStore:
    return InMemoryDecisionStore()


# ───────────────────────────────────────────────────────────── tenant required
def test_none_tenant_raises_count(store):
    with pytest.raises(ValueError):
        count_decisions(store, None)


def test_blank_tenant_raises_list(store):
    with pytest.raises(ValueError):
        list_decisions(store, "   ")


def test_none_tenant_raises_record(store):
    d = _decision(verdict=Verdict.PERMIT)
    store.save(d)
    with pytest.raises(ValueError):
        get_decision_record(store, d.decision_id, None)


# ─────────────────────────────────────────────────────────────── zero is sealed
def test_zero_count_is_sealed_not_error(store):
    ex = count_decisions(store, "acme", verdict="FORBID")
    assert ex["kind"] == "count"
    assert ex["value"] == 0
    assert ex["spoken"] == "zero"
    assert ex["anchor_sha256"] is None
    assert ex["query"]["tenant"] == "acme"
    assert ex["query"]["verdict"] == "FORBID"


# ───────────────────────────────────────────────────────────── verdict filter
def test_verdict_filter_counts_only_matching(store):
    store.save(_decision(verdict=Verdict.FORBID, seed="f1"))
    store.save(_decision(verdict=Verdict.FORBID, seed="f2"))
    store.save(_decision(verdict=Verdict.PERMIT, seed="p1"))
    store.save(_decision(verdict=Verdict.ABSTAIN, seed="a1"))

    assert count_decisions(store, "acme", verdict="FORBID")["value"] == 2
    assert count_decisions(store, "acme", verdict="PERMIT")["value"] == 1
    assert count_decisions(store, "acme")["value"] == 4  # None ⇒ all


def test_held_normalizes_to_abstain(store):
    store.save(_decision(verdict=Verdict.ABSTAIN, seed="a1"))
    store.save(_decision(verdict=Verdict.ABSTAIN, seed="a2"))
    store.save(_decision(verdict=Verdict.PERMIT, seed="p1"))

    held = count_decisions(store, "acme", verdict="HELD")
    abstain = count_decisions(store, "acme", verdict="ABSTAIN")
    assert held["value"] == 2
    assert abstain["value"] == 2
    # HELD is spoken as the store's real ABSTAIN in provenance — honest rows.
    assert held["query"]["verdict"] == "ABSTAIN"


def test_unknown_verdict_raises(store):
    with pytest.raises(ValueError):
        count_decisions(store, "acme", verdict="MAYBE")


def test_spoken_humanizes_the_count(store):
    for i in range(17):
        store.save(_decision(verdict=Verdict.FORBID, seed=f"f{i}"))
    ex = count_decisions(store, "acme", verdict="FORBID")
    assert ex["value"] == 17
    assert ex["spoken"] == "seventeen"


# ─────────────────────────────────────────────────────────── tenant isolation
def test_other_tenant_rows_never_counted(store):
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", seed="acme1"))
    store.save(_decision(verdict=Verdict.FORBID, tenant="globex", seed="gx1"))
    store.save(_decision(verdict=Verdict.FORBID, tenant="globex", seed="gx2"))

    assert count_decisions(store, "acme", verdict="FORBID")["value"] == 1
    assert count_decisions(store, "globex", verdict="FORBID")["value"] == 2


def test_shared_default_partition_is_visible(store):
    # A row with no tenant reads as "default" (shared) and is visible to every
    # named tenant — the private+shared rule the presence gate applies.
    store.save(_decision(verdict=Verdict.PERMIT, tenant=None, seed="shared1"))
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", seed="acme1"))

    assert count_decisions(store, "acme", verdict="PERMIT")["value"] == 2
    # Another tenant also sees the shared row, plus none of acme's private rows.
    assert count_decisions(store, "globex", verdict="PERMIT")["value"] == 1


# ─────────────────────────────────────────────────── UTC / local time windows
def test_today_window_excludes_prior_local_evening():
    """A decision at 03:00 UTC is 23:00 the previous day in America/New_York
    (EDT, UTC-4). It must NOT count as "today"."""
    import os

    os.environ["TEX_ANSWER_TZ"] = "America/New_York"
    tz_offset = timedelta(hours=4)  # EDT

    now_utc = datetime.now(UTC)
    # Build a UTC instant that lands at 03:00 local-today's-eve: take local
    # midnight today, then step back one hour → still "yesterday" locally.
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("America/New_York")
    local_midnight = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_evening_utc = (local_midnight - timedelta(hours=1)).astimezone(UTC)
    today_noon_utc = (local_midnight + timedelta(hours=12)).astimezone(UTC)

    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, decided_at=yesterday_evening_utc, seed="eve"))
    store.save(_decision(verdict=Verdict.FORBID, decided_at=today_noon_utc, seed="noon"))

    today = count_decisions(store, "acme", verdict="FORBID", window_label="today")
    assert today["value"] == 1  # only the noon-today row, not last evening
    assert today["query"]["window_label"] == "today"
    assert today["query"]["since"] is not None
    _ = (now_utc, tz_offset)  # retained for clarity of the boundary under test


def test_this_week_window_from_local_monday():
    from zoneinfo import ZoneInfo
    import os

    os.environ["TEX_ANSWER_TZ"] = "America/New_York"
    tz = ZoneInfo("America/New_York")
    now_local = datetime.now(tz)
    midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    monday = midnight - timedelta(days=midnight.weekday())

    before_monday_utc = (monday - timedelta(hours=1)).astimezone(UTC)
    after_monday_utc = (monday + timedelta(hours=1)).astimezone(UTC)

    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.PERMIT, decided_at=before_monday_utc, seed="pre"))
    store.save(_decision(verdict=Verdict.PERMIT, decided_at=after_monday_utc, seed="post"))

    week = count_decisions(store, "acme", verdict="PERMIT", window_label="this week")
    assert week["value"] == 1  # only the row after Monday 00:00 local


def test_explicit_since_until_wins_over_label(store):
    base = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)
    store.save(_decision(verdict=Verdict.PERMIT, decided_at=base, seed="in"))
    store.save(_decision(verdict=Verdict.PERMIT, decided_at=base - timedelta(days=5), seed="out"))

    ex = count_decisions(
        store,
        "acme",
        verdict="PERMIT",
        since=base - timedelta(days=1),
        until=base + timedelta(days=1),
    )
    assert ex["value"] == 1
    assert ex["query"]["since"] is not None
    assert ex["query"]["until"] is not None


# ───────────────────────────────────────────────────────────────── list button
def test_list_returns_rows_newest_first_capped(store):
    base = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)
    for i in range(5):
        store.save(
            _decision(verdict=Verdict.FORBID, decided_at=base + timedelta(minutes=i), seed=f"f{i}")
        )
    ex = list_decisions(store, "acme", verdict="FORBID", limit=3)
    assert ex["kind"] == "list"
    assert len(ex["value"]) == 3
    # The ear's rendering: agent names, never a serialized structure. All
    # three rows share one agent here, so the summary names it three times.
    assert ex["spoken"] == "billing-bot, billing-bot, and billing-bot"
    assert "[" not in ex["spoken"] and "{" not in ex["spoken"]
    ats = [row["at"] for row in ex["value"]]
    assert ats == sorted(ats, reverse=True)  # newest first
    row = ex["value"][0]
    assert set(row.keys()) == {"decision_id", "agent", "verdict", "at"}
    assert row["verdict"] == "FORBID"
    assert row["agent"] == "billing-bot"


def test_list_isolated_by_tenant(store):
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", seed="a1"))
    store.save(_decision(verdict=Verdict.PERMIT, tenant="globex", seed="g1"))
    ex = list_decisions(store, "acme")
    assert len(ex["value"]) == 1


def test_list_empty_is_sealed(store):
    ex = list_decisions(store, "acme", verdict="FORBID")
    assert ex["value"] == []
    # An empty list speaks as calm prose — "none" — which the gate's lexicon
    # deliberately allows (a determiner, not a spelled quantity).
    assert ex["spoken"] == "none"


# ─────────────────────────────────────────────────────────────── record button
def test_get_record_carries_real_anchor(store):
    d = _decision(verdict=Verdict.FORBID, seed="rec1")
    store.save(d)
    ex = get_decision_record(store, d.decision_id, "acme")
    assert ex["kind"] == "record"
    assert ex["anchor_sha256"] == d.content_sha256
    record = dict(ex["value"])  # value is an ordered list of [field, value] pairs
    assert record["decision_id"] == str(d.decision_id)
    assert record["verdict"] == "FORBID"
    assert record["agent"] == "billing-bot"


def test_get_record_accepts_string_id(store):
    d = _decision(verdict=Verdict.PERMIT, seed="rec2")
    store.save(d)
    ex = get_decision_record(store, str(d.decision_id), "acme")
    assert dict(ex["value"])["decision_id"] == str(d.decision_id)


def test_get_record_missing_raises_keyerror(store):
    with pytest.raises(KeyError):
        get_decision_record(store, uuid4(), "acme")


def test_get_record_cross_tenant_is_not_found(store):
    d = _decision(verdict=Verdict.FORBID, tenant="globex", seed="gx-rec")
    store.save(d)
    with pytest.raises(KeyError):
        get_decision_record(store, d.decision_id, "acme")


# ─────────────────────────────── held-waiting: only the UNRESOLVED holds, now
class _FakeResolutions:
    """Duck-types the recorder's batch lookup: resolved_decision_ids(ids)."""

    def __init__(self, resolved) -> None:
        self._resolved = {str(x) for x in resolved}
        self.seen: list[str] | None = None

    def resolved_decision_ids(self, candidate_ids=None) -> set[str]:
        self.seen = None if candidate_ids is None else [str(c) for c in candidate_ids]
        if candidate_ids is None:
            return set(self._resolved)
        return {str(c) for c in candidate_ids if str(c) in self._resolved}


def test_waiting_excludes_resolved_includes_unresolved(store):
    a1 = _decision(verdict=Verdict.ABSTAIN, seed="w1")
    a2 = _decision(verdict=Verdict.ABSTAIN, seed="w2")
    a3 = _decision(verdict=Verdict.ABSTAIN, seed="w3")
    for d in (a1, a2, a3):
        store.save(d)

    resolutions = _FakeResolutions([a2.decision_id])  # a2 already resolved
    ex = count_held_waiting(store, "acme", resolutions)

    assert ex["kind"] == "count"
    assert ex["value"] == 2  # a1 + a3 waiting; a2 excluded
    assert ex["query"]["tool"] == "count_held_waiting"
    assert ex["query"]["verdict"] == "ABSTAIN"
    assert ex["anchor_sha256"] is None
    # A real BATCH lookup: the resolver was handed exactly the candidate ids.
    assert set(resolutions.seen) == {
        str(a1.decision_id),
        str(a2.decision_id),
        str(a3.decision_id),
    }


def test_waiting_counts_only_abstain(store):
    store.save(_decision(verdict=Verdict.ABSTAIN, seed="w1"))
    store.save(_decision(verdict=Verdict.PERMIT, seed="p1"))
    store.save(_decision(verdict=Verdict.FORBID, seed="f1"))
    # No resolution source wired → nothing known-resolved → all ABSTAINs wait.
    assert count_held_waiting(store, "acme", None)["value"] == 1


def test_waiting_window_bounded_to_seven_days(store):
    now = datetime.now(UTC)
    store.save(
        _decision(verdict=Verdict.ABSTAIN, decided_at=now - timedelta(days=2), seed="fresh")
    )
    store.save(
        _decision(verdict=Verdict.ABSTAIN, decided_at=now - timedelta(days=30), seed="stale")
    )
    ex = count_held_waiting(store, "acme", None)
    assert ex["value"] == 1  # the 30-day-old hold is outside the waiting window
    assert ex["query"]["since"] is not None


def test_waiting_zero_is_sealed(store):
    ex = count_held_waiting(store, "acme", None)
    assert ex["value"] == 0
    assert ex["spoken"] == "zero"
    assert ex["query"]["is_zero"] is True


def test_waiting_isolated_by_tenant(store):
    store.save(_decision(verdict=Verdict.ABSTAIN, tenant="acme", seed="a1"))
    store.save(_decision(verdict=Verdict.ABSTAIN, tenant="globex", seed="g1"))
    assert count_held_waiting(store, "acme", None)["value"] == 1
    assert count_held_waiting(store, "globex", None)["value"] == 1


def test_list_waiting_rows_payload_shape(store):
    d = _decision(verdict=Verdict.ABSTAIN, agent="atlas-pay", seed="w1")
    store.save(d)
    ex = list_held_waiting(store, "acme", None)

    assert ex["kind"] == "list"
    assert ex["query"]["tool"] == "list_held_waiting"
    assert len(ex["rows"]) == 1
    row = ex["rows"][0]
    assert set(row.keys()) == {
        "decision_id",
        "agent",
        "action_type",
        "content_excerpt",
        "at",
    }
    assert row["decision_id"] == str(d.decision_id)
    assert row["agent"] == "atlas-pay"
    assert row["action_type"] == "send_email"
    assert row["content_excerpt"] == "hello"  # from the fixture, truncated to 280
    assert row["at"] is not None
    # The ear hears a name, never a serialized structure.
    assert "atlas-pay" in ex["spoken"]
    assert "[" not in ex["spoken"] and "{" not in ex["spoken"]


def test_list_waiting_caps_spoken_and_rows_but_counts_true_remainder(store):
    for i in range(30):
        store.save(_decision(verdict=Verdict.ABSTAIN, agent=f"bot-{i}", seed=f"w{i}"))
    ex = list_held_waiting(store, "acme", None)

    assert len(ex["rows"]) == 25  # rows payload capped at twenty-five
    assert len(ex["value"]) == 10  # spoken tier capped at ten
    # The ear is told the TRUE remainder (thirty minus three named), never the
    # capped tier's remainder — honesty about how many still need a human.
    assert "twenty-seven more" in ex["spoken"]


def test_list_waiting_excludes_resolved_from_rows(store):
    keep = _decision(verdict=Verdict.ABSTAIN, agent="keep", seed="k1")
    drop = _decision(verdict=Verdict.ABSTAIN, agent="drop", seed="d1")
    store.save(keep)
    store.save(drop)
    # A plain SET of resolved ids is one accepted resolution-source shape.
    ex = list_held_waiting(store, "acme", {str(drop.decision_id)})
    ids = {r["decision_id"] for r in ex["rows"]}
    assert str(keep.decision_id) in ids
    assert str(drop.decision_id) not in ids


def test_list_waiting_empty_is_sealed_zero(store):
    ex = list_held_waiting(store, "acme", None)
    assert ex["value"] == []
    assert ex["rows"] == []
    assert ex["query"]["is_zero"] is True


def test_resolution_read_fault_fails_open_shows_all(store):
    """An unreadable resolution source must never HIDE a waiting hold — it
    over-surfaces (fails open) rather than silencing one that needs a human."""

    def _boom(_ids):
        raise RuntimeError("resolution store down")

    store.save(_decision(verdict=Verdict.ABSTAIN, seed="w1"))
    assert count_held_waiting(store, "acme", _boom)["value"] == 1


# ───────────────────────────────── held-qualified record filters to ABSTAIN
def test_get_record_held_verdict_filters_to_abstain(store):
    now = datetime.now(UTC)
    held = _decision(verdict=Verdict.ABSTAIN, decided_at=now - timedelta(hours=2), seed="h1")
    permit = _decision(verdict=Verdict.PERMIT, decided_at=now, seed="p1")
    store.save(held)
    store.save(permit)

    # No verdict → the newest row, which is the PERMIT.
    assert dict(get_decision_record(store, None, "acme")["value"])["verdict"] == "PERMIT"
    # HELD verdict → the latest ABSTAIN, never the newer PERMIT.
    rec = dict(get_decision_record(store, None, "acme", verdict="HELD")["value"])
    assert rec["verdict"] == "ABSTAIN"
    assert rec["decision_id"] == str(held.decision_id)


def test_get_record_held_verdict_empty_raises(store):
    store.save(_decision(verdict=Verdict.PERMIT, seed="p1"))
    with pytest.raises(KeyError):
        get_decision_record(store, None, "acme", verdict="HELD")


def test_get_record_verdict_mismatch_on_explicit_id_raises(store):
    d = _decision(verdict=Verdict.PERMIT, seed="p1")
    store.save(d)
    with pytest.raises(KeyError):
        get_decision_record(store, d.decision_id, "acme", verdict="HELD")


# ───────────────────────────────────────── exhibit dict validates the contract
def test_exhibit_dict_validates_against_span_model(store):
    """The dict a primitive returns must construct the peer builder's pydantic
    Exhibit (extra='forbid') — proving the two workstreams join on shape."""
    from tex.answers.spans import Exhibit

    store.save(_decision(verdict=Verdict.FORBID, seed="v1"))
    store.save(_decision(verdict=Verdict.ABSTAIN, seed="v3"))
    for ex in (
        count_decisions(store, "acme", verdict="FORBID", window_label="today"),
        list_decisions(store, "acme"),
        count_held_waiting(store, "acme", None),
        list_held_waiting(store, "acme", None),  # carries the extra rows payload
    ):
        Exhibit(**ex)  # raises on any contract drift

    d = _decision(verdict=Verdict.PERMIT, seed="v2")
    store.save(d)
    Exhibit(**get_decision_record(store, d.decision_id, "acme"))
