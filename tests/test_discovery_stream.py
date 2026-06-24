"""
SIEVE STREAM — the incremental/online resolver tests (ARCHITECTURE.md §5).

Proves the four §5 commitments of ``engine/stream.StreamingResolver``:

1. feeding a NEW agent mid-stream yields it in ``new_entities``;
2. feeding more corroborating incidences for it yields it in ``tightened`` with
   MONOTONICALLY NON-DECREASING confidence;
3. withholding it for N windows yields it in ``confirmed_disappeared`` (the
   false-positive-suppressed N-consecutive-miss soft-disappearance);
4. the incremental-update cost is BOUNDED by the touched-component size, not the
   total estate size — update latency stays ~flat as the background estate grows.

All against the in-memory ``PresenceTracker`` (no DATABASE_URL needed): the
streaming path is import-safe and default-safe.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.stream import (
    INSTANT_PLANES,
    StreamDelta,
    StreamingResolver,
)
from tex.discovery.presence import PresenceTracker

_BASE = datetime(2026, 6, 23, 12, 0, 0, tzinfo=UTC)


def _inc(
    plane: PlaneId,
    keys: dict[str, str],
    *,
    attrs: dict[str, str] | None = None,
    ref: str = "ref",
    at: datetime | None = None,
) -> Incidence:
    return Incidence(
        plane_id=plane,
        footprint=FootprintVector.of(plane, keys, attrs or {}),
        catchability=1.0,
        admissibility=Admissibility.OBSERVED,
        raw_evidence_ref=ref,
        observed_at=at or _BASE,
    )


def _agent_incidence(name: str, plane: PlaneId, *, ref: str, at: datetime | None = None) -> Incidence:
    """One sighting of agent ``name`` on ``plane`` (workspace + ext-id keyed)."""
    return _inc(
        plane,
        {"agent_external_id": name, "workspace_path": f"work/{name}.jsonl"},
        attrs={"action_type": "write"},
        ref=ref,
        at=at,
    )


# ---------------------------------------------------------------------------
# Proof 1 — a NEW agent mid-stream lands in new_entities.
# ---------------------------------------------------------------------------


def test_new_agent_midstream_yields_new_entity() -> None:
    resolver = StreamingResolver(tenant_id="t1")

    delta = resolver.feed(_agent_incidence("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a1"))

    assert "AssayPilot" in delta.new_entities
    assert delta.tightened == ()
    assert resolver.estate_size == 1
    # Provisional entity emitted on the FIRST instant-plane sighting.
    assert PlaneId.ACTIONS_TRAIL in INSTANT_PLANES


def test_second_distinct_agent_is_new_not_tightened() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    resolver.feed(_agent_incidence("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a1"))

    delta = resolver.feed(_agent_incidence("ShadowBot", PlaneId.FS_WRITE, ref="s1"))

    assert "ShadowBot" in delta.new_entities
    # The unrelated AssayPilot component is NOT touched by ShadowBot's arrival.
    assert delta.touched_components == 0
    assert resolver.estate_size == 2


# ---------------------------------------------------------------------------
# Proof 2 — corroboration TIGHTENS confidence, monotonically non-decreasing.
# ---------------------------------------------------------------------------


def test_corroboration_tightens_monotonically() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    resolver.feed(_agent_incidence("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a1"))
    first = resolver.confidence_of("AssayPilot")
    assert first is not None

    # A second, genuinely-independent plane corroborates the same agent.
    delta = resolver.feed(_agent_incidence("AssayPilot", PlaneId.FS_WRITE, ref="a2"))

    keys = [k for (k, _old, _new) in delta.tightened]
    assert "AssayPilot" in keys
    (_k, old_conf, new_conf) = next(t for t in delta.tightened if t[0] == "AssayPilot")
    assert new_conf >= old_conf
    assert resolver.confidence_of("AssayPilot") >= first

    # Re-feeding the SAME evidence must never LOOSEN confidence (tighten-only).
    floor = resolver.confidence_of("AssayPilot")
    resolver.feed(_agent_incidence("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a3"))
    assert resolver.confidence_of("AssayPilot") >= floor


def test_confidence_never_decreases_across_many_feeds() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    confs: list[float] = []
    for i, plane in enumerate(
        [PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE, PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE]
    ):
        resolver.feed(_agent_incidence("AssayPilot", plane, ref=f"a{i}"))
        confs.append(resolver.confidence_of("AssayPilot"))

    assert all(b >= a for a, b in zip(confs, confs[1:])), confs


# ---------------------------------------------------------------------------
# Proof 3 — withholding for N windows confirms disappearance (FP-suppressed).
# ---------------------------------------------------------------------------


def test_withholding_n_windows_confirms_disappearance() -> None:
    resolver = StreamingResolver(tenant_id="t1", missing_threshold=3)
    resolver.feed(_agent_incidence("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a1"))
    resolver.feed(_agent_incidence("KeepBot", PlaneId.ACTIONS_TRAIL, ref="k1"))

    # Window 0: both present.
    w0 = resolver.window()
    assert w0.confirmed_disappeared == ()

    # Windows 1..2: AssayPilot withheld (KeepBot stays alive). Below threshold →
    # NO confirmed disappearance yet (false-positive suppression).
    for i in range(2):
        resolver.feed(_agent_incidence("KeepBot", PlaneId.ACTIONS_TRAIL, ref=f"k{i+2}"))
        w = resolver.window()
        assert "AssayPilot" not in w.confirmed_disappeared, f"premature at window {i+1}"

    # Window 3: third consecutive miss crosses the threshold → CONFIRMED.
    resolver.feed(_agent_incidence("KeepBot", PlaneId.ACTIONS_TRAIL, ref="k9"))
    w3 = resolver.window()
    assert "AssayPilot" in w3.confirmed_disappeared
    assert "KeepBot" not in w3.confirmed_disappeared


def test_reappearance_before_threshold_suppresses_alert() -> None:
    resolver = StreamingResolver(tenant_id="t2", missing_threshold=3)
    resolver.feed(_agent_incidence("Flaky", PlaneId.ACTIONS_TRAIL, ref="f1"))
    resolver.window()

    # Miss once, miss twice — still under threshold.
    resolver.window()
    resolver.window()
    # Then it comes back: the miss counter resets, no false positive ever fires.
    resolver.feed(_agent_incidence("Flaky", PlaneId.ACTIONS_TRAIL, ref="f2"))
    w = resolver.window()
    assert "Flaky" not in w.confirmed_disappeared

    # And a single subsequent miss does NOT immediately confirm (counter reset).
    w_next = resolver.window()
    assert "Flaky" not in w_next.confirmed_disappeared


# ---------------------------------------------------------------------------
# Bounded re-resolution — the benchmark: update cost ~flat as estate grows.
# ---------------------------------------------------------------------------


def _grow_estate(resolver: StreamingResolver, n: int) -> None:
    """Seed ``n`` mutually-unrelated background agents (no shared blocking keys)."""
    for i in range(n):
        resolver.feed(_agent_incidence(f"bg-{i}", PlaneId.ACTIONS_TRAIL, ref=f"bg{i}"))


def test_update_touches_only_its_own_component() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    _grow_estate(resolver, 50)
    assert resolver.estate_size == 50

    # A second sighting of ONE background agent must touch exactly that one
    # component — not the other 49.
    delta = resolver.feed(_agent_incidence("bg-7", PlaneId.FS_WRITE, ref="bg7b"))
    assert delta.touched_components == 1
    assert resolver.estate_size == 50  # tightened in place, not duplicated

    # A brand-new unrelated agent touches ZERO existing components.
    delta2 = resolver.feed(_agent_incidence("fresh", PlaneId.ACTIONS_TRAIL, ref="fr1"))
    assert delta2.touched_components == 0
    assert "fresh" in delta2.new_entities


def test_update_latency_bounded_by_component_not_estate() -> None:
    """The §5 benchmark: latency stays ~flat as the background estate grows.

    We measure the time to feed one corroborating incidence for a fixed agent
    while the unrelated background estate grows 20 → 320. Because re-resolution
    is bounded by the TOUCHED component (size ~2), the large-estate update must
    NOT be dramatically slower than the small-estate one, and every update must
    sit well under the 2s p95 target.
    """

    def time_one_update(background: int) -> float:
        resolver = StreamingResolver(tenant_id="t1")
        resolver.feed(_agent_incidence("subject", PlaneId.ACTIONS_TRAIL, ref="sub1"))
        _grow_estate(resolver, background)
        # Time ONLY the corroborating update against the now-large estate.
        start = time.perf_counter()
        delta = resolver.feed(_agent_incidence("subject", PlaneId.FS_WRITE, ref="sub2"))
        elapsed = time.perf_counter() - start
        assert delta.touched_components == 1
        return elapsed

    small = time_one_update(20)
    large = time_one_update(320)

    # Absolute p95 target: a single incremental update is far under 2s.
    assert small < 2.0
    assert large < 2.0

    # Bounded-by-component, not estate: a 16x bigger estate must not make the
    # update blow up. Allow generous slack for timer noise on tiny absolute
    # times, but reject estate-linear behavior (which would be ~16x).
    assert large < max(0.05, small * 6.0), (small, large)


# ---------------------------------------------------------------------------
# Online completeness + delta shape integrity.
# ---------------------------------------------------------------------------


def test_window_reports_online_unseen_and_health_deltas() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    resolver.feed(_agent_incidence("A", PlaneId.ACTIONS_TRAIL, ref="a1"))
    resolver.feed(_agent_incidence("A", PlaneId.FS_WRITE, ref="a2"))
    resolver.feed(_agent_incidence("B", PlaneId.ACTIONS_TRAIL, ref="b1"))
    resolver.feed(_agent_incidence("B", PlaneId.FS_WRITE, ref="b2"))

    w1 = resolver.window()
    # First window has no prior to diff against → zero delta, no health change.
    assert w1.unseen_fraction_delta == 0.0
    assert w1.coverage_health_delta is None
    assert w1.occasions  # the live capture occasions are recorded

    # Second window with no change → still a well-formed (likely zero) delta.
    w2 = resolver.window()
    assert isinstance(w2, StreamDelta)
    assert isinstance(w2.unseen_fraction_delta, float)


def test_delta_shape_has_all_section_5_fields() -> None:
    """The locked §5 delta shape is fully present on every emitted delta."""
    resolver = StreamingResolver(tenant_id="t1")
    delta = resolver.feed(_agent_incidence("A", PlaneId.ACTIONS_TRAIL, ref="a1"))
    for fieldname in (
        "new_entities",
        "tightened",
        "confirmed_disappeared",
        "capability_drift",
        "unseen_fraction_delta",
        "coverage_health_delta",
    ):
        assert hasattr(delta, fieldname), fieldname


def test_empty_feed_is_safe() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    delta = resolver.feed_batch([])
    assert delta.new_entities == ()
    assert resolver.estate_size == 0


def test_feed_batch_shares_one_resolution_pass() -> None:
    resolver = StreamingResolver(tenant_id="t1")
    batch = [
        _agent_incidence("A", PlaneId.ACTIONS_TRAIL, ref="a1", at=_BASE),
        _agent_incidence("A", PlaneId.FS_WRITE, ref="a2", at=_BASE + timedelta(seconds=1)),
        _agent_incidence("B", PlaneId.ACTIONS_TRAIL, ref="b1", at=_BASE),
    ]
    delta = resolver.feed_batch(batch)
    # A (two planes, fused) + B (one plane) = two entities, both new.
    assert set(delta.new_entities) == {"A", "B"}
    assert resolver.estate_size == 2


def test_presence_tracker_is_in_memory_safe(monkeypatch) -> None:
    """Construction never requires a DB — default-safe posture (§8)."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    tracker = PresenceTracker(missing_threshold=2)
    assert tracker.is_durable is False
    resolver = StreamingResolver(presence=tracker)
    resolver.feed(_agent_incidence("A", PlaneId.ACTIONS_TRAIL, ref="a1"))
    assert resolver.estate_size == 1
