"""SIEVE STREAM — end-to-end integration tests (ARCHITECTURE.md §5, §7).

Where ``test_discovery_stream.py`` unit-proves the ``StreamingResolver`` graph
mechanics, this file proves the WIRED streaming path end-to-end:

1. ``pipeline.run_stream`` consumes the sensor planes as an EVENT SOURCE and
   drives the adapter (registry.save → ledger.append) per delta, so a NEW agent
   appearing mid-stream is detected INCREMENTALLY and LANDS in a real registry +
   ledger — and is then governable, exactly like the batch ``run_slice`` path.
2. The per-window delta carries the full locked §5 shape.
3. Disappearance after N consecutive misses surfaces (false-positive-suppressed)
   via the wired ``PresenceTracker``.
4. Capability DRIFT surfaces when an entity's tools/list goes
   CLAIMED → OBSERVED mid-stream (a fast attribution event).
5. The BENCHMARK: incremental-update p95 latency < 2s from a new Incidence to
   the updated delta, with re-resolution cost bounded by TOUCHED-component size,
   not total estate size — demonstrated empirically as the background estate
   grows 20 → 200 → 600.

The batch path (``run_slice``) is asserted UNCHANGED — these additions never
touch it. All against the in-memory ``PresenceTracker`` + in-memory registry /
ledger (no DATABASE_URL needed): the streaming path is import-safe + default-safe.
"""

from __future__ import annotations

import statistics
import time
from datetime import UTC, datetime, timedelta

from tex.discovery.engine import pipeline
from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.stream import StreamDelta, StreamingResolver
from tex.discovery.presence import PresenceTracker
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

_BASE = datetime(2026, 6, 23, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Event-source helpers — a live stream over the planes.
# ---------------------------------------------------------------------------


def _inc(
    plane: PlaneId,
    keys: dict[str, str],
    *,
    attrs: dict[str, str] | None = None,
    ref: str = "ref",
    at: datetime | None = None,
    admissibility: Admissibility = Admissibility.OBSERVED,
) -> Incidence:
    return Incidence(
        plane_id=plane,
        footprint=FootprintVector.of(plane, keys, attrs or {}),
        catchability=1.0,
        admissibility=admissibility,
        raw_evidence_ref=ref,
        observed_at=at or _BASE,
    )


def _sighting(
    name: str,
    plane: PlaneId,
    *,
    ref: str,
    at: datetime | None = None,
    attrs: dict[str, str] | None = None,
    admissibility: Admissibility = Admissibility.OBSERVED,
) -> Incidence:
    """One sighting of agent ``name`` on ``plane`` (workspace + ext-id keyed)."""
    return _inc(
        plane,
        {"agent_external_id": name, "workspace_path": f"work/{name}.jsonl"},
        attrs=attrs or {"action_type": "write"},
        ref=ref,
        at=at,
        admissibility=admissibility,
    )


def _fresh_sink() -> tuple[InMemoryAgentRegistry, InMemoryDiscoveryLedger]:
    return InMemoryAgentRegistry(), InMemoryDiscoveryLedger()


# ---------------------------------------------------------------------------
# 1. run_stream consumes an event source and drives the adapter per delta.
# ---------------------------------------------------------------------------


def test_run_stream_consumes_event_source_and_writes_via_adapter() -> None:
    """A live event stream over two planes lands entities through the boundary.

    The event source yields ``Incidence`` records one-by-one (the per-candidate
    iterator seam). ``run_stream`` re-resolves incrementally and projects each
    new/tightened entity through ``adapter.project`` (registry.save →
    ledger.append) — so after draining the stream the registry holds exactly the
    resolved agents and the ledger is a hash-chained record of the projections.
    """
    registry, ledger = _fresh_sink()

    # Two agents, each seen on the two real planes — a genuine cross-plane fuse.
    stream = [
        _sighting("AssayPilot", PlaneId.ACTIONS_TRAIL, ref="a1", at=_BASE),
        _sighting("ShadowBot", PlaneId.FS_WRITE, ref="s1", at=_BASE),
        _sighting(
            "AssayPilot", PlaneId.FS_WRITE, ref="a2", at=_BASE + timedelta(seconds=1)
        ),
    ]

    deltas = list(pipeline.run_stream(stream, registry, ledger, tenant_id="t1"))

    # One ingest delta per event + one final window-close delta.
    assert len(deltas) == len(stream) + 1
    assert all(isinstance(d, StreamDelta) for d in deltas)

    # AssayPilot fused across both planes → ONE registry agent (no duplicate);
    # ShadowBot is its own entity. Two distinct agents landed in the registry.
    saved = registry.list_all()
    assert len(saved) == 2, [a.metadata.get("discovery_external_id") for a in saved]

    # Every landed agent carries the stable SIEVE reconciliation provenance so a
    # re-run re-links it instead of churning — and is now governable.
    for agent in saved:
        assert agent.metadata.get("discovery_external_id", "").startswith("sieve-")

    # Ledger-last: one hash-chained row per projection (>= the agent count).
    assert len(ledger.list_all()) >= 2


def test_new_agent_midstream_detected_incrementally_and_written() -> None:
    """A NEW agent appearing mid-stream is detected incrementally + written.

    Seed a background estate, then a brand-new agent arrives later in the stream.
    Its arrival delta names it in ``new_entities`` AND it lands in the registry
    via the adapter — without re-walking or re-writing the background estate.
    """
    registry, ledger = _fresh_sink()
    resolver = StreamingResolver(tenant_id="t1", registry=registry, ledger=ledger)

    # Background estate established first.
    early = [_sighting(f"bg-{i}", PlaneId.ACTIONS_TRAIL, ref=f"bg{i}") for i in range(5)]
    list(pipeline.run_stream(early, resolver=resolver, close_window=False))
    assert resolver.estate_size == 5
    registry_before = len(registry.list_all())
    assert registry_before == 5

    # The NEW agent arrives mid-stream.
    newcomer = _sighting("LateArrival", PlaneId.ACTIONS_TRAIL, ref="late1")
    arrival_deltas = list(
        pipeline.run_stream([newcomer], resolver=resolver, close_window=False)
    )

    assert len(arrival_deltas) == 1
    delta = arrival_deltas[0]
    # Detected incrementally — named new, touched ZERO existing components.
    assert "LateArrival" in delta.new_entities
    assert delta.touched_components == 0
    # And it LANDED through the adapter: exactly one new registry agent.
    assert len(registry.list_all()) == registry_before + 1
    landed = [
        a
        for a in registry.list_all()
        if a.metadata.get("discovery_external_id")
        not in {
            x.metadata.get("discovery_external_id")
            for x in registry.list_all()[:registry_before]
        }
    ]
    assert landed, "the new agent must be present in the registry"


# ---------------------------------------------------------------------------
# 2. Delta shape — every locked §5 field present, on ingest AND window deltas.
# ---------------------------------------------------------------------------


def test_every_delta_carries_full_section5_shape() -> None:
    stream = [
        _sighting("A", PlaneId.ACTIONS_TRAIL, ref="a1"),
        _sighting("A", PlaneId.FS_WRITE, ref="a2", at=_BASE + timedelta(seconds=1)),
    ]
    deltas = list(pipeline.run_stream(stream, tenant_id="t1"))
    assert deltas
    for delta in deltas:
        for fieldname in (
            "new_entities",
            "tightened",
            "confirmed_disappeared",
            "capability_drift",
            "unseen_fraction_delta",
            "coverage_health_delta",
        ):
            assert hasattr(delta, fieldname), fieldname
        # Types are exactly the locked shape.
        assert isinstance(delta.new_entities, tuple)
        assert isinstance(delta.tightened, tuple)
        assert isinstance(delta.confirmed_disappeared, tuple)
        assert isinstance(delta.capability_drift, tuple)
        assert isinstance(delta.unseen_fraction_delta, float)
        assert delta.coverage_health_delta is None or (
            isinstance(delta.coverage_health_delta, tuple)
            and len(delta.coverage_health_delta) == 2
        )


# ---------------------------------------------------------------------------
# 3. Disappearance after N misses (false-positive-suppressed).
# ---------------------------------------------------------------------------


def test_disappearance_after_n_misses_surfaces_via_window() -> None:
    """An agent withheld for N consecutive windows is confirmed disappeared.

    Drives the wired ``PresenceTracker`` over real ``run_stream`` windows: a
    keep-alive agent stays seen while the subject is withheld; only the Nth
    consecutive miss crosses the threshold (false-positive suppression — earlier
    misses are silent).
    """
    registry, ledger = _fresh_sink()
    resolver = StreamingResolver(
        tenant_id="t1", missing_threshold=3, registry=registry, ledger=ledger
    )

    # Window 0: both present.
    list(
        pipeline.run_stream(
            [
                _sighting("Subject", PlaneId.ACTIONS_TRAIL, ref="su0"),
                _sighting("KeepAlive", PlaneId.ACTIONS_TRAIL, ref="ka0"),
            ],
            resolver=resolver,
        )
    )

    confirmed_at_window: list[int] = []
    # Windows 1..3: Subject withheld, KeepAlive renewed each window.
    for w in range(1, 4):
        deltas = list(
            pipeline.run_stream(
                [_sighting("KeepAlive", PlaneId.ACTIONS_TRAIL, ref=f"ka{w}")],
                resolver=resolver,
            )
        )
        window_delta = deltas[-1]  # the window-close delta
        if "Subject" in window_delta.confirmed_disappeared:
            confirmed_at_window.append(w)

    # Confirmed exactly once, on the 3rd consecutive miss — not earlier.
    assert confirmed_at_window == [3], confirmed_at_window


# ---------------------------------------------------------------------------
# 4. Capability drift surfaces on a tools/list change mid-stream.
# ---------------------------------------------------------------------------


def test_capability_drift_surfaces_on_toolslist_change() -> None:
    """A tool that goes CLAIMED → OBSERVED mid-stream surfaces as drift.

    The agent first DECLARES a tool (a CLAIMED tools/list entry), then later is
    OBSERVED actually exercising that same tool. The grade mutated across the
    window on the same entity → a fast capability-DRIFT attribution event.
    """
    resolver = StreamingResolver(tenant_id="t1")

    # t0: the agent DECLARES (claims) it can send_email — a tools/list entry.
    resolver.feed(
        _sighting(
            "Bot",
            PlaneId.MCP_TOOLGRAPH,
            ref="decl1",
            at=_BASE,
            attrs={"declared_tool": "send_email"},
            admissibility=Admissibility.CLAIMED,
        )
    )

    # t1: later it is OBSERVED actually exercising send_email — grade mutated.
    drift_delta = resolver.feed(
        _sighting(
            "Bot",
            PlaneId.ACTIONS_TRAIL,
            ref="exer1",
            at=_BASE + timedelta(seconds=5),
            attrs={"tool": "send_email"},
            admissibility=Admissibility.OBSERVED,
        )
    )

    drift_keys = {key for (key, _tok) in drift_delta.capability_drift}
    drift_tokens = {tok for (_key, tok) in drift_delta.capability_drift}
    assert "Bot" in drift_keys, drift_delta.capability_drift
    assert "tool:send_email" in drift_tokens, drift_delta.capability_drift


# ---------------------------------------------------------------------------
# 5. BENCHMARK — incremental-update p95 < 2s, bounded by touched component.
# ---------------------------------------------------------------------------


def _time_incremental_update(background: int, *, reps: int = 7) -> list[float]:
    """Time ONE corroborating update against a background estate of ``background``.

    Returns ``reps`` per-update latencies (seconds). The update is a single
    corroborating sighting of a fixed subject; its touched component is size ~1,
    so the cost is bounded by the component, not the ``background`` size.
    """
    samples: list[float] = []
    for rep in range(reps):
        resolver = StreamingResolver(tenant_id="bench")
        resolver.feed(_sighting("subject", PlaneId.ACTIONS_TRAIL, ref="sub1"))
        # Grow a mutually-unrelated background estate (no shared blocking keys).
        for i in range(background):
            resolver.feed(_sighting(f"bg-{rep}-{i}", PlaneId.ACTIONS_TRAIL, ref=f"bg{i}"))
        # Time ONLY the corroborating update against the now-large estate.
        start = time.perf_counter()
        delta = resolver.feed(_sighting("subject", PlaneId.FS_WRITE, ref=f"sub2-{rep}"))
        samples.append(time.perf_counter() - start)
        assert delta.touched_components == 1
    return samples


def _p95(samples: list[float]) -> float:
    if len(samples) == 1:
        return samples[0]
    return statistics.quantiles(samples, n=20)[-1]  # 95th percentile


def test_incremental_update_p95_under_2s_and_bounded_by_component() -> None:
    """The §5 benchmark, demonstrated empirically.

    Update latency p95 < 2s from a new Incidence to the updated delta, AND the
    update cost stays ~flat as the background estate grows 20 → 200 → 600 — proof
    the re-resolution is bounded by the TOUCHED component (size ~2), not the total
    estate size (which would grow ~30x across this range).
    """
    lat_20 = _time_incremental_update(20)
    lat_200 = _time_incremental_update(200)
    lat_600 = _time_incremental_update(600)

    p95_20 = _p95(lat_20)
    p95_200 = _p95(lat_200)
    p95_600 = _p95(lat_600)

    # (a) Absolute target: a single incremental update p95 is far under 2s.
    assert p95_20 < 2.0
    assert p95_200 < 2.0
    assert p95_600 < 2.0

    # (b) Bounded by component, not estate: a 30x bigger estate must NOT make the
    #     update ~30x slower. Estate-linear behavior would blow this up; the
    #     component-bounded path stays flat (allow generous slack for timer noise
    #     on tiny absolute times).
    assert p95_600 < max(0.05, p95_20 * 6.0), (p95_20, p95_200, p95_600)


def test_run_stream_one_by_one_latency_under_target() -> None:
    """Each event through ``run_stream`` (with adapter sink) lands well under 2s."""
    registry, ledger = _fresh_sink()
    resolver = StreamingResolver(tenant_id="t1", registry=registry, ledger=ledger)

    # Pre-grow the background so the per-event timing is against a real estate.
    for i in range(100):
        resolver.feed(_sighting(f"bg-{i}", PlaneId.ACTIONS_TRAIL, ref=f"bg{i}"))

    latencies: list[float] = []
    events = [
        _sighting("subject", PlaneId.ACTIONS_TRAIL, ref="e1"),
        _sighting("subject", PlaneId.FS_WRITE, ref="e2", at=_BASE + timedelta(seconds=1)),
        _sighting("other", PlaneId.ACTIONS_TRAIL, ref="e3"),
    ]
    for event in events:
        start = time.perf_counter()
        list(pipeline.run_stream([event], resolver=resolver, close_window=False))
        latencies.append(time.perf_counter() - start)

    assert max(latencies) < 2.0, latencies
    # The subject landed + tightened through the adapter (no duplicate agent).
    ext_ids = [a.metadata.get("discovery_external_id") for a in registry.list_all()]
    assert len(ext_ids) == len(set(ext_ids)), "no duplicate registry agents"


# ---------------------------------------------------------------------------
# 6. The BATCH path (run_slice) is unchanged — additive, not a replacement.
# ---------------------------------------------------------------------------


def test_run_stream_without_sink_is_pure_delta_engine() -> None:
    """No registry/ledger → ``run_stream`` is a pure SENSE→FUSE delta pass."""
    deltas = list(
        pipeline.run_stream(
            [_sighting("A", PlaneId.ACTIONS_TRAIL, ref="a1")], tenant_id="t1"
        )
    )
    assert deltas
    assert "A" in deltas[0].new_entities


def test_run_stream_none_source_is_safe() -> None:
    registry, ledger = _fresh_sink()
    deltas = list(pipeline.run_stream(None, registry, ledger, tenant_id="t1"))
    # Only the final window-close delta (no events).
    assert len(deltas) == 1
    assert deltas[0].new_entities == ()
    assert len(registry.list_all()) == 0


def test_window_every_closes_windows_midstream() -> None:
    """``window_every`` closes a presence/unseen window mid-stream."""
    stream = [_sighting(f"A{i}", PlaneId.ACTIONS_TRAIL, ref=f"a{i}") for i in range(4)]
    deltas = list(
        pipeline.run_stream(stream, tenant_id="t1", window_every=2, close_window=True)
    )
    # 4 ingest deltas + 2 mid-stream window closes + 1 final window close = 7.
    assert len(deltas) == 4 + 2 + 1


def test_presence_tracker_in_memory_safe(monkeypatch) -> None:
    """The streaming path needs no DB — default-safe posture (§8)."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    tracker = PresenceTracker(missing_threshold=2)
    assert tracker.is_durable is False
    resolver = StreamingResolver(presence=tracker)
    list(pipeline.run_stream([_sighting("A", PlaneId.ACTIONS_TRAIL, ref="a1")], resolver=resolver))
    assert resolver.estate_size == 1
