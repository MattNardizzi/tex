"""
Tests for tex.graph — InMemoryTemporalKG, GraphQuery, StateProjection.

Coverage targets:
  - add_entity / add_event happy + error paths
  - timezone enforcement
  - time-travel correctness across multiple version edges
  - state_hash empty-graph pin + determinism + sensitivity
  - find_paths: edge_kind filter, within window, depth cap, no-path
  - causal_ancestors: 8-deep chain
  - StateProjection.project_at returns valid EcosystemState
  - 100-entity / 1000-event scaling smoke
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from tex.events._canonical import canonical_json, sha256_hex
from tex.graph import GraphQuery, InMemoryTemporalKG, StateProjection
from tex.graph.exceptions import (
    DuplicateEventIdError,
    GraphMutationError,
    MissingUpstreamEventError,
    NaiveDatetimeError,
    UnknownActorError,
    UnknownEntityError,
    UnknownEventError,
    UnknownTargetError,
)
from tex.graph.temporal_kg import STATE_HASH_SCHEMA_VERSION


# ----------------------------------------------------------------- fixtures

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _ts(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


@pytest.fixture
def graph() -> InMemoryTemporalKG:
    return InMemoryTemporalKG()


@pytest.fixture
def populated(graph: InMemoryTemporalKG) -> InMemoryTemporalKG:
    """A small graph: agent_a -> tool_t with one tool-call event at T0+10."""
    graph.add_entity(
        entity_id="agent_a",
        kind="agent",
        attrs={"registered_at": T0, "trust_label": "trusted"},
    )
    graph.add_entity(
        entity_id="tool_t",
        kind="tool",
        attrs={"registered_at": T0, "schema_uri": "https://x/y.json"},
    )
    graph.add_event(
        event_id="ev1",
        kind="agent_invokes_tool",
        actor="agent_a",
        target="tool_t",
        payload={"tool_id": "tool_t", "arguments": {"q": "hi"}},
        timestamp=_ts(10),
        upstream=(),
    )
    return graph


# ----------------------------------------------------------------- writes

def test_add_entity_happy_path(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(
        entity_id="agent_a",
        kind="agent",
        attrs={"registered_at": T0, "trust_label": "trusted"},
    )
    snap = graph.get_entity_at("agent_a", T0)
    assert snap is not None
    assert snap["trust_label"] == "trusted"


def test_add_entity_rejects_naive_datetime(graph: InMemoryTemporalKG) -> None:
    naive = datetime(2026, 1, 1)
    with pytest.raises(NaiveDatetimeError):
        graph.add_entity(
            entity_id="agent_a",
            kind="agent",
            attrs={"registered_at": naive},
        )


def test_add_entity_rejects_empty_id(graph: InMemoryTemporalKG) -> None:
    with pytest.raises(TypeError):
        graph.add_entity(entity_id="", kind="agent", attrs={"registered_at": T0})


def test_add_entity_rejects_empty_kind(graph: InMemoryTemporalKG) -> None:
    with pytest.raises(TypeError):
        graph.add_entity(entity_id="x", kind="", attrs={"registered_at": T0})


def test_add_entity_rejects_non_mapping_attrs(graph: InMemoryTemporalKG) -> None:
    with pytest.raises(TypeError):
        graph.add_entity(entity_id="x", kind="agent", attrs="not a dict")  # type: ignore[arg-type]


def test_add_entity_kind_immutable(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="x", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(ValueError):
        graph.add_entity(
            entity_id="x", kind="tool", attrs={"registered_at": _ts(1)}
        )


def test_add_entity_rejects_backward_version(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="x", kind="agent", attrs={"registered_at": _ts(10)})
    with pytest.raises(ValueError):
        graph.add_entity(entity_id="x", kind="agent", attrs={"registered_at": _ts(5)})


def test_add_entity_freeze_rejects_floats(graph: InMemoryTemporalKG) -> None:
    """Inherits Thread 2's float-rejecting canonicalization policy."""
    with pytest.raises(TypeError):
        graph.add_entity(
            entity_id="x",
            kind="agent",
            attrs={"registered_at": T0, "score": 0.5},
        )


def test_add_event_happy_path(populated: InMemoryTemporalKG) -> None:
    # ev1 already added by fixture; verify it's there
    nbrs = populated.neighbors("agent_a")
    assert len(nbrs) == 1
    assert nbrs[0]["event_id"] == "ev1"


def test_add_event_rejects_unknown_actor(graph: InMemoryTemporalKG) -> None:
    with pytest.raises(UnknownActorError):
        graph.add_event(
            event_id="e",
            kind="x",
            actor="ghost",
            target=None,
            payload={},
            timestamp=T0,
            upstream=(),
        )


def test_add_event_rejects_unknown_target(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(UnknownTargetError):
        graph.add_event(
            event_id="e",
            kind="agent_invokes_tool",
            actor="a",
            target="ghost_tool",
            payload={},
            timestamp=T0,
            upstream=(),
        )


def test_add_event_rejects_missing_upstream(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(MissingUpstreamEventError):
        graph.add_event(
            event_id="e",
            kind="agent_emits_output",
            actor="a",
            target=None,
            payload={},
            timestamp=T0,
            upstream=("not_a_real_event",),
        )


def test_add_event_rejects_duplicate_id(populated: InMemoryTemporalKG) -> None:
    with pytest.raises(DuplicateEventIdError):
        populated.add_event(
            event_id="ev1",  # collides with fixture
            kind="agent_emits_output",
            actor="agent_a",
            target=None,
            payload={},
            timestamp=_ts(20),
            upstream=(),
        )


def test_add_event_rejects_naive_timestamp(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(NaiveDatetimeError):
        graph.add_event(
            event_id="e",
            kind="agent_emits_output",
            actor="a",
            target=None,
            payload={},
            timestamp=datetime(2026, 1, 1),  # naive
            upstream=(),
        )


def test_add_event_self_target_when_target_none(graph: InMemoryTemporalKG) -> None:
    """Pure-emission events become a -> a self-edge so they remain walkable."""
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    graph.add_event(
        event_id="emit1",
        kind="agent_emits_output",
        actor="a",
        target=None,
        payload={"text": "hello"},
        timestamp=_ts(5),
        upstream=(),
    )
    # Self-edge should appear in outgoing neighbors of 'a'
    nbrs = graph.neighbors("a")
    assert len(nbrs) == 1
    assert nbrs[0]["actor"] == "a"
    assert nbrs[0]["target"] == "a"


def test_add_event_upstream_must_be_tuple(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(TypeError):
        graph.add_event(
            event_id="e",
            kind="x",
            actor="a",
            target=None,
            payload={},
            timestamp=T0,
            upstream=["not", "a", "tuple"],  # type: ignore[arg-type]
        )


def test_add_event_payload_must_be_mapping(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    with pytest.raises(TypeError):
        graph.add_event(
            event_id="e",
            kind="x",
            actor="a",
            target=None,
            payload="oops",  # type: ignore[arg-type]
            timestamp=T0,
            upstream=(),
        )


def test_add_event_normalizes_to_utc(graph: InMemoryTemporalKG) -> None:
    """Non-UTC tz-aware datetimes are converted to UTC before storage."""
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    eastern = timezone(timedelta(hours=-5))
    local_ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=eastern)  # = 17:00 UTC
    graph.add_event(
        event_id="e1",
        kind="agent_emits_output",
        actor="a",
        target=None,
        payload={},
        timestamp=local_ts,
        upstream=(),
    )
    nbrs = graph.neighbors("a")
    assert nbrs[0]["timestamp"].utcoffset() == timedelta(0)


# ----------------------------------------------------------------- time travel

def test_time_travel_before_first_version_returns_none(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": _ts(100)})
    assert graph.get_entity_at("a", _ts(50)) is None


def test_time_travel_unknown_entity_returns_none(graph: InMemoryTemporalKG) -> None:
    assert graph.get_entity_at("never_added", T0) is None


def test_time_travel_across_five_versions(graph: InMemoryTemporalKG) -> None:
    """Add 5 versioned snapshots; verify the right snapshot is returned for
    each interval between version timestamps."""
    versions = [
        ({"registered_at": _ts(0), "trust_label": "untrusted", "v": 1}, _ts(0)),
        ({"registered_at": _ts(10), "trust_label": "limited", "v": 2}, _ts(10)),
        ({"registered_at": _ts(20), "trust_label": "trusted", "v": 3}, _ts(20)),
        ({"registered_at": _ts(30), "trust_label": "privileged", "v": 4}, _ts(30)),
        ({"registered_at": _ts(40), "trust_label": "limited", "v": 5}, _ts(40)),
    ]
    for attrs, _ in versions:
        graph.add_entity(entity_id="a", kind="agent", attrs=attrs)

    # At each version timestamp, the matching version
    assert graph.get_entity_at("a", _ts(0))["v"] == 1
    assert graph.get_entity_at("a", _ts(10))["v"] == 2
    assert graph.get_entity_at("a", _ts(20))["v"] == 3
    assert graph.get_entity_at("a", _ts(30))["v"] == 4
    assert graph.get_entity_at("a", _ts(40))["v"] == 5

    # Between version timestamps, the previous version
    assert graph.get_entity_at("a", _ts(5))["v"] == 1
    assert graph.get_entity_at("a", _ts(15))["v"] == 2
    assert graph.get_entity_at("a", _ts(25))["v"] == 3
    assert graph.get_entity_at("a", _ts(35))["v"] == 4

    # Far in the future — last version
    assert graph.get_entity_at("a", _ts(10_000))["v"] == 5


def test_time_travel_merges_attrs_delta_style(graph: InMemoryTemporalKG) -> None:
    """A subsequent add_entity merges into the prior snapshot."""
    graph.add_entity(
        entity_id="a",
        kind="agent",
        attrs={"registered_at": _ts(0), "trust_label": "trusted", "model": "x"},
    )
    graph.add_entity(
        entity_id="a",
        kind="agent",
        attrs={"registered_at": _ts(10), "trust_label": "privileged"},  # no `model`
    )
    snap = graph.get_entity_at("a", _ts(20))
    assert snap is not None
    assert snap["trust_label"] == "privileged"
    assert snap["model"] == "x"  # carried forward from v1


def test_time_travel_returned_dict_is_independent(graph: InMemoryTemporalKG) -> None:
    """Caller mutations of the returned snapshot must not poison storage."""
    graph.add_entity(
        entity_id="a", kind="agent",
        attrs={"registered_at": T0, "trust_label": "trusted"},
    )
    snap = graph.get_entity_at("a", T0)
    snap["trust_label"] = "POISONED"
    again = graph.get_entity_at("a", T0)
    assert again["trust_label"] == "trusted"


# ----------------------------------------------------------------- state_hash

def test_empty_graph_state_hash_is_pinned(graph: InMemoryTemporalKG) -> None:
    """The empty-graph state hash is a literal we can compute outside the class."""
    expected = sha256_hex(canonical_json({
        "schema_version": "1",
        "entities": [],
        "events": [],
    }))
    assert graph.state_hash(at=T0) == expected
    # And the schema_version constant is what we think it is.
    assert STATE_HASH_SCHEMA_VERSION == "1"


def test_state_hash_deterministic_across_instances() -> None:
    """Two graphs built identically produce identical hashes."""
    def build() -> InMemoryTemporalKG:
        g = InMemoryTemporalKG()
        g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
        g.add_entity(entity_id="b", kind="tool", attrs={"registered_at": T0})
        g.add_event(
            event_id="e1", kind="agent_invokes_tool",
            actor="a", target="b",
            payload={"tool_id": "b"}, timestamp=_ts(5), upstream=(),
        )
        return g

    g1 = build()
    g2 = build()
    assert g1.state_hash(_ts(100)) == g2.state_hash(_ts(100))


def test_state_hash_independent_of_insertion_order() -> None:
    """Inserting entities/events in different orders yields the same hash."""
    g1 = InMemoryTemporalKG()
    g1.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    g1.add_entity(entity_id="b", kind="tool", attrs={"registered_at": T0})

    g2 = InMemoryTemporalKG()
    g2.add_entity(entity_id="b", kind="tool", attrs={"registered_at": T0})
    g2.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})

    assert g1.state_hash(_ts(100)) == g2.state_hash(_ts(100))


def test_state_hash_changes_when_event_added(populated: InMemoryTemporalKG) -> None:
    h_before = populated.state_hash(_ts(100))
    populated.add_event(
        event_id="ev2",
        kind="agent_emits_output",
        actor="agent_a",
        target=None,
        payload={"text": "hi"},
        timestamp=_ts(20),
        upstream=("ev1",),
    )
    h_after = populated.state_hash(_ts(100))
    assert h_before != h_after


def test_state_hash_excludes_future_events(populated: InMemoryTemporalKG) -> None:
    """Events with ts > at must not influence state_hash(at)."""
    h_at_5 = populated.state_hash(_ts(5))  # ev1 is at t=10, so excluded
    populated.add_event(
        event_id="ev2",
        kind="agent_emits_output",
        actor="agent_a",
        target=None,
        payload={"text": "future"},
        timestamp=_ts(1000),
        upstream=(),
    )
    h_at_5_again = populated.state_hash(_ts(5))
    assert h_at_5 == h_at_5_again


def test_state_hash_excludes_future_entities(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="a", kind="agent", attrs={"registered_at": _ts(100)})
    expected_empty = sha256_hex(canonical_json({
        "schema_version": "1", "entities": [], "events": [],
    }))
    # at t=50 the entity hasn't been registered yet
    assert graph.state_hash(_ts(50)) == expected_empty


# ----------------------------------------------------------------- neighbors

def test_neighbors_unknown_entity_returns_empty(graph: InMemoryTemporalKG) -> None:
    assert graph.neighbors("ghost") == ()


def test_neighbors_filters_by_kind(populated: InMemoryTemporalKG) -> None:
    populated.add_event(
        event_id="ev2",
        kind="agent_emits_output",
        actor="agent_a",
        target=None,
        payload={},
        timestamp=_ts(20),
        upstream=(),
    )
    only_invoke = populated.neighbors("agent_a", edge_kinds=("agent_invokes_tool",))
    assert {n["event_id"] for n in only_invoke} == {"ev1"}
    only_emit = populated.neighbors("agent_a", edge_kinds=("agent_emits_output",))
    assert {n["event_id"] for n in only_emit} == {"ev2"}


def test_neighbors_filters_by_window(populated: InMemoryTemporalKG) -> None:
    populated.add_event(
        event_id="ev2",
        kind="agent_emits_output",
        actor="agent_a",
        target=None,
        payload={},
        timestamp=_ts(100),
        upstream=(),
    )
    in_window = populated.neighbors(
        "agent_a", within=(_ts(0), _ts(50))
    )
    assert {n["event_id"] for n in in_window} == {"ev1"}


def test_neighbors_invalid_window_raises(populated: InMemoryTemporalKG) -> None:
    with pytest.raises(ValueError):
        populated.neighbors("agent_a", within=(_ts(50), _ts(0)))


def test_neighbors_includes_incoming_edges(populated: InMemoryTemporalKG) -> None:
    nbrs = populated.neighbors("tool_t")
    assert len(nbrs) == 1
    assert nbrs[0]["actor"] == "agent_a"
    assert nbrs[0]["target"] == "tool_t"


# ----------------------------------------------------------------- find_paths

def test_find_paths_direct_edge(populated: InMemoryTemporalKG) -> None:
    q = GraphQuery(graph=populated)
    paths = q.find_paths(from_entity="agent_a", to_entity="tool_t")
    assert paths == (("agent_a", "tool_t"),)


def test_find_paths_no_path(populated: InMemoryTemporalKG) -> None:
    populated.add_entity(entity_id="orphan", kind="tool", attrs={"registered_at": T0})
    q = GraphQuery(graph=populated)
    assert q.find_paths(from_entity="agent_a", to_entity="orphan") == ()


def test_find_paths_unknown_endpoint(populated: InMemoryTemporalKG) -> None:
    q = GraphQuery(graph=populated)
    assert q.find_paths(from_entity="ghost", to_entity="tool_t") == ()
    assert q.find_paths(from_entity="agent_a", to_entity="ghost") == ()


def test_find_paths_kind_filter() -> None:
    g = InMemoryTemporalKG()
    g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    g.add_entity(entity_id="b", kind="agent", attrs={"registered_at": T0})
    g.add_entity(entity_id="c", kind="tool", attrs={"registered_at": T0})
    g.add_event(
        event_id="m1", kind="agent_to_agent_message",
        actor="a", target="b",
        payload={"recipient_agent_id": "b", "body": "hi"},
        timestamp=_ts(1), upstream=(),
    )
    g.add_event(
        event_id="m2", kind="agent_invokes_tool",
        actor="b", target="c",
        payload={"tool_id": "c"}, timestamp=_ts(2), upstream=(),
    )
    q = GraphQuery(graph=g)

    # Both kinds allowed -> path exists
    full = q.find_paths(
        from_entity="a", to_entity="c",
        edge_kinds=("agent_to_agent_message", "agent_invokes_tool"),
    )
    assert ("a", "b", "c") in full

    # Only message kind -> no path to c (the b->c edge is wrong kind)
    msg_only = q.find_paths(
        from_entity="a", to_entity="c",
        edge_kinds=("agent_to_agent_message",),
    )
    assert msg_only == ()


def test_find_paths_within_window() -> None:
    g = InMemoryTemporalKG()
    g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    g.add_entity(entity_id="b", kind="tool", attrs={"registered_at": T0})
    g.add_event(
        event_id="early", kind="agent_invokes_tool",
        actor="a", target="b", payload={"tool_id": "b"},
        timestamp=_ts(5), upstream=(),
    )
    g.add_event(
        event_id="late", kind="agent_invokes_tool",
        actor="a", target="b", payload={"tool_id": "b"},
        timestamp=_ts(500), upstream=(),
    )
    q = GraphQuery(graph=g)

    # Window covers only `early` — path still exists
    paths = q.find_paths(
        from_entity="a", to_entity="b",
        within=(_ts(0), _ts(10)),
    )
    assert paths == (("a", "b"),)

    # Window covers no edges — no path
    none = q.find_paths(
        from_entity="a", to_entity="b",
        within=(_ts(1000), _ts(2000)),
    )
    assert none == ()


def test_find_paths_depth_cap() -> None:
    """A 4-hop chain is reachable at depth=4 but not depth=3."""
    g = _build_chain(length=4)
    q = GraphQuery(graph=g)
    paths_4 = q.find_paths(from_entity="n0", to_entity="n4", max_depth=4)
    assert ("n0", "n1", "n2", "n3", "n4") in paths_4
    paths_3 = q.find_paths(from_entity="n0", to_entity="n4", max_depth=3)
    assert paths_3 == ()


def test_find_paths_depth_8() -> None:
    """Acceptance: paths to depth 8 work."""
    g = _build_chain(length=8)
    q = GraphQuery(graph=g)
    paths = q.find_paths(from_entity="n0", to_entity="n8", max_depth=8)
    assert paths == (tuple(f"n{i}" for i in range(9)),)


def test_find_paths_invalid_depth_raises() -> None:
    g = InMemoryTemporalKG()
    q = GraphQuery(graph=g)
    with pytest.raises(ValueError):
        q.find_paths(from_entity="a", to_entity="b", max_depth=0)


def test_find_paths_empty_endpoints_raise() -> None:
    g = InMemoryTemporalKG()
    q = GraphQuery(graph=g)
    with pytest.raises(TypeError):
        q.find_paths(from_entity="", to_entity="x")
    with pytest.raises(TypeError):
        q.find_paths(from_entity="x", to_entity="")


def test_find_paths_simple_path_only() -> None:
    """A cycle must not produce non-simple paths."""
    g = InMemoryTemporalKG()
    for n in ("a", "b", "c"):
        g.add_entity(entity_id=n, kind="agent", attrs={"registered_at": T0})
    g.add_event(
        event_id="e1", kind="agent_to_agent_message",
        actor="a", target="b",
        payload={"recipient_agent_id": "b", "body": "x"},
        timestamp=_ts(1), upstream=(),
    )
    g.add_event(
        event_id="e2", kind="agent_to_agent_message",
        actor="b", target="c",
        payload={"recipient_agent_id": "c", "body": "x"},
        timestamp=_ts(2), upstream=(),
    )
    g.add_event(
        event_id="e3", kind="agent_to_agent_message",
        actor="c", target="a",  # creates cycle
        payload={"recipient_agent_id": "a", "body": "x"},
        timestamp=_ts(3), upstream=(),
    )
    q = GraphQuery(graph=g)
    paths = q.find_paths(from_entity="a", to_entity="c", max_depth=8)
    # The only simple path is the direct one
    assert paths == (("a", "b", "c"),)


# ----------------------------------------------------------------- causal_ancestors

def test_causal_ancestors_chain_of_eight() -> None:
    """An 8-deep upstream chain is fully resolvable at depth=8."""
    g = InMemoryTemporalKG()
    g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    prev: tuple[str, ...] = ()
    for i in range(9):  # ev0 .. ev8 — ev8 has 8 ancestors
        g.add_event(
            event_id=f"ev{i}",
            kind="agent_emits_output",
            actor="a",
            target=None,
            payload={},
            timestamp=_ts(i),
            upstream=prev,
        )
        prev = (f"ev{i}",)

    q = GraphQuery(graph=g)
    ancestors = q.causal_ancestors(event_id="ev8", depth=8)
    # BFS from ev8: discovers ev7, then ev6, ... ev0 — exactly 8 ancestors
    assert ancestors == ("ev7", "ev6", "ev5", "ev4", "ev3", "ev2", "ev1", "ev0")


def test_causal_ancestors_respects_depth() -> None:
    g = InMemoryTemporalKG()
    g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    prev: tuple[str, ...] = ()
    for i in range(9):
        g.add_event(
            event_id=f"ev{i}", kind="agent_emits_output",
            actor="a", target=None, payload={},
            timestamp=_ts(i), upstream=prev,
        )
        prev = (f"ev{i}",)
    q = GraphQuery(graph=g)
    short = q.causal_ancestors(event_id="ev8", depth=3)
    assert short == ("ev7", "ev6", "ev5")


def test_causal_ancestors_diamond_dedup() -> None:
    """An event with multiple upstream paths to a common root returns it once."""
    g = InMemoryTemporalKG()
    g.add_entity(entity_id="a", kind="agent", attrs={"registered_at": T0})
    g.add_event(
        event_id="root", kind="agent_emits_output",
        actor="a", target=None, payload={},
        timestamp=_ts(1), upstream=(),
    )
    g.add_event(
        event_id="left", kind="agent_emits_output",
        actor="a", target=None, payload={},
        timestamp=_ts(2), upstream=("root",),
    )
    g.add_event(
        event_id="right", kind="agent_emits_output",
        actor="a", target=None, payload={},
        timestamp=_ts(3), upstream=("root",),
    )
    g.add_event(
        event_id="join", kind="agent_emits_output",
        actor="a", target=None, payload={},
        timestamp=_ts(4), upstream=("left", "right"),
    )
    q = GraphQuery(graph=g)
    ancestors = q.causal_ancestors(event_id="join", depth=8)
    # left, right, root — root appears exactly once
    assert ancestors.count("root") == 1
    assert set(ancestors) == {"left", "right", "root"}


def test_causal_ancestors_unknown_event_raises() -> None:
    g = InMemoryTemporalKG()
    q = GraphQuery(graph=g)
    with pytest.raises(UnknownEventError):
        q.causal_ancestors(event_id="nope")


def test_causal_ancestors_invalid_depth_raises(populated: InMemoryTemporalKG) -> None:
    q = GraphQuery(graph=populated)
    with pytest.raises(ValueError):
        q.causal_ancestors(event_id="ev1", depth=0)
    with pytest.raises(TypeError):
        q.causal_ancestors(event_id="", depth=1)


def test_causal_ancestors_root_event_returns_empty(populated: InMemoryTemporalKG) -> None:
    q = GraphQuery(graph=populated)
    # ev1 has no upstream
    assert q.causal_ancestors(event_id="ev1") == ()


# ----------------------------------------------------------------- projection

def test_projection_empty_graph_returns_unknown_governance(graph: InMemoryTemporalKG) -> None:
    proj = StateProjection(graph=graph)
    state = proj.project_at(T0)
    assert state.active_agent_ids == ()
    assert state.active_tool_ids == ()
    assert state.active_capability_ids == ()
    assert state.active_governance_graph_id == "unknown"
    assert state.aggregate_drift_signals == {}
    assert state.sliding_window_compromise_ratio == 0.0


def test_projection_partitions_by_kind(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="agent_a", kind="agent", attrs={"registered_at": T0})
    graph.add_entity(entity_id="agent_b", kind="agent", attrs={"registered_at": T0})
    graph.add_entity(entity_id="tool_t", kind="tool", attrs={"registered_at": T0})
    graph.add_entity(entity_id="cap_c", kind="capability", attrs={"registered_at": T0})
    graph.add_entity(
        entity_id="gov_v1", kind="governance_graph",
        attrs={"registered_at": T0},
    )

    proj = StateProjection(graph=graph)
    state = proj.project_at(_ts(100))

    assert state.active_agent_ids == ("agent_a", "agent_b")
    assert state.active_tool_ids == ("tool_t",)
    assert state.active_capability_ids == ("cap_c",)
    assert state.active_governance_graph_id == "gov_v1"


def test_projection_excludes_not_yet_registered(graph: InMemoryTemporalKG) -> None:
    graph.add_entity(entity_id="agent_late", kind="agent", attrs={"registered_at": _ts(100)})
    proj = StateProjection(graph=graph)
    state = proj.project_at(_ts(50))
    assert state.active_agent_ids == ()


def test_projection_state_hash_matches_graph(populated: InMemoryTemporalKG) -> None:
    proj = StateProjection(graph=populated)
    state = proj.project_at(_ts(100))
    assert state.state_hash == populated.state_hash(_ts(100))


# ----------------------------------------------------------------- exception hierarchy

def test_all_mutation_errors_are_graph_mutation_errors() -> None:
    """The exception base class catches all mutation failures."""
    for cls in (
        UnknownActorError,
        UnknownTargetError,
        MissingUpstreamEventError,
        DuplicateEventIdError,
        NaiveDatetimeError,
        UnknownEntityError,
        UnknownEventError,
    ):
        assert issubclass(cls, GraphMutationError), cls


# ----------------------------------------------------------------- scaling smoke

def test_scaling_smoke_100_entities_1000_events() -> None:
    """Build a graph with 100 entities and 1000 events, then project + query.

    Not a perf assertion — just proves the implementation completes within a
    reasonable budget for the acceptance criterion.
    """
    g = InMemoryTemporalKG()
    # 100 entities (50 agents, 25 tools, 25 capabilities)
    for i in range(50):
        g.add_entity(
            entity_id=f"agent_{i}", kind="agent",
            attrs={"registered_at": T0, "i": i},
        )
    for i in range(25):
        g.add_entity(
            entity_id=f"tool_{i}", kind="tool",
            attrs={"registered_at": T0, "i": i},
        )
    for i in range(25):
        g.add_entity(
            entity_id=f"cap_{i}", kind="capability",
            attrs={"registered_at": T0, "i": i},
        )

    # 1000 events: each agent invokes round-robin tools and chains upstream
    last_event: str | None = None
    for k in range(1000):
        actor = f"agent_{k % 50}"
        target = f"tool_{k % 25}"
        upstream = (last_event,) if last_event is not None else ()
        ev_id = f"ev_{k:04d}"
        g.add_event(
            event_id=ev_id,
            kind="agent_invokes_tool",
            actor=actor,
            target=target,
            payload={"tool_id": target, "k": k},
            timestamp=_ts(k),
            upstream=upstream,
        )
        last_event = ev_id

    proj = StateProjection(graph=g)
    state = proj.project_at(_ts(2000))
    assert len(state.active_agent_ids) == 50
    assert len(state.active_tool_ids) == 25
    assert len(state.active_capability_ids) == 25
    # State hash is reproducible: rebuild and compare.
    h1 = g.state_hash(_ts(2000))
    h2 = g.state_hash(_ts(2000))
    assert h1 == h2

    # Causal walk over the long chain finishes.
    q = GraphQuery(graph=g)
    ancestors = q.causal_ancestors(event_id="ev_0999", depth=8)
    assert ancestors == tuple(f"ev_{i:04d}" for i in (998, 997, 996, 995, 994, 993, 992, 991))


# ----------------------------------------------------------------- helper

def _build_chain(length: int) -> InMemoryTemporalKG:
    """A linear graph n0 -> n1 -> ... -> n{length}."""
    g = InMemoryTemporalKG()
    for i in range(length + 1):
        g.add_entity(entity_id=f"n{i}", kind="agent", attrs={"registered_at": T0})
    for i in range(length):
        g.add_event(
            event_id=f"e{i}", kind="agent_to_agent_message",
            actor=f"n{i}", target=f"n{i+1}",
            payload={"recipient_agent_id": f"n{i+1}", "body": "x"},
            timestamp=_ts(i + 1),
            upstream=(),
        )
    return g
