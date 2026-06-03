"""Unit tests for ``tex.institutional.subagent_inheritance``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.institutional.subagent_inheritance import (
    CANONICAL_RESTRICTIVENESS,
    InheritedState,
    resolve_effective_state,
)


NOW = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def graph():
    return InMemoryTemporalKG()


def _add(graph, eid, **attrs):
    base = {"registered_at": NOW - timedelta(minutes=1)}
    base.update(attrs)
    graph.add_entity(entity_id=eid, kind="agent", attrs=base)


class TestNoParent:
    def test_actor_with_no_spawned_by_uses_direct_state(self, graph):
        _add(graph, "solo")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="solo",
            direct_state="active",
            institutional_states={"solo": "active"},
            at=NOW,
        )
        assert result == InheritedState(
            actor_entity_id="solo",
            direct_state="active",
            effective_state="active",
            inherited_from=None,
            chain_length=0,
        )

    def test_actor_not_in_graph_returns_direct_state_unchanged(self, graph):
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="nonexistent",
            direct_state="active",
            institutional_states={},
            at=NOW,
        )
        assert result.effective_state == "active"
        assert result.chain_length == 0


class TestInheritance:
    def test_subagent_of_suspended_inherits_suspended(self, graph):
        _add(graph, "parent")
        _add(graph, "child", spawned_by="parent")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="child",
            direct_state="active",
            institutional_states={"parent": "suspended", "child": "active"},
            at=NOW,
        )
        assert result.effective_state == "suspended"
        assert result.inherited_from == "parent"
        assert result.chain_length == 1

    def test_subagent_of_fined_inherits_fined(self, graph):
        _add(graph, "p")
        _add(graph, "c", spawned_by="p")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="c",
            direct_state="active",
            institutional_states={"p": "fined", "c": "active"},
            at=NOW,
        )
        assert result.effective_state == "fined"

    def test_direct_state_more_restrictive_than_parent_wins(self, graph):
        _add(graph, "p")
        _add(graph, "c", spawned_by="p")
        # Direct = fined, parent = warning → fined more restrictive → fined.
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="c",
            direct_state="fined",
            institutional_states={"p": "warning", "c": "fined"},
            at=NOW,
        )
        assert result.effective_state == "fined"
        assert result.inherited_from is None

    def test_two_hop_chain_walks_to_grandparent(self, graph):
        _add(graph, "gp")
        _add(graph, "p", spawned_by="gp")
        _add(graph, "c", spawned_by="p")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="c",
            direct_state="active",
            institutional_states={
                "gp": "suspended",
                "p": "active",
                "c": "active",
            },
            at=NOW,
        )
        assert result.effective_state == "suspended"
        assert result.inherited_from == "gp"
        assert result.chain_length == 2

    def test_credited_is_not_more_restrictive_than_active(self, graph):
        """Credited is rehabilitation overlay — restrictiveness 0."""
        _add(graph, "p")
        _add(graph, "c", spawned_by="p")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="c",
            direct_state="active",
            institutional_states={"p": "credited", "c": "active"},
            at=NOW,
        )
        assert result.effective_state == "active"
        assert result.inherited_from is None


class TestCycleAndDepth:
    def test_cycle_does_not_loop_forever(self, graph):
        # Misconfigured fixture: a -> b -> a. The walk starts at a, walks
        # to b, then sees a in the visited set and stops.
        _add(graph, "a", spawned_by="b")
        _add(graph, "b", spawned_by="a")
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="a",
            direct_state="active",
            institutional_states={"a": "active", "b": "fined"},
            at=NOW,
        )
        # The walk picks up b's fined state then breaks on the cycle.
        assert result.effective_state == "fined"

    def test_max_depth_caps_walk(self, graph):
        # Long chain of 50 — with max_depth=3 we only see the first 3.
        _add(graph, "n0")
        for i in range(1, 51):
            _add(graph, f"n{i}", spawned_by=f"n{i - 1}")
        states = {f"n{i}": "active" for i in range(51)}
        states["n40"] = "suspended"  # restrictive state far up the chain

        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="n50",
            direct_state="active",
            institutional_states=states,
            at=NOW,
            max_depth=3,
        )
        # Walked 3 ancestors (n49, n48, n47) — did NOT reach n40.
        assert result.effective_state == "active"
        assert result.chain_length == 3


class TestCustomRestrictiveness:
    def test_custom_ordering_override(self, graph):
        _add(graph, "p")
        _add(graph, "c", spawned_by="p")
        custom = {"under_audit": 5, "active": 0}
        result = resolve_effective_state(
            graph=graph,
            actor_entity_id="c",
            direct_state="active",
            institutional_states={"p": "under_audit", "c": "active"},
            at=NOW,
            restrictiveness=custom,
        )
        assert result.effective_state == "under_audit"


class TestCanonicalRestrictiveness:
    def test_ordering_is_active_credited_warning_fined_suspended(self):
        """The canonical ordering matches arxiv 2601.11369 Figure 2."""
        assert CANONICAL_RESTRICTIVENESS["active"] == 0
        assert CANONICAL_RESTRICTIVENESS["credited"] == 0
        assert CANONICAL_RESTRICTIVENESS["warning"] == 1
        assert CANONICAL_RESTRICTIVENESS["fined"] == 2
        assert CANONICAL_RESTRICTIVENESS["suspended"] == 3
