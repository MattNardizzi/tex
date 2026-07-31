"""
Subagent state inheritance for the institutional governance layer.

Post-cutoff motivation (May 8, 2026): arxiv 2605.08460 (Cai/Zhang/Hei,
"When Child Inherits: Modeling and Exploiting Subagent Spawn in
Multi-Agent Networks") shows that when one agent in a multi-agent
network is compromised, delegated subagents inherit the compromise — and
existing defenses do not propagate sanction or quarantine state across
spawn relationships. Their experiments demonstrate a class of attacks
where the parent agent passes its compromised state to spawned children
who continue acting under a clean reputation.

Mapped onto Tex's institutional layer (arxiv 2601.11369): if an actor
is in ``fined`` or ``suspended`` and spawns a subagent, the subagent
must inherit at least the *most restrictive* state in its parent chain.
Otherwise the institutional regime is trivially defeated by spawning a
fresh "clean" delegate.

This module is read-only graph traversal. It does NOT mutate the graph,
does NOT execute code, does NOT call out to any service. It walks the
``spawned_by`` attribute chain in the temporal knowledge graph to
compute the *effective* institutional state for legality checks in
``EcosystemEngine`` step 4.

Ontology note
-------------
The Tex ontology does NOT (yet) have an ``AGENT_SPAWNS_AGENT`` EventKind.
Subagent relationships are inferred from a ``spawned_by`` entity
attribute set at ``add_entity`` time:

    graph.add_entity(
        entity_id="subagent_42",
        kind="agent",
        attrs={"spawned_by": "parent_agent", "registered_at": ...},
    )

A future thread (Thread 2.5) will promote this to a first-class
EventKind so spawn relationships participate in the temporal lineage
and can be queried at a point in time. Today we read the attribute
verbatim and treat it as static.

Cycle safety
------------
Walks the chain with a visited-set guard. Cycles cannot occur if the
graph is built monotonically (you cannot spawn an entity that doesn't
exist yet, and you cannot retroactively make A the parent of A's
ancestor) — but defence in depth handles a misconfigured fixture.

Depth bound
-----------
The walk stops at a default depth of 32 ancestors. A spawn chain longer
than 32 is almost certainly a configuration error; we cap rather than
walk indefinitely. The bound is exposed as a constructor argument so
tests can lower it for verification.

Reference
---------
- arxiv 2605.08460 (Cai/Zhang/Hei, May 8 2026): subagent-spawn
  compromise in multi-agent networks
- arxiv 2601.11369 (Bracale Syrnikov et al., Jan 2026) §4.2: legal-state
  ordering used to define "most restrictive"
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from tex.observability.telemetry import emit_event


# Restrictiveness ordering for the canonical Cournot states. Higher
# integer = more restrictive. The ordering is partial; states not in
# this map are treated as restrictiveness 0 ("unknown — least
# restrictive"). Manifests using non-canonical state ids should call
# ``EffectiveStateResolver`` with an override mapping.
#
# Reference: arxiv 2601.11369 §4.2 (Figure 2: state graph) and Appendix
# C (notice templates ordered by severity).
CANONICAL_RESTRICTIVENESS: dict[str, int] = {
    "active": 0,
    "credited": 0,  # rehabilitation overlay — no more restrictive than active
    "warning": 1,
    "fined": 2,
    "suspended": 3,
}


class _GraphReader(Protocol):
    """Minimal protocol the temporal knowledge graph must satisfy."""

    def get_entity_at(self, entity_id: str, at: datetime) -> dict | None: ...

    def _has_entity(self, entity_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class InheritedState:
    """
    The effective institutional state for an actor after walking its
    spawn-parent chain.

    Fields
    ------
    actor_entity_id
        The actor whose effective state was resolved.
    direct_state
        The state explicitly held by ``actor_entity_id``, before any
        inheritance is applied.
    effective_state
        The most-restrictive state across the actor and its ancestors.
        Equals ``direct_state`` when no ancestor is more restrictive.
    inherited_from
        Entity id of the ancestor whose state was selected. ``None``
        when ``effective_state == direct_state`` (no inheritance).
    chain_length
        Number of ancestors walked. 0 when ``actor_entity_id`` has no
        ``spawned_by`` attribute.
    """

    actor_entity_id: str
    direct_state: str
    effective_state: str
    inherited_from: str | None
    chain_length: int


def resolve_effective_state(
    *,
    graph: _GraphReader,
    actor_entity_id: str,
    direct_state: str,
    institutional_states: dict[str, str],
    at: datetime,
    max_depth: int = 32,
    restrictiveness: dict[str, int] | None = None,
) -> InheritedState:
    """
    Resolve the most-restrictive institutional state for ``actor_entity_id``
    by walking its ``spawned_by`` chain.

    Parameters
    ----------
    graph
        Temporal knowledge graph the actor is registered in. Used to read
        the ``spawned_by`` attribute via ``get_entity_at``.
    actor_entity_id
        The actor whose effective state we want.
    direct_state
        The actor's own institutional state from ``institutional_states``.
    institutional_states
        Mapping ``entity_id -> state_id`` for all known actors. Ancestors
        not in this mapping are treated as ``"active"`` (no contribution).
    at
        Point in time at which to read entity attributes. Typically
        ``proposed.proposed_at``.
    max_depth
        Maximum ancestors to walk. Defaults to 32. Caps pathological
        chains.
    restrictiveness
        Optional override of the state-restrictiveness ordering.
        Defaults to ``CANONICAL_RESTRICTIVENESS``. State ids absent from
        the mapping are treated as restrictiveness 0.

    Returns
    -------
    InheritedState
        Frozen dataclass with the resolution result.

    Notes
    -----
    This is a *pure read* — never mutates the graph, never calls out.
    Cycle detection is via a visited-set guard; a misconfigured graph
    that cycles back to itself returns the most-restrictive state seen
    so far without infinite-looping.
    """
    order = restrictiveness or CANONICAL_RESTRICTIVENESS

    visited: set[str] = {actor_entity_id}
    best_state = direct_state
    best_score = order.get(direct_state, 0)
    inherited_from: str | None = None
    chain_length = 0

    current = actor_entity_id
    for _ in range(max_depth):
        attrs = graph.get_entity_at(current, at)
        if attrs is None:
            break
        parent = attrs.get("spawned_by")
        if not isinstance(parent, str) or not parent:
            break
        if parent in visited:
            # Cycle — stop. Telemetry so operators see the bad config.
            emit_event(
                "tex.institutional.subagent_inheritance.cycle_detected",
                actor=actor_entity_id,
                parent=parent,
                chain_length=chain_length,
            )
            break
        visited.add(parent)
        chain_length += 1

        parent_state = institutional_states.get(parent, "active")
        parent_score = order.get(parent_state, 0)
        if parent_score > best_score:
            best_state = parent_state
            best_score = parent_score
            inherited_from = parent

        current = parent

    return InheritedState(
        actor_entity_id=actor_entity_id,
        direct_state=direct_state,
        effective_state=best_state,
        inherited_from=inherited_from,
        chain_length=chain_length,
    )


__all__ = [
    "InheritedState",
    "resolve_effective_state",
    "CANONICAL_RESTRICTIVENESS",
]
