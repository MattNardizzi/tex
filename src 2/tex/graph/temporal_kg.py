"""
Temporal knowledge graph backbone.

Stores typed entities (nodes) and typed events (edges) with full temporal
attributes. Every event is append-only; entity attribute changes are
recorded as new EntityVersion edges.

Implementation
--------------
P0 in-memory backend over ``networkx.MultiDiGraph``. Each entity is one node;
each event is one directed edge (actor -> target, or actor -> actor self-edge
when ``target is None`` so that pure-emission events still participate in
graph-walks). A parallel per-entity version timeline carries snapshot dicts
so ``get_entity_at`` is a simple bisect over insertion-ordered timestamps.

Conventions inherited from Thread 2
-----------------------------------
* Canonical hashing: ``tex.events._canonical.canonical_json`` /
  ``canonical_sha256``. Floats are rejected at canonicalization time;
  graph attrs/payloads must be ``str | int | bool | None | dict | list``
  (see ``events/_canonical.py`` module docstring).
* Telemetry: ``emit_event("graph.kg.<verb>", ...)`` namespaced like
  ``events.ledger.appended``. No ``print``, no ``logging`` directly.
* Exception hierarchy: every mutation error subclasses ``GraphMutationError``
  in ``tex.graph.exceptions``, mirroring ``events.exceptions.LedgerAppendError``.

State-hash schema
-----------------
``state_hash(at)`` canonicalizes ``{"schema_version": "1", "entities": [...],
"events": [...]}`` and returns its SHA-256. ``schema_version`` is always the
first key. The empty-graph hash is therefore pinned and reproducible across
processes; bumping the schema is a one-line change.

Priority: P0.

References
----------
- Zep / Graphiti temporal-aware knowledge graph
- arxiv 2602.05665 (Graph-based Agent Memory: Taxonomy, Techniques, Applications)
"""

from __future__ import annotations

import json
from bisect import bisect_right
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

import networkx as nx

from tex.events._canonical import canonical_json, canonical_sha256
from tex.graph.exceptions import (
    DuplicateEventIdError,
    MissingUpstreamEventError,
    NaiveDatetimeError,
    UnknownActorError,
    UnknownEntityError,
    UnknownEventError,
    UnknownTargetError,
)
from tex.observability.telemetry import emit_event


# Bumped only when the canonical state-hash structure changes shape.
# Pinned by tests; downgrades require a deliberate code change here.
STATE_HASH_SCHEMA_VERSION: str = "1"


class TemporalKnowledgeGraph(Protocol):
    def add_entity(self, *, entity_id: str, kind: str, attrs: dict) -> None: ...
    def add_event(self, *, event_id: str, kind: str, actor: str, target: str | None,
                  payload: dict, timestamp: datetime, upstream: tuple[str, ...]) -> None: ...
    def get_entity_at(self, entity_id: str, at: datetime) -> dict | None: ...
    def neighbors(self, entity_id: str, *, edge_kinds: tuple[str, ...] | None = None,
                  within: tuple[datetime, datetime] | None = None) -> tuple[dict, ...]: ...
    def state_hash(self, at: datetime) -> str: ...


class InMemoryTemporalKG:
    """
    In-memory temporal knowledge graph backbone for dev/tests/small deployments.

    Backed by a ``networkx.MultiDiGraph`` (nodes = entities, edges = events) and
    a per-entity append-only version timeline. Time-travel reads walk the
    timeline; structural reads walk the graph; reproducible state hashes walk
    both and pipe them through Thread 2's canonicalizer.

    Reference: Zep/Graphiti + arxiv 2602.05665.
    """

    def __init__(self) -> None:
        # MultiDiGraph: many parallel events between the same (actor, target).
        # Keys are event_ids so each edge is uniquely addressable.
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        # entity_id -> list of (timestamp, attrs_snapshot). Append-only;
        # snapshots are full dicts (not deltas) to keep get_entity_at O(log n)
        # via bisect with no rebuild step. Each version is also frozen via a
        # canonical_json round-trip at insert time so it is hash-safe.
        self._versions: dict[str, list[tuple[datetime, dict[str, Any]]]] = {}
        # event_id -> stored payload tuple for fast lookup by id (used by
        # causal_ancestors and duplicate-id detection without walking edges).
        self._events_by_id: dict[str, _StoredEvent] = {}

    # ------------------------------------------------------------------ writes

    def add_entity(
        self,
        *,
        entity_id: str,
        kind: str,
        attrs: dict[str, Any],
    ) -> None:
        """
        Register an entity, or append a new versioned snapshot if one already
        exists. New attrs are merged into the previous snapshot (delta-style)
        and the merged snapshot is appended to the version timeline.

        TODO(P0): append-only entity registration  [done — versioned timeline]
        TODO(P1): pgvector embedding column on the Postgres mirror.

        Reference: Zep/Graphiti + arxiv 2602.05665 (Graph-based Agent Memory).

        ``attrs`` must contain a timezone-aware ``registered_at`` datetime
        which becomes the version timestamp. Subsequent re-adds must monotone-
        advance that timestamp.

        Raises
        ------
        TypeError                if entity_id/kind are not non-empty strings,
                                 or attrs is not a mapping
        NaiveDatetimeError       if registered_at is naive
        ValueError               if entity kind changes across re-adds, or if
                                 the new version timestamp precedes the prior
                                 one
        """
        if not isinstance(entity_id, str) or not entity_id:
            raise TypeError("entity_id must be a non-empty string")
        if not isinstance(kind, str) or not kind:
            raise TypeError("kind must be a non-empty string")
        if not isinstance(attrs, Mapping):
            raise TypeError("attrs must be a mapping")

        now = _ensure_aware(attrs.get("registered_at"))

        frozen_attrs = _freeze(dict(attrs))
        timeline = self._versions.get(entity_id)

        if timeline is None:
            # First registration: kind is locked here and lives on the node.
            self._graph.add_node(entity_id, kind=kind)
            self._versions[entity_id] = [(now, frozen_attrs)]
            version = 1
        else:
            # Versioned re-add: kind must match (entities don't change kind).
            existing_kind = self._graph.nodes[entity_id].get("kind")
            if existing_kind != kind:
                raise ValueError(
                    f"entity {entity_id!r} kind changed from "
                    f"{existing_kind!r} to {kind!r}; entity kinds are immutable"
                )
            last_ts, last_snapshot = timeline[-1]
            if now < last_ts:
                raise ValueError(
                    f"entity {entity_id!r} new version timestamp {now.isoformat()} "
                    f"precedes prior version {last_ts.isoformat()}"
                )
            merged = dict(last_snapshot)
            merged.update(frozen_attrs)
            merged = _freeze(merged)
            timeline.append((now, merged))
            version = len(timeline)

        emit_event(
            "graph.kg.entity_added",
            entity_id=entity_id,
            kind=kind,
            version=version,
            registered_at=now.isoformat(),
        )

    def add_event(
        self,
        *,
        event_id: str,
        kind: str,
        actor: str,
        target: str | None,
        payload: dict[str, Any],
        timestamp: datetime,
        upstream: tuple[str, ...],
    ) -> None:
        """
        Append a typed event edge to the graph.

        TODO(P0): append event with upstream-event lineage           [done]
        TODO(P0): assert ontology + ledger pre-existence of upstream [done]
        TODO(P1): pgvector embedding column on the Postgres mirror.

        Reference: Zep/Graphiti + arxiv 2602.05665.

        Validation
        ----------
        * actor must be a registered entity (UnknownActorError)
        * target, if given, must be registered (UnknownTargetError)
        * every upstream id must already be stored (MissingUpstreamEventError);
          enforces the same pre-existence invariant the events ledger does
          via ``MissingUpstreamError``.
        * event_id must be unique (DuplicateEventIdError).
        * timestamp must be timezone-aware (NaiveDatetimeError).
        """
        if not isinstance(event_id, str) or not event_id:
            raise TypeError("event_id must be a non-empty string")
        if not isinstance(kind, str) or not kind:
            raise TypeError("kind must be a non-empty string")
        if not isinstance(actor, str) or not actor:
            raise TypeError("actor must be a non-empty string")
        if target is not None and (not isinstance(target, str) or not target):
            raise TypeError("target must be a non-empty string or None")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        if not isinstance(upstream, tuple):
            raise TypeError("upstream must be a tuple of event_ids")

        ts = _ensure_aware(timestamp)

        if event_id in self._events_by_id:
            raise DuplicateEventIdError(f"event_id {event_id!r} already stored")

        if actor not in self._versions:
            emit_event("graph.kg.actor_missing", event_id=event_id, actor=actor)
            raise UnknownActorError(f"actor {actor!r} is not a registered entity")

        if target is not None and target not in self._versions:
            emit_event("graph.kg.target_missing", event_id=event_id, target=target)
            raise UnknownTargetError(f"target {target!r} is not a registered entity")

        for u in upstream:
            if u not in self._events_by_id:
                emit_event("graph.kg.upstream_missing", event_id=event_id, upstream=u)
                raise MissingUpstreamEventError(
                    f"upstream event_id {u!r} is not stored"
                )

        # Self-edge for pure-emission events so they remain walkable.
        edge_target = target if target is not None else actor
        frozen_payload = _freeze(dict(payload))

        self._graph.add_edge(
            actor,
            edge_target,
            key=event_id,
            event_id=event_id,
            kind=kind,
            payload=frozen_payload,
            timestamp=ts,
            upstream=tuple(upstream),
        )
        self._events_by_id[event_id] = _StoredEvent(
            event_id=event_id,
            kind=kind,
            actor=actor,
            target=target,
            payload=frozen_payload,
            timestamp=ts,
            upstream=tuple(upstream),
        )

        emit_event(
            "graph.kg.event_appended",
            event_id=event_id,
            kind=kind,
            actor=actor,
            target=target,
            timestamp=ts.isoformat(),
            upstream_count=len(upstream),
        )

    # ------------------------------------------------------------------- reads

    def get_entity_at(self, entity_id: str, at: datetime) -> dict[str, Any] | None:
        """
        Return the entity's attribute snapshot as of ``at``, or None if the
        entity had not yet been registered at that time.

        TODO(P0): time-travel query — apply EntityVersion deltas up to `at` [done]
        TODO(P1): vectorized batch get_entities_at for projection.

        Reference: Zep/Graphiti time-travel semantics.
        """
        at = _ensure_aware(at)
        timeline = self._versions.get(entity_id)
        if not timeline:
            return None
        # bisect on the timestamp axis — find rightmost version with ts <= at.
        idx = bisect_right([v[0] for v in timeline], at) - 1
        if idx < 0:
            return None
        # Return a defensive copy so callers can't mutate the stored snapshot.
        return dict(timeline[idx][1])

    def neighbors(
        self,
        entity_id: str,
        *,
        edge_kinds: tuple[str, ...] | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> tuple[dict[str, Any], ...]:
        """
        Return neighboring events (in + out) for an entity, optionally
        filtered by edge kinds and a closed temporal window [start, end].

        TODO(P0): typed-edge neighborhood query with temporal window [done]
        TODO(P1): edge-kind weights for path scoring (see GraphQuery).

        Reference: Zep/Graphiti property-graph neighborhood queries.
        """
        if entity_id not in self._versions:
            return ()
        kinds_set = set(edge_kinds) if edge_kinds is not None else None
        if within is not None:
            start = _ensure_aware(within[0])
            end = _ensure_aware(within[1])
            if start > end:
                raise ValueError("within window: start must be <= end")
        else:
            start = None
            end = None

        out: list[dict[str, Any]] = []

        # Outgoing edges
        for _src, dst, _key, data in self._graph.out_edges(entity_id, keys=True, data=True):
            if not _passes_filters(data, kinds_set, start, end):
                continue
            out.append(_edge_record(actor=entity_id, target=dst, data=data))
        # Incoming edges (skip self-edges already covered above)
        for src, _dst, _key, data in self._graph.in_edges(entity_id, keys=True, data=True):
            if src == entity_id:
                continue
            if not _passes_filters(data, kinds_set, start, end):
                continue
            out.append(_edge_record(actor=src, target=entity_id, data=data))

        # Stable ordering for callers that diff snapshots (timestamp, event_id).
        out.sort(key=lambda r: (r["timestamp"], r["event_id"]))
        return tuple(out)

    def state_hash(self, at: datetime) -> str:
        """
        Return a deterministic SHA-256 over the canonicalized state at ``at``.

        TODO(P0): canonicalized SHA-256 over the projected state at `at`  [done]
        TODO(P1): include drift signals once the drift package lands.
        TODO(P1): RFC 8785 number serialization once float payloads land
                  (currently inherits the float-rejecting policy from
                  tex.events._canonical).

        Reference: Zep/Graphiti immutable-snapshot contract;
                   tex.events._canonical (RFC 8785-subset canonicalizer).

        The empty-graph hash is pinned to::

            sha256_hex(canonical_json({
                "schema_version": "1",
                "entities": [],
                "events": [],
            }))

        Bumping the schema is a one-line change to STATE_HASH_SCHEMA_VERSION.
        """
        state = self._canonical_state_at(_ensure_aware(at))
        return canonical_sha256(state)

    # -------------------------------------------------------- internal helpers

    def _canonical_state_at(self, at: datetime) -> dict[str, Any]:
        """Build the canonical state structure that ``state_hash`` hashes."""
        entity_records: list[dict[str, Any]] = []
        for entity_id in sorted(self._versions.keys()):
            snap = self.get_entity_at(entity_id, at)
            if snap is None:
                continue
            entity_records.append(
                {
                    "id": entity_id,
                    "kind": self._graph.nodes[entity_id]["kind"],
                    "attrs": snap,
                }
            )

        event_records: list[dict[str, Any]] = []
        for event_id, ev in self._events_by_id.items():
            if ev.timestamp > at:
                continue
            event_records.append(
                {
                    "id": event_id,
                    "kind": ev.kind,
                    "actor": ev.actor,
                    "target": ev.target,
                    "payload": ev.payload,
                    "timestamp": ev.timestamp.isoformat(),
                    "upstream": list(ev.upstream),
                }
            )
        # Canonical ordering: events by (timestamp, id), entities already by id.
        event_records.sort(key=lambda r: (r["timestamp"], r["id"]))

        return {
            "schema_version": STATE_HASH_SCHEMA_VERSION,
            "entities": entity_records,
            "events": event_records,
        }

    # Convenience used by GraphQuery without exposing the raw nx graph.
    def _underlying_graph(self) -> nx.MultiDiGraph:
        return self._graph

    def _has_event(self, event_id: str) -> bool:
        return event_id in self._events_by_id

    def _get_event(self, event_id: str) -> _StoredEvent:
        try:
            return self._events_by_id[event_id]
        except KeyError as exc:
            raise UnknownEventError(f"event_id {event_id!r} not stored") from exc

    def _has_entity(self, entity_id: str) -> bool:
        return entity_id in self._versions

    def _entities(self) -> tuple[str, ...]:
        return tuple(self._versions.keys())

    def _entity_kind(self, entity_id: str) -> str:
        if entity_id not in self._versions:
            raise UnknownEntityError(f"entity {entity_id!r} is not registered")
        return self._graph.nodes[entity_id]["kind"]


# ---------------------------------------------------------------- module dataclass

class _StoredEvent:
    """Frozen-by-convention internal record. Not a public type."""

    __slots__ = ("event_id", "kind", "actor", "target", "payload", "timestamp", "upstream")

    def __init__(
        self,
        *,
        event_id: str,
        kind: str,
        actor: str,
        target: str | None,
        payload: dict[str, Any],
        timestamp: datetime,
        upstream: tuple[str, ...],
    ) -> None:
        self.event_id = event_id
        self.kind = kind
        self.actor = actor
        self.target = target
        self.payload = payload
        self.timestamp = timestamp
        self.upstream = upstream


# ----------------------------------------------------------------- pure helpers

def _ensure_aware(value: Any) -> datetime:
    """Coerce ``value`` to a timezone-aware datetime; reject naive inputs."""
    if not isinstance(value, datetime):
        raise TypeError(f"expected datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise NaiveDatetimeError(
            "timestamps must be timezone-aware (use datetime(..., tzinfo=UTC))"
        )
    return value.astimezone(UTC)


def _freeze(value: dict[str, Any]) -> dict[str, Any]:
    """
    Convert aware datetimes to UTC ISO strings, then round-trip through
    canonical_json to (a) reject any unsupported types up front (floats, sets,
    custom objects, naive datetimes) and (b) produce a stable, owned copy
    that downstream code cannot accidentally mutate.

    Datetimes are coerced before canonicalization because callers naturally
    place ``registered_at`` and similar fields in attrs/payloads; the
    Thread 2 canonicalizer rejects datetimes outright (RFC 8785-subset).
    Storing them as ISO strings keeps the state-hash deterministic and
    aligns with how event timestamps are already serialized in
    ``_canonical_state_at``.
    """
    return json.loads(canonical_json(_dt_to_iso(value)))


def _dt_to_iso(value: Any) -> Any:
    """Recursively coerce timezone-aware datetimes to UTC ISO strings.

    Naive datetimes are rejected with NaiveDatetimeError so the failure mode
    matches add_entity / add_event. All other types pass through unchanged
    and are validated by canonical_json downstream.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise NaiveDatetimeError(
                "datetime values in attrs/payload must be timezone-aware"
            )
        return value.astimezone(UTC).isoformat()
    if isinstance(value, dict):
        return {k: _dt_to_iso(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dt_to_iso(v) for v in value]
    return value


def _passes_filters(
    data: Mapping[str, Any],
    kinds_set: set[str] | None,
    start: datetime | None,
    end: datetime | None,
) -> bool:
    if kinds_set is not None and data.get("kind") not in kinds_set:
        return False
    if start is not None and end is not None:
        ts = data.get("timestamp")
        if ts is None or ts < start or ts > end:
            return False
    return True


def _edge_record(
    *,
    actor: str,
    target: str,
    data: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": data["event_id"],
        "kind": data["kind"],
        "actor": actor,
        "target": target,
        "timestamp": data["timestamp"],
        "payload": data["payload"],
        "upstream": data["upstream"],
    }
