"""
Exception hierarchy for the temporal knowledge graph.

All add-time failures are subclasses of ``GraphMutationError`` so callers can
branch on cause without catching a bare ValueError. Mirrors the layout of
``tex.events.exceptions``.

Priority: P0.
"""

from __future__ import annotations


class GraphMutationError(Exception):
    """Base class for any failure during InMemoryTemporalKG mutation."""


class EntityAlreadyExistsError(GraphMutationError):
    """An entity with the same id is already registered (use a new version add)."""


class UnknownActorError(GraphMutationError):
    """The event's actor_entity_id is not registered in the graph."""


class UnknownTargetError(GraphMutationError):
    """The event's target_entity_id is not registered in the graph."""


class MissingUpstreamEventError(GraphMutationError):
    """One or more upstream_event_ids do not resolve to stored events."""


class DuplicateEventIdError(GraphMutationError):
    """An event with the same event_id is already stored in the graph."""


class NaiveDatetimeError(GraphMutationError, TypeError):
    """A timestamp was supplied without timezone info."""


class UnknownEntityError(GraphMutationError):
    """A versioned add_entity call referenced an entity that does not exist yet."""


class UnknownEventError(GraphMutationError):
    """A causal_ancestors query referenced an event_id that is not stored."""
