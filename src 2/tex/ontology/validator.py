"""
Ontology validator.

Type-checks proposed events against the entity and event registries.

Pure type system. No store I/O. Upstream-existence checking is delegated
to an injected ``EventLookup`` protocol the caller wires up at the
ecosystem-engine layer (matches the existing ``SpecialistJudge`` pattern
elsewhere in Tex).

Priority: P0.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from tex.ecosystem.proposed_event import ProposedEvent
from tex.observability.telemetry import emit_event
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry


@runtime_checkable
class EventLookup(Protocol):
    """
    Protocol for upstream-event existence checks.

    Injected by the caller (typically the ecosystem engine) so the ontology
    package itself stays pure-types. If no lookup is wired, upstream checks
    are skipped and a single soft-warning telemetry event is emitted.
    """

    def exists(self, event_id: str) -> bool: ...


class OntologyValidator:
    """
    Validates ProposedEvents against the registries.

    Four checks, in order:
      1. event_kind resolves to a known EventKind
      2. payload validates against the event's payload schema
      3. actor_entity_id is non-empty
      4. upstream_event_ids all resolve via the injected EventLookup
         (skipped with a soft warning if no lookup was provided)
    """

    def __init__(
        self,
        *,
        entity_registry: EntityTypeRegistry,
        event_registry: EventTypeRegistry,
        event_lookup: EventLookup | None = None,
    ) -> None:
        self._entities = entity_registry
        self._events = event_registry
        self._event_lookup = event_lookup

    def validate_event(
        self, proposed: ProposedEvent
    ) -> tuple[bool, tuple[str, ...]]:
        """
        Returns (is_valid, error_messages).

        TODO(P0): event_kind must resolve in the EventTypeRegistry
        TODO(P0): actor_entity_id must resolve to an active entity
        TODO(P0): payload must conform to event schema
        TODO(P0): upstream_event_ids must all exist in the ledger

        The ``actor_entity_id must resolve to an active entity`` TODO is
        partially satisfied here (we enforce non-empty). Resolution against
        the live entity store is the ecosystem-engine's job, since the
        ontology package is pure types.
        """
        errors: list[str] = []

        # 1. event_kind resolves
        kind: EventKind | None = None
        try:
            kind = EventKind(proposed.event_kind)
        except ValueError:
            errors.append(
                f"unknown event_kind {proposed.event_kind!r}"
            )

        # 2. payload validates against schema (only if kind resolved)
        if kind is not None:
            payload_model = self._events.payload_model_for(kind)
            if payload_model is not None:
                try:
                    payload_model.model_validate(proposed.payload)
                except ValidationError as exc:
                    errors.append(
                        f"payload schema violation for {kind.value}: "
                        f"{_format_validation_error(exc)}"
                    )

        # 3. actor_entity_id non-empty
        if not proposed.actor_entity_id or not proposed.actor_entity_id.strip():
            errors.append("actor_entity_id must be a non-empty string")

        # 4. upstream_event_ids all resolve (if lookup wired)
        if proposed.upstream_event_ids:
            if self._event_lookup is None:
                emit_event(
                    "ontology.validation.upstream_skipped",
                    upstream_count=len(proposed.upstream_event_ids),
                    event_kind=proposed.event_kind,
                )
            else:
                for upstream_id in proposed.upstream_event_ids:
                    if not self._event_lookup.exists(upstream_id):
                        errors.append(
                            f"upstream_event_id {upstream_id!r} not found in ledger"
                        )

        ok = not errors
        if ok:
            emit_event(
                "ontology.validation.ok",
                event_kind=proposed.event_kind,
                actor_entity_id=proposed.actor_entity_id,
            )
        else:
            emit_event(
                "ontology.validation.failed",
                event_kind=proposed.event_kind,
                actor_entity_id=proposed.actor_entity_id,
                error_count=len(errors),
            )
        return ok, tuple(errors)


def _format_validation_error(exc: ValidationError) -> str:
    """Compact one-line summary of a pydantic ValidationError."""
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(parts)
