"""
ProposedEvent — the input to EcosystemEngine.evaluate.

Distinct from `events.Event` (which is the persisted ledger record):
ProposedEvent is the *candidate* before the engine has decided whether to
admit it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProposedEvent(BaseModel):
    """A candidate event awaiting ecosystem evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_kind: str  # one of EventKind values from ontology
    actor_entity_id: str
    target_entity_id: str | None = None
    payload: dict[str, Any]
    proposed_at: datetime
    session_id: str | None = None
    upstream_event_ids: tuple[str, ...] = Field(default_factory=tuple)
