"""
Denial record — the in-memory representation of a denied tool call,
mirroring the DENIAL_EVENT that gets written to the ledger.

ARM (arxiv 2604.04035 §3.7, §4.5) treats denied actions as first-class
events. In Tex, this maps to two artifacts:

  1. A ``DeniedActionNode`` in the in-memory provenance graph
     (see ``tex.causal._provenance_graph``).
  2. A ``DENIAL_EVENT`` appended to the existing hash-chained event
     ledger (``tex.events.ledger.InMemoryLedger``) using the
     ``EventKind.DENIAL_EVENT`` schema already registered in
     ``tex.ontology.event_types``.

The ``DenialRecord`` dataclass captures both artifacts' shared
identity so the ARM API can return a single value without leaking the
graph or ledger types.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DenialRecord(BaseModel):
    """
    Frozen record of one denied tool call.

    ``provenance_node_id`` is the in-graph node ID of the
    ``DeniedAction`` node; ``ledger_event_id`` is the ID of the
    ``DENIAL_EVENT`` in the event ledger when ARM is wired with one,
    otherwise ``None``.

    Reference: arxiv 2604.04035 §3.7 (denied actions as first-class
    nodes); §4.5 (hash-chained audit log).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    denial_id: str = Field(min_length=1, max_length=256)
    denied_event_id: str = Field(min_length=1, max_length=256)
    denied_tool_name: str = Field(min_length=1, max_length=256)
    denial_reason: str = Field(min_length=1, max_length=1_000)
    timestamp: datetime
    counterfactual_target_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    provenance_node_id: str = Field(min_length=1, max_length=256)
    ledger_event_id: str | None = None
