"""
EcosystemState — read-only snapshot of the ecosystem at a point in time.

A projection of the temporal knowledge graph at timestamp T. Contains:
  - all active entities (agents, tools, datasets, ...)
  - all active capability grants
  - all policies in effect
  - aggregate drift signals
  - the active institutional governance graph version
  - cumulative compromise ratio over a sliding window
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EcosystemState(BaseModel):
    """A read-only ecosystem snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_at: datetime
    state_hash: str  # SHA-256 over canonicalized state
    active_agent_ids: tuple[str, ...]
    active_tool_ids: tuple[str, ...]
    active_capability_ids: tuple[str, ...]
    active_governance_graph_id: str
    aggregate_drift_signals: dict[str, float] = Field(default_factory=dict)
    sliding_window_compromise_ratio: float = Field(default=0.0, ge=0, le=1)
