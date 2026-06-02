"""
Per-layer latency breakdown for a single Tex evaluation.

This is first-class on the response because "how fast" is the first
real question after any demo. Surfacing per-layer numbers lets a buyer
see at a glance whether the semantic layer is dominating (it usually
is), whether deterministic is under 10ms (it should be), and what the
total evaluation wall-clock was.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class LatencyBreakdown(BaseModel):
    """
    Wall-clock latency for each stage of the Tex evaluation pipeline.

    All values are milliseconds, rounded to two decimals. The ``total_ms``
    field is measured end-to-end by the PDP and is not necessarily equal
    to the sum of per-stage values, because there is small coordination
    overhead between stages.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    deterministic_ms: float = Field(ge=0.0, description="Deterministic gate wall-clock.")
    retrieval_ms: float = Field(ge=0.0, description="Retrieval orchestrator wall-clock.")
    agent_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Agent evaluation suite wall-clock (identity + capability + behavioral).",
    )
    specialists_ms: float = Field(ge=0.0, description="Specialist suite wall-clock.")
    semantic_ms: float = Field(ge=0.0, description="Semantic analyzer wall-clock.")
    router_ms: float = Field(ge=0.0, description="Fusion router wall-clock.")
    total_ms: float = Field(ge=0.0, description="End-to-end evaluation wall-clock.")

    @property
    def dominant_stage(self) -> str:
        """Return the name of the stage that took the most time."""
        candidates = (
            ("deterministic", self.deterministic_ms),
            ("retrieval", self.retrieval_ms),
            ("agent", self.agent_ms),
            ("specialists", self.specialists_ms),
            ("semantic", self.semantic_ms),
            ("router", self.router_ms),
        )
        return max(candidates, key=lambda item: item[1])[0]
