"""
Structured audit events emitted by every gated execution.

Every call through a TexGate produces exactly one GateEvent. Callers
plug in an observer to route events to logs, metrics, an audit
backend, or whatever they like. The default observer is a no-op so
the gate has zero overhead when nobody cares.

Event shape is intentionally minimal but complete: who was gated
(action_type, agent_id), what Tex said (verdict, decision_id,
fingerprint), and what the gate did (executed, blocked, reviewed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GateEvent:
    """
    One audit-grade record of a gated action's outcome.

    Frozen and slotted because we want it cheap to construct and safe
    to fan out to multiple observers. Everything in here either came
    from the inputs the caller already has, or from the Tex response.
    No I/O happens to build a GateEvent.
    """

    # --- request side ------------------------------------------------
    request_id: UUID
    action_type: str
    channel: str
    environment: str
    recipient: str | None
    agent_id: UUID | None

    # --- decision side -----------------------------------------------
    verdict: str  # PERMIT / ABSTAIN / FORBID / UNAVAILABLE
    decision_id: UUID | None
    determinism_fingerprint: str | None
    final_score: float | None
    confidence: float | None

    # --- gate side ---------------------------------------------------
    # What the gate physically did with the action:
    #   "executed"  — the wrapped callable ran
    #   "blocked"   — the wrapped callable did NOT run (FORBID, or
    #                 ABSTAIN with policy=BLOCK, or UNAVAILABLE with
    #                 fail_closed=True)
    #   "reviewed"  — the gate raised TexAbstainError for the caller
    #                 to route to human review
    outcome: str

    abstain_policy: str  # the policy that was active at decision time
    fail_closed: bool

    # Wall-clock latency of the entire gate, including the Tex call.
    # Useful for SLA dashboards.
    gate_latency_ms: float

    # Free-form extra fields. Adapter-specific context (HTTP status,
    # framework name, etc.) goes here so the core schema stays stable.
    details: dict[str, Any] = field(default_factory=dict)

    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@runtime_checkable
class GateEventObserver(Protocol):
    """
    Observer protocol for gate events.

    Implementations should not raise. The gate calls observers in a
    try/except that suppresses observer failures so a buggy logger
    never breaks enforcement. Implementations should also be cheap —
    the gate is on the hot path of every agent action.
    """

    def __call__(self, event: GateEvent) -> None: ...


class NullObserver:
    """No-op observer. Default. Zero overhead."""

    __slots__ = ()

    def __call__(self, event: GateEvent) -> None:  # pragma: no cover - trivial
        return None


class CollectingObserver:
    """
    In-memory observer that retains every event it sees.

    Useful for testing and for short-lived processes. Not a substitute
    for a real audit pipeline in production.
    """

    __slots__ = ("events",)

    def __init__(self) -> None:
        self.events: list[GateEvent] = []

    def __call__(self, event: GateEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()
