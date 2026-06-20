"""Tex Presence — the truth-gate (Session 2, the heart).

A deterministic, external gate that turns each candidate :class:`PresenceClaim`
into one monotone :class:`PresenceVerdict`. Aggregates are RECOMPUTED from sealed
rows (the model never counts); DERIVED claims carry a conformal correctness floor
with an honest coverage mode; everything else, and anything a hostile draft tries
to assert, fails closed to ABSTAIN.

Public surface::

    from tex.presence.gate import PresenceTruthGate, run_presence

``PresenceTruthGate`` implements the contract's ``TruthGate`` protocol;
``run_presence`` is the orchestrator the voice seam calls to produce an
``AnswerEnvelope`` (or ``None`` when presence is not engaged).
"""

from __future__ import annotations

from tex.presence.gate.compose import (
    PRESENCE_HOLD_AGENT_ID,
    build_envelope,
    raise_presence_hold,
    run_presence,
)
from tex.presence.gate.conformal import derive_root_cause_region
from tex.presence.gate.gate import ClaimEvaluation, PresenceTruthGate, RoutedClaim
from tex.presence.gate.queries import QUERIES, EVIDENCE_CAP, PresenceQuery, Recompute
from tex.presence.gate.telemetry import PresenceTelemetry

__all__ = [
    "PresenceTruthGate",
    "ClaimEvaluation",
    "RoutedClaim",
    "Recompute",
    "PresenceQuery",
    "QUERIES",
    "EVIDENCE_CAP",
    "PresenceTelemetry",
    "build_envelope",
    "run_presence",
    "raise_presence_hold",
    "derive_root_cause_region",
    "PRESENCE_HOLD_AGENT_ID",
]
