"""
Bridge between the existing six-layer router and the ecosystem engine.

The ecosystem layer pivots Tex from per-action verdicts to ecosystem-state
assessment. The six-layer pipeline (deterministic + specialists + semantic +
criticality + agent + fusion) still emits a ``RoutingResult`` per action —
that result is itself an event in the ecosystem graph and must be recorded
as a ``VERDICT_EMITTED`` typed event in the append-only ledger.

This module is the *only* coupling point. The existing ``DecisionRouter``,
``PolicyDecisionPoint``, and tests in ``tests/test_router.py`` /
``tests/test_pdp.py`` are not modified by Thread 10 — they emit
``RoutingResult`` exactly as before, and a separate caller (the runtime
composition root, future thread) chooses whether to forward it through this
bridge.

Direction
---------
Forward (P0): RoutingResult -> ProposedEvent -> EcosystemEngine.evaluate
              -> ledger entry of EventKind.VERDICT_EMITTED

Reverse (P1, stub): ecosystem FORBID -> kill-switch back to the six-layer
                    pipeline. Slot reserved; not implemented in P0.

Reference
---------
- AAF (arxiv 2512.18561) §4.2: every verdict is itself an interaction
  event in the provenance ledger.
- Institutional AI (arxiv 2601.10599) §3: VERDICT events participate in
  the LTS the same way action events do.

Priority: P0.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tex.domain.verdict import Verdict
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdict
from tex.engine.router import RoutingResult
from tex.observability.telemetry import emit_event
from tex.ontology.event_types import EventKind


def routing_result_to_proposed_event(
    *,
    routing_result: RoutingResult,
    actor_entity_id: str,
    proposed_at: datetime,
    request_id: str | None = None,
    upstream_event_ids: tuple[str, ...] = (),
    extra_payload: dict[str, Any] | None = None,
) -> ProposedEvent:
    """
    Convert a six-layer RoutingResult into an ecosystem-level ProposedEvent.

    The resulting ProposedEvent has ``event_kind = "verdict_emitted"`` and a
    payload that captures the underlying action verdict, the fused score and
    confidence, the per-layer scores dict, a count of findings/asi_findings,
    and whether the semantic-dominance override fired.

    Why the *count* of findings instead of the findings themselves:
    ``EventKind.VERDICT_EMITTED`` has a permissive payload schema (no
    typed model) and the underlying ``canonical_json`` rejects non-JSON
    types (frozen pydantic models, datetimes other than top-level fields,
    etc.). The full findings list belongs in the durable ``Decision``
    record the six-layer pipeline already writes; the ecosystem ledger
    stores the *fact that a verdict was emitted* plus enough metadata to
    reason about it later.

    Numeric scores are rounded to 4 decimal places and serialized as the
    canonical-JSON-friendly fixed-point integer ``round(value * 10_000)``
    so they survive the float-rejection in
    ``tex.events._canonical.canonical_json``. Verifiers reverse the
    transform by dividing by 10_000.

    Parameters
    ----------
    routing_result
        The fused output of the six-layer pipeline.
    actor_entity_id
        The agent (or "tex" itself, for tex-emitted policy decisions) that
        produced this verdict. Must be a registered ecosystem entity for
        ``EcosystemEngine.evaluate`` to admit it.
    proposed_at
        Timezone-aware datetime; usually the request's ``requested_at``
        plus the pipeline latency.
    request_id
        Carried into ``session_id`` so ledger consumers can join across
        request-level tracing.
    upstream_event_ids
        IDs of prior ecosystem events that causally enabled this verdict
        (e.g., the proposing agent's ``AGENT_EMITS_OUTPUT`` event).
    extra_payload
        Optional caller-provided dict merged into the payload. Must be
        canonical-JSON-friendly (no floats; ints/strs/bools/None/dicts/lists).
    """
    # Score dict: ints-as-ten-thousandths so canonical_json accepts them.
    layer_scores_fixed_point = {
        key: round(value * 10_000)
        for key, value in routing_result.scores.items()
    }

    payload: dict[str, Any] = {
        "verdict": routing_result.verdict.value,
        "confidence_x10000": round(routing_result.confidence * 10_000),
        "final_score_x10000": round(routing_result.final_score * 10_000),
        "layer_scores_x10000": layer_scores_fixed_point,
        "finding_count": len(routing_result.findings),
        "asi_finding_count": len(routing_result.asi_findings),
        "uncertainty_flag_count": len(routing_result.uncertainty_flags),
        "reason_count": len(routing_result.reasons),
        "semantic_dominance_override_fired": (
            routing_result.semantic_dominance_override_fired
        ),
    }

    if extra_payload:
        # Reject the structural keys we own to prevent accidental clobber.
        reserved = set(payload.keys())
        collisions = reserved & set(extra_payload.keys())
        if collisions:
            raise ValueError(
                f"extra_payload may not override reserved keys: {sorted(collisions)}"
            )
        payload.update(extra_payload)

    return ProposedEvent(
        event_kind=EventKind.VERDICT_EMITTED.value,
        actor_entity_id=actor_entity_id,
        target_entity_id=None,
        payload=payload,
        proposed_at=proposed_at,
        session_id=request_id,
        upstream_event_ids=upstream_event_ids,
    )


class EcosystemBridge:
    """
    Thin wrapper that ties a ``DecisionRouter`` output to an
    ``EcosystemEngine``.

    Holds no router or PDP state — the existing engine/router code is
    untouched. The bridge is the integration boundary that future runtime
    composition roots (post-Thread 10) plug into.
    """

    def __init__(self, *, engine: EcosystemEngine) -> None:
        self._engine = engine

    def emit_verdict(
        self,
        *,
        routing_result: RoutingResult,
        actor_entity_id: str,
        proposed_at: datetime,
        request_id: str | None = None,
        upstream_event_ids: tuple[str, ...] = (),
        extra_payload: dict[str, Any] | None = None,
    ) -> EcosystemVerdict:
        """
        Forward a ``RoutingResult`` into the ecosystem ledger.

        Returns the ``EcosystemVerdict`` produced by ``evaluate``. When the
        engine is disabled (``TEX_ECOSYSTEM=0``) the verdict is the inert
        PERMIT and no graph/ledger mutation occurs — this is the explicit
        guarantee that the existing six-layer pipeline runs unchanged.
        """
        proposed = routing_result_to_proposed_event(
            routing_result=routing_result,
            actor_entity_id=actor_entity_id,
            proposed_at=proposed_at,
            request_id=request_id,
            upstream_event_ids=upstream_event_ids,
            extra_payload=extra_payload,
        )
        verdict = self._engine.evaluate(proposed)
        emit_event(
            "ecosystem.bridge.verdict_emitted",
            action_verdict=routing_result.verdict.value,
            ecosystem_verdict=verdict.kind.value,
            actor_entity_id=actor_entity_id,
            request_id=request_id,
            evidence_record_id=verdict.evidence_record_id,
        )
        return verdict


__all__ = [
    "EcosystemBridge",
    "routing_result_to_proposed_event",
    "Verdict",  # re-exported for caller convenience
]
