"""
The in-process enforcement point, routed through the standing PDP.

``TexGate`` already wraps a callable so it cannot execute unless Tex permits,
and ships framework adapters (LangChain, CrewAI, async). It speaks to Tex
through a ``TexEvaluationTransport``. The transports in the box
(``DirectCommandTransport``, ``HttpClientTransport``) reach the *deep*
evaluator directly — which skips the standing-governance floor: the
fail-closed forbid for an unsealed agent, capability confinement, and
ABSTAIN-to-voice.

``StandingGovernanceTransport`` closes that gap. It routes every gate check
through ``StandingGovernance.decide_for_request`` — the full two-tier PDP — so
the in-process PEP makes exactly the same ruling the network PEPs make at
``/v1/govern/decide``. The deep ``EvaluationResponse`` is passed through
untouched when Tier 2 runs (so the gate's audit, fingerprint, and decision_id
are authoritative); floor verdicts are returned as a synthetic FORBID response
carrying the reason.

``build_standing_gate`` is the one-call constructor: hand it the governor and
you get a ``TexGate`` whose every adapter enforces the complete PDP.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import uuid4

from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.verdict import Verdict
from tex.enforcement.events import GateEventObserver
from tex.enforcement.gate import AbstainPolicy, GateConfig, TexGate
from tex.enforcement.transport import TransportResult
from tex.governance.standing import DecisionOutcome, StandingGovernance

__all__ = ["StandingGovernanceTransport", "build_standing_gate"]


def _floor_response(
    request: EvaluationRequest, outcome: DecisionOutcome
) -> EvaluationResponse:
    """Synthesize an EvaluationResponse for a Tier-1 (floor) verdict.

    The floor decides structurally, without running the deep evaluator, so
    there is no rich response to carry. We mint one whose verdict the gate
    will act on, tagged so any audit can see it was a floor ruling.
    """
    return EvaluationResponse(
        decision_id=outcome.decision_id or uuid4(),
        verdict=outcome.verdict,
        confidence=1.0 if outcome.verdict is Verdict.FORBID else 0.0,
        final_score=1.0 if outcome.verdict is Verdict.FORBID else 0.0,
        reasons=[outcome.reason],
        findings=[],
        scores={},
        uncertainty_flags=[] if outcome.verdict is Verdict.FORBID else ["floor"],
        asi_findings=[],
        determinism_fingerprint=None,
        latency=None,
        replay_url=None,
        evidence_bundle_url=None,
        policy_version=f"standing-floor:{outcome.tier}",
        evidence_hash=outcome.evidence_hash,
        evaluated_at=datetime.now(UTC),
    )


class StandingGovernanceTransport:
    """Adapts StandingGovernance to the gate's transport protocol.

    Satisfies ``TexEvaluationTransport`` (a ``evaluate(request) ->
    TransportResult``). Every call runs the full two-tier PDP.
    """

    __slots__ = ("_governance", "_tenant")

    def __init__(
        self, governance: StandingGovernance, *, tenant: str | None = None
    ) -> None:
        self._governance = governance
        self._tenant = tenant

    def evaluate(self, request: EvaluationRequest) -> TransportResult:
        start = time.perf_counter()
        try:
            outcome = self._governance.decide_for_request(request, tenant=self._tenant)
        except Exception as exc:  # noqa: BLE001 — any failure is "unavailable"
            elapsed = (time.perf_counter() - start) * 1000.0
            return TransportResult(
                response=None,
                error=f"{type(exc).__name__}: {exc}",
                transport_latency_ms=round(elapsed, 2),
                details={"transport": "standing-governance"},
            )
        elapsed = (time.perf_counter() - start) * 1000.0
        # Deep tier carries the authoritative response; floor tier is synthesized.
        response = outcome.response or _floor_response(request, outcome)
        return TransportResult(
            response=response,
            error=None,
            transport_latency_ms=round(elapsed, 2),
            details={
                "transport": "standing-governance",
                "tier": outcome.tier,
                "held": outcome.held,
                "reason": outcome.reason,
            },
        )


def build_standing_gate(
    governance: StandingGovernance,
    *,
    tenant: str | None = None,
    abstain_policy: AbstainPolicy = AbstainPolicy.BLOCK,
    fail_closed: bool = True,
    default_action_type: str = "agent_action",
    default_channel: str = "api",
    default_environment: str = "production",
    observer: GateEventObserver | None = None,
) -> TexGate:
    """Construct a TexGate that enforces the full standing-governance PDP.

    Use it to wrap any callable an agent invokes:

        gate = build_standing_gate(app.state.standing_governance, tenant="acme")
        send_wire = gate.wrap(raw_send_wire, action_type="wire_transfer")
        send_wire(amount=48000, to="acct-1234")   # raises TexForbiddenError on FORBID

    Defaults are fail-closed: ABSTAIN blocks (and is surfaced to the voice via
    the PDP), transport failure blocks, FORBID always blocks.
    """
    config = GateConfig(
        transport=StandingGovernanceTransport(governance, tenant=tenant),
        abstain_policy=abstain_policy,
        fail_closed=fail_closed,
        default_action_type=default_action_type,
        default_channel=default_channel,
        default_environment=default_environment,
        # An observer (e.g. the per-decision SealingGateObserver) turns every
        # gated ruling into a sealed, offline-verifiable receipt. Omitted ->
        # the gate's default NullObserver (zero overhead).
        **({"observer": observer} if observer is not None else {}),
    )
    return TexGate(config)
