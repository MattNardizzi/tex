"""Plan-path orchestration — the flag-gated generalization of ``run_presence``.

``run_presence`` (the legacy path) routes ONE claim to one of the 11 fixed QUERIES.
``answer_with_plan`` instead: compiles the question into a plan-DAG, executes it over
the real rows, wraps the resulting :class:`Recompute` as a :class:`ClaimEvaluation`,
and hands it to the SAME :func:`build_envelope` — so every downstream guarantee is
preserved unchanged: the gate is still the sole author of the spoken words
(``Recompute.canonical_phrase``), prosody is still a pure function of the verdict tier,
attestation/hold still fire, and an ungrounded answer abstains.

Fail-closed throughout: a missing/None plan, an execute error, or a build error all
yield the deterministic templated ABSTAIN envelope (and raise one presence hold), never
a guessed answer and never an exception into the voice path.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from tex.presence.brain.read_tools import build_read_tool_registry
from tex.presence.contract import (
    AnswerEnvelope,
    ClaimKind,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
    ProsodyPlan,
)
from tex.presence.gate.compose import build_envelope, raise_presence_hold
from tex.presence.gate.gate import ClaimEvaluation, RoutedClaim
from tex.presence.gate.queries import Recompute
from tex.presence.plan.executor import execute_plan

_logger = logging.getLogger(__name__)

__all__ = ["answer_with_plan", "evaluation_from_recompute"]

_PLAN_CLAIM_ID = "plan"

# Distinct honest-abstain phrasings — a user must be able to tell "that data doesn't
# exist" from "I can't compute that yet" from a generic failure. All still ABSTAIN-tier;
# only the words differ, and every one is authored here, never by the model.
ABSTAIN_NO_RECORD_TEXT = (
    "Nothing recorded holds that answer — that isn't in the records yet."
)
ABSTAIN_OUT_OF_DOMAIN_TEXT = (
    "That's outside my records. I speak for your agents — their actions, decisions, and evidence."
)
ABSTAIN_UNPROVABLE_TEXT = (
    "I couldn't prove that from the records I hold, so I won't guess."
)

_DECLINE_TEXTS = {
    "no-record": ABSTAIN_NO_RECORD_TEXT,
    "out-of-domain": ABSTAIN_OUT_OF_DOMAIN_TEXT,
}


def _state(request: Any) -> Any:
    state = getattr(getattr(request, "app", None), "state", None)
    return state if state is not None else request


def _resolve_decision_store(request: Any) -> Any | None:
    state = getattr(getattr(request, "app", None), "state", None)
    return getattr(state, "decision_store", None) if state is not None else None


def evaluation_from_recompute(
    rc: Recompute, *, claim_id: str = _PLAN_CLAIM_ID, kind: ClaimKind = ClaimKind.AGGREGATE
) -> ClaimEvaluation:
    """Wrap the plan's output :class:`Recompute` as the gate's :class:`ClaimEvaluation`
    currency. Tier is a pure function of what the executor proved: SEALED when grounded
    with bound evidence, DERIVED when it carries a conformal floor, else ABSTAIN."""
    grounded = bool(rc.grounded and rc.evidence and rc.canonical_phrase)
    if not grounded:
        tier = PresenceTier.ABSTAIN
    elif rc.correctness_floor is not None:
        tier = PresenceTier.DERIVED
    else:
        tier = PresenceTier.SEALED

    claim = PresenceClaim(claim_id=claim_id, text_span=rc.canonical_phrase or "", kind=kind)
    verdict = PresenceVerdict(
        claim_id=claim_id,
        tier=tier,
        evidence=rc.evidence if tier is not PresenceTier.ABSTAIN else (),
        recomputed_value=rc.value,
        correctness_floor=rc.correctness_floor if tier is PresenceTier.DERIVED else None,
        coverage_mode=rc.coverage_mode if tier is PresenceTier.DERIVED else None,
        governance_verdict=rc.governance_verdict,
        reason=rc.reason,
    )
    return ClaimEvaluation(claim, verdict, rc, RoutedClaim(None, None, "plan"))


def answer_with_plan(
    request: Any,
    *,
    transcript: str,
    tenant: str | None,
    compiler: Any,
    templated_abstain: str,
    registry: dict[str, Any] | None = None,
    attestor: Any = None,
    held_sink: Any = None,
    context: Any = None,
) -> AnswerEnvelope | None:
    """Compile → execute → speak. Returns an :class:`AnswerEnvelope` (an honest-abstain
    envelope when the model produced no usable plan), or ``None`` when the MODEL ITSELF is
    unavailable (no credits / outage / rate-limit) — the caller then degrades to the legacy
    deterministic path so a model outage never takes the voice down. Never raises.

    ``context`` is the prior Q/A ({"prior_question", "prior_answer"}) for follow-up
    reference resolution — it steers only the COMPILE step; the gate still recomputes
    every spoken value from real rows."""
    from tex.presence.plan.compile import PlanDecline

    state = _state(request)
    reg = registry if registry is not None else build_read_tool_registry(state)
    catalog = {name: getattr(tool, "description", "") for name, tool in reg.items()}

    now = datetime.now(UTC)  # one ground-truth 'now' shared by the prompt and the executor
    try:
        plan = compiler.compile(
            question=transcript, tenant=tenant, tool_catalog=catalog,
            reference_now=now.isoformat(), context=context,
        )
    except TypeError:  # an older compiler without the context kwarg (test doubles)
        try:
            plan = compiler.compile(
                question=transcript, tenant=tenant, tool_catalog=catalog,
                reference_now=now.isoformat(),
            )
        except Exception:  # noqa: BLE001
            _logger.warning("plan compile: model unavailable — degrading to the legacy path", exc_info=True)
            return None
    except Exception:  # noqa: BLE001 — the MODEL is unavailable (no credits / outage / rate-limit)
        _logger.warning("plan compile: model unavailable — degrading to the legacy path", exc_info=True)
        return None  # signal the caller to fall back to the deterministic path, never go dark

    if isinstance(plan, PlanDecline):  # a DELIBERATE decline — phrase it by its reason
        return AnswerEnvelope(
            spoken_text=_DECLINE_TEXTS.get(plan.reason, templated_abstain),
            prosody_plan=ProsodyPlan.from_tier(PresenceTier.ABSTAIN),
            surface_object=None,
        )

    if plan is None:  # the model replied but produced no usable plan → a genuine honest abstain
        return AnswerEnvelope(
            spoken_text=templated_abstain,
            prosody_plan=ProsodyPlan.from_tier(PresenceTier.ABSTAIN),
            surface_object=None,
        )

    try:
        rc = execute_plan(plan, request=request, tenant=tenant, registry=reg, reference_now=now)
    except Exception:  # noqa: BLE001 — executor is built not to raise, belt-and-braces
        _logger.warning("plan execute raised; abstaining", exc_info=True)
        rc = Recompute(False, reason="plan-execute-error")

    evaluation = evaluation_from_recompute(rc)
    try:
        # A plan that RAN but couldn't ground gets the "couldn't prove it" phrasing —
        # distinct from "no record" and from the generic fallback.
        envelope = build_envelope((evaluation,), templated_abstain=ABSTAIN_UNPROVABLE_TEXT, attestor=attestor)
    except Exception:  # noqa: BLE001 — composition/attestation must never break the voice
        _logger.warning("plan build_envelope raised; abstaining", exc_info=True)
        return AnswerEnvelope(spoken_text=templated_abstain, surface_object=None)

    if not envelope.verdicts:  # answer-level ABSTAIN → surface one hold
        raise_presence_hold(
            held_sink, (evaluation,), transcript=transcript,
            decision_store=_resolve_decision_store(request),
        )
    return envelope
