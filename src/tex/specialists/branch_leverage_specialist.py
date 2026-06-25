"""
BranchLeverageSpecialist + the CHOKE-X/CFI branch-leverage hold.

[Architecture: Layer 4 (Execution Governance)] — surfaces the metered CaMeL
interpreter's ABSTAIN signal (CHOKE-X per-branch over-leverage / CFI cumulative
over-budget) as a first-class, named PDP signal, and demotes a routed PERMIT to
ABSTAIN when it fires.

Why a separate specialist + a hold (not a structural FORBID)
------------------------------------------------------------
The structural FORBID floor only ever raises a verdict to FORBID, and only on a
PROOF of a violation. CHOKE-X over-leverage is NOT a proof of a violation — it is a
proof that Tex *cannot bound* the attacker's control-flow leverage within the
declared budget, so the honest response is **ABSTAIN** (deliberate caution), never
FORBID. (Iter-4 fixed this contract: a high-stakes branch over budget → ABSTAIN,
the irreversible arm is NOT committed.) So branch-leverage uses the same
monotone-lowering soft rail as the cadence / value-budget DEGRADED holds:
PERMIT→ABSTAIN only, never raising a verdict, never manufacturing a PERMIT.

The ``CamelSpecialist`` already runs the metered interpreter and emits the
``camel.branch_leverage_abstain`` clause id + the ``camel_branch_abstain`` flag on
an ABSTAIN. ``BranchLeverageSpecialist`` reads that bundle entry and re-publishes it
as its own named ``branch_leverage`` specialist signal — giving auditors /
dashboards a dedicated axis (and a place to attach CHOKE-X-specific evidence)
without duplicating the interpreter run. ``apply_branch_leverage_hold`` is the rail
that turns the signal into the PERMIT→ABSTAIN demotion on the live PDP path.

Default-safe: when no CaMeL plan ran (the overwhelmingly common recipe-traffic
case) the ``camel`` result carries no abstain signal, this specialist abstains
(risk 0.0, confidence 0.0), and the hold is a bit-for-bit no-op.
"""

from __future__ import annotations

from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.base import (
    SpecialistBundle,
    SpecialistResult,
)
from tex.specialists.camel_specialist import (
    CAMEL_BRANCH_ABSTAIN_CODE,
    CAMEL_BRANCH_ABSTAIN_FLAG,
)

BRANCH_LEVERAGE_SPECIALIST = "branch_leverage"
BRANCH_LEVERAGE_CODE = "branch_leverage.over_budget"
BRANCH_LEVERAGE_HOLD_FLAG = "branch_leverage_abstain"


def _camel_abstain_summary(bundle: SpecialistBundle | None) -> str | None:
    """The CaMeL specialist's branch-abstain summary if it fired, else None.

    A branch-abstain is identified by the ``camel.branch_leverage_abstain`` clause
    id (sturdier than the 0.5 score, which an UNTRUSTED-tainted completion shares).
    """
    if bundle is None:
        return None
    for result in bundle.results:
        if result.specialist_name != "camel":
            continue
        if CAMEL_BRANCH_ABSTAIN_CODE in result.matched_policy_clause_ids:
            return result.summary
        # Belt-and-braces: also honor the flag if a future camel variant sets it
        # without the clause id.
        if CAMEL_BRANCH_ABSTAIN_FLAG in result.uncertainty_flags:
            return result.summary
    return None


class BranchLeverageSpecialist:
    """Re-publishes the metered CaMeL interpreter's CHOKE-X/CFI ABSTAIN as a named
    ``branch_leverage`` PDP signal.

    It does NOT re-run the interpreter — it reads the ``camel`` specialist's result
    out of the shared bundle (passed via ``retrieval_context`` is not available, so
    the suite passes the in-progress bundle on the request metadata key
    ``_specialist_bundle`` when wired; absent that, this specialist abstains). To
    keep the suite contract simple and avoid ordering coupling, the canonical wiring
    is the ``apply_branch_leverage_hold`` rail reading the FINAL bundle; this
    specialist is the auditor-facing axis and abstains when it cannot see a camel
    abstain.
    """

    name: str = BRANCH_LEVERAGE_SPECIALIST

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        metadata = getattr(request, "metadata", None) or {}
        bundle = None
        if isinstance(metadata, dict):
            maybe = metadata.get("_specialist_bundle")
            if isinstance(maybe, SpecialistBundle):
                bundle = maybe
        summary = _camel_abstain_summary(bundle)
        if summary is None:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                summary="BranchLeverage specialist abstaining: no metered CaMeL "
                "branch ABSTAIN in this evaluation.",
                rationale="No high-stakes CaMeL branch exceeded its CHOKE-X "
                "leverage budget and the CFI cumulative budget was not exhausted.",
                uncertainty_flags=("no_branch_abstain",),
            )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=0.5,
            confidence=1.0,
            summary=summary,
            rationale="CHOKE-X certified more attacker control-flow leverage than "
            "the high-stakes branch's budget (or CFI cumulative budget exhausted); "
            "the high-stakes arm was not committed — ABSTAIN, not FORBID.",
            uncertainty_flags=(BRANCH_LEVERAGE_HOLD_FLAG,),
            matched_policy_clause_ids=(BRANCH_LEVERAGE_CODE,),
        )


def branch_leverage_abstained(bundle: SpecialistBundle | None) -> tuple[bool, str]:
    """True + reason iff the metered CaMeL interpreter ABSTAINED on a high-stakes /
    over-budget branch in this evaluation (read off the final specialist bundle).
    Pure — used by ``apply_branch_leverage_hold``."""
    summary = _camel_abstain_summary(bundle)
    if summary is None:
        return False, ""
    return True, summary


def apply_branch_leverage_hold(
    *, base: Any, request: Any, bundle: SpecialistBundle | None
) -> Any:
    """Demote a routed PERMIT to ABSTAIN when the metered CaMeL interpreter
    ABSTAINED on a high-stakes branch (CHOKE-X over-leverage) or exhausted its CFI
    cumulative steering budget.

    Monotone-lowering guard: only a PERMIT is ever touched, and the only outcome is
    ABSTAIN. CHOKE-X over-leverage is never a FORBID (it is an *unbounded leverage*
    proof, not a *violation* proof), so this rail can never raise a verdict. A no-op
    when no camel branch abstained (the common case)."""
    from tex.domain.verdict import Verdict

    if base.verdict is not Verdict.PERMIT:
        return base

    fired, reason = branch_leverage_abstained(bundle)
    if not fired:
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reasons = list(base.reasons)
    reasons.append(reason)

    flags = list(base.uncertainty_flags)
    if BRANCH_LEVERAGE_HOLD_FLAG not in flags:
        flags.append(BRANCH_LEVERAGE_HOLD_FLAG)

    findings = list(base.findings)
    findings.append(
        Finding(
            source="specialists.branch_leverage",
            rule_name="branch_leverage_abstain_hold",
            severity=Severity.WARNING,
            message=reason,
            metadata={
                "tier": "branch_leverage",
                "code": BRANCH_LEVERAGE_CODE,
            },
        )
    )

    scores = dict(base.scores)
    scores["branch_leverage"] = 0.5

    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=tuple(reasons),
        findings=tuple(findings),
        scores=scores,
        uncertainty_flags=tuple(flags),
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )


__all__ = [
    "BranchLeverageSpecialist",
    "BRANCH_LEVERAGE_SPECIALIST",
    "BRANCH_LEVERAGE_CODE",
    "BRANCH_LEVERAGE_HOLD_FLAG",
    "branch_leverage_abstained",
    "apply_branch_leverage_hold",
]
