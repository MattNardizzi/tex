"""
/v1/govern — the PEP-facing decision surface for standing governance.

This is the thin seam the enforcement point talks to. Whatever sits in the
path — an eBPF/Tetragon kernel hook, an MCP/mesh gateway, the in-process
TexGate — calls ``POST /v1/govern/decide`` synchronously before letting an
action cross, and obeys ``released``. The brain behind it is StandingGovernance
(see governance/standing.py): pre-loaded capability surfaces for the
microsecond floor, the full six-layer EvaluateActionCommand for deep
adjudication, ABSTAIN routed to the one voice, FORBID by default.

``GET /v1/govern/posture`` is the governed-vs-observed boundary, spoken —
the truth the voice is honest about: how much of the estate Tex can actually
rule on versus merely watch.

Output obeys the same doctrine as the discovery surface: ``spoken`` carries
meaning; ``object`` carries a bare handle or null. The screen never holds an
answer.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, TexPrincipal

__all__ = ["build_governance_standing_router"]


class DecideRequest(BaseModel):
    """What a PEP sends. Mirrors an EvaluationRequest's edge, plus the agent
    handle the PEP observed (a stable UUID where it has one, otherwise an
    external id or name)."""

    action_type: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=50_000)
    channel: str | None = Field(default=None, max_length=50)
    environment: str | None = Field(default=None, max_length=50)
    recipient: str | None = Field(default=None, max_length=500)
    agent_id: UUID | None = None
    agent_external_id: str | None = Field(default=None, max_length=300)
    session_id: str | None = Field(default=None, max_length=200)
    tenant_id: str | None = Field(default=None, max_length=200)


def _governance(request: Request):
    gov = getattr(request.app.state, "standing_governance", None)
    if gov is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="standing governance not attached",
        )
    return gov


def _resolve_tenant(principal: TexPrincipal, override: str | None) -> str:
    if override and principal.can_access_tenant(override):
        return override.strip().casefold()
    return principal.tenant


def build_governance_standing_router() -> APIRouter:
    router = APIRouter(prefix="/v1/govern", tags=["governance-standing"])

    @router.post(
        "/decide",
        summary="Rule on one action — the call every enforcement point makes",
    )
    def decide(
        request: Request,
        body: DecideRequest,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        gov = _governance(request)
        tenant = _resolve_tenant(principal, body.tenant_id)
        outcome = gov.decide(
            tenant=tenant,
            action_type=body.action_type,
            content=body.content,
            channel=body.channel,
            environment=body.environment,
            recipient=body.recipient,
            agent_id=body.agent_id,
            agent_external_id=body.agent_external_id,
            session_id=body.session_id,
        )
        # PROOF-CARRYING ENFORCEMENT (dormant unless a decision ledger is wired,
        # i.e. TEX_SEAL_DECISIONS=1): seal an offline-verifiable ENFORCEMENT
        # receipt for this PEP decision so a missing receipt reads as a bypass.
        # Fail-closed and best-effort — sealing NEVER changes or breaks the
        # decision the PEP obeys (the action proceeds on ``released`` regardless).
        ledger = getattr(request.app.state, "decision_ledger", None)
        if ledger is not None:
            try:
                from tex.provenance.enforcement_seal import seal_enforcement_decision

                seal_enforcement_decision(
                    ledger,
                    action_type=body.action_type,
                    channel=body.channel or "api",
                    environment=body.environment or "production",
                    recipient=body.recipient,
                    agent_id=(
                        str(body.agent_id)
                        if body.agent_id is not None
                        else (body.agent_external_id or None)
                    ),
                    verdict=str(getattr(outcome, "verdict", "FORBID")),
                    released=bool(getattr(outcome, "released", False)),
                    decision_id=(
                        str(outcome.decision_id)
                        if getattr(outcome, "decision_id", None)
                        else None
                    ),
                    reason=getattr(outcome, "reason", None),
                    tier=getattr(outcome, "tier", None),
                    held=bool(getattr(outcome, "held", False)),
                )
            except Exception:  # noqa: BLE001 — sealing must never break the decision
                pass

        # The one boolean a PEP obeys is ``released``. The rest is provenance.
        return outcome.to_jsonable()

    @router.get(
        "/posture",
        summary="Governed vs. observed — the edge of control, spoken",
    )
    def posture(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        gov = _governance(request)
        tenant = _resolve_tenant(principal, tenant_id)
        return gov.posture(tenant).to_jsonable()

    @router.get(
        "/forbid-set",
        summary="The hot FORBID destinations the kernel floor blocks inline",
    )
    def forbid_set(
        request: Request,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        # The kernel-floor PEP (pep/kernel) polls this to warm its in-kernel
        # verdict cache so the highest-confidence denials are blocked in
        # microseconds, before a packet leaves, without a userspace round trip.
        # This is deliberately the HOT SET only — not the policy. Absence from
        # it is never permit: every destination not listed flows through the
        # transparent redirect to the proxy for the full two-tier decision.
        # The set is empty until the PDP accumulates destination-level denials;
        # an empty set means "decide everything at the proxy," the safe default.
        gov = _governance(request)
        entries = []
        getter = getattr(gov, "forbid_destinations", None)
        if callable(getter):
            try:
                entries = list(getter(principal.tenant))
            except Exception:  # noqa: BLE001
                entries = []
        return {"forbid": entries, "count": len(entries)}

    return router
