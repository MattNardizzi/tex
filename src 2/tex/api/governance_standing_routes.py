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
