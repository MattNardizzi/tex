"""L3 habit hypotheses — backend route (Presence L3).

Tex mines its OWN sealed history for per-tenant patterns ("I've noticed your
agents tend to…") and OFFERS them — never asserts. Surfacing is read-only and
inert: nothing changes until an operator CONFIRMS a hypothesis, which writes ONE
L2 correction (monotone-tightening, toward caution) through the same per-tenant
profile the confirm/correct loop uses (see
:mod:`tex.presence.profile.influence`). A DECLINE writes nothing.

OWNED by L3; EXPOSES a router the orchestrator includes — it never edits
``main.py``/``voice_ask.py``. The orchestrator already wires
``app.state.presence_habits`` (a :class:`tex.presence.habits.HabitSurface`) and
``app.state.presence_profile``; this module just opens the HTTP surface:

    from tex.api.presence_habits_routes import build_presence_habits_router
    app.include_router(build_presence_habits_router())

ISOLATION DISCIPLINE (identical to ``/v1/presence/profile``):
  * the TENANT is resolved from the authenticated principal, NEVER the body — a
    wrong tenant cannot be injected by a caller (reuses ``_effective_tenant``).
  * the hypothesis to confirm/decline is RE-DERIVED server-side from
    ``surface(tenant)`` and matched by its content-addressed ``hypothesis_id`` —
    a client can never confirm/decline a fabricated or stale pattern.
  * the OPERATOR (the human who clicked) is a body field — the named human act
    L2's write-gate records as provenance.

HONEST BY CONSTRUCTION: ``GET`` returns ``[]`` until enough sealed evidence
accumulates to clear the miner's Wilson/Bonferroni floor — an empty surface is
"I have nothing worth offering yet", not a failure. The surface only ever offers
a tightening (DERIVED/ABSTAIN ceiling), never a confident assertion.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, authenticate_request
from tex.api.presence_profile_routes import _effective_tenant

_logger = logging.getLogger(__name__)

__all__ = ["build_presence_habits_router", "router"]


class ConfirmHabitRequest(BaseModel):
    """Confirm a surfaced hypothesis → one sealed, tightening L2 correction."""

    hypothesis_id: str = Field(min_length=1, max_length=128, description="The content-addressed id of a currently-surfaced hypothesis.")
    operator: str = Field(min_length=1, max_length=320, description="Identity of the human confirming (e.g. operator email).")
    decision_id: str | None = Field(default=None, max_length=128, description="Optional governance Decision this habit is about (rides through to L2 → L1 calibration).")


class DeclineHabitRequest(BaseModel):
    """Record a human "no" on a surfaced hypothesis. Writes nothing."""

    hypothesis_id: str = Field(min_length=1, max_length=128)
    operator: str = Field(min_length=1, max_length=320)


def _require_habits(request: Request) -> Any:
    surface = getattr(request.app.state, "presence_habits", None)
    if surface is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="presence habit surface is not configured on this server",
        )
    return surface


def _confidence_view(c: Any) -> dict[str, Any] | None:
    if c is None:
        return None
    return {
        "n": getattr(c, "n", None),
        "k": getattr(c, "k", None),
        "point_rate": getattr(c, "point_rate", None),
        "wilson_lower": getattr(c, "wilson_lower", None),
        "label": getattr(c, "label", None),
        "surfaced": getattr(c, "surfaced", None),
    }


def _hypothesis_view(h: Any) -> dict[str, Any]:
    action = getattr(h, "action", None)
    return {
        "hypothesis_id": h.hypothesis_id,
        "kind": h.kind.value,
        "dimension": h.dimension.value,
        "subject_key": h.subject_key,
        "dominant_outcome": h.dominant_outcome,
        # A habit may only ever propose a tightening (DERIVED/ABSTAIN), never SEALED.
        "proposed_tier": action.proposed_tier.value if action is not None else None,
        "phrasing": h.phrasing,
        "supporting_count": h.supporting_count(),
        "supporting": [
            {"record_id": r.record_id, "anchor_sha256": getattr(r, "record_hash", None)}
            for r in h.supporting
        ],
        "confidence": _confidence_view(getattr(h, "confidence", None)),
    }


def _find_hypothesis(surface: Any, *, tenant: str, hypothesis_id: str) -> Any:
    """Re-mine the tenant's CURRENT hypotheses and match by content-addressed id.
    Refuses (404) an unknown/stale id — a client can only act on a pattern Tex
    itself currently surfaces from real sealed evidence."""
    for h in surface.surface(tenant=tenant):
        if h.hypothesis_id == hypothesis_id:
            return h
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="no currently-supported hypothesis with that id for this tenant",
    )


router = APIRouter(prefix="/v1/presence/habits", tags=["presence-habits"])


@router.get(
    "",
    summary="Surface this tenant's habit hypotheses (read-only — offered, never asserted)",
    dependencies=[Depends(RequireScope("decision:read"))],
)
def surface(request: Request, tenant_id: str | None = None) -> dict[str, Any]:
    """Mine + phrase this tenant's noticed patterns. Read-only and inert: nothing
    here changes a verdict, a profile, or a future answer. Returns ``[]`` until
    the statistical floor is cleared."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, tenant_id)
    habits = _require_habits(request)
    mined = habits.surface(tenant=tenant)
    return {"tenant": tenant, "count": len(mined), "habits": [_hypothesis_view(h) for h in mined]}


@router.post(
    "/confirm",
    status_code=status.HTTP_201_CREATED,
    summary="Confirm a hypothesis → one sealed L2 correction (tightening)",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def confirm(body: ConfirmHabitRequest, request: Request) -> dict[str, Any]:
    """Confirm a currently-surfaced hypothesis. Seals ONE L2 correction capping the
    subject's tier at the hypothesis's proposed (cautious) ceiling, through the same
    profile the confirm/correct loop writes. Returns the citable receipt."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, request.query_params.get("tenant_id"))
    habits = _require_habits(request)
    profile = getattr(request.app.state, "presence_profile", None)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="presence profile memory is not configured; cannot seal a confirmation",
        )
    hypothesis = _find_hypothesis(habits, tenant=tenant, hypothesis_id=body.hypothesis_id)
    try:
        receipt = habits.confirm(
            hypothesis=hypothesis, operator=body.operator, decision_id=body.decision_id, profile=profile
        )
    except ValueError as exc:
        # L3's own refusal or L2's write-gate refused (e.g. an inflating tier).
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    ref = receipt.profile_ref
    return {
        "tenant": tenant,
        "hypothesis_id": receipt.hypothesis_id,
        "subject_key": receipt.subject_key,
        "operator": receipt.operator,
        "confirmed_at": receipt.confirmed_at,
        "decision_id": receipt.decision_id,
        "profile_record_id": ref.record_id,
        "anchor_sha256": getattr(ref, "record_hash", None),
        "store": "presence_profile",
    }


@router.post(
    "/decline",
    status_code=status.HTTP_200_OK,
    summary="Decline a hypothesis (audit only — writes nothing)",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def decline(body: DeclineHabitRequest, request: Request) -> dict[str, Any]:
    """Record a human "no". Writes nothing to any store — the no-op IS the
    behaviour; this just makes the human's decline auditable."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, request.query_params.get("tenant_id"))
    habits = _require_habits(request)
    hypothesis = _find_hypothesis(habits, tenant=tenant, hypothesis_id=body.hypothesis_id)
    record = habits.decline(hypothesis=hypothesis, operator=body.operator)
    return {
        "tenant": tenant,
        "hypothesis_id": record.hypothesis_id,
        "subject_key": record.subject_key,
        "operator": record.operator,
        "declined_at": record.declined_at,
        "written": False,
    }


def build_presence_habits_router() -> APIRouter:
    """Return the L3 habits router for the orchestrator to ``include_router``.
    A factory (not just the module-level ``router``) so the wiring reads
    symmetrically with the other ``build_*`` factories."""
    return router
