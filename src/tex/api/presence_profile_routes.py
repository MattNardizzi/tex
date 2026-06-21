"""The two-way confirm/correct loop — backend route (Presence L2).

An operator who hears Tex speak a claim can CONFIRM ("that's right") or CORRECT
("that's wrong / you were too confident") the claim's
:class:`~tex.presence.contract.PresenceTier`. A correction becomes a sealed,
content-anchored, optionally-signed LABEL in the per-tenant profile that TIGHTENS
the next verdict for that subject (monotone-lowering — see
:mod:`tex.presence.profile.influence`); a confirmation is a sealed positive receipt.

This module is OWNED by L2 and EXPOSES a router for the orchestrator to include —
it never edits ``main.py``/``voice_ask.py``. The orchestrator wires:

    from tex.api.presence_profile_routes import build_presence_profile_router
    app.include_router(build_presence_profile_router())
    app.state.presence_profile = build_profile_memory(durable=True)
    app.state.presence_calibration = build_calibration_feed()   # optional (S5)

ISOLATION DISCIPLINE (the same split as ``/decisions/{id}/seal``):
  * the TENANT is resolved from the authenticated principal, NEVER from the body —
    a wrong tenant cannot be injected by a caller.
  * the OPERATOR (the human who clicked) is a body field — the named human act the
    profile write-gate validates as provenance.
  * a decision-backed correction feeds L1's calibration seam from the
    SERVER-looked-up ``Decision`` (``decision_store.get``), never a request value —
    so a client cannot inject a chosen calibration point.

RESPONSE SHAPE (coordinated with S6's surface): a compact JSON carrying the
citable anchor (``record_id`` + ``anchor_sha256`` + ``store``), the sealed fields,
and the self-verifying signature block (algorithm/key_id/signature/public_key) when
sealing is on — so the operator walks away with a verifiable receipt, exactly like
the seal route.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, TexPrincipal, authenticate_request
from tex.presence.contract import PresenceTier

_logger = logging.getLogger(__name__)

__all__ = ["build_presence_profile_router", "router", "CorrectionCalibrationSink"]


# --------------------------------------------------------------------------- seam
@runtime_checkable
class CorrectionCalibrationSink(Protocol):
    """L1's calibration hook (structural). S5's
    :class:`tex.presence.memory.PresenceCalibrationFeed` already satisfies it, so
    the orchestrator can wire S5 today and L1 can swap a refined sink in later."""

    def record_resolution(self, *, tenant: str, decision: Any, human_verdict: str) -> bool: ...
    def forget_resolution(self, *, tenant: str, decision_id: str) -> bool: ...


# --------------------------------------------------------------------------- DTOs
_VALID_TIERS = {t.value for t in PresenceTier}


def _parse_tier(value: str, *, field_name: str) -> PresenceTier:
    v = (value or "").strip().lower()
    if v not in _VALID_TIERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field_name} must be one of {sorted(_VALID_TIERS)}; got {value!r}",
        )
    return PresenceTier(v)


class CorrectRequest(BaseModel):
    """An operator correction of a spoken claim's tier."""

    claim_id: str = Field(min_length=1, max_length=512, description="The gate's claim_id (subject) being corrected.")
    corrected_tier: str = Field(description="The tier ceiling to impose: 'derived' or 'abstain' (never 'sealed').")
    operator: str = Field(min_length=1, max_length=320, description="Identity of the human making the correction (e.g. operator email).")
    statement: str = Field(default="", max_length=2000, description="Optional human-readable boundary text; never spoken.")
    original_tier: str | None = Field(default=None, description="Optional: the tier Tex actually spoke ('sealed'/'derived'/'abstain').")
    decision_id: str | None = Field(default=None, max_length=128, description="Optional governance Decision this correction is about (feeds calibration server-side).")
    believed_value: str | None = Field(default=None, max_length=512, description="Operator-belief metadata ONLY — never spoken.")


class ConfirmRequest(BaseModel):
    """An operator confirmation that a spoken claim's tier was right."""

    claim_id: str = Field(min_length=1, max_length=512)
    tier: str = Field(description="The tier Tex spoke that the operator is affirming.")
    operator: str = Field(min_length=1, max_length=320)
    statement: str = Field(default="", max_length=2000)
    decision_id: str | None = Field(default=None, max_length=128)


# --------------------------------------------------------------------------- helpers
def _require_profile(request: Request) -> Any:
    profile = getattr(request.app.state, "presence_profile", None)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="presence profile memory is not configured on this server",
        )
    return profile


def _effective_tenant(principal: TexPrincipal, tenant_id: str | None) -> str:
    """Resolve the tenant a profile write/read applies to. A keyed, non-default
    principal is scoped to its OWN tenant (a body/query tenant that disagrees is
    403'd); anonymous dev may pass ``tenant_id``. The profile requires a concrete
    tenant — 400 if none can be determined."""
    if not principal.is_anonymous and principal.tenant and principal.tenant != "default":
        if tenant_id is not None and principal.tenant.casefold() != tenant_id.strip().casefold():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match requested tenant_id",
            )
        return principal.tenant
    resolved = (tenant_id or "").strip()
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="a tenant is required: use a tenant-scoped API key or pass tenant_id",
        )
    return resolved


def _signature_block(fact: Any) -> dict[str, Any] | None:
    pq = getattr(fact, "pq_signature", None)
    if not isinstance(pq, dict):
        return None
    return {
        "algorithm": pq.get("algorithm"),
        "key_id": pq.get("key_id"),
        "signature_b64": pq.get("signature_b64"),
        "public_key_b64": pq.get("public_key_b64"),
        "signed_at": pq.get("signed_at"),
        "post_quantum": "ml-dsa" in str(pq.get("algorithm", "")),
    }


def _fact_view(fact: Any) -> dict[str, Any]:
    return {
        "record_id": fact.record_id,
        "kind": fact.kind.value,
        "subject_key": fact.subject_key,
        "corrected_tier": fact.corrected_tier.value if fact.corrected_tier else None,
        "original_tier": fact.original_tier.value if fact.original_tier else None,
        "statement": fact.statement,
        "operator": fact.operator,
        "decision_id": fact.decision_id,
        "anchor_sha256": fact.content_hash,
        "store": "presence_profile",
        "created_at": fact.created_at,
        "signature": _signature_block(fact),
    }


def _maybe_feed_calibration(
    request: Request, *, tenant: str, decision_id: str | None, human_verdict: str
) -> bool:
    """Feed L1's calibration seam for a decision-backed correction, using the
    SERVER-looked-up Decision (never a request value). Returns True iff a real
    calibration point was recorded. Best-effort: never sinks the write.

    SEMANTIC CAVEAT (disclosed, not papered over): this interprets a correction
    that ATTACHES a ``decision_id`` as "the operator confirms Tex's confident
    handling of that decision was a true error" → maps to ``refused`` (the same
    confirmed-true-error label the ``/decisions/{id}/seal`` flywheel feeds, S5's
    ``record_resolution`` gating to refused-only + a real ``final_score``). A
    correction WITHOUT a ``decision_id`` is a pure spoken-credibility tightening and
    feeds ONLY the profile, never the conformal floor — so a presence-credibility
    correction can never poison the decisive-step calibration semantics. L1 owns the
    final mapping; the orchestrator may inject a different ``CorrectionCalibrationSink``.
    """
    if not decision_id:
        return False
    sink = getattr(request.app.state, "presence_calibration", None)
    decision_store = getattr(request.app.state, "decision_store", None)
    if sink is None or decision_store is None:
        return False
    try:
        decision = decision_store.get(decision_id)
    except Exception:  # noqa: BLE001
        decision = None
    if decision is None:
        return False
    try:
        return bool(sink.record_resolution(tenant=tenant, decision=decision, human_verdict=human_verdict))
    except Exception:  # noqa: BLE001 — a calibration fault never sinks the correction
        _logger.exception("presence profile: calibration feed failed for decision %s", decision_id)
        return False


# --------------------------------------------------------------------------- router
router = APIRouter(prefix="/v1/presence/profile", tags=["presence-profile"])


@router.post(
    "/correct",
    status_code=status.HTTP_201_CREATED,
    summary="Correct a spoken claim's tier (a sealed, tightening label)",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def correct(body: CorrectRequest, request: Request) -> dict[str, Any]:
    """Write a sealed CORRECTION that tightens the next verdict for ``claim_id``.
    Refuses (422) an upward correction to SEALED. A decision-backed correction
    additionally feeds L1's calibration seam as a confirmed-true error (``refused``)
    from the server-looked-up Decision."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, request.query_params.get("tenant_id"))
    profile = _require_profile(request)

    corrected_tier = _parse_tier(body.corrected_tier, field_name="corrected_tier")
    original_tier = _parse_tier(body.original_tier, field_name="original_tier") if body.original_tier else None

    try:
        ref = profile.apply_correction(
            tenant=tenant,
            claim_id=body.claim_id,
            corrected_tier=corrected_tier,
            operator=body.operator,
            statement=body.statement,
            original_tier=original_tier,
            decision_id=body.decision_id,
            believed_value=body.believed_value,
        )
    except ValueError as exc:
        # The write-gate refused (upward correction / no provenance / not a
        # tightening). 422 with the gate's own honest message.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    fact = profile.get(tenant=tenant, record_id=ref.record_id)
    calibration_fed = _maybe_feed_calibration(
        request, tenant=tenant, decision_id=body.decision_id, human_verdict="refused"
    )
    response = _fact_view(fact) if fact is not None else {"record_id": ref.record_id, "anchor_sha256": ref.record_hash}
    response["tenant"] = tenant
    response["calibration_fed"] = calibration_fed
    return response


@router.post(
    "/confirm",
    status_code=status.HTTP_201_CREATED,
    summary="Confirm a spoken claim's tier (a sealed, non-inflating receipt)",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def confirm(body: ConfirmRequest, request: Request) -> dict[str, Any]:
    """Write a sealed CONFIRMATION. Non-inflating by construction — it is never
    consulted by the influence fold, so it cannot raise a future tier. To LOOSEN a
    prior correction, revoke it."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, request.query_params.get("tenant_id"))
    profile = _require_profile(request)

    tier = _parse_tier(body.tier, field_name="tier")
    try:
        ref = profile.confirm(
            tenant=tenant,
            claim_id=body.claim_id,
            tier=tier,
            operator=body.operator,
            statement=body.statement,
            decision_id=body.decision_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    fact = profile.get(tenant=tenant, record_id=ref.record_id)
    response = _fact_view(fact) if fact is not None else {"record_id": ref.record_id, "anchor_sha256": ref.record_hash}
    response["tenant"] = tenant
    # A confirmation is the 'approved'/false-alarm analog — it does NOT feed the
    # refused-only conformal floor. Surfaced honestly so the UI does not imply it
    # tightened anything.
    response["calibration_fed"] = False
    return response


@router.get(
    "",
    summary="Recall this tenant's active profile facts (citable)",
    dependencies=[Depends(RequireScope("decision:read"))],
)
def recall(request: Request, query: str | None = None, tenant_id: str | None = None) -> dict[str, Any]:
    """Return this tenant's active (non-revoked) profile facts, each citable via
    its content anchor. Optional lexical ``query`` filter."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, tenant_id)
    profile = _require_profile(request)
    facts = profile.recall_profile(tenant=tenant, query=query)
    rows = []
    for f in facts.facts:
        full = profile.get(tenant=tenant, record_id=f.record_id)
        rows.append(_fact_view(full) if full is not None else {
            "record_id": f.record_id, "kind": f.kind.value, "subject_key": f.subject_key,
            "corrected_tier": f.corrected_tier.value if f.corrected_tier else None,
            "statement": f.statement, "operator": f.operator, "anchor_sha256": f.content_hash,
            "store": "presence_profile", "created_at": f.created_at,
        })
    return {"tenant": tenant, "count": len(rows), "facts": rows}


@router.delete(
    "/{record_id}",
    summary="Revoke (forget) a profile fact — stops it influencing future verdicts",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def revoke(record_id: str, request: Request, tenant_id: str | None = None) -> dict[str, Any]:
    """Forget a profile fact wholesale (forget-by-avoidance). For a decision-backed
    correction this also pulls the calibration contribution (cross-substrate
    deletion) via S5's ``forget_resolution`` — so revoking a correction stops it
    influencing the verdict AND the floor."""
    principal = authenticate_request(request)
    tenant = _effective_tenant(principal, tenant_id)
    profile = _require_profile(request)

    # Capture the decision_id BEFORE revoking, so we can pull its calibration point.
    fact = profile.get(tenant=tenant, record_id=record_id)
    decision_id = getattr(fact, "decision_id", None) if fact is not None else None

    revoked = profile.revoke(tenant=tenant, record_id=record_id)

    calibration_forgotten = False
    if revoked and decision_id:
        sink = getattr(request.app.state, "presence_calibration", None)
        if sink is not None:
            try:
                calibration_forgotten = bool(sink.forget_resolution(tenant=tenant, decision_id=decision_id))
            except Exception:  # noqa: BLE001
                _logger.exception("presence profile: forget_resolution failed for decision %s", decision_id)

    return {
        "tenant": tenant,
        "record_id": record_id,
        "revoked": revoked,
        "calibration_forgotten": calibration_forgotten,
    }


def build_presence_profile_router() -> APIRouter:
    """Return the confirm/correct router for the orchestrator to ``include_router``.
    A function (not just the module-level ``router``) so the orchestrator's wiring
    reads symmetrically with the other ``build_*`` factories."""
    return router
