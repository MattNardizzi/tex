"""
/v1/provenance — the behavioural provenance surface.

These endpoints expose identity-by-behaviour and let any relying party
verify the sealed transparency log. They are strict reads plus an
explicit observe trigger; the heavy work (deriving signatures, resolving
identity, sealing events) happens against the gate's decision stream on
the backend, the same way the rest of Tex keeps the work in the dark and
surfaces only what is asked.

Auth posture mirrors the proof endpoints: identity reads require
``decision:read``; the raw sealed log and verification require
``evidence:read`` as well, since they expose the full provenance chain.
Against a keyless dev backend the anonymous principal carries every
scope, so a keyless frontend works in dev.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope, TexPrincipal, authenticate_request
from tex.domain.signal_trust import SignalTrustTier
from tex.provenance import BehavioralProvenanceEngine, BehavioralSignature

__all__ = ["build_provenance_router"]


class ObserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: UUID
    # How many of the agent's most-recent action-ledger entries to fold
    # into the behavioural window. The gate's stream is the source.
    window: int = Field(default=200, ge=1, le=2000)


def _engine(request: Request) -> BehavioralProvenanceEngine:
    engine = getattr(request.app.state, "provenance_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="behavioural provenance engine not attached",
        )
    return engine


def _action_window(request: Request, agent_id: UUID, window: int):
    ledger = getattr(request.app.state, "action_ledger", None)
    if ledger is None:
        return ()
    try:
        return ledger.list_for_agent(agent_id, limit=window)
    except TypeError:
        # Some ledger variants take no limit kwarg.
        return tuple(ledger.list_for_agent(agent_id))[:window]
    except Exception:  # noqa: BLE001
        return ()


def build_provenance_router() -> APIRouter:
    router = APIRouter(prefix="/v1/provenance", tags=["provenance"])

    @router.post(
        "/observe",
        summary="Observe an agent's behaviour window, resolve identity, seal it",
    )
    def observe(
        request: Request,
        body: ObserveRequest = Body(...),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        engine = _engine(request)
        entries = _action_window(request, body.agent_id, body.window)
        resolution = engine.observe(
            agent_id=body.agent_id,
            entries=entries,
            signal_tier=SignalTrustTier.NETWORK_OBSERVED,
        )
        return resolution.model_dump(mode="json")

    @router.get(
        "/identity/{agent_id}",
        summary="The sealed behavioural birth certificate for an agent",
    )
    def identity(
        request: Request,
        agent_id: UUID,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        engine = _engine(request)
        cert = engine.birth_certificate(agent_id)
        if cert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"no sealed behavioural identity for agent {agent_id}",
            )
        return cert.model_dump(mode="json")

    @router.post(
        "/reidentify",
        summary="Graded matches of a candidate behaviour window against known actors",
    )
    def reidentify(
        request: Request,
        body: ObserveRequest = Body(...),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        engine = _engine(request)
        entries = _action_window(request, body.agent_id, body.window)
        sig = BehavioralSignature.from_actions(entries)
        matches = engine.reidentify(sig)
        return {
            "candidate_signature_hash": sig.signature_hash,
            "warm": sig.is_warm,
            "matches": [m.model_dump(mode="json") for m in matches],
        }

    @router.get(
        "/ledger/verify",
        summary="Verify the provenance log's hash chain and signatures",
    )
    def verify(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> dict[str, Any]:
        for scope in ("decision:read", "evidence:read"):
            if not principal.has_scope(scope):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"missing required scope: {scope}",
                )
        engine = _engine(request)
        chain = engine.ledger.verify_chain()
        sigs = engine.ledger.verify_signatures()
        return {
            "chain": chain,
            "signatures": sigs,
            "entries": len(engine.ledger),
            "signing_key_id": engine.ledger.signing_key_id,
            "public_key_pem": engine.ledger.public_key_pem.decode("ascii"),
        }

    @router.get(
        "/ledger",
        summary="The sealed provenance records (append-only, signed)",
    )
    def ledger(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> dict[str, Any]:
        for scope in ("decision:read", "evidence:read"):
            if not principal.has_scope(scope):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"missing required scope: {scope}",
                )
        engine = _engine(request)
        return {
            "records": [r.model_dump(mode="json") for r in engine.ledger.list_all()],
            "signing_key_id": engine.ledger.signing_key_id,
        }

    return router
