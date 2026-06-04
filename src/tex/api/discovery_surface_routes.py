"""
/v1/surface/discovery — the thin voice projection of discovery.

This is the surface side of the doctrine's §1. It is deliberately tiny:
the rich, audit-grade discovery API stays at ``/v1/discovery/scan``; this
is what the one screen talks to. Everything here obeys the same line:

  * **Ignition speaks once.** ``POST .../ignite`` returns exactly one
    sentence — the count and that Tex is beginning — and never again.
    The server-side ignition flag makes that true; a second call does not
    re-declare.

  * **Everything else is pull-only.** The client never has to ask, because
    Tex is working in the dark. When the client *does* reach in, Tex
    answers only what was asked: how many now (a count), what changed
    since X (a delta), who owns Y (the owner spoken, the exact name
    rising). There is no feed here. A list of findings is the alert queue
    Tex exists to refuse.

  * **The held queue is the one unprompted voice.** ``GET .../held`` is the
    surface read for the two things that earn the voice: a decision Tex is
    holding (an ABSTAIN it will not rule on alone) and — elsewhere — the
    faltering confession. Discovery itself is neither.

Output shape follows the locked output doctrine: ``spoken`` carries the
meaning (always speech, never digits); ``object`` carries a bare handle
(an exact name, a hash) that rises alone, monospace, only on reach. The
screen never holds an answer.
"""

from __future__ import annotations

import os

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from tex.api.auth import RequireScope, TexPrincipal
from tex.discovery.ignition import humanize_count
from tex.domain.agent import AgentLifecycleStatus
from tex.provenance.models import ProvenanceEventKind

__all__ = ["build_discovery_surface_router"]


def _registry(request: Request):
    reg = getattr(request.app.state, "agent_registry", None)
    if reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent registry not attached",
        )
    return reg


def _ignition(request: Request):
    ign = getattr(request.app.state, "ignition_registry", None)
    if ign is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ignition registry not attached",
        )
    return ign


def _engine(request: Request):
    return getattr(request.app.state, "provenance_engine", None)


def _discovery_service(request: Request):
    return getattr(request.app.state, "discovery_service", None)


# Agents that are "running" in the estate for the spoken count: everything
# discovered and present, excluding the ones Tex put to sleep (the dormant
# doctrine forbids speaking about them) and the terminally revoked. A
# freshly-discovered agent is PENDING governance but is still running — that
# is exactly what ignition is meant to surface.
_NOT_RUNNING = {AgentLifecycleStatus.SLEEPING, AgentLifecycleStatus.REVOKED}


def _estate_count(registry, tenant: str) -> int:
    return sum(
        1
        for a in registry.list_all()
        if a.tenant_id == tenant and a.lifecycle_status not in _NOT_RUNNING
    )


def _sandbox_real_tenant() -> str:
    """The synthetic estate this deployment treats as its OWN real tenant.

    In the sandbox the interface has no API key, so it must name the tenant on
    every call (``meridian-<seed>``) — which would otherwise read as an
    ephemeral preview override and strip the standing watch. Declaring it here
    (``TEX_SANDBOX_TENANT``) lets ignition treat it as the real estate it is:
    full discovery, standing watch enrolled, live PDP switched on, holds
    surfaced. Empty in a keyed production deployment, where the key carries the
    tenant and this seam is never reached.
    """
    return os.environ.get("TEX_SANDBOX_TENANT", "").strip().casefold()


def _resolve_tenant(principal: TexPrincipal, override: str | None) -> str:
    """
    The tenant a surface call operates on. Defaults to the principal's own
    tenant; an explicit override is honoured only for a principal allowed to
    act cross-tenant (anonymous/dev or a cross-tenant-scoped key), which is
    what lets the preview surface run each visit under its own fresh tenant.
    """
    if override and principal.can_access_tenant(override):
        return override.strip().casefold()
    return principal.tenant


def build_discovery_surface_router() -> APIRouter:
    router = APIRouter(prefix="/v1/surface/discovery", tags=["discovery-surface"])

    @router.get("/status", summary="Has ignition fired for this tenant? (no side effect)")
    def status_(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        # A pure read so the surface can decide whether to show the day-one
        # door WITHOUT firing ignition. The door is shown iff ignition has
        # not fired; firing is the user's deliberate act on /ignite.
        ignition = _ignition(request)
        tenant = _resolve_tenant(principal, tenant_id)
        fired = ignition.has_fired(tenant)
        at = ignition.fired_at(tenant)
        return {
            "ignited": fired,
            "ignited_at": at.isoformat() if at else None,
        }

    @router.post("/ignite", summary="Begin watching the estate — map it, then the count, said once")
    def ignite(
        request: Request,
        tenant_id: str | None = Query(default=None, description="Override tenant (anonymous/cross-tenant only)"),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        registry = _registry(request)
        ignition = _ignition(request)
        tenant = _resolve_tenant(principal, tenant_id)

        if ignition.has_fired(tenant):
            # The door has already opened. Pull-only from here; never
            # re-declare.
            return {
                "spoken": None,
                "object": None,
                "already_ignited": True,
                "ignited_at": ignition.fired_at(tenant).isoformat(),
            }

        # Ignition is the moment the witness starts watching: do the full
        # multi-plane discovery now, seal a behavioural birth for everything
        # found (the provenance engine engages here), take the inventory in,
        # then surface exactly one line — the count of what is running.
        # (DISCOVERY_DOCTRINE §1.) Silent by construction: the scan speaks
        # nothing; only this single ignition line is spoken.
        #
        # A real operator console ignites its own tenant (no override): that
        # tenant is enrolled into the standing watch (periodic re-scan,
        # dormancy sweep, held surfacing) and its holds are routed to the
        # voice. A preview/ephemeral tenant (an explicit override) does the
        # initial map only — no perpetual loop, no holds into the shared
        # queue — so the demo door can replay per visit without leaking.
        # A keyed operator console omits the tenant (the key carries it). The
        # keyless sandbox must name its tenant, so an explicit override that
        # matches the declared sandbox estate is ALSO real — it gets the full
        # standing treatment (watch enrolled, PDP activated, holds surfaced),
        # not the ephemeral preview path.
        sandbox_tenant = _sandbox_real_tenant()
        is_real_tenant = (not tenant_id) or (
            bool(sandbox_tenant) and tenant == sandbox_tenant
        )
        service = _discovery_service(request)
        if service is not None:
            try:
                service.scan(
                    tenant_id=tenant,
                    trigger="ignition",
                    surface_holds=is_real_tenant,
                )
            except Exception:  # noqa: BLE001
                # Discovery is decoupled from the voice: if a scan errors,
                # ignition still speaks the truth of what is already known
                # rather than failing the operator's deliberate act.
                pass

        if is_real_tenant:
            scheduler = getattr(request.app.state, "scan_scheduler", None)
            if scheduler is not None:
                try:
                    scheduler.enroll_tenant(tenant)
                except Exception:  # noqa: BLE001
                    pass

            # The inventory is in and the watch is enrolled. Switch on the
            # live PDP for this tenant NOW: from here every action an agent
            # attempts is ruled on at /v1/govern, fail-closed, and newly
            # discovered agents are governed by default the instant they act.
            governance = getattr(request.app.state, "standing_governance", None)
            if governance is not None:
                try:
                    governance.activate(tenant)
                except Exception:  # noqa: BLE001
                    pass

        count = _estate_count(registry, tenant)
        ignition.fire(tenant)
        words = humanize_count(count)
        agents = "agent" if count == 1 else "agents"
        return {
            "spoken": f"You have {words} {agents} running. I'll begin.",
            "object": None,
            "already_ignited": False,
            "count": count,
        }

    @router.post("/reset", summary="Re-stage the day-one threshold (sandbox only)")
    def reset(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        # Sandbox-only: clear the once-only ignition flag so the day-one door
        # re-appears and the operator can rehearse the first moment again. The
        # discovered inventory is left intact (re-igniting re-scans it), so the
        # spoken count stays genuine. Refused outright when not in sandbox mode
        # — the real fires-once threshold must never be resettable from the wire.
        if os.environ.get("TEX_SANDBOX") != "1":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="not found",
            )
        ignition = _ignition(request)
        tenant = _resolve_tenant(principal, tenant_id)
        ignition.reset(tenant)
        return {"reset": True, "tenant": tenant}

    @router.get("/count", summary="How many now (pull-only)")
    def count(
        request: Request,
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        registry = _registry(request)
        n = _estate_count(registry, _resolve_tenant(principal, tenant_id))
        words = humanize_count(n)
        agents = "agent" if n == 1 else "agents"
        return {"spoken": f"{words.capitalize()} {agents} running.", "object": None, "count": n}

    @router.get("/delta", summary="What changed since a moment (pull-only)")
    def delta(
        request: Request,
        since: datetime = Query(..., description="ISO-8601 timestamp"),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        registry = _registry(request)
        tenant = principal.tenant
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)

        new_agents = [
            a
            for a in registry.list_all()
            if a.tenant_id == tenant and a.registered_at >= since
        ]
        n = len(new_agents)
        if n == 0:
            spoken = "Nothing new."
        else:
            words = humanize_count(n)
            noun = "agent" if n == 1 else "agents"
            spoken = f"{words.capitalize()} new {noun} since then."
        return {"spoken": spoken, "object": None, "count": n, "since": since.isoformat()}

    @router.get("/owner/{agent_id}", summary="Who owns Y (pull-only)")
    def owner(
        request: Request,
        agent_id: UUID,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        registry = _registry(request)
        agent = registry.get(agent_id)
        if agent is None or agent.tenant_id != principal.tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"no agent {agent_id}",
            )
        # Meaning spoken; the exact name is the object that rises.
        return {
            "spoken": f"{agent.owner} owns it.",
            "object": agent.name,
        }

    @router.get(
        "/coverage/{agent_id}",
        summary="The sealed edge of sight for an agent (pull-only)",
    )
    def coverage(
        request: Request,
        agent_id: UUID,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        engine = _engine(request)
        if engine is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="provenance engine not attached",
            )
        boundary = engine.coverage_boundary(agent_id)
        if boundary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"no sealed coverage for agent {agent_id}",
            )
        data = boundary.model_dump(mode="json")
        # The grade spoken; the agent id is the object.
        data["spoken"] = boundary.edge_of_sight
        data["object"] = str(agent_id)
        return data

    @router.get(
        "/held",
        summary="Decisions Tex is holding — the one unprompted voice",
    )
    def held(
        request: Request,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> dict[str, Any]:
        feed = getattr(request.app.state, "provenance_feed", None)
        sink = getattr(request.app.state, "held_decision_sink", None)
        source = sink or (feed.held if feed is not None else None)
        if source is None:
            return {"held": [], "count": 0}
        items = source.peek()
        return {
            "held": [h.to_jsonable() for h in items],
            "count": len(items),
        }

    return router
