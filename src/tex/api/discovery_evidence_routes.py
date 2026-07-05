"""
Remote evidence-push ingress — the front door discovery was missing.

Tex's discovery engine measures agents from the *traces they leave*. Most planes
read a source Tex can reach on its own (a repo, a connected directory, the gate
calls agents already make). But an estate Tex is not on — a laptop, a customer
VPC, a CI runner — leaves its traces THERE, and a hosted backend cannot read a
disk it is not attached to. The industry answer is not to reach in; it is to let
a cooperating vantage on the estate push traces OUT. This route is that vantage's
landing pad.

``POST /v1/discovery/evidence`` accepts a batch of gate-shaped / OTel-GenAI event
dicts and drops each into the SAME in-process ring buffer ``/v1/govern/decide``
feeds (``record_decision``). The P11 governance-stream sensor already normalizes
that vocabulary (``otel_trace_id``, ``tool_name``/``operation``, ``agent_name``,
``otel_span_tokens`` …), so a pushed span is discovered on the next sweep of that
tenant's estate exactly as a gate call is — no new sensor, just the missing
ingress. This closes the INGRESS half of the estate-reach gap; discovery is NOT
automatic on push. Three things must also hold, and a push triggers none of them:

  - the estate must run a cooperating collector pointed at this URL (an
    OpenTelemetry collector re-pointed here, or a ~20-line shipper);
  - the P11 governance-stream plane must be ARMED (the default, because
    ``build_sieve_driver`` lights ``TEX_SIEVE_ALL``; an explicit
    ``TEX_SIEVE_ENABLED=0`` or ``TEX_SIEVE_P11_OTEL=0`` turns it off);
  - a sweep must actually RUN for that tenant (Begin/ignite, or the standing
    watch). A push only BUFFERS — discovery happens when the armed sweep next
    drains the buffer. Push into a tenant that never ignites and mint nobody.

Tex stays hosted throughout; only the collector lives on the estate.

Two invariants make this safe as a PUBLIC surface (the gate never had to care,
because it only ever saw first-party calls):

1. **Server-authoritative tenant.** Every event is stamped with the tenant
   resolved from the authenticated principal, and ALL client-supplied tenant
   alias forms (``tenant``/``tenant_id``) are stripped first — a client cannot
   smuggle a foreign tenant through any field. This SERVER STAMP is what
   guarantees isolation: the sweep's tenant scoping
   (``GovernanceStreamSensor._scope_to_tenant``) is lenient — an UNSTAMPED row
   stays in every tenant's cohort — so isolation depends on every writer to the
   shared buffer stamping the tenant, not on the sweep filter alone. Because
   this endpoint always stamps, evidence pushed HERE can never mint into another
   tenant's estate. (The tenant guarantee is for AUTHENTICATED principals; the
   anonymous-all-tenants principal is dev-only by the auth posture — prod fails
   closed with 401 when no keys are configured, see ``auth.py``.)
2. **Single-process buffer.** The ring is per-process/per-pod and in-memory.
   Prod runs a single uvicorn worker (``--workers 1``, Dockerfile) AND a single
   replica (helm ``values.yaml replicas: 1``) — both on purpose. Any horizontal
   scale — more workers OR more replicas — splits the buffer, so a push can land
   in a process that never sweeps and be silently dropped (under-discovery, not
   a leak). A durable/shared buffer (a single-writer evidence service) is the
   prerequisite for HA — tracked, not yet shipped.

Ingest NEVER fails a push over a single bad row and NEVER raises into the caller:
malformed events are counted as rejected, not 500'd — evidence collection is
best-effort telemetry, not a transaction.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, TexPrincipal

__all__ = ["build_discovery_evidence_router"]

#: Cap on events accepted in one push. Bounds the request and the share of the
#: 5000-slot ring a single call can claim; a collector with more ships batches.
_MAX_EVENTS_PER_PUSH = 1000

#: Every field the sweep reads as an event's tenant. The handler strips ALL of
#: them from client input before stamping the one server-authoritative value, so
#: no stale alias (e.g. a client ``tenant_id``) can linger in the buffered row.
#: Kept in sync with ``governance_stream._TENANT_ALIASES`` (case-insensitive).
_TENANT_ALIAS_KEYS = frozenset({"tenant", "tenant_id"})


class EvidencePushRequest(BaseModel):
    """A batch of discovery evidence from a cooperating vantage on the estate.

    ``events`` are free-form mappings — the collector sends whatever it has, and
    the P11 sensor's alias tables pick out the fields it understands (agent
    handle, trace id, tool/operation, billing account, token counts). An event
    with no attributable agent handle is simply not a footprint and is dropped by
    the sensor, never an error here.

    ``tenant_id`` is an OPTIONAL tenant SELECTOR — honored only when the key is
    authorized for it (``can_access_tenant``), otherwise ignored in favor of the
    principal's own tenant. It selects, it does not merely narrow: an authorized
    multi-tenant key uses it to route the push to a specific one of its tenants.
    A client can never push INTO a tenant it is not authorized for.

    ``events`` is typed ``list[Any]`` on purpose: a single malformed row must not
    422 the whole batch (a collector shipping thousands of spans would lose all
    of them over one bad one). Non-mapping rows are counted as ``rejected`` in
    the handler, best-effort telemetry rather than a transaction.
    """

    events: list[Any] = Field(default_factory=list)
    tenant_id: str | None = Field(default=None, max_length=200)


def _resolve_tenant(principal: TexPrincipal, override: str | None) -> str:
    """The tenant every event in this push is stamped with — server-authoritative.

    Mirrors the governance decide route: an override is honored only when the
    principal may access it; otherwise the push lands in the principal's own
    tenant. Never trusts a client-declared tenant beyond what the key allows.
    """
    if override and principal.can_access_tenant(override):
        return override.strip().casefold()
    return principal.tenant


def build_discovery_evidence_router() -> APIRouter:
    router = APIRouter(prefix="/v1/discovery", tags=["discovery-evidence"])

    @router.post(
        "/evidence",
        summary="Push agent activity evidence from a vantage Tex cannot reach",
    )
    def push_evidence(
        request: Request,
        body: EvidencePushRequest,
        principal: TexPrincipal = Depends(RequireScope("decision:write")),
    ) -> dict[str, Any]:
        tenant = _resolve_tenant(principal, body.tenant_id)

        from tex.discovery.engine.sensors.governance_stream import record_decision

        accepted = 0
        rejected = 0
        for event in body.events[:_MAX_EVENTS_PER_PUSH]:
            if not isinstance(event, dict):
                rejected += 1
                continue
            # Server-authoritative tenant: strip EVERY client-supplied tenant
            # alias (case-insensitively), then stamp the one resolved value, so a
            # push can only ever land in the tenant the key is scoped to and no
            # stale alias survives in the buffered row. This server stamp — not
            # the lenient sweep filter — is what guarantees cross-tenant isolation.
            row = {
                k: v
                for k, v in event.items()
                if not (isinstance(k, str) and k.strip().casefold() in _TENANT_ALIAS_KEYS)
            }
            row["tenant"] = tenant
            record_decision(row)
            accepted += 1

        # Anything beyond the cap is truncated — reported honestly, not silently.
        truncated = max(0, len(body.events) - _MAX_EVENTS_PER_PUSH)

        return {
            "accepted": accepted,
            "rejected": rejected,
            "truncated": truncated,
            "tenant": tenant,
        }

    return router
