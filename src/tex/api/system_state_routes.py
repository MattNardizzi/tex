"""
System state endpoint.

One read-only endpoint that aggregates everything a dashboard or
ops console needs to know:

    GET /v1/system/state[?tenant_id=...]

Returns:

  * version          — deployment/build identifiers
  * governance       — current % governed / ungoverned / partial / unknown
  * last_scan        — when discovery last ran, success/failure, ledger range
  * connector_health — per-connector status for the requested tenant
  * latest_drift     — recent NEW/CHANGED/DISAPPEARED events
  * scheduler        — running, interval, drift durability, alerts enabled
  * evidence_chain   — discovery ledger length + chain integrity boolean
  * snapshot_chain   — governance snapshot chain status

This is a strict read; no side effects, no scan trigger. The /v1/discovery/scan
endpoint stays the only thing that mutates discovery state.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import TexPrincipal, authenticate_request


class SystemVersionDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str
    version: str


class SystemGovernanceDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_agents: int = 0
    governed: int = 0
    ungoverned: int = 0
    partial: int = 0
    unknown: int = 0
    governed_pct: float = 0.0
    high_risk_total: int = 0
    high_risk_ungoverned: int = 0
    coverage_root_sha256: str = ""


class SystemLastScanDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    has_run: bool = False
    run_id: str | None = None
    tenant_id: str | None = None
    status: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    candidates_seen: int | None = None
    registered_count: int | None = None
    errors_count: int | None = None
    error: str | None = None
    ledger_seq_start: int | None = None
    ledger_seq_end: int | None = None


class SystemConnectorDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connector_name: str
    discovery_source: str
    status: str
    consecutive_failures: int
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_candidate_count: int | None = None
    last_error: str | None = None


class SystemSchedulerDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    running: bool = False
    interval_seconds: int | None = None
    tenants: list[str] = Field(default_factory=list)
    last_run_completed_at: float | None = None
    drift_durable: bool = False
    alerts_enabled: bool = False
    alert_sinks: list[str] = Field(default_factory=list)
    presence_tracker_enabled: bool = False
    presence_threshold: int | None = None


class SystemDriftSnapshotDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    occurred_at: str
    kind: str
    severity: str
    summary: str
    reconciliation_key: str
    discovery_source: str | None = None
    tenant_id: str
    scan_run_id: str | None = None


class SystemChainDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # HONEST SCOPE: unlike governance/last_scan/connectors/drift, this
    # block is NOT scoped to the principal's tenant — and cannot be. The
    # discovery ledger and the governance-snapshot store are single
    # append-only hash chains shared by every tenant; chain integrity is
    # a property of the whole chain, not of any one tenant's slice (you
    # cannot filter a hash chain by tenant without breaking the very
    # linkage the boolean attests to). That is also the right answer for
    # the surface: "can Tex still prove what it sealed?" is a system-wide
    # truth, not a per-tenant one (see the Vigil hook — a broken chain is
    # what flips EVERY tenant's surface into the faltering state). So we
    # label the block ``scope="global"`` rather than imply it belongs to
    # the requesting tenant. Additive + backward-compatible.
    scope: str = "global"
    discovery_ledger_length: int = 0
    discovery_chain_intact: bool = True
    snapshot_chain_intact: bool = True
    snapshot_chain_checked: int = 0
    snapshot_count: int = 0
    durable_persistence: bool = False
    # Real break timestamps. Both are ``None`` when the chain is intact;
    # NEVER a fabricated ``datetime.now()``. These are additive and
    # backward-compatible with the always-on chain booleans above — the
    # UI's "Tex is down" / faltering surface reads them but defaults to
    # safe-intact when absent.
    #
    # HONEST CAVEAT: each is the recorded write-time of the OFFENDING
    # record (snapshot ``captured_at`` / ledger ``appended_at``), not a
    # separate "we detected the break at" time. Tex records no distinct
    # detection timestamp; this is the most faithful real time available.
    snapshot_broke_at: str | None = None
    discovery_broke_at: str | None = None


class SystemStateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: SystemVersionDTO
    tenant_id: str | None = None
    generated_at: str
    governance: SystemGovernanceDTO
    last_scan: SystemLastScanDTO
    connector_health: list[SystemConnectorDTO] = Field(default_factory=list)
    scheduler: SystemSchedulerDTO
    latest_drift: list[SystemDriftSnapshotDTO] = Field(default_factory=list)
    chain: SystemChainDTO


def build_system_state_router() -> APIRouter:
    """
    Mount /v1/system/state. Authenticated when API keys are configured;
    a keyed principal with a non-default tenant is scoped to that tenant.
    """
    router = APIRouter(prefix="/v1/system", tags=["system"])

    @router.get(
        "/state",
        response_model=SystemStateResponse,
        summary="Aggregate read of governance %, last scan, health, drift, scheduler, chain",
    )
    def system_state(
        request: Request,
        tenant_id: str | None = Query(default=None, max_length=200),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SystemStateResponse:
        # Scope by principal if no tenant_id provided.
        effective_tenant = tenant_id
        if (
            tenant_id is None
            and not principal.is_anonymous
            and principal.tenant != "default"
        ):
            effective_tenant = principal.tenant
        elif (
            tenant_id is not None
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != tenant_id.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match query tenant_id",
            )

        from datetime import UTC, datetime

        from tex.main import APP_TITLE, APP_VERSION

        version_block = SystemVersionDTO(service=APP_TITLE, version=APP_VERSION)

        # ---- governance --------------------------------------------------
        # Scoped to the principal's tenant (see _governance_block): the
        # aggregate here must never sum another estate's rows under this
        # tenant's label.
        governance = _governance_block(request, principal)

        # ---- last scan ---------------------------------------------------
        last_scan = _last_scan_block(request, effective_tenant)

        # ---- connector health -------------------------------------------
        connector_health = _connector_health_block(request, effective_tenant)

        # ---- scheduler ---------------------------------------------------
        scheduler = _scheduler_block(request)

        # ---- drift -------------------------------------------------------
        latest_drift = _drift_block(request, effective_tenant)

        # ---- chain -------------------------------------------------------
        chain = _chain_block(request)

        return SystemStateResponse(
            version=version_block,
            tenant_id=effective_tenant,
            generated_at=datetime.now(UTC).isoformat(),
            governance=governance,
            last_scan=last_scan,
            connector_health=connector_health,
            scheduler=scheduler,
            latest_drift=latest_drift,
            chain=chain,
        )

    return router


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------


def _governance_block(
    request: Request, principal: TexPrincipal,
) -> SystemGovernanceDTO:
    try:
        import hashlib

        from tex.api.agent_routes import (
            _build_governance,
            _resolve_discovery_ledger,
            _resolve_ledger,
            _resolve_registry,
        )
        registry = _resolve_registry(request)
        action_ledger = _resolve_ledger(request)
        discovery_ledger = _resolve_discovery_ledger(request)
        gov = _build_governance(
            registry=registry,
            action_ledger=action_ledger,
            discovery_ledger=discovery_ledger,
        )

        # ``_build_governance`` walks the FULL registry + discovery ledger
        # with no tenant filter — the aggregate it returns is estate-wide.
        # Returning that under a tenant's label is the leak: a tenant-A key
        # would read tenant-B's governed/ungoverned counts as its own.
        #
        # So we recompute the aggregate over ONLY the rows belonging to the
        # principal's tenant, mirroring the exact post-filter the
        # ``GET /v1/agents/governance`` route applies (agent_routes.py
        # ``governance_state``): filter ``gov.agents`` by casefolded
        # tenant_id, then re-derive the counts + coverage root from that
        # filtered set so the aggregate stays consistent with what the
        # principal is actually allowed to see. Operator-grade principals
        # (anonymous / default-tenant / admin:cross_tenant) keep the full
        # estate view, same as everywhere else.
        from tex.api.auth import SCOPE_CROSS_TENANT

        if (
            principal.is_anonymous
            or SCOPE_CROSS_TENANT in principal.scopes
            or principal.tenant == "default"
        ):
            rows = list(gov.agents)
            coverage_root = gov.coverage_root_sha256 or ""
        else:
            target = principal.tenant.casefold()
            rows = [
                row for row in gov.agents
                if (row.tenant_id or "").casefold() == target
            ]
            # Re-derive the coverage root over the filtered rows so the
            # published hash binds exactly the tenant's own set — never a
            # root computed over agents this tenant cannot see. Same
            # ``agent_id|reconciliation_key|state`` line shape and sort
            # order as ``_build_governance``.
            coverage_lines = sorted(
                f"{row.agent_id or ''}|{row.reconciliation_key or ''}"
                f"|{row.governance_state}"
                for row in rows
            )
            coverage_root = hashlib.sha256(
                "\n".join(coverage_lines).encode("utf-8")
            ).hexdigest()

        from collections import Counter

        states = Counter(row.governance_state for row in rows)
        high_risk_rows = [
            row for row in rows
            if isinstance(row.risk_band, str)
            and row.risk_band.upper() in {"HIGH", "CRITICAL"}
        ]
        total = len(rows)
        governed = states.get("GOVERNED", 0)
        governed_pct = round(100.0 * governed / total, 2) if total else 0.0
        return SystemGovernanceDTO(
            total_agents=total,
            governed=governed,
            ungoverned=states.get("UNGOVERNED", 0),
            partial=states.get("PARTIAL", 0),
            unknown=states.get("UNKNOWN", 0),
            governed_pct=governed_pct,
            high_risk_total=len(high_risk_rows),
            high_risk_ungoverned=sum(
                1 for row in high_risk_rows
                if row.governance_state == "UNGOVERNED"
            ),
            coverage_root_sha256=coverage_root,
        )
    except Exception:  # noqa: BLE001
        return SystemGovernanceDTO()


def _last_scan_block(request: Request, tenant_id: str | None) -> SystemLastScanDTO:
    store = getattr(request.app.state, "scan_run_store", None)
    if store is None:
        return SystemLastScanDTO(has_run=False)

    # If a tenant is in scope, prefer that tenant's latest run; else
    # take the latest across all tenants.
    runs = store.list_recent(tenant_id=tenant_id, limit=1)
    if not runs:
        return SystemLastScanDTO(has_run=False)
    r = runs[0]
    s = r.summary or {}
    return SystemLastScanDTO(
        has_run=True,
        run_id=str(r.run_id),
        tenant_id=r.tenant_id,
        status=str(r.status),
        started_at=r.started_at.isoformat() if r.started_at else None,
        completed_at=r.completed_at.isoformat() if r.completed_at else None,
        duration_seconds=r.duration_seconds,
        candidates_seen=s.get("candidates_seen"),
        registered_count=s.get("registered_count"),
        errors_count=len(s.get("errors", []) or []),
        error=r.error,
        ledger_seq_start=r.ledger_seq_start,
        ledger_seq_end=r.ledger_seq_end,
    )


def _connector_health_block(
    request: Request, tenant_id: str | None,
) -> list[SystemConnectorDTO]:
    store = getattr(request.app.state, "connector_health_store", None)
    if store is None:
        return []
    if tenant_id is not None:
        records = store.list_for_tenant(tenant_id)
    else:
        records = store.list_all()
    return [
        SystemConnectorDTO(
            connector_name=r.connector_name,
            discovery_source=r.discovery_source,
            status=str(r.status),
            consecutive_failures=r.consecutive_failures,
            last_success_at=(
                r.last_success_at.isoformat() if r.last_success_at else None
            ),
            last_failure_at=(
                r.last_failure_at.isoformat() if r.last_failure_at else None
            ),
            last_candidate_count=r.last_candidate_count,
            last_error=r.last_error,
        )
        for r in records
    ]


def _scheduler_block(request: Request) -> SystemSchedulerDTO:
    sched = getattr(request.app.state, "scan_scheduler", None)
    if sched is None:
        return SystemSchedulerDTO(enabled=False, running=False)
    s = sched.status
    return SystemSchedulerDTO(
        enabled=True,
        running=bool(s.get("running")),
        interval_seconds=s.get("interval_seconds"),
        tenants=list(s.get("tenants") or []),
        last_run_completed_at=s.get("last_run_completed_at"),
        drift_durable=bool(s.get("drift_durable")),
        alerts_enabled=bool(s.get("alerts_enabled")),
        alert_sinks=list(s.get("alert_sinks") or []),
        presence_tracker_enabled=bool(s.get("presence_tracker_enabled")),
        presence_threshold=s.get("presence_threshold"),
    )


def _drift_block(
    request: Request, tenant_id: str | None,
) -> list[SystemDriftSnapshotDTO]:
    store = getattr(request.app.state, "drift_event_store", None)
    if store is None:
        return []
    try:
        if tenant_id:
            events = store.list_for_tenant(tenant_id, limit=10)
        else:
            events = store.list_recent(limit=10)
    except Exception:  # noqa: BLE001
        return []
    return [
        SystemDriftSnapshotDTO(
            event_id=str(e.event_id),
            occurred_at=e.occurred_at.isoformat(),
            kind=str(e.kind),
            severity=e.severity,
            summary=e.summary,
            reconciliation_key=e.reconciliation_key,
            discovery_source=e.discovery_source,
            tenant_id=e.tenant_id,
            scan_run_id=str(e.scan_run_id) if e.scan_run_id else None,
        )
        for e in events
    ]


def _chain_block(request: Request) -> SystemChainDTO:
    out = SystemChainDTO()
    discovery_ledger = getattr(request.app.state, "discovery_ledger", None)
    if discovery_ledger is not None:
        try:
            out.discovery_ledger_length = len(discovery_ledger)
            out.discovery_chain_intact = bool(discovery_ledger.verify_chain())
            durable = getattr(discovery_ledger, "is_durable", False)
            if durable:
                out.durable_persistence = True
            # Real break time when (and only when) the chain is broken.
            # ``find_break`` returns the offending entry; its
            # ``appended_at`` is its real write-time, never now().
            if not out.discovery_chain_intact:
                find_break = getattr(discovery_ledger, "find_break", None)
                if callable(find_break):
                    broken = find_break()
                    appended_at = getattr(broken, "appended_at", None)
                    if appended_at is not None:
                        out.discovery_broke_at = appended_at.isoformat()
        except Exception:  # noqa: BLE001
            out.discovery_chain_intact = False

    snapshot_store = getattr(request.app.state, "governance_snapshot_store", None)
    if snapshot_store is not None:
        try:
            verify = snapshot_store.verify_chain(limit=200)
            out.snapshot_chain_intact = bool(verify.get("intact"))
            out.snapshot_chain_checked = int(verify.get("checked") or 0)
            out.snapshot_count = len(snapshot_store)
            # Real break time: the offending snapshot's recorded
            # ``captured_at``. ``verify_chain`` returns the break index
            # into the SAME oldest→newest chain order that ``list_recent``
            # (reversed) produces, so we read that record's captured_at.
            # HONEST: this is the snapshot's captured_at, not a separate
            # detection time. Never now().
            if not out.snapshot_chain_intact:
                break_idx = verify.get("break_at_index")
                if isinstance(break_idx, int) and break_idx >= 0:
                    recent = snapshot_store.list_recent(limit=200)
                    chain = list(reversed(recent))
                    if break_idx < len(chain):
                        captured_at = chain[break_idx].get("captured_at")
                        if captured_at:
                            out.snapshot_broke_at = str(captured_at)
        except Exception:  # noqa: BLE001
            out.snapshot_chain_intact = False

    return out


__all__ = ["build_system_state_router", "SystemStateResponse"]
