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
    discovery_ledger_length: int = 0
    discovery_chain_intact: bool = True
    snapshot_chain_intact: bool = True
    snapshot_chain_checked: int = 0
    snapshot_count: int = 0
    durable_persistence: bool = False


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
        governance = _governance_block(request)

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


def _governance_block(request: Request) -> SystemGovernanceDTO:
    try:
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
        counts = gov.counts
        total = counts.total_agents
        governed_pct = (
            round(100.0 * counts.governed / total, 2) if total else 0.0
        )
        return SystemGovernanceDTO(
            total_agents=total,
            governed=counts.governed,
            ungoverned=counts.ungoverned,
            partial=counts.partial,
            unknown=counts.unknown,
            governed_pct=governed_pct,
            high_risk_total=counts.high_risk_total,
            high_risk_ungoverned=counts.high_risk_ungoverned,
            coverage_root_sha256=gov.coverage_root_sha256 or "",
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
        except Exception:  # noqa: BLE001
            out.discovery_chain_intact = False

    snapshot_store = getattr(request.app.state, "governance_snapshot_store", None)
    if snapshot_store is not None:
        try:
            verify = snapshot_store.verify_chain(limit=200)
            out.snapshot_chain_intact = bool(verify.get("intact"))
            out.snapshot_chain_checked = int(verify.get("checked") or 0)
            out.snapshot_count = len(snapshot_store)
        except Exception:  # noqa: BLE001
            out.snapshot_chain_intact = False

    return out


__all__ = ["build_system_state_router", "SystemStateResponse"]
