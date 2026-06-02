"""
Discovery HTTP routes.

Endpoints:

    POST /v1/discovery/scan              run a scan now (synchronous)
    GET  /v1/discovery/connectors        list wired connectors
    GET  /v1/discovery/connectors/health connector health per tenant
    GET  /v1/discovery/scan_runs         list recent scan runs
    GET  /v1/discovery/scan_runs/{id}    fetch one scan run
    GET  /v1/discovery/ledger            list ledger entries (cursor pagination)
    GET  /v1/discovery/ledger/verify     verify chain integrity
    GET  /v1/discovery/findings/{key}    history for one reconciliation key
    GET  /v1/discovery/agent/{agent_id}  history for one registered agent

Hardening added in V16:

  * **Idempotency**: ``POST /v1/discovery/scan`` accepts an
    ``Idempotency-Key`` header (or ``idempotency_key`` body field). A
    repeat with the same key returns the prior run's result, never a
    second run.
  * **Per-tenant locking**: a second concurrent scan for the same
    tenant returns ``409 Conflict`` with the holder run id so the
    caller can poll instead of racing.
  * **Rate limiting**: per-IP fixed-window limiter on POST /scan to
    keep someone from melting external APIs by spamming the endpoint.
  * **Auth on admin paths**: scan + scan-runs read goes through
    ``authenticate_request``; production deployments with
    ``TEX_API_KEYS`` set keep these surfaces locked.
  * **Tenant scoping**: a keyed principal whose tenant is not
    ``default`` is restricted to its own tenant on every route that
    takes a tenant_id parameter.
  * **Cursor pagination on /ledger**: replaces naive offset slicing.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.rate_limit import IPRateLimiter, enforce
from tex.discovery.service import DiscoveryService, ScanInProgress
from tex.domain.discovery import (
    DiscoveryLedgerEntry,
    DiscoveryScanRun,
    DiscoverySource,
    ReconciliationAction,
)


# ---------------------------------------------------------------------------
# Default rate-limit knobs. Per-IP, fixed window. The limiter itself lives
# on app.state.discovery_scan_rate_limiter so each FastAPI app (including
# each test TestClient) gets its own bucket — module-globals leak state
# between tests.
# ---------------------------------------------------------------------------
DEFAULT_SCAN_RATE_LIMIT_PER_MIN = int(
    os.environ.get("TEX_DISCOVERY_SCAN_RATE_LIMIT_PER_MIN", "60")
)


def _resolve_scan_limiter(request: Request) -> IPRateLimiter:
    """
    Resolve (or lazily build) the per-app scan rate limiter.

    Stored on app.state so tests that build a fresh app get a fresh
    bucket. In production a single app instance is built once at
    process start, so the bucket persists for the life of the process.
    """
    limiter = getattr(request.app.state, "discovery_scan_rate_limiter", None)
    if limiter is None:
        limiter = IPRateLimiter(
            max_per_window=DEFAULT_SCAN_RATE_LIMIT_PER_MIN,
            window_seconds=60,
        )
        request.app.state.discovery_scan_rate_limiter = limiter
    return limiter


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=200)
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=600.0)
    max_candidates_per_connector: int = Field(default=5_000, ge=1, le=100_000)
    name_filter: str | None = Field(default=None, max_length=400)
    idempotency_key: str | None = Field(default=None, max_length=200)
    policy_version: str | None = Field(default=None, max_length=200)


class ConnectorDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    source: DiscoverySource


class ConnectorListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connectors: list[ConnectorDTO]


class ConnectorHealthDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    connector_name: str
    discovery_source: str
    status: str
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_error: str | None = None
    consecutive_failures: int
    last_candidate_count: int | None = None
    last_scan_run_id: str | None = None


class ConnectorHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    health: list[ConnectorHealthDTO]


class ScanSummaryDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    started_at: str
    completed_at: str
    duration_seconds: float
    sources_scanned: list[DiscoverySource]
    candidates_seen: int
    registered_count: int
    updated_drift_count: int
    quarantined_count: int
    no_op_count: int
    held_count: int
    skipped_count: int
    errors: list[str]

    @classmethod
    def from_domain(cls, run: DiscoveryScanRun) -> "ScanSummaryDTO":
        return cls(
            run_id=run.run_id,
            started_at=run.started_at.isoformat(),
            completed_at=run.completed_at.isoformat(),
            duration_seconds=run.duration_seconds,
            sources_scanned=list(run.sources_scanned),
            candidates_seen=run.candidates_seen,
            registered_count=run.registered_count,
            updated_drift_count=run.updated_drift_count,
            quarantined_count=run.quarantined_count,
            no_op_count=run.no_op_count,
            held_count=run.held_count,
            skipped_count=run.skipped_count,
            errors=list(run.errors),
        )


class LedgerEntryDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    candidate_id: UUID
    reconciliation_key: str
    source: DiscoverySource
    name: str
    finding_kind: str
    action: ReconciliationAction
    confidence: float
    risk_band: str
    resulting_agent_id: UUID | None
    findings: list[str]
    decided_at: str
    appended_at: str
    payload_sha256: str
    record_hash: str
    previous_hash: str | None
    tenant_id: str

    @classmethod
    def from_entry(cls, entry: DiscoveryLedgerEntry) -> "LedgerEntryDTO":
        return cls(
            sequence=entry.sequence,
            candidate_id=entry.candidate.candidate_id,
            reconciliation_key=entry.outcome.reconciliation_key,
            source=entry.candidate.source,
            name=entry.candidate.name,
            finding_kind=entry.outcome.finding_kind.value,
            action=entry.outcome.action,
            confidence=entry.outcome.confidence,
            risk_band=entry.candidate.risk_band.value,
            resulting_agent_id=entry.outcome.resulting_agent_id,
            findings=list(entry.outcome.findings),
            decided_at=entry.outcome.decided_at.isoformat(),
            appended_at=entry.appended_at.isoformat(),
            payload_sha256=entry.payload_sha256,
            record_hash=entry.record_hash,
            previous_hash=entry.previous_hash,
            tenant_id=entry.candidate.tenant_id,
        )


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: ScanSummaryDTO
    entries: list[LedgerEntryDTO]
    scan_run_id: UUID | None = None
    ledger_seq_start: int | None = None
    ledger_seq_end: int | None = None
    registry_state_hash: str | None = None
    policy_version: str | None = None
    idempotent_replay: bool = False


class LedgerListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[LedgerEntryDTO]
    total: int
    next_cursor: int | None = None


class ChainVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_valid: bool
    record_count: int


class ScanRunDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    tenant_id: str
    status: str
    started_at: str
    completed_at: str | None = None
    last_heartbeat_at: str
    trigger: str
    idempotency_key: str | None = None
    ledger_seq_start: int | None = None
    ledger_seq_end: int | None = None
    registry_state_hash: str | None = None
    policy_version: str | None = None
    summary: dict
    error: str | None = None
    duration_seconds: float | None = None


class ScanRunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runs: list[ScanRunDTO]
    total: int


# ---------------------------------------------------------------------------
# Tenant guard helper
# ---------------------------------------------------------------------------


def _enforce_tenant_scope(
    principal: TexPrincipal, requested_tenant_id: str | None,
) -> None:
    """
    Reject calls where a keyed principal scoped to one tenant tries to
    read/write another tenant. Anonymous and "default"-tenant keys are
    allowed to operate cross-tenant since those represent ungated and
    operator-grade access.
    """
    if principal is None or principal.is_anonymous:
        return
    if principal.tenant == "default":
        return
    if requested_tenant_id is None:
        return
    if principal.tenant.casefold() != requested_tenant_id.strip().casefold():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key tenant does not match request tenant_id",
        )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def build_discovery_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/discovery",
        tags=["discovery"],
        dependencies=[Depends(authenticate_request)],
    )

    @router.post(
        "/scan",
        response_model=ScanResponse,
        summary="Run a discovery scan now (idempotent, locked per tenant, rate-limited)",
    )
    def run_scan(
        payload: ScanRequest,
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
        idempotency_header: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> ScanResponse:
        _enforce_tenant_scope(principal, payload.tenant_id)
        enforce(_resolve_scan_limiter(request), request)

        service = _resolve_service(request)
        idempotency_key = idempotency_header or payload.idempotency_key

        # Detect a replay BEFORE calling the service so we can mark the
        # response correctly. The service's own idempotency check still
        # owns the canonical decision.
        is_replay = False
        scan_run_store = getattr(request.app.state, "scan_run_store", None)
        if scan_run_store is not None and idempotency_key:
            existing_runs = scan_run_store.list_recent(
                tenant_id=payload.tenant_id, limit=200,
            )
            for r in existing_runs:
                if r.idempotency_key == idempotency_key:
                    is_replay = True
                    break

        try:
            result = service.scan(
                tenant_id=payload.tenant_id,
                timeout_seconds=payload.timeout_seconds,
                max_candidates_per_connector=payload.max_candidates_per_connector,
                name_filter=payload.name_filter,
                trigger="manual",
                idempotency_key=idempotency_key,
                policy_version=payload.policy_version,
            )
        except ScanInProgress as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "scan_in_progress",
                    "tenant_id": exc.tenant_id,
                    "holder_run_id": str(exc.holder_run_id),
                    "message": (
                        "another scan is currently running for this tenant; "
                        "poll /v1/discovery/scan_runs/{holder_run_id} or retry "
                        "after it completes"
                    ),
                },
            ) from exc

        return ScanResponse(
            summary=ScanSummaryDTO.from_domain(result.summary),
            entries=[LedgerEntryDTO.from_entry(e) for e in result.entries],
            scan_run_id=result.scan_run_id,
            ledger_seq_start=result.ledger_seq_start,
            ledger_seq_end=result.ledger_seq_end,
            registry_state_hash=result.registry_state_hash,
            policy_version=result.policy_version,
            idempotent_replay=is_replay,
        )

    @router.get(
        "/connectors",
        response_model=ConnectorListResponse,
        summary="List wired discovery connectors",
    )
    def list_connectors(request: Request) -> ConnectorListResponse:
        service = _resolve_service(request)
        return ConnectorListResponse(
            connectors=[
                ConnectorDTO(name=c.name, source=c.source)
                for c in service.list_connectors()
            ]
        )

    @router.get(
        "/connectors/health",
        response_model=ConnectorHealthResponse,
        summary="Per-connector health for one tenant",
    )
    def connectors_health(
        request: Request,
        tenant_id: str = Query(..., min_length=1, max_length=200),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> ConnectorHealthResponse:
        _enforce_tenant_scope(principal, tenant_id)
        store = getattr(request.app.state, "connector_health_store", None)
        if store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="connector health store is not configured",
            )
        records = store.list_for_tenant(tenant_id)
        return ConnectorHealthResponse(
            tenant_id=tenant_id.strip().casefold(),
            health=[ConnectorHealthDTO(**r.to_dict()) for r in records],
        )

    @router.get(
        "/ledger",
        response_model=LedgerListResponse,
        summary="List discovery ledger entries (cursor pagination)",
    )
    def list_ledger(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
        cursor: int | None = Query(
            default=None, ge=0,
            description="Sequence number to start AFTER (exclusive).",
        ),
        offset: int = Query(default=0, ge=0, description="Legacy offset; cursor preferred."),
        tenant_id: str | None = Query(default=None, max_length=200),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> LedgerListResponse:
        _enforce_tenant_scope(principal, tenant_id)

        # If a non-default keyed principal didn't pass tenant_id, scope
        # them to their own tenant so they can't see cross-tenant data.
        effective_tenant = tenant_id
        if (
            tenant_id is None
            and not principal.is_anonymous
            and principal.tenant != "default"
        ):
            effective_tenant = principal.tenant

        ledger = _resolve_ledger(request)
        all_entries = ledger.list_all()

        if effective_tenant is not None:
            normalized = effective_tenant.strip().casefold()
            all_entries = tuple(
                e for e in all_entries if e.candidate.tenant_id == normalized
            )

        if cursor is not None:
            start_idx = len(all_entries)
            for i, e in enumerate(all_entries):
                if e.sequence > cursor:
                    start_idx = i
                    break
            sliced = all_entries[start_idx : start_idx + limit]
        else:
            sliced = all_entries[offset : offset + limit]

        next_cursor = sliced[-1].sequence if sliced and len(sliced) == limit else None
        return LedgerListResponse(
            entries=[LedgerEntryDTO.from_entry(e) for e in sliced],
            total=len(all_entries),
            next_cursor=next_cursor,
        )

    @router.get(
        "/ledger/verify",
        response_model=ChainVerifyResponse,
        summary="Verify integrity of the discovery ledger chain",
    )
    def verify_ledger(request: Request) -> ChainVerifyResponse:
        ledger = _resolve_ledger(request)
        return ChainVerifyResponse(
            is_valid=ledger.verify_chain(),
            record_count=len(ledger),
        )

    @router.get(
        "/scan_runs",
        response_model=ScanRunListResponse,
        summary="List recent scan runs (durable)",
    )
    def list_scan_runs(
        request: Request,
        tenant_id: str | None = Query(default=None, max_length=200),
        limit: int = Query(default=50, ge=1, le=500),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> ScanRunListResponse:
        store = getattr(request.app.state, "scan_run_store", None)
        if store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="scan run store is not configured",
            )
        _enforce_tenant_scope(principal, tenant_id)
        effective_tenant = tenant_id
        if (
            tenant_id is None
            and not principal.is_anonymous
            and principal.tenant != "default"
        ):
            effective_tenant = principal.tenant
        runs = store.list_recent(tenant_id=effective_tenant, limit=limit)
        return ScanRunListResponse(
            runs=[
                ScanRunDTO(duration_seconds=r.duration_seconds, **r.to_dict())
                for r in runs
            ],
            total=len(runs),
        )

    @router.get(
        "/scan_runs/{run_id}",
        response_model=ScanRunDTO,
        summary="Fetch one scan run by id",
    )
    def get_scan_run(
        request: Request,
        run_id: UUID = Path(...),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> ScanRunDTO:
        store = getattr(request.app.state, "scan_run_store", None)
        if store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="scan run store is not configured",
            )
        run = store.get(run_id)
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"scan run not found: {run_id}",
            )
        if (
            not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != run.tenant_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match scan run tenant",
            )
        return ScanRunDTO(duration_seconds=run.duration_seconds, **run.to_dict())

    @router.get(
        "/findings/{reconciliation_key:path}",
        response_model=LedgerListResponse,
        summary="History of discovery outcomes for one reconciliation key",
    )
    def list_for_key(
        request: Request,
        reconciliation_key: str = Path(..., min_length=1),
    ) -> LedgerListResponse:
        ledger = _resolve_ledger(request)
        entries = ledger.list_for_key(reconciliation_key)
        return LedgerListResponse(
            entries=[LedgerEntryDTO.from_entry(e) for e in entries],
            total=len(entries),
        )

    @router.get(
        "/agent/{agent_id}",
        response_model=LedgerListResponse,
        summary="Discovery history for one registered agent_id",
    )
    def list_for_agent(
        request: Request,
        agent_id: UUID = Path(...),
    ) -> LedgerListResponse:
        ledger = _resolve_ledger(request)
        entries = ledger.list_for_agent_id(str(agent_id))
        return LedgerListResponse(
            entries=[LedgerEntryDTO.from_entry(e) for e in entries],
            total=len(entries),
        )

    @router.get(
        "/metrics",
        summary="In-process discovery metrics (scans, drift, alerts, snapshots)",
    )
    def discovery_metrics(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> dict:
        metrics = getattr(request.app.state, "discovery_metrics", None)
        if metrics is None:
            return {"enabled": False}
        return {"enabled": True, **metrics.snapshot()}

    return router


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------


def _resolve_service(request: Request) -> DiscoveryService:
    service = getattr(request.app.state, "discovery_service", None)
    if not isinstance(service, DiscoveryService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery service not wired into runtime",
        )
    return service


def _resolve_ledger(request: Request):
    ledger = getattr(request.app.state, "discovery_ledger", None)
    if ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery ledger not wired into runtime",
        )
    return ledger
