"""
Discovery HTTP routes.

Endpoints:

    POST /v1/discovery/scan              run a scan now (synchronous)
    GET  /v1/discovery/connectors        list wired connectors
    GET  /v1/discovery/ledger            list ledger entries (paginated)
    GET  /v1/discovery/ledger/verify     verify chain integrity
    GET  /v1/discovery/findings/{key}    history for one reconciliation key
    GET  /v1/discovery/agent/{agent_id}  history for one registered agent

The routes pull stores out of `app.state.discovery_service` and
`app.state.discovery_ledger`. They never bypass the service to
mutate the registry directly — discovery flows through the service
exactly so the audit story stays consistent.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.discovery.service import DiscoveryService
from tex.domain.discovery import (
    DiscoveryLedgerEntry,
    DiscoveryScanRun,
    DiscoverySource,
    ReconciliationAction,
)
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=200)
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=600.0)
    max_candidates_per_connector: int = Field(default=5_000, ge=1, le=100_000)
    name_filter: str | None = Field(default=None, max_length=400)


class ConnectorDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    source: DiscoverySource


class ConnectorListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connectors: list[ConnectorDTO]


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
        )


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: ScanSummaryDTO
    entries: list[LedgerEntryDTO]


class LedgerListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: list[LedgerEntryDTO]
    total: int


class ChainVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    record_count: int


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def build_discovery_router() -> APIRouter:
    """
    Build the FastAPI router for discovery endpoints.

    Stores are resolved from app.state, the same pattern the agent
    governance routes use.
    """
    router = APIRouter(prefix="/v1/discovery", tags=["discovery"])

    @router.post(
        "/scan",
        response_model=ScanResponse,
        summary="Run a discovery scan now",
    )
    def run_scan(payload: ScanRequest, request: Request) -> ScanResponse:
        service = _resolve_service(request)
        result = service.scan(
            tenant_id=payload.tenant_id,
            timeout_seconds=payload.timeout_seconds,
            max_candidates_per_connector=payload.max_candidates_per_connector,
            name_filter=payload.name_filter,
        )
        return ScanResponse(
            summary=ScanSummaryDTO.from_domain(result.summary),
            entries=[LedgerEntryDTO.from_entry(e) for e in result.entries],
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
        "/ledger",
        response_model=LedgerListResponse,
        summary="List discovery ledger entries",
    )
    def list_ledger(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
        offset: int = Query(default=0, ge=0),
    ) -> LedgerListResponse:
        ledger = _resolve_ledger(request)
        all_entries = ledger.list_all()
        sliced = all_entries[offset : offset + limit]
        return LedgerListResponse(
            entries=[LedgerEntryDTO.from_entry(e) for e in sliced],
            total=len(all_entries),
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

    return router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_service(request: Request) -> DiscoveryService:
    service = getattr(request.app.state, "discovery_service", None)
    if not isinstance(service, DiscoveryService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery service not wired into runtime",
        )
    return service


def _resolve_ledger(request: Request) -> InMemoryDiscoveryLedger:
    ledger = getattr(request.app.state, "discovery_ledger", None)
    if not isinstance(ledger, InMemoryDiscoveryLedger):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="discovery ledger not wired into runtime",
        )
    return ledger
