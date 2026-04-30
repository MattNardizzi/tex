"""
V15 governance/observability HTTP routes.

Endpoints:

    POST /v1/agents/governance/snapshot         capture a snapshot now
    GET  /v1/agents/governance/snapshots        list recent snapshots
    GET  /v1/agents/governance/snapshots/{id}   fetch one snapshot
    GET  /v1/agents/governance/snapshots/{id}/evidence_bundle
                                                regulator-grade export
    GET  /v1/agents/governance/chain/verify     verify the snapshot chain

    GET  /v1/discovery/drift                    recent drift events
    GET  /v1/discovery/drift/{kind}             filter by kind

    GET  /v1/discovery/scheduler/status         scheduler health
    POST /v1/discovery/scheduler/run            run a cycle now
    POST /v1/discovery/scheduler/start          start scheduler
    POST /v1/discovery/scheduler/stop           stop scheduler

The routes pull stores out of ``app.state``. They never bypass the
canonical service / store APIs — those are the durable source of
truth.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.agent_routes import (
    _build_governance,
    _resolve_discovery_ledger,
    _resolve_ledger,
    _resolve_registry,
)
from tex.api.auth import TexPrincipal, authenticate_request
from tex.stores.drift_events import DriftEventKind


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class CaptureSnapshotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(default=None, max_length=400)
    # V16: explicit scan binding. When supplied, the snapshot is
    # cryptographically tied to one scan run and that run's ledger
    # range — auditors can reconstruct exactly which discovery state
    # the snapshot reflected.
    scan_run_id: str | None = Field(default=None, max_length=64)
    tenant_id: str | None = Field(default=None, max_length=200)
    policy_version: str | None = Field(default=None, max_length=200)


class SnapshotSummaryDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: str
    captured_at: str
    label: str | None = None
    total_agents: int
    governed: int
    ungoverned: int
    partial: int
    unknown: int
    high_risk_total: int
    high_risk_ungoverned: int
    governed_with_forbids: int
    governed_pct: float
    ungoverned_pct: float
    coverage_root_sha256: str
    snapshot_hash: str
    previous_snapshot_hash: str | None = None
    critical_ungoverned_count: int
    # V16 binding fields (optional for backwards compat).
    scan_run_id: str | None = None
    ledger_seq_start: int | None = None
    ledger_seq_end: int | None = None
    registry_state_hash: str | None = None
    policy_version: str | None = None


class SnapshotListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshots: list[SnapshotSummaryDTO]
    total: int


class SnapshotDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot: dict


class EvidenceBundleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundle: dict


class ChainVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intact: bool
    checked: int
    break_at_index: int | None = None
    snapshot_id: str | None = None
    reason: str | None = None


class DriftEventDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    occurred_at: str
    tenant_id: str
    kind: str
    reconciliation_key: str
    discovery_source: str | None = None
    agent_id: str | None = None
    severity: str
    summary: str
    details: dict
    scan_run_id: str | None = None


class DriftListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[DriftEventDTO]
    total: int


class SchedulerStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    running: bool
    interval_seconds: int
    tenants: list[str]
    timeout_seconds: float
    run_count: int
    last_run_completed_at: float | None = None
    last_run_summary: dict | None = None
    drift_durable: bool
    alerts_enabled: bool
    alert_sinks: list[str]
    presence_tracker_enabled: bool = False
    presence_threshold: int | None = None
    presence_durable: bool = False


class SchedulerRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: dict


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------


def _resolve_snapshot_store(request: Request) -> Any:
    store = getattr(request.app.state, "governance_snapshot_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="governance snapshot store is not configured",
        )
    return store


def _resolve_drift_store(request: Request) -> Any:
    store = getattr(request.app.state, "drift_event_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="drift event store is not configured",
        )
    return store


def _resolve_scheduler(request: Request) -> Any:
    sched = getattr(request.app.state, "scan_scheduler", None)
    if sched is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="scan scheduler is not configured",
        )
    return sched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary_from_record(record: dict) -> SnapshotSummaryDTO:
    return SnapshotSummaryDTO(
        snapshot_id=record["snapshot_id"],
        captured_at=record["captured_at"],
        label=record.get("label"),
        total_agents=record["total_agents"],
        governed=record["governed"],
        ungoverned=record["ungoverned"],
        partial=record["partial"],
        unknown=record["unknown"],
        high_risk_total=record["high_risk_total"],
        high_risk_ungoverned=record["high_risk_ungoverned"],
        governed_with_forbids=record["governed_with_forbids"],
        governed_pct=record.get("governed_pct", 0.0),
        ungoverned_pct=record.get("ungoverned_pct", 0.0),
        coverage_root_sha256=record["coverage_root_sha256"],
        snapshot_hash=record.get("snapshot_hash", ""),
        previous_snapshot_hash=record.get("previous_snapshot_hash"),
        critical_ungoverned_count=len(record.get("critical_ungoverned", []) or []),
        scan_run_id=record.get("scan_run_id"),
        ledger_seq_start=record.get("ledger_seq_start"),
        ledger_seq_end=record.get("ledger_seq_end"),
        registry_state_hash=record.get("registry_state_hash"),
        policy_version=record.get("policy_version"),
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------


def build_governance_history_router() -> APIRouter:
    """
    Routes for governance snapshots and chain verification.

    Mounted at /v1/agents/governance/* — sits alongside the
    governance-state endpoint already in agent_routes.py.
    """
    router = APIRouter(
        prefix="/v1/agents/governance",
        tags=["governance-history"],
    )

    @router.post(
        "/snapshot",
        response_model=SnapshotSummaryDTO,
        status_code=status.HTTP_201_CREATED,
        summary="Capture and persist a governance snapshot",
    )
    def capture_snapshot(
        request: Request,
        payload: CaptureSnapshotRequest,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SnapshotSummaryDTO:
        # If the caller passed tenant_id, scope-check it.
        if (
            payload.tenant_id is not None
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != payload.tenant_id.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match request tenant_id",
            )

        store = _resolve_snapshot_store(request)
        registry = _resolve_registry(request)
        action_ledger = _resolve_ledger(request)
        discovery_ledger = _resolve_discovery_ledger(request)

        # Compute current governance state, then capture.
        gov = _build_governance(
            registry=registry,
            action_ledger=action_ledger,
            discovery_ledger=discovery_ledger,
        )

        # V16: bind to latest completed scan run when available.
        # This is the snapshot-to-scan binding the security buyer asks
        # for: every snapshot points to the discovery state it
        # captured.
        scan_run_id = payload.scan_run_id
        ledger_seq_start: int | None = None
        ledger_seq_end: int | None = None
        registry_state_hash: str | None = None
        policy_version: str | None = payload.policy_version
        scan_run_store = getattr(request.app.state, "scan_run_store", None)
        if scan_run_store is not None:
            if scan_run_id:
                # Caller gave an explicit run id; pull binding from it.
                try:
                    explicit = scan_run_store.get(UUID(scan_run_id))
                except Exception:  # noqa: BLE001
                    explicit = None
                if explicit is not None:
                    ledger_seq_start = explicit.ledger_seq_start
                    ledger_seq_end = explicit.ledger_seq_end
                    registry_state_hash = explicit.registry_state_hash
                    policy_version = policy_version or explicit.policy_version
            elif payload.tenant_id is not None:
                latest = scan_run_store.latest_completed_for_tenant(payload.tenant_id)
                if latest is not None:
                    scan_run_id = str(latest.run_id)
                    ledger_seq_start = latest.ledger_seq_start
                    ledger_seq_end = latest.ledger_seq_end
                    registry_state_hash = latest.registry_state_hash
                    policy_version = policy_version or latest.policy_version

        record = store.capture(
            governance_payload=gov.model_dump(mode="json"),
            label=payload.label,
            scan_run_id=scan_run_id,
            ledger_seq_start=ledger_seq_start,
            ledger_seq_end=ledger_seq_end,
            registry_state_hash=registry_state_hash,
            policy_version=policy_version,
            tenant_id=payload.tenant_id,
        )
        return _summary_from_record(record)

    @router.get(
        "/snapshots",
        response_model=SnapshotListResponse,
        summary="List recent governance snapshots",
    )
    def list_snapshots(
        request: Request,
        limit: int = Query(default=50, ge=1, le=500),
        tenant_id: str | None = Query(default=None, max_length=200),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SnapshotListResponse:
        # Tenant scope: a non-default keyed principal cannot see other
        # tenants' snapshots.
        if (
            tenant_id is not None
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != tenant_id.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match query tenant_id",
            )
        if (
            tenant_id is None
            and not principal.is_anonymous
            and principal.tenant != "default"
        ):
            tenant_id = principal.tenant

        store = _resolve_snapshot_store(request)
        records = store.list_recent(limit=limit)
        if tenant_id is not None:
            normalized = tenant_id.strip().casefold()
            records = [
                r for r in records
                if (r.get("tenant_id") or "").strip().casefold() == normalized
            ]
        summaries = [_summary_from_record(r) for r in records]
        return SnapshotListResponse(snapshots=summaries, total=len(summaries))

    @router.get(
        "/snapshots/{snapshot_id}",
        response_model=SnapshotDetailResponse,
        summary="Fetch one snapshot by id",
    )
    def get_snapshot(
        request: Request,
        snapshot_id: UUID = Path(...),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SnapshotDetailResponse:
        store = _resolve_snapshot_store(request)
        record = store.get(snapshot_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"snapshot not found: {snapshot_id}",
            )
        snapshot_tenant = record.get("tenant_id")
        if (
            snapshot_tenant
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != snapshot_tenant.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match snapshot tenant",
            )
        return SnapshotDetailResponse(snapshot=record)

    @router.get(
        "/snapshots/{snapshot_id}/evidence_bundle",
        response_model=EvidenceBundleResponse,
        summary="Regulator-grade evidence bundle for one snapshot",
    )
    def evidence_bundle(
        request: Request,
        snapshot_id: UUID = Path(...),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> EvidenceBundleResponse:
        store = _resolve_snapshot_store(request)
        # Look up the snapshot first so we can scope-check it.
        record_for_scope = store.get(snapshot_id)
        if record_for_scope is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"snapshot not found: {snapshot_id}",
            )
        snapshot_tenant = record_for_scope.get("tenant_id")
        if (
            snapshot_tenant
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != snapshot_tenant.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match snapshot tenant",
            )

        drift_store = getattr(request.app.state, "drift_event_store", None)
        discovery_ledger = _resolve_discovery_ledger(request)
        registry = _resolve_registry(request)

        drift_events = []
        if drift_store is not None:
            drift_events = [e.to_dict() for e in drift_store.list_recent(limit=200)]

        discovery_root = None
        if discovery_ledger is not None:
            latest = discovery_ledger.latest()
            if latest is not None:
                discovery_root = latest.record_hash

        # Per-agent chain heads
        registry_chain_proof: dict[str, dict] = {}
        verify_method = getattr(registry, "verify_agent_chain", None)
        if callable(verify_method):
            for agent in registry.list_all():
                try:
                    intact = bool(verify_method(agent.agent_id))
                except Exception:  # noqa: BLE001
                    intact = False
                registry_chain_proof[str(agent.agent_id)] = {
                    "revisions": len(registry.history(agent.agent_id)),
                    "chain_intact": intact,
                }

        action_ledger = _resolve_ledger(request)
        policy_versions: list[str] = sorted(
            {
                entry.policy_version
                for entry in action_ledger.list_all()
                if entry.policy_version
            }
        )

        # V16: include the scan_run record so a regulator sees the
        # scan that produced the registry state captured in this
        # snapshot.
        scan_run_dict: dict | None = None
        scan_run_id_str = record_for_scope.get("scan_run_id")
        if scan_run_id_str:
            scan_run_store = getattr(request.app.state, "scan_run_store", None)
            if scan_run_store is not None:
                try:
                    sr = scan_run_store.get(UUID(scan_run_id_str))
                except Exception:  # noqa: BLE001
                    sr = None
                if sr is not None:
                    scan_run_dict = sr.to_dict()
                    scan_run_dict["duration_seconds"] = sr.duration_seconds

        bundle = store.export_evidence_bundle(
            snapshot_id,
            drift_events=drift_events,
            discovery_ledger_root=discovery_root,
            registry_chain_proof=registry_chain_proof,
            policy_versions_present=policy_versions,
            scan_run=scan_run_dict,
        )
        if bundle is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"snapshot not found: {snapshot_id}",
            )
        return EvidenceBundleResponse(bundle=bundle)

    @router.get(
        "/snapshots/{snapshot_id}/evidence_bundle.zip",
        summary="Download a signed zip containing the evidence bundle and its manifest",
    )
    def evidence_bundle_zip(
        request: Request,
        snapshot_id: UUID = Path(...),
        principal: TexPrincipal = Depends(authenticate_request),
    ):
        """
        Stream a zipped, manifest-signed evidence bundle.

        The zip contains:

          * ``bundle.json``    — full evidence bundle with all sections
          * ``manifest.json``  — bundle hash + per-section hashes + HMAC
          * ``README.txt``     — human-readable verification recipe

        Auditors can verify the bundle without opening the API: SHA-256
        the bundle.json bytes, compare to manifest.bundle_sha256;
        recompute HMAC-SHA256(secret, bundle_sha256), compare to
        manifest.manifest_signature_hmac_sha256.
        """
        import io
        import json
        import zipfile

        from fastapi.responses import StreamingResponse

        store = _resolve_snapshot_store(request)
        record_for_scope = store.get(snapshot_id)
        if record_for_scope is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"snapshot not found: {snapshot_id}",
            )
        snapshot_tenant = record_for_scope.get("tenant_id")
        if (
            snapshot_tenant
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != snapshot_tenant.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match snapshot tenant",
            )

        # Reuse the JSON evidence bundle path — same data, same
        # manifest. Then pack it.
        drift_store = getattr(request.app.state, "drift_event_store", None)
        discovery_ledger = _resolve_discovery_ledger(request)
        registry = _resolve_registry(request)
        action_ledger = _resolve_ledger(request)

        drift_events = []
        if drift_store is not None:
            drift_events = [e.to_dict() for e in drift_store.list_recent(limit=200)]

        discovery_root = None
        if discovery_ledger is not None:
            latest = discovery_ledger.latest()
            if latest is not None:
                discovery_root = latest.record_hash

        registry_chain_proof: dict[str, dict] = {}
        verify_method = getattr(registry, "verify_agent_chain", None)
        if callable(verify_method):
            for agent in registry.list_all():
                try:
                    intact = bool(verify_method(agent.agent_id))
                except Exception:  # noqa: BLE001
                    intact = False
                registry_chain_proof[str(agent.agent_id)] = {
                    "revisions": len(registry.history(agent.agent_id)),
                    "chain_intact": intact,
                }

        policy_versions: list[str] = sorted(
            {
                entry.policy_version
                for entry in action_ledger.list_all()
                if entry.policy_version
            }
        )

        scan_run_dict: dict | None = None
        scan_run_id_str = record_for_scope.get("scan_run_id")
        if scan_run_id_str:
            scan_run_store = getattr(request.app.state, "scan_run_store", None)
            if scan_run_store is not None:
                try:
                    sr = scan_run_store.get(UUID(scan_run_id_str))
                except Exception:  # noqa: BLE001
                    sr = None
                if sr is not None:
                    scan_run_dict = sr.to_dict()
                    scan_run_dict["duration_seconds"] = sr.duration_seconds

        bundle = store.export_evidence_bundle(
            snapshot_id,
            drift_events=drift_events,
            discovery_ledger_root=discovery_root,
            registry_chain_proof=registry_chain_proof,
            policy_versions_present=policy_versions,
            scan_run=scan_run_dict,
        )
        if bundle is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"snapshot not found: {snapshot_id}",
            )

        manifest = bundle.get("manifest", {})
        bundle_for_serialization = {
            k: v for k, v in bundle.items() if k != "manifest"
        }
        bundle_bytes = json.dumps(
            bundle_for_serialization,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        manifest_bytes = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        readme = (
            "Tex Aegis — Governance Evidence Bundle\n"
            "======================================\n\n"
            f"snapshot_id: {snapshot_id}\n"
            f"schema_version: {bundle.get('schema_version')}\n\n"
            "Verification recipe (any auditor):\n"
            "  1. sha256(bundle.json) MUST equal manifest.bundle_sha256\n"
            "  2. HMAC-SHA256(operator_secret, bundle_sha256) MUST equal\n"
            "     manifest.manifest_signature_hmac_sha256\n"
            "  3. Each section in bundle.json hashed independently MUST\n"
            "     match the corresponding entry in manifest.section_hashes\n\n"
            "Sections recorded in manifest.section_hashes include:\n"
            "  - snapshot, counts, agents, drift_events, registry_chain_proof,\n"
            "    policy_versions, scan_run, discovery_ledger_root, coverage_root\n\n"
            "If any check fails, the bundle has been tampered with or did not\n"
            "originate from this Tex deployment.\n"
        ).encode("utf-8")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bundle.json", bundle_bytes)
            zf.writestr("manifest.json", manifest_bytes)
            zf.writestr("README.txt", readme)
        buf.seek(0)
        filename = f"tex-evidence-{snapshot_id}.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Tex-Bundle-SHA256": manifest.get("bundle_sha256", ""),
                "X-Tex-Bundle-Signature": (
                    manifest.get("manifest_signature_hmac_sha256", "")
                ),
            },
        )

    @router.get(
        "/chain/verify",
        response_model=ChainVerifyResponse,
        summary="Verify the governance snapshot hash chain",
    )
    def verify_snapshot_chain(
        request: Request,
        limit: int = Query(default=1_000, ge=1, le=10_000),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> ChainVerifyResponse:
        store = _resolve_snapshot_store(request)
        result = store.verify_chain(limit=limit)
        return ChainVerifyResponse(**result)

    return router


def build_drift_router() -> APIRouter:
    """Routes for drift event introspection."""
    router = APIRouter(prefix="/v1/discovery/drift", tags=["drift"])

    @router.get(
        "",
        response_model=DriftListResponse,
        summary="Recent drift events across all tenants",
    )
    def list_drift_events(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
        tenant_id: str | None = Query(default=None),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> DriftListResponse:
        # Scope: a non-default keyed principal sees only its own tenant.
        if (
            tenant_id is not None
            and not principal.is_anonymous
            and principal.tenant != "default"
            and principal.tenant.casefold() != tenant_id.strip().casefold()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key tenant does not match query tenant_id",
            )
        if (
            tenant_id is None
            and not principal.is_anonymous
            and principal.tenant != "default"
        ):
            tenant_id = principal.tenant

        store = _resolve_drift_store(request)
        if tenant_id:
            events = store.list_for_tenant(tenant_id, limit=limit)
        else:
            events = store.list_recent(limit=limit)
        return DriftListResponse(
            events=[DriftEventDTO(**e.to_dict()) for e in events],
            total=len(events),
        )

    @router.get(
        "/{kind}",
        response_model=DriftListResponse,
        summary="Drift events filtered by kind",
    )
    def list_drift_by_kind(
        request: Request,
        kind: str = Path(..., description="NEW_AGENT | AGENT_CHANGED | AGENT_DISAPPEARED"),
        limit: int = Query(default=100, ge=1, le=1_000),
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> DriftListResponse:
        store = _resolve_drift_store(request)
        try:
            kind_enum = DriftEventKind(kind.upper())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unknown drift kind: {kind}",
            ) from exc
        events = store.list_by_kind(kind_enum, limit=limit)
        # Tenant filter applied here too so a per-tenant key cannot
        # see other tenants' drift events even via the kind filter.
        if (
            not principal.is_anonymous
            and principal.tenant != "default"
        ):
            events = [e for e in events if e.tenant_id == principal.tenant.casefold()]
        return DriftListResponse(
            events=[DriftEventDTO(**e.to_dict()) for e in events],
            total=len(events),
        )

    return router


def build_scheduler_router() -> APIRouter:
    """Admin routes for the background scheduler."""
    router = APIRouter(
        prefix="/v1/discovery/scheduler",
        tags=["scheduler"],
    )

    @router.get(
        "/status",
        response_model=SchedulerStatusResponse,
        summary="Scheduler status, including last-run summary",
    )
    def scheduler_status(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SchedulerStatusResponse:
        sched = _resolve_scheduler(request)
        return SchedulerStatusResponse(**sched.status)

    @router.post(
        "/run",
        response_model=SchedulerRunResponse,
        summary="Trigger one scheduler cycle synchronously (admin)",
    )
    def scheduler_run(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SchedulerRunResponse:
        # Admin op: when keys are configured, only the operator
        # ("default" tenant) may invoke it. Per-tenant keys cannot
        # globally trigger the scheduler.
        if not principal.is_anonymous and principal.tenant != "default":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="scheduler admin actions require operator-grade key",
            )
        sched = _resolve_scheduler(request)
        summary = sched.trigger_now()
        return SchedulerRunResponse(summary=summary)

    @router.post(
        "/start",
        response_model=SchedulerStatusResponse,
        summary="Start the scheduler (idempotent)",
    )
    def scheduler_start(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SchedulerStatusResponse:
        if not principal.is_anonymous and principal.tenant != "default":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="scheduler admin actions require operator-grade key",
            )
        sched = _resolve_scheduler(request)
        sched.start()
        return SchedulerStatusResponse(**sched.status)

    @router.post(
        "/stop",
        response_model=SchedulerStatusResponse,
        summary="Stop the scheduler",
    )
    def scheduler_stop(
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> SchedulerStatusResponse:
        if not principal.is_anonymous and principal.tenant != "default":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="scheduler admin actions require operator-grade key",
            )
        sched = _resolve_scheduler(request)
        sched.stop()
        return SchedulerStatusResponse(**sched.status)

    return router
