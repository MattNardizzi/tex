"""
HTTP routes for the V17 Learning/Drift layer.

Endpoints:

  POST /v1/learning/proposals
       Create a calibration proposal for a tenant. Runs the full
       feedback-loop pipeline (validator → safety → replay → health)
       and returns either the new PENDING proposal or the advisories
       explaining why no proposal was generated.

  GET /v1/learning/proposals
       List proposals, filterable by tenant and status.

  GET /v1/learning/proposals/{id}
       Fetch one proposal by id.

  POST /v1/learning/proposals/{id}/approve
       Approve and apply a pending proposal. Body must include the
       approver identity. Activates the new policy snapshot.

  POST /v1/learning/proposals/{id}/reject
       Reject a pending proposal with a structured reason.

  POST /v1/learning/proposals/{id}/rollback
       Roll back an applied proposal to its source policy version.

  GET /v1/learning/health?tenant_id=...
       Return the current calibration health snapshot for a tenant.

  GET /v1/learning/reputation
       List all known reporter reputations.

  GET /v1/learning/reputation/{reporter}
       Look up one reporter's reputation snapshot.

These routes never auto-apply. Every state-changing endpoint requires an
explicit identity in the request body, which the proposal store records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tex.domain.calibration_proposal import ProposalStatus
from tex.learning.feedback_loop import FeedbackLoopOrchestrator
from tex.learning.outcomes import (
    classify_batch,
    summarize_outcomes,
)
from tex.stores.calibration_proposal_store import (
    InvalidProposalTransitionError,
    ProposalNotFoundError,
)


# ── DTOs ──────────────────────────────────────────────────────────────────


class CreateProposalRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=200)
    proposed_new_version: str = Field(min_length=1, max_length=100)
    # created_by is optional in the body — when absent we resolve from
    # the authenticated principal or X-Tex-Approver header. When present,
    # auth context still wins.
    created_by: str | None = Field(default=None, max_length=200)
    source_policy_version: str | None = Field(default=None, max_length=100)
    recent_window_days: int | None = Field(default=14, ge=1, le=365)
    replay_window_size: int | None = Field(default=200, ge=10, le=10_000)


class ApproveProposalRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # When auth context provides identity, this can be omitted.
    approver: str | None = Field(default=None, max_length=200)


class RejectProposalRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rejecter: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=1, max_length=2_000)


class RollbackProposalRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rolled_back_by: str | None = Field(default=None, max_length=200)


class ProposalDiffDTO(BaseModel):
    permit_threshold_before: float
    permit_threshold_after: float
    forbid_threshold_before: float
    forbid_threshold_after: float
    minimum_confidence_before: float
    minimum_confidence_after: float


class ProposalSummaryDTO(BaseModel):
    proposal_id: str
    tenant_id: str | None
    source_policy_version: str
    proposed_new_version: str
    status: str
    diff: ProposalDiffDTO
    safety_adjusted: bool
    safety_reasons: list[str]
    health_band: str
    health_composite_score: float
    created_by: str
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    rejected_by: str | None
    rejected_at: datetime | None
    rejection_reason: str | None
    applied_at: datetime | None
    applied_policy_version: str | None
    rolled_back_by: str | None
    rolled_back_at: datetime | None
    rollback_target_version: str | None
    advisories_at_creation: list[str] = Field(default_factory=list)


class ProposalDetailDTO(ProposalSummaryDTO):
    replay: dict[str, Any]
    health_subscores: list[dict[str, Any]]
    metadata: dict[str, Any]


class CreateProposalResponseDTO(BaseModel):
    proposal: ProposalSummaryDTO | None
    advisories: list[str]
    drift_classification: dict[str, Any]
    poisoning_summary: dict[str, Any]
    health_band: str


class HealthResponseDTO(BaseModel):
    tenant_id: str
    overall: str
    composite_score: float
    sample_size: int
    quarantine_rate: float
    reporter_diversity: float
    subscores: list[dict[str, Any]]
    advisories: list[str]


class ReporterReputationDTO(BaseModel):
    reporter: str
    observations: int
    agreements: int
    disagreements: int
    accuracy: float
    disagreement_rate: float
    effective_weight: float
    last_seen_at: datetime | None


# ── helpers ───────────────────────────────────────────────────────────────


def _orchestrator(request: Request) -> FeedbackLoopOrchestrator:
    orch = getattr(request.app.state, "learning_orchestrator", None)
    if orch is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="learning orchestrator not configured",
        )
    return orch


def _proposal_store(request: Request):
    store = getattr(request.app.state, "proposal_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="proposal store not configured",
        )
    return store


def _resolve_actor(
    request: Request,
    *,
    body_value: str | None,
    field_name: str,
) -> str:
    """
    Resolve actor identity for state-changing endpoints.

    Order of precedence:
      1. Authenticated principal on request.state.principal (set by
         upstream auth middleware). May be a string or an object with
         a ``.username`` / ``.id`` attribute.
      2. ``X-Tex-Approver`` header (signed/short-lived in production
         deployments behind a gateway).
      3. Body value (deprecated path; only honored when no auth context
         is present at all, i.e. local dev or tests).

    Raises 401 if no identity can be resolved.
    Raises 409 if both auth context and a *different* body value are
    supplied — that's an attempt to spoof identity, and we refuse it
    rather than silently picking one.
    """
    principal_value: str | None = None
    principal = getattr(request.state, "principal", None)
    if principal is not None:
        if isinstance(principal, str):
            principal_value = principal.strip() or None
        else:
            for attr in ("username", "id", "email", "subject"):
                value = getattr(principal, attr, None)
                if isinstance(value, str) and value.strip():
                    principal_value = value.strip()
                    break

    header_value = request.headers.get("X-Tex-Approver")
    if header_value:
        header_value = header_value.strip() or None

    body_value = (body_value or "").strip() or None

    auth_value = principal_value or header_value

    # Spoofing guard: if auth context exists AND body specifies a
    # *different* identity, reject. Equal values are fine.
    if auth_value and body_value and body_value != auth_value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{field_name} in body ({body_value!r}) does not match "
                f"authenticated identity ({auth_value!r})."
            ),
        )

    resolved = auth_value or body_value
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"{field_name} required: provide via authenticated "
                "session, X-Tex-Approver header, or request body."
            ),
        )
    return resolved


def _proposal_to_summary_dto(proposal, advisories: list[str] | None = None) -> ProposalSummaryDTO:
    return ProposalSummaryDTO(
        proposal_id=str(proposal.proposal_id),
        tenant_id=proposal.tenant_id,
        source_policy_version=proposal.source_policy_version,
        proposed_new_version=proposal.proposed_new_version,
        status=proposal.status.value,
        diff=ProposalDiffDTO(
            permit_threshold_before=proposal.diff.permit_threshold_before,
            permit_threshold_after=proposal.diff.permit_threshold_after,
            forbid_threshold_before=proposal.diff.forbid_threshold_before,
            forbid_threshold_after=proposal.diff.forbid_threshold_after,
            minimum_confidence_before=proposal.diff.minimum_confidence_before,
            minimum_confidence_after=proposal.diff.minimum_confidence_after,
        ),
        safety_adjusted=proposal.safety_adjusted,
        safety_reasons=list(proposal.safety_reasons),
        health_band=proposal.health.overall.value,
        health_composite_score=proposal.health.composite_score,
        created_by=proposal.created_by,
        created_at=proposal.created_at,
        approved_by=proposal.approved_by,
        approved_at=proposal.approved_at,
        rejected_by=proposal.rejected_by,
        rejected_at=proposal.rejected_at,
        rejection_reason=proposal.rejection_reason,
        applied_at=proposal.applied_at,
        applied_policy_version=proposal.applied_policy_version,
        rolled_back_by=proposal.rolled_back_by,
        rolled_back_at=proposal.rolled_back_at,
        rollback_target_version=proposal.rollback_target_version,
        advisories_at_creation=advisories or [],
    )


def _proposal_to_detail_dto(proposal) -> ProposalDetailDTO:
    summary = _proposal_to_summary_dto(proposal)
    return ProposalDetailDTO(
        **summary.model_dump(),
        replay={
            "total_replayed": proposal.replay.total_replayed,
            "hard_blocked_unchanged": proposal.replay.hard_blocked_unchanged,
            "original_distribution": {
                "permit": proposal.replay.original_distribution.permit,
                "abstain": proposal.replay.original_distribution.abstain,
                "forbid": proposal.replay.original_distribution.forbid,
            },
            "proposed_distribution": {
                "permit": proposal.replay.proposed_distribution.permit,
                "abstain": proposal.replay.proposed_distribution.abstain,
                "forbid": proposal.replay.proposed_distribution.forbid,
            },
            "new_permits": proposal.replay.new_permits,
            "new_abstains": proposal.replay.new_abstains,
            "new_forbids": proposal.replay.new_forbids,
            "resolved_abstains": proposal.replay.resolved_abstains,
            "would_have_blocked_safe": proposal.replay.would_have_blocked_safe,
            "would_have_released_unsafe": proposal.replay.would_have_released_unsafe,
            "labelled_decisions": proposal.replay.labelled_decisions,
            "new_false_permit_rate": proposal.replay.new_false_permit_rate,
            "new_false_forbid_rate": proposal.replay.new_false_forbid_rate,
            "risky_change": proposal.replay.risky_change,
        },
        health_subscores=[
            {"name": s.name, "value": s.value, "band": s.band.value, "reason": s.reason}
            for s in proposal.health.subscores
        ],
        metadata=dict(proposal.metadata),
    )


# ── router ────────────────────────────────────────────────────────────────


def build_learning_router() -> APIRouter:
    from tex.api.auth import RequireScope, authenticate_request

    router = APIRouter(
        prefix="/v1/learning",
        tags=["learning"],
        dependencies=[Depends(authenticate_request)],
    )

    @router.post(
        "/proposals",
        response_model=CreateProposalResponseDTO,
        dependencies=[Depends(RequireScope("learning:write"))],
    )
    def create_proposal(
        body: CreateProposalRequestDTO,
        request: Request,
    ) -> CreateProposalResponseDTO:
        from datetime import timedelta

        created_by = _resolve_actor(
            request, body_value=body.created_by, field_name="created_by"
        )
        orch = _orchestrator(request)
        result = orch.propose(
            tenant_id=body.tenant_id,
            proposed_new_version=body.proposed_new_version,
            created_by=created_by,
            source_policy_version=body.source_policy_version,
            recent_window=timedelta(days=body.recent_window_days or 14),
            replay_window_size=body.replay_window_size or 200,
        )
        proposal_dto = (
            _proposal_to_summary_dto(result.proposal, list(result.advisories))
            if result.proposal is not None
            else None
        )
        return CreateProposalResponseDTO(
            proposal=proposal_dto,
            advisories=list(result.advisories),
            drift_classification={
                "drift_type": result.drift_classification.drift_type.value,
                "posture": result.drift_classification.posture.value,
                "confidence": result.drift_classification.confidence,
                "rationale": list(result.drift_classification.rationale),
            },
            poisoning_summary={
                "max_severity": result.poisoning_report.max_severity,
                "cluster_count": len(result.poisoning_report.clusters),
                "sudden_shift_count": len(result.poisoning_report.sudden_shifts),
                "repeat_disagreement_count": len(
                    result.poisoning_report.repeated_disagreements
                ),
            },
            health_band=result.health.overall.value,
        )

    @router.get("/proposals", response_model=list[ProposalSummaryDTO])
    def list_proposals(
        request: Request,
        tenant_id: str | None = None,
        status_filter: str | None = None,
        limit: int = 50,
    ) -> list[ProposalSummaryDTO]:
        store = _proposal_store(request)
        if status_filter is not None:
            try:
                want = ProposalStatus(status_filter.upper())
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"unknown status: {status_filter}",
                )
            proposals = [
                p
                for p in store.list_recent(limit=limit)
                if p.status is want and (tenant_id is None or p.tenant_id == tenant_id)
            ]
        else:
            if tenant_id is not None:
                proposals = list(store.list_for_tenant(tenant_id, limit=limit))
            else:
                proposals = list(store.list_recent(limit=limit))
        return [_proposal_to_summary_dto(p) for p in proposals]

    @router.get("/proposals/{proposal_id}", response_model=ProposalDetailDTO)
    def get_proposal(proposal_id: UUID, request: Request) -> ProposalDetailDTO:
        store = _proposal_store(request)
        try:
            proposal = store.require(proposal_id)
        except ProposalNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id}",
            )
        return _proposal_to_detail_dto(proposal)

    @router.post(
        "/proposals/{proposal_id}/approve",
        response_model=ProposalDetailDTO,
        dependencies=[Depends(RequireScope("learning:approve"))],
    )
    def approve_proposal(
        proposal_id: UUID,
        body: ApproveProposalRequestDTO,
        request: Request,
    ) -> ProposalDetailDTO:
        approver = _resolve_actor(
            request, body_value=body.approver, field_name="approver"
        )
        orch = _orchestrator(request)
        try:
            applied = orch.apply_proposal(
                proposal_id=proposal_id,
                approver=approver,
            )
        except ProposalNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id}",
            )
        except InvalidProposalTransitionError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            )
        return _proposal_to_detail_dto(applied)

    @router.post(
        "/proposals/{proposal_id}/reject",
        response_model=ProposalDetailDTO,
        dependencies=[Depends(RequireScope("learning:approve"))],
    )
    def reject_proposal(
        proposal_id: UUID,
        body: RejectProposalRequestDTO,
        request: Request,
    ) -> ProposalDetailDTO:
        rejecter = _resolve_actor(
            request, body_value=body.rejecter, field_name="rejecter"
        )
        orch = _orchestrator(request)
        try:
            rejected = orch.reject_proposal(
                proposal_id=proposal_id,
                rejecter=rejecter,
                reason=body.reason,
            )
        except ProposalNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id}",
            )
        except InvalidProposalTransitionError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            )
        return _proposal_to_detail_dto(rejected)

    @router.post(
        "/proposals/{proposal_id}/rollback",
        response_model=ProposalDetailDTO,
        dependencies=[Depends(RequireScope("learning:approve"))],
    )
    def rollback_proposal(
        proposal_id: UUID,
        body: RollbackProposalRequestDTO,
        request: Request,
    ) -> ProposalDetailDTO:
        rolled_back_by = _resolve_actor(
            request, body_value=body.rolled_back_by, field_name="rolled_back_by"
        )
        orch = _orchestrator(request)
        try:
            rolled = orch.rollback_proposal(
                proposal_id=proposal_id,
                rolled_back_by=rolled_back_by,
            )
        except ProposalNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id}",
            )
        except (InvalidProposalTransitionError, RuntimeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            )
        return _proposal_to_detail_dto(rolled)

    @router.get("/health", response_model=HealthResponseDTO)
    def calibration_health(
        request: Request,
        tenant_id: str,
    ) -> HealthResponseDTO:
        from tex.learning.health import compute_health
        from tex.learning.drift import PolicyDriftMonitor

        outcome_store = request.app.state.outcome_store
        decision_store = request.app.state.decision_store
        policies = request.app.state.policy_store

        eligible = outcome_store.list_calibration_eligible(tenant_id=tenant_id)
        decisions = []
        for o in eligible:
            d = decision_store.get(o.decision_id)
            if d is not None:
                decisions.append(d)
        classifications = classify_batch(decisions=decisions, outcomes=eligible)
        summary = summarize_outcomes(classifications)

        drift_monitor = PolicyDriftMonitor(decision_store=decision_store)
        active_policy = policies.get_active()
        drift_report = (
            drift_monitor.report(policy_version=active_policy.version)
            if active_policy is not None
            else None
        )

        health = compute_health(
            outcome_summary=summary,
            trusted_outcomes=eligible,
            quarantined_count=outcome_store.quarantine_count(tenant_id=tenant_id),
            drift_report=drift_report,
        )
        return HealthResponseDTO(
            tenant_id=tenant_id,
            overall=health.overall.value,
            composite_score=health.composite_score,
            sample_size=health.sample_size,
            quarantine_rate=health.quarantine_rate,
            reporter_diversity=health.reporter_diversity,
            subscores=[
                {
                    "name": s.name,
                    "value": s.value,
                    "band": s.band.value,
                    "reason": s.reason,
                }
                for s in health.subscores
            ],
            advisories=list(health.advisories),
        )

    @router.get("/reputation", response_model=list[ReporterReputationDTO])
    def list_reputations(request: Request) -> list[ReporterReputationDTO]:
        rep_store = getattr(request.app.state, "reporter_reputation", None)
        if rep_store is None:
            raise HTTPException(status_code=503, detail="reputation store missing")
        return [
            ReporterReputationDTO(
                reporter=r.reporter,
                observations=r.observations,
                agreements=r.agreements,
                disagreements=r.disagreements,
                accuracy=r.accuracy,
                disagreement_rate=r.disagreement_rate,
                effective_weight=r.effective_weight,
                last_seen_at=r.last_seen_at,
            )
            for r in rep_store.list_all()
        ]

    @router.get("/reputation/{reporter}", response_model=ReporterReputationDTO)
    def get_reputation(reporter: str, request: Request) -> ReporterReputationDTO:
        rep_store = getattr(request.app.state, "reporter_reputation", None)
        if rep_store is None:
            raise HTTPException(status_code=503, detail="reputation store missing")
        r = rep_store.get(reporter)
        return ReporterReputationDTO(
            reporter=r.reporter,
            observations=r.observations,
            agreements=r.agreements,
            disagreements=r.disagreements,
            accuracy=r.accuracy,
            disagreement_rate=r.disagreement_rate,
            effective_weight=r.effective_weight,
            last_seen_at=r.last_seen_at,
        )

    @router.get("/metrics")
    def learning_metrics(request: Request) -> dict[str, Any]:
        """
        Return the current learning-layer metrics snapshot.

        Counters are lifetime totals plus a per-tenant breakdown.
        ``recent`` is a ring buffer of the last events for dashboard
        visibility.
        """
        metrics = getattr(request.app.state, "learning_metrics", None)
        if metrics is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="learning metrics not configured",
            )
        return metrics.snapshot()

    @router.get("/metrics/prometheus", response_class=None)
    def learning_metrics_prometheus(request: Request):
        """Prometheus text-exposition endpoint for the learning layer."""
        from fastapi.responses import PlainTextResponse

        metrics = getattr(request.app.state, "learning_metrics", None)
        if metrics is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="learning metrics not configured",
            )
        return PlainTextResponse(
            metrics.prometheus_text(),
            media_type="text/plain; version=0.0.4",
        )

    @router.get("/alerts")
    def learning_alerts(request: Request) -> list[dict[str, Any]]:
        """
        Return currently-active learning-layer alerts.

        Alert rules are evaluated on every call against the metrics
        observer's rolling window, so this endpoint always returns the
        live set.
        """
        engine = getattr(request.app.state, "learning_alert_engine", None)
        if engine is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="learning alert engine not configured",
            )
        return [
            {
                "rule": a.rule,
                "severity": a.severity,
                "message": a.message,
                "tenant_id": a.tenant_id,
                "count": a.count,
                "window_minutes": a.window_minutes,
                "raised_at": a.raised_at.isoformat(),
            }
            for a in engine.evaluate()
        ]

    @router.get("/proposals/{proposal_id}/audit")
    def proposal_audit_trail(
        proposal_id: UUID,
        request: Request,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Return the durable audit trail for a proposal.

        Every state transition (saved / approved / rejected / applied /
        rolled_back / expired) is logged with actor + timestamp + detail.
        Returns an empty list when running in pure in-memory mode.
        """
        store = _proposal_store(request)
        # Fail fast if proposal doesn't exist.
        try:
            store.require(proposal_id)
        except ProposalNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id}",
            )
        return store.list_audit_trail(proposal_id, limit=limit)

    return router


__all__ = ["build_learning_router"]
