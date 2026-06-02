"""
Feedback loop orchestrator.

The orchestrator is the only path that turns observed outcomes into a
calibration proposal. It enforces the full chain:

  1. validate the outcome (trust tier promotion or quarantine)
  2. persist the outcome via the outcome store
  3. update the reporter's reputation when ground truth is available
  4. on a calibration trigger:
       a. pull trusted outcomes (calibration-eligible only, tenant-scoped)
       b. produce the calibrator's recommendation
       c. evaluate against the safety guard (rate limit + bounds)
       d. run replay against historical decisions
       e. compute calibration health
       f. assemble a CalibrationProposal in PENDING state
  5. on approval:
       a. apply the new policy
       b. commit the safety-guard movement budget
       c. mark the proposal APPLIED
  6. on rollback:
       a. activate the proposal's source policy version
       b. mark the proposal ROLLED_BACK

The orchestrator never auto-applies. Step 6 (approval) requires an
explicit approver string from a caller outside this module — there is
no API for "auto-approve" anywhere in this layer.

Cold-start protection (item 13) is implemented inside ``propose``:
when the trusted-outcome sample is below ``cold_start_minimum``, the
orchestrator refuses to produce a proposal and surfaces a structured
"cold start" advisory instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

from tex.domain.calibration_proposal import CalibrationProposal
from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.policy import PolicySnapshot
from tex.learning.calibration_safety import CalibrationSafetyGuard
from tex.learning.calibrator import ThresholdCalibrator
from tex.learning.drift import PolicyDriftMonitor, PolicyDriftReport
from tex.learning.drift_classifier import (
    ClassifiedDrift,
    DriftClassifier,
    DriftPosture,
)
from tex.learning.health import CalibrationHealth, compute_health
from tex.learning.outcome_validator import (
    OutcomeValidator,
    ValidationResult,
)
from tex.learning.outcomes import (
    classify_batch,
    summarize_outcomes,
    summarize_outcomes_weighted,
)
from tex.learning.poisoning_detector import (
    PoisoningDetector,
    PoisoningReport,
)
from tex.learning.replay import ReplayReport, ReplayValidator
from tex.learning.reporter_reputation import ReporterReputationStore
from tex.stores.calibration_proposal_store import CalibrationProposalStore
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.outcome_store import InMemoryOutcomeStore
from tex.stores.policy_store import InMemoryPolicyStore


DEFAULT_COLD_START_MINIMUM = 30
DEFAULT_PROPOSAL_FRESHNESS_WINDOW = timedelta(days=14)


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Outcome of a single feedback-loop ingest call."""

    validation: ValidationResult
    persisted: bool
    quarantined: bool
    reputation_updated: bool


@dataclass(frozen=True, slots=True)
class ProposalDraftResult:
    """
    Outcome of a propose() call.

    When ``proposal`` is None, the loop refused to produce one — the
    advisories explain why (cold start, no movement, safety blocked,
    health RED, etc).
    """

    proposal: CalibrationProposal | None
    drift_report: PolicyDriftReport
    drift_classification: ClassifiedDrift
    poisoning_report: PoisoningReport
    health: CalibrationHealth
    advisories: tuple[str, ...]


class _LearningObserver(Protocol):
    """
    Optional observer hook for the orchestrator.

    Implementations receive structured events at every step so external
    metrics + alerting systems can subscribe without coupling to the
    orchestrator's internals.
    """

    def on_event(self, *, event: str, payload: dict) -> None: ...


class _NullObserver:
    def on_event(self, *, event: str, payload: dict) -> None:  # pragma: no cover
        return None


class FeedbackLoopOrchestrator:
    """The single legitimate path from outcome to proposal."""

    __slots__ = (
        "_decisions",
        "_outcomes",
        "_policies",
        "_proposals",
        "_validator",
        "_reputation",
        "_calibrator",
        "_safety",
        "_replay",
        "_drift_monitor",
        "_drift_classifier",
        "_poisoning",
        "_observer",
        "_cold_start_minimum",
        "_clock",
    )

    def __init__(
        self,
        *,
        decisions: InMemoryDecisionStore,
        outcomes: InMemoryOutcomeStore,
        policies: InMemoryPolicyStore,
        proposals: CalibrationProposalStore,
        validator: OutcomeValidator,
        reputation: ReporterReputationStore,
        calibrator: ThresholdCalibrator,
        safety: CalibrationSafetyGuard,
        replay: ReplayValidator,
        drift_monitor: PolicyDriftMonitor,
        drift_classifier: DriftClassifier | None = None,
        poisoning_detector: PoisoningDetector | None = None,
        observer: _LearningObserver | None = None,
        cold_start_minimum: int = DEFAULT_COLD_START_MINIMUM,
        clock: callable | None = None,
    ) -> None:
        self._decisions = decisions
        self._outcomes = outcomes
        self._policies = policies
        self._proposals = proposals
        self._validator = validator
        self._reputation = reputation
        self._calibrator = calibrator
        self._safety = safety
        self._replay = replay
        self._drift_monitor = drift_monitor
        self._drift_classifier = drift_classifier or DriftClassifier()
        self._poisoning = poisoning_detector or PoisoningDetector()
        self._observer = observer or _NullObserver()
        self._cold_start_minimum = cold_start_minimum
        self._clock = clock or (lambda: datetime.now(UTC))

    # ── ingest ──────────────────────────────────────────────────────────

    def ingest_outcome(self, outcome: OutcomeRecord) -> IngestResult:
        """
        Validate, persist, and (when applicable) update reporter reputation.

        Reputation is only updated when there's a clear ground-truth
        comparison available. We treat presence of a non-UNKNOWN label
        plus a non-quarantined outcome as the signal.
        """
        result = self._validator.validate(outcome)
        self._outcomes.save(result.outcome)
        self._observer.on_event(
            event="outcome_persisted",
            payload={
                "outcome_id": str(result.outcome.outcome_id),
                "trust_level": result.outcome.trust_level.value,
                "tenant_id": result.outcome.tenant_id,
                "failures": [f.value for f in result.failures],
            },
        )
        if result.outcome.trust_level is OutcomeTrustLevel.QUARANTINED:
            self._observer.on_event(
                event="outcome_quarantined",
                payload={
                    "outcome_id": str(result.outcome.outcome_id),
                    "tenant_id": result.outcome.tenant_id,
                    "reporter": result.outcome.reporter,
                    "failures": [f.value for f in result.failures],
                },
            )
        # The validator surfaces rate-limit failures; alerting wants its
        # own event-type so threshold rules can target it directly.
        for failure in result.failures:
            if failure.value == "reporter_rate_limited":
                self._observer.on_event(
                    event="reporter_rate_limited",
                    payload={
                        "tenant_id": result.outcome.tenant_id,
                        "reporter": result.outcome.reporter,
                    },
                )
                break

        reputation_updated = False
        if (
            result.is_valid
            and result.outcome.reporter
            and result.outcome.was_safe is not None
        ):
            agreed = self._derive_agreement(result.outcome)
            self._reputation.record_observation(
                reporter=result.outcome.reporter,
                agreed_with_consensus=agreed,
                observed_at=result.outcome.recorded_at,
            )
            reputation_updated = True

        return IngestResult(
            validation=result,
            persisted=True,
            quarantined=result.outcome.trust_level
            is OutcomeTrustLevel.QUARANTINED,
            reputation_updated=reputation_updated,
        )

    def _derive_agreement(self, outcome: OutcomeRecord) -> bool:
        """
        A reporter "agreed with consensus" when their label matches what
        the system's already-VERIFIED labels say for this decision. With
        no VERIFIED prior, we fall back to "agreed" so we don't penalize
        first reporters; the reputation system is rate-limited and decay-
        weighted, so this default doesn't propagate harm.
        """
        priors = self._outcomes.list_for_decision(outcome.decision_id)
        verified = [
            p
            for p in priors
            if p.trust_level is OutcomeTrustLevel.VERIFIED
            and p.outcome_id != outcome.outcome_id
        ]
        if not verified:
            return True
        return any(p.label is outcome.label for p in verified)

    # ── propose ─────────────────────────────────────────────────────────

    def propose(
        self,
        *,
        tenant_id: str,
        proposed_new_version: str,
        created_by: str,
        source_policy_version: str | None = None,
        recent_window: timedelta = DEFAULT_PROPOSAL_FRESHNESS_WINDOW,
        replay_window_size: int = 200,
    ) -> ProposalDraftResult:
        """
        Drive the full proposal pipeline for one tenant.

        Returns a ``ProposalDraftResult``. When ``proposal`` is None, the
        orchestrator declined to produce a proposal — the advisories
        explain why.
        """
        advisories: list[str] = []

        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id must be non-blank")
        if not created_by or not created_by.strip():
            raise ValueError("created_by must be non-blank")

        source_policy = self._resolve_source_policy(source_policy_version)
        now = self._clock()
        since = now - recent_window

        eligible = self._outcomes.list_calibration_eligible(
            tenant_id=tenant_id.strip(),
            since=since,
        )
        eligible_count = len(eligible)
        quarantined_count = self._outcomes.quarantine_count(
            tenant_id=tenant_id.strip()
        )

        # Drift report (computed even on cold start so callers can see it).
        drift_report = self._drift_monitor.report(
            policy_version=source_policy.version,
        )

        # Poisoning report uses the recent ingest window for clusters and a
        # longer baseline window for sudden-shift detection.
        baseline_since = now - max(recent_window * 2, timedelta(days=30))
        baseline = self._outcomes.list_calibration_eligible(
            tenant_id=tenant_id.strip(),
            since=baseline_since,
        )
        poisoning_report = self._poisoning.detect(
            recent_outcomes=eligible,
            baseline_outcomes=baseline,
        )

        drift_classification = self._drift_classifier.classify(
            drift_report=drift_report,
            poisoning_report=poisoning_report,
            last_calibrated_at=None,  # safety guard tracks this internally
            clock=self._clock,
        )

        # Cold start guard.
        if eligible_count < self._cold_start_minimum:
            advisories.append(
                f"Cold start: only {eligible_count} calibration-eligible outcomes "
                f"for tenant '{tenant_id}' (minimum {self._cold_start_minimum}). "
                "Holding the safe baseline policy."
            )
            return ProposalDraftResult(
                proposal=None,
                drift_report=drift_report,
                drift_classification=drift_classification,
                poisoning_report=poisoning_report,
                health=self._snapshot_health(
                    eligible=eligible,
                    quarantined_count=quarantined_count,
                    drift_report=drift_report,
                ),
                advisories=tuple(advisories),
            )

        # Surface poisoning-detector findings as a dedicated event for
        # operator alerting, regardless of which path the proposal takes.
        if poisoning_report.has_findings:
            self._observer.on_event(
                event="poisoning_detected",
                payload={
                    "tenant_id": tenant_id,
                    "max_severity": poisoning_report.max_severity,
                    "cluster_count": len(poisoning_report.clusters),
                    "sudden_shift_count": len(poisoning_report.sudden_shifts),
                    "repeat_disagreement_count": len(
                        poisoning_report.repeated_disagreements
                    ),
                },
            )

        # Adversarial freeze: when the drift classifier or poisoning
        # detector reports FREEZE, refuse to propose.
        if drift_classification.posture is DriftPosture.FREEZE:
            advisories.append(
                "Drift classifier returned FREEZE posture due to adversarial "
                "signals; refusing to draft a calibration proposal until "
                "operator review clears the freeze."
            )
            self._observer.on_event(
                event="proposal_freeze",
                payload={
                    "tenant_id": tenant_id,
                    "drift_type": drift_classification.drift_type.value,
                    "rationale": list(drift_classification.rationale),
                },
            )
            return ProposalDraftResult(
                proposal=None,
                drift_report=drift_report,
                drift_classification=drift_classification,
                poisoning_report=poisoning_report,
                health=self._snapshot_health(
                    eligible=eligible,
                    quarantined_count=quarantined_count,
                    drift_report=drift_report,
                ),
                advisories=tuple(advisories),
            )

        # Build the trust-weighted summary the calibrator consumes.
        decisions_for_classification = self._collect_decisions_for(eligible)
        classifications = classify_batch(
            decisions=decisions_for_classification,
            outcomes=eligible,
        )
        outcomes_by_id = {str(o.decision_id): o for o in eligible}
        weighted = summarize_outcomes_weighted(
            classifications=classifications,
            outcomes_by_id=outcomes_by_id,
            reporter_weight=self._reputation.weight_for,
        )

        recommendation = self._calibrator.recommend(
            policy=source_policy,
            summary=weighted.as_outcome_summary(),
        )

        safety_decision = self._safety.evaluate(
            policy=source_policy,
            recommendation=recommendation,
        )

        if not safety_decision.allowed:
            advisories.append(
                "Safety guard rejected the proposal: "
                + "; ".join(safety_decision.reasons)
            )
            self._observer.on_event(
                event="calibration_safety_blocked",
                payload={
                    "tenant_id": tenant_id,
                    "rate_limited": safety_decision.rate_limited,
                    "bounds_violated": safety_decision.bounds_violated,
                    "cumulative_budget_exhausted": safety_decision.cumulative_budget_exhausted,
                    "reasons": list(safety_decision.reasons),
                },
            )
            return ProposalDraftResult(
                proposal=None,
                drift_report=drift_report,
                drift_classification=drift_classification,
                poisoning_report=poisoning_report,
                health=self._snapshot_health(
                    eligible=eligible,
                    quarantined_count=quarantined_count,
                    drift_report=drift_report,
                ),
                advisories=tuple(advisories),
            )

        if not safety_decision.clipped_recommendation.changed:
            advisories.append(
                "Recommendation produced no threshold movement after safety "
                "clipping; no proposal needed."
            )
            return ProposalDraftResult(
                proposal=None,
                drift_report=drift_report,
                drift_classification=drift_classification,
                poisoning_report=poisoning_report,
                health=self._snapshot_health(
                    eligible=eligible,
                    quarantined_count=quarantined_count,
                    drift_report=drift_report,
                ),
                advisories=tuple(advisories),
            )

        # Replay against recent decisions for the same policy version.
        recent_decisions = self._decisions.find(
            policy_version=source_policy.version,
            limit=replay_window_size,
        )
        replay_report = self._replay.replay(
            decisions=recent_decisions,
            outcomes=eligible,
            policy=source_policy,
            recommendation=safety_decision.clipped_recommendation,
        )

        if replay_report.risky_change:
            self._observer.on_event(
                event="proposal_replay_risky",
                payload={
                    "tenant_id": tenant_id,
                    "new_permits": replay_report.new_permits,
                    "new_forbids": replay_report.new_forbids,
                    "new_abstains": replay_report.new_abstains,
                    "would_have_blocked_safe": replay_report.would_have_blocked_safe,
                    "would_have_released_unsafe": replay_report.would_have_released_unsafe,
                },
            )

        health = self._snapshot_health(
            eligible=eligible,
            quarantined_count=quarantined_count,
            drift_report=drift_report,
        )

        proposal = CalibrationProposal.build(
            source_policy=source_policy,
            proposed_new_version=proposed_new_version.strip(),
            recommendation=safety_decision.clipped_recommendation,
            replay=replay_report,
            health=health,
            safety_adjusted=safety_decision.bounds_violated,
            safety_reasons=safety_decision.reasons,
            tenant_id=tenant_id.strip(),
            created_by=created_by.strip(),
            metadata={
                "drift_report": _drift_report_dict(drift_report),
                "drift_classification": _drift_classification_dict(drift_classification),
                "poisoning_summary": _poisoning_summary_dict(poisoning_report),
                "weighted_total": weighted.total,
                "raw_total": weighted.raw.total,
            },
        )
        self._proposals.save(proposal)
        self._observer.on_event(
            event="proposal_created",
            payload={
                "proposal_id": str(proposal.proposal_id),
                "tenant_id": tenant_id,
                "source_policy_version": source_policy.version,
                "proposed_new_version": proposal.proposed_new_version,
                "health_band": health.overall.value,
                "drift_type": drift_classification.drift_type.value,
            },
        )

        return ProposalDraftResult(
            proposal=proposal,
            drift_report=drift_report,
            drift_classification=drift_classification,
            poisoning_report=poisoning_report,
            health=health,
            advisories=tuple(advisories),
        )

    # ── apply / rollback ────────────────────────────────────────────────

    def apply_proposal(
        self,
        *,
        proposal_id: UUID,
        approver: str,
    ) -> CalibrationProposal:
        """
        Approve a pending proposal, save the new policy snapshot, activate
        it, commit the safety budget, and mark the proposal APPLIED.
        """
        approved = self._proposals.approve(
            proposal_id=proposal_id,
            approver=approver,
        )
        source = self._policies.require(approved.source_policy_version)
        new_policy = self._calibrator.apply_recommendation(
            policy=source,
            recommendation=approved.recommendation,
            new_version=approved.proposed_new_version,
            metadata_updates={
                "calibration_proposal_id": str(approved.proposal_id),
                "calibration_approved_by": approver,
            },
            activate=True,
        )
        self._policies.save(new_policy)
        self._policies.activate(new_policy.version)
        self._safety.commit(
            policy_id=source.policy_id,
            applied_recommendation=approved.recommendation,
        )
        applied = self._proposals.mark_applied(
            proposal_id=proposal_id,
            applied_policy_version=new_policy.version,
        )
        self._observer.on_event(
            event="proposal_applied",
            payload={
                "proposal_id": str(applied.proposal_id),
                "applied_policy_version": new_policy.version,
                "approver": approver,
            },
        )
        return applied

    def reject_proposal(
        self,
        *,
        proposal_id: UUID,
        rejecter: str,
        reason: str,
    ) -> CalibrationProposal:
        rejected = self._proposals.reject(
            proposal_id=proposal_id,
            rejecter=rejecter,
            reason=reason,
        )
        self._observer.on_event(
            event="proposal_rejected",
            payload={
                "proposal_id": str(rejected.proposal_id),
                "rejecter": rejecter,
                "reason": reason,
            },
        )
        return rejected

    def rollback_proposal(
        self,
        *,
        proposal_id: UUID,
        rolled_back_by: str,
    ) -> CalibrationProposal:
        proposal = self._proposals.require(proposal_id)
        if proposal.rollback_target_version is None:
            raise RuntimeError(
                "proposal has no rollback target; only APPLIED proposals carry one"
            )
        self._policies.activate(proposal.rollback_target_version)
        rolled = self._proposals.mark_rolled_back(
            proposal_id=proposal_id,
            rolled_back_by=rolled_back_by,
        )
        self._observer.on_event(
            event="proposal_rolled_back",
            payload={
                "proposal_id": str(rolled.proposal_id),
                "rollback_target_version": rolled.rollback_target_version,
                "rolled_back_by": rolled_back_by,
            },
        )
        return rolled

    # ── helpers ─────────────────────────────────────────────────────────

    def _resolve_source_policy(self, version: str | None) -> PolicySnapshot:
        if version is None:
            return self._policies.require_active()
        return self._policies.require(version.strip())

    def _collect_decisions_for(
        self, outcomes: tuple[OutcomeRecord, ...]
    ) -> tuple[Decision, ...]:
        decisions: list[Decision] = []
        for outcome in outcomes:
            decision = self._decisions.get(outcome.decision_id)
            if decision is not None:
                decisions.append(decision)
        return tuple(decisions)

    def _snapshot_health(
        self,
        *,
        eligible: tuple[OutcomeRecord, ...],
        quarantined_count: int,
        drift_report: PolicyDriftReport | None,
    ) -> CalibrationHealth:
        decisions_for_summary = self._collect_decisions_for(eligible)
        classifications = classify_batch(
            decisions=decisions_for_summary,
            outcomes=eligible,
        )
        summary = summarize_outcomes(classifications)
        return compute_health(
            outcome_summary=summary,
            trusted_outcomes=eligible,
            quarantined_count=quarantined_count,
            drift_report=drift_report,
        )


def _drift_report_dict(report: PolicyDriftReport) -> dict[str, Any]:
    return {
        "policy_version": report.policy_version,
        "window_size": report.window_size,
        "total_samples": report.total_samples,
        "permit_rate_delta": report.permit_rate_delta,
        "abstain_rate_delta": report.abstain_rate_delta,
        "forbid_rate_delta": report.forbid_rate_delta,
        "flags": list(report.flags),
    }


def _drift_classification_dict(classification: ClassifiedDrift) -> dict[str, Any]:
    return {
        "drift_type": classification.drift_type.value,
        "posture": classification.posture.value,
        "confidence": classification.confidence,
        "rationale": list(classification.rationale),
    }


def _poisoning_summary_dict(report: PoisoningReport) -> dict[str, Any]:
    return {
        "max_severity": report.max_severity,
        "cluster_count": len(report.clusters),
        "sudden_shift_count": len(report.sudden_shifts),
        "repeat_disagreement_count": len(report.repeated_disagreements),
    }


__all__ = [
    "FeedbackLoopOrchestrator",
    "IngestResult",
    "ProposalDraftResult",
]
