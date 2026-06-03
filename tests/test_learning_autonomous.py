"""Tests for the e-process trigger, sufficiency gate, OPE bound, and the
calibration-hold provider — the autonomous-learning build."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import OutcomeSourceType, OutcomeTrustLevel
from tex.domain.calibration_proposal import ProposalStatus
from tex.domain.verdict import Verdict
from tex.learning.feedback_loop import FeedbackLoopOrchestrator
from tex.learning.ope import OffPolicyEvaluator, _anytime_valid_upper_bound
from tex.learning.sufficiency import EvidenceSufficiency
from tex.learning.trigger import (
    AnytimeValidCalibrationTrigger,
    _standardise_false_permit,
)
from tex.vigil.calibration_provider import (
    CalibrationProposalVigilProvider,
    CompositeHeldProvider,
)

# Reuse the end-to-end builders from the existing feedback-loop suite.
from test_feedback_loop import _build_orchestrator, _make_decision


def _full_orchestrator(*, ope_budget: float = 0.95, target_count: int = 12):
    """An orchestrator with the frontier collaborators + trigger attached."""
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    full = FeedbackLoopOrchestrator(
        decisions=decisions,
        outcomes=outcomes,
        policies=policies,
        proposals=proposals,
        validator=orch._validator,
        reputation=orch._reputation,
        calibrator=orch._calibrator,
        safety=orch._safety,
        replay=orch._replay,
        drift_monitor=orch._drift_monitor,
        drift_classifier=orch._drift_classifier,
        poisoning_detector=orch._poisoning,
        cold_start_minimum=8,
        sufficiency_gate=EvidenceSufficiency(
            target_count=target_count, readiness_threshold=0.5
        ),
        ope_evaluator=OffPolicyEvaluator(alpha=0.05),
        ope_unsafe_release_budget=ope_budget,
    )
    trigger = AnytimeValidCalibrationTrigger(
        orchestrator=full,
        proposals=proposals,
        alpha=0.01,
        min_observations=5,
    )
    full.set_trigger(trigger)
    return full, decisions, outcomes, policies, proposals, trigger


def _permit_outcome(decision, *, safe: bool, reporter: str):
    return OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=safe,
        reporter=reporter,
        source_type=OutcomeSourceType.HUMAN_REVIEWER,
    )


def _stream(orch, decisions, *, n, bad_rate, tenant="acme"):
    for i in range(n):
        d = _make_decision(tenant_id=tenant)
        decisions.save(d)
        bad = (i % max(1, round(1 / bad_rate))) == 0 if bad_rate > 0 else False
        orch.ingest_outcome(
            _permit_outcome(d, safe=not bad, reporter=f"rep-{i % 4}")
        )


# ── e-process trigger ──────────────────────────────────────────────────


def test_trigger_fires_on_miscalibrated_stream() -> None:
    orch, decisions, _, _, proposals, _ = _full_orchestrator()
    _stream(orch, decisions, n=40, bad_rate=0.33)  # 33% >> 5% null
    # A proposal was drafted with nobody calling propose() directly.
    assert len(proposals) >= 1
    pending = proposals.list_pending(tenant_id="acme")
    assert len(pending) == 1  # supersession keeps exactly one live


def test_trigger_silent_on_well_calibrated_stream() -> None:
    orch, decisions, _, _, proposals, _ = _full_orchestrator()
    _stream(orch, decisions, n=60, bad_rate=0.0)  # zero false-permits
    # No miscalibration evidence -> the e-process never crosses -> silence.
    assert len(proposals) == 0


def test_trigger_seals_certificate_into_proposal() -> None:
    orch, decisions, _, _, proposals, _ = _full_orchestrator()
    _stream(orch, decisions, n=40, bad_rate=0.33)
    p = proposals.list_pending(tenant_id="acme")[0]
    cert = p.metadata.get("calibration_trigger")
    assert cert is not None
    assert cert["trigger"] == "anytime_valid_eprocess"
    assert cert["p_anytime_valid"] < 0.01  # crossed the alpha boundary
    assert "ope" in p.metadata  # OPE bound also sealed


def test_supersession_expires_prior_pending() -> None:
    orch, decisions, _, _, proposals, _ = _full_orchestrator()
    _stream(orch, decisions, n=80, bad_rate=0.33)
    # Many crossings over the stream; only the freshest stays pending, the
    # rest are EXPIRED (lapse-on-supersession), never REJECTED/APPLIED.
    assert len(proposals.list_pending(tenant_id="acme")) == 1
    statuses = [pr.status for pr in proposals.list_recent(limit=100)]
    assert ProposalStatus.EXPIRED in statuses
    assert statuses.count(ProposalStatus.PENDING) == 1


def test_trigger_never_raises_on_garbage() -> None:
    orch, decisions, _, _, proposals, trigger = _full_orchestrator()
    # An outcome with no signal (FORBID) must be a clean no-op.
    d = _make_decision(tenant_id="acme", verdict=Verdict.FORBID)
    decisions.save(d)
    o = OutcomeRecord.create(
        decision_id=d.decision_id,
        request_id=d.request_id,
        verdict=Verdict.FORBID,
        outcome_kind=OutcomeKind.BLOCKED,
        was_safe=True,
        reporter="rep",
        source_type=OutcomeSourceType.HUMAN_REVIEWER,
    )
    result = trigger.on_outcome(o)
    assert result.fired is False


# ── sufficiency gate ─────────────────────────────────────────────────────


def _mk_outcome(*, safe, trust, reporter, age_days=0):
    o = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=safe,
        reporter=reporter,
        source_type=OutcomeSourceType.HUMAN_REVIEWER,
    )
    return o.model_copy(
        update={
            "trust_level": trust,
            "recorded_at": datetime.now(UTC) - timedelta(days=age_days),
        }
    )


def test_sufficiency_ready_on_good_window() -> None:
    gate = EvidenceSufficiency(target_count=10, readiness_threshold=0.5)
    window = tuple(
        _mk_outcome(
            safe=(i % 2 == 0),
            trust=OutcomeTrustLevel.VERIFIED,
            reporter=f"r{i % 3}",
        )
        for i in range(12)
    )
    report = gate.assess(window)
    assert report.ready is True


def test_sufficiency_blocks_thin_window() -> None:
    gate = EvidenceSufficiency(target_count=30, readiness_threshold=0.6)
    window = tuple(
        _mk_outcome(safe=(i % 2 == 0), trust=OutcomeTrustLevel.VERIFIED, reporter="r")
        for i in range(4)
    )
    report = gate.assess(window)
    assert report.ready is False
    assert "outcomes" in report.reason.lower()


def test_sufficiency_blocks_one_sided_window() -> None:
    gate = EvidenceSufficiency(target_count=10, readiness_threshold=0.6)
    # All safe -> representativeness collapses.
    window = tuple(
        _mk_outcome(safe=True, trust=OutcomeTrustLevel.VERIFIED, reporter=f"r{i%3}")
        for i in range(20)
    )
    report = gate.assess(window)
    assert report.representativeness < 0.3
    assert report.ready is False


def test_sufficiency_blocks_stale_window() -> None:
    gate = EvidenceSufficiency(
        target_count=10,
        readiness_threshold=0.6,
        freshness_horizon=timedelta(days=14),
    )
    window = tuple(
        _mk_outcome(
            safe=(i % 2 == 0),
            trust=OutcomeTrustLevel.VERIFIED,
            reporter=f"r{i%3}",
            age_days=90,  # far outside the freshness horizon
        )
        for i in range(20)
    )
    report = gate.assess(window)
    assert report.freshness == 0.0
    assert report.ready is False


# ── OPE bound ────────────────────────────────────────────────────────────


def test_ope_upper_bound_no_exposure_is_zero() -> None:
    assert _anytime_valid_upper_bound(successes=0, n=0, alpha=0.05) == 0.0


def test_ope_upper_bound_exceeds_point_estimate() -> None:
    # The anytime-valid bound must be conservative: UB > mu_hat.
    ub = _anytime_valid_upper_bound(successes=5, n=20, alpha=0.05)
    assert ub > 0.25  # mu_hat = 0.25
    assert ub <= 1.0


def test_ope_bound_tightens_with_n() -> None:
    ub_small = _anytime_valid_upper_bound(successes=10, n=40, alpha=0.05)
    ub_large = _anytime_valid_upper_bound(successes=250, n=1000, alpha=0.05)
    # Same rate (0.25), more data -> tighter bound.
    assert ub_large < ub_small


def test_ope_budget_blocks_unsafe_proposal() -> None:
    # Tight budget: an unsafe-heavy stream should be refused by the OPE gate.
    orch, decisions, _, _, proposals, _ = _full_orchestrator(ope_budget=0.02)
    _stream(orch, decisions, n=60, bad_rate=0.4)
    # The e-process crosses, but the OPE bound on a 40%-unsafe stream blows the
    # 2% budget, so no proposal is ever drafted.
    assert len(proposals) == 0


# ── calibration-hold provider ────────────────────────────────────────────


def test_calibration_provider_maps_pending_to_hold() -> None:
    orch, decisions, _, _, proposals, _ = _full_orchestrator()
    _stream(orch, decisions, n=40, bad_rate=0.33)
    provider = CalibrationProposalVigilProvider(proposals)
    payload = provider.current("acme")
    assert payload is not None
    assert payload["dimension"] == "learning"
    hold = payload["hold"]
    assert hold["kind"] == "calibration"
    assert hold["proposal_id"] is not None
    assert hold["proposed_change"] is not None
    assert hold["resolving_question"]


def test_calibration_provider_empty_store_returns_none() -> None:
    _, _, _, _, proposals, _ = _full_orchestrator()
    provider = CalibrationProposalVigilProvider(proposals)
    assert provider.current("acme") is None


def test_composite_is_decision_first() -> None:
    class _Decision:
        def current(self, tenant):
            return {"id": "decision", "sentence": "held decision"}

    class _Calibration:
        def current(self, tenant):
            return {"id": "calibration", "sentence": "proposal"}

    composite = CompositeHeldProvider([_Decision(), _Calibration()])
    assert composite.current("acme")["id"] == "decision"


def test_composite_falls_through_to_calibration() -> None:
    class _NoDecision:
        def current(self, tenant):
            return None

    class _Calibration:
        def current(self, tenant):
            return {"id": "calibration", "sentence": "proposal"}

    composite = CompositeHeldProvider([_NoDecision(), _Calibration()])
    assert composite.current("acme")["id"] == "calibration"


# ── standardisation sanity ───────────────────────────────────────────────


def test_standardise_false_permit_zero_mean_under_null() -> None:
    p0 = 0.05
    x_false = _standardise_false_permit(is_false_permit=True, p0=p0)
    x_ok = _standardise_false_permit(is_false_permit=False, p0=p0)
    # Mean under the null rate p0 is ~0: p0 * x_false + (1-p0) * x_ok ≈ 0.
    mean = p0 * x_false + (1 - p0) * x_ok
    assert abs(mean) < 1e-9
