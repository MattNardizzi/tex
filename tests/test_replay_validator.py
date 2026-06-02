"""Tests for the replay validator."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.verdict import Verdict
from tex.learning.calibrator import CalibrationRecommendation
from tex.learning.outcomes import OutcomeSummary
from tex.learning.replay import ReplayValidator
from tex.policies.defaults import build_default_policy


def _decision(
    *,
    final_score: float,
    confidence: float,
    verdict: Verdict,
    request_id=None,
) -> Decision:
    return Decision(
        request_id=request_id or uuid4(),
        verdict=verdict,
        confidence=confidence,
        final_score=final_score,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi",
        content_sha256="b" * 64,
        policy_version="default-v1",
        scores={"semantic": final_score},
        reasons=[] if verdict is not Verdict.FORBID else ["risk"],
        uncertainty_flags=[] if verdict is not Verdict.ABSTAIN else ["uncertain"],
    )


def _summary() -> OutcomeSummary:
    return OutcomeSummary(
        total=10, correct_permits=8, false_permits=0,
        correct_forbids=2, false_forbids=0, abstain_reviews=0, unknown=0,
    )


def _rec(
    *,
    new_permit: float,
    new_forbid: float,
    new_min_conf: float,
    cur_permit: float = 0.30,
    cur_forbid: float = 0.65,
    cur_min_conf: float = 0.60,
) -> CalibrationRecommendation:
    return CalibrationRecommendation(
        current_permit_threshold=cur_permit,
        recommended_permit_threshold=new_permit,
        current_forbid_threshold=cur_forbid,
        recommended_forbid_threshold=new_forbid,
        current_minimum_confidence=cur_min_conf,
        recommended_minimum_confidence=new_min_conf,
        summary=_summary(),
        reasons=("test",),
        false_permit_rate=0.0,
        false_forbid_rate=0.0,
        abstain_review_rate=0.0,
        unknown_rate=0.0,
        sample_weight=0.8,
        permit_threshold_delta=new_permit - cur_permit,
        forbid_threshold_delta=new_forbid - cur_forbid,
        minimum_confidence_delta=new_min_conf - cur_min_conf,
    )


# ── re-derivation correctness ─────────────────────────────────────────────


def test_replay_correctly_flips_borderline_permit_to_forbid() -> None:
    # Decision was a permit at score 0.20.
    # Tightening forbid_threshold to 0.18 should now flip it to FORBID under replay.
    decisions = [
        _decision(final_score=0.20, confidence=0.95, verdict=Verdict.PERMIT),
    ]
    rec = _rec(new_permit=0.10, new_forbid=0.18, new_min_conf=0.60)
    rep = ReplayValidator().replay(
        decisions=decisions,
        outcomes=[],
        policy=build_default_policy(),
        recommendation=rec,
    )
    assert rep.new_forbids == 1
    assert rep.proposed_distribution.forbid == 1


def test_replay_resolved_abstains() -> None:
    # Decision was ABSTAIN at score 0.50, confidence 0.50.
    # Loosening confidence requirement to 0.40 should now PERMIT it.
    decisions = [
        _decision(final_score=0.10, confidence=0.50, verdict=Verdict.ABSTAIN),
    ]
    rec = _rec(new_permit=0.30, new_forbid=0.65, new_min_conf=0.40)
    rep = ReplayValidator().replay(
        decisions=decisions,
        outcomes=[],
        policy=build_default_policy(),
        recommendation=rec,
    )
    assert rep.resolved_abstains == 1


# ── safety scoring ────────────────────────────────────────────────────────


def test_replay_counts_would_have_blocked_safe() -> None:
    request_id = uuid4()
    decision = _decision(
        final_score=0.20, confidence=0.95, verdict=Verdict.PERMIT, request_id=request_id
    )
    # Outcome attached: was_safe=True (i.e. the original PERMIT was correct).
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="auditor",
        trust_level=OutcomeTrustLevel.VERIFIED,
    )
    # Tightening forbid threshold to 0.18 would now block this safe permit.
    rec = _rec(new_permit=0.10, new_forbid=0.18, new_min_conf=0.60)
    rep = ReplayValidator().replay(
        decisions=[decision],
        outcomes=[outcome],
        policy=build_default_policy(),
        recommendation=rec,
    )
    assert rep.would_have_blocked_safe == 1


def test_replay_counts_would_have_released_unsafe() -> None:
    request_id = uuid4()
    # Original FORBID at low score 0.20 (e.g. produced by a strict policy
    # whose forbid_threshold was 0.18). Outcome was actually unsafe —
    # the FORBID was correct. Loosening forbid_threshold to 0.65 and
    # confidence threshold to 0.40 means score 0.20 now PERMITs through.
    decision = _decision(
        final_score=0.20, confidence=0.60, verdict=Verdict.FORBID, request_id=request_id
    )
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=request_id,
        verdict=Verdict.FORBID,
        outcome_kind=OutcomeKind.BLOCKED,
        was_safe=False,
        reporter="auditor",
        trust_level=OutcomeTrustLevel.VERIFIED,
    )
    rec = _rec(
        new_permit=0.30,  # score 0.20 <= 0.30 -> PERMIT
        new_forbid=0.65,
        new_min_conf=0.40,  # confidence 0.60 >= 0.40 -> permit clears
        cur_permit=0.05,    # score 0.20 was above the strict permit, hence not permitted originally
        cur_forbid=0.18,    # score 0.20 >= 0.18 was forbid originally
        cur_min_conf=0.50,
    )
    rep = ReplayValidator().replay(
        decisions=[decision],
        outcomes=[outcome],
        policy=build_default_policy(),
        recommendation=rec,
    )
    assert rep.would_have_released_unsafe == 1


def test_replay_marks_risky_change_when_many_flips() -> None:
    decisions = []
    # 10 permits at score 0.20 — all flip to FORBID under tighter threshold.
    for _ in range(10):
        decisions.append(_decision(final_score=0.20, confidence=0.95, verdict=Verdict.PERMIT))
    rec = _rec(new_permit=0.10, new_forbid=0.18, new_min_conf=0.60)
    rep = ReplayValidator(risky_flip_threshold=0.10).replay(
        decisions=decisions,
        outcomes=[],
        policy=build_default_policy(),
        recommendation=rec,
    )
    assert rep.risky_change is True
