"""Tests for adversarial / poisoning detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tex.domain.outcome import OutcomeKind, OutcomeLabel, OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.verdict import Verdict
from tex.learning.poisoning_detector import PoisoningDetector


def _make_outcome(
    *,
    decision_id=None,
    reporter: str,
    label: OutcomeLabel,
    tenant_id: str = "acme",
    recorded_at: datetime | None = None,
    trust_level: OutcomeTrustLevel = OutcomeTrustLevel.VALIDATED,
) -> OutcomeRecord:
    # Pick a verdict/kind/was_safe combo that produces the requested label.
    if label is OutcomeLabel.CORRECT_PERMIT:
        verdict, kind, safe = Verdict.PERMIT, OutcomeKind.RELEASED, True
    elif label is OutcomeLabel.FALSE_PERMIT:
        verdict, kind, safe = Verdict.PERMIT, OutcomeKind.RELEASED, False
    elif label is OutcomeLabel.CORRECT_FORBID:
        verdict, kind, safe = Verdict.FORBID, OutcomeKind.BLOCKED, False
    elif label is OutcomeLabel.FALSE_FORBID:
        verdict, kind, safe = Verdict.FORBID, OutcomeKind.BLOCKED, True
    else:
        verdict, kind, safe = Verdict.ABSTAIN, OutcomeKind.ESCALATED, None

    o = OutcomeRecord.create(
        decision_id=decision_id or uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        outcome_kind=kind,
        was_safe=safe,
        reporter=reporter,
        tenant_id=tenant_id,
        trust_level=trust_level,
    )
    if recorded_at is not None:
        o = o.model_copy(update={"recorded_at": recorded_at})
    return o


def test_no_findings_when_nothing_suspicious() -> None:
    detector = PoisoningDetector()
    now = datetime.now(UTC)
    outcomes = [
        _make_outcome(reporter=f"r{i}", label=OutcomeLabel.CORRECT_PERMIT, recorded_at=now)
        for i in range(3)
    ]
    report = detector.detect(recent_outcomes=outcomes)
    assert not report.has_findings


def test_cluster_detection_flags_coordinated_reporters() -> None:
    detector = PoisoningDetector(
        cluster_min_reporters=3,
        cluster_min_outcomes=8,
    )
    now = datetime.now(UTC)
    # 4 reporters, 12 outcomes, all with the same FALSE_PERMIT label.
    outcomes = []
    for i in range(12):
        outcomes.append(
            _make_outcome(
                reporter=f"r{i % 4}",
                label=OutcomeLabel.FALSE_PERMIT,
                recorded_at=now - timedelta(minutes=i),
            )
        )
    report = detector.detect(recent_outcomes=outcomes)
    assert report.has_findings
    assert len(report.clusters) == 1
    assert report.clusters[0].dominant_label is OutcomeLabel.FALSE_PERMIT
    assert len(report.clusters[0].reporters) == 4


def test_sudden_shift_detected_when_false_permit_rate_jumps() -> None:
    detector = PoisoningDetector(
        sudden_shift_delta=0.20,
        sudden_shift_min_samples=10,
    )
    now = datetime.now(UTC)
    # Baseline: 20 outcomes, 1 false_permit (5%)
    baseline = [
        _make_outcome(
            reporter=f"r{i}", label=OutcomeLabel.CORRECT_PERMIT, recorded_at=now - timedelta(days=20)
        )
        for i in range(19)
    ] + [
        _make_outcome(
            reporter="r0", label=OutcomeLabel.FALSE_PERMIT, recorded_at=now - timedelta(days=20)
        )
    ]
    # Recent: 20 outcomes, 12 false_permit (60%) — jump of 55%
    recent = [
        _make_outcome(
            reporter=f"r{i}", label=OutcomeLabel.FALSE_PERMIT, recorded_at=now
        )
        for i in range(12)
    ] + [
        _make_outcome(
            reporter=f"r{i}", label=OutcomeLabel.CORRECT_PERMIT, recorded_at=now
        )
        for i in range(8)
    ]
    report = detector.detect(recent_outcomes=recent, baseline_outcomes=baseline)
    assert any(s.metric == "false_permit_rate" for s in report.sudden_shifts)


def test_repeated_disagreement_flags_lone_dissenter() -> None:
    detector = PoisoningDetector(
        repeat_disagreement_rate=0.40,
        repeat_disagreement_min_observations=6,
    )
    now = datetime.now(UTC)
    decision_ids = [uuid4() for _ in range(10)]
    outcomes = []
    for did in decision_ids:
        # VERIFIED prior says CORRECT_PERMIT
        outcomes.append(
            _make_outcome(
                decision_id=did,
                reporter="auditor",
                label=OutcomeLabel.CORRECT_PERMIT,
                recorded_at=now,
                trust_level=OutcomeTrustLevel.VERIFIED,
            )
        )
        # Bad reporter consistently disagrees
        outcomes.append(
            _make_outcome(
                decision_id=did,
                reporter="dissenter",
                label=OutcomeLabel.FALSE_PERMIT,
                recorded_at=now,
            )
        )
    report = detector.detect(recent_outcomes=outcomes)
    assert any(d.reporter == "dissenter" for d in report.repeated_disagreements)


def test_max_severity_returns_highest_finding_grade() -> None:
    detector = PoisoningDetector(
        cluster_min_reporters=3,
        cluster_min_outcomes=8,
    )
    now = datetime.now(UTC)
    # 5 reporters, 40 outcomes (5x the threshold) -> high severity cluster
    outcomes = [
        _make_outcome(
            reporter=f"r{i % 5}",
            label=OutcomeLabel.FALSE_PERMIT,
            recorded_at=now - timedelta(minutes=i),
        )
        for i in range(40)
    ]
    report = detector.detect(recent_outcomes=outcomes)
    assert report.max_severity in ("medium", "high")
