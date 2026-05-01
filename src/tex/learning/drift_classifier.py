"""
Drift classification.

The existing ``PolicyDriftMonitor`` reports verdict-distribution shifts.
That's useful but underspecified — a shift can mean very different things:

  DATA drift        — the inputs Tex sees have changed (different
                      content types, different agent populations)
  BEHAVIOR drift    — the system's decision pattern has changed without
                      the inputs changing materially (model regression,
                      retrieval drift, specialist score drift)
  POLICY drift      — operators changed thresholds (expected change)
  ADVERSARIAL drift — the inputs are deliberately probing the boundary

The classifier fuses three signals:

  - the existing ``PolicyDriftReport`` (verdict-distribution movement)
  - a recent ``PoisoningReport`` (clusters / shifts / disagreements)
  - the calibration history (was a policy change applied recently?)

into a single ``ClassifiedDrift`` finding with the diagnosis and the
recommended response posture (NORMAL_REVIEW / ELEVATED_REVIEW / FREEZE).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from tex.learning.drift import PolicyDriftReport
from tex.learning.poisoning_detector import PoisoningReport


class DriftType(StrEnum):
    DATA = "DATA"
    BEHAVIOR = "BEHAVIOR"
    POLICY = "POLICY"
    ADVERSARIAL = "ADVERSARIAL"
    UNKNOWN = "UNKNOWN"


class DriftPosture(StrEnum):
    NORMAL_REVIEW = "NORMAL_REVIEW"
    ELEVATED_REVIEW = "ELEVATED_REVIEW"
    FREEZE = "FREEZE"


@dataclass(frozen=True, slots=True)
class ClassifiedDrift:
    """The classifier's diagnosis."""

    drift_type: DriftType
    posture: DriftPosture
    confidence: float
    rationale: tuple[str, ...]
    sourced_from: tuple[str, ...]


@dataclass(slots=True)
class DriftClassifier:
    """
    Classifies drift signals into a single diagnosis.

    Parameterless construction is fine; thresholds are deliberately
    conservative.
    """

    recent_calibration_window: timedelta = timedelta(hours=4)
    significant_movement: float = 0.10

    def classify(
        self,
        *,
        drift_report: PolicyDriftReport,
        poisoning_report: PoisoningReport | None = None,
        last_calibrated_at: datetime | None = None,
        clock: callable | None = None,
    ) -> ClassifiedDrift:
        now = (clock or (lambda: datetime.now(UTC)))()
        sources: list[str] = []
        rationale: list[str] = []

        if not drift_report.sufficient_data:
            return ClassifiedDrift(
                drift_type=DriftType.UNKNOWN,
                posture=DriftPosture.NORMAL_REVIEW,
                confidence=0.0,
                rationale=("Insufficient data for classification.",),
                sourced_from=("drift_report",),
            )

        # Adversarial signal trumps everything when present at medium+ severity.
        if poisoning_report is not None and poisoning_report.has_findings:
            sources.append("poisoning_report")
            severity = poisoning_report.max_severity
            if severity in ("medium", "high"):
                rationale.append(
                    f"Poisoning detector flagged {severity}-severity findings: "
                    f"{len(poisoning_report.clusters)} cluster(s), "
                    f"{len(poisoning_report.sudden_shifts)} sudden shift(s), "
                    f"{len(poisoning_report.repeated_disagreements)} repeated-"
                    "disagreement reporter(s)."
                )
                posture = (
                    DriftPosture.FREEZE
                    if severity == "high"
                    else DriftPosture.ELEVATED_REVIEW
                )
                return ClassifiedDrift(
                    drift_type=DriftType.ADVERSARIAL,
                    posture=posture,
                    confidence=0.85 if severity == "high" else 0.65,
                    rationale=tuple(rationale),
                    sourced_from=tuple(sources),
                )

        # Recent calibration explains drift cheaply.
        if (
            last_calibrated_at is not None
            and (now - last_calibrated_at) <= self.recent_calibration_window
        ):
            rationale.append(
                "Drift coincides with a recent calibration; classifying as "
                "expected POLICY drift."
            )
            return ClassifiedDrift(
                drift_type=DriftType.POLICY,
                posture=DriftPosture.NORMAL_REVIEW,
                confidence=0.7,
                rationale=tuple(rationale),
                sourced_from=("drift_report", "calibration_history"),
            )

        # Distinguish data vs behavior drift by the *shape* of movement.
        permit_d = abs(drift_report.permit_rate_delta)
        forbid_d = abs(drift_report.forbid_rate_delta)
        abstain_d = abs(drift_report.abstain_rate_delta)

        sources.append("drift_report")

        # Behavior drift fingerprint: abstain rate moves a lot while
        # permit + forbid stay relatively coherent. The system is becoming
        # less confident on inputs it would have decided on cleanly before.
        if abstain_d >= self.significant_movement and abstain_d >= max(
            permit_d, forbid_d
        ):
            rationale.append(
                f"Abstain-rate delta ({abstain_d:.2f}) dominates verdict "
                "movement; consistent with BEHAVIOR drift (degraded "
                "confidence on existing input shapes)."
            )
            return ClassifiedDrift(
                drift_type=DriftType.BEHAVIOR,
                posture=DriftPosture.ELEVATED_REVIEW,
                confidence=0.65,
                rationale=tuple(rationale),
                sourced_from=tuple(sources),
            )

        # Data drift fingerprint: permit and forbid both move significantly
        # while abstain stays relatively stable. The system is decisive
        # but on a different input distribution.
        if (
            permit_d >= self.significant_movement
            and forbid_d >= self.significant_movement
            and abstain_d < self.significant_movement
        ):
            rationale.append(
                "Permit and forbid both shifted while abstain held; "
                "consistent with DATA drift (input distribution change)."
            )
            return ClassifiedDrift(
                drift_type=DriftType.DATA,
                posture=DriftPosture.ELEVATED_REVIEW,
                confidence=0.6,
                rationale=tuple(rationale),
                sourced_from=tuple(sources),
            )

        # Anything else: return UNKNOWN with the raw flags so dashboards
        # can still surface it.
        rationale.append(
            "Drift movement does not match known fingerprints. Holding at "
            "normal review."
        )
        return ClassifiedDrift(
            drift_type=DriftType.UNKNOWN,
            posture=DriftPosture.NORMAL_REVIEW,
            confidence=0.4,
            rationale=tuple(rationale),
            sourced_from=tuple(sources),
        )


__all__ = [
    "ClassifiedDrift",
    "DriftClassifier",
    "DriftPosture",
    "DriftType",
]
