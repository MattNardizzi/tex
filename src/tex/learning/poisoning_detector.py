"""
Adversarial / poisoning detection.

A coordinated group of attackers can submit "valid-looking" outcomes
that, individually, pass structural validation but, in aggregate, push
calibration in a chosen direction. This module surfaces three signals:

  1. Reporter clustering — many reporters submitting near-identical
     label distributions in a short window, especially when their
     individual reputations have not been established.

  2. Sudden label shift — the false-permit (or false-forbid) rate within
     a single tenant suddenly diverges from its baseline; we surface
     this as a candidate poisoning signal so the calibration safety
     bounds and the human-approval workflow get triggered.

  3. Repeated disagreement — a single reporter (or cluster) disagrees
     with VERIFIED outcomes much more often than chance.

The detector is read-only: it produces a structured ``PoisoningReport``
with severities and the reporters/tenants implicated. Action (quarantine,
sanction) is the responsibility of the feedback-loop orchestrator, which
weighs the report against the calibration safety bounds.

Detection here is intentionally conservative. False positives cost real
operator time; we tune for "this is worth a human looking at it" rather
than "auto-block." The thresholds are constructor-tunable.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from tex.domain.outcome import OutcomeLabel, OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel


DEFAULT_CLUSTER_WINDOW = timedelta(hours=6)
DEFAULT_CLUSTER_MIN_REPORTERS = 3
DEFAULT_CLUSTER_MIN_OUTCOMES = 8
DEFAULT_SUDDEN_SHIFT_DELTA = 0.20
DEFAULT_SUDDEN_SHIFT_MIN_SAMPLES = 20
DEFAULT_REPEAT_DISAGREEMENT_RATE = 0.40
DEFAULT_REPEAT_DISAGREEMENT_MIN_OBSERVATIONS = 6


@dataclass(frozen=True, slots=True)
class ReporterCluster:
    """A group of reporters acting in unusual concert."""

    reporters: tuple[str, ...]
    tenant_id: str
    dominant_label: OutcomeLabel
    outcome_count: int
    window_start: datetime
    window_end: datetime
    severity: str  # "low" | "medium" | "high"


@dataclass(frozen=True, slots=True)
class SuddenShift:
    """A sudden movement in a tenant's outcome label distribution."""

    tenant_id: str
    metric: str  # "false_permit_rate" | "false_forbid_rate"
    baseline_value: float
    current_value: float
    delta: float
    sample_size: int
    severity: str


@dataclass(frozen=True, slots=True)
class RepeatedDisagreement:
    """A reporter who disagrees with VERIFIED outcomes too often."""

    reporter: str
    tenant_id: str | None
    observations: int
    disagreements: int
    rate: float
    severity: str


@dataclass(frozen=True, slots=True)
class PoisoningReport:
    """Aggregate findings from the poisoning detector."""

    generated_at: datetime
    clusters: tuple[ReporterCluster, ...]
    sudden_shifts: tuple[SuddenShift, ...]
    repeated_disagreements: tuple[RepeatedDisagreement, ...]

    @property
    def has_findings(self) -> bool:
        return bool(self.clusters or self.sudden_shifts or self.repeated_disagreements)

    @property
    def max_severity(self) -> str:
        ranks = {"low": 1, "medium": 2, "high": 3}
        worst = 0
        for finding in (
            *self.clusters,
            *self.sudden_shifts,
            *self.repeated_disagreements,
        ):
            worst = max(worst, ranks.get(finding.severity, 0))
        return {3: "high", 2: "medium", 1: "low"}.get(worst, "none")


class PoisoningDetector:
    """
    Stateless detector run against a recent slice of outcomes.

    Each detection method is independent so the orchestrator can run them
    on different cadences. A cluster check might run every 5 minutes; a
    sudden-shift check might run on-demand before a calibration proposal
    is generated.
    """

    __slots__ = (
        "_cluster_window",
        "_cluster_min_reporters",
        "_cluster_min_outcomes",
        "_sudden_shift_delta",
        "_sudden_shift_min_samples",
        "_repeat_disagreement_rate",
        "_repeat_disagreement_min_observations",
        "_clock",
    )

    def __init__(
        self,
        *,
        cluster_window: timedelta = DEFAULT_CLUSTER_WINDOW,
        cluster_min_reporters: int = DEFAULT_CLUSTER_MIN_REPORTERS,
        cluster_min_outcomes: int = DEFAULT_CLUSTER_MIN_OUTCOMES,
        sudden_shift_delta: float = DEFAULT_SUDDEN_SHIFT_DELTA,
        sudden_shift_min_samples: int = DEFAULT_SUDDEN_SHIFT_MIN_SAMPLES,
        repeat_disagreement_rate: float = DEFAULT_REPEAT_DISAGREEMENT_RATE,
        repeat_disagreement_min_observations: int = (
            DEFAULT_REPEAT_DISAGREEMENT_MIN_OBSERVATIONS
        ),
        clock: callable | None = None,
    ) -> None:
        if cluster_window.total_seconds() <= 0:
            raise ValueError("cluster_window must be positive")
        if cluster_min_reporters < 2:
            raise ValueError("cluster_min_reporters must be >= 2")
        if not 0.0 < sudden_shift_delta <= 1.0:
            raise ValueError("sudden_shift_delta must be in (0.0, 1.0]")
        if sudden_shift_min_samples < 5:
            raise ValueError("sudden_shift_min_samples must be >= 5")
        if not 0.0 < repeat_disagreement_rate <= 1.0:
            raise ValueError("repeat_disagreement_rate must be in (0.0, 1.0]")

        self._cluster_window = cluster_window
        self._cluster_min_reporters = cluster_min_reporters
        self._cluster_min_outcomes = cluster_min_outcomes
        self._sudden_shift_delta = sudden_shift_delta
        self._sudden_shift_min_samples = sudden_shift_min_samples
        self._repeat_disagreement_rate = repeat_disagreement_rate
        self._repeat_disagreement_min_observations = (
            repeat_disagreement_min_observations
        )
        self._clock = clock or (lambda: datetime.now(UTC))

    def detect(
        self,
        *,
        recent_outcomes: Iterable[OutcomeRecord],
        baseline_outcomes: Iterable[OutcomeRecord] | None = None,
    ) -> PoisoningReport:
        """
        Run all three detectors and return a combined report.

        ``recent_outcomes`` is the window we are scrutinizing.
        ``baseline_outcomes`` is the longer-term reference window used
        only by the sudden-shift detector. When omitted, sudden-shift is
        skipped.
        """
        recent = tuple(recent_outcomes)
        clusters = self._detect_clusters(recent)
        repeats = self._detect_repeated_disagreement(recent)

        shifts: tuple[SuddenShift, ...] = ()
        if baseline_outcomes is not None:
            shifts = self._detect_sudden_shifts(
                recent=recent,
                baseline=tuple(baseline_outcomes),
            )

        return PoisoningReport(
            generated_at=self._clock(),
            clusters=clusters,
            sudden_shifts=shifts,
            repeated_disagreements=repeats,
        )

    # ── cluster detection ───────────────────────────────────────────────

    def _detect_clusters(
        self, recent: tuple[OutcomeRecord, ...]
    ) -> tuple[ReporterCluster, ...]:
        if not recent:
            return ()
        now = self._clock()
        cutoff = now - self._cluster_window
        in_window = [o for o in recent if o.recorded_at >= cutoff]
        if len(in_window) < self._cluster_min_outcomes:
            return ()

        # Group by (tenant, label). A "cluster" is a group with >= N
        # distinct reporters all submitting the same label inside the
        # window — the kind of pattern coordinated poisoning produces.
        buckets: dict[tuple[str, OutcomeLabel], list[OutcomeRecord]] = defaultdict(list)
        for outcome in in_window:
            tenant = outcome.tenant_id or "<unknown>"
            buckets[(tenant, outcome.label)].append(outcome)

        clusters: list[ReporterCluster] = []
        for (tenant, label), bucket in buckets.items():
            if len(bucket) < self._cluster_min_outcomes:
                continue
            reporters = sorted({o.reporter for o in bucket if o.reporter})
            if len(reporters) < self._cluster_min_reporters:
                continue
            severity = self._cluster_severity(
                outcome_count=len(bucket),
                distinct_reporters=len(reporters),
            )
            clusters.append(
                ReporterCluster(
                    reporters=tuple(reporters),
                    tenant_id=tenant,
                    dominant_label=label,
                    outcome_count=len(bucket),
                    window_start=cutoff,
                    window_end=now,
                    severity=severity,
                )
            )
        return tuple(clusters)

    def _cluster_severity(self, *, outcome_count: int, distinct_reporters: int) -> str:
        if outcome_count >= self._cluster_min_outcomes * 4:
            return "high"
        if outcome_count >= self._cluster_min_outcomes * 2:
            return "medium"
        return "low"

    # ── sudden shift detection ──────────────────────────────────────────

    def _detect_sudden_shifts(
        self,
        *,
        recent: tuple[OutcomeRecord, ...],
        baseline: tuple[OutcomeRecord, ...],
    ) -> tuple[SuddenShift, ...]:
        # Per tenant, compute the false-permit and false-forbid rates in
        # both windows. A jump bigger than ``sudden_shift_delta`` with
        # enough samples becomes a finding.
        recent_by_tenant: dict[str, list[OutcomeRecord]] = defaultdict(list)
        baseline_by_tenant: dict[str, list[OutcomeRecord]] = defaultdict(list)
        for o in recent:
            recent_by_tenant[o.tenant_id or "<unknown>"].append(o)
        for o in baseline:
            baseline_by_tenant[o.tenant_id or "<unknown>"].append(o)

        findings: list[SuddenShift] = []
        for tenant, recent_bucket in recent_by_tenant.items():
            if len(recent_bucket) < self._sudden_shift_min_samples:
                continue
            baseline_bucket = baseline_by_tenant.get(tenant, [])
            if len(baseline_bucket) < self._sudden_shift_min_samples:
                continue

            for metric_name, label in (
                ("false_permit_rate", OutcomeLabel.FALSE_PERMIT),
                ("false_forbid_rate", OutcomeLabel.FALSE_FORBID),
            ):
                base_rate = _label_rate(baseline_bucket, label)
                cur_rate = _label_rate(recent_bucket, label)
                delta = cur_rate - base_rate
                if abs(delta) < self._sudden_shift_delta:
                    continue
                severity = self._shift_severity(abs(delta))
                findings.append(
                    SuddenShift(
                        tenant_id=tenant,
                        metric=metric_name,
                        baseline_value=round(base_rate, 4),
                        current_value=round(cur_rate, 4),
                        delta=round(delta, 4),
                        sample_size=len(recent_bucket),
                        severity=severity,
                    )
                )
        return tuple(findings)

    def _shift_severity(self, abs_delta: float) -> str:
        if abs_delta >= self._sudden_shift_delta * 3:
            return "high"
        if abs_delta >= self._sudden_shift_delta * 2:
            return "medium"
        return "low"

    # ── repeated disagreement ───────────────────────────────────────────

    def _detect_repeated_disagreement(
        self, recent: tuple[OutcomeRecord, ...]
    ) -> tuple[RepeatedDisagreement, ...]:
        # Per (reporter, tenant), count outcomes that disagree with a
        # VERIFIED prior on the same decision. We approximate by grouping
        # outcomes by decision_id and scanning for "this reporter labelled
        # X but a VERIFIED outcome on the same decision says Y."
        by_decision: dict = defaultdict(list)
        for o in recent:
            by_decision[o.decision_id].append(o)

        per_reporter: dict[tuple[str, str | None], Counter] = defaultdict(Counter)
        for outcomes in by_decision.values():
            verified = [
                o
                for o in outcomes
                if o.trust_level is OutcomeTrustLevel.VERIFIED
                and o.label is not OutcomeLabel.UNKNOWN
            ]
            if not verified:
                continue
            verified_label = verified[0].label  # arbitrary VERIFIED reference
            for o in outcomes:
                if not o.reporter:
                    continue
                if o.trust_level is OutcomeTrustLevel.QUARANTINED:
                    continue
                if o.label is OutcomeLabel.UNKNOWN:
                    continue
                key = (o.reporter, o.tenant_id)
                per_reporter[key]["observations"] += 1
                if o.label is not verified_label:
                    per_reporter[key]["disagreements"] += 1

        findings: list[RepeatedDisagreement] = []
        for (reporter, tenant), counts in per_reporter.items():
            observations = counts["observations"]
            disagreements = counts["disagreements"]
            if observations < self._repeat_disagreement_min_observations:
                continue
            rate = disagreements / observations if observations else 0.0
            if rate < self._repeat_disagreement_rate:
                continue
            findings.append(
                RepeatedDisagreement(
                    reporter=reporter,
                    tenant_id=tenant,
                    observations=observations,
                    disagreements=disagreements,
                    rate=round(rate, 4),
                    severity=self._disagreement_severity(rate),
                )
            )
        return tuple(findings)

    def _disagreement_severity(self, rate: float) -> str:
        if rate >= 0.75:
            return "high"
        if rate >= 0.55:
            return "medium"
        return "low"


def _label_rate(outcomes: list[OutcomeRecord], label: OutcomeLabel) -> float:
    if not outcomes:
        return 0.0
    matching = sum(1 for o in outcomes if o.label is label)
    return matching / len(outcomes)


__all__ = [
    "PoisoningDetector",
    "PoisoningReport",
    "RepeatedDisagreement",
    "ReporterCluster",
    "SuddenShift",
]
