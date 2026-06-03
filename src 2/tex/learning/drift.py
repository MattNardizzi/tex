"""
Policy-drift detection for Tex.

Galileo charged for calibration intelligence. This module gives Tex the
same muscle out of the box: given the recent decision stream, surface
verdict-distribution changes across time windows so operators can see
when a policy version is drifting.

The monitor is intentionally simple:

- window the stored decisions by insertion order
- compute verdict distribution (permit / abstain / forbid rate) per
  window
- compute delta: how much has each rate moved window-over-window?
- surface human-readable flags when the delta crosses meaningful bars

The monitor does not write calibration recommendations. Tex's existing
``ThresholdCalibrator`` owns that. This is the observability surface
that tells you it is time to look.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore


DEFAULT_DRIFT_WINDOW_SIZE: int = 50
SIGNIFICANT_RATE_DELTA: float = 0.10
SIGNIFICANT_ABSTAIN_DELTA: float = 0.08


class VerdictDistribution(BaseModel):
    """Verdict rates for a single window of decisions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_size: int = Field(ge=0)
    permit_rate: float = Field(ge=0.0, le=1.0)
    abstain_rate: float = Field(ge=0.0, le=1.0)
    forbid_rate: float = Field(ge=0.0, le=1.0)


class PolicyDriftReport(BaseModel):
    """
    Policy-drift report for one policy version.

    Computed from the most recent ``window_size * 2`` decisions on the
    policy version, split into a previous and current window.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_version: str = Field(min_length=1, max_length=100)
    window_size: int = Field(ge=1)
    total_samples: int = Field(ge=0)
    sufficient_data: bool = Field(
        description=(
            "True only when both windows have at least one sample. "
            "Consumers should gate alerts on this."
        ),
    )
    previous_window: VerdictDistribution
    current_window: VerdictDistribution
    permit_rate_delta: float
    abstain_rate_delta: float
    forbid_rate_delta: float
    flags: tuple[str, ...] = Field(default_factory=tuple)


class PolicyDriftMonitor:
    """
    Compute verdict-distribution drift for a given policy version.

    This is read-only. It does not mutate the decision store.
    """

    __slots__ = ("_decision_store",)

    def __init__(self, decision_store: InMemoryDecisionStore) -> None:
        self._decision_store = decision_store

    def report(
        self,
        *,
        policy_version: str,
        window_size: int = DEFAULT_DRIFT_WINDOW_SIZE,
    ) -> PolicyDriftReport:
        if window_size <= 0:
            raise ValueError("window_size must be positive")

        normalized_version = policy_version.strip()
        if not normalized_version:
            raise ValueError("policy_version must not be blank")

        matches = self._decision_store.find(
            policy_version=normalized_version,
            limit=window_size * 2,
        )
        # find() returns newest-first; reverse to have chronological order
        # so "previous" truly precedes "current".
        chronological = tuple(reversed(matches))

        total = len(chronological)
        previous_slice = chronological[:window_size]
        current_slice = chronological[window_size : window_size * 2]

        previous_distribution = _distribution(previous_slice)
        current_distribution = _distribution(current_slice)

        permit_delta = round(
            current_distribution.permit_rate - previous_distribution.permit_rate, 4
        )
        abstain_delta = round(
            current_distribution.abstain_rate - previous_distribution.abstain_rate, 4
        )
        forbid_delta = round(
            current_distribution.forbid_rate - previous_distribution.forbid_rate, 4
        )

        sufficient_data = (
            previous_distribution.sample_size > 0
            and current_distribution.sample_size > 0
        )

        flags = _build_flags(
            sufficient_data=sufficient_data,
            permit_delta=permit_delta,
            abstain_delta=abstain_delta,
            forbid_delta=forbid_delta,
        )

        return PolicyDriftReport(
            policy_version=normalized_version,
            window_size=window_size,
            total_samples=total,
            sufficient_data=sufficient_data,
            previous_window=previous_distribution,
            current_window=current_distribution,
            permit_rate_delta=permit_delta,
            abstain_rate_delta=abstain_delta,
            forbid_rate_delta=forbid_delta,
            flags=flags,
        )


def _distribution(decisions: tuple) -> VerdictDistribution:
    """Verdict distribution for a slice of decisions."""
    size = len(decisions)
    if size == 0:
        return VerdictDistribution(
            sample_size=0, permit_rate=0.0, abstain_rate=0.0, forbid_rate=0.0
        )

    permit_count = sum(1 for d in decisions if d.verdict == Verdict.PERMIT)
    abstain_count = sum(1 for d in decisions if d.verdict == Verdict.ABSTAIN)
    forbid_count = sum(1 for d in decisions if d.verdict == Verdict.FORBID)

    return VerdictDistribution(
        sample_size=size,
        permit_rate=round(permit_count / size, 4),
        abstain_rate=round(abstain_count / size, 4),
        forbid_rate=round(forbid_count / size, 4),
    )


def _build_flags(
    *,
    sufficient_data: bool,
    permit_delta: float,
    abstain_delta: float,
    forbid_delta: float,
) -> tuple[str, ...]:
    """Human-readable flags a UI or alerting system can key off of."""
    if not sufficient_data:
        return ("insufficient_data",)

    flags: list[str] = []

    if abstain_delta >= SIGNIFICANT_ABSTAIN_DELTA:
        flags.append("abstain_rate_climbing")
    elif abstain_delta <= -SIGNIFICANT_ABSTAIN_DELTA:
        flags.append("abstain_rate_falling")

    if forbid_delta >= SIGNIFICANT_RATE_DELTA:
        flags.append("forbid_rate_climbing")
    elif forbid_delta <= -SIGNIFICANT_RATE_DELTA:
        flags.append("forbid_rate_falling")

    if permit_delta >= SIGNIFICANT_RATE_DELTA:
        flags.append("permit_rate_climbing")
    elif permit_delta <= -SIGNIFICANT_RATE_DELTA:
        flags.append("permit_rate_falling")

    if not flags:
        flags.append("stable")

    return tuple(flags)
