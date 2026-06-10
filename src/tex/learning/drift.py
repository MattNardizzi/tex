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

Window deltas are a *heuristic* alarm: they fire on a fixed bar and carry no
control over how often you peek. The ``RiskStreamEDetector`` below upgrades
that to an **anytime-valid e-detector** over the same streams: it folds each
decision's verdict (and, when available, each PERMIT's safety label) into a
mixture e-process (``drift/_anytime_valid.py``) and reports a Ville-bounded
``p_anytime_valid`` — so when the false-permit or abstain-rate stream drifts
against its baseline, the alarm's false-positive rate is bounded by ``alpha``
over the whole horizon no matter how often the loop looks. On a breach the
detector emits a **tighten-only** recommendation: a false-permit breach moves
the policy toward caution autonomously; an abstain-rate breach is flagged for
human review (rising abstention is ambiguous, and *loosening must always stay
human-gated*). The detector never emits "loosen" — signals only ever lower a
verdict toward caution.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict
from tex.drift._anytime_valid import AnytimeValidEProcess
from tex.stores.decision_store import InMemoryDecisionStore


DEFAULT_DRIFT_WINDOW_SIZE: int = 50
SIGNIFICANT_RATE_DELTA: float = 0.10
SIGNIFICANT_ABSTAIN_DELTA: float = 0.08

# E-detector defaults. The null hypotheses are "the false-permit rate equals
# its tolerated baseline" and "the abstain rate equals its expected baseline".
DEFAULT_EDETECTOR_ALPHA: float = 0.01
DEFAULT_BASELINE_FALSE_PERMIT_RATE: float = 0.05
DEFAULT_BASELINE_ABSTAIN_RATE: float = 0.20
# An anytime-valid crossing is valid from t=1, but acting on a governance
# change off a couple of points is operationally absurd — a sanity floor.
_EDETECTOR_MIN_OBSERVATIONS: int = 5


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


# ── Anytime-valid e-detector over the risk streams ───────────────────────


class RiskStream(StrEnum):
    """The two streams the e-detector watches."""

    FALSE_PERMIT = "false_permit"  # safety-critical: unsafe among emitted PERMITs
    ABSTAIN_RATE = "abstain_rate"  # governance-load / drift health


class DriftAction(StrEnum):
    """The only actions a breach may recommend. There is no ``loosen``.

    Probabilistic drift evidence can only ever move the policy toward caution;
    loosening is never autonomous (doctrine: loosening stays human-gated).
    """

    NONE = "none"          # below boundary, accumulating
    TIGHTEN = "tighten"    # autonomous-safe: reduce permits / raise scrutiny
    REVIEW = "review"      # human-gated: surface for an operator to judge


@dataclass(frozen=True, slots=True)
class EDriftSignal:
    """One observation's anytime-valid drift verdict for a stream.

    ``p_anytime_valid`` is Ville-bounded: gating intervention on ``p < alpha``
    bounds the false-positive rate by ``alpha`` over the entire horizon, no
    matter how often the loop peeks. ``log_e_value`` is reported in log space
    so a composite certificate can be built by addition (the multiplicative
    e-value spine the truth track composes).
    """

    stream: str
    breached: bool
    p_anytime_valid: float
    log_e_value: float
    dominant_lambda: float
    sample_size: int
    baseline_rate: float
    action: DriftAction
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "stream": self.stream,
            "breached": self.breached,
            "p_anytime_valid": round(self.p_anytime_valid, 9),
            "log_e_value": round(self.log_e_value, 6),
            "dominant_lambda": self.dominant_lambda,
            "sample_size": self.sample_size,
            "baseline_rate": self.baseline_rate,
            "action": self.action.value,
            "reason": self.reason,
        }


def _standardise_indicator(*, indicator: bool, p0: float) -> float:
    """Standardise a Bernoulli indicator against the null rate ``p0``.

    ``x = (1{event} - p0) / sqrt(p0 (1 - p0))``. Under H0 (true rate == p0) the
    indicator has mean p0 and variance p0(1-p0), so ``x`` has ~zero mean and
    unit variance — the input the sub-Gaussian e-process expects. A sustained
    excess pushes the mean positive and drives the e-process up.
    """
    if not 0.0 < p0 < 1.0:
        raise ValueError("baseline rate p0 must be in (0, 1)")
    x = (1.0 if indicator else 0.0) - p0
    return x / math.sqrt(p0 * (1.0 - p0))


class RiskStreamEDetector:
    """Anytime-valid e-detector over Tex's risk streams → tighten-only signal.

    One ``AnytimeValidEProcess`` (drift/_anytime_valid.py) per stream. Feed it
    individual events with :meth:`observe`; it standardises each against the
    stream's baseline null rate and returns an :class:`EDriftSignal`. On a
    crossing (``p < alpha`` past the observation floor) the recommended action
    is:

      * ``TIGHTEN`` for the FALSE_PERMIT stream — too many unsafe permits is a
        one-directional safety failure; tightening (fewer PERMITs) is the
        autonomous-safe response.
      * ``REVIEW`` for the ABSTAIN_RATE stream — a climbing abstain rate is
        ambiguous (genuine drift vs. over-conservatism), so it is surfaced for
        a human rather than acted on; the detector never autonomously loosens.

    This is an OFFLINE detector: it consumes the decision/outcome stream the
    same way the calibrator and OPE evaluator do (a false-permit label exists
    only after Layer-6 outcome validation, not synchronously in the PDP hot
    path). It does not touch ``engine/pdp.py``.

    The detector is read-mostly and stateful only in its e-processes; reset a
    stream after a confirmed regime change to certify the new regime against a
    fresh baseline.
    """

    __slots__ = ("_alpha", "_baselines", "_min_observations", "_eprocesses")

    def __init__(
        self,
        *,
        alpha: float = DEFAULT_EDETECTOR_ALPHA,
        baseline_false_permit_rate: float = DEFAULT_BASELINE_FALSE_PERMIT_RATE,
        baseline_abstain_rate: float = DEFAULT_BASELINE_ABSTAIN_RATE,
        min_observations: int = _EDETECTOR_MIN_OBSERVATIONS,
    ) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        self._alpha = alpha
        self._baselines: dict[str, float] = {
            RiskStream.FALSE_PERMIT.value: baseline_false_permit_rate,
            RiskStream.ABSTAIN_RATE.value: baseline_abstain_rate,
        }
        # Validate baselines eagerly.
        for rate in self._baselines.values():
            if not 0.0 < rate < 1.0:
                raise ValueError("baseline rates must be in (0, 1)")
        self._min_observations = max(1, min_observations)
        self._eprocesses: dict[str, AnytimeValidEProcess] = {
            key: AnytimeValidEProcess() for key in self._baselines
        }

    @property
    def alpha(self) -> float:
        return self._alpha

    def _action_for(self, stream: RiskStream, breached: bool) -> DriftAction:
        if not breached:
            return DriftAction.NONE
        # The only autonomous action is to tighten the safety-critical stream.
        # A climbing abstain rate is surfaced for human judgement — never an
        # autonomous loosen.
        return (
            DriftAction.TIGHTEN
            if stream is RiskStream.FALSE_PERMIT
            else DriftAction.REVIEW
        )

    def observe(self, *, stream: RiskStream, event: bool) -> EDriftSignal:
        """Fold one Bernoulli event into ``stream``'s e-process; report drift.

        ``event`` is the stream's indicator: for FALSE_PERMIT, True iff an
        emitted PERMIT was actually unsafe; for ABSTAIN_RATE, True iff the
        decision was an ABSTAIN.
        """
        key = stream.value
        ep = self._eprocesses[key]
        baseline = self._baselines[key]
        x = _standardise_indicator(indicator=event, p0=baseline)
        cert = ep.observe(standardised_x=x)
        breached = (
            cert.sample_size >= self._min_observations
            and cert.is_significant_at(self._alpha)
        )
        action = self._action_for(stream, breached)
        if breached:
            reason = (
                f"{key} e-process crossed: p_anytime_valid="
                f"{cert.p_anytime_valid:.2e} < alpha={self._alpha} "
                f"(baseline {baseline:.0%}); recommend {action.value}."
            )
        else:
            reason = (
                f"{key} e-process below boundary; accumulating "
                f"({cert.sample_size} obs)."
            )
        return EDriftSignal(
            stream=key,
            breached=breached,
            p_anytime_valid=cert.p_anytime_valid,
            log_e_value=cert.log_e_value,
            dominant_lambda=cert.dominant_lambda,
            sample_size=cert.sample_size,
            baseline_rate=baseline,
            action=action,
            reason=reason,
        )

    def observe_decision(self, decision) -> EDriftSignal:
        """Fold one decision's verdict into the ABSTAIN_RATE stream.

        Connects the e-detector to the same decision stream ``PolicyDriftMonitor``
        windows. Returns the abstain-stream signal. (The false-permit stream is
        fed separately from labelled outcomes via :meth:`observe`, since a
        decision alone carries no ground-truth safety label.)
        """
        is_abstain = decision.verdict is Verdict.ABSTAIN
        return self.observe(stream=RiskStream.ABSTAIN_RATE, event=is_abstain)

    def reset(self, stream: RiskStream) -> None:
        """Restart a stream's e-process (after a confirmed regime change)."""
        self._eprocesses[stream.value].reset()
