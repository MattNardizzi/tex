"""
Replay-based validation for calibration proposals.

Before a calibration proposal is approved, we replay historical decisions
through the proposed thresholds and report what would have changed:

  - decisions that would flip PERMIT → FORBID  ("new_forbids")
  - decisions that would flip FORBID → PERMIT  ("new_permits")
  - decisions that would flip into ABSTAIN     ("new_abstains")
  - decisions that would flip out of ABSTAIN   ("resolved_abstains")
  - PERMITs that would have been blocked       ("would_have_blocked_safe")
  - FORBIDs that would have been released      ("would_have_released_unsafe")

The last two come from labelled outcomes: when a historical decision has
a VERIFIED or VALIDATED outcome attached, we know the ground-truth label
and can score the proposal against it.

Replay never mutates anything. It produces a ``ReplayReport`` that the
proposal store carries alongside the recommendation so the human approver
sees both the threshold change and its consequences.

Re-derivation rule:

  We use ``final_score`` and ``confidence`` from the original Decision
  record together with the new thresholds to re-derive the verdict the
  same way the PDP would. This is faithful for any decision the PDP
  made through normal scoring; for hard-blocks (deterministic gate fires),
  ``final_score`` is already saturated and the verdict survives any
  threshold change. We surface the count of "untouched-because-hard-block"
  separately so it's clear those decisions are unaffected.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.learning.calibrator import CalibrationRecommendation


@dataclass(frozen=True, slots=True)
class ReplayCount:
    permit: int
    abstain: int
    forbid: int

    @property
    def total(self) -> int:
        return self.permit + self.abstain + self.forbid


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """
    Result of replaying decisions through proposed thresholds.

    Counts cover only decisions where the verdict would change. Decisions
    whose verdict would be the same under both old and new thresholds are
    left out of the diff counts but contribute to ``total_replayed``.
    """

    total_replayed: int
    hard_blocked_unchanged: int

    original_distribution: ReplayCount
    proposed_distribution: ReplayCount

    new_permits: int
    new_abstains: int
    new_forbids: int
    resolved_abstains: int

    would_have_blocked_safe: int
    would_have_released_unsafe: int

    labelled_decisions: int
    new_false_permit_rate: float | None
    new_false_forbid_rate: float | None

    risky_change: bool

    @property
    def materially_different(self) -> bool:
        return (
            self.new_permits
            + self.new_abstains
            + self.new_forbids
            + self.resolved_abstains
        ) > 0


class ReplayValidator:
    """
    Replays decisions through proposed thresholds.

    The validator is stateless. Inputs are passed in directly so callers
    can scope the replay window however they like (last-N decisions,
    last-7-days, only this tenant, etc).
    """

    __slots__ = ("_risky_flip_threshold",)

    def __init__(self, *, risky_flip_threshold: float = 0.10) -> None:
        if not 0.0 < risky_flip_threshold <= 1.0:
            raise ValueError("risky_flip_threshold must be in (0.0, 1.0]")
        self._risky_flip_threshold = risky_flip_threshold

    def replay(
        self,
        *,
        decisions: Iterable[Decision],
        outcomes: Iterable[OutcomeRecord],
        policy: PolicySnapshot,
        recommendation: CalibrationRecommendation,
    ) -> ReplayReport:
        decisions_tuple = tuple(decisions)
        outcomes_by_decision: dict = {}
        for o in outcomes:
            if o.trust_level not in (
                OutcomeTrustLevel.VALIDATED,
                OutcomeTrustLevel.VERIFIED,
            ):
                continue
            outcomes_by_decision.setdefault(o.decision_id, []).append(o)

        original_permit = original_abstain = original_forbid = 0
        proposed_permit = proposed_abstain = proposed_forbid = 0

        new_permits = 0
        new_abstains = 0
        new_forbids = 0
        resolved_abstains = 0

        would_have_blocked_safe = 0
        would_have_released_unsafe = 0
        labelled = 0
        false_permits_after = 0
        false_forbids_after = 0
        new_permits_or_kept_permits_with_label = 0
        new_forbids_or_kept_forbids_with_label = 0

        hard_blocked_unchanged = 0

        new_permit = recommendation.recommended_permit_threshold
        new_forbid = recommendation.recommended_forbid_threshold
        new_min_conf = recommendation.recommended_minimum_confidence

        for decision in decisions_tuple:
            original_v = decision.verdict
            if original_v is Verdict.PERMIT:
                original_permit += 1
            elif original_v is Verdict.ABSTAIN:
                original_abstain += 1
            else:
                original_forbid += 1

            replayed_v = _rederive_verdict(
                decision=decision,
                permit_threshold=new_permit,
                forbid_threshold=new_forbid,
                minimum_confidence=new_min_conf,
            )
            if replayed_v is Verdict.PERMIT:
                proposed_permit += 1
            elif replayed_v is Verdict.ABSTAIN:
                proposed_abstain += 1
            else:
                proposed_forbid += 1

            # Hard-block detection: deterministic gate fires saturate
            # final_score to 1.0 with confidence 1.0; those won't move.
            if decision.final_score >= 0.999 and decision.confidence >= 0.999:
                hard_blocked_unchanged += 1

            if replayed_v is original_v:
                # Label-based scoring even when verdict didn't change so we
                # report the new false-permit and false-forbid rates correctly.
                attached = outcomes_by_decision.get(decision.decision_id, [])
                for o in attached:
                    if o.was_safe is None:
                        continue
                    labelled += 1
                    if replayed_v is Verdict.PERMIT:
                        new_permits_or_kept_permits_with_label += 1
                        if not o.was_safe:
                            false_permits_after += 1
                    elif replayed_v is Verdict.FORBID:
                        new_forbids_or_kept_forbids_with_label += 1
                        if o.was_safe:
                            false_forbids_after += 1
                continue

            # Verdict changed under proposed thresholds.
            if replayed_v is Verdict.PERMIT:
                new_permits += 1
                if original_v is Verdict.ABSTAIN:
                    resolved_abstains += 1
            elif replayed_v is Verdict.ABSTAIN:
                new_abstains += 1
            else:
                new_forbids += 1
                if original_v is Verdict.ABSTAIN:
                    resolved_abstains += 1

            # Labelled-decision impact on safety.
            attached = outcomes_by_decision.get(decision.decision_id, [])
            for o in attached:
                if o.was_safe is None:
                    continue
                labelled += 1
                if (
                    replayed_v is Verdict.FORBID
                    and original_v is Verdict.PERMIT
                    and o.was_safe is True
                ):
                    would_have_blocked_safe += 1
                if (
                    replayed_v is Verdict.PERMIT
                    and original_v is Verdict.FORBID
                    and o.was_safe is False
                ):
                    would_have_released_unsafe += 1
                if replayed_v is Verdict.PERMIT:
                    new_permits_or_kept_permits_with_label += 1
                    if not o.was_safe:
                        false_permits_after += 1
                elif replayed_v is Verdict.FORBID:
                    new_forbids_or_kept_forbids_with_label += 1
                    if o.was_safe:
                        false_forbids_after += 1

        new_fp_rate: float | None = None
        if new_permits_or_kept_permits_with_label > 0:
            new_fp_rate = round(
                false_permits_after / new_permits_or_kept_permits_with_label, 4
            )
        new_ff_rate: float | None = None
        if new_forbids_or_kept_forbids_with_label > 0:
            new_ff_rate = round(
                false_forbids_after / new_forbids_or_kept_forbids_with_label, 4
            )

        total = len(decisions_tuple)
        flips = new_permits + new_abstains + new_forbids
        risky = total > 0 and (flips / total) > self._risky_flip_threshold

        return ReplayReport(
            total_replayed=total,
            hard_blocked_unchanged=hard_blocked_unchanged,
            original_distribution=ReplayCount(
                permit=original_permit,
                abstain=original_abstain,
                forbid=original_forbid,
            ),
            proposed_distribution=ReplayCount(
                permit=proposed_permit,
                abstain=proposed_abstain,
                forbid=proposed_forbid,
            ),
            new_permits=new_permits,
            new_abstains=new_abstains,
            new_forbids=new_forbids,
            resolved_abstains=resolved_abstains,
            would_have_blocked_safe=would_have_blocked_safe,
            would_have_released_unsafe=would_have_released_unsafe,
            labelled_decisions=labelled,
            new_false_permit_rate=new_fp_rate,
            new_false_forbid_rate=new_ff_rate,
            risky_change=risky,
        )


def _rederive_verdict(
    *,
    decision: Decision,
    permit_threshold: float,
    forbid_threshold: float,
    minimum_confidence: float,
) -> Verdict:
    """
    Re-derive the verdict from final_score + confidence under new thresholds.

    Mirrors the PDP's threshold logic:
      score >= forbid_threshold                     -> FORBID
      score <= permit_threshold AND
        confidence >= minimum_confidence            -> PERMIT
      otherwise                                     -> ABSTAIN
    """
    score = decision.final_score
    confidence = decision.confidence
    if score >= forbid_threshold:
        return Verdict.FORBID
    if score <= permit_threshold and confidence >= minimum_confidence:
        return Verdict.PERMIT
    return Verdict.ABSTAIN


__all__ = ["ReplayCount", "ReplayReport", "ReplayValidator"]
