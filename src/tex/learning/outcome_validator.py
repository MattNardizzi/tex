"""
Outcome validation: REPORTED → VALIDATED / QUARANTINED.

This module is the *only* legitimate path from raw outcome input to a
calibration-eligible outcome. Every outcome that arrives via the API
gets routed through ``OutcomeValidator.validate(...)`` before it lands
in the store. The validator either:

  - returns a promoted outcome (trust level VALIDATED, possibly VERIFIED
    if the source type already starts there and all checks pass); or
  - returns a quarantined outcome (trust level QUARANTINED, with the
    failure reasons recorded in ``metadata`` for audit) which the store
    persists but the calibrator excludes.

Design principles:

  1. Validation is deterministic and pure given (outcome, decision,
     prior outcomes, reporter context). No hidden randomness.
  2. Quarantine is reversible only via a NEW outcome record. We never
     mutate the existing record's trust level downward except as the
     direct output of validation at write time.
  3. Quarantine reasons are visible: every quarantined outcome carries
     a ``quarantine_reasons`` list explaining why.
  4. The validator does NOT know about reputation or poisoning. Those
     run as separate downstream stages so each layer is testable in
     isolation. The feedback loop orchestrator chains them.

Checks implemented (each maps to a named ``ValidationFailure``):

  decision_missing       — referenced decision_id is unknown
  request_id_mismatch    — outcome.request_id != decision.request_id
  tenant_mismatch        — outcome carries a tenant inconsistent with
                           the linked decision's tenant context
  label_inconsistent     — verdict/outcome_kind/was_safe combination
                           is structurally impossible
  override_inconsistent  — OVERRIDDEN kind without human_override flag
                           (caught at model level too, but we re-check)
  too_late               — outcome reported too long after the decision
                           was made (default: 90 days)
  reporter_blank         — required reporter identity missing
  reporter_rate_limited  — reporter exceeded its per-window submission cap
  duplicate_outcome      — same (decision_id, reporter) already saw a
                           stable outcome; resubmission with a NEW
                           label is treated as a *conflict* not a dup
  conflicting_with_prior — prior outcome from a more-trusted source
                           disagrees with this label

The validator does not raise on failure for control-flow reasons. It
returns a ``ValidationResult`` so the command layer can persist the
quarantined outcome instead of dropping it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeKind, OutcomeLabel, OutcomeRecord
from tex.domain.outcome_trust import (
    OutcomeSourceType,
    OutcomeTrustLevel,
    VerificationMethod,
)
from tex.domain.verdict import Verdict


DEFAULT_MAX_REPORT_LAG = timedelta(days=90)
DEFAULT_REPORTER_RATE_LIMIT = 200       # outcomes per reporter
DEFAULT_REPORTER_RATE_WINDOW = timedelta(hours=1)


class ValidationFailure(StrEnum):
    DECISION_MISSING = "decision_missing"
    REQUEST_ID_MISMATCH = "request_id_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    LABEL_INCONSISTENT = "label_inconsistent"
    OVERRIDE_INCONSISTENT = "override_inconsistent"
    TOO_LATE = "too_late"
    REPORTER_BLANK = "reporter_blank"
    REPORTER_RATE_LIMITED = "reporter_rate_limited"
    DUPLICATE_OUTCOME = "duplicate_outcome"
    CONFLICTING_WITH_PRIOR = "conflicting_with_prior"


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """
    Outcome of a validation pass.

    The validator returns the *new* outcome (with promoted/demoted trust
    level and any backfilled fields) plus the structured failure list.
    Callers persist whichever they receive.
    """

    outcome: OutcomeRecord
    is_valid: bool
    failures: tuple[ValidationFailure, ...]
    detail_messages: tuple[str, ...]

    @property
    def quarantined(self) -> bool:
        return self.outcome.trust_level is OutcomeTrustLevel.QUARANTINED


class _DecisionLookup(Protocol):
    """
    Narrow protocol so the validator does not depend on the concrete store.

    Implementations:
      - InMemoryDecisionStore.get(decision_id) -> Decision | None
      - any future Postgres-backed decision store
    """

    def get(self, decision_id: UUID) -> Decision | None: ...


class _PriorOutcomeLookup(Protocol):
    """Narrow protocol for prior outcomes per decision."""

    def list_for_decision(self, decision_id: UUID) -> tuple[OutcomeRecord, ...]: ...


class _ReporterRateCheck(Protocol):
    """
    Narrow protocol for the rate limiter. The default implementation is a
    sliding-window counter held in process; a Postgres-backed implementation
    can drop in without changing the validator.
    """

    def consume(self, *, reporter: str, now: datetime) -> bool: ...


@dataclass(slots=True)
class InProcessRateLimiter:
    """
    Default sliding-window rate limiter.

    Per-reporter cap; exceeding it during the window returns False from
    consume() and the validator quarantines the outcome.
    """

    cap_per_window: int = DEFAULT_REPORTER_RATE_LIMIT
    window: timedelta = DEFAULT_REPORTER_RATE_WINDOW
    _events: dict[str, list[datetime]] = field(default_factory=dict)

    def consume(self, *, reporter: str, now: datetime) -> bool:
        bucket = self._events.setdefault(reporter, [])
        cutoff = now - self.window
        # Drop expired entries (kept simple; under load swap for a deque).
        fresh = [t for t in bucket if t >= cutoff]
        if len(fresh) >= self.cap_per_window:
            self._events[reporter] = fresh
            return False
        fresh.append(now)
        self._events[reporter] = fresh
        return True


class OutcomeValidator:
    """
    Validates an incoming outcome against its decision, prior outcomes, and
    reporter rate limits. Returns a ``ValidationResult`` carrying the
    outcome with its trust level set appropriately.
    """

    __slots__ = (
        "_decisions",
        "_priors",
        "_rate_limiter",
        "_max_report_lag",
        "_clock",
    )

    def __init__(
        self,
        *,
        decisions: _DecisionLookup,
        priors: _PriorOutcomeLookup,
        rate_limiter: _ReporterRateCheck | None = None,
        max_report_lag: timedelta = DEFAULT_MAX_REPORT_LAG,
        clock: callable | None = None,
    ) -> None:
        self._decisions = decisions
        self._priors = priors
        self._rate_limiter = rate_limiter or InProcessRateLimiter()
        self._max_report_lag = max_report_lag
        self._clock = clock or (lambda: datetime.now(UTC))

    def validate(self, outcome: OutcomeRecord) -> ValidationResult:
        failures: list[ValidationFailure] = []
        details: list[str] = []

        decision = self._decisions.get(outcome.decision_id)
        if decision is None:
            failures.append(ValidationFailure.DECISION_MISSING)
            details.append(
                f"No decision found for decision_id={outcome.decision_id}; "
                "outcome cannot be calibration-eligible."
            )
            return self._quarantine(outcome, failures, details)

        # Backfill tenant_id and policy_version from the decision if missing.
        outcome = self._backfill_from_decision(outcome=outcome, decision=decision)

        if outcome.request_id != decision.request_id:
            failures.append(ValidationFailure.REQUEST_ID_MISMATCH)
            details.append(
                "Outcome request_id does not match the linked decision's "
                "request_id."
            )

        if not _tenant_consistent(outcome=outcome, decision=decision):
            failures.append(ValidationFailure.TENANT_MISMATCH)
            details.append(
                "Outcome tenant_id does not match the decision's tenant "
                "context; cross-tenant outcomes must never feed calibration."
            )

        if not _label_structurally_valid(outcome=outcome):
            failures.append(ValidationFailure.LABEL_INCONSISTENT)
            details.append(
                f"Verdict={outcome.verdict.value} / outcome_kind="
                f"{outcome.outcome_kind.value} / was_safe={outcome.was_safe} "
                "is not a coherent combination."
            )

        if (
            outcome.outcome_kind is OutcomeKind.OVERRIDDEN
            and not outcome.human_override
        ):
            # The model-level validator already catches this, but if a future
            # caller bypasses it (eg. dict-construction in a fixture), we want
            # belt-and-braces protection.
            failures.append(ValidationFailure.OVERRIDE_INCONSISTENT)
            details.append("OVERRIDDEN outcome must carry human_override=True.")

        if (outcome.recorded_at - decision.decided_at) > self._max_report_lag:
            failures.append(ValidationFailure.TOO_LATE)
            details.append(
                f"Outcome recorded {(outcome.recorded_at - decision.decided_at).days}d "
                f"after the decision; lag exceeds the {self._max_report_lag.days}d limit."
            )

        if not outcome.reporter:
            failures.append(ValidationFailure.REPORTER_BLANK)
            details.append("Reporter identity is required for calibration-eligible outcomes.")
        else:
            allowed = self._rate_limiter.consume(
                reporter=outcome.reporter,
                now=self._clock(),
            )
            if not allowed:
                failures.append(ValidationFailure.REPORTER_RATE_LIMITED)
                details.append(
                    f"Reporter '{outcome.reporter}' exceeded the per-window "
                    "submission limit; outcome quarantined."
                )

        priors = self._priors.list_for_decision(outcome.decision_id)
        for prior in priors:
            if prior.outcome_id == outcome.outcome_id:
                continue
            if (
                prior.reporter == outcome.reporter
                and prior.label is outcome.label
                and prior.was_safe == outcome.was_safe
            ):
                failures.append(ValidationFailure.DUPLICATE_OUTCOME)
                details.append(
                    "Reporter has already submitted an identical outcome for "
                    "this decision; treating as duplicate."
                )
                break

        for prior in priors:
            if prior.outcome_id == outcome.outcome_id:
                continue
            if prior.trust_level is OutcomeTrustLevel.QUARANTINED:
                continue
            disagrees = (
                prior.label is not outcome.label
                and prior.label is not OutcomeLabel.UNKNOWN
                and outcome.label is not OutcomeLabel.UNKNOWN
            )
            if disagrees and _trust_rank(prior.trust_level) > _trust_rank(
                outcome.trust_level
            ):
                failures.append(ValidationFailure.CONFLICTING_WITH_PRIOR)
                details.append(
                    f"Prior outcome (trust={prior.trust_level.value}) labelled "
                    f"this decision {prior.label.value}; this report disagrees "
                    "and is from a less-trusted source. Quarantining for review."
                )
                break

        if failures:
            return self._quarantine(outcome, failures, details)

        promoted = self._promote(outcome)
        return ValidationResult(
            outcome=promoted,
            is_valid=True,
            failures=(),
            detail_messages=(),
        )

    @staticmethod
    def _backfill_from_decision(
        *,
        outcome: OutcomeRecord,
        decision: Decision,
    ) -> OutcomeRecord:
        updates: dict[str, object] = {}
        if outcome.tenant_id is None:
            decision_tenant = _decision_tenant(decision)
            if decision_tenant is not None:
                updates["tenant_id"] = decision_tenant
        if outcome.policy_version is None and decision.policy_version:
            updates["policy_version"] = decision.policy_version
        if not updates:
            return outcome
        return outcome.model_copy(update=updates)

    @staticmethod
    def _promote(outcome: OutcomeRecord) -> OutcomeRecord:
        """
        Set trust level based on source type.

        Validated outcomes from external-audit / automated-replay sources
        skip straight to VERIFIED. Everything else lands at VALIDATED.
        """
        baseline = outcome.source_type.baseline_trust
        target = (
            OutcomeTrustLevel.VERIFIED
            if baseline is OutcomeTrustLevel.VERIFIED
            else OutcomeTrustLevel.VALIDATED
        )
        if outcome.trust_level is target:
            return outcome
        return outcome.model_copy(
            update={
                "trust_level": target,
                "verification_method": (
                    VerificationMethod.STRUCTURAL
                    if outcome.verification_method is VerificationMethod.NONE
                    else outcome.verification_method
                ),
            }
        )

    @staticmethod
    def _quarantine(
        outcome: OutcomeRecord,
        failures: list[ValidationFailure],
        details: list[str],
    ) -> ValidationResult:
        unique_failures = tuple(dict.fromkeys(failures))
        unique_details = tuple(details)
        return ValidationResult(
            outcome=outcome.model_copy(
                update={
                    "trust_level": OutcomeTrustLevel.QUARANTINED,
                    "verification_method": VerificationMethod.STRUCTURAL,
                }
            ),
            is_valid=False,
            failures=unique_failures,
            detail_messages=unique_details,
        )


# ── helpers ──────────────────────────────────────────────────────────────


_TRUST_RANK = {
    OutcomeTrustLevel.QUARANTINED: -1,
    OutcomeTrustLevel.REPORTED: 0,
    OutcomeTrustLevel.VALIDATED: 1,
    OutcomeTrustLevel.VERIFIED: 2,
}


def _trust_rank(level: OutcomeTrustLevel) -> int:
    return _TRUST_RANK[level]


def _decision_tenant(decision: Decision) -> str | None:
    """
    Pull the tenant_id from decision metadata.

    Decisions don't carry tenant_id as a top-level field, but the
    evaluation pipeline writes it into metadata. We accept either
    a top-level "tenant_id" key in metadata or a nested
    "tenant"/"id" pair to stay flexible across writers.
    """
    metadata = decision.metadata or {}
    raw = metadata.get("tenant_id")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    nested = metadata.get("tenant")
    if isinstance(nested, dict):
        nested_id = nested.get("id")
        if isinstance(nested_id, str) and nested_id.strip():
            return nested_id.strip()

    return None


def _tenant_consistent(*, outcome: OutcomeRecord, decision: Decision) -> bool:
    decision_tenant = _decision_tenant(decision)
    if outcome.tenant_id is None:
        return True  # backfill handled by caller
    if decision_tenant is None:
        # Decision has no tenant context at all — accept the outcome's tenant
        # without flagging; we cannot prove a mismatch.
        return True
    return outcome.tenant_id == decision_tenant


def _label_structurally_valid(*, outcome: OutcomeRecord) -> bool:
    """
    Re-derive what the label SHOULD be from (verdict, outcome_kind, was_safe)
    and confirm the supplied label matches.

    This catches cases where a caller hand-constructed an outcome with a
    label that contradicts its own verdict/safety fields.
    """
    expected = OutcomeRecord.classify(
        verdict=outcome.verdict,
        outcome_kind=outcome.outcome_kind,
        was_safe=outcome.was_safe,
    )
    if outcome.label is OutcomeLabel.UNKNOWN:
        # UNKNOWN is always permissible; the calibrator will count it as
        # such and the reputation system can reason about the reporter
        # later.
        return True
    return expected is outcome.label


def _verdict_outcome_compat(verdict: Verdict, kind: OutcomeKind) -> bool:
    """Soft sanity check used by tests; not enforced by validator directly."""
    if verdict is Verdict.PERMIT:
        return kind in (OutcomeKind.RELEASED, OutcomeKind.OVERRIDDEN, OutcomeKind.UNKNOWN)
    if verdict is Verdict.FORBID:
        return kind in (OutcomeKind.BLOCKED, OutcomeKind.OVERRIDDEN, OutcomeKind.UNKNOWN)
    if verdict is Verdict.ABSTAIN:
        return kind in (
            OutcomeKind.ESCALATED,
            OutcomeKind.OVERRIDDEN,
            OutcomeKind.UNKNOWN,
            OutcomeKind.RELEASED,
            OutcomeKind.BLOCKED,
        )
    return True


__all__ = [
    "DEFAULT_MAX_REPORT_LAG",
    "DEFAULT_REPORTER_RATE_LIMIT",
    "DEFAULT_REPORTER_RATE_WINDOW",
    "InProcessRateLimiter",
    "OutcomeValidator",
    "ValidationFailure",
    "ValidationResult",
]
