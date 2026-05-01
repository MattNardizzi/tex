"""
Outcome trust hierarchy and source classification.

This module formalizes the trust tiers Tex applies to observed outcomes.
The calibrator must NOT treat all outcomes equally: a label written by an
audited ground-truth pipeline is worth more than a label from an anonymous
client SDK. The tiers below are the contract that the validator, the
reputation system, and the calibrator all agree on.

Tiers (lowest → highest):

  REPORTED    — raw input, just persisted. No structural validation has run.
                MUST NOT influence calibration.

  VALIDATED   — passed structural + identity + alignment checks. Eligible
                for calibration with a downweight factor based on reporter
                reputation and recency.

  VERIFIED    — high-confidence ground truth. Examples: human auditor
                signed it, multiple independent reporters agree, replay
                against external system confirmed it. Full weight.

  QUARANTINED — failed validation, was flagged by the poisoning detector,
                or came from a sanctioned reporter. Stored for audit but
                MUST NEVER be counted in calibration.

The progression is monotonic: an outcome can be promoted (REPORTED →
VALIDATED → VERIFIED) but only QUARANTINED is terminal-on-the-down-side.
A VERIFIED outcome that later fails an audit gets a NEW outcome record
with a contradicting label, not a downgrade in place; the original record
stays immutable.
"""

from __future__ import annotations

from enum import StrEnum


class OutcomeTrustLevel(StrEnum):
    """Trust tier the calibrator uses to weight an outcome."""

    REPORTED = "REPORTED"
    VALIDATED = "VALIDATED"
    VERIFIED = "VERIFIED"
    QUARANTINED = "QUARANTINED"

    @property
    def calibration_weight(self) -> float:
        """
        Default per-tier weight applied during calibration.

        Reporter reputation and recency apply on top of this. QUARANTINED
        outcomes always score 0.0 regardless of any other multiplier.
        """
        if self is OutcomeTrustLevel.VERIFIED:
            return 1.0
        if self is OutcomeTrustLevel.VALIDATED:
            return 0.6
        # REPORTED never participates in calibration directly.
        return 0.0

    @property
    def is_calibration_eligible(self) -> bool:
        return self in (OutcomeTrustLevel.VALIDATED, OutcomeTrustLevel.VERIFIED)


class OutcomeSourceType(StrEnum):
    """Where the outcome originated."""

    HUMAN_REVIEWER = "HUMAN_REVIEWER"
    SYSTEM_FEEDBACK = "SYSTEM_FEEDBACK"
    EXTERNAL_AUDIT = "EXTERNAL_AUDIT"
    AUTOMATED_REPLAY = "AUTOMATED_REPLAY"
    THIRD_PARTY = "THIRD_PARTY"
    UNKNOWN = "UNKNOWN"

    @property
    def baseline_trust(self) -> OutcomeTrustLevel:
        """
        Source-type → starting trust tier *before* validation runs.

        Validation can promote VALIDATED to VERIFIED if additional checks
        pass. It can also demote anything to QUARANTINED.
        """
        if self in (
            OutcomeSourceType.EXTERNAL_AUDIT,
            OutcomeSourceType.AUTOMATED_REPLAY,
        ):
            return OutcomeTrustLevel.VERIFIED
        if self in (OutcomeSourceType.HUMAN_REVIEWER, OutcomeSourceType.SYSTEM_FEEDBACK):
            return OutcomeTrustLevel.VALIDATED
        return OutcomeTrustLevel.REPORTED


class VerificationMethod(StrEnum):
    """How an outcome was verified, when verification ran."""

    NONE = "NONE"
    STRUCTURAL = "STRUCTURAL"
    REPORTER_HISTORY = "REPORTER_HISTORY"
    GROUND_TRUTH = "GROUND_TRUTH"
    MULTI_SOURCE_CONSENSUS = "MULTI_SOURCE_CONSENSUS"
    AUDIT_SIGN_OFF = "AUDIT_SIGN_OFF"


__all__ = [
    "OutcomeTrustLevel",
    "OutcomeSourceType",
    "VerificationMethod",
]
