"""
The Abstention Certificate — a structured receipt sealed with every ABSTAIN.

[Architecture: domain model — the typed payload; the builder lives in
``engine/abstention_certificate.py`` because it reads engine artifacts.]

PERMIT stands on a bound and FORBID stands on a proof; ABSTAIN is the only
verdict the operator ever experiences (``hold.py``). The :class:`Hold` already
voices *why* Tex cannot decide and *what one fact* would resolve it. The
abstention certificate is the **audit-facing** companion to that spoken hold:
a single descriptive object, sealed into the ledger alongside the verdict, that
lets a regulator / competitor / adversary running our own code answer three
questions about any ABSTAIN without trusting us:

  1. TRIGGER — which recognizer / contract / floor / gate condition caused the
     abstention, and the signal value that tripped it.

  2. JUSTIFICATION — the risk score and threshold band the pipeline ALREADY
     computed that made abstaining the calibrated choice. It invents no new
     calibration: ``certified`` is True only when the CRC two-sided gate had
     real calibration AND this score fell inside its certified hold band. With
     no field corpus the certificate is honestly ``v1`` / uncalibrated
     (``certified=False``) — the same convention ``crc_gate`` and
     ``verdict_certificate`` use for "real mechanism, not yet field-calibrated".

  3. NON-WEAPONIZATION WITNESS — derived from the verdict-level counterfactual
     the gate already encodes (the permit cutoff / permit region edge): a record
     that the SAME policy + gate configuration WOULD permit a lower-risk,
     legitimate variant of this action. This is the structural evidence that an
     ABSTAIN is a score-specific hold, not a blanket covert deny. When the
     configuration genuinely cannot certify any PERMIT (an enabled-but-
     uncertifiable gate), the witness says so honestly — ``permit_reachable``
     is False — rather than fabricate a reachable permit.

INVARIANTS (the constitution's load limits):
  * **Purely descriptive — never raises a verdict.** The certificate is built
    AFTER the verdict is final, from the finalized artifacts, and is read by no
    runtime decision path. ``descriptive_only`` is structurally pinned True.
  * **Honest calibration.** ``certified`` follows the CRC certificate's
    real-calibration signal; it is never set True from a synthetic threshold.

Maturity: the SEAL is real (live ECDSA-P256 + hash chain — authorship +
integrity); the certificate's *content* is descriptive and, until a field
corpus calibrates the band, ``research-early`` / uncalibrated by its own flag.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict

__all__ = [
    "AbstentionTrigger",
    "AbstentionJustification",
    "NonWeaponizationWitness",
    "AbstentionCertificate",
    "ABSTENTION_CERTIFICATE_VERSION",
]

# The schema version. Bumped only when the field shape changes; the honest
# "uncalibrated until a field corpus exists" posture is a property of
# ``certified``, not of the version.
ABSTENTION_CERTIFICATE_VERSION = "v1"


class AbstentionTrigger(BaseModel):
    """Part 1 — what caused the abstention, and the signal value that tripped it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(
        description=(
            "The condition class that produced the ABSTAIN: a named uncertainty "
            "flag (e.g. 'crc_permit_region_exceeded', 'no_retrieval_context'), "
            "or 'selective_risk_band' when the fused score simply fell in the "
            "mid-band with no more specific flag. Names a real, in-code cause."
        )
    )
    signal_name: str = Field(
        description=(
            "The specific signal the trigger reads — the pivotal uncertainty "
            "flag when one is present, else 'fused_score'."
        )
    )
    signal_value: float = Field(
        description=(
            "The numeric value of the tripping signal: the fused final risk "
            "score in [0, 1] that the pipeline computed and that lands inside "
            "the abstention band. This is the scalar the verdict region is read "
            "from, not a re-derived quantity."
        )
    )
    uncertainty_flags: tuple[str, ...] = Field(
        default=(),
        description="Every uncertainty flag the routed result carried, for audit.",
    )
    detail: str = Field(
        default="",
        description="One-line human-readable statement of the triggering condition.",
    )


class AbstentionJustification(BaseModel):
    """Part 2 — why abstaining was the calibrated choice, in the pipeline's own
    score and thresholds. Invents no calibration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="The fused final risk score this verdict was read from.",
    )
    band_lower: float = Field(
        description=(
            "Lower edge of the abstention band — the permit-side cutoff. The "
            "CRC certified permit cutoff (lambda_hat) when the band is "
            "certified, else the policy permit_threshold the router used."
        )
    )
    band_upper: float = Field(
        description=(
            "Upper edge of the abstention band — the forbid-side cutoff. The "
            "CRC certified forbid cutoff (lambda_forbid) when certified, else "
            "the policy forbid_threshold."
        )
    )
    band_certified: bool = Field(
        description=(
            "Whether the band carries a finite-sample CRC guarantee: True only "
            "when the two-sided gate had real calibration AND this score fell "
            "strictly inside its certified hold band. False when the gate is "
            "inert/uncalibrated — the band is still the real decision boundary, "
            "it just carries no live coverage statement yet."
        )
    )
    calibration: Literal["certified", "uncalibrated"] = Field(
        description=(
            "Honest calibration status. 'certified' only when band_certified; "
            "otherwise 'uncalibrated' — the existing certified=false convention."
        )
    )
    certified_false_permit_rate: float | None = Field(
        default=None,
        description=(
            "When certified: the CRC upper bound on how often a PERMIT would "
            "leak a genuinely-unsafe action. None when uncalibrated."
        ),
    )
    certified_false_forbid_rate: float | None = Field(
        default=None,
        description=(
            "When certified: the CRC upper bound on how often a FORBID would "
            "block a genuinely-safe action. None when uncalibrated."
        ),
    )
    rationale: str = Field(
        description=(
            "Plain-English statement of why the score in this band resolves to "
            "ABSTAIN rather than PERMIT or FORBID."
        )
    )


class NonWeaponizationWitness(BaseModel):
    """Part 3 — evidence that the SAME configuration would PERMIT a legitimate
    (lower-risk) variant: the abstain is not a blanket covert deny."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    permit_reachable: bool = Field(
        description=(
            "Whether the PERMIT region in score-space is non-empty under THIS "
            "exact policy + gate configuration. True is the non-weaponization "
            "evidence: a lower-risk variant of this action would be permitted. "
            "False is the honest disclosure that the configuration currently "
            "certifies no PERMIT at all (an enabled-but-uncertifiable gate — "
            "fail-closed, calibration needed); the certificate never fabricates "
            "a reachable permit it cannot stand behind."
        )
    )
    permit_score_ceiling: float = Field(
        description=(
            "The highest fused risk score that would still PERMIT under this "
            "exact configuration — the permit region's upper edge. The CRC "
            "certified permit cutoff when certified, else the policy "
            "permit_threshold. -1.0 means no score is permit-certifiable "
            "(permit_reachable is False)."
        )
    )
    counterfactual_delta: float = Field(
        description=(
            "How far this action's risk score sits above the permit ceiling "
            "(risk_score - permit_score_ceiling). A positive value is the gap a "
            "legitimate variant would need to close to be permitted under the "
            "same configuration; it quantifies that the hold is specific to "
            "this action's risk, not categorical."
        )
    )
    source: str = Field(
        description=(
            "Which existing verdict-level counterfactual the witness derives "
            "from: 'crc_certified_permit_cutoff', 'policy_permit_threshold', or "
            "'crc_uncertifiable_fail_closed'."
        )
    )
    counterfactual: str = Field(
        description="Plain-English statement of the permitting counterfactual.",
    )


class AbstentionCertificate(BaseModel):
    """The sealed, descriptive receipt for one ABSTAIN verdict.

    Emitted with every ABSTAIN and only with ABSTAIN. Read by no runtime
    decision path — ``descriptive_only`` is structurally pinned True.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal["v1"] = Field(
        default=ABSTENTION_CERTIFICATE_VERSION,
        description="Schema version. Calibration honesty lives in `certified`, not here.",
    )
    verdict: Literal[Verdict.ABSTAIN] = Field(
        default=Verdict.ABSTAIN,
        description="Always ABSTAIN — the certificate exists for no other verdict.",
    )
    certified: bool = Field(
        description=(
            "Whether the JUSTIFICATION band carries a real finite-sample "
            "calibration (== justification.band_certified). False — the honest "
            "default — until a field corpus calibrates the CRC gate, matching "
            "the codebase-wide certified=false convention for "
            "real-but-uncalibrated mechanisms."
        )
    )
    descriptive_only: Literal[True] = Field(
        default=True,
        description=(
            "Structurally pinned True: the certificate is evidence ABOUT the "
            "verdict, never an input to it. It cannot raise a verdict toward "
            "PERMIT or lower it toward FORBID."
        ),
    )

    trigger: AbstentionTrigger
    justification: AbstentionJustification
    witness: NonWeaponizationWitness
