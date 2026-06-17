"""
The Abstention Certificate — a sealed, structured *receipt* for every ABSTAIN.

[Architecture: Engine evidence layer — evidence ABOUT the verdict, never an input to it]

A PERMIT keeps the glass clean; a FORBID blocks in silence; an ABSTAIN is the
only verdict the operator ever experiences (``hold.py``). The :class:`Hold`
already gives that abstention a *spoken* surface (type + the one resolving
fact). This module gives it an *auditable* surface: a typed, three-part
certificate an auditor, a regulator, or a competitor's engineer can read to
answer three distinct questions about a single ABSTAIN —

  1. **TRIGGER** — *what* raised the hold. Which recognizer / contract / floor
     condition fired, and the fused signal value it fired at. Distilled from the
     uncertainty flags the pipeline already raised and the ``Hold``'s pivotal
     flag — never re-derived, so it cannot disagree with the verdict.

  2. **JUSTIFICATION** — *why abstaining was the calibrated choice*. The fused
     risk score against the operative band [permit_cutoff, forbid_cutoff). When
     a two-sided CRC certificate is live (``crc_gate.py``) the band carries a
     finite-sample guarantee and the certificate says so; with no calibration
     the band is the hand-tuned policy thresholds and the certificate is marked
     ``certified=False`` / ``calibration_status="uncalibrated"`` — the same
     ``certified=false`` convention ``verdict_certificate.py`` / ``crc_gate.py``
     use. We never invent calibration: no field corpus → no guarantee claimed.

  3. **NON-WEAPONIZATION WITNESS** — *evidence the ABSTAIN is not a blanket
     covert deny*. Under R4 (``router._determine_verdict``) a PERMIT is reachable
     for any action whose fused risk is ``<= permit_cutoff``: the PERMIT region
     is non-empty under this exact policy+gate. The witness records that
     boundary, this action's distance from it, and the dominant lever (the
     existing ASI counterfactual signal). It is an *existence/reachability*
     statement about the configuration — it does NOT assert any particular
     rendered string is benign, nor that moving the named lever alone crosses
     the boundary. Overclaiming either would be the ``nanozk`` lesson repeated.

Hard contracts (the four non-negotiables):
  * **Descriptive only — never raises a verdict.** Built *after* the verdict is
    final, from a finalized ``Hold``. ``descriptive_only`` is pinned ``True``.
    Returns ``None`` for any non-ABSTAIN verdict, so PERMIT/FORBID are untouched.
  * **Pure & deterministic.** No I/O, no clocks, no randomness — a fixed function
    of (hold, certificate, thresholds, flags, reasons, ASI findings). The PDP
    determinism fingerprint is preserved; the same request yields the same
    certificate byte-for-byte.
  * **Honest maturity.** The certificate is ``abstention-certificate/v1``. Its
    JUSTIFICATION is calibrated only when a two-sided CRC certificate backs the
    band; otherwise it is explicitly uncalibrated.

Maturity: the *mechanism* (deterministic distillation + sealing) is production;
the *calibration* of the band is RUNTIME-DEPENDENT (inert until an operator
supplies a CRC calibration set), which the certificate reports rather than hides.
"""

from __future__ import annotations

from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.asi_finding import ASIFinding
from tex.domain.verdict import Verdict
from tex.engine.crc_gate import CRCCertificate
from tex.engine.hold import Hold

__all__ = [
    "AbstentionTrigger",
    "AbstentionJustification",
    "NonWeaponizationWitness",
    "AbstentionCertificate",
    "build_abstention_certificate",
]

SCHEMA_VERSION = "abstention-certificate/v1"


# Coarse provenance for the most-salient ABSTAIN trigger. Keyed off the flag a
# deterministic in-repo path actually emits (the same flags ``hold._FLAG_PIVOTS``
# is keyed on) so a category never names a signal no emitter can raise.
_FLAG_CATEGORY: dict[str, str] = {
    "crc_permit_region_exceeded": "crc_gate_demotion",
    "no_retrieval_context": "retrieval_grounding",
    "cold_start": "agent_behavioral_baseline",
    "forbid_streak": "agent_behavioral_baseline",
    "agent_pending": "agent_lifecycle",
    "weak_semantic_evidence": "semantic_evidence",
    "low_confidence_semantic_dimension": "semantic_ambiguity",
    "systemic_lookahead_risk": "predictive_lookahead",
    "rv4_recoverable_violation": "path_policy",
}

# Substrings of router ``reasons`` that name a soft-signal source when no flag is
# more specific. Order is precedence (most specific first).
_REASON_CATEGORY: tuple[tuple[str, str], ...] = (
    ("behavioral contract", "behavioral_contract"),
    ("path policy", "path_policy"),
    ("pq", "pq_durability"),
    ("crc gate", "crc_gate_demotion"),
    ("e-value", "risk_spine"),
)


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _round(x: float) -> float:
    return round(x, 6)


def _classify_trigger(
    *,
    pivotal_flag: str | None,
    uncertainty_flags: Sequence[str],
    reasons: Sequence[str],
) -> tuple[str, str]:
    """Return (condition, category) — the single most-salient ABSTAIN trigger.

    Distillation, not re-derivation: the condition is whichever uncertainty
    signal the pipeline already surfaced (the ``Hold``'s pivotal flag first,
    then any raised flag), falling back to the score-band relation. The category
    is a coarse provenance label for that condition.
    """
    flags_cf = [f.casefold() for f in uncertainty_flags]

    condition: str
    if pivotal_flag:
        condition = pivotal_flag
    elif flags_cf:
        # Prefer a flag we have a category for; else the first raised flag.
        condition = next((f for f in flags_cf if f in _FLAG_CATEGORY), flags_cf[0])
    else:
        condition = "fused_score_within_hold_band"

    category = _FLAG_CATEGORY.get(condition.casefold())
    if category is None:
        reasons_cf = " || ".join(r.casefold() for r in reasons)
        category = next(
            (cat for needle, cat in _REASON_CATEGORY if needle in reasons_cf),
            "router_uncertainty",
        )
    return condition, category


def _dominant_lever(asi_findings: Sequence[ASIFinding]) -> str | None:
    """The highest-severity ASI trigger signal — the existing counterfactual
    lever a lower-risk variant would lack. ``None`` when no ASI finding fired."""
    if not asi_findings:
        return None
    top_finding = max(asi_findings, key=lambda f: f.severity)
    if not top_finding.triggered_by:
        return top_finding.short_code
    top_trigger = max(top_finding.triggered_by, key=lambda t: t.score)
    return top_trigger.signal_name


# ── The three parts ──────────────────────────────────────────────────────


class AbstentionTrigger(BaseModel):
    """Part 1 — which condition raised the hold, and its signal value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    condition: str = Field(
        description=(
            "The single most-salient trigger: the Hold's pivotal uncertainty "
            "flag when present, else a raised flag, else the score-band relation."
        )
    )
    category: str = Field(
        description=(
            "Coarse provenance of the trigger (e.g. 'retrieval_grounding', "
            "'behavioral_contract', 'crc_gate_demotion', 'semantic_ambiguity')."
        )
    )
    fused_signal_value: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "The fused risk score the abstention fired at — the scalar the "
            "hold band is defined over (higher = more dangerous)."
        ),
    )
    uncertainty_flags: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Every uncertainty flag the pipeline raised for this evaluation.",
    )
    contributing_signal: str | None = Field(
        default=None,
        description=(
            "Highest-severity upstream ASI trigger signal (recognizer / "
            "specialist / semantic dimension), when one fired. None otherwise."
        ),
    )
    contributing_signal_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Severity of ``contributing_signal``, when present.",
    )
    reasons: tuple[str, ...] = Field(
        default_factory=tuple,
        description="The router reasons attached to this verdict (audit trail).",
    )


class AbstentionJustification(BaseModel):
    """Part 2 — why abstaining was the calibrated choice, with honest calibration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fused_score: float = Field(ge=0.0, le=1.0)
    permit_cutoff: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Lower edge of the operative band: the certified permit cutoff "
            "(lambda_hat) when a two-sided CRC certificate is live, else the "
            "policy permit_threshold."
        ),
    )
    forbid_cutoff: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Upper edge of the operative band: the certified forbid cutoff "
            "(lambda_forbid) when live, else the policy forbid_threshold."
        ),
    )
    band_relation: str = Field(
        description=(
            "Where the fused score sits relative to the band: 'within_hold_band', "
            "'within_permit_region_by_score_but_held_on_uncertainty', or "
            "'at_or_above_forbid_cutoff' (defensive; an ABSTAIN normally is not)."
        )
    )
    risk_basis: str = Field(
        description=(
            "'crc_two_sided_certified_hold_band' when the band carries a "
            "finite-sample guarantee, else 'policy_thresholds_uncalibrated'."
        )
    )
    calibration_status: str = Field(
        description="'field-calibrated' or 'uncalibrated' (the certified=false convention)."
    )
    certified_false_permit_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "The certified upper bound on the false-permit rate Tex stands "
            "behind, from the live CRC certificate. None when uncalibrated — "
            "no number is invented."
        ),
    )
    certified_false_forbid_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Certified upper bound on the false-forbid rate. None when uncalibrated.",
    )
    rationale: str = Field(description="One-paragraph plain-English justification.")


class NonWeaponizationWitness(BaseModel):
    """Part 3 — evidence the ABSTAIN is risk-discriminating, not a covert deny."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    permit_reachable: bool = Field(
        description=(
            "Whether the PERMIT region {fused_score <= permit_boundary_score} is "
            "non-empty under this exact policy+gate configuration. The crux of "
            "the witness: a configuration that COULD permit is not a blanket deny."
        )
    )
    permit_boundary_score: float = Field(
        ge=0.0,
        le=1.0,
        description="The fused-risk boundary at/below which this same config returns PERMIT.",
    )
    held_score: float = Field(ge=0.0, le=1.0, description="This action's fused risk score.")
    permit_margin: float = Field(
        description=(
            "held_score - permit_boundary_score. Positive = how much lower a "
            "legitimate variant's risk must be to reach PERMIT; <= 0 = already "
            "in the permit-by-score region (held on an uncertainty signal)."
        )
    )
    witness_basis: str = Field(
        description=(
            "'crc_certified_permit_cutoff' or 'policy_permit_threshold_uncalibrated' "
            "— which boundary the reachability claim rests on."
        )
    )
    dominant_lever: str | None = Field(
        default=None,
        description=(
            "The existing counterfactual lever: the signal a lower-risk "
            "legitimate variant would lack (or the uncertainty condition to "
            "resolve). None when no ASI finding fired."
        ),
    )
    permitting_variant: str = Field(
        description=(
            "Plain-English description of a legitimate variant the SAME "
            "configuration would PERMIT."
        )
    )
    scope: str = Field(
        description=(
            "The honest scope of the witness: an existence/reachability claim "
            "about the configuration, NOT a benign-string guarantee."
        )
    )


class AbstentionCertificate(BaseModel):
    """The sealed, three-part receipt attached to every ABSTAIN verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION)
    verdict: Literal["ABSTAIN"] = Field(
        default="ABSTAIN",
        description="Pinned: a certificate exists only for an ABSTAIN verdict.",
    )
    certified: bool = Field(
        description=(
            "Whether the JUSTIFICATION band carries a finite-sample guarantee "
            "(a live two-sided CRC certificate). False under the inert default "
            "— the honest posture until an operator supplies calibration."
        )
    )
    calibration_status: str = Field(
        description="'field-calibrated' or 'uncalibrated'."
    )
    descriptive_only: Literal[True] = Field(
        default=True,
        description=(
            "Pinned True: the certificate is evidence ABOUT the verdict and "
            "never an input to it. It cannot raise, lower, or change a verdict."
        ),
    )

    trigger: AbstentionTrigger
    justification: AbstentionJustification
    non_weaponization_witness: NonWeaponizationWitness


def build_abstention_certificate(
    *,
    verdict: Verdict,
    hold: Hold | None,
    crc_certificate: CRCCertificate | None,
    permit_threshold: float,
    forbid_threshold: float,
    final_score: float | None = None,
    uncertainty_flags: Sequence[str] = (),
    reasons: Sequence[str] = (),
    asi_findings: Sequence[ASIFinding] = (),
) -> AbstentionCertificate | None:
    """Build the certificate for an ABSTAIN. Returns ``None`` for any other verdict.

    Pure and deterministic — identical inputs always produce an identical
    certificate, so the PDP determinism fingerprint is preserved. Built from a
    finalized verdict + ``Hold``, so it can never alter the verdict.
    """
    if verdict is not Verdict.ABSTAIN:
        return None

    # Fused score: trust the Hold's clamped value first (the band is defined over
    # it); fall back to the passed score; finally 0.0.
    if hold is not None:
        score = _clamp(hold.final_score)
    elif final_score is not None:
        score = _clamp(final_score)
    else:
        score = 0.0

    pivotal_flag = hold.pivotal_flag if hold is not None else None

    # ── calibration: a band is certified only with a live two-sided CRC cert ──
    band_certified = bool(
        crc_certificate is not None and crc_certificate.hold_certified
    )
    calibration_status = "field-calibrated" if band_certified else "uncalibrated"

    if band_certified:
        assert crc_certificate is not None  # narrowed by band_certified
        permit_cutoff = _clamp(crc_certificate.hold_band_lower)
        forbid_cutoff = _clamp(crc_certificate.hold_band_upper)
        risk_basis = "crc_two_sided_certified_hold_band"
        cfp_rate: float | None = _clamp(crc_certificate.certified_false_permit_rate)
        cff_rate: float | None = _clamp(crc_certificate.certified_false_forbid_rate)
    else:
        permit_cutoff = _clamp(permit_threshold)
        forbid_cutoff = _clamp(forbid_threshold)
        risk_basis = "policy_thresholds_uncalibrated"
        cfp_rate = None
        cff_rate = None

    # ── TRIGGER ──────────────────────────────────────────────────────────────
    condition, category = _classify_trigger(
        pivotal_flag=pivotal_flag,
        uncertainty_flags=uncertainty_flags,
        reasons=reasons,
    )
    lever = _dominant_lever(asi_findings)
    lever_score: float | None = None
    if asi_findings:
        top_finding = max(asi_findings, key=lambda f: f.severity)
        lever_score = _round(top_finding.severity)

    trigger = AbstentionTrigger(
        condition=condition,
        category=category,
        fused_signal_value=_round(score),
        uncertainty_flags=tuple(uncertainty_flags),
        contributing_signal=lever,
        contributing_signal_score=lever_score,
        reasons=tuple(reasons),
    )

    # ── JUSTIFICATION ────────────────────────────────────────────────────────
    if score >= forbid_cutoff:
        band_relation = "at_or_above_forbid_cutoff"
    elif score <= permit_cutoff:
        band_relation = "within_permit_region_by_score_but_held_on_uncertainty"
    else:
        band_relation = "within_hold_band"

    if band_relation == "within_hold_band":
        why = (
            f"Fused risk {score:.3f} lies in the hold band "
            f"[{permit_cutoff:.3f}, {forbid_cutoff:.3f}): above the permit cutoff "
            f"and below the forbid cutoff, so neither release nor block is the "
            f"calibrated call — Tex routes it to human review."
        )
    elif band_relation == "within_permit_region_by_score_but_held_on_uncertainty":
        why = (
            f"Fused risk {score:.3f} is at/below the permit cutoff "
            f"{permit_cutoff:.3f}, but R4 emits PERMIT only when positively clean; "
            f"the '{condition}' signal blocks an automatic release, so Tex abstains "
            f"on uncertainty rather than permit on it."
        )
    else:  # at_or_above_forbid_cutoff (defensive)
        why = (
            f"Fused risk {score:.3f} is at/above the forbid cutoff "
            f"{forbid_cutoff:.3f}; the verdict is ABSTAIN (not FORBID) because a "
            f"non-score signal routed it to review rather than a structural block."
        )

    if band_certified:
        why += (
            f" The band is field-calibrated: a two-sided CRC certificate bounds "
            f"the false-permit rate <= {cfp_rate:.3f} and false-forbid rate "
            f"<= {cff_rate:.3f}."
        )
    else:
        why += (
            " The band is hand-tuned policy thresholds — UNCALIBRATED (no field "
            "corpus); marked certified=False per the certified=false convention. "
            "No finite-sample guarantee is claimed."
        )

    justification = AbstentionJustification(
        fused_score=_round(score),
        permit_cutoff=_round(permit_cutoff),
        forbid_cutoff=_round(forbid_cutoff),
        band_relation=band_relation,
        risk_basis=risk_basis,
        calibration_status=calibration_status,
        certified_false_permit_rate=_round(cfp_rate) if cfp_rate is not None else None,
        certified_false_forbid_rate=_round(cff_rate) if cff_rate is not None else None,
        rationale=why,
    )

    # ── NON-WEAPONIZATION WITNESS ────────────────────────────────────────────
    permit_boundary = permit_cutoff
    permit_reachable = permit_boundary >= 0.0  # valid policy => non-empty region
    witness_basis = (
        "crc_certified_permit_cutoff"
        if band_certified
        else "policy_permit_threshold_uncalibrated"
    )
    margin = _round(score - permit_boundary)

    if band_relation == "within_hold_band":
        lever_phrase = f"'{lever}'" if lever else "the dominant risk signal"
        permitting_variant = (
            f"A same-intent action whose fused risk fell to <= {permit_boundary:.3f} "
            f"(e.g. one not carrying {lever_phrase}) would return PERMIT under this "
            f"same policy+gate; this action scored {score:.3f}, {margin:.3f} above "
            f"that boundary."
        )
    else:
        permitting_variant = (
            f"A same-intent action that resolves '{condition}' (e.g. supplies the "
            f"missing grounding) at this risk level would return PERMIT under this "
            f"same policy+gate; the PERMIT region {{score <= {permit_boundary:.3f}}} "
            f"is non-empty."
        )

    witness = NonWeaponizationWitness(
        permit_reachable=permit_reachable,
        permit_boundary_score=_round(permit_boundary),
        held_score=_round(score),
        permit_margin=margin,
        witness_basis=witness_basis,
        dominant_lever=lever or (condition if condition else None),
        permitting_variant=permitting_variant,
        scope=(
            "Existence/reachability witness: proves the PERMIT region is non-empty "
            "under the fixed policy+gate, so this ABSTAIN is risk-discriminating, "
            "not a blanket covert deny. It does NOT assert any specific rendered "
            "string is benign, nor that moving the named lever alone crosses the "
            "boundary."
        ),
    )

    return AbstentionCertificate(
        certified=band_certified,
        calibration_status=calibration_status,
        trigger=trigger,
        justification=justification,
        non_weaponization_witness=witness,
    )
