"""
Colorado AI Act — SB 24-205, as delayed by SB25B-004.

Effective **30 June 2026** (delayed from the original 1 February 2026
date by SB25B-004, which moved the effective date by approximately
17 months relative to the as-passed bill).

Federal preemption pending — EO 14365 (11 December 2025) tasks the FTC
Chairman with assessing whether state laws requiring "alterations to
truthful outputs of AI models" are preempted by §5 of the FTC Act, but
the resulting policy statement was not published on its 11 March 2026
deadline. Treat as in-force until preemption is litigated.

Scope
-----
Imposes governance, risk-assessment, and documentation obligations on
"high-risk" AI systems used in "consequential decisions" — defined in
SB 24-205 §6-1-1701(3) as:

- employment / employment opportunities
- educational enrollment or opportunity
- essential government services
- financial / lending services
- essential health-care services
- housing
- insurance
- legal services

Both **developers** (§6-1-1702) and **deployers** (§6-1-1703) have
documentation duties. This module emits the deployer-side packet, which
is what Tex's customers (the AI-using businesses) need.

What this module emits
----------------------
``ColoradoAiActPayload`` plus ``emit_co_ai_evidence()`` factory.
Statutory fields (§6-1-1703(3)–(5)):

- ``deployer_legal_entity`` — covered "deployer" of record
- ``system_purpose`` — what consequential decision is being made
- ``system_version`` — model/system version under evaluation
- ``algorithmic_discrimination_risk_assessment`` — required impact
  assessment narrative
- ``human_oversight_summary`` — §6-1-1703(3)(c) mandate
- ``individual_consumer_notice_provided`` — §6-1-1703(4) mandate
- ``c2pa_manifest_id`` — provenance binding (Tex extension; not
  statute-mandated but supplies the cryptographic anchor)

Priority: P2 (state law, smaller buyer pool than EU AI Act).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from tex.observability.telemetry import emit_event


ConsequentialDecisionKind = Literal[
    "employment",
    "education",
    "government_service",
    "financial_lending",
    "health_care",
    "housing",
    "insurance",
    "legal_service",
]


@dataclass(frozen=True, slots=True)
class ColoradoAiActPayload:
    """Machine-readable Colorado AI Act §6-1-1703 deployer record."""

    deployer_legal_entity: str
    system_purpose: ConsequentialDecisionKind
    system_version: str
    algorithmic_discrimination_risk_assessment: str
    human_oversight_summary: str
    individual_consumer_notice_provided: bool
    c2pa_manifest_id: str | None
    impact_assessment_date: datetime
    statute_version: str = "SB_24-205_as_amended_2026-06"


def emit_co_ai_evidence(
    *,
    deployer_legal_entity: str,
    system_purpose: ConsequentialDecisionKind,
    system_version: str,
    algorithmic_discrimination_risk_assessment: str,
    human_oversight_summary: str,
    individual_consumer_notice_provided: bool,
    impact_assessment_date: datetime,
    c2pa_manifest_id: str | None = None,
) -> ColoradoAiActPayload:
    """Emit a Colorado AI Act §6-1-1703 deployer evidence packet.

    Raises
    ------
    ValueError
        On any field-level pre-condition failure (empty narrative,
        empty deployer entity, etc.). Fail-closed at construction.
    """
    if not deployer_legal_entity:
        raise ValueError("deployer_legal_entity is required")
    if not system_version:
        raise ValueError("system_version is required")
    if not algorithmic_discrimination_risk_assessment.strip():
        raise ValueError(
            "algorithmic_discrimination_risk_assessment narrative is required "
            "by §6-1-1703(3)(b)"
        )
    if not human_oversight_summary.strip():
        raise ValueError(
            "human_oversight_summary narrative is required by §6-1-1703(3)(c)"
        )

    payload = ColoradoAiActPayload(
        deployer_legal_entity=deployer_legal_entity,
        system_purpose=system_purpose,
        system_version=system_version,
        algorithmic_discrimination_risk_assessment=(
            algorithmic_discrimination_risk_assessment
        ),
        human_oversight_summary=human_oversight_summary,
        individual_consumer_notice_provided=individual_consumer_notice_provided,
        c2pa_manifest_id=c2pa_manifest_id,
        impact_assessment_date=impact_assessment_date,
    )
    emit_event(
        "compliance.colorado_ai_act.emitted",
        deployer=deployer_legal_entity,
        system_purpose=system_purpose,
        system_version=system_version,
        individual_consumer_notice_provided=individual_consumer_notice_provided,
        statute_version=payload.statute_version,
    )
    return payload


__all__ = (
    "ColoradoAiActPayload",
    "ConsequentialDecisionKind",
    "emit_co_ai_evidence",
)
