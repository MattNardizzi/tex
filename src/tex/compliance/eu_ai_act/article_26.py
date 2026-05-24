"""
EU AI Act Article 26: Deployer Obligations for High-Risk AI Systems.

Effective **2 August 2026**. Article 26 governs the *deployer* (the
party that puts a high-risk AI system into use) — distinct from the
provider obligations under Article 16. The deployer's duties are:

- Article 26(1): use the system in accordance with the provider's
  instructions for use.
- Article 26(2): assign human oversight to natural persons with
  necessary competence, training, authority, and support.
- Article 26(3): input-data relevance (ensure input data is
  representative of the system's intended purpose).
- Article 26(5): monitor operation per the provider's instructions
  and inform the provider of malfunctions / serious incidents within
  72 hours per §73.
- Article 26(6): keep automatically-generated logs for the period
  appropriate to the system's intended purpose (minimum six months).
- Article 26(8): cooperate with national competent authorities.
- Article 26(11): inform natural persons subject to a decision that
  they are subject to the use of a high-risk AI system.

What this module emits
----------------------
``Article26DeployerPayload`` plus ``emit_article_26_evidence()``.

The packet binds the deployer's legal entity to a window of operation
(``logs_retention_window``), a roster of human-oversight assignees
(``human_oversight_assignees``), and a list of bound C2PA manifest
IDs / SCITT statement IDs covering the deployment artifacts. The
72-hour incident-reporting clock (§26(5) → §73) is enforced by the
``incident_reporting_max_delay_hours`` field — set lower than 72 to
attest a stricter internal SLA.

Priority: P1 (full EU positioning for GTM-A).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Sequence

from tex.observability.telemetry import emit_event


@dataclass(frozen=True, slots=True)
class HumanOversightAssignee:
    """One natural person assigned per §26(2)."""

    person_identifier: str  # opaque identifier; not PII
    role: str
    competence_summary: str
    training_completed_at: datetime
    authority_to_intervene: bool = True


@dataclass(frozen=True, slots=True)
class Article26DeployerPayload:
    """Machine-readable §26 deployer evidence packet."""

    deployer_legal_entity: str
    high_risk_system_name: str
    high_risk_system_version: str
    provider_legal_entity: str
    instructions_for_use_url: str
    human_oversight_assignees: tuple[HumanOversightAssignee, ...]
    input_data_relevance_attestation: str
    logs_retention_window: timedelta
    incident_reporting_max_delay_hours: int
    affected_persons_notice_template_url: str
    bound_evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    statute_version: str = "AIA_Art_26_2026-08"


def emit_article_26_evidence(
    *,
    deployer_legal_entity: str,
    high_risk_system_name: str,
    high_risk_system_version: str,
    provider_legal_entity: str,
    instructions_for_use_url: str,
    human_oversight_assignees: Sequence[HumanOversightAssignee],
    input_data_relevance_attestation: str,
    logs_retention_window: timedelta,
    affected_persons_notice_template_url: str,
    incident_reporting_max_delay_hours: int = 72,
    bound_evidence_ids: Sequence[str] = (),
) -> Article26DeployerPayload:
    """Emit a §26 deployer evidence packet.

    Pre-conditions enforced (fail-closed):
    - At least one §26(2) human-oversight assignee.
    - ``logs_retention_window`` ≥ 6 months (§26(6) statutory minimum).
    - ``incident_reporting_max_delay_hours`` ≤ 72 (§26(5) → §73).
    - Non-empty input-data-relevance attestation (§26(3)).

    Raises
    ------
    ValueError
        On any pre-condition failure.
    """
    if not deployer_legal_entity:
        raise ValueError("deployer_legal_entity is required")
    if not high_risk_system_name:
        raise ValueError("high_risk_system_name is required")
    if not high_risk_system_version:
        raise ValueError("high_risk_system_version is required")
    if not provider_legal_entity:
        raise ValueError("provider_legal_entity is required")
    if not instructions_for_use_url:
        raise ValueError(
            "instructions_for_use_url is required (§26(1))"
        )
    if not human_oversight_assignees:
        raise ValueError(
            "at least one HumanOversightAssignee is required (§26(2))"
        )
    if not input_data_relevance_attestation.strip():
        raise ValueError(
            "input_data_relevance_attestation is required (§26(3))"
        )

    six_months = timedelta(days=183)
    if logs_retention_window < six_months:
        raise ValueError(
            f"logs_retention_window {logs_retention_window} < 6-month "
            f"§26(6) statutory minimum"
        )
    if incident_reporting_max_delay_hours > 72:
        raise ValueError(
            f"incident_reporting_max_delay_hours "
            f"{incident_reporting_max_delay_hours} exceeds §26(5) "
            f"72-hour maximum"
        )
    if not affected_persons_notice_template_url:
        raise ValueError(
            "affected_persons_notice_template_url is required (§26(11))"
        )

    payload = Article26DeployerPayload(
        deployer_legal_entity=deployer_legal_entity,
        high_risk_system_name=high_risk_system_name,
        high_risk_system_version=high_risk_system_version,
        provider_legal_entity=provider_legal_entity,
        instructions_for_use_url=instructions_for_use_url,
        human_oversight_assignees=tuple(human_oversight_assignees),
        input_data_relevance_attestation=input_data_relevance_attestation,
        logs_retention_window=logs_retention_window,
        incident_reporting_max_delay_hours=incident_reporting_max_delay_hours,
        affected_persons_notice_template_url=affected_persons_notice_template_url,
        bound_evidence_ids=tuple(bound_evidence_ids),
    )
    emit_event(
        "compliance.eu_ai_act.article_26.emitted",
        deployer=deployer_legal_entity,
        system=f"{high_risk_system_name}/{high_risk_system_version}",
        provider=provider_legal_entity,
        oversight_assignees=len(payload.human_oversight_assignees),
        retention_days=logs_retention_window.days,
        incident_sla_hours=incident_reporting_max_delay_hours,
        statute_version=payload.statute_version,
    )
    return payload


__all__ = (
    "Article26DeployerPayload",
    "HumanOversightAssignee",
    "emit_article_26_evidence",
)
