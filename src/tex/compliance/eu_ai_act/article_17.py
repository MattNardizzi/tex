"""
EU AI Act Article 17: Quality Management System (QMS).

Effective for high-risk AI systems from **2 August 2026** along with
Annex III obligations. Providers of high-risk AI systems must have a
quality management system in place that ensures compliance with the
Act, documented as written policies, procedures, and instructions.

Article 17(1) lists ten (a)-(k) substantive QMS components. This module
emits a machine-readable representation of those components plus the
operational evidence (post-market monitoring, corrective actions,
version control) that auditors actually inspect.

Frontier delta (May 18, 2026)
-----------------------------
- The 7 May 2026 Digital Omnibus did NOT change the Article 17
  deadline; it moved the watermark technical-solutions deadline only.
- The Code of Practice second draft (3 March 2026) §QMS-3 calls out
  CI/CD provenance (commit-signed change events) as a presumptively-
  compliant approach for the §17(1)(g) version-control component. Tex
  binds this to its evidence chain via ``c2pa_manifest_id``.

Priority: P1 (full EU positioning for GTM-A).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from tex.observability.telemetry import emit_event


@dataclass(frozen=True, slots=True)
class CorrectiveAction:
    """One row in the §17(1)(j) corrective-action log."""

    incident_id: str
    opened_at: datetime
    closed_at: datetime | None
    root_cause: str
    remediation: str
    bound_evidence_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class PostMarketMonitoringWindow:
    """§17(1)(i) post-market monitoring summary for a review period."""

    window_start: datetime
    window_end: datetime
    deployments_observed: int
    serious_incidents_reported: int
    near_misses_logged: int


@dataclass(frozen=True, slots=True)
class Article17QmsPayload:
    """Machine-readable §17 QMS evidence packet."""

    provider_legal_entity: str
    high_risk_system_name: str
    high_risk_system_version: str
    qms_policy_url: str
    qms_components_implemented: tuple[str, ...]
    post_market_monitoring: PostMarketMonitoringWindow
    corrective_actions: tuple[CorrectiveAction, ...]
    version_control_repository_url: str
    code_of_practice_alignment: str = "draft_2026_03_03"


# Article 17(1) (a)–(k) — substantive QMS components. We emit the canonical
# IDs the AI Office's Code of Practice second draft uses.
_QMS_COMPONENTS: tuple[str, ...] = (
    "regulatory_compliance_strategy",       # (a)
    "design_verification_procedures",       # (b)
    "design_control_procedures",            # (c)
    "examination_test_validation_proc",     # (d)
    "technical_specifications_data_mgmt",   # (e)
    "data_management_systems",              # (f)
    "risk_management_system",               # (g)
    "post_market_monitoring_system",        # (h, also §72)
    "incident_reporting_procedures",        # (i, also §73)
    "communication_procedures",             # (j)
    "record_keeping_procedures",            # (k)
)


def emit_article_17_evidence(
    *,
    provider_legal_entity: str,
    high_risk_system_name: str,
    high_risk_system_version: str,
    qms_policy_url: str,
    post_market_monitoring: PostMarketMonitoringWindow,
    corrective_actions: Sequence[CorrectiveAction],
    version_control_repository_url: str,
    qms_components_implemented: Sequence[str] | None = None,
) -> Article17QmsPayload:
    """Emit a §17 QMS evidence packet.

    Parameters
    ----------
    qms_components_implemented
        Defaults to the full set of (a)-(k) §17(1) components. Pass an
        explicit subset to attest partial implementation (e.g. during
        ramp-up). Each entry MUST be one of ``_QMS_COMPONENTS``.

    Raises
    ------
    ValueError
        On empty provider/system name, missing QMS policy URL, or any
        unknown component identifier.
    """
    if not provider_legal_entity:
        raise ValueError("provider_legal_entity is required")
    if not high_risk_system_name:
        raise ValueError("high_risk_system_name is required")
    if not high_risk_system_version:
        raise ValueError("high_risk_system_version is required")
    if not qms_policy_url:
        raise ValueError("qms_policy_url is required (§17(1)(a))")
    if not version_control_repository_url:
        raise ValueError(
            "version_control_repository_url is required for §17(1)(g)"
        )

    components = tuple(qms_components_implemented or _QMS_COMPONENTS)
    unknown = [c for c in components if c not in _QMS_COMPONENTS]
    if unknown:
        raise ValueError(
            f"Unknown §17(1) QMS component identifiers: {unknown}. "
            f"Valid: {_QMS_COMPONENTS}"
        )

    payload = Article17QmsPayload(
        provider_legal_entity=provider_legal_entity,
        high_risk_system_name=high_risk_system_name,
        high_risk_system_version=high_risk_system_version,
        qms_policy_url=qms_policy_url,
        qms_components_implemented=components,
        post_market_monitoring=post_market_monitoring,
        corrective_actions=tuple(corrective_actions),
        version_control_repository_url=version_control_repository_url,
    )
    emit_event(
        "compliance.eu_ai_act.article_17.emitted",
        provider=provider_legal_entity,
        system=f"{high_risk_system_name}/{high_risk_system_version}",
        components=len(components),
        corrective_actions=len(payload.corrective_actions),
        window_start=post_market_monitoring.window_start.isoformat(),
        window_end=post_market_monitoring.window_end.isoformat(),
    )
    return payload


__all__ = (
    "Article17QmsPayload",
    "CorrectiveAction",
    "PostMarketMonitoringWindow",
    "emit_article_17_evidence",
)
