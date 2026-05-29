"""
VP Marketing / Head of Brand pitch surface.

Programmatically generates the personalized brand-safety risk dossier
for an AI-SDR-using SaaS prospect. Used in inbound demos and outbound
investigation runs.

Priority: P0.

References
----------
- ECOSYSTEM_BUYER_NARRATIVES.md (repo) — VP Marketing pitch frame
- FRONTIER_COMPLIANCE.md (repo) — authoritative dates/statuses for
  EU AI Act Art. 50, CA SB 942 (operative 2 Aug 2026 per AB 853),
  NY AI Advertising Disclosure (Jun 2026), FTC §5 enforcement
- Operation AI Comply enforcement dockets (DoNotPay, Rytr, Automators,
  Ascend Ecom, Ecommerce Empire Builders) — see _compliance_corpus
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.observability.telemetry import emit_event
from tex._pending.pitch._compliance_corpus import (
    FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD,
    FTC_OPERATION_AI_COMPLY,
    MARKETING_REGULATORY_ANCHORS,
    EnforcementAction,
    RegulatoryAnchor,
)
from tex._pending.pitch._intel import (
    derive_company_name,
    estimate_ai_sdr_vendor,
    estimate_outbound_volume_per_month,
)


# Tex deliverables a VP Marketing actually cares about. Stable order so
# the dossier renders consistently across calls.
_TEX_BRAND_SAFETY_CAPABILITIES: tuple[str, ...] = (
    "C2PA Content Credentials on every outbound AI-generated email "
    "(satisfies EU AI Act Art. 50 machine-readable disclosure)",
    "ML-DSA-signed evidence chain — every send carries a post-quantum "
    "signature recoverable years after enforcement inquiry",
    "FTC §5 substantiation packet — claim → evidence → reviewer chain "
    "exportable as a single signed artifact",
    "California SB 942 latent-disclosure embedding ahead of the "
    "2 August 2026 operative date",
    "Insurer-verifiable evidence packet — General Counsel hands one "
    "hash to underwriter at renewal; verification is offline",
)


@dataclass(frozen=True, slots=True)
class BrandSafetyDossier:
    """
    Brand-safety dossier for a VP Marketing prospect.

    Attributes
    ----------
    company_name
        Presentational name derived from the domain.
    detected_ai_sdr_vendor
        Best-guess AI-SDR vendor in use; ``None`` if heuristic detected
        no clear AI-SDR footprint.
    estimated_outbound_volume_per_month
        Deterministic estimate of monthly outbound AI-generated email
        volume. Sized for the 50–500-employee Series B/C/D SaaS ICP.
    enforcement_exposure_summary
        One-paragraph headline summary suitable for a slide footer.
    enforcement_actions
        Structured corpus of FTC §5 AI-related enforcement actions.
    regulatory_anchors
        Structured statutes/articles the company is (or will be) on the
        hook for, with operative dates.
    total_monetary_judgments_usd
        Aggregate monetary judgments across the enforcement corpus.
    tex_evidence_capabilities
        What Tex delivers against this exposure, in pitch order.
    """

    company_name: str
    detected_ai_sdr_vendor: str | None
    estimated_outbound_volume_per_month: int
    enforcement_exposure_summary: str
    enforcement_actions: tuple[EnforcementAction, ...]
    regulatory_anchors: tuple[RegulatoryAnchor, ...]
    total_monetary_judgments_usd: int
    tex_evidence_capabilities: tuple[str, ...]


def _summarize_exposure(
    *,
    vendor: str | None,
    volume: int,
    judgments_usd: int,
    anchors: tuple[RegulatoryAnchor, ...],
) -> str:
    """Build the headline summary string from structured inputs."""
    vendor_phrase = (
        f"running {vendor}"
        if vendor is not None
        else "with no detected AI-SDR vendor (manual outbound or in-house)"
    )
    judgments_m = judgments_usd // 1_000_000
    earliest_eu = next(
        (a for a in anchors if a.citation.startswith("EU AI Act")), None
    )
    earliest_ca = next(
        (a for a in anchors if a.citation.startswith("California")), None
    )
    eu_phrase = (
        f"; EU AI Act Art. 50 operative {earliest_eu.operative_date.isoformat()}"
        if earliest_eu is not None
        else ""
    )
    ca_phrase = (
        f"; CA SB 942 operative {earliest_ca.operative_date.isoformat()}"
        if earliest_ca is not None
        else ""
    )
    return (
        f"AI-SDR stack {vendor_phrase} sending an estimated "
        f"{volume:,} outbound emails/month into a "
        f"${judgments_m}M+ FTC §5 enforcement corpus"
        f"{eu_phrase}{ca_phrase}."
    )


def build_brand_safety_dossier(*, company_domain: str) -> BrandSafetyDossier:
    """
    Build the personalized brand-safety dossier for a prospect domain.

    Parameters
    ----------
    company_domain
        The prospect's primary domain, e.g. ``acmecorp.com``. Normalized
        case-insensitively.

    Returns
    -------
    BrandSafetyDossier
        Frozen dossier suitable for templating into outbound or for
        feeding the demo-time render pipeline.

    TODO(P0): detect AI-SDR vendor from outbound email patterns
        - Currently uses ``_intel.estimate_ai_sdr_vendor`` deterministic
          heuristic (10% of domains report no vendor). Live OSINT (DNS
          MX, SPF/DKIM include chains, footer fingerprints) is P1.
    TODO(P0): estimate outbound volume from public hiring + funding signals
        - Currently uses ``_intel.estimate_outbound_volume_per_month``
          deterministic seed. Live signal: LinkedIn SDR headcount +
          Crunchbase last-round size. P1.
    TODO(P0): summarize: $24M FTC settlements, EU Art 50 Aug 2 2026,
              CA SB 942 live, NY June 2026
        - DONE: structured corpus in ``_compliance_corpus`` plus
          ``_summarize_exposure`` headline assembly. Source: Operation
          AI Comply dockets and FRONTIER_COMPLIANCE.md.
    TODO(P0): list Tex deliverables: C2PA manifests, ML-DSA signed audit chain,
              insurer-verifiable evidence
        - DONE: ``_TEX_BRAND_SAFETY_CAPABILITIES`` enumerates the five.
    """
    company_name = derive_company_name(company_domain)
    vendor = estimate_ai_sdr_vendor(company_domain)
    volume = estimate_outbound_volume_per_month(company_domain)
    summary = _summarize_exposure(
        vendor=vendor,
        volume=volume,
        judgments_usd=FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD,
        anchors=MARKETING_REGULATORY_ANCHORS,
    )

    dossier = BrandSafetyDossier(
        company_name=company_name,
        detected_ai_sdr_vendor=vendor,
        estimated_outbound_volume_per_month=volume,
        enforcement_exposure_summary=summary,
        enforcement_actions=FTC_OPERATION_AI_COMPLY,
        regulatory_anchors=MARKETING_REGULATORY_ANCHORS,
        total_monetary_judgments_usd=FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD,
        tex_evidence_capabilities=_TEX_BRAND_SAFETY_CAPABILITIES,
    )

    emit_event(
        "pitch.dossier.built",
        dossier_kind="brand_safety",
        company_domain=company_domain,
        company_name=company_name,
        ai_sdr_vendor=vendor,
        outbound_volume=volume,
        enforcement_actions_count=len(FTC_OPERATION_AI_COMPLY),
        regulatory_anchors_count=len(MARKETING_REGULATORY_ANCHORS),
    )

    return dossier


__all__ = ["BrandSafetyDossier", "build_brand_safety_dossier"]
