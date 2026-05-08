"""
Dual-ICP Pitch Surfaces
=======================

Two doors, same product:

  vp_marketing.py     "Your AI-SDR is one hallucinated stat away from an FTC
                       settlement. $24M in 2025-26 enforcement."

  ciso.py             "Your AI stack runs on MCP. 36.7% of MCP servers are
                       SSRF-vulnerable per BlueRock Feb 2026. Tex adjudicates
                       every tool call with a signed receipt."

  insurer_export.py   The unified evidence packet an insurer or regulator
                       can verify offline.

  verifier.py         The independent verifier function. Acceptance criteria
                       require the insurer packet to round-trip through this.

Priority
--------
P0 — these are programmatic surfaces driving the demo and sales motion.

References
----------
- ECOSYSTEM_BUYER_NARRATIVES.md (repo) — pitch frames for all three
- FRONTIER_COMPLIANCE.md (repo, last reviewed 7 May 2026) — every
  date and statute cited
- FRONTIER_KNOWN_BYPASSES.md (repo) — CVEs and BlueRock figures
- NIST FIPS 204 (ML-DSA), NSA CNSA 2.0 — signing primitives
- arxiv 2603.10060 — NabaOS receipts
"""

from tex.pitch._compliance_corpus import (
    BLUEROCK_FLEET_SAMPLE_SIZE,
    BLUEROCK_SSRF_VULNERABLE_FRACTION,
    FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD,
    FTC_OPERATION_AI_COMPLY,
    MARKETING_REGULATORY_ANCHORS,
    MCP_CVE_EXPOSURE,
    EnforcementAction,
    McpCveExposure,
    RegulatoryAnchor,
)
from tex.pitch.ciso import McpRiskDossier, build_mcp_risk_dossier
from tex.pitch.insurer_export import (
    InsurerEvidencePacket,
    build_insurer_evidence_packet,
)
from tex.pitch.verifier import (
    PacketVerificationIssue,
    PacketVerificationResult,
    verify_insurer_evidence_packet,
)
from tex.pitch.vp_marketing import (
    BrandSafetyDossier,
    build_brand_safety_dossier,
)


__all__ = [
    # VP Marketing
    "BrandSafetyDossier",
    "build_brand_safety_dossier",
    # CISO
    "McpRiskDossier",
    "build_mcp_risk_dossier",
    # Insurer
    "InsurerEvidencePacket",
    "build_insurer_evidence_packet",
    # Verifier
    "PacketVerificationIssue",
    "PacketVerificationResult",
    "verify_insurer_evidence_packet",
    # Corpus types (so tests + downstream code can introspect)
    "EnforcementAction",
    "RegulatoryAnchor",
    "McpCveExposure",
    "FTC_OPERATION_AI_COMPLY",
    "MARKETING_REGULATORY_ANCHORS",
    "MCP_CVE_EXPOSURE",
    "BLUEROCK_SSRF_VULNERABLE_FRACTION",
    "BLUEROCK_FLEET_SAMPLE_SIZE",
    "FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD",
]
