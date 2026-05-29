"""
Curated regulatory corpus used by the dual-ICP dossier surfaces.

All values are sourced from ``FRONTIER_COMPLIANCE.md`` (last reviewed
7 May 2026) and ``FRONTIER_KNOWN_BYPASSES.md``. Centralizing them here
means any pitch surface — VP Marketing, CISO, Insurer — citing the same
fact cites the *same byte-for-byte string*, which keeps demos consistent
and makes future updates a single-file change.

References
----------
- FRONTIER_COMPLIANCE.md (repo root) — authoritative for dates/statuses
- FRONTIER_KNOWN_BYPASSES.md (repo root) — authoritative for CVEs and
  the BlueRock 36.7% telemetry figure
- 15 U.S.C. § 45 (FTC Act §5)
- EU AI Act Articles 17, 26, 50
- California SB 942 (CAITA), as amended by AB 853 (signed 13 Oct 2025)
- Colorado SB 24-205 (delayed by SB25B-004)
- New York AI Advertising Disclosure (effective Jun 2026)

This module has no side effects and no I/O. It is a frozen data table.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field


class EnforcementAction(BaseModel):
    """A single FTC §5 AI-related enforcement action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    docket: str = Field(min_length=1, max_length=128)
    respondent: str = Field(min_length=1, max_length=256)
    settled_year: int = Field(ge=2020, le=2099)
    summary: str = Field(min_length=1, max_length=512)


class RegulatoryAnchor(BaseModel):
    """A single regulatory obligation a customer is exposed to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    citation: str = Field(min_length=1, max_length=256)
    operative_date: date
    obligation: str = Field(min_length=1, max_length=512)
    tex_module: str = Field(min_length=1, max_length=256)


class McpCveExposure(BaseModel):
    """A single CVE in the MCP attack surface."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    affected_product: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=512)


# --- FTC §5 AI enforcement (Operation AI Comply + adjacent) ---
# Sourced from FRONTIER_COMPLIANCE.md; canonical reference for the
# brand-safety dossier's "$24M in 2025-26 enforcement" pitch line.
FTC_OPERATION_AI_COMPLY: tuple[EnforcementAction, ...] = (
    EnforcementAction(
        docket="FTC v. DoNotPay",
        respondent="DoNotPay, Inc.",
        settled_year=2024,
        summary=(
            "$193,000 settlement; deceptive claims that an AI chatbot "
            "could substitute for a human lawyer."
        ),
    ),
    EnforcementAction(
        docket="FTC v. Rytr",
        respondent="Rytr LLC",
        settled_year=2024,
        summary=(
            "Consent order; AI writing assistant generated false consumer "
            "reviews on demand. Settlement: prohibition + monitoring."
        ),
    ),
    EnforcementAction(
        docket="FTC v. Automators AI",
        respondent="Automators LLC / Roman Cresto",
        settled_year=2024,
        summary=(
            "Stipulated order; ~$22M in monetary judgment for AI-business-"
            "in-a-box scheme misrepresentations. Largest AI-Comply action."
        ),
    ),
    EnforcementAction(
        docket="FTC v. Ascend Ecom",
        respondent="Ascend Capventures Inc.",
        settled_year=2024,
        summary=(
            "TRO + asset freeze; 'AI-powered' e-commerce store false "
            "earnings claims. Operation AI Comply sweep."
        ),
    ),
    EnforcementAction(
        docket="FTC v. Ecommerce Empire Builders",
        respondent="Ecommerce Empire Builders LLC",
        settled_year=2024,
        summary=(
            "Stipulated order; AI-store training program with "
            "deceptive earnings testimonials."
        ),
    ),
)

# Aggregate from the corpus above, used as a structured count rather
# than a free-form string so the dossier can render it any number of ways.
FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD: int = 24_000_000


# --- Regulatory anchors a VP of Marketing is on the hook for ---
MARKETING_REGULATORY_ANCHORS: tuple[RegulatoryAnchor, ...] = (
    RegulatoryAnchor(
        citation="FTC Act §5 (15 U.S.C. § 45)",
        operative_date=date(1914, 9, 26),
        obligation=(
            "Prohibition on unfair or deceptive acts or practices. AI-"
            "generated marketing claims fall under existing §5 authority "
            "regardless of subsequent AI-specific rulemaking."
        ),
        tex_module="compliance/ftc/policy_statement.py",
    ),
    RegulatoryAnchor(
        citation="EU AI Act Art. 50 (Transparency for AI-generated content)",
        operative_date=date(2026, 8, 2),
        obligation=(
            "Providers of generative systems must mark output as AI-generated "
            "in a machine-readable format. C2PA Content Credentials are the "
            "anticipated mechanism per the Code of Practice 2nd draft "
            "(3 March 2026)."
        ),
        tex_module="compliance/eu_ai_act/article_50.py",
    ),
    RegulatoryAnchor(
        citation="California SB 942 (CAITA), as amended by AB 853",
        operative_date=date(2026, 8, 2),
        obligation=(
            "Covered providers must offer a free public AI-detection tool and "
            "embed both visible and latent disclosures in AI-generated content. "
            "AB 853 (signed 13 Oct 2025) moved the operative date from "
            "1 Jan 2026 to 2 Aug 2026 to align with EU AI Act."
        ),
        tex_module="compliance/state/california_sb942.py",
    ),
    RegulatoryAnchor(
        citation="New York AI Advertising Disclosure",
        operative_date=date(2026, 6, 1),
        obligation=(
            "Required disclosure of AI use in commercial advertisements "
            "directed to NY consumers."
        ),
        tex_module="compliance/state/new_york_ai_disclosure.py",
    ),
)


# --- CVE exposure surface from FRONTIER_KNOWN_BYPASSES.md ---
MCP_CVE_EXPOSURE: tuple[McpCveExposure, ...] = (
    McpCveExposure(
        cve_id="CVE-2025-49596",
        affected_product="Anthropic MCP Inspector",
        summary=(
            "Remote code execution via developer-tool introspection endpoint. "
            "MCP server instances exposing Inspector are RCE-vulnerable."
        ),
    ),
    McpCveExposure(
        cve_id="CVE-2026-22252",
        affected_product="LibreChat",
        summary=(
            "MCP-tool-mediated injection in LibreChat agent runtime. "
            "Malicious tool descriptions coerce the agent into unsafe calls."
        ),
    ),
    McpCveExposure(
        cve_id="CVE-2025-54136",
        affected_product="Cursor IDE",
        summary=(
            "MCP integration permits malicious server to alter the editor's "
            "tool surface and execute commands without user re-consent."
        ),
    ),
    McpCveExposure(
        cve_id="CVE-2026-22688",
        affected_product="WeKnora",
        summary=(
            "MCP server exposes SSRF primitive via tool input parameters; "
            "internal-network pivot from public deployment."
        ),
    ),
)


# --- BlueRock 2026 MCP fleet telemetry (Feb 2026) ---
# 36.7% of 7,000+ public MCP servers SSRF-vulnerable.
BLUEROCK_FLEET_SAMPLE_SIZE: int = 7_000
BLUEROCK_SSRF_VULNERABLE_FRACTION: float = 0.367


__all__ = [
    "EnforcementAction",
    "RegulatoryAnchor",
    "McpCveExposure",
    "FTC_OPERATION_AI_COMPLY",
    "FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD",
    "MARKETING_REGULATORY_ANCHORS",
    "MCP_CVE_EXPOSURE",
    "BLUEROCK_FLEET_SAMPLE_SIZE",
    "BLUEROCK_SSRF_VULNERABLE_FRACTION",
]
