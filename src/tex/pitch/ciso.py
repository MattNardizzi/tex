"""
CISO pitch surface.

Programmatically generates the personalized MCP-vulnerability dossier
for a CISO at an AI-SDR-using SaaS company.

Priority: P0.

References
----------
- ECOSYSTEM_BUYER_NARRATIVES.md (repo) — CISO pitch frame (bounded-
  compromise theorem language)
- FRONTIER_KNOWN_BYPASSES.md (repo) — authoritative for the four CVEs
  and the BlueRock 36.7% telemetry figure
- arxiv 2504.03767 — MCP Safety Audit
- BlueRock 2026 Feb telemetry — 36.7% of 7,000+ MCP servers SSRF-
  vulnerable
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.observability.telemetry import emit_event
from tex.pitch._compliance_corpus import (
    BLUEROCK_FLEET_SAMPLE_SIZE,
    BLUEROCK_SSRF_VULNERABLE_FRACTION,
    MCP_CVE_EXPOSURE,
    McpCveExposure,
)
from tex.pitch._intel import (
    derive_company_name,
    detect_mcp_runtime_footprint,
)


# Tex runtime defenses a CISO actually cares about. Stable order.
_TEX_RUNTIME_CAPABILITIES: tuple[str, ...] = (
    "kernel-MCP gate — every tool call adjudicated against signed "
    "policy; no MCP server can poison tool descriptions silently",
    "HMAC-SHA-256 tool execution receipts (NabaOS pattern, "
    "arxiv 2603.10060) — runtime issues, agent never holds the key",
    "ClawGuard deterministic boundary enforcement against IPI via "
    "skill files (OWASP Agentic Skills Top 10, arxiv 2604.11790)",
    "MCPShield + mcp_injection_specialist — defends MCP-001 "
    "(tool poisoning) and MCP-002 (SSRF)",
    "Bounded-compromise certificate per renewal period — provable "
    "long-run ratio of compromised interactions below 1, signed",
    "ML-DSA / hybrid signed audit chain — post-quantum durable "
    "evidence the SOC can hand to an insurer offline",
)


@dataclass(frozen=True, slots=True)
class McpRiskDossier:
    """
    MCP-risk dossier for a CISO prospect.

    Attributes
    ----------
    company_name
        Presentational name derived from the domain.
    detected_mcp_servers
        Best-guess MCP runtimes deployed at this company.
    cve_exposure
        Tuple of CVE IDs from ``MCP_CVE_EXPOSURE``. Always exactly the
        four canonical CVEs from FRONTIER_KNOWN_BYPASSES.md so the
        pitch is consistent.
    cve_exposure_detail
        Structured CVE records, parallel to ``cve_exposure``.
    ssrf_risk_score
        Estimated SSRF exposure (0.0–1.0) — the BlueRock 36.7% baseline
        scaled by the count of detected vulnerable runtimes. The 36.7%
        figure itself is exposed as ``bluerock_ssrf_fraction`` so the
        pitch can cite it verbatim.
    bluerock_ssrf_fraction
        The raw BlueRock February 2026 figure: 0.367 (= 36.7%).
    bluerock_fleet_sample_size
        The raw BlueRock sample: 7,000 public MCP servers.
    tex_runtime_capabilities
        What Tex delivers against this exposure, in pitch order.
    """

    company_name: str
    detected_mcp_servers: tuple[str, ...]
    cve_exposure: tuple[str, ...]
    cve_exposure_detail: tuple[McpCveExposure, ...]
    ssrf_risk_score: float
    bluerock_ssrf_fraction: float
    bluerock_fleet_sample_size: int
    tex_runtime_capabilities: tuple[str, ...]


def _ssrf_risk_score(
    detected: tuple[str, ...],
    *,
    base_fraction: float,
) -> float:
    """
    Compute a 0.0–1.0 SSRF risk score for the detected footprint.

    Anchored on the BlueRock 36.7% baseline. Each detected runtime that
    appears in the CVE corpus or the canonical SSRF-prone list pushes
    the score upward sub-linearly so even a CISO running 1 MCP server
    sees the headline 36.7% figure as a starting point. The sub-linear
    accumulation prevents the score from blowing past 1.0 even with a
    large detected footprint.
    """
    if not detected:
        return base_fraction
    # Each additional vulnerable-class runtime adds half of the residual
    # gap to 1.0. score = 1 - (1 - base) * (0.5 ** n_vuln).
    vuln_classes = sum(
        1
        for runtime in detected
        if any(
            runtime.lower().startswith(c.affected_product.lower())
            or c.affected_product.lower() in runtime.lower()
            for c in MCP_CVE_EXPOSURE
        )
    )
    if vuln_classes == 0:
        return base_fraction
    residual = 1.0 - base_fraction
    return 1.0 - residual * (0.5 ** vuln_classes)


def build_mcp_risk_dossier(*, company_domain: str) -> McpRiskDossier:
    """
    Build the personalized MCP-risk dossier for a CISO prospect.

    Parameters
    ----------
    company_domain
        The prospect's primary domain. Normalized case-insensitively.

    Returns
    -------
    McpRiskDossier
        Frozen dossier with detected MCP footprint, the four canonical
        CVEs, the BlueRock 36.7% figure, an SSRF risk score derived
        from both, and the Tex runtime capability set.

    TODO(P0): detect MCP servers in use (Cursor, LibreChat, custom)
        - Currently uses ``_intel.detect_mcp_runtime_footprint``
          deterministic heuristic. Live signal (active scanning of
          public MCP /sse endpoints, GitHub repo introspection) is P1.
    TODO(P0): map to known CVEs:
              CVE-2025-49596 (MCP Inspector RCE)
              CVE-2026-22252 (LibreChat)
              CVE-2025-54136 (Cursor)
              CVE-2026-22688 (WeKnora)
        - DONE: ``MCP_CVE_EXPOSURE`` in ``_compliance_corpus`` carries
          all four with respondent + summary. Sourced from
          FRONTIER_KNOWN_BYPASSES.md.
    TODO(P0): cite BlueRock 2026: 36.7% of 7,000+ MCP servers SSRF-vulnerable
        - DONE: ``BLUEROCK_SSRF_VULNERABLE_FRACTION = 0.367`` and
          ``BLUEROCK_FLEET_SAMPLE_SIZE = 7000`` carried into the
          dossier as first-class fields.
    TODO(P0): list Tex runtime defenses:
              kernel-MCP gate, signed receipts, ClawGuard, MCPShield
        - DONE: ``_TEX_RUNTIME_CAPABILITIES`` enumerates six (the four
          plus bounded-compromise certificate and ML-DSA audit chain).
    """
    company_name = derive_company_name(company_domain)
    detected = detect_mcp_runtime_footprint(company_domain)
    score = _ssrf_risk_score(
        detected, base_fraction=BLUEROCK_SSRF_VULNERABLE_FRACTION
    )
    cve_ids = tuple(c.cve_id for c in MCP_CVE_EXPOSURE)

    dossier = McpRiskDossier(
        company_name=company_name,
        detected_mcp_servers=detected,
        cve_exposure=cve_ids,
        cve_exposure_detail=MCP_CVE_EXPOSURE,
        ssrf_risk_score=score,
        bluerock_ssrf_fraction=BLUEROCK_SSRF_VULNERABLE_FRACTION,
        bluerock_fleet_sample_size=BLUEROCK_FLEET_SAMPLE_SIZE,
        tex_runtime_capabilities=_TEX_RUNTIME_CAPABILITIES,
    )

    emit_event(
        "pitch.dossier.built",
        dossier_kind="mcp_risk",
        company_domain=company_domain,
        company_name=company_name,
        detected_mcp_count=len(detected),
        cve_count=len(cve_ids),
        ssrf_risk_score=score,
    )

    return dossier


__all__ = ["McpRiskDossier", "build_mcp_risk_dossier"]
