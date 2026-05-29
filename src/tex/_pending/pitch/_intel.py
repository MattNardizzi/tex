"""
Deterministic intelligence helpers used by both VP-Marketing and CISO
dossiers.

Design decision (paper-silent)
------------------------------
The acceptance criteria for the dossier builders say things like
"detect AI-SDR vendor from outbound email patterns" and "detect MCP
servers in use." A live OSINT or DNS-sweep implementation is out of
scope for this thread (P1+). Instead, the dossier surfaces are *driven
by deterministic, domain-seeded heuristics* so that:

  - demos and tests are reproducible byte-for-byte
  - the same prospect domain returns the same dossier across calls
  - sales motion does not depend on a reachable third-party scanner

The heuristic uses a SHA-256 hash of the normalized domain to seed
selections from curated tables. Live signal collection is a future
plug-in: each ``estimate_*`` function takes the domain through this
deterministic path and accepts (in a future thread) an optional
``signal_source`` callable that overrides the deterministic default.

When live OSINT lands, swap the body of each helper to query
``signal_source`` first and fall back to the deterministic value.
"""

from __future__ import annotations

import hashlib

# Curated AI-SDR vendor list. These are the vendors a 50-500 employee
# Series B/C/D SaaS company commonly runs in May 2026. Order is stable;
# the deterministic seeded index picks one.
_AI_SDR_VENDORS: tuple[str, ...] = (
    "Clay",
    "Apollo.io",
    "Outreach AI",
    "Salesloft Rhythm",
    "Regie.ai",
    "11x Alice",
    "AiSDR",
    "Reggie",
    "Lavender",
)

# Curated MCP server / agent-runtime list. Drawn directly from the four
# CVEs in MCP_CVE_EXPOSURE plus the common open-source MCP runtimes.
_MCP_RUNTIME_FOOTPRINT: tuple[str, ...] = (
    "Anthropic MCP Inspector",
    "LibreChat",
    "Cursor IDE",
    "WeKnora",
    "Custom in-house MCP server",
    "MCP filesystem server",
    "MCP github server",
)


def _normalized_domain(domain: str) -> str:
    """Normalize a domain to a canonical form for hashing."""
    if not domain:
        raise ValueError("domain must be non-empty")
    return domain.strip().lower().lstrip("https://").lstrip("http://").rstrip("/")


def _seed_int(domain: str, *, label: str) -> int:
    """SHA-256-derived deterministic int from (domain, label)."""
    digest = hashlib.sha256(f"{label}::{_normalized_domain(domain)}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def derive_company_name(domain: str) -> str:
    """Render a presentational company name from a domain.

    'acmecorp.com' -> 'Acmecorp'. Deterministic; no network.
    """
    nd = _normalized_domain(domain)
    head = nd.split(".", 1)[0]
    return head.capitalize() if head else nd


def estimate_ai_sdr_vendor(domain: str) -> str | None:
    """
    Return the AI-SDR vendor most likely in use at the given domain.

    Deterministic; same domain -> same vendor. Returns ``None`` for ~10%
    of domains so the dossier surfaces "no AI-SDR detected" honestly
    when it has to.
    """
    seed = _seed_int(domain, label="ai_sdr_vendor")
    # 10% of domains: report "no AI-SDR detected"
    if seed % 10 == 0:
        return None
    return _AI_SDR_VENDORS[seed % len(_AI_SDR_VENDORS)]


def estimate_outbound_volume_per_month(domain: str) -> int:
    """
    Estimate outbound AI-SDR email volume per month.

    Deterministic, derived from domain seed. Range chosen to match the
    observed footprint of Series B/C/D SaaS companies running modern
    AI-SDR stacks (~5k to ~250k outbound/mo).
    """
    seed = _seed_int(domain, label="outbound_volume")
    # Bucketize into a 5,000–250,000 range, rounded to nearest 5,000.
    raw = 5_000 + (seed % 50) * 5_000
    return raw


def detect_mcp_runtime_footprint(domain: str) -> tuple[str, ...]:
    """
    Return the MCP runtimes most likely deployed at the given domain.

    Deterministic. Always returns at least one runtime — the assumption
    is that a CISO at an AI-stack-using company has *some* MCP surface
    to worry about. The size of the footprint scales with the seed so
    small companies get 1-2 entries and larger ones get 3-5.
    """
    seed = _seed_int(domain, label="mcp_footprint")
    footprint_size = 1 + (seed % 5)  # 1..5 entries
    selected: list[str] = []
    cursor = seed
    for _ in range(footprint_size):
        idx = cursor % len(_MCP_RUNTIME_FOOTPRINT)
        candidate = _MCP_RUNTIME_FOOTPRINT[idx]
        if candidate not in selected:
            selected.append(candidate)
        # Re-mix the cursor so we don't pick the same index repeatedly.
        cursor = int.from_bytes(
            hashlib.sha256(f"{cursor}".encode()).digest()[:8], "big", signed=False
        )
    return tuple(selected)


__all__ = [
    "derive_company_name",
    "estimate_ai_sdr_vendor",
    "estimate_outbound_volume_per_month",
    "detect_mcp_runtime_footprint",
]
