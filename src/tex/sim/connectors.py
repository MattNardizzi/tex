"""
connectors.py — wire the synthetic estate into the real discovery pipeline.

This mirrors ``tex.main._build_discovery_connectors`` but feeds the connectors
the estate generator's fixtures instead of ``demo_seed``. The connector logic,
reconciliation, ledger, and provenance are all untouched — only the data
source changes. This is the population seam.

To turn it on, the backend's ``_build_discovery_connectors`` gains a small
sandbox branch (see install_hint() for the exact snippet). With
``TEX_SANDBOX=1`` set, ``uvicorn tex.main:app`` boots watching Meridian
Financial, and the day-one ignition door maps 200 agents through the real
pipeline.
"""

from __future__ import annotations

import os

from tex.sim.estate import (
    Estate,
    cloudtrail_records,
    entra_pages,
    generate_estate,
    mcp_clients,
)


def estate_from_env() -> Estate:
    """Build the estate the running backend should watch, from env."""
    seed = int(os.environ.get("TEX_SANDBOX_SEED", "7"))
    idp = int(os.environ.get("TEX_SANDBOX_IDP_AGENTS", "170"))
    shadow = int(os.environ.get("TEX_SANDBOX_SHADOW_AGENTS", "30"))
    mcp = int(os.environ.get("TEX_SANDBOX_MCP_AGENTS", "0"))
    return generate_estate(seed=seed, idp_agents=idp, shadow_agents=shadow, mcp_agents=mcp)


def build_sandbox_connectors(estate: Estate | None = None) -> list:
    """
    Construct the connector list bound to the synthetic estate. Same connector
    classes the live path uses; only the transports carry estate fixtures.
    """
    est = estate or estate_from_env()

    from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
    from tex.discovery.connectors.cloud_audit_ocsf import OcsfAuditConnector
    from tex.discovery.connectors.mcp_server import MCPServerConnector
    from tex.discovery.graph_transport import FixtureGraphTransport

    connectors: list = [
        EntraConsentGraphConnector(transport=FixtureGraphTransport(entra_pages(est))),
        OcsfAuditConnector(source=lambda ctx: cloudtrail_records(est), source_format="cloudtrail"),
    ]
    mcp_records = mcp_clients(est)
    if mcp_records:
        try:
            connectors.append(MCPServerConnector(records=mcp_records))
        except TypeError:
            connectors.append(MCPServerConnector())
    return connectors


def install_hint() -> str:
    """The exact snippet to drop into tex.main._build_discovery_connectors."""
    return (
        "    # --- SANDBOX: watch a synthetic estate through the real pipeline ---\n"
        "    import os\n"
        "    if os.environ.get('TEX_SANDBOX') == '1':\n"
        "        from tex.sim.connectors import build_sandbox_connectors\n"
        "        return build_sandbox_connectors()\n"
    )
