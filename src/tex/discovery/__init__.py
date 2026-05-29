"""
[Architecture: Layer 1 (Discovery)] — scan tenants for AI agents across OpenAI, Slack, AWS Bedrock, GitHub, Microsoft Graph, Salesforce, and MCP servers

See ARCHITECTURE.md for the full six-layer model.

Tex Discovery Layer.

The discovery layer answers the upstream half of agent governance:
"what agents exist in this organization that I have not been told
about?" It complements the runtime evaluation pipeline by feeding
discovered candidates into the agent registry, where they become
first-class participants in the same fused decision the rest of
Tex makes.

Public API:

  - DiscoveryService: orchestrator that runs scans
  - ReconciliationEngine: pure decision logic
  - ReconciliationIndex: reconciliation_key → agent_id map
  - DiscoveryScanResult: what a scan returns

Connectors live in tex.discovery.connectors. Mock implementations
ship in this repo; real connectors that hit live cloud APIs are
drop-in replacements that satisfy the DiscoveryConnector Protocol.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.discovery import __layer__, __layer_kind__`.
__layer__: int | None = 1
__layer_kind__: str = 'discovery'

from tex.discovery.reconciliation import (
    AUTO_REGISTER_THRESHOLD,
    QUARANTINE_DRIFT_THRESHOLD,
    ReconciliationDecision,
    ReconciliationEngine,
)
from tex.discovery.service import (
    DiscoveryScanResult,
    DiscoveryService,
    ReconciliationIndex,
)

__all__ = [
    "AUTO_REGISTER_THRESHOLD",
    "DiscoveryScanResult",
    "DiscoveryService",
    "QUARANTINE_DRIFT_THRESHOLD",
    "ReconciliationDecision",
    "ReconciliationEngine",
    "ReconciliationIndex",
]
