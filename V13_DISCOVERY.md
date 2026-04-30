# V13 — Discovery: Closing the Upstream Half of Agent Governance

## Summary

V10 fused agent governance into the verdict. V11 added cross-agent
content baseline. V12 made enforcement physical end-to-end. V13
closes the upstream half of the governance loop: **finding the
agents in the first place**.

Before V13, Tex assumed the agent registry was complete: every agent
had been deliberately registered through `POST /v1/agents` before its
first action hit the gate. That assumption holds in greenfield
deployments. It does not hold in any organization that has already
deployed AI agents — which, as of 2026, is most of them. Microsoft
365 tenants accumulate Copilot Studio agents the way they accumulate
SharePoint sites. Salesforce orgs sprout Einstein bots and
Agentforce agents. AWS accounts have Bedrock agents in three
regions. Engineering teams install GitHub Copilot, hook Cursor to an
internal MCP server, and spin up OpenAI assistants — none of which
ever pass through anyone's identity provider.

V13 ships the discovery layer that finds those agents and feeds them
into the same fused evaluation pipeline as everything else.

## What V13 ships

### Core: `tex.discovery.DiscoveryService`

A single orchestrator that runs scans across every wired connector,
reconciles findings against the registry, and writes outcomes to a
hash-chained ledger.

```python
from tex.discovery import DiscoveryService
from tex.discovery.connectors import (
    MicrosoftGraphConnector,
    SalesforceConnector,
    AwsBedrockConnector,
    GitHubConnector,
    OpenAIConnector,
    MCPServerConnector,
)

# Wired automatically by build_runtime() with empty mock connectors.
# Live connectors that hit real APIs are drop-in replacements
# satisfying the same DiscoveryConnector Protocol.

result = runtime.discovery_service.scan(tenant_id="acme")
print(result.summary.registered_count)  # candidates promoted to PENDING
print(result.summary.quarantined_count)  # known agents whose surface drifted
print(result.summary.held_count)         # candidates held for operator review
```

### The seven connectors that ship in V13

Each translates one platform's view of "AI agents that exist here"
into the canonical `CandidateAgent` shape:

| Connector | Source | What it finds |
|-----------|--------|---------------|
| `MicrosoftGraphConnector` | `microsoft_graph` | Copilot Studio agents and OAuth-permissioned apps with Mail.Send / Files.ReadWrite.All / Directory.ReadWrite.All scopes |
| `SalesforceConnector` | `salesforce` | Agentforce agents and Einstein bots, with permission profile risk scoring |
| `AwsBedrockConnector` | `aws_bedrock` | Bedrock agents, action groups, knowledge bases, IAM role overprovisioning |
| `GitHubConnector` | `github` | Copilot seats and GitHub App installations with permission risk scoring |
| `OpenAIConnector` | `openai` | OpenAI Assistants with tool-type risk scoring (code_interpreter + function = CRITICAL) |
| `MCPServerConnector` | `mcp_server` | MCP servers and the agents (Cursor, Claude Desktop, Cline) connected to them |
| Generic | `generic` | Available as an extension surface for in-house custom platforms |

The connectors that ship are **mock implementations** — they encode
the shape of each platform's response so the architecture is
testable end-to-end without live cloud credentials. Each one has a
`replace_records()` method to inject fixture data, and a documented
implementation note describing the API call a live connector would
make to fetch real data. Replacing a mock with a live connector is a
single class swap; the rest of the discovery pipeline does not
change.

### The reconciliation engine

The `ReconciliationEngine` is the part of V13 that's structurally
different from competing products. Where Zenity and Noma's discovery
output is a dashboard, Tex's discovery output is a registry action.
Every candidate that crosses the auto-register threshold becomes one
of:

- **REGISTERED**: a new `AgentIdentity` lands in the registry with
  `lifecycle_status=PENDING`, the discovery metadata bound into its
  `metadata` bag. The next action this agent takes flows through the
  same fused decision as any other agent.
- **UPDATED_DRIFT**: the discovered surface is wider than the
  registered surface, but not enough to quarantine. The capability
  surface is updated.
- **QUARANTINED_FOR_DRIFT**: the discovered surface widened beyond
  the configured threshold. The agent transitions to `QUARANTINED`,
  which causes any subsequent evaluation against it to return
  ABSTAIN with `agent_quarantined` in the uncertainty flags.
- **NO_OP_KNOWN_UNCHANGED**: the candidate matches a registered
  agent and no surface drift was observed. The ledger still records
  the no-op so there's a continuous audit trail of when each agent
  was last confirmed.
- **NO_OP_BELOW_THRESHOLD**: confidence is too low to auto-promote.
  Held for operator review via the API.
- **HELD_AMBIGUOUS**: the connector reported an unbounded capability
  surface (e.g. tenant-wide write access). Auto-promotion is
  disabled in this case; operator review required.
- **SKIPPED_REVOKED**: the candidate matches a revoked agent.
  Revoke is terminal; rediscovery cannot revive it.

Two thresholds are configurable on `ReconciliationEngine`:

- `auto_register_threshold` (default 0.80): below this confidence,
  candidates are held instead of promoted.
- `quarantine_drift_threshold` (default 0.60): drift score below
  this updates the surface; above this quarantines the agent.

### The discovery ledger

The `InMemoryDiscoveryLedger` is an append-only, hash-chained store
of every reconciliation outcome. Each entry's `record_hash` covers
`payload_sha256 + previous_hash`, identical to the evidence chain
shape Tex uses for runtime decisions. `verify_chain()` recomputes
every hash and confirms the chain is intact.

This is the audit story for discovery: not just "we found these
agents," but "we found these agents in this exact order, and here is
the cryptographic proof that nothing was added or removed after the
fact." If a regulator asks "how did this AI agent end up authorized
to send email on behalf of your company?", you can replay the chain
and prove the answer.

### HTTP API

```
POST /v1/discovery/scan              run a scan now (synchronous)
GET  /v1/discovery/connectors        list wired connectors
GET  /v1/discovery/ledger            list ledger entries (paginated)
GET  /v1/discovery/ledger/verify     verify chain integrity
GET  /v1/discovery/findings/{key}    history for one reconciliation key
GET  /v1/discovery/agent/{agent_id}  history for one registered agent
```

## The architectural property V13 establishes

The point of V13 is not that Tex now does discovery. Many products
do discovery. The point is that discovery flows directly into the
same fused decision the rest of Tex makes, with no seam.

When a discovered agent's first action lands at the gate, the
identity stream populates `AgentIdentitySignal.discovery_source`,
`discovery_external_id`, and `discovery_risk_band` from the agent's
metadata. The determinism fingerprint folds those values into the
identity signature line **only when present**, so:

1. Agents registered manually (no discovery metadata) reproduce the
   exact V11 fingerprint, byte for byte. Backwards compatibility is
   strict.
2. Agents promoted by discovery carry the discovery provenance into
   the cryptographic evidence chain. The audit log captures *how*
   the agent ended up in the registry as well as *what* it has done
   since.

This is what Zenity and Noma cannot do: their discovery products
write to an inventory. Their content security products read from a
firewall. The two are not the same record. Tex's are.

## Tests

V13 ships 109 new tests across seven files:

- `tests/test_discovery_domain.py` — domain models and validation
- `tests/test_discovery_connectors.py` — all six connectors
- `tests/test_discovery_ledger.py` — hash-chain integrity and indexes
- `tests/test_discovery_reconciliation.py` — all eight decision branches
- `tests/test_discovery_service.py` — full scan flow integration
- `tests/test_discovery_routes.py` — HTTP API
- `tests/test_discovery_fusion_integration.py` — proves discovery
  provenance is bound into the determinism fingerprint, including the
  strict backwards-compatibility check that pre-discovery fingerprints
  are unchanged.

Total test count: 436 (327 baseline + 109 new), all passing.

## What V13 is not

V13 ships the architecture for discovery, not live cloud credentials.
The connectors are mocks that encode the shape of each platform's
response. A production deployment of V13 replaces the mocks with live
connectors that satisfy the same `DiscoveryConnector` Protocol. The
reconciliation engine, the ledger, the index, the API, the fusion
binding — all of those are real and exercised by the test suite. The
remaining work to ship live discovery against any one platform is
implementing one connector against that platform's SDK; the rest of
the discovery pipeline does not change.
