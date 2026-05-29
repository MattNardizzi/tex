# Layer 2 — Identity / Access

> **Working doc.** Per-agent identity, capability, and behavioral evaluation.

## What this layer does

For every evaluation request that includes an `agent_id`, this layer answers three questions about the agent in parallel:

1. **Identity** — who is this agent? Trust tier, attestation status, lifecycle state.
2. **Capability** — what is this agent permitted to do? Does the requested action/channel/recipient fall inside its declared capability surface?
3. **Behavioral** — how has this agent behaved historically? Is the current request a deviation from its baseline?

These three streams (Streams 3, 4, 5 of the seven-stream PDP) collapse to neutral when no agent is present. When present, they contribute to the routing fusion alongside the four content streams.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `src/tex/agent/` | 5 | ~1,093 | WIRED |
| `src/tex/stores/agent_registry.py` + `_postgres.py` | 2 | ~600 | WIRED |
| `src/tex/api/agent_routes.py` | 1 | ~1,200 | WIRED |

## Key files

### The three evaluators
- `src/tex/agent/identity_evaluator.py` — Stream 3
- `src/tex/agent/capability_evaluator.py` — Stream 4
- `src/tex/agent/behavioral_evaluator.py` — Stream 5

### Bundles and types
- `src/tex/agent/bundle.py` — `AgentEvaluationBundle` combining the three stream outputs
- `src/tex/domain/agent.py` — `AgentRecord`, `AgentLifecycleState`, `TrustTier`, `AttestationStatus`
- `src/tex/domain/agent_signal.py` — `AgentSignal` (per-stream), `AgentEvaluationResult` (fused)

### Storage
- `src/tex/stores/agent_registry.py` — InMemory implementation
- `src/tex/stores/agent_registry_postgres.py` — Postgres implementation; swapped in when `DATABASE_URL` is set
- The registry indexes by `(tenant_id, agent_id)` and tracks lifecycle transitions in an embedded ledger.

### HTTP
`src/tex/api/agent_routes.py` exposes:
- `GET /v1/agents` — list
- `POST /v1/agents` — register
- `GET /v1/agents/{id}` — fetch
- `PATCH /v1/agents/{id}` — update
- `POST /v1/agents/{id}/lifecycle` — transition (e.g. PROVISIONED → ACTIVE → QUARANTINED)
- `GET /v1/agents/{id}/evidence_summary`
- `GET /v1/agents/{id}/history`
- `GET /v1/agents/{id}/ledger`
- `GET /v1/agents/{id}/baseline`
- `GET /v1/agents/governance` — aggregate
- `GET /v1/agents/systemic-risks` — cross-agent risks

## Current state

✅ Solid:
- All three evaluators wired into the PDP
- Lifecycle state machine with embedded ledger (every transition is hash-chained)
- Cold-start detection (new agents with no history don't get penalized for absent baseline)
- Forbid-streak tracking (consecutive FORBIDs flag the agent for review)
- Trust tier propagation (UNVERIFIED < SELF_ATTESTED < ATTESTED < QUORUM_ATTESTED)
- Per-tenant isolation
- Postgres durability

⚠ Watch:
- No external identity protocol integration today (DID, A2A signed agent cards, Okta agent identities). All identity is locally minted. The `_pending/interop/a2a/signed_agent_card.py` is the stub for that direction.

## Improvement vectors

### 1. External identity binding (high impact)
Today an `agent_id` is a free-form string. Customers want to bind it to a verifiable external identity:
- **DID-based identity** with signed Agent Cards (A2A v1.2)
- **Okta for AI Agents** — sync identities from Okta
- **mTLS client certs** for service-to-service agents

This is the single biggest credibility upgrade for the enterprise pitch.

### 2. Capability surface as a typed schema
Today capability fields are loosely typed (`allowed_actions: set[str]`, etc.). A stronger approach: capabilities as a structured schema (action × channel × recipient × resource pattern × time window) with formal subsumption — so policy authors can write "capability X is strictly less than capability Y."

### 3. Behavioral baselining with drift detection
The behavioral evaluator today is reactive (flags deviations). It could be predictive — given current trajectory, this agent is likely to violate policy X within N steps. The `drift/` package (Layer 4) has the math; wiring it into the behavioral evaluator is the integration work.

### 4. Cross-agent collusion detection
Per-agent behavioral evaluation is necessary but not sufficient. When agents A and B individually behave fine but their joint behavior is anomalous, today we miss it. The `systemic/` package (Layer 4) has digital-twin simulation; cross-link.

### 5. Continuous attestation
Today attestation status is a field. Real continuous attestation (TEE-backed, refresh every N minutes) would let the identity stream carry actual trust signal not just a token.

## Constraints

- The three evaluators must run independently and not share mutable state. They MAY share read-only context (the agent record).
- Each evaluator must produce an `AgentSignal` even when uncertain (with the appropriate `uncertainty_flags`). Never raise.
- Lifecycle transitions must be hash-chained into the agent registry's embedded ledger.
- Tenant isolation: the agent registry must never return an agent from a different tenant.

## Testing

```bash
pytest tests/test_agent_governance.py tests/test_governance_endpoint.py tests/test_governance_history_routes.py tests/test_governance_snapshots.py
```

## Cross-layer touch points

- **Reads from Layer 1** — discovery findings update the agent registry.
- **Feeds Layer 4** — the three streams are inputs to the PDP fusion.
- **Writes to Layer 5** — lifecycle transitions and evaluation results land in evidence records.
- **Feeds Layer 6** — outcome reports tagged with agent_id update the agent's baseline.
