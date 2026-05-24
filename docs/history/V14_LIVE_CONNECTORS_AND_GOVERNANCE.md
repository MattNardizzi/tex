# V14 — Live Connectors + Dual-Source Governance Endpoint

## Summary

V13 shipped the discovery architecture: a reconciliation engine, a
hash-chained discovery ledger, six mock connectors, and the fusion
binding that folds discovery provenance into the cryptographic
evidence chain. What V13 did not ship was a way to actually pitch
this to a buyer: the connectors were mocks, and there was no single
endpoint that answered the question every CISO asks first —
*"out of every agent in my environment, which ones are actually
under your governance?"*

V14 closes both gaps.

## What V14 ships

### 1. Two live connectors (real APIs, no SDK dependencies)

- **`OpenAIAssistantsLiveConnector`** (`tex.discovery.connectors.openai_live`)
  - Calls `GET /v1/assistants` against the OpenAI API
  - Pagination via `last_id` cursor
  - Optional `OpenAI-Organization` and `OpenAI-Project` headers
  - Risk classification identical to the mock (`code_interpreter +
    function = CRITICAL`, etc.)
  - Uses `urllib` only — no new dependencies

- **`SlackLiveConnector`** (`tex.discovery.connectors.slack_live`)
  - Combines `users.list` (paginated, filtered to `is_bot=true`)
    with `admin.apps.approved.list` to get OAuth scopes per bot
  - Graceful degradation when admin scopes are missing — bots still
    appear, with empty `scopes` and LOW risk band
  - Risk classification: `admin → CRITICAL`,
    `write + sensitive_read → HIGH`, `write only → MEDIUM`,
    read-only → `LOW`
  - Slack rate-limit responses (`error: ratelimited`) raise
    `ConnectorTimeout`, recorded as a structured scan error

### 2. New `SlackConnector` mock for parity

The mock connector matches the live one's shape and risk taxonomy
exactly. Tests that run against fixtures get the same
`CandidateAgent` shape that production gets against the live API.
This is what makes mock-to-live a class swap rather than a rewrite.

### 3. Env-var-based connector wiring

`tex.main._build_discovery_connectors` now constructs the connector
list from environment variables:

```
TEX_DISCOVERY_OPENAI_API_KEY    → OpenAIAssistantsLiveConnector
TEX_DISCOVERY_OPENAI_ORG        → optional org header
TEX_DISCOVERY_OPENAI_PROJECT    → optional project header

TEX_DISCOVERY_SLACK_TOKEN       → SlackLiveConnector
TEX_DISCOVERY_SLACK_TEAM_ID     → optional, scope to one workspace
```

When credentials are missing, the corresponding mock is wired
instead. When a live connector fails to construct (bad token, bad
URL), the failure is logged and the system falls back to the mock
for that source so a single broken credential cannot take down
discovery.

### 4. Dual-source governance-state endpoint

```
GET /v1/agents/governance
```

Returns the four-state matrix that joins external observation with
adjudication evidence:

| State      | Externally observed | Adjudicated | Meaning                        |
|------------|---------------------|-------------|--------------------------------|
| GOVERNED   | yes                 | yes         | Seen + evidence chain          |
| UNGOVERNED | yes                 | no          | Seen but bypassing Tex (alert) |
| PARTIAL    | no                  | yes         | Adjudicated, no corroboration  |
| UNKNOWN    | no                  | no          | Residual blind spot            |

Response shape:

```json
{
  "counts": {
    "total_agents": 18,
    "governed": 6,
    "ungoverned": 9,
    "partial": 2,
    "unknown": 1,
    "high_risk_total": 4,
    "high_risk_ungoverned": 3,
    "governed_with_forbids": 1
  },
  "agents": [
    {
      "agent_id": "...",
      "discovery_source": "slack",
      "external_id": "B0LANXQ001",
      "reconciliation_key": "slack:acme:b0lanxq001",
      "name": "Support Bot",
      "tenant_id": "acme",
      "owner": "ops@acme.com",
      "risk_band": "HIGH",
      "governance_state": "UNGOVERNED",
      "externally_observed": true,
      "adjudicated": false,
      "decision_count": 0,
      "forbid_count": 0,
      "last_decision_at": null,
      "last_seen_externally_at": "2026-04-15T12:00:00Z",
      "discovery_mode": null
    }
    // ...
  ],
  "coverage_root_sha256": "...",
  "signature_hmac_sha256": "...",
  "generated_at": "2026-04-30T21:19:00Z"
}
```

The response is signed with the same HMAC machinery as the per-agent
evidence summary, so a regulator can verify that a snapshot covered
exactly the set of agents claimed.

#### Ghost rows

Candidates that were observed by an external connector but
*not* registered (held for ambiguity, below confidence threshold,
admin-scope unbounded surface) appear as ghost rows with
`agent_id: null`. These are the cleanest UNGOVERNED examples — the
buyer's environment contains an agent Tex chose not to auto-promote,
which is exactly the "what's bypassing my controls" report security
teams want.

### 5. The architectural property V14 establishes

V13 made discovery and runtime governance share one record. V14
makes that record *legible*. The governance matrix is something
Zenity and Noma cannot produce: their discovery output is an
inventory and their content security output is firewall logs, and
the two are not joined. Tex's are. The endpoint is the single line
of code that proves it.

## Tests

V14 ships 34 new tests across three files:

- `tests/test_discovery_slack_connector.py` — 10 tests for the Slack mock
- `tests/test_discovery_live_connectors.py` — 16 tests for the live
  OpenAI and Slack connectors, covering HTTP construction,
  pagination, error paths, rate limiting, and graceful degradation
- `tests/test_governance_endpoint.py` — 8 tests covering all four
  governance states, ghost rows, determinism of the coverage root
  hash, and the high-risk metric breakdown

Total test count: 470 (436 baseline + 34 new), all passing.

## What V14 is not

V14 does not migrate the agent registry or discovery ledger to
Postgres. Both remain in-memory. The governance endpoint reads from
in-memory stores at request time, which is fine for the volumes a
pilot will see; the moment you have a customer with thousands of
agents, swap `InMemoryAgentRegistry` and `InMemoryDiscoveryLedger`
for Postgres-backed implementations behind the same interfaces. The
governance computation is pure over those reads, so nothing else
changes.

## Sequence

1. ✅ adjudication-derived discovery wired (V13)
2. ✅ external connector framework + mocks (V13)
3. ✅ governance-state endpoint
4. ✅ live OpenAI connector
5. ✅ live Slack connector
6. ⏳ Postgres-backed registry + ledger
7. ⏳ Whitepaper with real output from a pilot tenant
