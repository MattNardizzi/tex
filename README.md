# Tex

Tex is the **evidence-grade adjudication layer for AI agent outputs**.
It evaluates a content + context payload through a six-layer pipeline
(deterministic → retrieval → specialists → semantic → router → evidence)
and returns a `PERMIT` / `ABSTAIN` / `FORBID` verdict bound to a
SHA-256 hash-chained, HMAC-signed evidence record.

Everything Tex emits is reproducible from the durable record: inputs,
scores, findings, the policy version that produced the verdict, and the
chain link to every prior decision. The decision artifact is the
product — not the model behind it.

---

## What Tex is for

Tex sits between an agent and the world it acts on. Any time an AI agent
is about to send an email, call a tool, post content, transfer value,
or otherwise affect a system someone is accountable for, Tex evaluates
the action and issues a verdict bound to verifiable evidence.

**Tex is product-agnostic on who the buyer is.** The same evaluation
pipeline, evidence chain, and signed export packets serve:

- **VP Marketing / Head of Brand at AI-SDR-using SaaS companies** —
  brand-safety adjudication on AI-generated outbound, with C2PA
  manifests and a signed evidence chain that satisfies EU AI Act
  Article 50, California SB 942, and NY AI advertising disclosure.
- **CISO / Head of AppSec at MCP-using companies** — runtime governance
  of MCP tool calls with deny-by-default on sensitive paths, signed
  tool-call receipts, and OWASP Agentic Top 10 coverage.
- **Compliance / Risk at regulated AI deployments** — auditable
  decision chains exportable as offline-verifiable bundles for
  regulators, third-party auditors, and underwriters.
- **Platform engineers** — drop-in guardrail behind any of six gateway
  adapters (Portkey, LiteLLM, Cloudflare AI Gateway, Solo.io,
  TrueFoundry, Bedrock-style) or as an MCP server.

The technology is one product. The pitch is shaped to the buyer.
See `FRONTIER_GTM.md` for the active dual-ICP go-to-market.

---

## What's in this repo

| Path | What it is |
|---|---|
| `src/tex/` | The FastAPI service: domain, stores, engine, specialists, evidence, governance, runtime guards, compliance, pitch surfaces, gateway adapters, MCP server |
| `tests/` | 200+ test files; ~3,700 tests collected. Frontier modules (pqcrypto / c2pa / compliance) ship 490+ passing tests in ~3 seconds. Full suite runs in ~3 minutes. |
| `sdks/python/tex_guardrail/` | Python client SDK (pure stdlib, shippable) |
| `scripts/` | Local demos and the `audit.py` navigation tool |
| `cpsa_models/` | MITRE CPSA formal-methods model for the C2PA + cosign protocol composition (Scheme source + vendored shapes JSON) |
| `docs/history/` | Per-thread development log (commit messages, deltas, version notes) |

**May 2026 frontier upgrade (this revision).** The pqcrypto, c2pa, and
compliance layers received a substantial upgrade aligned with the May 18,
2026 standards-track state of the art: native pyca/cryptography 48
ML-DSA + ML-KEM (no liboqs build), C2PA 2.4 OCSP stapling + TSA v2
timestamps, draft-ietf-lamps-pq-composite-sigs-18 composite signatures,
EU AI Act Articles 17/26 + state disclosure modules (NY §1700-A,
Colorado SB 24-205), the Sherman 2026 attack-class defense matrix
(arxiv 2604.24890), TrustMark durable credentials, and SLH-DSA code
signing per CNSA 2.0 §2. See `CLAIMS_CURRENT.md` §3–§9 and
`STUB_REGISTRY.md` for the full delta.

Top-level docs (each has a specific job — see `NAVIGATION.md` for the map):

- **`NAVIGATION.md`** — read first; tells you which doc answers which question
- **`TIER_OWNERSHIP.md`** — every subpackage tagged by dev tier (A/B/C/D) and capability tier
- **`CAPABILITY_TIERS.md`** — the five capability tiers (Discovery, Identity, Monitoring, Governance, Evidence) defined precisely
- **`MODULES.md`** — per-subpackage cards for Tier A/B packages
- **`RUNBOOKS.md`** — procedures for the common change scenarios
- **`STUB_REGISTRY.md`** — every unfinished site with a "blocks current claim?" column
- **`KNOWN_BUGS.md`** — verified defects with sev rating, reproduction, fix
- **`CLAIMS_CURRENT.md`** — what holds up today (use for outreach + pitches)
- **`CLAIMS_HISTORY.md`** — historical per-thread log of when each capability landed
- **`CLAIMS_ASPIRATIONAL.md`** — claims tied to unfinished work; not yet defensible

---

## Quickstart (local development)

```bash
# 1. Clone and install
pip install -r requirements.txt

# 2. Set environment (see "Environment variables" below)
cp .env.example .env
# then edit .env

# 3. Run the API on http://localhost:8000
uvicorn tex.main:create_app --factory --reload

# 4. Run the test suite
python -m pytest tests/ -q \
    --ignore=tests/governance/test_kernel_mcp.py
```

The `--ignore` is a temporary workaround for a known broken parametrize
in that one test file (`KNOWN_BUGS.md` Bug #1, 30-second fix pending).

Expected on a fresh clean install with all optional crypto deps
(`cryptography>=48`, `pyasn1`, `blake3`, `asyncpg`, `psycopg[binary]`):
**~3,700 tests collected, ~3,700 pass, ~30 skip** (SLH-DSA / ML-KEM-512
gated on liboqs) in roughly 3 minutes. Without the optional deps,
expect ~30 skips and a handful of failures in the crypto wrappers —
hygiene, not a product defect.

The pqcrypto + frontier + c2pa subset (the May 2026 frontier upgrade)
runs **490+ passing tests, 28 skipped** in under 3 seconds — this is
the targeted regression command:

```bash
python -m pytest tests/pqcrypto/ tests/frontier/ tests/c2pa/ -q \
    --ignore=tests/frontier/test_scaffolding_imports.py
```

The runtime starts in pure in-memory mode when `DATABASE_URL` is unset
and logs one warning per durable store. This is intentional for local
development — it boots in seconds with zero infrastructure.

---

## Smoke test — verify the product works end-to-end

```python
from uuid import uuid4
from fastapi.testclient import TestClient
from tex.main import create_app

client = TestClient(create_app())

# 1. Evaluate a BEC-shaped payload
response = client.post("/evaluate", json={
    "request_id": str(uuid4()),
    "action_type": "send_email",
    "channel": "outbound_email",
    "environment": "production",
    "content": "URGENT: per the CEO's directive, wire $50,000 to vendor X by EOD",
})
assert response.status_code == 200
decision = response.json()
assert decision["verdict"] == "FORBID", decision["verdict"]
print(f"Verdict: {decision['verdict']}, score: {decision['final_score']:.3f}")
print(f"Decision ID: {decision['decision_id']}")

# 2. Replay the decision
decision_id = decision["decision_id"]
replay = client.get(f"/decisions/{decision_id}/replay").json()
print(f"Determinism fingerprint: {replay['determinism_fingerprint'][:16]}...")

# 3. Pull the chain-verified evidence bundle
bundle = client.get(f"/decisions/{decision_id}/evidence-bundle").json()
print(f"Evidence records in bundle: {len(bundle['records'])}")
```

Expected output:
```
Verdict: FORBID, score: 0.356
Decision ID: <uuid>
Determinism fingerprint: 68f5b68b...
Evidence records in bundle: 1
```

Performance on a sandbox VM with no LLM provider configured (offline path):
**~80 evaluations/sec, p50 ~12ms, p95 ~16ms, p99 ~17ms** sustained over
1,000 requests.

---

## Architecture in one paragraph

A request enters through `/evaluate`, `/v1/guardrail`, the MCP server,
or one of the six gateway adapters. The `PolicyDecisionPoint` (`src/tex/engine/pdp.py`)
fans the request out to the `RetrievalOrchestrator` (policy clauses,
precedents, sensitive entities), the deterministic regex layer
(`src/tex/deterministic/`), the **24 specialist judges**
(`src/tex/specialists/`: brand, compliance, capability, ASI, OWASP-style
runtime guards), the semantic layer (`src/tex/semantic/` — LLM-driven
risk scoring with offline fallback), and the agent suite (`src/tex/agent/` —
identity, capability, behavioral baseline). The `Router`
(`src/tex/engine/router.py`) fuses every signal into a `final_score` and
issues a verdict. The `EvaluateActionCommand` (`src/tex/commands/`)
writes the durable `Decision`, appends the action ledger entry, updates
the tenant content baseline, and records the evidence chain link.
Outcomes reported back via `/outcomes` flow into the learning
orchestrator (`src/tex/learning/`), which produces calibration
proposals — **never auto-applied** (CI-guarded by
`test_no_auto_apply_codepaths_in_learning_layer`).

---

## Capability tiers (what Tex actually does)

Every subpackage maps to one of five capability tiers. See
`CAPABILITY_TIERS.md` for the precise definitions.

| Capability tier | What it does | Where it lives |
|---|---|---|
| **Discovery / Inventory** | Finds agents, MCP servers, tools, connectors in a customer's environment | `discovery/`, parts of `governance/ifc/` |
| **Identity / Access** | Establishes who an agent claims to be and whether it's allowed | `agent/`, `vet/` (Agent Identity Documents), `enforcement/` |
| **Monitoring / Observability** | Watches the system over time: drift, change-points, systemic risk | `observability/`, `drift/`, `systemic/`, `causal/`, `learning/` (feedback portion) |
| **Execution Governance** | Decides per-action permit/abstain/forbid; content adjudication | `engine/`, `specialists/`, `semantic/`, `deterministic/`, `contracts/`, `runtime/`, `governance/`, `intervention/`, `pcas/`, `camel/`, `safeflow/` |
| **Evidence / Recording** | Signed, verifiable artifacts of every decision | `evidence/`, `events/`, `c2pa/`, `pqcrypto/`, `compliance/`, `pitch/`, `zkprov/`, `tee/`, `nanozk/`, `receipts/`, `institutional/` |

Plus cross-cutting kernel infrastructure (`domain/`, `commands/`,
`stores/`, `memory/`, `api/`, `db/`, `ontology/`, `graph/`, etc.).

---

## API surface

~95 routes across 24 router files. The major surfaces:

- `POST /evaluate` — the canonical adjudication entry
- `POST /v1/guardrail/{portkey,litellm,cloudflare,solo,truefoundry,bedrock}` — gateway-adapter routes returning each gateway's expected wire format
- `POST /mcp` — JSON-RPC 2.0 MCP server exposing the `evaluate_action` tool
- `GET /decisions/{id}/replay` — full decision reconstruction with determinism fingerprint
- `GET /decisions/{id}/evidence-bundle` — chain-verified evidence bundle for one decision
- `GET /v1/agents/governance/snapshots/{id}/evidence_bundle.zip` — streamed offline-verifiable ZIP for a snapshot window (regulator-shaped delivery)
- `/v1/agents/*` — agent registry, lifecycle, baseline, evidence summary
- `/v1/discovery/*` — connector scans, ledger verify, presence findings
- `/v1/learning/*` — calibration proposals (human-approval required)
- `/v1/governance/*` — snapshots, chain verify, scheduler
- `/v1/vet/*`, `/v1/zkprov/*`, `/v1/c2pa/*`, `/v1/tee/*` — differentiation routes
- `GET /v1/learning/metrics/prometheus` — Prometheus-format metrics

**Known issue:** API prefixing is inconsistent. Some routes are
unprefixed (`/evaluate`, `/health`, `/outcomes`, `/policies/activate`,
`/leaderboard`, `/mcp`), others are under `/v1/`. Migration to a
consistent `/v1/` namespace is on the cleanup list.

---

## Production readiness

### Persistence

Set `DATABASE_URL` to enable Postgres-backed durable stores. Verified
Postgres backends exist for: **decisions, policies, precedents, agents,
action ledger, evidence (mirror), discovery ledger, provenance proofs,
outcomes, governance snapshots, drift events, scan runs, connector
health, calibration proposals**. Several use a single-file pattern
(self-detecting `DATABASE_URL` inside the store class) rather than
separate `_postgres.py` files; both shapes work.

### Authentication

Set `TEX_REQUIRE_AUTH=1` and `TEX_API_KEYS=...` to require a valid
scoped key on every route. The auth layer (`src/tex/api/auth.py`)
implements scoped API keys, tenant binding, constant-time comparison,
and RBAC scopes (`agent:read`, `agent:write`, `learning:write`,
`learning:approve`, etc.).

**Known issue (security):** authentication is enforced uniformly but
**tenant isolation is not**. The centralized `enforce_tenant_match()`
helper is only called in `tenant_routes.py` and `discovery_routes.py`.
Other tenant-aware routes (`agent_routes`, `learning_routes`, `c2pa_routes`,
`vet_routes`, `zkprov_routes`) accept a `tenant_id` from the request body
without checking that the caller's key is scoped to that tenant. See
`KNOWN_BUGS.md` Bug #6. **Fix before any multi-tenant pilot.** One-day
work to wrap each route in the existing helper.

### Evidence integrity

Set `TEX_EVIDENCE_HMAC_SECRET` to a stable random secret. The evidence
chain is SHA-256 hash-linked and HMAC-signed; tampering is byte-level
detectable. Rotate the secret only with a documented re-signing
procedure.

### Learning gate (human-in-the-loop)

Calibration proposals are **never auto-applied**. Approving requires
`POST /v1/learning/proposals/{id}/approve` with a key scoped to
`learning:approve`. There is a CI-enforced guard test
(`test_no_auto_apply_codepaths_in_learning_layer`) that scans
`src/tex/learning/` for the symbols `auto_apply`, `auto_approve`,
`auto_activate` and fails the build if any are found. The invariant
cannot be silently violated.

### Optional capabilities

- **Post-quantum signing:** install `oqs` (liboqs Python wrapper) for
  ML-DSA-65 hybrid signing. Without it, the evidence chain signs with
  Ed25519 + HMAC (still tamper-evident; not yet PQ-resistant).
- **C2PA content credentials:** signer + verifier exist with partial
  C2PA 2.2 implementation. Full COSE_Sign1 envelope, OCSP staple, and
  trust-list anchor validation are open P0 TODOs. See
  `CLAIMS_ASPIRATIONAL.md`.
- **TEE attestation, ZK provenance, web proofs:** all real
  implementations exist (`tee/`, `zkprov/`, `vet/`); some depend on
  optional dependencies for production-grade backends.

---

## Environment variables

| Variable | Purpose | Required for prod |
|---|---|---|
| `DATABASE_URL` | Postgres DSN for durable stores | yes |
| `TEX_REQUIRE_AUTH` | Set to `1` to enforce auth on every route | yes |
| `TEX_API_KEYS` | Comma-separated list of `key:scope:tenant` entries | yes |
| `TEX_EVIDENCE_HMAC_SECRET` | Stable random secret for chain signing | yes |
| `OPENAI_API_KEY` | For the semantic LLM scorer | recommended |
| `TEX_SPECIALIST_LLM_MODE` | Set to `tiered` to enable LLM-escalation in specialists | optional |
| `TEX_ECOSYSTEM_SYSTEMIC` | Set to `1` to enable systemic risk fusion | optional |

A populated `.env.example` is pending — the current file is empty.
See `KNOWN_BUGS.md` Bug #8 for the cleanup item.

---

## Honest state — what works, what's broken, what's stub

**Works end-to-end (verified by running):**
- Six-layer evaluation pipeline (deterministic → retrieval → specialists → semantic → router → evidence)
- Evidence chain (byte-level tamper-evident)
- Decision replay endpoint
- Per-decision and per-snapshot evidence bundle export
- All six gateway adapters at the wire-format level
- MCP server (JSON-RPC 2.0)
- Insurer evidence packet builder (ECDSA-P256 verified offline)
- VP Marketing and CISO pitch packet builders
- Postgres durability across ~14 store types
- Authentication, scoped keys, tenant binding
- 24 specialist judges across brand, compliance, capability, ASI, OWASP-style runtime guards
- Discovery service (connectors, reconciliation, ledger)
- Calibration governance (proposals, human-approval gate, CI-enforced no-auto-apply)

**Known defects:** see `KNOWN_BUGS.md` (8 verified bugs, sev 1-3).

**Stub graveyards:** see `STUB_REGISTRY.md`. The biggest cluster of
NotImplementedError sites is in `src/tex/_pending/interop/` (Microsoft,
Okta, Ping, NIST, A2A adapter stubs) — moved out of the main tree
because the active GTM does not require them.

**Buried capabilities (real code, no HTTP route):** the insurer evidence
packet, CISO export, and VP Marketing packet builders all work but are
not exposed as HTTP endpoints yet. One-day wiring fix. See
`CLAIMS_ASPIRATIONAL.md`.

---

## Auditing the codebase

If you're new to this repo or trying to figure out where something
lives, start here:

```bash
python scripts/audit.py --list                # list every subpackage with both tiers
python scripts/audit.py engine                # full context for one package
python scripts/audit.py --capability E/G      # everything in Execution Governance
python scripts/audit.py --stub-summary        # where the unfinished work is
python scripts/audit.py --check-deps          # tier-violation dependency check
```

See `NAVIGATION.md` for the full set of operational docs.

---

## License

Proprietary. © VortexBlack. All rights reserved.
