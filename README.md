# Tex

Tex is the evidence-grade adjudication layer for AI agent outputs.
It evaluates a content+context payload through a six-layer pipeline
(deterministic → retrieval → specialists → semantic → router →
evidence) and returns a `PERMIT` / `ABSTAIN` / `FORBID` verdict
with a SHA-256 hash-chained, HMAC-signed evidence record.

The product is positioned against OWASP ASI 2026 as the reference
adjudicator for regulated outbound AI content. Everything Tex
emits is reproducible from the durable record: inputs, scores,
findings, the policy version that produced the verdict, and the
chain link to every prior decision.

---

## What's in this repo

- `src/tex/` — the FastAPI service and its domain, store, and engine code
- `tex-frontend/` — the React/Vite frontend (Tex Arena, dashboards, run pages)
- `tests/` — 720 tests covering deterministic, retrieval, specialists,
  semantic, router, evidence, learning/drift, discovery, governance,
  enforcement, agent governance, and the V18 production-readiness suite
- `scripts/` — local runners and smoke tests
- `sdks/` — language-specific client SDKs

---

## Quickstart (local development)

```bash
# 1. Install
pip install -r requirements.txt

# 2. Copy env template
cp .env.example .env

# 3. Run the API on http://localhost:8000
make run        # or: uvicorn tex.main:create_app --factory --reload

# 4. Run the test suite (target: 720 passed)
make test       # or: python -m pytest tests/ -q
```

The runtime starts in pure in-memory mode when `DATABASE_URL` is
unset and logs one warning per durable store. This is intentional
for local development — it boots in seconds with zero infra. For
production, see `DEPLOYMENT.md`.

---

## Honest test pass count

```
$ make test
720 passed in ~22s
```

This is the verifiable pass count from a clean install. If your local
run hangs, check that `psycopg[binary]` and `asyncpg` are both
installed — see `requirements.txt`.

---

## Architecture in one paragraph

A request enters through `/v1/guardrail` (or one of the gateway
adapters), gets normalized into an `EvaluationRequest`, and runs
through the `PolicyDecisionPoint`. The PDP fans out to the
`RetrievalOrchestrator` (policy clauses, precedents, sensitive
entities), the deterministic regex layer, the specialist judges
(brand, compliance, capability, ASI), the semantic layer (LLM-driven
risk scoring), and the agent suite (identity, capability, behavioral
baseline). The `Router` fuses every signal into a `final_score` and
issues a verdict. The `EvaluateActionCommand` writes the durable
`Decision`, appends the action ledger entry, updates the tenant
content baseline, and records the evidence chain link. Outcomes
reported back via `/outcomes` flow into the learning orchestrator,
which produces calibration proposals — never auto-applied.

---

## Production readiness

See `DEPLOYMENT.md` for the deployment guide. The short version:

- **Persistence:** set `DATABASE_URL` to enable Postgres-backed durable
  stores for decisions, policies, precedents, agents, action ledger,
  evidence, outcomes, governance snapshots, drift events, scan runs,
  connector health, and calibration proposals.
- **Auth:** set `TEX_REQUIRE_AUTH=1` and `TEX_API_KEYS=...` to force
  every route to require a valid scoped key.
- **Evidence integrity:** set `TEX_EVIDENCE_HMAC_SECRET` to a stable
  random secret. Rotate only with a documented re-signing procedure.
- **Learning gate:** calibration proposals are NEVER auto-applied.
  Apply requires an explicit human approver via `POST
  /v1/learning/proposals/{id}/approve`. There is a guard test
  (`test_no_auto_apply_codepaths_in_learning_layer`) that fails CI
  if anyone introduces an auto-apply hook.

---

## License

Proprietary. © VortexBlack. All rights reserved.
