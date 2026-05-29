# Layer 6 — Learning

> **Working doc.** The "close the loop" layer.

## What this layer does

Take ground-truth outcome reports from customers ("this PERMIT was wrong / this FORBID was wrong"), update reporter reputation, generate calibration proposals (proposed policy threshold adjustments), and route those proposals through a human-approval workflow before activation.

This is the layer that makes Tex **improve** rather than just enforce.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `src/tex/learning/` | 13 | 4,701 | WIRED |

## Key files

- `src/tex/learning/outcomes.py` — outcome ingestion. Validates the outcome shape, links to the decision, updates the decision store.
- `src/tex/learning/outcome_validator.py` — validates outcome reports (no orphan outcomes, no contradictory outcomes for the same decision).
- `src/tex/learning/outcome_trust.py` — per-reporter trust weighting.
- `src/tex/learning/reporter_reputation.py` — long-running reputation scoring. Reporters with high accuracy get higher weight on future calibration proposals.
- `src/tex/learning/calibration_proposal.py` — generates proposed policy threshold adjustments based on accumulated outcomes.
- `src/tex/learning/auth_resolver.py` — resolves authorization for who can approve/reject proposals.
- `src/tex/learning/feedback.py` — feedback aggregation.
- `src/tex/learning/drift.py` — drift detection over outcomes (also linked from Layer 3).
- `src/tex/learning/observability.py` — Prometheus-style metrics for the learning loop.
- `src/tex/learning/poisoning_detector.py` — detects coordinated bad-faith reporting (defends against gaming).

## HTTP endpoints

- `POST /v1/outcomes` — submit an outcome report
- `POST /v1/learning/proposals` — generate a calibration proposal
- `GET /v1/learning/proposals` — list pending proposals
- `GET /v1/learning/proposals/{id}` — fetch one
- `POST /v1/learning/proposals/approve` — human approval → activates the proposal
- `POST /v1/learning/proposals/reject`
- `POST /v1/learning/proposals/rollback`
- `GET /v1/learning/proposals/audit` — audit trail of every decision
- `GET /v1/learning/reputation` + `/{reporter}` — reputation queries
- `GET /v1/learning/metrics` + `/metrics/prometheus`
- `GET /v1/learning/alerts`
- `GET /v1/learning/health`

## Current state

✅ Solid:
- Full outcome → reputation → proposal → approval → activation loop
- Per-reporter reputation with decay
- Coordinated-poisoning detection
- Rollback support (activated proposal can be reverted, with full chain integrity)
- Prometheus-compatible metrics
- Postgres-durable proposal store

⚠ Watch:
- Calibration proposals today adjust threshold values. They don't propose **new policy clauses** or **new specialists**. The latter would require generating policy candidates, which is a different ML problem.
- Reputation is per-reporter; no concept of reporter affinity ("Alice is good at detecting PII leaks, bad at detecting plan-integrity failures"). Could be more granular.

## Improvement vectors

### 1. Policy clause synthesis (high impact, high effort)
Today proposals tune thresholds. The next step: when accumulated false-positives or false-negatives suggest a missing policy clause, **synthesize a candidate clause** and propose it. Uses the LLM judge to draft the clause, deterministic verification to sanity-check, then human approval.

### 2. Per-domain reporter reputation (medium impact, medium effort)
Track reporter accuracy by **specialty**. Alice's reputation for PII reports is independent of her reputation for MCP-injection reports. Lets the system weight reporters appropriately by topic.

### 3. Active learning (high impact, medium effort)
Today learning is passive — wait for outcomes to arrive. Active learning: identify decisions in the high-uncertainty zone (semantic confidence ~0.5) and **proactively request outcome reports** for those decisions. Maximizes information gain per outcome.

### 4. Counterfactual proposal generation (medium impact, high effort)
"What if we had set the FORBID threshold to 0.65 instead of 0.72 over the last 30 days?" Replay decisions against a candidate policy and report aggregate outcome distribution. Already exists in `replay/`; surfacing it as part of the proposal review is the upgrade.

### 5. Outcome-driven specialist re-weighting (medium impact, medium effort)
Each specialist has a fusion weight. Outcomes tell us which specialists are over- or under-weighted. Today this happens manually via calibration proposals; could be automated as a per-specialist weight proposal.

### 6. Cross-tenant transfer learning (high impact, hard — privacy minefield)
Patterns learned at one tenant could inform calibration at another. Must be done as aggregated, differentially-private updates only — no per-tenant data leakage.

### 7. Reputation portability (low impact, low effort)
Today reporter reputation is tenant-scoped. A SOC analyst working across tenants could carry signed reputation. Niche, but easy to add given Layer 5's signature infrastructure.

## Constraints

- **Every policy activation must be hash-chained.** Activating a calibration proposal updates the policy store AND writes an evidence record linking to the proposal AND its outcomes. No silent policy updates.
- **Human-in-the-loop is mandatory.** Calibration proposals MUST be reviewed before activation. There is no auto-apply path.
- **Outcomes are append-only.** An outcome submitted in error cannot be deleted; it can only be superseded by a corrective outcome that references it.
- **Reporter reputation cannot be reset.** Append-only too.
- **Poisoning detection runs every cycle.** Don't bypass it.

## Testing

```bash
pytest tests/test_outcomes.py tests/test_outcome_validator.py tests/test_outcome_trust.py tests/test_reporter_reputation.py tests/test_calibration_proposal_store.py tests/test_calibration_safety.py tests/test_feedback_loop.py tests/test_poisoning_detector.py tests/test_learning_auth_resolver.py tests/test_learning_observability.py
```

## Cross-layer touch points

- **Reads from Layer 4** — every decision is a potential subject of an outcome report
- **Writes to Layer 4** — activated calibration proposals update the policy store, which the PDP reads on next evaluation
- **Reads from Layer 2** — outcome reports tagged with agent_id update that agent's baseline
- **Writes to Layer 5** — every proposal and activation produces evidence
- **Feeds Layer 3** — drift detection and metrics aggregation
