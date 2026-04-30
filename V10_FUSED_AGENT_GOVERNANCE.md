# V10 — Fused Agent Governance

## Summary

Tex now governs AI agents end-to-end. The four-layer content evaluation
engine (deterministic / retrieval / specialists / semantic) has been
unified with three new agent governance evaluation streams (identity /
capability / behavioral) into a single seven-stream fusion event that
produces one verdict, one fingerprint, and one evidence chain.

This is one cohesive system, not a content engine with a governance
plugin bolted onto it. Every Tex decision is now informed by who the
agent is, what it's authorized to do, how it has been behaving, and
what it just produced — fused at the moment of decision.

## Why this is different from Noma / Zenity

Noma and Zenity have a posture system that talks to a runtime system
through alerts and policy correlations. The seam between posture and
runtime is where they lose fidelity. Tex has no seam: agent posture,
agent capability, behavioral history, and content evaluation are peer
evidence streams in the same fusion router. The "did this sequence of
actions add up to something bad" question their stateful threat
engines try to answer post-hoc is asked structurally on every
evaluation, because every prior decision is in the agent's ledger,
the ledger feeds the behavioral stream, and the behavioral stream is
in fusion.

## What changed

### Domain layer
- **`tex.domain.agent`** — `AgentIdentity`, `CapabilitySurface`,
  `AgentAttestation`, `AgentLifecycleStatus` (PENDING/ACTIVE/QUARANTINED/REVOKED),
  `AgentTrustTier` (UNVERIFIED/STANDARD/TRUSTED/PRIVILEGED), `AgentEnvironment`,
  `ActionLedgerEntry`, `BehavioralBaseline`. All frozen Pydantic, all timezone-aware.
- **`tex.domain.agent_signal`** — `AgentIdentitySignal`, `CapabilitySignal`,
  `BehavioralSignal`, `AgentEvaluationBundle`. Each agent stream is a peer
  to the four content streams with the same shape: bounded risk, bounded
  confidence, structured findings, uncertainty flags.
- **`tex.domain.evaluation`** — `EvaluationRequest` gains optional
  `agent_id: UUID | None` and `session_id: str | None` fields. When omitted,
  Tex behavior reproduces pre-fusion exactly (verified by determinism fingerprint).
- **`tex.domain.policy`** — `PolicySnapshot.fusion_weights` now allows
  seven keys: the four content keys plus `agent_identity`, `agent_capability`,
  `agent_behavioral`. Default weights preserve content-layer ratios when
  renormalized for no-agent paths.
- **`tex.domain.latency`** — `LatencyBreakdown` gains an `agent_ms` stage.
- **`tex.domain.determinism`** — `compute_determinism_fingerprint` now folds
  agent stream signatures into the hash when the agent is present, and
  produces a fingerprint identical to pre-fusion when absent.

### Engine layer
- **`tex.agent.identity_evaluator`** — risk and confidence based on
  trust tier, lifecycle status, environment match, attestations, age.
  Quarantined agents force max identity risk; revoked agents are rejected
  upstream at the registry layer.
- **`tex.agent.capability_evaluator`** — structural risk based on
  declared capability surface. Out-of-surface action_type / channel /
  environment / recipient produce CRITICAL findings and a high risk score
  that the router routes to FORBID via standard fusion math.
- **`tex.agent.behavioral_evaluator`** — reads the per-agent action
  ledger and produces a deviation score relative to the agent's
  established behavioral baseline. Surfaces novel actions, novel
  channels, novel recipient domains, FORBID streaks, and capability
  violation rates. Cold-start agents return a low-confidence neutral
  signal with `cold_start` flag.
- **`tex.agent.suite.AgentEvaluationSuite`** — composes all three
  agent streams. Returns a neutral bundle when the request carries no
  agent context. Rejects revoked agents at request entry.
- **`tex.engine.router`** — rebuilt for seven-stream fusion. New
  helper `_effective_weights` renormalizes agent weights into content
  weights when no agent is present, preserving original four-layer
  ratios exactly. Verdict logic gains capability-violation FORBID,
  quarantine ABSTAIN, forbid-streak ABSTAIN, cold-start-on-borderline
  ABSTAIN, and PENDING-lifecycle ABSTAIN rules.
- **`tex.engine.pdp`** — calls the agent suite as a peer evaluation
  stream between retrieval and specialists. Threads `AgentEvaluationBundle`
  through routing, decision, response, and the determinism fingerprint.
  When no agent evaluator is wired, synthesizes a neutral bundle so
  unit tests bypassing the runtime continue to pass.

### Stores
- **`tex.stores.agent_registry`** — thread-safe in-memory registry
  with monotonic revisioning. `set_lifecycle` produces a new revision.
  `require_evaluable` rejects revoked agents.
- **`tex.stores.action_ledger`** — bounded per-agent ordered ledger.
  `compute_baseline` is a pure function returning a fresh
  `BehavioralBaseline` over the most recent N entries.

### Application layer
- **`tex.commands.evaluate_action`** — accepts an optional action
  ledger and writes a durable `ActionLedgerEntry` after every
  agent-attached decision. This is the feedback loop that lets the
  behavioral stream improve over time.

### API layer
- **`/v1/agents`** — register, list, get, patch, lifecycle-transition,
  history, ledger, baseline. Public DTOs in `tex.api.agent_routes`.
- **`/evaluate`** — `EvaluateRequestDTO` accepts `agent_id` and
  `session_id` for opt-in agent governance.

### Runtime
- **`tex.main.TexRuntime`** — composition root now builds and exposes
  `agent_registry`, `action_ledger`, and `agent_suite`, attaches them
  to FastAPI app state, and includes the agent router in the app.

## Backwards-compatibility contract

A request without `agent_id` produces a verdict, final score, and
determinism fingerprint that are bit-for-bit identical to what
pre-fusion Tex produced. This is enforced by:

1. The router's `_effective_weights` redistributes agent weight back
   to content weights using the exact ratio
   `(content_mass + agent_mass) / content_mass`, preserving the
   original 0.30 / 0.25 / 0.35 / 0.10 (or 0.28 / 0.22 / 0.42 / 0.08
   for strict) ratios exactly.
2. The determinism fingerprint excludes agent contributions when
   `agent_present=False`.
3. The `tests/test_agent_governance.py::test_pdp_no_agent_id_reproduces_legacy_behavior`
   test asserts fingerprint equality between the agent-suite-attached
   and agent-suite-absent paths.

## Test coverage

- 230 pre-existing tests: all passing (zero regressions).
- 29 new agent governance tests: all passing.
- Total: 259 passing, 0 failing.

## Files added

```
src/tex/agent/__init__.py
src/tex/agent/identity_evaluator.py
src/tex/agent/capability_evaluator.py
src/tex/agent/behavioral_evaluator.py
src/tex/agent/suite.py
src/tex/api/agent_routes.py
src/tex/domain/agent.py
src/tex/domain/agent_signal.py
src/tex/stores/agent_registry.py
src/tex/stores/action_ledger.py
tests/test_agent_governance.py
V10_FUSED_AGENT_GOVERNANCE.md
```

## Files modified

```
src/tex/commands/evaluate_action.py    # ledger write on agent-attached decisions
src/tex/domain/determinism.py          # fingerprint folds agent streams when present
src/tex/domain/evaluation.py           # agent_id, session_id on EvaluationRequest
src/tex/domain/latency.py              # agent_ms stage
src/tex/domain/policy.py               # 7-key fusion weights with safe defaults
src/tex/engine/pdp.py                  # agent stream wired between retrieval and specialists
src/tex/engine/router.py               # 7-stream fusion + renormalization
src/tex/policies/defaults.py           # default + strict weights for 7-stream fusion
src/tex/api/schemas.py                 # EvaluateRequestDTO accepts agent_id, session_id
src/tex/main.py                        # composition root builds agent suite + stores + router
tests/test_april_2026_fixes.py         # updated semantic-dominance assertion to 7-layer aware
```

## Pitch for the change

Tex was the only product evaluating actual outbound content at the
moment of release. With this rebuild, Tex evaluates the agent and its
content at the moment of release in one fused event. Competitors who
do agent posture, capability, or behavioral monitoring run their
checks upstream as separate systems and have to reconcile across the
seam at runtime. Tex has no seam. Every decision is one composite
question with one fingerprint, one chain, one verdict.
