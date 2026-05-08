# TEX ECOSYSTEM GRAPH GOVERNANCE — MAY 2026

> **The architectural shift:** Tex stops emitting per-action verdicts and
> starts emitting *ecosystem state assessments*. Every artifact (email, tool
> call, agent message) is a typed event in a temporal knowledge graph. Tex's
> verdict is now: "Given the current ecosystem state and this proposed event,
> does executing this event move the system toward or away from a governable
> equilibrium per the active governance graph?"

## The Eight-Layer Ecosystem Stack

```
                    ┌────────────────────────────────────────┐
                    │  ecosystem_engine.py                   │
                    │  (top-level ecosystem verdict surface) │
                    └───────────────┬────────────────────────┘
                                    │
   ┌────────────────────────────────┼────────────────────────────────┐
   │                                │                                │
┌──▼──────────┐ ┌────────────┐ ┌────▼─────────┐ ┌──────────────┐
│ contracts/  │ │ systemic/  │ │ institutional│ │ intervention/│
│ behavioral  │ │ risk +     │ │ governance   │ │ cost-bounded │
│ specs       │ │ digital    │ │ graph + LTS  │ │ steering     │
│             │ │ twin       │ │ Oracle+Ctrl  │ │              │
└──┬──────────┘ └─────┬──────┘ └──────┬───────┘ └─────┬────────┘
   │                  │               │               │
   └──────────────────┼───────────────┼───────────────┘
                      │               │
              ┌───────▼───┐ ┌────────▼──────┐ ┌──────────────┐
              │ causal/   │ │ drift/        │ │ events/      │
              │ CHIEF+ARM │ │ change-point  │ │ append-only  │
              │ attribution│ │ detection    │ │ crypto ledger│
              └───────┬───┘ └────────┬──────┘ └──────┬───────┘
                      │              │               │
                      └──────────────┼───────────────┘
                                     │
                          ┌──────────▼──────────────┐
                          │ graph/                  │
                          │ temporal knowledge graph│
                          │ + property graph engine │
                          └──────────┬──────────────┘
                                     │
                          ┌──────────▼──────────────┐
                          │ ontology/               │
                          │ entity/edge type system │
                          │ + AIRO/EU AI Act bindings│
                          └─────────────────────────┘
```

## What Changes Conceptually

**Before** — Action governance:
  Input: a single artifact (email, tool call, output)
  Tex pipeline: deterministic + specialists + semantic + criticality + agent + fusion
  Output: PERMIT / ABSTAIN / FORBID on the artifact

**After** — Ecosystem governance:
  Input: a proposed event in an ecosystem (typed: AGENT_EMITS_OUTPUT,
         AGENT_INVOKES_TOOL, AGENT_TO_AGENT_MESSAGE, DATA_ACCESS,
         CAPABILITY_GRANT, POLICY_DECISION, ...)
  State: temporal knowledge graph of all entities and prior events
  Tex pipeline:
    1. ontology check — does this event conform to the type system?
    2. graph projection — what is the ecosystem state right now?
    3. behavioral contract check — does any agent's contract forbid this?
    4. governance graph LTS check — is this a legal transition per the
       active institutional governance graph?
    5. causal attribution — what prior events causally enable this one?
    6. drift detection — does this event increase any tracked drift signal?
    7. systemic risk — what is the bounded-compromise score under this event?
    8. intervention selection — if FORBID, what cost-bounded intervention
       restores governable state? (capability revocation, sanction, restorative
       path triggering)
  Output:
    - Ecosystem verdict: PERMIT / ABSTAIN / FORBID / SANCTION / REMEDIATE
    - Per-axis scores (drift, risk, contract, governance graph, causal)
    - Recommended intervention if not PERMIT
    - Updated ecosystem state hash + cryptographic receipt

## What This Lets You Say to Buyers

- **VP Marketing:** "Tex doesn't just check your email. Tex models your
  entire AI marketing ecosystem and tells you when the *system* is drifting
  toward an FTC-actionable pattern — before any single email triggers it."

- **CISO:** "Tex doesn't just check tool calls. Tex models your full agent
  ecosystem as a governance graph and proves bounded-compromise: even under
  10% Byzantine agents, the ratio of compromised interactions stays
  provably below one."

- **Insurer:** "Tex emits a continuous ecosystem-state attestation, not a
  pile of artifact verdicts. The packet you verify is a single signed
  ecosystem hash plus a bounded-compromise certificate."

## P0/P1/P2 Build Order for the Ecosystem Layer

| Tier | Window     | Modules                                                        |
|------|------------|----------------------------------------------------------------|
| P0   | Days 1-30  | `ontology/`, `graph/` (in-memory), `events/`, `ecosystem_engine`|
| P1   | Days 31-90 | `causal/`, `institutional/`, `drift/`, `contracts/`            |
| P2   | Days 90+   | `intervention/` (full), `systemic/` (digital twin), Postgres+graph DB |

## Frontier Source Crosswalk

| Module                  | arxiv ID / paper                                          |
|-------------------------|-----------------------------------------------------------|
| `institutional/`        | 2601.11369 + 2601.10599 (Institutional AI)               |
| `ontology/airo.py`      | AIRO + arxiv 2604.27713                                  |
| `causal/chief.py`       | 2602.23701 (CHIEF)                                       |
| `causal/arm.py`         | 2604.04035 (Agentic Reference Monitor)                   |
| `events/ledger.py`      | 2512.18561 (AAF cryptographic provenance)                |
| `drift/change_point.py` | 2512.18561 (AAF distributional change-point detection)   |
| `intervention/`         | 2512.18561 (AAF cost-bounded interventions + bounded compromise) |
| `contracts/`            | 2602.22302 (Agent Behavioral Contracts)                  |
| `graph/temporal_kg.py`  | Zep/Graphiti + arxiv 2602.05665 (Graph-based Agent Memory)|
| `systemic/digital_twin.py` | SR-DTMA + arxiv 2509.17878 (Systemic risk in AI)      |
