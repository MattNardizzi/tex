# CAPABILITY_TIERS

The five-tier capability model. This is the **product-facing** view of Tex —
the language a CISO or insurance buyer would recognize. It's separate from the
dev-tier system (A/B/C/D) in `TIER_OWNERSHIP.md`, which is about engineering
blast radius.

Every package gets tagged with both:
- A **dev tier** (A/B/C/D) — what to run when this changes.
- A **capability tier** (one of the five below) — what this contributes to the product.

The two tags answer different questions. Use the dev tier when you change a file.
Use the capability tier when you pitch the product or onboard a collaborator.

---

## The five tiers

### 1. Discovery / Inventory

**What it does.** Finds the agents, MCP servers, tools, and connectors operating
in a customer's environment. Reconciles claimed inventory against observed
inventory. Quarantines drift.

**The buyer question it answers.** "What AI agents do we have, and what are they
allowed to do?"

**Test for membership.** If a package is primarily about *finding* things that
already exist or *registering* new things, it belongs here. If it's about
*deciding* on things, it doesn't.

**Current packages:** `discovery/` (connectors, reconciliation, service),
parts of `governance/ifc/` (information flow classification at the input layer).

---

### 2. Identity / Access

**What it does.** Establishes who an agent claims to be, what capabilities it
claims to have, and whether either claim is allowed. Includes Agent Identity
Documents (AIDs), capability attestation, and access enforcement at runtime.

**The buyer question it answers.** "Is this agent who it claims to be, and is
it allowed to do what it's trying to do?"

**Test for membership.** If a package is about *who* the agent is or *what it's
allowed to be*, it belongs here. Capability checks that gate access live here.
Capability checks that evaluate the *content* of an action live under Execution
Governance.

**Current packages:** `agent/identity_evaluator.py`, `agent/capability_evaluator.py`,
`vet/` (Agent Identity Documents, web proofs), `enforcement/` (edge enforcement),
parts of `runtime/` (the access-gating guards).

---

### 3. Monitoring / Observability

**What it does.** Watches the system over time. Detects drift, change points,
emergent norms, systemic risk. Ingests feedback. Reports health.

**The buyer question it answers.** "How is the system behaving over time, and
has anything changed?"

**Test for membership.** If a package is *passive* — observing, measuring,
detecting, reporting — and doesn't make decisions itself, it belongs here. If
it makes a deny/permit decision, it doesn't.

**Current packages:** `observability/`, `drift/`, `systemic/`, `learning/feedback.py`
and `learning/observability`, `causal/` (post-hoc attribution).

---

### 4. Execution Governance

**What it does.** Decides whether a specific action by a specific agent should
be permitted, abstained, or forbidden. The decision pipeline. Includes content
adjudication (the LLM-backed specialist judges), behavioral contract enforcement,
and the policy decision point.

**The buyer question it answers.** "Should this specific action be allowed
right now, given everything we know?"

**Test for membership.** If a package is *active* in the decision path — taking
an action proposal and returning a verdict — it belongs here. This is the
biggest tier and the one that contains Tex's specific differentiator: content
adjudication of agent actions, not just identity/capability checks.

**Current packages:** `engine/` (PDP, router, contract bridge), `specialists/`
(the 24 judges), `semantic/` (LLM scoring), `deterministic/` (rule layer),
`contracts/` (LTL behavioral contracts + enforcer), `agent/behavioral_evaluator.py`,
most of `governance/` (path policy, private data, kernel MCP, STPA),
`intervention/`, parts of `runtime/` (content-adjudication guards: clawguard,
mage, planguard, mcpshield, agentarmor), `pcas/`, `camel/`, `safeflow/`.

---

### 5. Evidence / Recording

**What it does.** Produces signed, verifiable artifacts of everything that
happened. The hash-linked audit chain. C2PA manifests. ML-DSA signatures.
Compliance disclosure packets. Buyer-facing export bundles.

**The buyer question it answers.** "Can we prove what happened, to a regulator
or insurer, in a way they'll accept?"

**Test for membership.** If a package is about *producing artifacts that
outlive the decision* — for auditors, regulators, insurers, the buyer's
lawyer — it belongs here. This is Tex's structural differentiator from Noma,
Zenity, and Cisco AGT, who operate in tiers 1–4 but treat recording as a log.

**Current packages:** `evidence/`, `events/` (append-only ledger), `c2pa/`,
`pqcrypto/`, `compliance/` (EU AI Act, NAIC, NIST, state regs), `pitch/`
(insurer / CISO / VP Marketing export packets), `zkprov/`, `tee/`, `nanozk/`,
`receipts/`, `institutional/`.

---

## Cross-cutting infrastructure (no capability tier)

Some packages don't fit any capability tier because they serve all of them.
Tag these as **`kernel`** for clarity.

- `domain/` — shared dataclasses used everywhere.
- `commands/` — the CQRS write path; routes into Execution Governance but
  isn't itself a capability.
- `stores/`, `memory/`, `db/` — persistence; serves all tiers.
- `api/` — HTTP transport; carries traffic for all tiers.
- `bench/`, `adversarial/`, `proofs/` — test infrastructure and proofs.
- `ontology/`, `policies/` — schema and policy primitives used across tiers.
- `ecosystem/`, `graph/`, `drift/` (signal registry portion) — shared analytics
  substrate. Some of these straddle Monitoring and Execution Governance.

`kernel` is a load-bearing tag, not a junk drawer. If something is kernel, it
should be **stable** (rare changes) and **dependency-free of other tiers**
(nothing in `domain/` should import from `engine/`).

---

## Rules for ambiguous cases

These are the cases that come up. The rules below are the answers — don't
re-debate them per file, just apply.

### "Capability check" — Identity or Execution Governance?

- **Identity/Access:** "is this agent allowed to be this capability?" — gating
  *who you are*. Lives in `agent/capability_evaluator.py`.
- **Execution Governance:** "given this agent has capability X, is this specific
  use of X allowed right now given the content?" — gating *what you're doing*.
  Lives in `specialists/` and `runtime/`.

Rule: if the check happens *before* the action's content is evaluated, it's
Identity. If it happens *with* the action's content, it's Execution Governance.

### `runtime/` — Identity or Execution Governance?

`runtime/` is split:
- `clawguard/`, `mage/`, `planguard/`, `mcpshield/`, `agentarmor/` — these
  inspect action *content* and decide permit/forbid. **Execution Governance.**
- Any future runtime guards that gate based purely on agent identity or static
  capability declaration → **Identity/Access.**

### `drift/` — Monitoring or Execution Governance?

`drift/` is split:
- Change-point detection, emergent norm tracing, signal observation — these
  watch and report. **Monitoring.**
- Any `drift/`-derived signal that gates a decision in the engine →
  **Execution Governance** at the point of use, but the package itself stays
  in Monitoring.

### `learning/` — Monitoring or Execution Governance?

`learning/` is split:
- `feedback.py`, `observability`, `reputation.py` — these ingest and analyze.
  **Monitoring.**
- `calibration.py`, `safety.py`, `proposal_store.py` — these modify scoring
  weights, which directly affect future decisions. **Execution Governance.**

The whole `learning/` package is tagged Monitoring as its primary capability,
with calibration noted as Execution Governance overlap. This is the cleanest
split and matches how the package is structured.

### `compliance/` — Evidence or something else?

`compliance/` is entirely Evidence. Every file in it produces an export
artifact bound to a regulation. Even when the file is a stub, its *intent* is
evidence production.

### `governance/` — Execution Governance or split?

`governance/` is mostly Execution Governance (path policy, private data exec,
kernel MCP, STPA), with `governance/ifc/` (information-flow classification)
partly in Discovery (input classification) and partly in Execution Governance
(downstream flow gating). Tag the whole package Execution Governance with an
internal note that IFC has Discovery overlap.

### `evidence/` vs `events/` — both Evidence?

Yes, both are Evidence. `events/` is the append-only ledger primitive;
`evidence/` is the buyer-facing chain + exporter. Same tier, different layers.

---

## Pressure-test cases

Three concrete future additions that the model should answer cleanly:

### Q1. A new `salesforce_connector.py` is added.

- Goes under `discovery/connectors/`.
- Capability tier: **Discovery / Inventory.**
- Dev tier: **B** (buyer-facing surface; discovery is Tier B).

### Q2. A new BEC-detection specialist is added.

- Goes under `specialists/`.
- Capability tier: **Execution Governance.**
- Dev tier: **A** (specialists are Tier A — judge layer is product core).

### Q3. A new evidence export format (FedRAMP audit packet) is added.

- Goes under `pitch/` if buyer-facing, or `compliance/fedramp/` if regulation-bound.
- Capability tier: **Evidence / Recording.**
- Dev tier: **B** (buyer-facing) or **D** (stub) depending on completion state.

All three resolve cleanly. Model is good.

---

## Why this exists alongside the dev-tier system

| | Dev tier (A/B/C/D) | Capability tier (this file) |
|---|---|---|
| Question it answers | "What's the blast radius of this change?" | "What does this contribute to the product?" |
| Audience | Engineers (you, me, future engineers) | Buyers, partners, GTM, AND engineers |
| When you use it | When you change a file | When you pitch the product, onboard, or restructure |
| How often it changes | Stable | Stable once defined |

Both axes appear in `TIER_OWNERSHIP.md`. The audit tool prints both. Most of
the time you'll only care about one — but having both means the same map serves
the engineering audit and the buyer conversation.
