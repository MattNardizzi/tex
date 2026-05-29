# Layer 4 — Execution Governance

> **Working doc.** The PDP — where every PERMIT/ABSTAIN/FORBID is decided.
> This is the largest layer (21 packages, 55,645 lines).

## What this layer does

For every proposed agent action, fuse seven independent risk-signal streams plus policy criticality into one verdict (`PERMIT` / `ABSTAIN` / `FORBID`) with a confidence score, a deterministic fingerprint, and a structured set of reasons.

This is **the engine.** Everything else feeds it (Layers 1-3) or consumes its output (Layers 5-6).

## The seven streams (the canonical mental model)

In order of execution in `engine/pdp.py:602-611`:

| # | Stream | Package | What it answers |
|---|---|---|---|
| 1 | Deterministic recognizers | `deterministic/` | Does this content trigger any hard regex/rule? |
| 2 | Policy retrieval | `retrieval/` | What policy clauses, entities, and precedents are relevant? |
| 3 | Agent identity | `agent/identity_evaluator.py` | Is this agent trusted? |
| 4 | Agent capability | `agent/capability_evaluator.py` | Is this action within the agent's declared capabilities? |
| 5 | Agent behavioral | `agent/behavioral_evaluator.py` | Is this consistent with the agent's behavioral baseline? |
| 6 | Specialist judges | `specialists/` (17 of them) | Each specialist scores its specialty (PII leak, MCP injection, plan integrity, etc.) |
| 7 | Semantic | `semantic/` | LLM judge (default `gpt-5-mini`) with deterministic fallback |

Then:

- **Behavioral contracts** (`contracts/`) check LTLf temporal logic. Hard violations short-circuit to FORBID. Soft violations feed routing as findings.
- **Routing** (`engine/router.py`) does weighted fusion across the 7 streams + policy criticality.
- **Decision materialization** (`engine/pdp.py`) builds the durable `Decision` and writes evidence.

## Packages in scope (21 packages, 182 files)

### Core PDP
| Package | Files | Status | Role |
|---|---|---|---|
| `engine/` | 4 | WIRED | The PDP itself + router + contract bridge |
| `commands/` | 6 | WIRED | Use-case orchestration (evaluate, outcome, activate, calibrate, export) |
| `policies/` | 2 | WIRED | Default policy snapshots |

### The seven streams
| Package | Files | Status | Role |
|---|---|---|---|
| `deterministic/` | 3 | WIRED | Stream 1 — regex/rule gate (13 recognizers) |
| `retrieval/` | 2 | WIRED | Stream 2 — RAG orchestrator |
| (`agent/` is Layer 2) | | | Streams 3-5 |
| `specialists/` | 24 | WIRED | Stream 6 — 17 specialist judges + shared infrastructure |
| `semantic/` | 6 | WIRED | Stream 7 — LLM judge with deterministic fallback |

### Specialist supporting machinery
| Package | Files | Status | Role |
|---|---|---|---|
| `runtime/` | 17 | WIRED | 5 sub-packages (mcpshield, mage, planguard, clawguard, agentarmor) invoked by their matching specialists |
| `camel/` | 7 | WIRED | CamEL capability-based interpreter (used by `camel_specialist`) |
| `pcas/` | 13 | WIRED | PCAS Datalog policy compiler (used by `pcas_specialist`) |

### Contracts
| Package | Files | Status | Role |
|---|---|---|---|
| `contracts/` | 6 | WIRED | LTLf behavioral contracts gating routing |

### Ecosystem engine (the eight-step pipeline wrapping the PDP)
| Package | Files | Status | Role |
|---|---|---|---|
| `ecosystem/` | 8 | WIRED | Orchestrates the 8 steps |
| `ontology/` | 8 | 4 WIRED + 4 TEST_ONLY | Step 1: entity/event types |
| `contracts/` | (above) | WIRED | Step 3: contract check |
| `institutional/` | 8 | WIRED | Step 4: governance LTS (deep stub) |
| `causal/` | 13 | WIRED | Step 5: causal attribution (deep stub in live path) |
| `drift/` | 7 | WIRED | Step 6: drift detection (deep stub in live path) |
| `systemic/` | 9 | WIRED | Step 7: systemic risk + digital twin |
| `intervention/` | 7 | WIRED | Step 8: intervention selection (deep stub) |

### Deep governance (tested, NOT invoked at runtime)
| Package | Files | Status | Role |
|---|---|---|---|
| `governance/` | 20 | Mixed — `private_data_exec/ifc` WIRED via `ifc_specialist`; `path_policy/`, `kernel_mcp/`, `stpa_specs/` TEST_ONLY | Deeper governance work that hasn't been wired into the runtime |

### Built-but-not-invoked
| Package | Files | Status | Role |
|---|---|---|---|
| `enforcement/` | 7 | TEST_ONLY | `TexGate`, `@tex_gated`, framework adapters, ASGI proxy |
| `safeflow/` | 5 | TEST_ONLY | Transactional execution with WAL |

## Key files (start here)

- `src/tex/engine/pdp.py` (~1,300 lines) — the PDP. The `evaluate()` method is the main entry point.
- `src/tex/engine/router.py` — the fusion router.
- `src/tex/engine/contract_bridge.py` — bridges `contracts/` into the PDP.
- `src/tex/commands/evaluate_action.py` — orchestrates a single evaluation request end-to-end (this is what the HTTP route calls).
- `src/tex/specialists/judges.py` — registry of all 17 specialists.
- `src/tex/ecosystem/engine.py` — eight-step ecosystem engine.

## Current state

✅ Solid:
- Seven-stream PDP fully wired and well-tested
- 17 specialist judges all firing
- Deterministic fallback for semantic when no provider configured
- Behavioral contracts with LTLf evaluator (hard + soft violations)
- Ecosystem engine integrated into `evaluate_action` flow
- Routing fusion with criticality-weighted scoring
- Deterministic fingerprint per decision (replay-ready)
- 80 HTTP endpoints fronting Layer 4 work

⚠ Wired but with shallow live behavior:
- **Ecosystem steps 4-8**: institutional / causal / drift / systemic / intervention. The packages have deep machinery (sometimes 5,000+ lines), but their integration into the live ecosystem engine is gated as P1/P2 stubs in the engine itself.
- **Governance subpackages 3 of 4**: `path_policy/` (LTLf path checker), `kernel_mcp/syscall_gate.py` (771 lines!), `stpa_specs/` are tested but never invoked by the runtime.
- **`enforcement/`**: 1,691 lines of `TexGate` / adapter / proxy code. Per its own docstring this is what makes Tex "decision-and-enforcement" rather than just "decision." Not wired.
- **`safeflow/`**: 892 lines of transactional execution. Not invoked.

## Improvement vectors

### 1. Activate ecosystem steps 4-8 (high impact, medium effort)
Each of the five P1/P2 stubs in `ecosystem/engine.py` corresponds to a real package with substantial implementation. Activating them in shadow mode (don't gate on results, just emit telemetry) is the path to making the eight-step pipeline real. Per step:
- **Step 4 (institutional)** — wire `institutional/governance_lts.py` into `engine.py:_step_governance_check`. Adds policy-stability gating.
- **Step 5 (causal)** — wire `causal/attribution_engine.py` into `_step_causal_check`. Currently only fired post-incident via `/v1/incidents/.../attribute`.
- **Step 6 (drift)** — wire `drift/emergent_norm.py` into `_step_drift_check`.
- **Step 7 (systemic)** — wire `systemic/digital_twin.py` for in-flight twin sims (currently only the explicit `/v1/ecosystem/twin/simulate` route uses it).
- **Step 8 (intervention)** — wire `intervention/engine.py` for next-action selection when ABSTAIN.

### 2. Wire MCP governance (high impact, low effort)
`governance/kernel_mcp/syscall_gate.py` is 771 lines implementing a 6-stage MCP syscall pipeline. `api/mcp_server.py` exposes an MCP server endpoint. **They are not connected.** Wiring the gate in front of every `tools/call` is ~30 lines and instantly upgrades the MCP server route from passthrough to governed.

### 3. Wire path policies (medium impact, medium effort)
`governance/path_policy/` implements LTLf-checked path policies. Customer use case: "this agent may only invoke search_db AFTER receiving user input AND BEFORE invoking send_email." Today no path policies are checked. Wiring `PathPolicyChecker` into the PDP as an 8th stream (or as a sibling check to contracts) activates this.

### 4. Decide enforcement direction (high impact)
There are TWO enforcement primitives in the repo: `src/tex/enforcement/` (in-process gate) and `sdks/python/tex_guardrail/` (HTTP client). Only the SDK is in any customer integration path. Either:
- Wire `enforcement/` into the runtime as a first-party integration target (and document it), OR
- Delete `enforcement/` and consolidate to the SDK as the sole integration path.

Either is a defensible decision; the current state (both exist, neither dominates) is not.

### 5. New specialist judges (variable impact)
The 17 specialists today cover most known agent-risk surface. Gaps as of May 2026:
- **Tool-chain integrity** — when an agent's plan involves 5 tool calls, verify the result of step N matches what was assumed at step N+1
- **Multi-agent collusion** — already noted in Layer 2; this is the specialist-side hook
- **Refusal-bypass detection** — model jailbreak attempts often try to bypass refusal via formatting tricks

### 6. Replace semantic fallback with a stronger model (low-effort win)
The deterministic fallback in `semantic/fallback.py` is heuristic. A small distilled model (running locally, no API call) could give substantially better fallback quality without latency cost.

### 7. Activate `safeflow/` for multi-step plans (high impact, high effort)
Today PDP evaluates one action at a time. Real agent flows are multi-step plans. SAFEFLOW gives ACID semantics so a 5-step plan that fails policy at step 4 rolls back the prior 3. Requires defining a "plan submission" API first.

## Constraints

- **Determinism**: the same input must produce the same decision. The `determinism_fingerprint` field on every Decision validates this. Any change that introduces nondeterminism must be opt-in.
- **Fail-closed**: if any stream raises, the decision must NOT default to PERMIT. Either ABSTAIN with uncertainty flag or FORBID.
- **Latency**: the canonical PDP is on the critical path of every customer request. Each stream's contribution is budgeted (see `latency_ms` in the decision evidence). Don't add anything synchronous over ~10ms without explicit approval.
- **No `await`-in-eval cycles**: streams are independent; they may not call back into the router or other streams during evaluation.
- **Every decision writes evidence**: the recorder is always called. A successful evaluation that doesn't write evidence is a bug.

## Testing

```bash
pytest tests/test_pdp.py tests/test_router.py tests/test_deterministic.py tests/test_specialists.py tests/test_semantic.py tests/test_retrieval.py tests/test_ecosystem_engine_integration.py tests/test_thread7_integration.py
pytest tests/specialists/  tests/governance/  tests/runtime/
```

## Cross-layer touch points

- **Reads from Layer 1**: discovery findings inform retrieval (entity matching)
- **Reads from Layer 2**: agent record drives streams 3-5
- **Writes to Layer 3**: every decision emits a span + metrics
- **Writes to Layer 5**: every decision writes an evidence record
- **Feeds Layer 6**: every outcome triggers learning updates
