# Thread 15 — Runtime Defenses: Design Decisions

## What was built

Five-layer defense-in-depth runtime stack against indirect prompt injection,
each layer implementing a specific peer-reviewed paper from late 2025 / 2026:

| Layer        | Reference         | Defense focus                                         |
| ------------ | ----------------- | ----------------------------------------------------- |
| PlanGuard    | arxiv 2604.10134  | Plan-isolation + intent verification, two-stage       |
| ClawGuard    | arxiv 2604.11790  | Tool-call boundary enforcement, ⊤/⊥/amb verdicts      |
| AgentArmor   | arxiv 2508.01249  | CFG/DFG/PDG IR + Bell-LaPadula/Biba type system       |
| MAGE         | arxiv 2605.03228  | Shadow memory + Judge for long-horizon attacks        |
| MCPShield    | arxiv 2604.05969  | LTS model + 4 formal properties on MCP interactions   |

Five sub-packages, 17 source files, 138 tests, 96% line coverage on the
runtime package as a whole. Every module is ≥90% covered.

Each defense layer is independently usable — the entire stack is wired by
the application calling each component in order. No layer assumes any
other layer is active. This is deliberate: defense in depth requires that
any single bypass does not compromise the rest of the chain.

## Architectural decisions worth knowing

**Pluggable LLM hooks with deterministic offline fallbacks.** Every paper
backs at least one component with an LLM (PlanGuard's Stage II verifier;
ClawGuard's task rule inducer; AgentArmor's tool/data scanners; MAGE's M_θ
and J_θ). We expose those as injection points but ship deterministic
fallbacks so the entire stack runs offline in CI and tests pass without
any model dependency. When an injected LLM raises, every layer falls
through to the deterministic path with telemetry rather than failing
open. This matters: failing-open under model timeout is a known IPI
attack vector.

**Backwards-compatible scaffolded contracts preserved.** The original
scaffold returned `tuple[bool, tuple[str, ...]]` from `verify_property`,
`check`, `check_call`, etc. Each implementation keeps that signature for
existing call sites, plus adds a `*_detailed` or `*_with_reasoning`
variant returning structured records (`TypeViolation`, decision objects)
that downstream telemetry / audit can serialise.

**Lattice-based information flow is duplicated across AgentArmor and
MCPShield, on purpose.** Both layers ship their own `SecurityLabel` lattice.
A single shared module would have been cleaner — but it would also mean a
single registry change could weaken both layers. The AgentArmor lattice is
{PUBLIC, INTERNAL, CONFIDENTIAL, SECRET} for confidentiality with a parallel
{HIGH, MEDIUM, LOW} for integrity (Biba); MCPShield uses the same
confidentiality lattice but does not track integrity (the paper's Property
2 only addresses confinement). They are intentionally separate.

**Append-only audit semantics on shadow memory.** `ShadowMemory.append`
enforces strictly-monotonic `turn_index`. Any regression is rejected with
`ValueError`. This is a hard invariant because shadow memory must remain
auditable evidence: rewriting history during an attack would defeat the
post-mortem property the paper relies on. This is also why we don't ship a
`forget()` or `redact()` method — both would break the invariant.

**Property verification on MCPShield is decidable, not LTL model-checking.**
The paper claims decidability for each of its four properties via the
finite state space and finite security lattice. We implement each property
directly (BFS reachability with a label monitor for confinement; per-edge
hash check for integrity; per-edge cap subset check for boundedness;
authorisation set lookup for isolation) rather than wiring NuSMV / PRISM.
This keeps the runtime layer free of external model-checker dependencies
and is consistent with the paper's complexity claims (`O(|τ|·|T|)` for
tool integrity, etc).

**Reasoning-smell + obfuscation patterns are duplicated across PlanGuard,
ClawGuard, and MAGE.** Each layer ships its own copy of the regexes that
detect "ignore prior", base64-pipe-bash, etc. Centralising into one module
was tempting but a single registry change could disable all checks
simultaneously. Each layer keeps its own copy, which means three regex
updates whenever a new attack pattern is added — but no single attacker
edit can disable the chain.

**Graph constructor tracks ALL prior observations, not just the latest.**
AgentArmor's DFG must capture the case where a tainted observation at
turn 4 is used by a tool at turn 18 with seven benign tool calls in
between. Single-prior-observation tracking missed that path. The new
implementation links any later `tool_param` to any earlier `observation`
whose content the param's value contains.

**Three-valued ClawGuard verdicts (⊤/⊥/amb) with deny-by-default on amb
when no approval handler is wired.** The paper requires user-in-the-loop
on `amb`, but a headless deployment without an approval handler must not
fall open. We treat handler-absent + amb as deny.

**Approval handler routing in ClawGuard is fully optional.** If wired, an
amb verdict pauses for human approval; if not wired, amb degrades to
deny. Either way, the contract is "deny by default at every ambiguity",
matching the paper's ⊥-dominance principle.

**ToolDefinition uses SHA-256 (FIPS 180-4) for hash integrity, not PQ.**
Tool integrity in MCPShield only requires collision resistance; SHA-256
is sufficient and keeps the runtime layer free of liboqs dependencies for
this purpose. The PQ path stays in `tex.pqcrypto` for evidence chains and
signature use cases — different threat model, different requirements.

**Trust Domain D_i = (S_i, T_i, π_i) is a frozen dataclass, not pydantic.**
Pydantic is used for inputs and validated payloads; frozen dataclasses
for compact value types where we want to interop with tuples and
hashable membership checks. Both `TrustDomain` and `ToolDefinition` need
to live inside `frozenset` literals in tests, so dataclasses with
`frozen=True, slots=True` was the right call.

## Acceptance criteria — verified in tests

| Criterion                                                                                  | Test                                                                  |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| PlanGuard reduces InjecAgent ASR from ≥40% baseline to ≤5%                                 | `test_planguard.py::test_injecagent_50_prompt_fixture_reduces_asr`    |
| ClawGuard `BaseRuleSet.default()` ships the documented base rules                          | `test_clawguard.py::test_default_rule_set_has_baseline_rules`         |
| ClawGuard `check_call()` enforces deny-by-default on SSRF/secret patterns                  | `test_clawguard.py::TestSsrfDenyByDefault` (multiple)                 |
| AgentArmor builds CFG/DFG/PDG over a 20-step trace and detects info-flow violations        | `test_agentarmor.py::test_twenty_step_trace_detects_information_flow_violation` |
| MAGE.ShadowMemory distills relevant entries for a long-horizon attack                      | `test_mage.py::test_long_horizon_distillation_surfaces_attack_signal` |
| MCPShield verifies LTS properties on a 10-state model                                      | `test_mcpshield.py::TestTenStateClean::*`                             |

## Test summary

```
tests/runtime/test_planguard.py    23 passed
tests/runtime/test_clawguard.py    39 passed
tests/runtime/test_agentarmor.py   29 passed
tests/runtime/test_mage.py         24 passed
tests/runtime/test_mcpshield.py    23 passed
                                  ─────────
                                  138 passed, 0 failed
```

Coverage on `src/tex/runtime/`: **96% line coverage**, every module ≥90%.

## Follow-up TODOs for later threads

### Thread 16 — Wire the runtime stack to Tex's adjudication pipeline
- Add a `RuntimeDefenseGate` in `src/tex/adjudication/gates/` that runs
  PlanGuard → ClawGuard → AgentArmor → MAGE → MCPShield in sequence, with
  short-circuit on first ⊥. PERMIT only if all five layers agree.
- The C2PA evidence manifest must include each layer's verdict + the
  counterexample path (when present) so audit reconstruction is possible.
- Telemetry events already emit; add a single "runtime.gate" rollup
  event at the gate boundary.

### Thread 17 — Plug the LLM-backed paths
- PlanGuard Stage II: wire to a small reasoning model (Claude Haiku or
  equivalent) for `M_verify(I, S_ref, a_act, r_act)`. Paper §VI shows
  Stage II drops FPR from 27-38% to <3.3%.
- ClawGuard Skill Inspector + Task Rule Inducer: wire to the same model.
- AgentArmor Tool Scanner + Data Scanner: paper uses an LLM-backed
  inference; ours falls back to lexical heuristic. For tools with no
  registered spec, the LLM path matters for accuracy on novel APIs.
- MAGE M_θ and J_θ: paper uses Qwen3-4B fine-tuned with GRPO. For Tex's
  deployment, a smaller distilled model on Modal or vLLM would work.
  The Judge call is per-action and on the critical path; latency budget
  is ~50-100ms.

### Thread 18 — Integration tests on real attack benchmarks
- AgentDojo benchmark: run the full attack suite with the gate enabled
  and report ASR + utility delta.
- InjecAgent: run the 1054-test corpus end-to-end. Paper baseline GPT-4
  ASR is 24% (47% with hacking prompt); target ≤5% with PlanGuard.
- STAC benchmark (Li et al. 2025a): for the MAGE long-horizon attacks.
- PI2 benchmark (Jiang et al. 2026a): for environment-as-adversary tests.

### Thread 19 — Performance tuning
- Current latency is dominated by the offline-path regexes (microseconds).
- Once LLM hooks are wired, the hot path is PlanGuard Stage II and MAGE
  judge. Both should be cached on `(action, distilled_memory_hash)`.
- AgentArmor PDG construction is O(n) per event; cache PDGs per
  trajectory snapshot.
- MCPShield property verification is O(|τ|·|T|) per property. Most
  expensive is data confinement (state monitor); profile if it ever
  shows up in hot path.

### Thread 20 — Tex Arena integration
- Add per-layer "shield" challenges to Tex Arena: one round each
  testing PlanGuard, ClawGuard, AgentArmor, MAGE, MCPShield.
- The known_bypasses.md file should be updated with any AgentArmor/
  MAGE/MCPShield-specific bypasses found during arena play.

### Known limitations to document on the marketing site
- AgentArmor's LLM/Thought-node-excluded DFG means a sufficiently clever
  attack that hides taint inside a thought (rather than data) cannot be
  caught by the type system. The paper acknowledges this; mitigation is
  the Dependency Analyzer (LLM-backed) which we have not yet wired.
- MAGE's offline judge depends on keyword overlap. Paper achieves 8.3%
  ASR only with the RL-trained M_θ + J_θ. Our offline path will be
  weaker until those are plugged in.
- MCPShield's tool integrity check assumes the runtime knows the
  approved-time `definition_blob`. In practice this requires a tool
  registry with cryptographic provenance — see the related "Trustworthy
  Registry" work (mdpi 1999-5903/18/5/243) for a deployable design.

### Out-of-scope for thread 15 (deliberate)
- No new third-party dependencies: stick with stdlib + already-approved
  liboqs/c2pa-rs/networkx/pyld.
- No web API surface: the runtime layer is purely library code. The
  HTTP / WebSocket surface lives in `src/tex/api/` and is wired in a
  later thread.
- No persistence: shadow memory is in-process only. Persistence and
  cross-session shadow memory are deferred.
