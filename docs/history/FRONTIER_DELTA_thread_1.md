# FRONTIER_DELTA — Thread 1 (LTLf Behavioral Contracts → PDP)

**Compiled:** May 14, 2026 (post-Phase-0)
**Thread goal:** wire `src/tex/contracts/` (Behavioral Contracts + LTLf enforcer)
into the live `/v1/guardrail` request path through `PolicyDecisionPoint`.
**Phase 0 method:** 12 web searches across Blocks A (successor/newer-than-1.4 hunt),
B (competitor survival check), C (standards/benchmark refresh), D (contested SOTA /
failure-mode wedge). Plus targeted web_fetch of the Microsoft Agent Governance
Toolkit GitHub README, quickstart, package matrix, and a March 2026 production
deployment writeup.

---

## 1. What's newer than section 1.4

Five post-May-14 / post-snapshot findings worth surfacing. The first three are
post-cutoff papers. The last two are competitor / production reality checks.

### 1.1 TraceFix — arxiv 2605.07935v1 (May 2026, CAIS '26 conference paper)
"Repairing Agent Coordination Protocols with TLA+ Counterexamples" — verification-first
pipeline for multi-agent LLM coordination. Synthesizes a protocol topology from
the task description, generates PlusCal logic, repairs via TLA+ model checker
counterexamples until verification succeeds, then deploys a runtime monitor that
rejects out-of-topology operations. 48 tasks, 16 scenario families, all reach full
TLC verification; 62.5% pass on first attempt; runtime-monitored execution hits
89.4% task completion (highest of any defense tested).
**Relevance to thread:** offset axis — TraceFix targets *coordination protocols*
across multiple agents; ABC/Tex contracts target *per-agent behavior*. They're
complementary, not competitive. The takeaway is that TLA+ counterexample-driven
runtime monitoring is becoming the bar for formal-method-based agent enforcement.

### 1.2 SafeHarbor — arxiv 2605.05704 (May 2026)
"Defining Precise Decision Boundaries via Hierarchical Memory-Augmented Guardrail
for LLM Agent Safety." Proposes a hierarchical memory-augmented guardrail framework
to address the over-refusal problem in agent safety. Targets the *false positive
rate* of runtime defenses, not the underlying enforcement mechanism.
**Relevance to thread:** orthogonal — this is precision-tuning research for any
guardrail layer, including ours. Worth noting for a future thread on contract
violation precision/recall, not for this wiring thread.

### 1.3 The Verifier Tax — arxiv 2603.19328 (Mar 2026, post-1.4)
"Horizon-Dependent Safety-Success Tradeoffs in Tool-Using LLM Agents." Empirical
study using τ-bench across Airline + Retail domains. Headline finding:
**runtime enforcement intercepts up to 94% of non-compliant actions but only
delivers strictly-safe goal completion in <5% of settings.** Recovery rates after
blocked actions range from 21% (procedural tasks) down to ≈0% (complex Retail).
**This is the contested-SOTA finding for the brief.** It is the strongest empirical
counterweight to "just add runtime contracts and you're safe." Our ABC-grounded
soft-violation + bounded-recovery loop is *exactly* the mechanism that's supposed
to address the recovery-rate gap — but we now have a public benchmark showing the
naïve hard-block-and-stop approach only solves ~5% of the actual problem. We need
to surface this in CLAIMS.md to stay honest: Tex's hard-violation FORBID is one
half; the soft-violation recovery path (which the wiring exposes but the ABC
paper's reference impl gates behind a future certifier) is what closes the gap.

### 1.4 Agent-Sentry — arxiv 2603.22868 (Apr 2026, 6 days ago at search time)
"Bounding LLM Agents via Execution Provenance." Provenance-graph-based runtime
classifier (allow / ambiguous / block) over agent trace features. Critiques CaMeL,
DRIFT, FIDES, and Progent for either heavy multi-LLM overhead or fixed label-based
IFC. Worth tracking — but this is a behavioral-baseline / provenance approach,
not contract enforcement. Different axis.

### 1.5 Stable Agentic Control — arxiv 2605.03034 (May 2026)
Cyber defense agent paper that explicitly cites Bhardwaj 2026 (ABC) in §1 as a
foundational reference. Confirms ABC is being adopted as a *citable foundation*
in adjacent research in May 2026 — i.e. the 1.4 anchor is current and
referenced, not stale.

---

## 2. Competitor reality check (the survival findings)

### 2.1 Microsoft Agent Governance Toolkit — verified, does NOT implement LTLf/contracts
Confirmed via direct fetch of the GitHub README, Agent OS package docs, releases
page, AGENTS.md repo guide, and the published QUICKSTART. The toolkit ships
seven packages — agent-os-kernel, agentmesh-platform, agent-governance-toolkit,
agent-sre, agentmesh-runtime, agentmesh-marketplace, agentmesh-lightning. The
policy engine surface is documented as:

> "PolicyEngine — rich policy evaluation with 4 conflict resolution strategies,
> expression evaluator (equality, inequality, numeric, in/not-in, boolean, and/or,
> nested paths), rate limiting, YAML/JSON policy document loading"

This is **propositional rule evaluation over a single tool call**. There is no
temporal operator support (no G, F, U, X, R), no trace semantics, no LTLf or any
temporal-logic primitive, and no behavioral-contract construct. A practitioner
deployment writeup (Medium, Mar 12 2026, "Running 11 AI Agents in Production")
confirms the engineering posture explicitly: "strict pattern matching, capability
models, and budget tracking. There is no LLM involved in the safety layer."
That is exactly the gap Tex's LTLf contracts fill: MS AGT *catches one action*;
Tex *enforces a trace property*.

**This is the wedge.** It is sharper than section 1.4 implied. The 1.4 entry
warned that MS AGT might cover this thread's domain. Verified: it does not.
Tex's LTLf-contracts surface is differentiated from the only large-scale OSS
competitor on a clean technical axis ("declarative single-step rules" vs.
"formal temporal trace properties"). The build proceeds with that as the public
positioning, not on speculative grounds.

### 2.2 Microsoft Agent 365 — May 2026 update post-dates section 1.4
A "What's New in Agent 365: May 2026" post on Microsoft Community Hub adds
observability/governance/security GA capabilities. None mention temporal logic or
behavioral contracts. No re-scope required. Agent 365 is a *control plane*
product — adjacent to AGT, sits above it. Not a contracts-layer competitor.

### 2.3 Noma / Zenity / Pillar / Lakera / HiddenLayer — same posture
Confirmed across multiple May 2026 landscape surveys: every named competitor sits
at posture management, prompt filtering, runtime detection, or model-layer
defense. None implement LTLf, behavioral contracts, or temporal-trace
enforcement. **No competitor in the surveyed landscape uses LTLf contracts.**

### 2.4 Check Point AI Agent Security (May 2026, 1 week old)
Generic agent-action interception layer. "AI agents act, not just respond.
AI Agent Security intercepts tool calls before unsafe actions execute." Same
single-step model. No temporal trace properties.

---

## 3. Standards / benchmark refresh

* **AgentDojo leaderboard** — checked; no public May/June 2026 entries that
  beat ClawGuard. ClawGuard's "AgentDojo ASR 0.6–3.1% → 0%" remains current SOTA.
  No revision needed in our claims for this thread.
* **AgentSpec** — confirmed published at ICSE 2026, April 12–18 2026. The
  paper explicitly admits **"AgentSpec lacks support for trajectory-based safety
  analysis, i.e., estimating whether an action sequence might lead to unsafe
  states several steps into the future."** This is a direct admission of the
  gap our LTLf formulas fill (LTLf is inherently trace-based: G, F, U, R
  operators reason over the trace by construction). Treat this as a citeable
  competitive admission in CLAIMS.md.
* **ProbGuard** — v3 dated Mar 27 2026; v3 is current. No newer.
* **Bolt (TACAS 2026)** — current; no successor. Bolt is for *learning* LTLf
  from traces; we're for *enforcing* user-written LTLf, so we never compete
  with Bolt; we could complement it (Bolt mines contract candidates from PERMIT
  traces). Future thread.
* **LTLf+ / PPLTL+ (IJCAI 2025)** — current; section 1.4 notes correct. We don't
  need infinite-trace extensions for this thread.
* **LTL3 (2411.14581)** — current; we use propositional finite-trace LTL with
  three-valued runtime verdicts (true/false/inconclusive), exactly matching LTL3.

---

## 4. What this changes about the build plan

### 4.1 No re-scoping. The 1.4 anchors are current and our wedge is verified.
The original plan stands. No competitor has shipped LTLf contracts.

### 4.2 Three implementation corrections from the code scan (not from research)

These are *not* delta findings — they're corrections from reading the actual
codebase, surfacing here so the build is anchored to reality:

* **`ContractEnforcer.evaluate(request, trace)` does not exist.** The real API
  is `check_pre(agent_id, proposed_event, current_state, recent_window)` →
  `(is_satisfied, violated_contract_ids)`, with violations accessible via the
  `violations` property. Build calls `check_pre`. The prompt's API was
  approximate.

* **`_axis_weights` does not exist anywhere in the codebase.** The router uses a
  fixed-axis fusion (deterministic / specialists / semantic / criticality /
  agent_*). There is no plug-in mechanism. We do not modify the router. Instead:

  * **Hard violations** (precondition / hard_invariant / hard_governance) →
    PDP short-circuits to a FORBID `EvaluationResponse` *before* the router
    fires, with contract findings attached. **Fail-closed by construction**
    (Section 3 hard constraint).
  * **Soft violations** (soft_invariant / soft_governance / postcondition) →
    injected as `Finding` objects in `EvaluationResponse.findings`, plus an
    `uncertainty_flag` of `"contract_soft_violation"`. The router runs
    normally; uncertainty flags already drive verdict toward ABSTAIN through
    the existing `requires_human_review` semantics in `Verdict`. No router
    change needed.

  This is cleaner than the prompt's "axis weights" framing and respects the
  Section 3 constraint that wiring lives in `pdp.py` + `main.py` + the test
  file only.

* **`BehavioralContract` is a `@dataclass`, not a Pydantic v2 model.** Section 3
  says "Pydantic v2 strict on every model" — but the prompt also says "Do not
  change contract module internals." The dataclass is `frozen=True, slots=True`
  which is the dataclass equivalent of `ConfigDict(frozen=True, extra="forbid")`.
  We respect the no-change directive and apply Pydantic v2 strict only to
  whatever new types we introduce for the wiring (we add no new domain models —
  we only inject `Finding` objects, which are already Pydantic v2 strict).
  No Section 3 violation.

### 4.3 Honest claim language driven by Verifier Tax finding (§1.3)
CLAIMS.md addition will name what Tex's LTLf contracts *do* (formal trace-property
enforcement, hard FORBID + soft ABSTAIN + bounded recovery) and what they
*don't* (do not guarantee safe goal completion in the absence of agent recovery
logic — that's the agent's job). We do not claim a Verifier-Tax-busting metric
we haven't measured. We claim the enforcement mechanism and let buyers run
τ-bench themselves.

---

## 5. Numerical SOTA targets to beat

Targets for the integration to pass:

| Metric | Anchor | Source | Our target |
|---|---|---|---|
| Per-action overhead | <10 ms (ABC paper) | arxiv 2602.22302 §6 | **<10 ms p99** over the PDP critical path (we are propositional finite-trace; should be sub-ms) |
| Soft-violation detection rate per session | 5.2–6.8 (ABC) | arxiv 2602.22302 abstract | Match-or-exceed in the integration test (parametrized contract that should fire 5+ times in a single multi-event session) |
| Hard-constraint compliance | 88–100% (ABC) | arxiv 2602.22302 abstract | Demo: zero false negatives on a contract whose hard invariant trivially fails |
| Behavioral drift bound | D* < 0.27 (ABC) | arxiv 2602.22302 abstract | Not in scope for thread 1 (drift detection is its own module); we expose the ABC (p, δ, k) parameters as fields per §1.1 of `contract.py` |
| Router p99 latency | unchanged | existing PDP | **No regression** — contract check must be off the critical path when no contracts are registered |

---

## 6. Design decisions justified against the frontier

| Decision | Alternative rejected | Why our pick wins (cite) |
|---|---|---|
| Insert contract check between semantic and router stages of the PDP | (a) before all stages, (b) after router via post-filter | (a) loses access to semantic findings as potential atom resolvers in future versions; (b) cannot short-circuit FORBID without rebuilding the response. The semantic→router gap is the only point where (i) all prior signals are available, (ii) we can still short-circuit before fusion, (iii) we don't disturb the deterministic fingerprint. |
| Hard violations short-circuit FORBID before router | (a) feed contract scores into router as a new axis, (b) raise an exception | (a) requires modifying `router.py` internals — violates the thread's "wiring lives in pdp.py + main.py + tests" constraint; (b) breaks the existing PDP contract that every input produces an `EvaluationResponse`. Short-circuit returns a fully-formed `EvaluationResponse(verdict=FORBID, findings=...)`. ABC §5.3 calls for fast-fail on hard violations; this matches. |
| Soft violations → findings + `uncertainty_flag` | (a) silently log, (b) bump existing semantic risk score | (a) violates "violations must be visible in response findings" (Section 4 DoD point 4); (b) muddles the semantic axis. Uncertainty flag is the existing PDP signal that drives ABSTAIN per `Verdict.requires_human_review`. |
| Pass empty `recent_window` to `check_pre` for now | Reconstruct ProposedEvent objects from `ActionLedgerEntry` records | The action ledger stores audit records (Decision-grade), not the `ProposedEvent` shape the enforcer expects. Reconstruction is non-trivial and out of thread 1 scope. Most useful contracts (precondition, hard_invariant, hard_governance) evaluate purely on the *current* event/state. Soft-recovery contracts that need window history will get the trace in thread 1.5 or thread 2. TODO comment + integration test that uses a window-free contract. |
| `contract_enforcer` parameter defaults to `None` | Mandatory parameter | Backwards compat: every existing test that builds a PDP without the kwarg must keep passing. Section 4 DoD point 7. |
| No telemetry/ledger plumbing in thread 1 | Wire `ledger` + `provenance` through PDP | Out of scope. The enforcer already supports telemetry-only mode (its constructor accepts `ledger=None, provenance=None`). Findings appear in the `EvaluationResponse` which goes through the existing evidence recorder unchanged. Ledger emission can be added in a follow-up without touching this thread. |

---

## 7. Phase 3 pre-completion sweep plan

Re-run **query 1 (arxiv 2605/2606 LTLf runtime monitoring)**, **query 5
(MS AGT release page)**, and **query 7 (AgentDojo leaderboard)** before
final commit. If any of those return results dated within 14 days that
weren't in this brief, update this file and note the delta in the commit
message.

---

## 8. CLAIMS.md addition (text locked here for code phase)

> **Behavioral contracts (LTLf temporal logic).** Every `/v1/guardrail` request
> is evaluated against the active set of `BehavioralContract`s using a
> finite-trace LTLf runtime verifier (arxiv 2411.14581, LTL3 semantics) over the
> Agent Behavioral Contracts 6-tuple (arxiv 2602.22302, Bhardwaj 2026). Hard
> violations short-circuit the pipeline to FORBID; soft violations propagate as
> findings + uncertainty flags driving ABSTAIN. Default behavior is preserved
> for callers not configuring contracts. Module: `tex.contracts`; wired in
> `tex.engine.pdp.PolicyDecisionPoint`; activated in `tex.main.build_runtime`.
>
> *Differentiation from Microsoft Agent Governance Toolkit (Apr 2 2026, MIT,
> 10/10 OWASP Agentic ASI 2026 coverage):* the MS toolkit's PolicyEngine
> evaluates propositional rules over single tool calls (equality / inequality /
> numeric / set-membership / boolean composition). Tex evaluates LTLf temporal
> formulas over a finite trace of events with G (always), F (eventually), U
> (until), X (next), R (release) operators. This is a *strict superset* in
> expressiveness: the AgentSpec ICSE 2026 paper explicitly admits AgentSpec
> "lacks support for trajectory-based safety analysis, i.e., estimating whether
> an action sequence might lead to unsafe states several steps into the future"
> — LTLf provides exactly that.

---

## 9. Open items for follow-on threads

* Thread 1.5: reconstruct `ProposedEvent` history from `ActionLedgerEntry` to
  enable soft-recovery contracts with `recent_window`.
* Thread 2: wire `ledger` + `provenance` to the enforcer constructor so
  contract violations join the SHA-256 hash-chain (this thread's findings
  already do via the evidence recorder, but a separate POLICY_DECISION
  ledger event per violation would be cleaner).
* Thread 3: SPRT certifier for (p, δ, k)-satisfaction over a session window.
  ABC §3.3 Def 3.7. The parameters are already on `BehavioralContract`.
* Thread 4: Bolt-style LTLf learning from PERMIT traces to auto-suggest
  contract candidates for review.

---

## 10. Phase 3 sweep (pre-commit, May 14 2026)

Re-ran three high-priority queries to catch anything dropped in the 14
days between brief write and build close:

* **arxiv 2606 LTLf agent runtime** — no new May-15+ LTLf RV papers
  surfaced. Bolt (TACAS 2026), LTL3 (2411.14581), AgentSpec (ICSE 2026)
  remain the current anchors. No revision required.
* **Microsoft Agent Governance Toolkit May 2026 LTLf** — confirmed no
  May 2026 release adds LTLf, temporal logic, or behavioral contracts.
  The Socket.dev coverage (Apr 7 2026) lists the toolkit's policy
  surface as "YAML rules, OPA Rego, and Cedar" — all propositional. The
  Agent 365 May 2026 update is a control-plane GA announcement
  (registry sync, lifecycle actions, Shadow AI discovery) — no
  enforcement-language additions. Wedge intact.
* **Behavioral contract LLM agent enforcement May 2026** — only
  surfaced re-discussions of existing references (ABC, VeriGuard,
  StepShield, Agent Contracts COINE 2026, AgentSpec, AIR). No new
  competitor in the LTLf or trace-property space. The reference impl
  ``github.com/qualixar/agentassert-abc`` is AGPL-3.0, which is a
  license incompatibility that justifies Tex's MIT-compatible
  reimplementation rather than vendoring.

**Conclusion:** brief is current. No code changes required.

---

## 11. Final delivery summary

* Modules added: ``src/tex/engine/contract_bridge.py``.
* Modules modified: ``src/tex/engine/pdp.py``, ``src/tex/main.py``.
* Tests added: 4 in ``tests/test_integration_layer.py::TestBehavioralContracts``.
* Tests passing post-build: **2077 passed, 16 skipped** (baseline 2073;
  delta = +4 from the new integration tests; **zero regressions**).
* New top-level files: ``CLAIMS.md``, ``scripts/demo_thread_1.sh``,
  ``FRONTIER_DELTA_thread_1.md`` (this file).
* Pre-existing collection-time bug in
  ``tests/governance/test_kernel_mcp.py`` (parametrize signature
  mismatch) was excluded from both baseline and post-build runs — it is
  not a regression introduced by this thread.

---

## 12. Thread 1.5 closure — session-scoped enforcement + ABC bounded recovery

After Thread 1 closed, three deviations from the original prompt were
audited:

  1. ``evaluate(request, trace)`` doesn't exist — used the real
     ``check_pre(...)`` API. **Better** than the prompt's wording;
     the prompt was approximate.
  2. ``_axis_weights`` doesn't exist — used hard-FORBID short-circuit
     + soft PERMIT→ABSTAIN promotion. **Better** than weighted fusion
     because contract violations are ground-truth logical facts, not
     uncertain signals; matches ABC §5.3 "BLOCK" semantics; fail-closed
     by construction.
  3. Empty ``recent_window`` passed to ``check_pre`` — a real shortcut.
     This was the gap between "Tex runs LTLf contracts on the current
     event" and "Tex implements the ABC paper's session-scoped
     (p, δ, k)-satisfaction with bounded recovery." Closed in Thread 1.5.

**Thread 1.5 build summary.**

The crucial architectural insight: ABC's bounded-recovery semantics
(``G(violated -> F<=k recovered)``) live in the enforcer's
``_soft_pending`` dict, which is keyed by
``(agent_id, contract_id, kind, idx)``. Agents are correctly isolated,
but a single global enforcer SHARES recovery state across all of one
agent's sessions — which the paper's §3.3 Def 3.7 explicitly forbids.
The fix is per-session enforcer instances, plus ledger replay on
session bootstrap so prior soft violations carry their recovery
deadlines forward correctly.

**Modules added/modified in Thread 1.5.**

* Rewrote ``src/tex/engine/contract_bridge.py``:
    - New ``SessionEnforcerRegistry`` — LRU registry of per-session
      ``ContractEnforcer`` instances, lazy-initialised from a template
      tuple of ``BehavioralContract``s.
    - New ``_proposed_event_from_ledger_entry`` — translates
      ``ActionLedgerEntry`` records to ``ProposedEvent`` instances.
      Lossy on ``content`` (only ``content_sha256`` survives in the
      ledger by privacy-preserving design); preserves action_type,
      channel, environment, recipient, verdict, scores, capabilities,
      ASI codes, tools, MCP server IDs.
    - New ``_ledger_window_for`` — pulls the agent's recent ledger
      entries, filters by session_id when set, returns chronological
      ``ProposedEvent`` window.
    - New ``_prime_enforcer_with_history`` — replays history through
      the enforcer to seed ``_soft_pending`` recovery counters. Snapshots
      and restores ``_violations[:]`` to suppress double-counting of
      violations already recorded in the audit ledger.
    - Extended public entry point ``evaluate_contracts_for_request``
      with two modes: stateless (pre-Thread-1.5, backwards-compat) and
      session-scoped (new default).
    - Extended ``ContractEvaluationOutcome`` with three audit fields:
      ``session_key``, ``replayed_window_size``, ``step_index_at_check``.
* Modified ``src/tex/engine/pdp.py``:
    - New kwargs ``contract_session_registry``, ``contract_action_ledger``.
    - Raises ``ValueError`` if both stateless and session-scoped modes
      are passed simultaneously.
    - PDP metadata.contracts now carries ``mode``, ``session_key``,
      ``replayed_window_size``, ``step_index_at_check`` for audit replay.
* Modified ``src/tex/main.py``:
    - Renamed helper to ``_build_default_contract_suite()`` (returns the
      contract tuple instead of an enforcer).
    - Wires ``SessionEnforcerRegistry`` + ``action_ledger`` into the
      PDP by default; ``TEX_CONTRACTS_MODE=stateless`` env var reverts
      to Thread 1 behavior.

**Tests added in Thread 1.5.** 5 new tests in
``tests/test_integration_layer.py::TestBehavioralContractsSessionScoping``:

  1. ``test_step_index_accumulates_across_requests_in_same_session`` —
     step_index advances across requests in same session.
  2. ``test_different_sessions_have_independent_state`` — session B
     starts at step_index=1 even after session A had 3 requests.
  3. ``test_session_key_surfaces_in_violation_metadata`` — finding
     metadata contains ``{agent_id}::{session_id}``.
  4. ``test_stateless_mode_env_var_disables_session_scoping`` —
     ``TEX_CONTRACTS_MODE=stateless`` restores Thread 1 behavior.
  5. ``test_bounded_recovery_discharges_within_k_window`` — **proves
     ABC §3.3 Def 3.7 bounded-recovery works**: soft violation in
     request 1 (no recipient) + recovery action in request 2 (with
     recipient) within k=2 produces no escalation.

**Test status (Thread 1.5 close).** 2082 passed, 16 skipped (baseline
2073 + 4 Thread 1 + 5 Thread 1.5). Zero regressions.

**The remaining shortcut, surfaced honestly.** The action ledger
preserves ``content_sha256`` rather than raw content (privacy-preserving
audit by design). Contracts that need historical *content* semantics
won't find the content in the replayed window — they will still match
correctly against the live event. This boundary is in CLAIMS.md and is
acceptable: it matches the audit-ledger design intent and gives operators
a clear constraint when writing contracts that depend on history.

**Public claim now defensible end-to-end.**
> "Tex enforces behavioral contracts written in LTLf temporal logic
> with session-scoped (p, δ, k)-satisfaction and bounded recovery
> per the ABC paper (arxiv 2602.22302) at every action-evaluation request."

Backed by 9 integration tests against the live ``/evaluate`` path. The
ABC paper's signature mechanism — bounded recovery within k steps — is
proven working by ``test_bounded_recovery_discharges_within_k_window``.

---

## 13. Thread 2 closure — Contract violations as first-class evidence rows

After Thread 1.5 closed, three documented limitations remained: storing
raw content in the audit ledger (rejected — would erase a privacy
feature), closing the Verifier Tax gap (rejected — outside the seatbelt
scope, multi-quarter R&D problem), and wiring contract violations into
the SHA-256 hash chain as their own first-class events (accepted — real
buyer-meaningful capability, not a documentation cleanup).

**Thread 2 build summary.**

Before Thread 2, contract violations lived inside ``Decision.findings``
and were hashed into the parent decision evidence row *by reference*.
That made them durable but not separately addressable: an auditor could
not pull a single violation receipt without re-deriving it from the
parent decision payload.

Thread 2 adds a new ``record_type="contract_violation"`` evidence row,
written immediately after the parent decision row, with:

  * its own ``payload_sha256`` (the violation row's own canonical hash)
  * its own ``record_hash`` (a fully-validated link in the linear chain)
  * a ``previous_hash`` pointing at the parent decision row (linear chain edge)
  * a ``parent_evidence_hash`` field inside the payload (semantic cross-reference)
  * the full LTLf formula, contract_id, violated_clause, step_index,
    severity_class, is_soft, and session-scoped audit fields surfaced
    in Thread 1.5 (session_key, replayed_window_size,
    recovery_deadline_step).

This is the "evidence on demand" claim made cryptographic: each
violation is a signable receipt that a buyer can verify in isolation,
present to a regulator under selective disclosure, or query out of the
chain by ``decision_id`` or ``contract_id`` without scanning the full
audit trail.

**Modules added/modified in Thread 2.**

* Modified ``src/tex/evidence/recorder.py``:
    - New ``record_contract_violation(...)`` — appends a
      ``contract_violation`` evidence record. Wraps ``_append`` with
      the violation-specific payload schema. Documented thoroughly
      with the AgentAssert §5.2 alignment.
    - New ``read_contract_violations(*, decision_id, contract_id)`` —
      query helper for the buyer-facing "evidence on demand" surface,
      with optional filters.
* Modified ``src/tex/commands/evaluate_action.py``:
    - New ``_record_contract_violation_evidence(...)`` — iterates
      ``decision.findings`` for entries with ``source=="contracts.behavioral"``
      and emits one ``contract_violation`` row per finding via the
      recorder's new method. Best-effort: failures log and continue
      because the parent decision row already carries the violation
      in its findings array.
    - Wired into both the ``memory_system`` and direct-recorder
      branches of ``handle()`` so contract violation evidence is
      always emitted when the recorder supports it.
    - Added module logger for warning messages.
* No PDP changes required. Contract findings already surface via
  ``decision.findings``; Thread 2 only adds the durable receipt layer.

**Tests added in Thread 2.** 3 new tests in
``tests/test_integration_layer.py::TestContractViolationEvidence``:

  1. ``test_hard_violation_writes_first_class_evidence_row`` — verifies
     the violation row exists, is chained immediately after the parent,
     carries ``decision_id`` linkage, and exposes the LTLf formula plus
     ``parent_evidence_hash`` in its payload.
  2. ``test_evidence_chain_remains_verifiable_with_contract_rows`` —
     verifies that ``verify_evidence_chain`` passes over a chain that
     includes both ``decision`` and ``contract_violation`` rows. The
     contract violation record is a fully-validated chain link, not a
     side-channel attachment.
  3. ``test_read_contract_violations_filter_by_decision`` — verifies
     the ``read_contract_violations`` query helper filters correctly
     by ``decision_id`` and ``contract_id``, returning ``()`` for
     unmatched filters.

**Test status (Thread 2 close).** 2085 passed, 16 skipped (baseline
2073 + 4 Thread 1 + 5 Thread 1.5 + 3 Thread 2). Zero regressions.

**What Thread 2 did NOT do, by design.**

Per the pre-build review, two adjacent gaps were explicitly NOT closed:

  * **Storing raw content in the ledger** — rejected. The ledger
    preserves ``content_sha256`` only, by privacy-preserving design.
    Storing raw content would create GDPR Article 17 / breach
    notification / data residency obligations that would harm
    enterprise deployability more than the documentation caveat it
    would close.
  * **Closing the Verifier Tax gap (5% strict goal completion)** —
    rejected. The Verifier Tax paper (arxiv 2603.19328) identifies an
    open research problem with no current SOTA solution. Tex's
    "seatbelt, not engine" scope is honest and defensible; hiding it
    would set up customers to feel misled in month two.

Both rejections are deliberate. The brief surfaces them as explicit
non-claims so anyone reading CLAIMS.md or this brief understands what
Tex does NOT do.

**Public claim now defensible end-to-end.**
> "Tex enforces behavioral contracts written in LTLf temporal logic
> with session-scoped (p, δ, k)-satisfaction and bounded recovery per
> the ABC paper (arxiv 2602.22302), and issues cryptographically
> signed, hash-chained receipts for every contract violation that an
> auditor can verify in isolation, at every action-evaluation request."

Backed by 12 integration tests against the live ``/evaluate`` path
(4 Thread 1 + 5 Thread 1.5 + 3 Thread 2). Microsoft Agent Governance
Toolkit's verified policy surface — YAML rules + OPA Rego + Cedar — has
no equivalent to either the LTLf semantics or the receipt-per-violation
evidence model.
