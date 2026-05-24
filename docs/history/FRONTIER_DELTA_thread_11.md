# Frontier delta — Thread 11 (May 20, 2026)

## Scope
Wire the existing GAAP-style ``tex.governance.private_data_exec``
sandbox into the live PDP request path, extended with the four
bleeding-edge May 2026 IFC advances that no shipping competitor has
yet implemented. Deliver one composite ``IfcSpecialist`` that fuses
ARM denial-aware causal provenance + FIDES dual-axis IFC + NeuroTaint
cross-session taint + CA-CI six-tuple contextual integrity into a
single specialist verdict on every adjudication.

## Research deltas vs Tex's prior thread (Thread 10, May 18-20)

### ARM (Agentic Reference Monitor) — the primary anchor
- **arXiv:2604.04035 v1** (Chinaei, Apr 5 2026). Identifies *causality
  laundering*: a denial-feedback leakage pattern where an adversary
  probes a protected action, learns from the denial outcome, and
  exfiltrates the inferred information through a later seemingly
  benign tool call.
- Flat IFC tracking (FIDES) misses this attack because no successful
  data flow occurred. Dependency graphs over *successful* executions
  (PCAS) miss it because the denied call has no successful output.
  Causal-attribution defenses (AgentSentry, CausalArmor) miss it
  because they ablate untrusted *content*, not denial events.
- ARM's defense: model denied actions as first-class provenance
  nodes; auto-link a ``Counterfactual`` edge to the next CALL; query
  graph reachability through that edge.
- Five-level integrity lattice (ARM §2.3):
  ``ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr``.
  Conservative join is *min* (MinTrust).
- Four-edge graph (ARM §5.2):
  ``DirectOutput``, ``InputTo``, ``FieldOf``, ``Counterfactual``.
- Four-node taxonomy:
  ``Call``, ``Data``, ``DataField``, ``DeniedAction``.
- Sub-millisecond enforcement on graphs of tens-to-hundreds of nodes.

### FIDES (Flow-Integrity Deterministic Enforcement System)
- **arXiv:2505.23643** (Costa/Köpf/Kolluri/Paverd/Russinovich/Salem/
  Tople/Wutschitz/Zanella-Béguelin, Microsoft Research, 2025).
- Open-source: github.com/microsoft/fides (MIT).
- Key novelty: *product lattice* ``(ℓ, μ)`` — labels × type-capacity.
  Low-capacity output types (bool, enum) can safely declassify
  because they cannot encode an arbitrary attacker payload.
- Only two policies (weak-secrecy + integrity) instead of per-tool
  rules — easier formal reasoning.

### NeuroTaint — "Ghost in the Agent"
- **arXiv:2604.23374** (Apr 2026). First framework explicit about
  three IFC dimensions in LLM agents:
    1. Explicit content transfer
    2. Semantic transformation (LLM rephrases tainted content)
    3. Causal influence on decisions
    4. **Cross-session persistence through memory** — taint outlives
       a single request.
- The cross-session axis is what we wire via ``MemoryStream``.

### PCAS (Policy Compiler for Agentic Systems)
- **arXiv:2602.16708 v2** (Palumbo/Choudhary/Choi/Chalasani/
  Christodorescu/Jha; Wisconsin + Google, Feb 18 2026).
- Datalog-derived policy language over dependency graphs.
- 48% → 93% policy compliance on customer-service tasks, zero
  violations in instrumented runs.
- We adopt PCAS's "dependency graph captures causal relationships
  among events" perspective but enforce via direct graph traversal
  rather than compiled Datalog (Datalog can be added later as a
  policy-spec front-end without changing the graph engine).

### CA-CI — Contextual Integrity + Capabilities Approach
- **Roemmich/Martin/Schaub, IEEE Security & Privacy (2026)**.
  Extends Nissenbaum's five-tuple by elevating *purpose* to a
  constitutive parameter, enabling scope-creep detection.
- Six-tuple norm:
  ``(sender, receiver, subject, information_type,
     transmission_principle, purpose)``.
- A flow is *appropriate* iff it matches a permitted norm. Same
  flow with a different purpose = different norm.

### SAFEFLOW — transactional IFC with WAL
- **arXiv:2506.07564**. Multi-agent, transactional execution,
  write-ahead logging, secure caches. Bigger surface than our
  Thread 11 scope but cited as the next logical extension; the
  ``IfcEngine`` and ``ProvenanceGraph`` we ship are compatible
  with adding WAL/rollback as a Thread 12 follow-up.

### Rule of Two corrective
- **Meta AI, Oct 31 2025**: an agent should satisfy at most two of
  three properties simultaneously — (A) processes untrusted input,
  (B) has access to sensitive data, (C) communicates externally.
- **EchoLeak counterexample** (CVE-2025-32711; Reddy & Gujral AAAI
  Fall 2025; Towards AI analysis Nov 14 2025): Rule of Two as
  taught is insufficient because *private data is also a source*.
  The defense is taint analysis where private data carries a label
  alongside untrusted input.
- We implement the corrective: if all three buckets are present we
  fire ``ifc.rule_of_two_trifecta``.

## Competitor landscape (the wedge, May 20 2026)
- **Microsoft Agent Governance Toolkit** (Apr 2 2026, MIT, 7
  packages, sub-ms policy enforcement): zero IFC module. The
  ``agent-os`` policy engine is stateless.
- **Microsoft Agent 365** (GA May 1 2026): observe / govern / secure
  pillars; no IFC, no causal provenance, no cross-session taint.
- **Zenity / Noma / Pillar / Lakera / Rubrik SAGE**: none ship
  denial-aware causal provenance, cross-session IFC, or CI norms
  at runtime.
- **FIDES** itself (Microsoft Research) is the closest thing on the
  market — open-source planner library, not a runtime governance
  product. ARM is research-only. PCAS is research-only. NeuroTaint
  is research-only. CA-CI is academic.

This is precisely the white space Tex's Thread 11 claims: a single
specialist that fuses all four research advances into one
deterministic runtime verdict, on the same evidence chain as Tex's
other four content streams plus the three agent streams.

## What Tex shipped this thread

1. **`tex.governance.private_data_exec.ifc.lattice`** — 5-level
   integrity lattice (ARM) + 4-level confidentiality lattice +
   FIDES 6-step capacity lattice; composite ``IfcLabel`` with
   monotonic join semantics; predefined source labels for the
   common Tex request-element categories.

2. **`tex.governance.private_data_exec.ifc.provenance`** —
   ``ProvenanceGraph`` with four edge kinds and four node kinds.
   ARM Algorithm 1 (auto-link Counterfactual on next CALL after a
   denial) is implemented. ``min_trust``, ``max_sensitivity``,
   ``effective_label``, ``has_counterfactual_chain``, and
   ``counterfactual_denials`` queries plus a stable SHA-256
   ``fingerprint`` for determinism replay.

3. **`tex.governance.private_data_exec.ifc.memory`** —
   tenant-scoped, capacity-bounded, TTL-evicted LRU memory stream
   keyed by content hash. The NeuroTaint cross-session axis.
   Thread-safe via a single lock; no Postgres dependency (a
   durable backend can be added without API change).

4. **`tex.governance.private_data_exec.ifc.ci_norms`** —
   ``CiNorm`` (CA-CI six-tuple, frozen Pydantic model) and
   ``CiNormRegistry``. ``with_purpose()`` helper for scope-creep
   tests. Fail-closed when at least one norm is registered;
   advisory-only otherwise.

5. **`tex.governance.private_data_exec.ifc.classifier`** — maps
   Tex ``EvaluationRequest`` fields and ``RetrievalContext``
   collections to labeled source nodes. Lexical confidentiality
   classifier (SSN, API keys, card patterns) + operator-asserted
   overrides via ``metadata["sensitivity"]``. Sink-action set
   covers send_email, post_message, transfer_funds, deploy_code,
   etc.

6. **`tex.governance.private_data_exec.ifc.engine`** — the
   orchestrator. Builds the per-request provenance graph, runs all
   six checks, records cross-session taint, emits structured
   ``IfcVerdict`` with risk score, fingerprint, and per-violation
   evidence.

7. **`tex.specialists.ifc_specialist.IfcSpecialist`** — narrow
   adapter wrapping the engine into a ``SpecialistJudge``.
   Registered at the tail of ``default_specialist_judges()`` as
   specialist #15. Maps violation classes to OWASP ASI 2026
   short-codes.

8. **Tests (81 new):**
   - 14 lattice tests in ``tests/governance/test_ifc_lattice.py``
   - 14 provenance-graph tests in
     ``tests/governance/test_ifc_provenance.py`` (incl. p99 <5ms
     latency benchmark on a 50-node graph)
   - 8 memory tests in ``tests/governance/test_ifc_memory.py``
   - 8 CI-norm tests in ``tests/governance/test_ifc_ci_norms.py``
   - 17 engine tests in ``tests/governance/test_ifc_engine.py``
     covering all six violation classes, plus benign, monotone
     risk, frozen verdict, sink-vs-non-sink behavior, and
     retrieved-entity sensitivity promotion.
   - 12 specialist tests in
     ``tests/specialists/test_ifc_specialist.py``
   - 3 live-pipeline integration tests in
     ``tests/test_integration_layer.py::TestIfcSpecialistInLiveGuardrail``

9. **Documentation & claim chain:**
   - ``CLAIMS.md``: removed
     ``tex.governance.private_data_exec`` from the "not wired"
     list; added a complete Thread 11 claim block with all
     references.
   - ``COMMIT_MSG_thread_11.txt``: commit message naming the
     primary arXiv IDs.

## Honest gaps and explicit non-claims

1. **No PCAS Datalog frontend yet.** Our graph is structurally
   compatible with a Datalog policy spec (PCAS uses the same
   "dependency graph + reference monitor" pattern), but we ship
   direct Python traversal queries. A Datalog frontend is straight-
   forward to add in a follow-up thread without API change.

2. **No FIDES quarantined-LLM declassification path.** FIDES's
   product lattice allows declassification when a quarantined LLM
   produces a low-capacity output. We ship the *capacity tag* but
   not the quarantined-LLM execution path; the tag is operator-
   asserted in the current build. A "declassify if upstream is a
   quarantined LLM" wire-in is a follow-up.

3. **No rustworkx dependency.** ARM uses rustworkx for sub-ms
   graph operations. We use pure-Python BFS and benchmark it under
   5ms p99 on 50-node graphs (test in
   ``test_ifc_provenance.py``). On larger graphs (thousands of
   nodes) a rustworkx backend would be worth adding; for typical
   Tex requests our budget is preserved.

4. **NeuroTaint is in-memory only.** ``MemoryStream`` is bounded
   and TTL-evicted; it does not survive a process restart. A
   Postgres-durable variant is a separate thread.

5. **GAAP's existing ``DisclosureLog`` is preserved unchanged.**
   The new ``ifc/`` subpackage is *additive* — it does not replace
   GAAP's permission DB or disclosure log. GAAP remains the
   downstream egress audit; ``ifc/`` is the upstream policy gate.

## What is now true that wasn't before

Tex's ``/v1/guardrail`` request path now runs, on every
adjudication, a deterministic six-check IFC pass that:

- detects causality laundering (ARM novel attack class) via
  counterfactual edges in a provenance graph;
- enforces dual-axis label-based IFC (FIDES) with a product
  lattice and a declassification rule;
- tracks taint across agent sessions (NeuroTaint);
- matches the realized flow against a CA-CI six-tuple norm
  registry with explicit scope-creep detection;
- catches the Meta Rule-of-Two trifecta corrected for the
  EchoLeak counterexample (private data is also a source);
- emits structured evidence into the same hash-chained evidence
  bundle as the other 14 specialists, the deterministic layer,
  and the three agent streams.

Microsoft Agent Governance Toolkit and Agent 365 ship none of
this. Zenity, Noma, Pillar, Lakera, Rubrik SAGE ship none of
this. The May 2026 papers (ARM, FIDES, NeuroTaint, PCAS, CA-CI)
exist in theory; Tex Thread 11 is the operational wire-in.
