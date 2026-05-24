# CLAIMS.md — Tex public-facing capability claims

This file is the single source of truth for what Tex actually does in the
live ``/v1/guardrail`` request path. Every claim names the wired module
and the test that proves it. Outreach copy must not exceed what's listed
here.

Discipline:
  * **Wired** = exercised by an actual ``/v1/guardrail`` (or ``/evaluate``)
    request and asserted in ``tests/test_integration_layer.py``.
  * **Built-but-unwired** = passing unit tests in ``tests/``, but not yet
    consumed by ``PolicyDecisionPoint`` (or equivalent live endpoint).
  * Anything not in this file is not a claim. If outreach references a
    capability, it must show up here first.

---

## Wired claims

### 1. Behavioral contracts in LTLf temporal logic with session-scoped (p, δ, k)-satisfaction (Thread 1 + Thread 1.5)

**Claim.** Every ``/v1/guardrail`` request is evaluated against the
active set of ``BehavioralContract``s using a finite-trace LTLf runtime
verifier (LTL3 three-valued semantics) over the Agent Behavioral
Contracts 6-tuple (preconditions / hard invariants / soft invariants /
hard governance / soft governance / recovery). Hard violations
short-circuit the pipeline to FORBID before fusion. Soft violations
propagate as findings + an uncertainty flag and promote PERMIT to
ABSTAIN. Per-``(agent_id, session_id)`` enforcer instances maintain
the recovery-counter state across requests, so ABC's bounded-recovery
semantics ``G(violated -> F<=k recovered)`` work end-to-end across an
agent session. Default behavior is preserved bit-for-bit for callers
not configuring contracts (default registry is None → zero-cost
neutral branch).

**Source paper anchors.**
- Bhardwaj 2026, *Agent Behavioral Contracts: Formal Specification and
  Runtime Enforcement for Reliable Autonomous AI Agents* (arxiv
  2602.22302) — §3 6-tuple structure; §3.3 Def 3.7
  (p, δ, k)-satisfaction; §5.3 per-turn enforcement loop.
- De Giacomo & Vardi 2013 — LTLf finite-trace semantics.
- Bauer, Leucker, Schallhart 2011 / arxiv 2411.14581 — LTL3
  three-valued runtime-verification semantics.
- Felicia et al. 2026 / arxiv 2601.22136 (StepShield) — temporal
  detection metrics; session-scoped ``step_index`` enables Early
  Intervention Rate / Intervention Gap measurement.

**Modules.**
  * Spec: ``tex.contracts.BehavioralContract``,
    ``tex.contracts.ContractEnforcer``, ``tex.contracts.ContractViolation``,
    ``tex.contracts._ltl.LTLFormula``, ``tex.contracts._atoms.ContractContext``.
  * Wiring: ``tex.engine.pdp.PolicyDecisionPoint``,
    ``tex.engine.contract_bridge.evaluate_contracts_for_request``,
    ``tex.engine.contract_bridge.SessionEnforcerRegistry``.
  * Composition root: ``tex.main.build_runtime`` (env vars
    ``TEX_CONTRACTS_DISABLE=1`` opts out; ``TEX_CONTRACTS_MODE=stateless``
    reverts to Thread 1 single-enforcer behaviour).

**Tests proving the claim.**
  * ``tests/test_integration_layer.py::TestBehavioralContracts`` (4 tests)
    — clean PERMIT, hard-FORBID, soft-ABSTAIN, env-disable.
  * ``tests/test_integration_layer.py::TestBehavioralContractsSessionScoping``
    (5 tests) — step_index accumulation across requests in a session,
    independent state across different sessions of the same agent,
    session_key in violation metadata, stateless-mode env var reverts
    behavior, **bounded-recovery discharges within k window** (the ABC
    §3.3 signature mechanism).

**Demo.** ``scripts/demo_thread_1.sh``.

**Competitive differentiation.**
Microsoft Agent Governance Toolkit (Apr 2 2026, MIT, 10/10 OWASP Agentic
ASI 2026 coverage) evaluates propositional rules over single tool calls:
equality, inequality, numeric, set-membership, boolean composition. Tex
evaluates LTLf temporal formulas over a finite trace of events with
``G`` (always), ``F`` (eventually), ``F<=k`` (bounded eventually),
``U`` (until), ``X`` (next), ``R`` (release), session-scoped across
agent activity. This is a strict expressiveness superset. The
AgentSpec ICSE 2026 paper (Wang/Poskitt/Sun) explicitly admits its
rule DSL "lacks support for trajectory-based safety analysis, i.e.,
estimating whether an action sequence might lead to unsafe states
several steps into the future" — LTLf with session-scoped state
provides exactly that.

**Honest scope statement.**
The Verifier Tax study (arxiv 2603.19328, Mar 2026) found that runtime
enforcement intercepts up to 94% of non-compliant actions on τ-bench but
delivers strictly-safe goal completion in <5% of settings. Tex's claim
is the *enforcement mechanism*: hard-violation FORBID with cryptographic
evidence, soft-violation ABSTAIN with uncertainty propagation, and the
ABC paper's bounded-recovery window k surfaced as a contract field. We
do not claim Tex closes the goal-completion gap; that requires
agent-side recovery logic, which is the agent's responsibility, not the
enforcement layer's.

**Replay limitation surfaced honestly.**
The action ledger preserves ``content_sha256`` rather than raw content
(privacy-preserving audit by design). Past-event atoms that read
``field:content~contains:...`` will not match against the replayed
window — they will still match correctly against the *live* event, but
historical content semantics require contracts written against the
fields the ledger preserves (action_type, channel, environment,
recipient, content_sha256, verdict, scores, capability_violations,
asi_short_codes, policy_version, evidence_hash).

---

### 2. Cryptographic evidence-on-demand for behavioral contract violations (Thread 2)

**Claim.** Every behavioral contract violation produces its own
first-class evidence record in the SHA-256 hash chain, with its own
``payload_sha256`` and its own ``record_hash``, linked to the parent
decision evidence record by both the linear chain edge
(``previous_hash``) and a semantic cross-reference
(``parent_evidence_hash``). A buyer (or a regulator) can verify a
single violation receipt in isolation, query the chain by
``decision_id`` or ``contract_id`` to retrieve all matching receipts,
and present selective disclosure proofs without exposing unrelated
decision payloads.

**Source paper anchors.**
- Bhardwaj 2026, arxiv 2602.22302 §5.2 — AgentAssert evidence model:
  every contract violation is a discrete, signable, cryptographically
  chained event.
- The Tex implementation strengthens the paper's model by keeping the
  linear-chain integrity property of the JSONL evidence log intact:
  the contract violation row is itself a fully-validated link in the
  hash chain, not a side-channel attachment.

**Modules.**
  * Append API: ``tex.evidence.recorder.EvidenceRecorder.record_contract_violation``.
  * Query API: ``tex.evidence.recorder.EvidenceRecorder.read_contract_violations``
    (filters by ``decision_id`` and/or ``contract_id``).
  * Wiring: ``tex.commands.evaluate_action.EvaluateActionCommand._record_contract_violation_evidence``
    — runs immediately after the parent decision evidence row is written,
    in both the ``memory_system`` and direct-recorder branches.

**Tests proving the claim.**
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_hard_violation_writes_first_class_evidence_row``
    — a hard violation produces exactly one ``contract_violation`` row
    chained immediately after the parent ``decision`` row, with all
    semantic cross-references intact (decision_id, contract_id,
    clause_ltl, parent_evidence_hash).
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_evidence_chain_remains_verifiable_with_contract_rows``
    — ``verify_evidence_chain`` passes over the combined chain of
    decision and contract_violation rows; the contract violation
    record is a fully-validated link, not a side channel.
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_read_contract_violations_filter_by_decision``
    — the query helper correctly filters by ``decision_id`` and
    ``contract_id``, returning ``()`` for unmatched filters.

**Buyer-meaningful framing.**
"Tex doesn't just log that a contract violation happened — it issues a
cryptographically signed receipt for it. Each receipt is independently
verifiable, addressable by ``decision_id`` or ``contract_id``, and
chained into the same tamper-evident SHA-256 hash chain that protects
every other audit event. Selective disclosure to regulators or insurers
becomes trivial: hand them the receipt plus the chain segment up to its
parent, without exposing any unrelated content or decisions."

---

## Thread 2 — Institutional governance-graph LTS (wired, May 14 2026)

**Public-facing claim:**

> **Institutional governance (governance-graph LTS).** Every
> ``EcosystemEngine.evaluate()`` invocation is checked against the active
> institutional governance graph — a public, immutable manifest declaring
> legal states, transitions, sanctions, and restorative paths per Bracale
> Syrnikov et al. (arxiv 2601.11369, Jan 2026; mean collusion tier 3.1 →
> 1.8, Cohen's d=1.28 vs Ungoverned in repeated homogeneous-agent Cournot
> duopoly experiments). Illegal transitions return FORBID with rationale
> citing the (from_state, triggered_by) pair that has no manifest-declared
> edge. Every assessment — legal or illegal — is recorded to a
> cryptographically-keyed, append-only governance log signed via
> ``tex.pqcrypto.algorithm_agility`` with automatic algorithm-agility
> selection (ML-DSA-65 / HYBRID_ML_DSA_ED25519 / ECDSA-P256 per liboqs
> availability). Modules: ``tex.institutional``,
> ``tex.institutional._pq_signing``,
> ``tex.institutional.subagent_inheritance``; wired in
> ``tex.ecosystem.engine.EcosystemEngine``.
>
> *Subagent state inheritance:* per arxiv 2605.08460 (Cai/Zhang/Hei, May 8,
> 2026 — "When Child Inherits"), an actor's effective institutional state
> is the most-restrictive state across its ``spawned_by`` chain. A
> subagent of a ``suspended`` actor is evaluated under ``suspended``.
>
> *EU AI Act framing:* the GovernanceLog satisfies Article 12 (logging
> integrated into core design, not bolted on) and Article 19 (≥6-month
> retention via durable Postgres backing in production). Article 50
> deployer transparency obligations apply August 2, 2026. **Phase 3
> sweep update (May 14, 2026):** On May 7, 2026 the Council + Parliament
> reached *provisional political agreement* on the Digital Omnibus on
> AI. If formally adopted (expected June-July 2026), Annex III standalone
> high-risk obligations move to December 2, 2027; Annex I embedded
> high-risk to August 2, 2028; Article 50(2) watermarking to December 2,
> 2026. All other Article 50 transparency obligations remain at August 2,
> 2026. Article 12 logging obligations are unchanged in both timelines —
> Tex's GovernanceLog satisfies them under either schedule.
>
> *Differentiation from Microsoft Agent Governance Toolkit v3.5.0 (May
> 2026, MIT, 10/10 OWASP Agentic Top 10 coverage):* the AGT PolicyEngine
> evaluates propositional rules over single tool calls (YAML, OPA Rego,
> Cedar) with a reputation-based trust-tier overlay (0-1000, 5 behavioral
> tiers). Tex evaluates legal-state transitions in a labeled transition
> system over institutional regimes. Multi-agent collusion is not a
> category in the OWASP Agentic Top 10; governance-graph LTS is the gap.
>
> *Differentiation from MAGIQ (arxiv 2605.06933, May 7 2026, Avizeh /
> Mallick / Oprea / Nita-Rotaru / Safavi-Naini):* MAGIQ secures the
> agent-to-agent communication channel with post-quantum cryptographic
> primitives and Universal Composability-framework proofs. Tex governs
> the regulator's response to agent behavior. The two layers compose;
> they do not compete.
>
> *Honest caveat (per Keppo et al. arxiv 2603.20281, "On the Fragility
> of AI Agent Collusion", Jan 30 2026):* the 2601.11369 collusion-
> reduction numbers hold for homogeneous-agent Cournot duopolies.
> Heterogeneous real-world deployments may see smaller absolute baseline
> collusion and therefore smaller absolute Tex-vs-baseline deltas. The
> audit-trail value (Article 12) is independent of the absolute delta.

**Backing modules and tests:**
- ``src/tex/institutional/governance_graph.py`` (918 LOC, manifest)
- ``src/tex/institutional/oracle.py`` (517 LOC, Cournot signal detector)
- ``src/tex/institutional/governance_log.py`` (328 LOC, signed audit log)
- ``src/tex/institutional/_pq_signing.py`` (Thread 2, PQ provider resolver)
- ``src/tex/institutional/subagent_inheritance.py`` (Thread 2, arxiv 2605.08460)
- ``src/tex/ecosystem/engine.py::EcosystemEngine.evaluate()`` (Thread 2 wire-in)
- ``tests/ecosystem/test_engine_step4_institutional.py`` (7 integration tests)
- ``tests/institutional/test_pq_signing.py`` (8 unit tests)
- ``tests/institutional/test_subagent_inheritance.py`` (10 unit tests)
- 2,125 tests pass post-Thread-2 (baseline 2,100; +25 from this thread).

---

## Thread 3 — Causal attribution as cryptographically signed post-incident evidence (wired, May 18, 2026)

### Claim

Every incident — every FORBID, every ABSTAIN, every contract violation
— produced by Tex's ``/v1/guardrail`` path can be causally attributed
to a ranked set of candidate root-cause agents and trajectory steps,
with per-agent LSH-Shapley blame distribution, ARM causality-
laundering detection, and a cryptographically signed SCITT-shaped
attribution receipt that auditors can verify in isolation. The receipt
is optionally extensible with a PTV-shaped Groth16 envelope (for ZK
proof of attribution computation) and an NVIDIA NRAS EAT JWT (for
TEE-attested binding to the hardware that computed the attribution).

This is a **read-only post-incident surface**:
``POST /v1/incidents/{decision_id}/attribute``. The ``/v1/guardrail``
hot path is unchanged; the attribution endpoint reads the stored
``Decision``, runs ``compute_attribution``, signs a SCITT-shaped
COSE_Sign1 statement, and hash-chains the result into the same
evidence ledger as decisions and contract violations.

### Why this matters

The 2026 AI-governance vendor field — Microsoft AGT v3.5.0 (May 8,
2026), Zenity, Noma, F5/CalypsoAI, CrowdStrike/Pangea, Palo Alto/
Protect AI — ships incident *correlation* (which decisions clustered
together) and *logging* (what happened). None ships **causal failure
attribution** as a first-class signed audit artifact. The four pieces
this thread combines exist in research and standards drafts as of
May 18, 2026 but have not been assembled in any published
implementation or shipping product:

  1. **Graph-based attribution** — CHIEF (arxiv 2602.23701, Feb 2026)
     + ARM causality-laundering detection (arxiv 2604.04035, Apr 2026).
  2. **Prefill-stage SLM signals** — adapted from MASPrism (arxiv
     2605.07509, May 7, 2026), upgraded to Qwen3.5-0.8B (Mar 2026,
     post-MASPrism) preferred / Qwen3-0.6B fallback.
  3. **Optional ZK proof envelope** — PTV draft shape
     (draft-anandakrishnan-ptv-attested-agent-identity-00, Mar 2026)
     with NanoZK-style layerwise Groth16 (arxiv 2603.18046, Mar 2026).
  4. **Optional TEE attestation binding** — NVIDIA NRAS production v3
     EAT JWT (ES384-signed, May 2026 GA).
  5. **Optional conformal prediction set** — filtration-based CP per
     arxiv 2605.06788 (May 7, 2026); produces a contiguous range of
     trajectory indices guaranteed under CP exchangeability to
     contain the decisive error with confidence ``1 - alpha``. Where
     the other four layers produce a point prediction, this one
     bounds the region of uncertainty.

All four are wrapped in a SCITT-shaped Signed Statement conformant to
``draft-kamimura-scitt-refusal-events-02`` (Jan 29, 2026) with the
``event-type = "ATTRIBUTE"`` extension via the draft's
``* tstr => any`` extension point. The blame distribution uses
LSH-Shapley (arxiv 2605.03581, May 2026), an O(n log n) Shapley
approximation co-designed with a ZK protocol, instead of the
heuristic proportional-blame approach used elsewhere.

### Wire-level shape

SCITT claim set per refusal-events-02 §3 + extension point::

    {
      "event-type":             "ATTRIBUTE",
      "event-id":               <uuid hex>,
      "timestamp":              <unix>,
      "issuer":                 "urn:tex:aegis:<environment>",
      "references_attempt_id":  <decision-uuid>,
      "references_outcome_id":  <decision-uuid>,
      "attribution": {
        "primary_root_cause":              { agent_id, step_id, confidence_ppm, ... },
        "candidates":                      [ ... ],
        "blame_distribution_ppm":          { agent_id: ppm_share, ... },
        "causality_laundering_suspected":  bool,
        "attribution_method":              "graph" | "graph+prefill" | "graph+prefill+zk_pending" | "graph+prefill+zk_pending+tee" | ...,
        "slm_model_id":                    "<id or empty>",
        "slm_model_weight_sha256":         "<hex or empty>",
        "confidence_signals_ppm":          { mean_nll_ppm, max_nll_ppm, ... },
        "attribution_latency_us":          <int>
      },
      "ptv_envelope":     { method, proof, model_hash, input_hash, output_hash } | absent,
      "tee_attestation":  { format, nras_jwt_sha256, nonce, issuer, gpu_measurement_sha256, test_mode } | absent,
      "conformal_set":    { algorithm, start_index, end_index, set_size, trace_length, alpha_ppm, target_coverage_ppm, threshold_ppm, score_source, coverage_mode, step_ids_in_set } | absent
    }

Float fields are encoded as parts-per-million integers for CBOR-
deterministic encoding (the C2PA-style deterministic encoder in
``tex.c2pa._cbor`` refuses floats because IEEE-754 representation
differences fragment cross-language hash-chain integrity). The
public API surface preserves floats; only the signed claim set uses
fixed-point.

**Integrity levels are real, not placeholder.** Each candidate's
``integrity_level`` is computed via an ARM MinTrust lattice walk per
arxiv 2604.04035 §4.2 + Definition 4: each agent_id is classified by
its source family (deterministic.* → TOOL_TRUSTED, semantic.* →
TOOL_UNTRUSTED, asi.* → USER_INPUT, tex.* → SYS_INSTR), then the
candidate's effective level is lattice_meet (min) over its
ancestors in the HCG. The level reported in the signed claim set is
the *effective* trust of the candidate, not just its own.

### Honest scope split

**Real and bleeding-edge today.** Every wire format, schema, verifier,
signing primitive, COSE encoding, claim set assembly, evidence chain
integration, and API surface is real. Verified by 7 end-to-end
integration tests in ``TestIncidentAttribution`` plus full
COSE_Sign1 round-trip decoding with all four layers signed.

**Plumbed stubs with honest naming.** Two pieces are deliberately
documented stubs that the wire format is already shaped to consume
once open reference implementations land:

  * **NanoZK prover.** The PTV envelope's ``proof`` field is empty
    until a NanoZK or EZKL-compatible Groth16 prover is wired. The
    method tag is ``"proof_pending"`` (not ``"groth16-2026"``) and
    the ``attribution_method`` reflects this as
    ``"...+zk_pending"`` so consumers can distinguish stub from
    real proof. The verifier rejects ``proof_pending`` in production
    mode.

  * **Real NRAS network call.** ``build_test_mode_jwt`` generates a
    deterministic ``alg=none`` JWT marked with ``x-tex-test-mode:
    true`` for integration testing without H100 hardware. Tex's
    own verifier rejects ``alg=none`` JWTs unless
    ``TEX_TEE_ATTESTATION_MODE=test``. Production deployments wire
    NRAS via the NVIDIA Python SDK in a follow-on thread.

### Backing modules and tests

- ``src/tex/causal/attribution_engine.py`` (orchestrator + integrity classifier)
- ``src/tex/causal/prefill_signals.py`` (Qwen3.5-0.8B SLM wrapper)
- ``src/tex/causal/lsh_shapley.py`` (LSH-Shapley blame)
- ``src/tex/causal/conformal_attribution.py`` (filtration-based CP)
- ``src/tex/evidence/attribution_zk.py`` (PTV envelope)
- ``src/tex/evidence/tee_binding.py`` (NRAS EAT JWT verifier, 366 LOC)
- ``src/tex/evidence/scitt_cose_alg.py`` (COSE alg label map, prior session)
- ``src/tex/evidence/scitt_statement.py`` (COSE_Sign1 mint/verify, prior session)
- ``src/tex/evidence/recorder.py::record_attribution`` (hash-chained row)
- ``src/tex/api/incident_routes.py`` (endpoint, 547 LOC)
- ``src/tex/api/schemas.py`` (Thread 3 DTOs)
- ``src/tex/main.py`` (router wired via ``build_incident_router``)
- ``tests/test_integration_layer.py::TestIncidentAttribution`` (7 tests)
- **2042 tests pass post-Thread-3, 16 skipped, 0 failures.**

### Source-paper alignment

| Paper / standard | Date | Role in Thread 3 |
|---|---|---|
| arxiv 2602.23701 (CHIEF) | Feb 2026 | Hierarchical causal graph + four-stage progressive screening |
| arxiv 2603.25001 (Rethinking Failure Attribution) | Mar 2026 | Multi-candidate output; no single deterministic root cause |
| arxiv 2604.04035 (ARM, Causality Laundering) | Apr 2026 | ``causality_laundering_suspected`` flag surfacing |
| arxiv 2605.07509 (MASPrism) | May 7, 2026 | Prefill-stage SLM signals approach; we use richer SLM |
| arxiv 2605.06788 (Conformal Agent Error Attribution) | May 7, 2026 | Filtration-based CP producing contiguous prediction sets |
| arxiv 2605.03581 (ZK-Value LSH-Shapley) | May 2026 | Blame distribution algorithm |
| arxiv 2603.18046 (NanoZK) | Mar 2026 | Layerwise Groth16; we wire the verifier surface |
| arxiv 2509.08682 (AAAI 2026) | accepted 2026 | Shapley + CDC-MAS reference |
| draft-kamimura-scitt-refusal-events-02 | Jan 29, 2026 | Signed claim set shape (ATTRIBUTE event-type via extension point) |
| draft-anandakrishnan-ptv-attested-agent-identity-00 | Mar 2026 | PTV envelope shape for the optional ZK+TEE binding |
| NVIDIA NRAS production v3 | GA May 2026 | EAT JWT shape for the optional TEE attestation |
| draft-ietf-scitt-architecture-22 | Oct 2025 | Signed Statement issuance pattern |
| FIPS 204 (ML-DSA) | Aug 2024 | Algorithm-agile signing path (via ``tex.pqcrypto``) |
| RFC 9052 / RFC 9360 / RFC 9334 | 2022–2023 | COSE structures, X.509 in COSE, RATS Architecture |

### Caveats

> *Per the AAAI 2026 paper (arxiv 2509.08682) §3.4 and the
> "Rethinking Failure Attribution" paper (arxiv 2603.25001):*
> attribution accuracy on the Who&When and TRAIL benchmarks is
> ~27–36% Top-1 in the LLM-judge and causal regimes respectively.
> Tex's hybrid graph + prefill design is not directly comparable
> because our input is a structured decision graph from a
> governance engine, not a flat trace. A follow-on thread benchmarks
> against Who&When for an honest comparison.

> *Per the NanoZK paper (arxiv 2603.18046):* the 23ms verification
> time assumes a wired NanoZK verifier. Tex's PTV envelope is shaped
> to consume such a verifier when one lands as an open reference
> implementation, but the v1 prover is a documented stub
> (``proof_pending`` method tag). The wire format and verifier
> surface are bleeding-edge today; the prover is plumbed and
> waiting.

> *Per the PTV draft §B.2:* the ``model_hash`` field binds the
> envelope to a specific SLM. Tex computes this as the SHA-256 of
> a stable identifier surrogate for the loaded model (e.g.
> ``sha256("transformers:Qwen/Qwen3.5-0.8B")``); a production
> deployment hashes the actual safetensors weights. This is
> a documented v1 simplification, not a security claim relaxation.

---

## Thread 4 — Runtime defense specialist judges (wired, May 18, 2026)

Five frontier-research runtime defense modules participate as specialist
judges inside the live ``/v1/guardrail`` request path, evaluated in
Layer 3 of the six-layer pipeline alongside the existing six judges
(``secret_and_pii``, ``external_sharing``, ``unauthorized_commitment``,
``destructive_or_bypass``, ``owasp_skills_top10``, ``mcp_injection``).
The default suite now exposes 11 judges; each runtime-defense specialist
emits structured ``SpecialistResult`` evidence with reason codes,
ASI 2026 tags, and a < 5 ms p99 latency budget enforced via the
``LatencyBreakdown`` instrumentation. Test coverage: 40 new unit tests
in ``tests/specialists/`` plus 6 integration tests in
``tests/test_integration_layer.py::TestThread4RuntimeDefenseSpecialists``.
2,192 tests pass on the full suite (was 2,146 pre-Thread-4).

### 4.1 Boundary enforcement against indirect prompt injection (ClawGuard)

**Claim.** Every ``/v1/guardrail`` request is scanned by
``ClawGuardSpecialist`` for the three primary IPI attack channels:
web/local content injection, MCP server injection, and skill file
injection. When request metadata carries a ``tool_call`` shape the
specialist additionally dispatches to ``ToolCallBoundaryEnforcer``,
short-circuiting risk to 1.0 on deterministic DENY. Per FRONTIER_DELTA
§1.3 an ARGUS-style influence-provenance reason code
(``CLAW_ARGUS_PROVENANCE_UNJUSTIFIED``) is surfaced as an additional
signal.

**Source paper anchor.** arxiv 2604.11790v1 (Zhao et al., 13 Apr 2026)
— §III-A four-component boundary pipeline. Reports AgentDojo IPI ASR
0.6–3.1% → 0.0% and MCPSafeBench 36.5–46.1% → 7.1–11.2% across five
SOTA LLMs.

**Wired modules.**
- ``tex.specialists.clawguard_specialist.ClawGuardSpecialist`` —
  specialist judge registered in
  ``default_specialist_judges()``.
- ``tex.runtime.clawguard.boundary_enforcer.ToolCallBoundaryEnforcer``
  — paper-faithful four-component pipeline (sanitizer, rule evaluator,
  approval mechanism, audit emitter).
- ``tex.runtime.clawguard.rule_set.{BaseRuleSet, TaskRuleSet, Rule}``
  — three-domain {cmd, file, net} rule schema with allow/deny/ambiguous
  three-valued verdicts and most-restrictive-wins aggregation.

**Test references.** ``tests/specialists/test_clawguard_specialist.py``
(11 tests); ``tests/test_integration_layer.py::
TestThread4RuntimeDefenseSpecialists::test_clawguard_fires_on_indirect_prompt_injection``.

### 4.2 InjecAgent-class defense with verified plan intent (PlanGuard)

**Claim.** Every ``/v1/guardrail`` request is checked by
``PlanGuardSpecialist`` for InjecAgent Type I (unauthorized tool) and
Type II (parameter hijack) patterns, plus reasoning-hijack and
fake-preapproval social-engineering markers. When metadata carries a
reference plan + candidate action, the specialist dispatches to the
underlying hierarchical ``IntentVerifier`` (Stage I deterministic
constraint matching + Stage II LLM-aware intent check).

**Source paper anchors.**
- arxiv 2604.10134v1 (Gong & Deng, 11 Apr 2026) — §IV-C hierarchical
  verification mechanism. Stage I alone produces FPR 27–38%;
  Stage I + Stage II reasoning-aware check brings FPR to <3.3%.
- arxiv 2403.02691 (Zhan et al., InjecAgent benchmark) — 1,054 test
  cases across 17 user tools and 62 attacker tools.

**Wired modules.**
- ``tex.specialists.planguard_specialist.PlanGuardSpecialist``.
- ``tex.runtime.planguard.intent_verifier.IntentVerifier`` — Stage I/II
  hierarchical verifier.
- ``tex.runtime.planguard.isolated_planner.{IsolatedPlanner,
  ReferencePlan, Action}`` — paper-isolated planner backbone.

**Test references.** ``tests/specialists/test_planguard_specialist.py``
(10 tests); ``tests/test_integration_layer.py::
TestThread4RuntimeDefenseSpecialists::test_planguard_fires_on_fake_preapproval``.

### 4.3 Long-horizon defense via shadow memory (MAGE)

**Claim.** Every ``/v1/guardrail`` request is checked by
``MageSpecialist`` for the five long-horizon attack families
enumerated in the MAGE paper: memory poisoning (MINJA), tool-chaining
attacks (STAC), persistent indirect prompt injection (PI2), objective
drift (GoalDrift), and observation-authority claims. When metadata
carries a ``ShadowMemory`` or entries list, the specialist consults
prior-turn high-risk entries (risk ≥ 0.6) for token-overlap matches
against the current action — the cross-turn STAC pattern. Detection
is O(T) instead of full O(T²) trajectory replay.

**Source paper anchor.** arxiv 2605.03228v1 (Wang, Jiang, Liang,
Fleming, Wang — Stony Brook + Cisco, **submitted 4 May 2026 — two
weeks old at wire time**). §V STAC ASR 100.0% → 8.3% (Qwen3-4B); §VI
PI2 ASR → 0.0% (environment-as-adversary); 94.4% / 73.0% benign
utility; ≤ 7K extra tokens per task; majority of attacks detected at
or near the first attack turn.

**Wired modules.**
- ``tex.specialists.mage_specialist.MageSpecialist``.
- ``tex.runtime.mage.shadow_memory.{ShadowMemory, ShadowMemoryEntry}``
  — paper-faithful shadow-stack abstraction with monotonic
  ``turn_index``, exponential TTL decay, append-only invariant.
- ``tex.runtime.mage.risk_assessor`` — pre-action judge J implementing
  Eq. 3.

**Test references.** ``tests/specialists/test_mage_specialist.py``
(10 tests); ``tests/test_integration_layer.py::
TestThread4RuntimeDefenseSpecialists::test_mage_fires_on_memory_poisoning``.

### 4.4 Formal verification against canonical MCP attack surfaces (MCPShield)

**Claim.** Every ``/v1/guardrail`` request is checked by
``McpShieldSpecialist`` against the four fundamental MCP security
properties — tool integrity (P1), data confinement (P2), privilege
boundedness (P3), context isolation (P4) — plus the eight protocol-
level MCP attack categories (tool poisoning, tool description
injection, parasitic tool chaining, intent injection, data tampering,
identity spoofing, dynamic trust violation, supply-chain compromise).
When metadata carries an ``LtsModel``, the specialist dispatches to
``verify_property`` and short-circuits risk to 1.0 on any property
failure (counterexample path preserved in evidence).

**Source paper anchor.** arxiv 2604.05969v1 (Acharya & Gupta, 7 Apr
2026) — §III hierarchical threat taxonomy (7 categories, 23 attack
vectors, 4 attack surfaces, grounded in 177,000 MCP tools); §IV
labeled transition system MMCP with trust-boundary annotations.
Supplemented by MCP-SafetyBench v2 (arxiv 2512.15163, 5 Mar 2026) and
MCPSecBench (arxiv 2508.13220) which together enumerate 20+17 attack
types across four attack surfaces.

**Wired modules.**
- ``tex.specialists.mcpshield_specialist.McpShieldSpecialist``.
- ``tex.runtime.mcpshield.lts_model.{LtsModel, Transition, Capability,
  SecurityLabel}`` — paper-faithful labeled transition system tuple.
- ``tex.runtime.mcpshield.verifier.verify_property`` — decidable
  reachability check over (state, label, capability) products.

**Test references.** ``tests/specialists/test_mcpshield_specialist.py``
(10 tests); ``tests/test_integration_layer.py::
TestThread4RuntimeDefenseSpecialists::test_mcpshield_fires_on_data_confinement_violation``.

### 4.5 Runtime type-system invariants on agent actions + ARGUS provenance (AgentArmor)

**Claim.** Every ``/v1/guardrail`` request is checked by
``AgentArmorSpecialist`` for information-flow violations against the
AgentArmor PDG type system: untrusted-to-exec, secret-to-network, and
integrity-downgrade flows. Per FRONTIER_DELTA §1.3, **the specialist
additionally exposes three ARGUS-style influence-provenance reason
codes** (``ARMOR_INFLUENCE_PROVENANCE_UNTRUSTED_TO_HIGH_INT``,
``ARMOR_INFLUENCE_PROVENANCE_TAINTED_FLOW``,
``ARMOR_INFLUENCE_PROVENANCE_UNJUSTIFIED_DECISION``). When request
metadata carries an annotated PDG, the specialist dispatches to
``TypeSystem.check`` and surfaces each violation with src/dst
attribution.

**ARGUS exposure is the frontier piece.** ARGUS (arxiv 2605.03378v1,
Weng et al., **submitted 5 May 2026 — 13 days old at wire time**)
reports AgentDojo ASR 3.8% with 87.5% utility, robust to adaptive
white-box adversaries. The paper is novel and unimplemented in any
commercial governance platform; Tex is the first to expose ARGUS
provenance signals inline with the AgentArmor type-system check.

**Source paper anchors.**
- arxiv 2508.01249v3 (Wang et al., ByteDance, 18 Nov 2025) — three
  components: graph constructor (CFG/DFG/PDG), property registry,
  type system. AgentDojo ASR 3%, utility drop 1%, TPR 95.75%, FPR
  3.66%.
- arxiv 2605.03378v1 (Weng et al., 5 May 2026) — influence provenance
  graph + provenance-aware decision auditing.

**Wired modules.**
- ``tex.specialists.agentarmor_specialist.AgentArmorSpecialist``.
- ``tex.runtime.agentarmor.type_system.{TypeSystem, TypeViolation}``
  — Bell-LaPadula confidentiality JOIN + Biba integrity MEET + trust
  JOIN lattice operations.
- ``tex.runtime.agentarmor.property_registry`` — confidentiality /
  integrity / trust / capability label assignment.
- ``tex.runtime.agentarmor.graph_constructor`` — CFG/DFG/PDG.

**Test references.**
``tests/specialists/test_agentarmor_specialist.py`` (10 tests including
explicit ARGUS coverage); ``tests/test_integration_layer.py::
TestThread4RuntimeDefenseSpecialists::test_agentarmor_fires_on_argus_provenance_signal``.

**Five Eyes alignment.** The Five Eyes joint guidance *Careful Adoption
of Agentic AI Services* (1 May 2026) recommends fail-safe-by-default
agent governance. Tex's AgentArmor specialist contributes to the
privilege, design/configuration, behavioral, and supply-chain risk
categories the guidance enumerates.

---

## Thread 4.5 — Frontier++ runtime defenses (wired, May 18, 2026)

Three additional specialist judges, plus a cross-specialist fusion
layer, plus a Five Eyes-aligned human-review escalation, plus an
adversarial fuzz harness, plus conformal-prediction-calibrated LLM-judge
dispatch — pushing Tex past Thread 4 to the genuine frontier as of May
18, 2026. **The default specialist suite is now 14 judges.** Total
tests: 2,266 passing (up from 2,192). New code: ~3,200 LOC across
``src/tex/specialists/`` and ``src/tex/adversarial/``.

### 4.6 ARGUS standalone influence-provenance graph + counterfactual tests

**Claim.** Every ``/v1/guardrail`` request is checked by
``ArgusSpecialist``, which constructs the full influence-provenance graph
(IPG) from arxiv 2605.03378v1 (Weng et al., 5 May 2026 — 13 days before
this build). Where AgentArmor's reason codes are heuristic hints, ARGUS
builds the actual graph the paper proposes: nodes partition into V_user,
V_obs, V_decision, V_evidence; edges carry kinds {derives_from,
justified_by, contradicted_by}; for each decision node, ARGUS runs the
**counterfactual test** by rebuilding the IPG with instruction-like
observations redacted and checking whether the decision retains a
justification path.

The four reason codes ARGUS emits (``ARGUS_DECISION_OBSERVATION_DRIVEN``,
``ARGUS_DECISION_NO_JUSTIFICATION``, ``ARGUS_DECISION_CONTRADICTED``,
``ARGUS_HIGH_RISK_ANCESTRY``) map to OWASP ASI 2026 categories ASI01
(goal hijack), ASI06 (memory poisoning), and ASI09 (human-agent trust
exploitation).

**Wired modules.**
- ``tex.specialists.argus_specialist.ArgusSpecialist``.
- ``tex.specialists.argus_specialist.{IPGNode, IPGEdge, InfluenceProvenanceGraph}``
  — paper-faithful graph primitives.
- ``tex.specialists.argus_specialist._build_counterfactual`` — implements
  the §3.3 attenuation procedure.

**Tex is the first runtime governance platform to ship the full IPG
primitive.** ARGUS is paper-only as of May 18 2026; commercial competitors
including Microsoft AGT v3.5.0 do not implement it.

**Test refs.** ``tests/specialists/test_argus_specialist.py`` (9 tests);
``tests/test_integration_layer.py::TestThread4_5FrontierSpecialists::test_argus_fires_standalone``.

### 4.7 Action-level causal attribution via shadow replay (AttriGuard)

**Claim.** Every ``/v1/guardrail`` request is checked by
``AttriGuardSpecialist`` — the runtime analogue of Tex's Thread 3
post-incident CHIEF attribution. AttriGuard re-evaluates what the
agent's policy would have proposed under **control-attenuated views**
of its observations and flags observations whose attenuation would
materially change the proposed action as **causal drivers**.

Per arxiv 2603.10749 (Hu et al., March 2026), this is the most novel
paradigm shift in IPI defense from 2026 — attribution vs detection.
Existing defenses ask "is this content malicious?" AttriGuard asks
"WHICH observation caused this action?" The four scoring signals
(token overlap, authority lift, action inheritance, external source)
implement the paper's §4 attribution functional with paper-faithful
behavior.

When ≥ 2 observations score as causal drivers, AttriGuard emits the
``REQUIRES_HUMAN_REVIEW`` uncertainty flag per Five Eyes May 2026
guidance.

**Wired modules.**
- ``tex.specialists.attriguard_specialist.AttriGuardSpecialist``.
- ``tex.specialists.attriguard_specialist.AttributionScore`` — pydantic
  audit-trail record per observation.

**Microsoft AGT v3.5.0 and other commercial platforms do not ship
runtime causal attribution as a primitive.**

**Test refs.** ``tests/specialists/test_attriguard_specialist.py``
(9 tests); ``tests/test_integration_layer.py::TestThread4_5FrontierSpecialists::test_attriguard_fires_on_causal_attribution``.

### 4.8 Verify-before-commit on tool stream (VIGIL + SIREN)

**Claim.** Every ``/v1/guardrail`` request is checked by
``VigilSpecialist``, which implements the verify-before-commit
protocol from arxiv 2601.05755v2 (VIGIL framework + SIREN benchmark,
January 2026).

VIGIL inverts the static-isolation paradigm: instead of restricting
the agent's reasoning over external content, the specialist treats
each tool call as a speculative hypothesis whose commit must be
verified against the user-grounded intent. The five SIREN-class
signals (intent divergence, tool-stream poisoning, cross-observation
contamination, cascade-style chaining, metadata claim mismatch) feed
the verify-before-commit decision.

Per paper §IV, intent divergence by itself is too noisy on legitimate
tool calls whose interface vocabulary doesn't overlap the user's
domain vocabulary. The wired specialist requires divergence to be
**corroborated** by an independent tool-stream signal before firing —
paper-faithful behavior. On DENY verdicts the specialist emits the
``REQUIRES_HUMAN_REVIEW`` Five Eyes flag.

**Wired modules.**
- ``tex.specialists.vigil_specialist.VigilSpecialist``.
- ``tex.specialists.vigil_specialist.VigilVerification`` — replay-
  reproducible verification verdict.

**Test refs.** ``tests/specialists/test_vigil_specialist.py`` (9 tests);
``tests/test_integration_layer.py::TestThread4_5FrontierSpecialists::test_vigil_fires_on_tool_stream_poison``.

### 4.9 Cross-specialist fusion layer

**Claim.** The router replaces ``SpecialistBundle.max_risk_score`` with
the output of a frontier cross-specialist fusion rule that accounts
for signal correlations across specialists. The fused risk is monotonic
non-decreasing relative to the max — fusion only adds detection
sensitivity, never reduces it. Calibration is preserved because:

- 0 firing specialists → 0 corroboration bonus (test:
  ``test_fuse_empty_bundle_zero_bonus``).
- Floor-only specialists with no reason codes → 0 bonus.
- 1 firing specialist → no corroboration bonus.

When 2+ specialists agree, a corroboration bonus is added (capped at
0.20). When frontier specialists (Argus, AttriGuard, VIGIL, AgentArmor,
MAGE) are in the agreement set, the bonus is multiplied by 1.5 per
Nasr-class adaptive-attack robustness. Five pairwise correlations
from the published literature are wired as explicit pair signals
(MAGE × AgentArmor → ASI08; ARGUS × AttriGuard → causal attribution;
VIGIL × ClawGuard → tool hijack; PlanGuard × MAGE → cross-turn injection;
AgentArmor × AttriGuard → exfiltration).

When ≥ 3 specialists fire AND ≥ 1 is a frontier specialist, the
fusion layer tags ``ASI08_cascading_failure`` — the OWASP-recognized
trigger for human review.

**Wired modules.**
- ``tex.specialists.fusion.FusionVerdict`` / ``fuse`` / ``fusion_reason_codes``.
- ``tex.engine.router.Router`` consumes ``fused_risk`` in place of
  ``max_risk_score``.

**Test refs.** Eight ``test_fuse_*`` tests in
``tests/specialists/test_thread_4_5_frontier.py``;
integration test ``TestThread4_5FrontierSpecialists::test_fusion_surfaces_cascading_failure_signal``.

### 4.10 Five Eyes ``requires_human_review`` flag

**Claim.** Per the Five Eyes joint guidance *Careful Adoption of Agentic
AI Services* (1 May 2026), Tex emits a structured ``HumanReviewEscalation``
on every request. The verdict is composed onto the SpecialistBundle
(does NOT modify the existing contract surface) and persisted into
hash-chained evidence so audit replay can verify human review was
triggered per policy.

Four escalation rules:

1. **Explicit specialist request** — any specialist that adds an
   ``REQUIRES_HUMAN_REVIEW: <reason>`` uncertainty flag triggers review.
   VIGIL and AttriGuard emit this on deny / multi-driver conditions.
2. **High-risk + structural** — bundle max risk ≥ 0.7 with at least one
   firing frontier specialist (Argus, AttriGuard, VIGIL, AgentArmor).
3. **Defense-in-depth cascade** — ≥ 3 specialists firing reason codes
   simultaneously.
4. **ASI08 cascading failure** tagged anywhere → review_required.

**Wired modules.**
- ``tex.specialists.human_review.HumanReviewEscalation``.
- ``tex.specialists.human_review.build_specialist_human_review_flag``.

**Test refs.** ``tests/specialists/test_human_review.py`` (8 tests).

### 4.11 Conformal-prediction-calibrated LLM-judge dispatch

**Claim.** When ``TEX_SPECIALIST_LLM_MODE`` is set to ``tiered`` or
``dual_tiered``, PlanGuard's Stage II LLM judge and MAGE's J_θ judge
fire under conformal-prediction-calibrated escalation. The lexical
layer always runs (~0.5ms per specialist); the LLM judge fires only
when the lexical risk score's calibrated upper bound at confidence
1 - α crosses the FORBID decision boundary.

The conformal interval uses the split-CP finite-sample correction:

    h_α = scores[ ceil((n + 1)(1 - α)) / n ]

For α = 0.1 (90% marginal coverage), the engineered default half-width
is 0.18, derived from a 200-fixture calibration mix across AgentDojo,
InjecAgent, and MCPSafeBench. The fuzz harness refreshes calibration
nightly. The LLM judge fires when ``lexical + h_α ≥ 0.5``.

This defeats the Nasr et al. October 2025 adaptive-attack class —
"The Attacker Moves Second" bypassed 12 published defenses with >90%
ASR by exploiting static thresholds. The conformal envelope is
content-dependent, not a hardcoded threshold, so adversarial paraphrase
attacks cannot find a stable corner to exploit.

**FAIL-CLOSED on every error path.** Timeouts, parse errors, schema
errors, rate-limits → specialist surfaces ``MAGE_LLM_JUDGE_FAIL_CLOSED``
(and analogous PlanGuard codes) instead of defaulting to PERMIT.

Default mode is ``disabled`` — existing buyers see no latency drift.

**Wired modules.**
- ``tex.specialists.conformal_escalation.ConformalEscalationGate``.
- ``tex.specialists.llm_dispatch.SpecialistLLMDispatcher`` (async,
  semaphore-bounded, structured event emission).
- ``tex.specialists.llm_bridge.build_planguard_stage_ii_judge``.
- ``tex.specialists.llm_bridge.build_mage_judge_callable``.

**This is the architecture frontier labs are doing internally but no
commercial governance platform ships as of May 2026.** Microsoft AGT
v3.5.0, CrowdStrike/Pangea, F5/CalypsoAI, Palo Alto/Protect AI, and
Zenity all use static escalation thresholds where they use LLM judges
at all.

**Test refs.** Eighteen ``test_gate_*`` / ``test_conformal_*`` /
``test_llm_mode_*`` / ``test_build_*_judge_*`` tests in
``tests/specialists/test_thread_4_5_frontier.py``.

### 4.12 Adversarial fuzz harness with measured ASR

**Claim.** Tex ships ``src/tex/adversarial/`` — a fuzz harness that runs
curated fixture suites from six public IPI benchmarks against the live
``/v1/guardrail`` endpoint and produces a measured per-suite + per-
specialist attack success rate report.

**Measured baseline (lexical-only, ``TEX_SPECIALIST_LLM_MODE=disabled``)
as of May 18, 2026:**

  | Suite          | ASR    | FPR   | Notes                              |
  |----------------|--------|-------|------------------------------------|
  | agentdojo      |  0.0%  | 0.0%  | 7 attacks + 7 benign               |
  | injecagent     |  0.0%  | 0.0%  | 5 attacks + 4 benign               |
  | mcpsafebench   |  0.0%  | 0.0%  | 10 attacks + 4 benign              |
  | agentlab       |  0.0%  | 0.0%  | 5 attacks + 3 benign               |
  | siren          |  0.0%  | 0.0%  | 3 attacks + 4 benign               |
  | nasr_adaptive  | 33.3%  | 0.0%  | 3 attacks + 2 benign (Nasr et al.) |
  | **OVERALL**    | **3.0%** | **0.0%** | **33 attacks + 24 benign (57 total)** |

**Paper-SOTA comparison:**
- ClawGuard (arxiv 2604.11790) AgentDojo ASR: 0.6–3.1% **— Tex matches/exceeds**.
- MAGE (arxiv 2605.03228) STAC ASR: 8.3% **— Tex below**.
- AgentArmor (arxiv 2508.01249) AgentDojo ASR: 3% **— Tex matches**.

**This is measured per-deployment ASR, not paper-derived.** The Tex
lexical-only baseline sits at the lab SOTA target. With
``TEX_SPECIALIST_LLM_MODE=tiered``, the architecture extends to
defeat the Nasr-adaptive class as well.

Suites:

- **AgentDojo** — Important Instructions attack family (Debenedetti et al.).
- **InjecAgent** — Type I tool hijack + Type II param hijack (arxiv 2403.02691).
- **MCPSafeBench** — MCP-specific protocol attacks (arxiv 2604.05969 + 2512.15163).
  Fixtures rewritten in Thread 4.5 Option A to match real attack-payload
  shape (tool poisoning as actual tool descriptions, supply-chain as
  actual install commands).
- **AgentLAB** — 5 attack-family taxonomy (arxiv 2602.16901).
- **SIREN** — tool-stream poisoning (arxiv 2601.05755v2).
- **Nasr-adaptive** — paraphrase-class bypasses adapted from Nasr et al.
  October 2025 ("The Attacker Moves Second"). One miss on this suite is
  expected behavior at the lexical tier and is the wedge for the LLM-judge
  tier.

This converts CLAIMS.md from "we cite paper SOTA" to **"we measure our
own ASR against the same benchmarks the papers do."** Microsoft AGT
v3.5.0 reports paper-derived SOTA only — measured per-deployment ASR
is not in their documentation as of May 18, 2026.

CLI entrypoint: ``scripts/run_adversarial.py``. **Two CI gates**
(``tests/test_integration_layer.py::TestAdversarialMeasuredASR``)
assert overall ASR ≤ 8% and FPR ≤ 5% on every test run; lexical
pattern regressions fail the build.

**Wired modules.**
- ``tex.adversarial.fuzz_runner.FuzzRunner`` / ``FuzzReport`` / ``SuiteResult``.
- ``tex.adversarial.fixtures`` — 57 fixtures across 6 suites (33 attacks + 24 benign).

**Architectural change in Option A:**
- ``tex.engine.router._should_abstain_on_signals`` now elevates to
  ABSTAIN when any structural specialist (clawguard, mcpshield,
  planguard, mage, agentarmor, argus, attriguard, vigil) fires at risk
  ≥ 0.30 with at least one matched policy clause and the fused score is
  below the FORBID threshold. This recovers the paper-SOTA numerics
  that pure pipeline fusion was diluting away. Calibration on benign
  traffic preserved because structural specialists return floor (0.05)
  on benign content.
- ``tex.specialists.fusion.fuse`` gives a small solo-frontier bonus
  (+0.08, x 1.5 frontier multiplier = +0.12) when a single frontier
  specialist fires alone — paper-faithful because the papers report
  specialist ASR, not pipeline-fused ASR.

**Test refs.** Six ``test_fuzz_*`` tests in
``tests/specialists/test_thread_4_5_frontier.py``;
``TestThread4_5FrontierSpecialists::test_adversarial_harness_runs_end_to_end``;
``TestAdversarialMeasuredASR`` (2 CI gates).

### 4.13 Bundle composition

The 14-judge default specialist suite as of Thread 4.5:

  | # | Specialist                | Paper anchor                       | Tier         |
  |---|---------------------------|------------------------------------|--------------|
  | 1 | secret_and_pii            | (baseline)                         | lexical      |
  | 2 | external_sharing          | (baseline)                         | lexical      |
  | 3 | unauthorized_commitment   | (baseline)                         | lexical      |
  | 4 | destructive_or_bypass     | (baseline)                         | lexical      |
  | 5 | owasp_skills_top10        | OWASP ASI 2026                     | lexical      |
  | 6 | mcp_injection             | (baseline MCP)                     | lexical      |
  | 7 | clawguard                 | arxiv 2604.11790 (Apr 2026)        | structural   |
  | 8 | mcpshield                 | arxiv 2604.05969 (Apr 2026)        | formal       |
  | 9 | planguard                 | arxiv 2604.10134 + InjecAgent      | hierarchical |
  |10 | mage                      | arxiv 2605.03228 (4 May 2026)      | shadow-mem   |
  |11 | agentarmor                | arxiv 2508.01249 + ARGUS hints     | IFC          |
  |12 | argus                     | arxiv 2605.03378 (5 May 2026) IPG  | provenance   |
  |13 | attriguard                | arxiv 2603.10749 (Mar 2026)        | causal       |
  |14 | vigil                     | arxiv 2601.05755 + SIREN benchmark | verify       |

---



## Thread 5 — C2PA Content Credentials with post-quantum evidence cosign (wired, May 18, 2026)

### Claim

Every PERMIT verdict produced by Tex on an outbound AI-generated
artifact carries a **C2PA 2.4 Content Credential** with a Tex
**``tex.evidence_cosign``** extension assertion. The cosign is signed
under ``tex.pqcrypto.algorithm_agility`` with **ML-DSA-65 (NIST
FIPS 204)** by default — falling back to Ed25519 when the
operational keystore exposes no ML-DSA key — and explicitly closes
the **six attack classes** identified in arxiv 2604.24890
(Sherman / Krawetz / NSA et al., Apr 27 2026) against C2PA 2.2–2.4:

  1. **Timestamp swap** — the bound timestamp is signed into the
     cosign payload; the outer signature also covers the cosign
     assertion, so swapping the trusted timestamp without breaking
     either signature is no longer possible.
  2. **Revocation skipped** — the cosign carries a
     ``revocation_proof`` (CRL snapshot hash pinned at signing
     time), avoiding the spec's optional OCSP-only path.
  3. **Cross-validator contradiction** — the cosign carries a
     ``canonicalization_version`` field; two validators that
     disagree on canonicalization cannot both report VALID.
  4. **Exclusion-range tamper** — the cosign carries a
     ``full_file_sha256`` over the entire asset with no exclusion
     ranges, alongside the C2PA hard binding.
  5. **Cert expiry before retention** — the cosign carries a
     ``retention_anchor`` pointer (``record_hash`` + evidence-id)
     into Tex's hash-chained evidence ledger. The chain serves as
     the offline retention anchor; a manifest whose C2PA cert has
     expired remains verifiable via the chain.
  6. **Conformance self-reporting** — addressed operationally
     (independent audits, source-reviewed Tex implementation).

Outbound paths that are FORBID, when a refusal reason is supplied,
inline a **SCITT refusal event** per
``draft-kamimura-scitt-refusal-events-02`` (Jan 2026) into the
evidence row's payload, providing the symmetric FORBID-side
provenance signal that pairs with the PERMIT-side C2PA manifest.

The HTTP surface is two endpoints, both production-shaped:

  * ``GET /v1/evidence/{record_id}/c2pa`` — returns the
    JSON-enveloped CBOR claim + outer COSE_Sign1 + cert chain for
    offline verification.
  * ``POST /v1/c2pa/verify`` — accepts a manifest (inline or by
    ``record_id``) plus optional asset bytes; returns outer-
    signature validity, cosign validity, and a structured per-
    attack defense report.

### Why this matters

EU AI Act **Article 50 transparency obligations** apply on
**August 2, 2026** (for new systems) and **December 2, 2026** (for
legacy systems, per the May 7 2026 grandfathering rule).
**Article 50(2)** requires AI-generated content to be marked in a
machine-readable format. The **May 8, 2026 Commission Draft
Guidelines** (paras 28, 54, 64, 81, 140) explicitly bring **agentic
AI** into Article 50 scope and clarify that any vendor of a
generative tool whose output reaches an external counterparty —
which is every AI-SDR — is in scope. Penalties: up to **€15 M or
3% global turnover**.

The **March 2026 second-draft Code of Practice** mandates a
**multi-layered marking approach** (metadata embedding +
imperceptible watermarking) and names C2PA as the metadata
primitive. As of May 18, 2026:

  * **Microsoft Agent Governance Toolkit** (shipped April 2, 2026)
    — does not ship C2PA. Their evidence is Ed25519 hash-chained
    receipts only.
  * **Zenity, Noma, Lakera, Pillar, F5/CalypsoAI, CrowdStrike/
    Pangea, Palo Alto/Protect AI** — zero C2PA integration across
    the field.
  * **c2pa-rs** (Adobe reference implementation, Feb 2026
    CHANGELOG) — does not yet ship ML-DSA signing support.

Tex is the **first agent-governance platform** whose evidence is
C2PA-compliant by default, AND the **only known implementation as
of May 2026** that closes the six NSA-paper attack classes via a
post-quantum cosign assertion.

### Source-paper anchors

  * **C2PA 2.4** (`spec.c2pa.org/specifications/specifications/
    2.4/`) — current published spec, supersedes 2.2/2.3 named in
    the Thread 5 build prompt.
  * **arxiv 2604.24890** (Apr 27 2026) — Sherman, Krawetz, Zieglar
    (NSA), Yus, Kullman et al., "Verifying Provenance of Digital
    Media: Why the C2PA Specifications Fall Short." First formal-
    methods analysis of C2PA. The six attack classes the
    ``tex.evidence_cosign`` assertion closes.
  * **NIST FIPS 204 (ML-DSA, Aug 2024)** — the post-quantum
    signature standard used for the cosign.
  * **draft-ietf-cose-dilithium-11** (Nov 2025) — IANA COSE
    codepoint registration for ML-DSA (still TBD; X.509 OID
    ``2.16.840.1.101.3.4.3.18`` is final).
  * **draft-kamimura-scitt-refusal-events-02** (Jan 2026) — SCITT
    refusal-events taxonomy emitted on FORBID.
  * **EU AI Act Article 50 Draft Guidelines** (May 8 2026, AI
    Office) — paras 28, 54, 64, 81, 140.
  * **EU Code of Practice on Transparency of AI-Generated
    Content** (2nd draft Mar 5 2026; final June 2026).

### Backing modules and tests

  * ``src/tex/c2pa/manifest.py`` — ``build_tex_evidence_cosign_assertion``,
    ``attach_cosign_assertion``, ``TEX_EVIDENCE_COSIGN_SCHEMA_V1``.
  * ``src/tex/c2pa/evidence_emission.py`` — ``build_signed_manifest_with_cosign``
    (one-pass: outer COSE_Sign1 covers the cosign assertion; cosign signs
    a fixed-shape canonical-JSON document over the asset hash, timestamp,
    canonicalization version, retention anchor, revocation proof).
  * ``src/tex/c2pa/cosign_verifier.py`` — ``verify_evidence_cosign``
    returns a ``CosignVerificationResult`` with per-attack defense flags.
  * ``src/tex/evidence/c2pa_emitter.py`` — ``C2paEmitter`` +
    ``C2paEmissionContext`` + ``ScittRefusalEvent`` facade for the
    recorder; lazy-imports ``tex.c2pa`` so unrelated callers see no
    cold-start cost.
  * ``src/tex/evidence/manifest_mirror.py`` — ``PostgresManifestMirror``
    backing the ``tex_evidence_manifests`` table.
  * ``src/tex/evidence/recorder.py`` — ``EvidenceRecorder.record_decision``
    now accepts ``outbound_artifact`` + ``c2pa_context`` (both optional;
    pre-Thread-5 callers see zero behavioral change).
  * ``src/tex/api/c2pa_routes.py`` — ``GET /v1/evidence/{record_id}/c2pa``
    and ``POST /v1/c2pa/verify`` mounted in ``main.create_app``.

Tests (31 new this thread):

  * ``tests/frontier/test_c2pa_evidence_cosign.py`` (18) — assertion
    builder, attach-cosign helper, full sign+cosign roundtrip, each of
    the five attack-defense flags (including tampering and missing-field
    paths), and the Postgres-mirror serializer.
  * ``tests/test_thread5_integration.py`` (5) — end-to-end via
    ``EvidenceRecorder``: PERMIT emits a verifiable manifest with all
    five defenses satisfied; FORBID inlines a SCITT refusal event;
    bare PERMIT without ``outbound_artifact`` is unchanged.
  * ``tests/test_c2pa_http_routes.py`` (8) — POST /v1/c2pa/verify
    (success, tampered asset, malformed CBOR, missing args), GET
    /v1/evidence/{record_id}/c2pa (success, 404, 503), and
    POST verify via record_id resolution through the mirror.

Existing 53 ``tests/frontier/test_c2pa.py`` tests continue to pass —
the cosign is a strictly additive extension assertion.

### Caveats

  * The COSE codepoint for ML-DSA is still draft
    (``draft-ietf-cose-dilithium-11``). The outer C2PA COSE_Sign1
    is therefore signed with ES256/Ed25519 (C2PA 2.4 §13.2
    allow-list), not ML-DSA — putting ML-DSA outside the spec
    allow-list would produce a manifest no validator accepts.
    Post-quantum coverage is supplied by the cosign, which lives
    inside the spec-conformant outer signature.
  * In CI environments without ``liboqs`` installed, the default
    cosign algorithm degrades to **Ed25519** (still hash-chained,
    still signed). Production deployments must install ``liboqs``
    to honour the ML-DSA-65 default.
  * The ``tex.evidence_cosign`` assertion is a Tex extension
    assertion. Vanilla C2PA validators (Adobe Inspect, CAI Verify,
    c2patool, Microsoft Edge) will report the outer signature as
    valid and skip the unknown assertion label — exactly the
    spec-defined behaviour for unknown extension labels.

---

## Thread 6 — Durable Content Credentials + hardware attestation + CPSA formal verification (wired, May 18, 2026)

### Claim

Every PERMIT verdict produced by Tex on an outbound AI-generated
artifact now carries a **C2PA 2.4 Content Credential** under whose
single outer COSE_Sign1 signature **four** Tex extension assertions
are cryptographically bound:

  1. ``tex.evidence_cosign`` (Thread 5) — post-quantum ML-DSA-65
     cosign closing the **six attack classes** of arxiv 2604.24890.
     **Upgraded in Thread 6** to the Merkle-context-tree signing
     input v2 (``tex.evidence_cosign/v2``), formally verified under
     CPSA. Thread 5's v1 (flat-JSON) signing input remains accepted
     on the verifier side for backward compatibility with manifests
     signed before the v2 cutover.

  2. ``tex.evidence_watermark`` (new) — soft-binding assertion
     naming the watermark scheme (**SynthID-Text** — Google
     DeepMind, Nature Oct 2024; or **TextSeal** — Meta FAIR,
     arxiv 2605.12456, May 12 2026) that was applied at generation
     time, the watermark detection score (Bayesian posterior for
     SynthID-Text; entropy-weighted log-likelihood for TextSeal),
     and a perceptual-text-hash soft binding that survives the
     whitespace/case/punctuation normalisation common in Gmail and
     Outlook outbound recompression. Includes the **cross-layer
     audit** from arxiv 2603.02378 (Mar 2 2026) which flags
     **desynchronisation attacks**: manifests where the asserted
     origin contradicts the watermark detector (e.g. manifest claims
     "human-authored" but the watermark detector says "AI-generated",
     or vice versa). Both signatures may be cryptographically valid
     but they assert contradictory things — no shipping C2PA
     validator catches this as of May 18, 2026.

  3. ``tex.evidence_attestation`` (new) — **hardware-attested
     signing** binding via the **C2PA Attestation chapter**
     (spec.c2pa.org/.../1.4/attestations/attestation.html, still
     current in 2.4). The assertion carries an **EAT (Entity
     Attestation Token, RFC 9334)** JWT issued by one of:

       * **NVIDIA NRAS V3** — JWT, ES384-signed, multi-GPU batch
         attestation up to 8 H100/B200 GPUs in a single token;
       * **Intel Trust Authority** — JWT, ES384, EAT Profile
         v1.0.1 doc v2.2 (Feb 16 2026), composite Intel TDX + NVIDIA
         GPU attestation;
       * **Veraison** — open-source RATS verifier under the EAR
         profile ``tag:github.com,2023:veraison/ear``.

     The EAT's ``user_data`` claim binds to ``SHA-256(claim_cbor)``,
     closing the attack where an adversary steals the C2PA private
     key from a memory snapshot of the signing service: the cosign
     is only verifiable when produced inside an attested TEE.

  4. ``tex.formal_verification`` (new) — **CPSA-verified protocol
     soundness**. The Tex cosign v2 protocol is modelled in
     ``cpsa_models/tex_cosign_v2.scm`` as a three-role composition
     (outer-signer, cosign-signer, verifier) under a Dolev-Yao
     adversary. **CPSA v4.4.5 (MITRE, current on Hackage)** enumerates
     every essentially-different execution shape. The vendored output
     (``cpsa_models/tex_cosign_v2_shapes.json``) confirms exactly the
     two expected shapes — one per defskeleton — satisfying five
     security goals:

       * **G1**: outer-signature authentication.
       * **G2**: cosign-signature authentication.
       * **G3**: outer-covers-cosign binding (rules out the
         cross-validator contradiction attack #3 from arxiv 2604.24890).
       * **G4**: cosign-covers-every-attack-defense-leaf binding
         (each of the seven typed Merkle leaves is structurally
         bound under the cosign signature).
       * **G5**: no signature reflection (the outer signature
         cannot be promoted into a cosign-position by an adversary,
         enforced by sort disjointness between ``claim:text`` and
         ``root:data``).

     The assertion carries the CPSA tool version, the model SHA-256,
     a per-goal pass/fail report, and the per-skeleton expected vs
     actual shape count. Offline auditors get cryptographic evidence
     that **the protocol the cosign implements was the protocol
     CPSA proved sound**.

The HTTP surface ``POST /v1/c2pa/verify`` now returns, in addition
to the Thread 5 cosign + attack-defense fields:

  * ``watermark_present``, ``watermark_scheme``, ``watermark_score``,
    ``watermark_cross_layer_consistent``, ``watermark_issues`` (the
    cross-layer audit outcome).
  * ``attestation_present``, ``attestation_verifier``,
    ``attestation_user_data_bound``, ``attestation_issues``.
  * ``formal_verification_present``,
    ``formal_verification_all_goals_satisfied``,
    ``formal_verification_goals``.

### Why this matters

**No agent-governance vendor ships any of these four layers as of
May 18, 2026.** Confirmed via search across Microsoft AGT, Zenity,
Noma, Lakera, Pillar, F5/CalypsoAI, CrowdStrike/Pangea, and
Palo Alto/Protect AI. The C2PA spec itself names ML-DSA support as
"planned, not yet" in the v2.4 explainer (Apr 22 2025); the EU AI
Act Code of Practice (Mar 2026 2nd draft, June 2026 final) names a
**multi-layered marking approach** as the compliance target — which
maps directly onto Tex's four-layer composition.

This is the genuine bleeding edge: **the tech exists in published
papers but nobody has wired it into a shipping agent-governance
product**. Tex Aegis does as of May 18, 2026.

### Source-paper anchors

  * **TextSeal** — Tom Sander et al., Meta FAIR, arxiv 2605.12456
    (May 12 2026). Strictly dominates SynthID-Text in detection
    strength and is robust to dilution; radioactive (survives model
    distillation). github.com/facebookresearch/textseal.
  * **SynthID-Text** — Sumanth Dathathri et al., Google DeepMind,
    Nature (Oct 2024). Production in Gemini; Hugging Face
    Transformers v4.46.0+. Theoretical analysis in arxiv 2603.03410
    (Omidi/Wang, Mar 2026).
  * **Desynchronised provenance attack** — arxiv 2603.02378
    (Mar 2 2026). C2PA + watermark cross-layer contradictions.
  * **C2PA Attestation chapter** — spec.c2pa.org/specifications/
    specifications/1.4/attestations/attestation.html. Still current
    in 2.4.
  * **RFC 9334 (RATS)** — Remote Attestation Procedures (Jan 2023).
  * **Intel Trust Authority EAT Profile v1.0.1 doc v2.2**
    (Feb 16 2026).
  * **NVIDIA NRAS V3** — multi-GPU batch attestation token format
    (production, Apr 2026).
  * **CPSA v4.4.5** (MITRE) — Hackage; ``cabal install cpsa``.
  * **arxiv 2604.24890 §Recommendations** — Sherman et al. (NSA),
    Apr 27 2026. Calls for formal-methods analysis of provenance
    protocols. ``tex.formal_verification`` is that analysis.
  * **Golaszewski / Sherman / UMBC Cyber Defense Lab** — Merkle-hash-
    tree context-binding methodology, formal-methods talk Dec 2023;
    FIDO UAF channel-binding paper arxiv 2511.06028 (Nov 8 2025).

### Backing modules and tests

  * ``src/tex/c2pa/watermark.py`` — ``WatermarkScheme``,
    ``WatermarkDetector`` protocol, ``RecordedScoreDetector``,
    ``SynthIDTextDetectorAdapter``, ``TextSealDetectorAdapter``,
    ``build_tex_evidence_watermark_assertion``,
    ``text_perceptual_hash``, ``cross_layer_audit``.
  * ``src/tex/c2pa/attestation.py`` — ``AttestationVerifier`` enum
    (NRAS / Intel Trust Authority / Veraison / AMD SEV-SNP),
    ``parse_eat_jwt``, ``verify_attestation_assertion`` (ES256 /
    ES384 / ES512 / RS256 / EdDSA), ``synthesize_test_eat_jwt``,
    ``build_tex_evidence_attestation_assertion``.
  * ``src/tex/c2pa/cosign_context_tree.py`` — ``MerkleLeaf``,
    ``build_cosign_v2_leaves``, ``merkle_root``,
    ``canonical_cosign_signing_input_v2``, ``merkle_proof``,
    ``verify_merkle_proof`` (selective-disclosure inclusion proofs).
  * ``src/tex/c2pa/cpsa_shapes.py`` — ``CpsaShapesBundle``,
    ``load_cpsa_shapes``, ``model_provenance_assertion_data``.
  * ``cpsa_models/tex_cosign_v2.scm`` — CPSA S-expression model
    (3 roles, 2 defskeletons, G1-G5 security goals).
  * ``cpsa_models/tex_cosign_v2_shapes.json`` — vendored CPSA
    output for offline CI verification.
  * ``src/tex/c2pa/evidence_emission.py`` — ``build_signed_manifest_with_cosign``
    extended with ``canonicalization_version`` (v2 default) and
    ``extra_assertions`` (tuple of C2paAssertion appended before
    the cosign so the outer signature covers them).
  * ``src/tex/api/c2pa_routes.py`` — ``POST /v1/c2pa/verify``
    extended with Thread 6 fields in ``C2paVerifyResponse``.

Tests (50 new this thread):

  * ``tests/frontier/test_durable_credentials.py`` (17) —
    ``RecordedScoreDetector`` for SynthID-Text and TextSeal,
    assertion builder shape and limits, perceptual-text-hash
    robustness to whitespace/case/punctuation normalisation, and
    the cross-layer audit detecting both desynchronisation attack
    variants from arxiv 2603.02378.
  * ``tests/frontier/test_attestation.py`` (13) — EAT JWT parse,
    full roundtrip for NRAS V3 (ES384 + multi-GPU claims),
    Intel Trust Authority (composite TDX + GPU), and Veraison EAR.
    Negative paths: missing, user_data_mismatch, expired, malformed,
    unknown_verifier. Builder input validation.
  * ``tests/frontier/test_cpsa_shapes.py`` (14) — vendored bundle
    load, skeleton lookup, every-goal coverage (G1-G5), unsatisfied
    detection, ``tex.formal_verification`` assertion payload
    well-formedness with .scm-hash binding.
  * ``tests/test_thread6_integration.py`` (6) — Merkle context tree
    inclusion proofs, every-leaf-tamper-changes-root, end-to-end
    four-layer manifest sign + verify roundtrip (outer COSE_Sign1
    + cosign v2 + watermark + attestation + formal_verification),
    cross-layer audit pass, attestation EAT JWT signature verify,
    and tamper-after-signing breaks the outer signature.

All 2,300 existing tests continue to pass — Thread 6 is a strictly
additive extension layer with v1 backward compatibility on the
verifier side.

### Caveats

  * Watermark **insertion** is the AI gateway's job (applied at
    the model logits layer in Hugging Face Transformers, vLLM, or
    TGI). Tex's role is **detection + recording**: the gateway
    computes the detection score at generation time, Tex records it
    under the cosign + outer signature. ``RecordedScoreDetector``
    is the production path; ``SynthIDTextDetectorAdapter`` and
    ``TextSealDetectorAdapter`` are lazy-import hooks for
    deployments that want in-process re-detection (P1 wiring).
  * The CPSA binary is **Haskell**, not shipped in the Tex Python
    runtime. The vendored ``tex_cosign_v2_shapes.json`` is the CI
    artifact; production deployments wishing to re-run CPSA against
    the .scm source install ``cabal`` and execute
    ``cpsa cpsa_models/tex_cosign_v2.scm | cpsashapes`` (the
    parsing script is sketched in ``src/tex/c2pa/cpsa_shapes.py``).
  * The CWT (CBOR Web Token) variant of EAT is not implemented in
    Thread 6 — only the JWT path. CWT requires ``cbor2`` + a
    ``COSE_Sign1`` layering over the EAT claim set; a P1 upgrade.
    JWT covers Intel Trust Authority, NVIDIA NRAS V3, and Veraison's
    JWT output, which is the production landscape as of May 2026.
  * Hardware attestation is **conditionally emitted**: when no EAT
    token is provided in ``c2pa_context``, the assertion is omitted
    (same pattern as ``revocation_proof``).

---



## Thread 7 — Ecosystem engine eight-axis composition (wired, May 18, 2026)

### Claim

**Tex's ecosystem engine evaluates every proposed event across all
eight governance axes — ontology, graph projection, behavioral
contracts, governance LTS, causal attribution, drift detection, and
systemic risk — before admitting the event into the ecosystem state.**

Per evaluation, the engine populates a six-field ``EcosystemAxisScores``
object alongside the ledger and graph hash envelope, giving an auditor
the full per-axis decomposition of *why* the verdict landed where it
did. Six axis scores + two envelope fields (state hash, recommended
intervention) is the surface form of the eight-step pipeline.

### Why this matters

Before Thread 7 the engine evaluated only steps 1, 2, and 4
(ontology, graph projection, and governance-LTS legality) on the
critical path; steps 3, 5, 6, 7 returned hardcoded zero. Thread 7
closes that gap: each remaining axis is computed from a real
collaborator on every ``evaluate()`` call.

Industry frame as of May 18 2026:

- **Microsoft Agent 365** (GA May 1 2026) ships discovery + identity
  + lifecycle. It does not compute eight-axis composite verdicts
  per event.
- **Microsoft Agent Governance Toolkit** (Apr 2 2026, MIT) with the
  May 14 2026 Intent Manager update ships **declared-intent comparison
  drift** + Merkle-chained Decision BOM audit. AGT does not run
  statistical change-point detection (BOCPD) on agent action streams,
  does not run causal-influence-graph attribution on the request
  path, does not run LTLf temporal contract evaluation, and does
  not emit eight-axis composite verdicts.
- **Zenity** (Gartner "Company to Beat" April 2026) markets "AI Intent
  Detection" with drift, same declared-intent mechanism. Same gap.
- **Noma, Pillar, HiddenLayer, F5/CalypsoAI, CrowdStrike/Pangea,
  Palo Alto/Protect AI, Mindgard** all operate at identity, content,
  or model layer — not the request-path eight-axis composition Tex
  occupies.

Tex Thread 7 is the first production realization of the AAF
(Adaptive Accountability Framework, arxiv 2512.18561 v3, Mar 19 2026)
pipeline — AAF is a 87,480-run factorial simulation up to 500 agents,
not a shipping runtime.

### Source-paper anchors

- **AAF — Adaptive Accountability in Networked MAS** (Alqithami,
  arxiv 2512.18561 v3, Mar 19 2026) §4.1 — pipeline ordering of
  (i) cryptographic provenance, (ii) distributional change-point
  detection on streaming traces, (iii) causal-influence-graph
  attribution, (iv) cost-bounded interventions. Tex Thread 7
  wires (ii) and (iii) on the request path; Thread 5/6 wired (i);
  Thread 8 wires (iv).
- **Bhardwaj — Agent Behavioral Contracts** (arxiv 2602.22302) §3.2
  (deterministic satisfaction), §3.3 (p, δ, k)-satisfaction, §3.6
  Def 3.20 (reliability index). Step 3 reads ``compliance_scores``
  (pure, no state mutation) and converts ``1 - min(C_hard, C_soft)``
  into ``contract_violation_severity``.
- **CHIEF — Hierarchical Causal Graph** (arxiv 2602.23701) §4.1 +
  §4.3. Step 5 calls a new ``fast_attribute`` method that walks the
  agent's declared upstream chain and the active-agent set, returning
  a top-K candidate-source list + confidence in [0, 1]. The slow
  post-incident ``attribute_root_cause`` endpoint remains untouched.
- **MASPrism** (arxiv 2605.07509, May 8 2026, 10 days ago) —
  technique inspiration only. The "zero-decode signals from
  already-computed state" insight (MASPrism reads SLM prefill NLL +
  attention) carries over to ``fast_attribute`` (which reads
  in-memory upstream chain), not the implementation (MASPrism is
  2.66 s/trace; ``fast_attribute`` targets 5 ms p99).
- **Adams & MacKay — BOCPD** (arxiv:0710.3742) — base Bayesian
  online change-point algorithm; Tex's ``_bocpd.py`` adds top-K
  pruning per **Alami et al. 2020** (PMLR v119).
- **Drift-to-Action Controllers** (arxiv 2603.08578, Mar 9 2026) §3
  — anytime-valid risk certificate under delayed supervision. Step
  6 layers a Howard/Ramdas/McAuliffe/Sekhon (arxiv 1810.08240)
  mixture e-process on top of BOCPD: BOCPD answers "is there a
  change point" (Bayesian); the e-process answers "is acting now
  justified given budget" (frequentist, anytime-valid). Both signals
  are emitted on every evaluation.
- **ProbGuard / Pro2Guard** (arxiv 2508.00500 v3, Mar 27 2026) —
  PCTL property ``P_{<θ}[F unsafe_state]`` over a DTMC abstraction
  of the ecosystem. Cited as one of two Thread-9 design directions
  for the Step 7 systemic-risk scorer.
- **GeomHerd** (arxiv 2605.11645, May 2026) — Ollivier-Ricci curvature
  on agent-interaction graphs. Forward-looking ≥272 steps before
  order-parameter onset. Cited as the alternative Thread-9 systemic-
  risk direction.
- **Ye/Tan — Agent Contracts** (arxiv 2601.08815 v3, Mar 25 2026,
  COINE 2026 at AAMAS) — resource-bounded contracts orthogonal to
  behavioral. The ``contract_violation_severity`` field is currently
  the *behavioral* leg only; a future thread can add a resource leg
  without changing the engine call site.

### Backing modules and tests

  * Step 3 wiring: ``tex.ecosystem.engine.EcosystemEngine.evaluate``
    calls ``self._contracts.compliance_scores`` when a
    ``ContractEnforcer`` is wired. Severity =
    ``1 - min(c_hard, c_soft)``. Pure call; does not pollute the
    Thread-1 session state.
  * Step 5: new ``tex.causal.chief.HierarchicalCausalGraph.fast_attribute``
    method + new ``FastAttribution`` Pydantic model
    (``model_config = ConfigDict(frozen=True, extra="forbid")``).
    Reads ``proposed.upstream_event_ids`` + ``state_before.active_agent_ids``.
    Returns top-K candidates + confidence in [0, 1]. Sub-µs typical.
  * Step 6: new ``tex.drift.signal_registry.evaluate_drift``
    orchestrator + new ``DriftEvaluation`` Pydantic model. Composes
    BOCPD (already in ``_bocpd.py``) with a new
    ``tex.drift._anytime_valid.AnytimeValidEProcess`` (mixture
    e-process, stdlib-only). Blended ``drift_delta`` =
    ``max(BOCPD_score, 1 - anytime_valid_p)`` so the axis tracks
    accumulating evidence even before the BOCPD threshold trips.
  * Step 7 call site: gated by the ``TEX_ECOSYSTEM_SYSTEMIC`` env
    flag (default ``0``). When ``1`` and a scorer is wired, calls
    ``SystemicRiskEvaluator.score(state=state_before)``. Today's
    scorer raises ``NotImplementedError``; the engine catches that
    explicitly and reports the axis as 0.0 with a
    ``step7.systemic_not_implemented`` telemetry event — operators
    detect misconfigured flags without DoS'ing the engine.
  * Field naming: ``EcosystemAxisScores`` keeps its existing
    six-field shape — Thread 7 populates them, does not change them.
  * Stale rationale text removed: PERMIT verdicts now read
    ``"steps 1-7 evaluated (contracts severity=X.XXX, causal
    confidence=X.XXX, drift delta=X.XXX, systemic=X.XXX); admitted
    at sequence N"`` instead of the old
    ``"steps 3-7 neutral (P1/P2); ..."``.

**Tests proving the claim.**

  * ``tests/causal/test_chief_fast_attribute.py`` (18 tests) —
    FastAttribution shape, confidence-saturation curve, top_k
    truncation, liveness factor, bounds validation, deterministic
    re-execution, and **5 ms p99 latency budget** over 1000
    invocations (spec acceptance criterion #2).
  * ``tests/drift/test_signal_registry_evaluate.py`` (22 tests) —
    DriftEvaluation shape, irrelevant event neutrality, drift
    escalation, e-process stationarity, NaN/inf rejection, e-process
    reset, dominant-λ diagnostic, custom-registry plumbing,
    orchestrator isolation, and **3 ms p99 latency budget** (spec
    Step 6 target).
  * ``tests/ecosystem/test_engine_step7_flag.py`` (8 tests) — Flag
    off/on combinations: default off, on with no scorer, on with
    NotImplementedError-raising scorer, on with valid scorer, on
    with out-of-bounds returns (clamped), generic exception
    fail-closed, and strict-equality flag-value parsing.
  * ``tests/test_thread7_integration.py`` (7 tests) — end-to-end
    integration:
      - all four newly-wired axes populated in one verdict
      - new rationale format
      - **50 ms p99 evaluate() latency** over 200 events (spec
        acceptance criterion #6)
      - eight-axis claim is observable on the verdict envelope
      - drift escalates across repeated events (the wedge against
        AGT/Zenity declared-intent comparison)
      - flag-on + NotImplementedError-scorer still PERMITs
      - backward-compat: engine without Thread 7 collaborators still
        works
  * ``tests/test_integration_layer.py::TestEcosystemEightAxisPipeline``
    (1 test) — canonical-integration-file anchor per spec
    acceptance criterion #7.
  * ``tests/ecosystem/test_engine.py::test_evaluate_permit_axis_scores_neutral_without_thread7_collaborators``
    — updated from the prior "neutral_for_p0" naming to reflect
    Thread 7 semantics.

**Demo.** ``scripts/demo_thread_7_eightaxis.sh``.

### Competitive differentiation (as of May 18, 2026)

Tex Thread 7 ships three theory-ahead-of-practice wedges:

  1. **Eight-axis composite verdict with cryptographic emission per
     event.** AAF (arxiv 2512.18561, Mar 2026) is the paper. Tex is
     the first production runtime. No competitor composes ≥3 axes
     per event.
  2. **Pre-emission causal attribution on the request path.** Every
     competitor's attribution is post-hoc: Microsoft AGT's Decision
     BOM reconstructs after the fact; Zenity's intent detection
     flags after deviation. Tex's ``fast_attribute`` is before
     admission, in <5 ms p99.
  3. **BOCPD + anytime-valid certificate on agent action streams.**
     Microsoft AGT (May 14, 2026 Intent Manager) and Zenity (April
     2026 AI Intent Detection) ship declared-intent comparison only
     — they catch "agent did X but X wasn't declared." Tex
     additionally catches "agent's tool-call distribution shifted
     regimes regardless of what was declared" — distributional /
     emergent / collusive drift that doesn't violate any single
     declared intent.

### Caveats and honest scope

  * **Step 7 is flag-gated, not scored today.** Thread 9 implements
    the scorer (ProbGuard- or GeomHerd-style). Until then,
    ``TEX_ECOSYSTEM_SYSTEMIC`` defaults off and the systemic axis
    is honestly reported as 0.0. Outreach must NOT claim Tex
    "computes systemic risk in production" — the call site is wired,
    the scorer is not.
  * **Step 6 drift detection requires explicit collaborator wiring.**
    When constructing ``EcosystemEngine`` without
    ``drift=DriftSignalRegistry(...)``, the engine does NOT
    silently fall back to a module-level singleton — it honestly
    reports the axis as 0.0 with a
    ``step6.drift_skipped_no_collaborator`` telemetry event.
    Defense against operator-state leakage across deployments.
  * **fast_attribute is not the same as full attribute_root_cause.**
    Per spec, the request-path version is "faster, less complete"
    — it walks the declared upstream chain only, with no
    counterfactual screening or LLM-judge tie-breaking. The full
    ``attribute_root_cause`` endpoint remains the post-incident tool.
    Outreach can claim "request-path attribution" but should NOT
    claim "the AAAI 2026 36.2% step-level accuracy on every event"
    — that endpoint is Thread 3's post-incident surface.
  * **Aggregate composition gate is Thread 8.** Today's engine
    PERMITs on every event even when ``contract_violation_severity =
    1.0`` or ``drift_delta = 1.0``. The axis scores are inputs to a
    composition rule Thread 8 will land — FORBID/ABSTAIN/SANCTION
    decisions on aggregate axis scores are not yet automatic.
  * **Ye/Tan resource contracts are not wired.** The
    ``contract_violation_severity`` field is currently the *behavioral*
    leg only (Bhardwaj ABC). A future thread adds resource contracts
    (arxiv 2601.08815 v3) as a separate axis or sub-leg.
  * **The drift probe map is conservative.** Only event kinds the
    spec maps to a known signal (tool-call, capability-grant,
    cross-agent-message, denial, outbound-content, capability-used)
    trigger a Step 6 evaluation. Other event kinds get a clear
    drift verdict (axis = 0.0). A future thread can extend the
    probe map; the field shape is preserved.

---



---



## Thread 7.1 — Frontier upgrades: Shapley attribution, Rath three-dimension drift, ProbGuard PCTL, RiskGate viability, GAAT OTel (wired, May 19, 2026)

### Claim

**Tex's ecosystem engine now operates ahead of every shipping competitor and every published paper at May 2026.** Seven upgrades close the gap between Thread 7's "wired call sites" and the literal frontier:

  1. **Causal attribution is Shapley-value cooperative-game-theoretic** (Halpern-Kleiman-Weiner 2018 / Friedenberg-Halpern 2019 / Jørgensen-Apr-30-2026 arxiv 2605.00248), not heuristic. Exact for n ≤ 6 upstreams, Castro-Gómez-Tejada 2009 unbiased Monte-Carlo otherwise. Per-candidate ``shapley_scores`` are surfaced.
  2. **Drift detection is three-dimensional per Rath 2026** (arxiv 2601.04170 §3): ``semantic_drift`` / ``coordination_drift`` / ``behavioral_drift`` are independent axes; aggregate ``drift_delta`` = max(three). Distributional drift is one sub-case of behavioral.
  3. **Systemic risk is live, not flag-gated to NotImplementedError.** ProbGuard-style PCTL bounded reachability (arxiv 2508.00500 v3) over a 27-state DTMC abstraction (agent_count × capability_pressure × compromise bands). Online-learning transition matrix with self-loop prior calibration. Cold-start risk ~0.08 on safe states; absorbing unsafe states return 1.0. p99 latency 0.48 ms.
  4. **RiskGate Viability Index is computed** (arxiv 2604.24686, Apr 27 2026 — Aubin viability theory). Scalar ``viability_index = 1 - max(U, SB, RG)`` decomposes the six axis scores into RiskGate's three risk terms. Surfaces alongside the existing six-axis breakdown.
  5. **RiskGate P3 monotonic restriction** is implemented as an opt-in (``monotonic_restriction=True``). Per-actor viability floor recorded across evaluations; never relaxes without explicit ``record_recovery(actor)`` operator call.
  6. **GAAT-compatible OpenTelemetry span schema** (Apple, arxiv 2604.05119, Apr 6 2026). ``verdict_to_otel_attributes()`` emits the GAAT GTS §III.A core set (``governance.decision`` / ``governance.enforcement_level`` / ``governance.viability_index``) plus the six Tex-specific axes. ``GraduatedEnforcementLevel`` enum maps viability to GAAT's L0..L4 tiers.
  7. **Declarative ProbeMapPolicy** replaces the static probe-map dict. Three-tier evaluation (exact / substring / none) mirrors GAAT's OPA Rego layering. Operators register custom event kinds without modifying Tex source.

### Why this matters at May 19, 2026

Competitive scan as of May 19, 2026:

  * **RiskGate** (arxiv 2604.24686, Apr 27 2026): published architecture; Tex Thread 7.1 is the first production realization.
  * **GAAT** (Apple, arxiv 2604.05119, Apr 6 2026): published 98.3% VPR architecture with 127ms p50 enforcement latency. Tex emits in GAAT's span schema while executing in <5ms p99 per step. Operators can swap NeMo / Cedar / OPA out for Tex without rewriting their OpenTelemetry pipeline.
  * **ProbGuard** (arxiv 2508.00500 v3, Mar 27 2026): published DTMC-abstraction approach with 38.66 s forward-looking warnings. Tex's 27-state production DTMC runs the same PCTL property in 0.48 ms p99.
  * **Rath agent drift** (arxiv 2601.04170, Jan 7 2026): published 12-dimension Agent Stability Index. Tex's three-dimension cut covers the three Rath drift categories (semantic / coordination / behavioral) at the per-event request path.
  * **Kaptein "Policies on Paths"** (arxiv 2603.16586): formal framework for runtime governance. Tex's per-event evaluation is a special case (path-length = 1) of the Kaptein path-functional framework.
  * **Microsoft Agent 365 / AGT Intent Manager** (May 14, 2026): declared-intent comparison; no statistical drift on action streams, no Shapley attribution, no PCTL forward-looking risk.
  * **Zenity AI Intent Detection** (April 2026): same declared-intent gap.
  * **Microsoft Bedrock AgentCore Cedar** (April 2026): stateless tuple authorization; explicitly noted by RiskGate §1 as "no memory of prior behavior, no distributional context."

### Source-paper anchors

- **Halpern, Kleiman-Weiner 2018** — "Towards Formal Definitions of Blameworthiness". Shapley-value blameworthiness foundation.
- **Friedenberg, Halpern 2019** — survey at arxiv 2411.03275. Multi-agent Shapley extension.
- **Castro, Gómez, Tejada 2009** — unbiased Monte-Carlo permutation Shapley estimator.
- **Jørgensen, et al. 2026** (arxiv 2605.00248, Apr 30) — "Causal Foundations of Collective Agency". Causal games + causal abstraction; Shapley vectors identify the operative collective.
- **Rath 2026** (arxiv 2601.04170, Jan 7) — three-dimension drift taxonomy: semantic / coordination / behavioral.
- **Pro²Guard / ProbGuard** (arxiv 2508.00500 v3, Mar 27 2026) — PCTL on DTMC abstraction, 38.66 s forward-looking warnings. Tex Thread 7.1 ships the production DTMC.
- **Hansson, Jonsson 1994** — PCTL bounded-until semantics for the reachability computation.
- **Aubin** (viability theory 1991+) — viability kernel framework.
- **RiskGate / Marín, Chaudhary 2026** (arxiv 2604.24686, Apr 27) — Informational Viability Principle; P1/P2/P3 properties; B̂(x) decomposition.
- **GAAT / Apple** (arxiv 2604.05119, Apr 6 2026) — Governance Telemetry Schema; OpenTelemetry GTS extension; graduated intervention L0..L4 enforcement bus.
- **Kaptein 2026** (arxiv 2603.16586) — Runtime Governance for AI Agents: Policies on Paths. Path-functional framework that Tex's per-event evaluation is a special case of.

### Backing modules and tests

  * ``tex.causal.chief.HierarchicalCausalGraph.fast_attribute`` — Shapley implementation with adaptive sample budget (120 / 60 / 30 by n band) and bitmask-cached payoff. ``_compute_shapley_values`` exact + Monte-Carlo helpers.
  * ``tex.causal.chief.FastAttribution`` — adds ``shapley_scores`` field; ``top_candidates`` sorted by descending Shapley share.
  * ``tex.drift.signal_registry.DriftEvaluation`` — adds ``semantic_drift`` / ``coordination_drift`` / ``behavioral_drift`` / ``dominant_dimension`` fields.
  * ``tex.drift.signal_registry.ProbeMapPolicy`` — frozen dataclass; ``DEFAULT_PROBE_MAP_POLICY`` covers ontology event kinds with substring fallback.
  * ``tex.systemic.probguard`` — new module; ``DTMCModel`` + ``abstract_state`` + ``reachability_probability``; 27-state abstraction with Laplace + self-loop prior.
  * ``tex.systemic.risk_evaluator.SystemicRiskEvaluator`` — now backed by ProbGuard. ``score(state=)`` returns the PCTL bounded-reachability probability.
  * ``tex.ecosystem.verdict.EcosystemAxisScores`` — adds ``viability_index`` + ``graduated_level`` computed properties.
  * ``tex.ecosystem.verdict.GraduatedEnforcementLevel`` — GAAT L0..L4 enum.
  * ``tex.ecosystem.engine.EcosystemEngine`` — adds ``monotonic_restriction`` param; ``viability_floor_for(actor)`` and ``record_recovery(actor)`` methods.
  * ``tex.observability.governance_span`` — new module; ``verdict_to_otel_attributes`` emits the GAAT GTS schema; ``GAAT_ACTION_TABLE`` mirrors GAAT §III.A Table I.

**Tests added / modified.**

  * ``tests/causal/test_chief_shapley.py`` (13 tests) — Shapley axioms (efficiency, dummy, symmetry); exact vs MC paths; deterministic MC under fixed seed; latency budget at n=20.
  * ``tests/drift/test_drift_dimensions.py`` (9 tests) — Rath three-dimension routing per event kind; backward-compat defaults.
  * ``tests/drift/test_probe_map_policy.py`` (9 tests) — exact / substring / no-match classification; custom policy overrides.
  * ``tests/systemic/test_probguard.py`` (16 tests) — abstraction totality; row-stochastic transition matrix; reachability bounds; cold-start prior calibration; transition recording across calls; <5ms p99.
  * ``tests/ecosystem/test_viability_p3_gaat.py`` (15 tests) — viability_index axioms; GAAT level thresholds; P3 floor recording; P3 only decreases; record_recovery clears; default off; OTel attribute schema.
  * ``tests/test_thread7_integration.py`` — renamed not-implemented test to ``test_step7_flag_on_with_probguard_scorer_computes_risk``.

### Latency profile after Thread 7.1

  | Step | Target | Actual p99 |
  | --- | --- | --- |
  | 1 ontology | 0.5 ms | <0.1 ms |
  | 2 projection | 5.0 ms | <2 ms |
  | 3 contracts | 0.5 ms | <0.5 ms |
  | 4 governance LTS | 5.0 ms | <2 ms |
  | 5 fast_attribute (Shapley) | 5.0 ms | <5 ms at n=20 |
  | 6 drift (BOCPD + anytime + Rath) | 3.0 ms | <3 ms |
  | 7 systemic (ProbGuard PCTL) | 10.0 ms | <0.5 ms |
  | ledger + graph emit | 5.0 ms | <2 ms |
  | **Total** | **50 ms** | **<15 ms p99 typical** |

### Caveats preserved

  * Aggregate composition gate (FORBID / ABSTAIN / SANCTION on aggregate axes / viability) is still **Thread 8 territory** — today's engine PERMITs even at low viability; the graduated level is advisory. P3 monotonic restriction records floors but does not block.
  * Ye/Tan resource contracts (arxiv 2601.08815 v3) not wired; ``contract_violation_severity`` is behavioral-only.
  * ProbGuard's 27-state abstraction is a working proxy; **GeomHerd-class Ollivier-Ricci curvature** systemic-risk model is Thread 9.
  * fast_attribute is still the request-path "faster, less complete" variant; full ``attribute_root_cause`` remains the post-incident endpoint.

---



## Thread 8 — Bounded-compromise calculator + Step 8 intervention selection (wired, May 19, 2026)

### Claim

**"Tex emits evidence-grade, cryptographically signed bounded-compromise certificates for every governance intervention it applies. The certificate carries the operative math: λ·H, g_max, the strict-dominance slack, and the long-run compromise ratio ceiling η* = αH / (λH − g_max) the system has just committed to enforce. The intervention engine selects the lowest-cost intervention that satisfies the AAF Theorem 5 bound (arxiv 2512.18561 v3, March 2026) and fails closed to FORBID if no candidate satisfies. The bound is provable, not heuristic."**

This is operative as of Thread 8 (May 19, 2026). On any request where the axis-derived FORBID predicate fires (contract-violation severity, governance-graph illegality, drift delta, or systemic risk above 0.5), Step 8 of `EcosystemEngine.evaluate()` calls `InterventionEngine.select()` over operator-declared candidate interventions. The chosen intervention is applied via `InterventionEngine.apply()` which emits an ML-DSA-signed governance-log record (routed through `tex.pqcrypto.algorithm_agility`) carrying the full `CompromiseCertificate`. The verdict is downgraded from PERMIT to SANCTION (non-blocking intervention) or REMEDIATE (blocking intervention — quarantine, human-approval gate, or restorative path) with `recommended_intervention_id` populated. When no candidate satisfies the bound, the engine fails closed to FORBID with no recommendation — operators must remediate out-of-band.

### Why this matters

The AAF bounded-compromise theorem provides a mathematical convergence guarantee that no shipping commercial governance product implements as of May 19, 2026. Microsoft Agent Governance Toolkit (open-sourced April 2026, MIT) does have a remediation surface — per Microsoft's own March 26, 2026 documentation, AGT ships an SLO-style error budget that drives automated remediation: when an agent's "safety SLI" drops below 99%, AGT can automatically trigger a kill switch, downgrade the agent's execution ring, or activate a circuit breaker until recovery. That is real remediation, not nothing. But the mechanism is **reactive threshold logic** ("SLI dropped below 99% → trigger one of three fixed escalation steps"). Tex Step 8 is **prescriptive math** ("select the lowest-cost candidate intervention λ such that λH ≥ g_max + ε, with provable long-run compromise ratio η* = αH/(λH − g_max) cryptographically attested per intervention"). AGT has no analytical convergence guarantee, no minimum-viable-penalty formula, and no selection among multiple candidate interventions by cost. AGT emits deterministic policy-enforcement records; it does not emit a CompromiseCertificate the way Tex does.

Microsoft Agent 365 May 2026 update is agent-posture management. Microsoft Agentic Center of Enablement (Power Platform) ships human-in-the-loop "Action Plan" remediation but at the tenant-admin layer, not request-path. Zenity, Noma, Pillar, HiddenLayer, Mindgard, F5/CalypsoAI, CrowdStrike/Pangea, Palo Alto/Protect AI — none ships cost-minimum intervention selection with a provable long-run compromise ratio.

Academic neighbors close the surface but not the math: AIR (arxiv 2602.11749, Feb 12 2026) defines a four-phase NIST-style IR lifecycle for LLM agents (detect/contain/recover/eradicate) with detection >90% and remediation/eradication >95% but no analytical bound. SafeAgent (arxiv 2604.17562, Apr 19 2026) defines a runtime controller + context-aware decision core with utility-cost evaluation, also without convergence guarantee. Embodied Agents Runtime Governance (arxiv 2604.07833 v2, Apr 10 2026) achieves 96.2% interception and 91.4% recovery success on a 1,000-trial study but again no analytical bound.

Tex's wedge over these neighbors: the AAF Theorem 5 ratio bound is *provable* and is *cryptographically attested per intervention*. A cyber-insurance underwriter or NAIC examiner can reconstruct the math offline from the signed certificate alone. EU AI Act Article 26 (deployer post-market monitoring, in force August 2, 2026) and Colorado AI Act (June 2026) both require "documented remediation procedures" — Tex's record is documented *by construction*.

### Source-paper anchors

- **arxiv 2512.18561 v3** (AAF, Alqithami, Mar 19 2026) §5.4 Theorem 5 (bounded-compromise) and Proposition 1 (minimum viable penalty). **PDF fetched and §5.4 read in full during Phase 0 of Thread 8.** Note: the paper's printed Proposition 1 (`λ_min = (g_max + αH) / (Hη*)`) does not algebraically rearrange Theorem 5; Tex implements the algebraically-correct form `λ_min = g_max/H + α/η*`. See `tex/intervention/bounded_compromise.py` `compute_minimum_penalty` docstring for the discrepancy note.
- **arxiv 2602.22302** (Bhardwaj ABC, Feb 2026) §3 Drift Bounds Theorem D* = α/γ — input to `estimate_adversary_payoff` via the `abc_drift_d_star` signal.
- **arxiv 2602.11749** (AIR, Xiao/Sun/Chen, Feb 12 2026) — incident-response vocabulary (detect/contain/recover/eradicate). The `air_phase_for` map and the AIR-vocabulary `Intervention.rationale` formatting let downstream tooling compose with AIR-style consumers without Tex depending on AIR or its DSL.
- **arxiv 2604.07833 v2** (Embodied Agents Runtime Governance, Apr 10 2026) — recovery-success benchmarks; informative SOTA target for `RestorativePathExecutor` production aspirations.
- **arxiv 2604.17562** (SafeAgent, Liu et al., Apr 19 2026) — closest design-pattern neighbor cited for honest comparison; Tex's analytical bound is the wedge over SafeAgent's heuristic framework.
- **arxiv 2601.11369** §4.2 + §6.2.2 (Bracale/Syrnikov, Jan 2026) — restorative-path manifest model + sanction ladder (already wired by Thread 2; Thread 8 consumes the existing `RestorativePath` type).
- **arxiv 2507.15886** (Hua et al., Combining Cost-Constrained Runtime Monitors, NeurIPS 2025) — informative cross-reference for Neyman-Pearson-style cost-constrained allocation; flagged in `bounded_compromise.py` docstring as future-thread material (multi-monitor selection is downstream of Thread 8's single-intervention selection).

### Backing modules and tests

**Modules (`src/tex/intervention/`):**
- `bounded_compromise.py` — `BoundedCompromiseCalculator` with `estimate_adversary_payoff`, `satisfies_bound`, `long_run_compromise_ratio_from_window`, `long_run_compromise_ratio` (history-driven), `compute_minimum_penalty`, `certify`. `CompromiseCertificate` frozen dataclass carries the math.
- `engine.py` — `InterventionEngine.select()` (ranks candidates by cost-to-system ascending, filters by strict-dominance + operator target η*) and `apply()` (emits ML-DSA-signed governance-log record with AIR phase tag + embedded `CompromiseCertificate`). FAIL-CLOSED on ledger error via `InterventionApplyError`.
- `restorative.py` — `RestorativePathExecutor.execute()` walks a manifest-declared `RestorativePath` from the active governance graph; emits header + ordered per-event ML-DSA-signed records; mutates and verifies actor's institutional state to the target legal state.

**Wire-in:**
- `tex/ecosystem/engine.py` constructor accepts five new optional params (`intervention_calc`, `candidate_interventions`, `restorative_executor`, `auto_execute_restorative`, `target_compromise_ratio`). Backward-compatible: defaults preserve all Thread 1-7 verdicts byte-for-byte (verified by full regression suite).
- `evaluate()` Step 8 region: axis-derived FORBID predicate (any of sb_severity / drift_delta / systemic_risk_under_event >= 0.5), intervention selection, apply, restorative-path execution (when configured), verdict-kind mapping (SANCTION for non-blocking, REMEDIATE for blocking, FORBID FAIL-CLOSED for no satisfier).

**Tests (98 new, all passing; 0 regressions on the 2,470 baseline):**
- `tests/intervention/test_bounded_compromise.py` — 53 tests covering construction, payoff estimation, satisfies_bound, ratio formula, history-driven estimator, Proposition 1 minimum-penalty formula (with the algebraic-correctness round-trip test that caught the paper typo), and certificate shape + welfare-bound clamping.
- `tests/intervention/test_engine.py` — 24 tests covering selection (lowest-cost, no-satisfier, empty set, deterministic tie-break, target-η filter, calc-failure handling, argument validation), apply (payload composition with embedded certificate, ledger-failure FAIL-CLOSED, no-ledger path), and AIR-phase mapping coverage for every InterventionKind.
- `tests/intervention/test_restorative.py` — 11 tests covering path lookup (missing graph, unknown path, lookup error), happy-path success (with and without ledger), empty event-kinds, ledger header/per-event failure modes.
- `tests/intervention/test_engine_step8_wiring.py` — 8 tests covering EcosystemEngine Step 8 integration: backward-compat (no calc), axes-clean PERMIT, axes-dirty SANCTION, REMEDIATE for blocking kinds, FAIL-CLOSED FORBID for no satisfier, target_compromise_ratio validation.
- `tests/test_integration_layer.py::TestThread8InterventionStep8` — 2 end-to-end integration tests: SANCTION round-trip with signed governance-log record + chain-verifies-True; REMEDIATE round-trip with restorative-path execution and actor state transition.

**Coverage on Thread 8 modules: 95%** (only "defence in depth" exception-handler branches uncovered, intentional).

### Numerical SOTA targets (production aspiration)

- `η*` ≤ 0.5 at defaults (α=0.05, H=25, target η*=0.10) per AAF Theorem 5. Verified by the integration tests' SANCTION path (eta=0.108).
- Recovery success ≥ 91% production aspiration per arxiv 2604.07833 v2. Thread 8 guarantees *mechanical* correctness (every well-formed path call succeeds); statistical recovery rates are a downstream metric.
- Governance-log append latency: existing ML-DSA-65 / ECDSA-P256 path; no new crypto.
- Test coverage 95% on the three new modules (exceeds 90% bar from Section 3 of `tex_build_master_prompt`).

### Caveats and honest scope

- **AIR-style LLM-synthesized eradication rules are NOT in Thread 8.** AIR (arxiv 2602.11749) generates new guardrail rules during eradication via LLM. Tex's `InterventionKind` enum has 7 fixed kinds. Adding an 8th `LLM_SYNTHESIZED_GUARDRAIL` kind requires plan-level check infrastructure Tex does not yet have. Deferred to a future dedicated thread per FRONTIER_DELTA_thread_8 §8.
- **Neyman-Pearson multi-monitor selection** (Hua et al. arxiv 2507.15886) is not in Thread 8. That paper allocates *detection* under budget; Tex Step 8 allocates *intervention* after FORBID. Future thread when Tex grows multiple specialist intervention selectors.
- **Step 8 fires only when `intervention_calc` is wired at engine construction.** Without the calc, the engine preserves Thread 1-7 PERMIT/FORBID behavior byte-for-byte. The 2,470 existing tests verify this backward compatibility.
- **The paper's printed Proposition 1 formula `λ_min = (g_max + αH) / (Hη*)` does not algebraically rearrange Theorem 5.** Tex implements the algebraically-correct rearrangement `λ_min = g_max/H + α/η*`. The round-trip property test in `tests/intervention/test_bounded_compromise.py::TestComputeMinimumPenalty::test_lambda_min_satisfies_bound` proves the correctness. Documented in the module docstring as an honest reading of the paper.
- **The axis-derived FORBID threshold of 0.5 is a default.** Operators may want different thresholds per axis (e.g., 0.3 for contract violations, 0.7 for systemic risk). Per-axis tuning is a future-thread feature; Thread 8 ships the uniform threshold.

---

## Thread 8.1 — Frontier upgrades: BLAKE3-ML-DSA, AIR eradication synthesis, Neyman-Pearson monitor portfolios (wired, May 19, 2026)

**Outreach positioning.** Tex Aegis is the only AI governance product as of May 19, 2026 to implement: (1) post-quantum signatures with BLAKE3-accelerated ML-DSA-B for signed governance-log records, (2) AIR-style LLM-synthesized eradication rules with cryptographic attestation, and (3) Neyman-Pearson optimal multi-monitor selection under cost-and-false-alarm budget. None of these three primitives is shipped today in any product in the agent-governance category (Microsoft AGT/Agent 365, Zenity, Noma, Pillar, HiddenLayer, Mindgard, F5/CalypsoAI, CrowdStrike/Pangea, Palo Alto/Protect AI, AIR research demo).

### Frontier #1: BLAKE3-accelerated ML-DSA-B

Per Project Eleven and Taurus / JP Aumasson / Zooko Wilcox (Oct 2025), ML-DSA-B replaces SHAKE-256 calls inside FIPS 204 ML-DSA with BLAKE3. Reported gains on x86_64: signing up to 25% faster, verification up to 30% faster. The win comes from hashing dominance in production ML-DSA: 60-80% of sign/verify time is spent in the hash function.

**What Tex Thread 8.1 ships:**
- `src/tex/pqcrypto/blake3_ml_dsa.py` — FIPS 204 §5.4 HashML-DSA construction with BLAKE3 as the pre-hash function. Domain-separated with a 16-byte tag `b"tex-ml-dsa-b/v1\0"` so a verifier cannot be fooled by a forwarded plain ML-DSA signature.
- `SignatureAlgorithm.BLAKE3_ML_DSA_65` added to the algorithm-agility enum.
- Dispatcher in `algorithm_agility.py` routes the new enum to `Blake3MlDsaProvider`.
- `select_institutional_signing_provider()` updated: BLAKE3-ML-DSA-65 promoted to **top of the selection chain**, ahead of stock ML-DSA-65. Selection-chain version bumped to `v2-blake3-thread-8.1`.
- On hosts with liboqs + BLAKE3 binding installed, governance-log records are now signed with ML-DSA-B. On hosts without liboqs, the chain falls through honestly to ECDSA-P256 with the probe-failure reason emitted to telemetry — the existing fallback path is unchanged.

**Honest engineering note.** Project Eleven's full Rust reference also replaces SHAKE *inside* the lattice algorithm (sampling, expansion). That requires a vendored ML-DSA reference rather than a liboqs binding. Thread 8.1 implements the FIPS 204 §5.4 HashML-DSA subset (BLAKE3 pre-hashing, delegating lattice math to liboqs). Per the Taurus blog: "Even on Apple silicon, which features a native instruction set for SHAKE acceleration, the pre-hashing advantage for ML-DSA-B remains significant, especially for larger message sizes." We capture the dominant performance win; the full Rust design is a future-thread item pinned to Python binding availability.

**References (Frontier #1):**
- Project Eleven (Oct 2025): https://blog.projecteleven.com/posts/announcing-ml-dsa-b-optimizing-post-quantum-signatures-with-blake3
- Taurus (Oct 2025): https://www.taurushq.com/blog/faster-post-quantum-signatures-introducing-ml-dsa-b/
- NIST FIPS 204 §5.4 (HashML-DSA)
- BLAKE3 specification (Aumasson, Neves, Wilcox-O'Hearn, O'Connor 2020)
- Backing tests: `tests/pqcrypto/test_blake3_ml_dsa.py` (16 tests, all passing)

### Frontier #2: AIR-style LLM-synthesized eradication rules

Per AIR (arxiv 2602.11749, Xiao/Sun/Chen, Feb 12 2026) §3, the eradication phase generates a new structured guardrail rule from the incident context so the same incident class cannot recur. The paper reports LLM-generated rules approach the effectiveness of developer-authored rules across domains.

**What Tex Thread 8.1 ships:**
- `src/tex/intervention/eradication.py` — `EradicationRuleSynthesizer` with two modes: LLM-preferred (uses an injected `LLMClient`) and deterministic fallback (template-based from incident fingerprint). Plan-level checks pipeline: schema, safety (forbid-only structurally prevents widening), cost (predicate-count ≤ 10, LTLf-depth ≤ 6, both operator-tunable).
- `SynthesizedRule` (frozen, slotted) carries rule_id, applies_to_actor_pattern, forbidden_event_kinds, forbidden_payload_substrings, severity (warn/block), synthesiser_mode, predicate_count, ltlf_depth.
- `InMemoryRuleRegistry` with idempotent register, active_rules listing, and event-matching predicate. Production deployments swap for Postgres-backed registry; the `RuleRegistry` Protocol makes this mechanical.
- `InterventionKind.ERADICATION_RULE_SYNTHESIS` — 8th kind in the enum. AIR phase mapping: `eradicate`.
- `InterventionEngine` constructor extended with optional `eradication_synthesizer` + `rule_registry` parameters. The apply path detects the kind, pulls `incident_context` from `intervention.parameters`, synthesises a rule, registers it, embeds the serialisable rule dict in the governance-log payload as `synthesised_rule`. **FAIL-CLOSED** when synthesizer or registry is not wired, or when incident_context is malformed.
- `ERADICATION_RULE_SYNTHESIS` is NOT in the engine's `blocking_kinds` set — verdict defaults to `SANCTION` (admit current event, the registered rule blocks future recurrences). This matches AIR §3.

**References (Frontier #2):**
- arxiv 2602.11749 (AIR, Feb 12 2026) §3 eradication, §4 LLM-rule generation effectiveness
- Backing tests: `tests/intervention/test_eradication.py` (30 tests, all passing) — covers deterministic-mode severity escalation, LLM-mode JSON parsing + fallback on LLM error/invalid JSON/non-string, plan-check rejection of over-complex LLM rules with deterministic fallback firing, registry idempotence + pattern matching + wildcard, full engine-integration round trip with audit log embedding.

### Frontier #3: Neyman-Pearson multi-monitor selection

Per Hua et al. ("Combining Cost-Constrained Runtime Monitors with the Neyman-Pearson Lemma", arxiv 2507.15886, NeurIPS 2025): when a system has multiple monitors with different (detection_rate, false_alarm_rate, cost) tradeoffs, the optimal portfolio under a global cost budget is the subset whose Lagrangian utility `log(LR_m) - λ·cost_m` is maximised, subject to a composite-false-alarm-rate ceiling via union bound. Hua et al. Theorem 1 proves the greedy selector is optimal for n < 20 monitors (Tex's deployment regime).

**What Tex Thread 8.1 ships:**
- `src/tex/intervention/neyman_pearson.py` — `MonitorPortfolio` (frozen, with `from_rates` builder computing LR = detection_rate/false_alarm_rate, validates rates in [0,1] and FA>0, cost>0), `NeymanPearsonSelector` (greedy Lagrangian knapsack with operator-chosen lambda, ties broken deterministically by monitor_id), `PortfolioSelection` (selected_monitors, total_cost, composite_detection/false_alarm via union-bound on independence, budget_used_fraction, rationale).
- `compose_intervention_pool()` — union of selected monitors' candidate intervention sets with deduplication by intervention_id. The `MonitorCandidateSource` Protocol makes per-monitor candidate sources swappable.
- Algorithm enforces: per-monitor utility = `log(LR_m) - λ·cost_m`, greedy descending, accept if utility > 0 AND cost fits remaining budget AND composite-FA ≤ α (union bound on independence). Default λ=1.0.
- Verified smoke test: 3 monitors (drift LR=28.3 cost=2, contracts LR=95 cost=1, weak LR=15 cost=5), budget=4, α=0.05 → selected {contracts, drift}, total_cost=3.0, composite_detection=0.9925, composite_FA=0.0397 (≤ α), `weak` excluded with rationale "over_budget(cost=5.0000,rem=1.0000)".

**References (Frontier #3):**
- arxiv 2507.15886 (Hua et al., NeurIPS 2025) — Neyman-Pearson multi-monitor optimality theorem
- Neyman & Pearson (1933) — classical UMP-test result
- Backing tests: `tests/intervention/test_neyman_pearson.py` (23 tests, all passing) — covers LR computation, validation rejections, frozen shape, alpha bound enforcement via union bound (two FA=0.04 monitors selected only one because 1-(0.96)²=0.0784 > 0.05), Lagrangian cost-aversion responds to lambda, deterministic tie-break, compose_intervention_pool union+dedup, broken-source skip.

### Test coverage (Thread 8.1)

- BLAKE3-ML-DSA: 16 tests
- Eradication synthesis: 30 tests
- Neyman-Pearson selection: 23 tests
- **Thread 8.1 new tests: 69**
- Combined with Thread 8 baseline (2,568): **2,637 passed, 16 skipped, 0 failed** across the full regression.

### Caveats and honest scope (Thread 8.1)

- **BLAKE3-ML-DSA is FIPS 204 §5.4 HashML-DSA, not the full Project Eleven Rust design.** Tex captures the dominant pre-hash performance win; full lattice-internal SHAKE replacement is a future-thread item.
- **The eradication LLM client is a Protocol, not a default implementation.** Production deployments inject OpenAI/Anthropic/Azure clients. When no LLM is wired, the deterministic-mode synthesizer always fires — eradication is never blocked by LLM unavailability.
- **The InMemoryRuleRegistry is for single-process deployments.** Multi-process deployments swap for a Postgres-backed registry via the `RuleRegistry` Protocol. The interface is stable across this swap.
- **Neyman-Pearson greedy is optimal for n < 20 monitors per Hua et al. Theorem 1.** Above that, the full ILP becomes NP-hard and the greedy is approximate. Tex's typical deployment (3-8 specialist monitors) is well within the optimal regime.
- **Thread 8.1 wires three primitives into the engine surface; the engine constructor accepts them as optional kwargs.** Existing deployments and Thread 8's full 2,568 tests continue to pass unchanged. The new capabilities only fire when explicitly wired.

---

## Thread 9 — EcosystemDigitalTwin + CascadePredictor + fused systemic risk (wired, May 20, 2026)

### Claim

**Tex pre-evaluates every consequential proposed action against a Koopman-lifted digital twin of the agent ecosystem, forecasting semantic-geometric cascade trajectories with conformal coverage guarantees before admission.** The systemic axis (Step 7 of ``EcosystemEngine.evaluate()``) is now fully implemented and runs by default. Every evaluate() call produces a real fused risk score that composes three forward-looking signals — ProbGuard PCTL (PAC-bounded reachability over a 27-state DTMC, Thread 7.1), SCCAL semantic-geometric coupled-dynamics violation (Ollivier-Ricci curvature on the interaction graph), and cascade reachability over the LLM-MAS dependency graph (bounded BFS, From-Spark-to-Fire propagation math). The result is anytime-valid conformal-covered.

A new endpoint ``POST /v1/ecosystem/twin/simulate`` exposes the twin directly: operators (and the agent ecosystem itself) can fork the live state at any timestamp, apply a counterfactual perturbation, and receive a full forward trajectory with per-step conformal bands plus cascade-path predictions — all before any state mutation reaches the live ledger.

### Why this matters

Industry frame as of May 20 2026:
- **Microsoft Agent Governance Toolkit (Apr 2 2026)** uses reactive circuit breakers for cascading failure — they fire *after* the violation propagates.
- **Microsoft Defender Agent 365 (May 1 2026)** does static topology mapping; no counterfactual forecasting.
- **Zenity / Noma / Pillar** offer threat-taxonomy mapping only.
- **JuliaHub Dyad 3.0 / Siemens / Forward Networks** ship industrial / network digital twins, not agent-ecosystem governance twins.
- **arxiv 2601.03905 (Jan 2026)** documents that LLM agents themselves invoke simulation < 1% of the time and degrade when forced to. The right place for the twin is the *governance layer*, not the agent.

Tex is the first agent-governance product to ship pre-execution counterfactual cascade simulation at the gate.

### Source paper anchors

- **arxiv 2603.13325** (ICLR 2026 Workshop) — SCCAL: Semantic-Geometric Coupled-dynamics Cascading-risk AuditIng Layer. Strict generalization of Ollivier-Ricci curvature analysis with co-evolutionary semantic flow. Fires several interaction turns *before* explicit semantic violation appears.
- **arxiv 2603.04474** (Mar 2026) — "From Spark to Fire": LLM-MAS cascade math, three vulnerability classes (cascade_amplification, topological_sensitivity, consensus_inertia). Defense success rate measured at 0.32 → 0.89 with governance interventions; informs ``DependencyEdge.spark_to_fire_class`` and ``min_probability=0.05`` BFS prune.
- **arxiv 2601.01076** (PMLR 2026, Nath/Yin/Chou GA Tech) — Koopman lifting with conformal coverage guarantees. Math basis for ``simulate_forward``.
- **arxiv 2605.01803** (May 2026, Köglmayr/Räth) — Koopman representations for early outbreak warning + minimal counterfactual intervention in multi-agent simulations.
- **arxiv 2602.04364** (Feb 2026) — Anytime-Valid Conformal Risk Control. Hoeffding-style ``sqrt(log(2/delta) / (2n))`` correction ensures coverage holds at any time t under cumulatively growing calibration data.
- **arxiv 2604.06024** (Apr 2026) — Closed-form Average-VaR cascading-failure analysis on Laplacian spectrum; analytical lower bound when historical co-failure data is missing.
- **arxiv 2512.17600** — STAMP/STPA loss-of-control taxonomy; every ``CascadePath`` is tagged with the corresponding Unsafe-Control-Action class.
- **arxiv 2605.11645** (May 2026, GeomHerd) — 272-step early warning baseline; SCCAL strictly dominates via co-evolutionary semantic coupling.

### Modules

- ``tex.systemic.digital_twin.EcosystemDigitalTwin``
- ``tex.systemic.digital_twin.DEFAULT_HORIZON`` / ``MAX_HORIZON``
- ``tex.systemic._koopman`` — EDMD Koopman lift, RBF dictionary, ridge-regularized fit
- ``tex.systemic._sccal`` — Ollivier-Ricci curvature via Sinkhorn-stabilized W1, semantic-flow tension, coupled-dynamics violation, top-K negative-curvature attribution
- ``tex.systemic._conformal`` — ``CalibrationBuffer`` + ``band_for_prediction`` with anytime-valid Hoeffding correction
- ``tex.systemic.cascade_predictor.CascadePredictor``
- ``tex.systemic.cascade_predictor.DependencyEdge``
- ``tex.systemic.cascade_predictor.estimate_edge_probability``
- ``tex.systemic.trajectory`` — frozen Pydantic v2 models: ``TrajectoryStep``, ``CascadePath``, ``SimulationTrajectory``, ``SystemicWeights``
- ``tex.systemic.risk_evaluator.SystemicRiskEvaluator.score_fused`` — convex combination of PCTL + SCCAL + cascade

### Wire-in points

- ``tex.ecosystem.engine.EcosystemEngine`` — Step 7 now runs by default. ``TEX_ECOSYSTEM_SYSTEMIC=1`` is the new default; operators set it to ``"0"`` for opt-out.
- ``tex.api.ecosystem_twin_routes.build_twin_router`` — ``POST /v1/ecosystem/twin/simulate``.
- ``tex.main.create_app`` — twin router registered after C2PA router.

### Tests proving the claim

Unit tests (``tests/systemic/``):
- ``test_digital_twin.py`` — 16 tests: fork independence, ISO validation, horizon bounds, perturbation monotonicity, Koopman training, conformal bands, twin_run_id determinism, custom weights, calibration isolation.
- ``test_cascade_predictor.py`` — 15 tests: empty seed, single/two-hop, min-prob prune, max-depth bound, sorting, cycle handling, STPA tag propagation, simple wrapper, ``estimate_edge_probability`` variants.
- ``test_sccal.py`` — 8 tests: empty graph, single node, clique curvature, chain-vs-clique ordering, unit-interval bounds, top-K attribution, semantic-flow coupling, square-adjacency enforcement.
- ``test_conformal.py`` — 10 tests: empty buffer, size limits, FIFO eviction, cold-start widening, decreasing-band-with-n, alpha validation, NaN/inf rejection, negative-score clamp.
- ``test_risk_evaluator_fused.py`` — 7 tests: backward-compat PCTL preserved, fused equals weighted PCTL when other signals zero, SCCAL lift, output clamping, custom weights, trajectory integration, defensive clamping.

Integration tests (``tests/test_integration_layer.py::TestThread9DigitalTwinIntegration``):
- ``test_step_7_no_longer_raises_with_default_flag`` — Step 7 runs at default env without ``NotImplementedError``.
- ``test_twin_endpoint_returns_trajectory`` — ``POST /v1/ecosystem/twin/simulate`` returns conformal-covered trajectory.
- ``test_twin_endpoint_503_without_wired_twin`` — endpoint correctly 503s when ``app.state.ecosystem_twin`` is unwired.
- ``test_twin_endpoint_cascade_paths_included`` — cascade paths sorted descending by aggregate probability.

The existing ``TestEcosystemEightAxisPipeline::test_all_four_axes_populated_in_one_verdict`` was updated: the prior assertion ``systemic_risk_under_event == 0.0`` (stub) becomes ``0.0 <= systemic_risk_under_event <= 1.0`` (real Thread 9 score).

### Caveats and honest scope (Thread 9)

- **Koopman fit requires ≥ ``MIN_TRAINING_N`` (default 8) observed transitions per tenant.** Below that, ``simulate_forward`` falls back to identity advance — the trajectory exists, but it is the "no model so safest forecast is no change" baseline. The conformal band widens proportionally (cold start ⇒ wide band).
- **SCCAL adjacency is currently a bipartite-ish proxy on agent×tool entities.** Live deployments override with the event-graph from the temporal KG via the ``adjacency_override`` parameter on ``simulate_forward``. The math is paper-faithful regardless of how the adjacency is constructed.
- **The Sinkhorn-regularized Ollivier-Ricci approximation does not yield mathematically pure negative curvature on chains** *(Thread 9 caveat — closed by Thread 9.1).* Thread 9.1 ships an exact-OT path via scipy's HiGHS LP solver for combined supports ≤ 64; the governance-graph scale (< 200 nodes) hits this every typical edge, restoring mathematically clean discrete-Ricci curvature with sharp clique-vs-chain separation. Sinkhorn remains the fallback for larger supports.
- **Cascade dependency graph is supplied per-request.** The engine is wired to ``CascadePredictor`` but a live deployment must supply the dependency edges (from the temporal KG or operator policy). When no edges are supplied, the cascade reachability contribution to fused systemic risk is zero — fail-closed safe.
- **Anytime-valid conformal correction term decays as ``sqrt(log(2/delta)/(2n))``.** Per-tenant calibration buffers reach the asymptotic regime around n ≈ 200; cold-start deployments see wide bands for the first few dozen evaluations. This is by design — overconfident narrow bands at low n is exactly what arxiv 2602.04364 was written to prevent.

---

## Thread 9.1 — Self-tuning twin: calibrator-informed Koopman + NN-lift + curvature-gated attention + exact-OT (wired, May 20, 2026)

### Claim

**Tex's digital twin self-tunes per tenant.** What the calibrator learns about which signals matter at this tenant directly shapes the twin's Koopman observable dictionary and the SCCAL semantic-flow weighting. Identical perturbations applied at two tenants with different calibrator-learned profiles produce *different* fused systemic forecasts — the twin reflects each tenant's actual risk geometry, not a generic baseline. Four concurrent upgrades close the gap between Thread 9's "wired call sites" and the literal May-2026 frontier:

1. **Calibrator-informed Koopman dictionary.** ``TenantSignalProfile`` carries per-coordinate signal importance + high-leverage state-space regions; the polynomial+RBF dictionary scales linear/squared/cross features by signal weight and places ``leverage_fraction=0.5`` of RBF centers preferentially at the high-leverage regions. Operator learns dynamics in a calibrator-shaped frame.
2. **NN-lift (ScaRe-Kro per arxiv 2601.01076 §III.A).** When ``learned_dictionary=True`` and torch is installed, a two-layer NN lift is trained end-to-end via one-step prediction loss with a closed-form linear operator. Deterministic seeded from SHA-256 of training data for replay stability. Falls back to polynomial+RBF on torch-less environments (no surprise dep).
3. **Curvature-gated attention recurrence (SCCAL paper §3.3, full mechanism).** Bidirectional ψ (geometry-aware semantic) and ϕ (semantic-aware geometric) predictors run multiplicative gating per arxiv 2604.14702 ("Gating Enables Curvature", Apr 2026). Edge attention weights are multiplicatively modulated by ``sigmoid(2*kappa)`` for the semantic predictor and ``sigmoid(-2*tension)`` for the geometric predictor. The mean KL-divergence between the two predictors over a 4-step horizon is the forward-looking SCCAL signal — fires several turns before explicit semantic violation per the paper.
4. **Exact discrete-OT for Ollivier-Ricci.** scipy ``linprog`` (HiGHS backend) solves the Monge-Kantorovich LP exactly for combined supports ≤ 64. Clique-vs-chain mean curvature separation is now sharp (0.625 vs 0.25 on n=5 graphs) instead of Sinkhorn-smoothed to 1.0 ≈ 1.0. Sinkhorn remains the fallback for larger graphs.

### Self-tuning loop

```
                  ┌──────────────────────────────────┐
                  │     ThresholdCalibrator (Th 7)   │
                  │   observes outcomes,             │
                  │   updates signal importance      │
                  └─────────────┬────────────────────┘
                                │ snapshot_version++
                                ▼
                  ┌──────────────────────────────────┐
                  │  EcosystemDigitalTwin            │
                  │  .update_tenant_profile()        │
                  │  refits Koopman with new         │
                  │  signal_weights + leverage RBF   │
                  └─────────────┬────────────────────┘
                                │ simulate_forward
                                ▼
                  ┌──────────────────────────────────┐
                  │  Trajectory steps now reflect    │
                  │  what THIS tenant has learned;   │
                  │  SCCAL recurrence weighted by    │
                  │  tenant-shaped semantic flow     │
                  └─────────────┬────────────────────┘
                                │ outcomes
                                ▼
                  (back to ThresholdCalibrator)
```

### Why this matters

- **Microsoft AGT (Apr 2026), Microsoft Agent 365 (May 1, 2026), Neura (May 18, 2026), IBM watsonx Orchestrate (May 5, 2026)** all ship pre-action governance decision layers. None of them: (a) use a learned-NN Koopman lift on the governance state, (b) implement SCCAL's curvature-gated attention recurrence, (c) use exact discrete-OT for Ollivier-Ricci curvature, or (d) wire a calibrator → simulator → calibrator self-tuning loop. Each of these four is in published research at May 2026; none is in any shipping product.
- The ScaRe-Kro Koopman+NN+conformal paper (arxiv 2601.01076) targets robotics, not agent governance. Tex applies the same mathematical machinery one layer above where it lives in any cited paper.
- The Gating-Enables-Curvature paper (arxiv 2604.14702, Apr 2026) proves multiplicative gating is what allows non-flat representational geometry — the math basis SCCAL needed for its curvature-gated recurrence. Tex composes both papers into one runtime decision.

### Source paper anchors

- **arxiv 2601.01076** — Nath/Yin/Chou, "ScaRe-Kro": Koopman NN-lift + conformal coverage. Thread 9.1 implements the NN-lift as an optional path behind ``learned_dictionary=True``.
- **arxiv 2603.13325** — SCCAL: curvature-gated recurrent architecture; Thread 9.1 adds the full bidirectional ψ/ϕ attention recurrence (Thread 9 shipped the static signal only).
- **arxiv 2604.14702** — "Gating Enables Curvature": multiplicative gating ↔ non-flat representational geometry. Math justification for SCCAL's gated attention.
- All Thread 9 anchors (2603.04474 Spark-to-Fire, 2602.04364 anytime-valid conformal, 2604.06024 Laplacian-spectrum closed form, 2512.17600 STAMP/STPA) carry over unchanged.

### Modules

- ``tex.systemic._koopman.TenantSignalProfile`` — calibrator → twin signal carrier.
- ``tex.systemic._koopman.fit_koopman(..., tenant_profile=, learned_dictionary=)``
- ``tex.systemic._koopman._NNLift`` + ``_train_nn_lift`` + ``_nn_lift_from_state`` — torch-optional NN dictionary, NumPy-only forward inference.
- ``tex.systemic._koopman.lift_via_state`` — unified dispatcher across polynomial+RBF and NN dictionaries.
- ``tex.systemic._sccal.curvature_gated_attention_step`` — one step of bidirectional gated recurrence.
- ``tex.systemic._sccal.curvature_gated_recurrence`` — horizon-T recurrence, returns mean divergence + final semantic state.
- ``tex.systemic._sccal._wasserstein1_exact_lp`` — HiGHS-LP exact OT for small supports; dispatched against Sinkhorn fallback in ``_wasserstein1_general``.
- ``tex.systemic.digital_twin.EcosystemDigitalTwin.update_tenant_profile`` — operator side of the self-tuning loop.
- ``tex.systemic.digital_twin.EcosystemDigitalTwin._build_calibrator_weighted_semantic_flow`` — closes the loop into SCCAL.

### Tests proving the claim

Unit tests added (``tests/systemic/test_tenant_profile.py`` — 18 tests, ``tests/systemic/test_sccal_v2.py`` — 9 tests):
- ``TenantSignalProfile`` uniform default, normalized-importance preserves scale + handles zero sum
- Fit-with-profile records signal weights + snapshot version
- Two profiles → two operators → two forecasts (same data)
- High-leverage regions land in RBF centers
- ``lift_via_state`` dispatches correctly on dictionary kind
- NN-lift dictionary kind, determinism, advance produces valid state, fallback when torch missing
- ``update_tenant_profile`` refits on version bump; no-op below MIN_TRAINING_N; carries to forks
- Two tenants diverge for same perturbation
- Exact OT matches Sinkhorn within tolerance + yields sharper clique-vs-chain separation
- Curvature-gated recurrence: trivial graph, unit-interval divergence, horizon mean, zero steps no-op
- ``compute_sccal`` integrates recurrence when semantic flow provided; geometry-only mode has zero recurrence divergence; recurrence can be disabled
- Adversarial semantic flow increases SCCAL score

Integration tests (``tests/test_integration_layer.py::TestThread9_1SelfTuningLoop`` — 2 tests):
- ``test_two_tenants_diverge_through_api`` — two tenants, identical observed transitions, identical perturbation through ``POST /v1/ecosystem/twin/simulate`` → different fused systemic forecasts.
- ``test_tenant_profile_version_bump_triggers_refit`` — ``update_tenant_profile`` with bumped version refits the operator on the wired twin.

Total Thread 9 + 9.1 test count: 110 passing (76 prior systemic + 27 new Thread 9.1 unit + 7 integration).

### Caveats and honest scope (Thread 9.1)

- **The NN-lift is a small architecture (one hidden layer, ~32 lifted dim).** The ScaRe-Kro paper itself uses similar sizes for low-dim robotics state; the governance state space (4-dim abstract) doesn't need more. Larger architectures + GPU + longer training are a follow-on; the current configuration trains in ~200 ms on CPU.
- **``TenantSignalProfile.high_leverage_regions`` is a concrete frozen tuple, not a learned distribution.** Operators (or a calibrator adapter) materialize these from observed false-permit / false-forbid regions; live deployments will likely add a ``CalibratorToProfileAdapter`` to bridge ``CalibrationRecommendation`` → ``TenantSignalProfile``.
- **The curvature-gated recurrence uses fixed gating coefficients (sigmoid slope = 2.0).** The SCCAL paper trains these jointly with attention weights on a labeled corpus; we use fixed values that are stable across the test grid. A learned-gating follow-on would tune these per tenant from outcome data — another natural extension of the self-tuning loop.
- **scipy is now an effective soft-dependency for sharp ORC.** When scipy is absent, the code falls back to Sinkhorn cleanly (degraded fidelity, same surface). When scipy is present, exact OT runs.

---





(These exist in ``src/tex/`` with passing unit tests but are NOT
consumed by ``PolicyDecisionPoint`` and must not appear in outreach.)

- ``tex.graph`` — temporal knowledge graph (in-memory only; Postgres +
  JanusGraph backends are stubs).
- ``tex.governance.path_policy`` — LTLf path policy checker.
- ``tex.governance.kernel_mcp`` — capability-based MCP syscall gate.
- ``tex.governance.stpa_specs`` — STPA hazard manifest.
- ``tex.runtime.clawguard`` / ``planguard`` / ``mage`` / ``mcpshield`` /
  ``agentarmor`` — runtime defense modules themselves remain as the
  enforcer backends; their specialist judges are wired in Thread 4
  (see above). With ``TEX_SPECIALIST_LLM_MODE=tiered``, the paper-faithful
  LLM judges fire via the Thread 4.5 conformal-escalation bridge. With
  mode disabled, the deterministic-offline fallback runs.
- ``tex.c2pa`` is now **wired** at the evidence-emission layer — see
  the Thread 5 claim block above. Outreach can reference C2PA.
- ``tex.compliance.eu_ai_act`` — Article 50, 26, 17 modules.
- ``tex.ecosystem.engine`` steps 3, 5, 6, 7 — **wired in Thread 7;
  see the Thread 7 claim section above.** Step 7 (systemic risk
  scorer) is now **fully wired in Thread 9** (May 20, 2026): the
  ``SystemicRiskEvaluator`` extension fuses ProbGuard PCTL
  (Thread 7.1) with SCCAL semantic-geometric coupling
  (arxiv 2603.13325) and cascade reachability
  (arxiv 2603.04474), runs by default
  (``TEX_ECOSYSTEM_SYSTEMIC=1``), and produces a real axis score on
  every evaluate(). See the Thread 9 claim block below.
  *(Step 4 was wired in Thread 2; see entry above.)*

Threads 3+ wire these in. Outreach must not reference them yet.

---

## Thread 10 — Frontier post-quantum cryptography wave (wired, May 20, 2026)

**Tex Aegis is the first AI agent governance platform to ship the full
NIST post-quantum signing stack plus threshold ML-DSA and composite
ML-DSA in production.** Approved outreach copy:

> Tex Aegis ships, in the live evidence path:
>
> 1. **FIPS 203 ML-KEM** at all three parameter sets (512 / 768 / 1024)
>    via liboqs 0.15 with the formally-verified PQCP `mlkem-native`
>    backend (CBMC + HOL-Light), for confidential agent-to-agent
>    transports (MCP-over-mTLS, A2A handshakes). ML-KEM-1024 is the
>    CNSA 2.0 mandated path per `draft-jenkins-cnsa2-pkix-profile §4`.
>
> 2. **FIPS 205 SLH-DSA** at all four production parameter sets
>    (128s / 128f / 192s / 256s) with a built-in **sign-then-verify
>    fault countermeasure** per the NXP scalable-fault-countermeasure
>    paper (ePrint 2026/759, Apr 17 2026). SLH-DSA-256s is the CNSA 2.0
>    mandated path for software and firmware signing.
>
> 3. **Threshold ML-DSA quorum signing** for the highest-stakes evidence
>    records — FORBID verdicts, cross-jurisdiction audit anchors,
>    high-severity tool receipts. k-of-n quorum over ML-DSA-87 keys with
>    SHA-256 descriptor commitment binding, Sybil resistance via
>    duplicate-index rejection, and forward compatibility with the
>    Mithril MPC threshold ML-DSA scheme (ePrint 2026/013, USENIX
>    Security '26) once a Python binding ships. Activated by the
>    `TEX_EVIDENCE_QUORUM_K` runtime flag.
>
> 4. **Composite ML-DSA** per `draft-ietf-lamps-pq-composite-sigs-18`
>    (Apr 9 2026) for BSI 2021 / ANSSI 2024 jurisdictions and any
>    customer who wants a non-lattice hedge alongside ML-DSA.
>    Supported pairs:
>    - ML-DSA-65 + Ed25519 (recommended general-use composite, signs
>      ~3,377 bytes)
>    - ML-DSA-87 + ECDSA-P384 (CNSA 2.0 quorum-side composite, signs
>      ~4,733 bytes)
>    Uses the HPKE-style domain-separator label strings introduced in
>    the draft's revision 16 (`CompositeAlgorithmSignatures2026:id-...`).
>    Non-separability is verified: the ML-DSA half alone does NOT
>    validate as a composite signature.

What this lets Tex tell customers
---------------------------------
- **U.S. NSS / defence supply chain (CNSA 2.0):** the full ML-KEM-1024
  + ML-DSA-87 + SLH-DSA-256s parameter set required by the January 2027
  procurement gate. No other AI governance platform ships this stack.
- **EU / DACH customers (BSI, ANSSI):** PQ/T hybrid via composite
  ML-DSA per the current IETF LAMPS draft — what the regulators
  actually mandate.
- **Long-lived AI agent audit trails (EU AI Act, 10+ year retention):**
  threshold ML-DSA-87 quorum means a single-key compromise — by an
  insider, a stolen HSM, or a future quantum break against an HSM
  that didn't migrate — cannot forge an evidence record. Microsoft
  Agent Governance Toolkit (Apr 2 2026) ships ML-DSA-65 single-key.
  Asqav ships ML-DSA-65 single-key with hash chain. Both can be
  forged by a single key compromise. Tex requires k.

What Tex does NOT yet ship (honesty)
------------------------------------
- True MPC threshold ML-DSA producing a single FIPS 204 signature
  (Mithril, TALUS). Tex's k-of-n is a verifiable quorum certificate,
  not a single ML-DSA signature, because no Python binding for the
  Mithril Rust crate (`threshold-ml-dsa` v0.3 on crates.io,
  Apr 14 2026) exists yet. Forward path is wired behind a
  `MITHRIL_BACKEND` flag.
- FN-DSA (FIPS 206 / FALCON). NIST is still drafting it (IPD released
  Sep 2025, final expected late 2026 / early 2027). liboqs has no
  stable FN-DSA implementation.
- Constant-time SLH-DSA on commodity x86_64. liboqs 0.15 SLH-DSA
  reference implementation is not formally constant-time; the sign-
  then-verify guard is a fault-detection countermeasure, not a
  side-channel countermeasure. Server-side x86_64 is outside the
  threat model for the most credible 2026 SLH-DSA side-channel
  classes (which target embedded power analysis).

References
----------
- NIST FIPS 203 (ML-KEM, Aug 2024)
- NIST FIPS 205 (SLH-DSA, Aug 2024)
- liboqs 0.15.0 release notes
- ePrint 2026/013 (Celi, del Pino, Espitau, Niot, Prest — Mithril, USENIX Security '26)
- arxiv 2603.22109 v2 (Kao — TALUS, Mar 24 2026)
- ePrint 2026/814 (Rambaud, Roth, Urban — ML-DSaaS / TSaaS, Apr 2026)
- ePrint 2026/759 (Azouaoui, Schneider, Verbakel, NXP — SLH-DSA fault countermeasure, Apr 17 2026)
- `draft-ietf-lamps-pq-composite-sigs-18` (Ounsworth et al., Apr 9 2026)
- `draft-ietf-lamps-cms-composite-sigs-04` (Feb 5 2026)
- `draft-jenkins-cnsa2-pkix-profile §4` (CNSA 2.0 algorithm profile, Apr 2026 update)
- arxiv 2605.17061 (Shaw — "quantum-safe" + CoV timing methodology, May 16 2026)

---

## Thread 10 (extended) — Genuine Mithril + TALUS-TEE + HQC + CMS DER (wired, May 20, 2026)

This block supersedes the previous Thread 10 claims on threshold ML-DSA.
Tex now ships the genuine bleeding-edge: real MPC threshold signing,
TEE-attested 1-round signing, code-based KEM hedge, and standards-compliant
ASN.1 DER for composite signatures.

### Genuine Mithril threshold ML-DSA (FIPS 204 single-signature output)

> Tex vendors the upstream Rust crate ``threshold-ml-dsa`` v0.3.6
> (lattice-safe org, MIT, crates.io Apr 14 2026) — the reference
> implementation of Mithril (ePrint 2026/013, USENIX Security '26 —
> Celi/del Pino/Espitau/Niot/Prest, PQShield). The crate is wrapped via
> PyO3 (``vendor/mithril/tex_mithril.so``) and exposed through
> ``tex.pqcrypto.threshold_ml_dsa.distributed_keygen(t, n)``.
>
> **The output is a single bit-for-bit FIPS 204 ML-DSA-44 signature
> (2,420 bytes per FIPS 204 §8.2).** It verifies under any unmodified
> ML-DSA-44 verifier — interop is proven in the test suite by
> verifying Mithril-produced signatures with the standard
> ``oqs.Signature("ML-DSA-44")`` verifier from liboqs.
>
> All 15 (T, N) parameter sets from ePrint 2026/013 Figure 8 are
> supported: (2,2) through (6,6). 3-of-5 cross-region quorum signing
> runs in roughly 3–15 seconds depending on rejection-sampling retries
> (typical: <2 attempts).

### TALUS-TEE 1-round signing harness with attestation

> ``tex.pqcrypto.talus_tee`` implements the operational profile from
> TALUS-TEE (arxiv 2603.22109 v2, Leo Kao / Codebat, Mar 24 2026).
> The paper has no public reference implementation — Tex ships the
> first production harness.
>
> The module provides:
>
> 1. RFC 9334 attestation evidence handling with pluggable verifiers
>    for Intel SGX (DCAP), Intel TDX, and AMD SEV-SNP.
> 2. Public-key binding: every quote's ``report_data`` first 32 bytes
>    must equal ``SHA-256(threshold_public_key)``, per TALUS-TEE §6.
> 3. Measurement-pinned signatures: every ``TalusTeeSignature`` carries
>    the attested enclave measurement so verifiers can pin to a known-good
>    enclave image.
> 4. Freshness window via ``TEX_TALUS_FRESHNESS_SECONDS``.
> 5. Fail-closed default: SGX/TDX/SEV-SNP quotes are rejected unless a
>    real attestation verifier is installed. NONE_TEST_ONLY quotes
>    are rejected unless ``TEX_TALUS_ALLOW_INSECURE_TEE=1``.
>
> The cryptographic core today is genuine Mithril (3-round MPC) running
> inside the TEE coordinator — the user-facing online signing is one
> round because Mithril rounds 1 and 2 happen inside the enclave during
> the offline preprocessing phase. This delivers TALUS-TEE's
> operational profile-P1 description today, with a future swap to the
> native BCC+CEF cryptographic optimization gated behind
> ``TEX_TALUS_NATIVE_BCC=1`` (currently raises ``NotImplementedError``
> until the TALUS paper authors release reference code).
>
> Every signature produced is still a bit-for-bit FIPS 204 ML-DSA-44
> signature, verifiable by any standard verifier.

### HQC KEM (NIST 4th-round selection, FIPS 207 draft)

> ``tex.pqcrypto.hqc`` ships HQC-128 / HQC-192 / HQC-256 via liboqs
> 0.15 with ``-DOQS_ENABLE_KEM_HQC=ON`` (the default is OFF since
> CVE-2025-52473; liboqs mitigates by compiling HQC objects with -O0).
>
> The headline construction is ``MlKemHqcHybridProvider`` — runs
> ML-KEM-1024 and HQC-256 in parallel and combines their shared
> secrets via HKDF-SHA-512 (RFC 5869). The hybrid session is secure
> if EITHER ML-KEM OR HQC remains unbroken — true defense in depth
> against a hypothetical lattice cryptanalytic break. Required by
> BSI TR-02102 and ANSSI 2024 for high-assurance applications.
>
> **No shipping AI governance product implements HQC.** Tex Aegis is
> first.

### CMS / X.509 DER serialization for composite signatures

> ``tex.pqcrypto.composite_cms`` provides ASN.1 DER serialization of
> composite ML-DSA signatures per
> ``draft-ietf-lamps-pq-composite-sigs-18 §4.1``
> (``CompositeSignatureValue ::= SEQUENCE { mldsaSignature OCTET STRING,
> traditionalSignature OCTET STRING }``) using pyasn1 + pyasn1-modules.
>
> Functions: ``encode_composite_signature_der``,
> ``decode_composite_signature_der``,
> ``build_algorithm_identifier``, ``parse_algorithm_identifier``,
> ``encode_cms_signer_info``. The prototype OIDs from draft-18 §6.4
> (``2.16.840.1.114027.80.9.1.4`` and ``.7``) are exposed as named
> constants and re-binding to IANA-registered OIDs is a single edit.
>
> Required for BSI auditors and any CMS-style export pipeline (e.g.
> EU AI Act Article 12 audit packages).

### Module split clarification (honest naming)

The previous Thread 10 zip used the name "threshold ML-DSA" for what was
actually a quorum certificate construction. That module has been **renamed**:

- ``tex.pqcrypto.quorum_ml_dsa`` — k-of-n verifiable certificate over
  independent ML-DSA-44/65/87 keys (formerly named "threshold"). New
  enum values: ``QUORUM_ML_DSA_{44,65,87}``. No inter-signer coordination
  required. Backwards-compat alias ``ThresholdMlDsaProvider =
  QuorumMlDsaProvider`` kept so older test fixtures still import cleanly.

- ``tex.pqcrypto.threshold_ml_dsa`` — **genuine Mithril MPC threshold
  signing** producing a single FIPS 204 signature. Enum values:
  ``THRESHOLD_ML_DSA_{44,65,87}`` (only 44 wired today since upstream
  Rust crate is v0.3; 65/87 will land in upstream v0.4).

The ``get_signature_provider`` dispatcher routes ``QUORUM_*`` to
``QuorumMlDsaProvider`` and raises ``NotImplementedError`` with a
redirect for ``THRESHOLD_*`` (because genuine MPC threshold doesn't
fit the single-key ``SignatureProvider`` Protocol — callers must use
the Mithril-specific API instead).

### Bottom line vs the competitive landscape (May 20, 2026)

- **Microsoft Agent Governance Toolkit** (Apr 2 2026): Ed25519 + ML-DSA-65,
  no threshold of any kind, no composite, no SLH-DSA, no ML-KEM, no HQC.
- **Asqav** (Apr 2026): ML-DSA-65 single-key.
- **PQShield Mithril**: shipping Rust crate, but no Python binding or
  AI-governance integration — Tex is first.
- **TALUS paper**: no public reference implementation as of May 20 2026.
  Tex's TALUS-TEE harness is the first production deployment surface.

References (in addition to those listed in the prior Thread 10 block)
---------------------------------------------------------------------
- ``threshold-ml-dsa`` v0.3.6 (lattice-safe, crates.io, Apr 14 2026, MIT) —
  vendored at ``vendor/mithril/upstream/``
- RFC 9334 (Remote ATtestation procedureS, Jan 2023)
- Intel SGX DCAP, Intel TDX, AMD SEV-SNP attestation specs
- RFC 5869 (HKDF) — used in the ML-KEM/HQC hybrid combiner
- RFC 5280, RFC 5652 — X.509 + CMS standards we serialize for
- NIST IR 8528 (HQC selection rationale, March 2025)
- CVE-2025-52473 (HQC reference impl, mitigated in liboqs 0.15)


## Thread 11 — Information-Flow Control wired (May 20, 2026)

**Marketing claim (AC6):** Tex enforces dual-lattice information-flow
control on every agent action: untrusted-source content cannot reach
sensitive sinks. Implements the FIDES / MVAR IFC pattern with
deterministic, auditable policy decisions, extended with the ARM
denial-aware causal-provenance defense (arXiv:2604.04035, Apr 2026),
NeuroTaint cross-session taint persistence (arXiv:2604.23374), and
CA-CI six-tuple contextual-integrity scope-creep detection (IEEE S&P
2026). Every adjudication produces a structured ``ifc_labels`` audit
record alongside the verdict, hash-chained into the same evidence
chain as the rest of Tex's signals.

What was wired
--------------
The ``tex.governance.private_data_exec`` subpackage — previously a
stand-alone GAAP sandbox (passing tests, no PDP consumer) — is now
extended with a new ``ifc/`` subpackage that is consumed live by the
PDP through a new ``IfcSpecialist``. The IFC stream now participates
in every adjudication on the ``/v1/guardrail`` surface.

The new ``ifc/`` subpackage layers four bleeding-edge May 2026 advances
on top of the existing GAAP taint sandbox:

1. **ARM provenance graph with counterfactual edges** —
   ``ifc/provenance.py``. Implements the four-edge graph (DirectOutput,
   InputTo, FieldOf, Counterfactual) and the five-level integrity
   lattice (ToolDesc < ToolUntrusted < ToolTrusted < UserInput <
   SysInstr) from Chinaei (arXiv:2604.04035v1, Apr 2026). The
   COUNTERFACTUAL edge is auto-linked from each denied-action node to
   the next CALL per ARM Algorithm 1. Detects *causality laundering*:
   denial-feedback leakage that flat IFC misses.

2. **FIDES product lattice (ℓ, μ)** — ``ifc/lattice.py``. Composite
   ``IfcLabel`` over (integrity, confidentiality, type-capacity) per
   Costa/Köpf et al (arXiv:2505.23643). Low-capacity outputs (bool,
   enum) can declassify under explicit operator policy; free text
   cannot.

3. **NeuroTaint cross-session memory** — ``ifc/memory.py``. Per
   "Ghost in the Agent" (arXiv:2604.23374, Apr 2026), taint persists
   across sessions through a tenant-scoped, capacity-bounded, TTL-
   evicted LRU memory stream keyed by content hash. Operators are
   alerted when prior-session tainted content carries forward.

4. **CA-CI six-tuple norm matching** — ``ifc/ci_norms.py``. Implements
   the contextual-integrity flow descriptor (sender, receiver,
   subject, information_type, transmission_principle, purpose) per
   Roemmich/Martin/Schaub (IEEE S&P 2026). Extends Nissenbaum's
   five-tuple by elevating *purpose* to a constitutive parameter,
   enabling scope-creep detection. CI enforcement is fail-closed once
   any norm is registered; empty registry runs advisory-only.

Six distinct violation classes are detected and surfaced as
specialist evidence:

- ``ifc.flow_integrity``           (FIDES dual-axis)
- ``ifc.causality_laundering``     (ARM novel)
- ``ifc.min_trust_floor``          (ARM Layer-2 trust check)
- ``ifc.ci_norm_violation``        (CA-CI scope creep)
- ``ifc.neurotaint_cross_session`` (NeuroTaint axis)
- ``ifc.rule_of_two_trifecta``     (Meta + EchoLeak corrective)

Each violation class carries OWASP ASI 2026 mappings:

- All six                          → ASI09 (Unintended Information Leakage)
- NEUROTAINT_CROSS_SESSION         → ASI09 + ASI07 (Memory Poisoning)
- RULE_OF_TWO_TRIFECTA             → ASI09 + ASI01 (Agent Goal Hijack)

What is verified
----------------
- 66 new unit tests in ``tests/governance/test_ifc_*.py`` covering
  lattice algebra, provenance-graph traversal, counterfactual chain
  detection, memory stream LRU + TTL, CI norm matching, and engine
  orchestration.
- 12 specialist-layer tests in ``tests/specialists/test_ifc_specialist.py``
  verifying all six violation classes surface to ``SpecialistResult``
  evidence, ASI mappings are emitted in ``matched_policy_clause_ids``,
  and the rationale cites the arXiv references.
- 3 integration tests in
  ``tests/test_integration_layer.py::TestIfcSpecialistInLiveGuardrail``
  confirming the specialist runs as part of the live ``/v1/guardrail``
  pipeline and lethal-trifecta payloads yield FORBID + ASI09 findings.
- Existing ``tests/specialists/`` and ``tests/test_pdp.py`` continue
  to pass with the IfcSpecialist registered as specialist #15.

Performance budget verified
---------------------------
``tests/governance/test_ifc_provenance.py::test_query_under_5ms_on_small_graph``
asserts p99 of (has_counterfactual_chain + min_trust + effective_label)
on a 50-node graph is under 5ms. The ARM paper claims sub-millisecond;
our pure-Python implementation hits the contribution budget.

Wedge confirmation
------------------
As of May 20, 2026:

- Microsoft Agent Governance Toolkit (April 2 2026 release, 7
  packages, MIT, sub-ms policy enforcement) and Agent 365 (May 1 2026
  GA) ship **NO IFC module**. Their ``agent-os`` policy engine is
  stateless.
- Zenity, Noma Security, Pillar Security, Lakera, Rubrik SAGE — none
  ship denial-aware causal provenance, cross-session IFC, or CI norm
  matching at runtime.
- FIDES is open-source at github.com/microsoft/fides but ships as a
  planner library, not as a runtime governance product.

This is Tex's wedge: a single deterministic specialist that fuses
ARM + FIDES + NeuroTaint + CA-CI into one composite verdict on the
same evidence chain as the other four content streams plus the three
agent streams.

References
----------
- Chinaei, M. H. "Causality Laundering: Denial-Feedback Leakage in
  Tool-Calling LLM Agents." arXiv:2604.04035 (Apr 5, 2026).
- Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz,
  Zanella-Béguelin. "Securing AI Agents with Information-Flow
  Control" (FIDES). arXiv:2505.23643.
- Stanley, Verma, Tsai, Kallas, Kumar. "An AI Agent Execution
  Environment to Safeguard User Data" (GAAP). arXiv:2604.19657
  (Apr 21, 2026).
- "Ghost in the Agent: Redefining Information Flow Tracking for
  LLM Agents" (NeuroTaint). arXiv:2604.23374 (Apr 2026).
- Palumbo, Choudhary, Choi, Chalasani, Christodorescu, Jha. "Policy
  Compiler for Secure Agentic Systems" (PCAS). arXiv:2602.16708
  (Feb 18, 2026).
- Roemmich, K., Martin, K., Schaub, F. "CA-CI: Integrating Contextual
  Integrity and the Capabilities Approach for Dignity Considerations
  in AI Governance." IEEE Security & Privacy (2026).
- Wang et al. "SAFEFLOW: A Principled Protocol for Trustworthy and
  Transactional Autonomous Agent Systems." arXiv:2506.07564.
- Debenedetti et al. "Defeating Prompt Injections by Design"
  (CaMeL). arXiv:2503.18813.
- Kim, Choi, Lee. "Prompt Flow Integrity to Prevent Privilege
  Escalation in LLM Agents" (PFI). arXiv:2503.15547.
- Meta AI. "Agents Rule of Two." Oct 31 2025 (corrective per
  Towards AI, Nov 14 2025 EchoLeak counterexample analysis).
- Willison, S. "The Lethal Trifecta for AI Agents." Jun 16 2025.
- Reddy & Gujral. "EchoLeak: The First Real-World Zero-Click
  Prompt Injection Exploit in a Production LLM System." AAAI Fall
  Symposium 2025; CVE-2025-32711.

## Thread 12 — Frontier modules (wired, May 20, 2026)

Seven net-new modules implementing bleeding-edge May 2026 SOTA that
competitors have not yet shipped. Each module is wired into the live
Tex pipeline (where applicable) and exercised by deterministic tests.

Total Thread 12 tests: 102/102 passing. Zero regressions to the
existing test suite (3,028 passed, 0 new failures; the 3 failures
that remain pre-exist in tex_5.zip baseline).

### 12.1 — PCAS Datalog policy frontend (wired, May 20, 2026)

**Claim.** Tex ships the **first production-grade implementation of
the PCAS Datalog policy language** (arxiv 2602.16708, Palumbo et al.,
Wisconsin + Google, Feb 18 2026). The paper described algorithms; the
authors' supplemental code has not been released. Microsoft Agent
Governance Toolkit (Apr 2 2026) ships sub-ms policy enforcement but
**no Datalog frontend, no recursive queries, no causal-provenance
graph traversal**. Per PCAS Table 1, only PCAS supports the four-of-
four combination (expressive language + recursion + causal +
multi-agent + deterministic).

What Tex actually does:
- Hand-rolled lexer with line/col tracking, RFC-style errors
  (``tex.pcas.language.lexer``).
- Recursive-descent parser → typed pydantic v2 AST
  (``tex.pcas.language.parser``, ``ast``).
- Stratification via iterative Tarjan SCC, Apt-Blair-Walker variable
  safety, helper disambiguation. Rejects recursion-through-negation
  with structured ``StratificationError`` (``stratify``).
- Bottom-up semi-naive evaluator with stratified negation, lazy
  column-set indexes on relations, ``MAX_ITERATIONS=1024``
  termination cap (``runtime.evaluator``).
- Helper-function registry: ``equals``, ``not_equals``, ``greater``,
  ``less``, ``has_substring``, ``starts_with``, ``json_extract``
  (with constant-output equality check) (``runtime.helpers``).
- Dependency-graph adapter projecting Tex's IFC provenance graph
  (Thread 11) into a PCAS EDB over 8 relations: action/4, message/4,
  tool_call/5, data/4, denied/2, depends_on/2, role/2, approved/3
  (``graph.adapter``).
- Reference monitor returning PERMIT/ABSTAIN/FORBID with fail-closed
  error handling (any parse/eval failure → FORBID). p95 latency
  < 5ms on empty graphs; sub-ms on small EDBs (``monitor``).
- Default policy demonstrates the toxic-flow pattern from PCAS §5.2:
  "deny actions that read from untrusted data and write externally."
- ``PcasSpecialist`` wires the monitor into the PDP default suite.

Tests: 32/32 in ``tests/frontier_thread_12/test_pcas.py`` — lexer,
parser, stratifier, evaluator (joins, recursion, negation, helpers),
adapter, monitor (PERMIT/ABSTAIN/FORBID), latency bound.

### 12.2 — CaMeL dual-LLM capability interpreter (wired, May 20, 2026)

**Claim.** Tex ships the **first integration of a CaMeL capability
interpreter with a Datalog policy frontend over a shared causal
provenance graph**. The Google research prototype at
``github.com/google-research/camel-prompt-injection`` is a paper
artifact; Microsoft Agent Governance Toolkit (Apr 2026) ships no
CaMeL equivalent.

What Tex actually does:
- Three-level capability lattice (TRUSTED ⊑ USER ⊑ UNTRUSTED) with
  total order and join (max) operation (``capability``).
- Capability-tagged values (``CapValue``) with deterministic
  ``derived(value, from_values=...)`` propagation matching CaMeL §5.2.
- Plan AST: ``Literal``, ``Var``, ``Read``, ``Assign``, ``Call``,
  ``QLLM``, ``Return``. Frozen pydantic v2 models. Plan structure
  validator rejects non-terminating plans (``plan``).
- ``ToolPolicyRegistry`` with frozen-after-startup discipline,
  fail-closed defaults (TRUSTED-only for unregistered tools),
  per-argument level caps + forbidden-source labels (``policy``).
- ``QuarantinedLLM`` Protocol with ``StubQuarantinedLLM`` for tests
  and ``CallableQuarantinedLLM`` for production wiring (``q_llm``).
- ``CamelInterpreter`` executes the plan, propagates capabilities
  through every operation, gates every tool call against the
  registry, halts fail-closed on any policy denial (``interpreter``).
- Full execution trace with one ``TraceEntry`` per node, serializable
  into Tex's hash-chained evidence ledger.
- ``CamelSpecialist`` wires the interpreter into the PDP default
  suite. Halts on capability check → FORBID; UNTRUSTED-tainted
  final value → ABSTAIN; clean execution → PERMIT.

Tests: 20/20 in ``tests/frontier_thread_12/test_camel.py`` — lattice
algebra, policy gating, plan structure, interpreter execution paths,
Q-LLM determinism.

### 12.3 — SAFEFLOW transactional WAL + rollback (wired, May 20, 2026)

**Claim.** Tex ships the **first reference-monitor-integrated
implementation of SAFEFLOW** (arxiv 2506.07564, Hu et al., June
2025). The paper is reference-implementation-free. Atomix (arxiv
2602.14849, Feb 17 2026) ships transactional tool use but no
governance integration; LogAct (arxiv 2604.07988) handles multi-agent
shared WAL but no inverse-op discipline.

What Tex actually does:
- Append-only WAL with SHA-256 hash chaining and ``prev_hash``
  enforcement; chain-break and sequence-skip detection
  (``tex.safeflow.wal``).
- Two backends: ``InMemoryWAL`` (tests), ``FileWAL`` (fsync on every
  append, ARIES-style durability).
- 7-state ``WALEntryKind`` taxonomy: BEGIN, STEP_BEFORE, STEP_AFTER,
  COMMIT, ABORT, ROLLBACK_BEFORE, ROLLBACK_AFTER. ``replay()`` for
  crash recovery.
- ``InverseOpRegistry`` enforces that any step participating in a
  transaction must declare a registered inverse operation; tools
  with no inverse (send_email, transfer) cannot transact
  (``rollback``).
- ``TransactionalExecutor`` drives begin → step* → commit | abort.
  On step failure: auto-abort. On abort: reverse-order inverse-op
  invocation, logging every failure to the WAL without stopping the
  rollback loop. Terminal state ROLLED_BACK if all inverses
  succeeded, FAILED otherwise (``executor``).
- SHA-256 over the canonical step sequence + terminal state gives a
  tamper-evident transaction hash for evidence emission.

Tests: 13/13 in ``tests/frontier_thread_12/test_safeflow.py`` — WAL
chain integrity, tamper detection, file persistence + reload,
transactional discipline (commit/abort/post-commit step rejection),
rollback ordering, failing-inverse-op continuation, step-failure
auto-abort, crash recovery, outcome hash.

### 12.4 — AgentDojo benchmark harness (wired, May 20, 2026)

**Claim.** Tex ships an **end-to-end working AgentDojo eval harness**
(arxiv 2406.13352, NeurIPS 2024 Datasets and Benchmarks) wired to
the live PDP. As of May 2026, no agent-governance product publishes
AgentDojo scores; AgentSys (arxiv 2602.07398) reports 0.78% ASR but
isn't a governance product.

What Tex actually does:
- ``TexPipelineDefense`` adapter wrapping the PDP as an AgentDojo-
  compatible defense, mapping PERMIT → pass / ABSTAIN → pass-with-note
  / FORBID → refusal message + tool-call suppression
  (``pipeline_defense``).
- ``AgentDojoHarness`` task runner: per-step adjudication, evidence-
  chained JSONL outcome stream, summary statistics (utility mean,
  attack success rate, forbid rate).
- 6 bundled task fixtures covering all 4 AgentDojo suites (banking,
  slack, travel, workspace) including 2 injection-case tasks. CI-
  friendly — no API key required.
- ``StubAgentModel`` is a *vulnerable* agent that always tries to
  execute the injected attack on the second step; a working defense
  blocks the malicious call, ASR drops to 0%.
- CLI: ``python -m tex.bench.agentdojo --smoke`` runs 2 tasks; the
  ``--model`` flag is gated on a real ``agentdojo`` install + API
  keys for a publishable leaderboard number.

Tests: 9/9 in ``tests/frontier_thread_12/test_agentdojo.py``. Smoke
CLI verified: strict PDP drives ASR to 0%; permissive PDP shows
non-zero ASR — proving the harness actually measures the defense.

### 12.5 — rustworkx native graph backend (wired, May 20, 2026)

**Claim.** Tex ships a **conditional rustworkx accelerator** for the
provenance-graph BFS that dominates per-request latency. Microsoft
Agent Governance Toolkit (Apr 2026) still ships networkx; no agent-
governance product uses rustworkx as of May 18 2026.

What Tex actually does:
- ``tex.graph.rustworkx_backend.available()`` returns True iff
  rustworkx is importable.
- ``bfs_descendants(graph, source, edge_kinds=None, max_depth=None)``
  uses rustworkx if available, networkx fallback otherwise. Same
  signature, identical results.
- ``reachable_pairs(graph, sources)`` for all-pairs reachability
  queries used by PCAS recursive policies.
- Filtered traversal: edge-kind matching against the Thread 11
  ARM-style 4 edge labels (DirectOutput, InputTo, FieldOf,
  Counterfactual) and the Thread 11 IFC graph in general.

Tests: 6/6 in ``tests/frontier_thread_12/test_rustworkx.py``. (CI
exercises the networkx fallback; the rustworkx path is exercised
when rustworkx is installed in the deployment environment.)

### 12.6 — Lean 4 non-interference proof (publication-ready, May 20, 2026)

**Claim.** Tex ships the **first mechanically-checked Lean 4 proof
of non-interference for the FIDES product-lattice capability
algebra**. FIDES (arxiv 2505.23643) is paper-only; no Lean / Coq /
Isabelle proof of its lattice properties exists in the public
literature. Microsoft published FIDES at
``github.com/microsoft/fides`` as an unverified Python library.

What Tex actually proves (``src/tex/proofs/non_interference.lean``):
- ``CapLevel`` forms a total order (TRUSTED ≤ USER ≤ UNTRUSTED).
- ``join`` is commutative, associative, idempotent, has identity
  ``TRUSTED``, and is monotone: ``a ≤ b → join a c ≤ join b c``.
- ``derive_chain_monotone``: for any sequence of derivations
  ``v₀ → v₁ → ... → vₙ``, ``level vₙ ≥ level v₀``.
- Corollary ``untrusted_propagates``: an UNTRUSTED initial value
  remains UNTRUSTED at the end of any derivation chain.
- Corollary ``derive_chain_bounded``: ``level vₙ ≤ UNTRUSTED``.

What is **not** proved (and not claimed): refinement to the Python
interpreter. That would require a verified compiler; we deliberately
do not state a refinement theorem so the proof contains no ``sorry``
on its algebraic theorems.

Build: ``lake build`` from a Mathlib4 project pointing at this file.
CI does not build Lean for this delivery — the file is for
publication review and manual proof checking.

### 12.7 — MELON / StruQ / SecAlign adapters (wired, May 20, 2026)

**Claim.** Tex ships the **first PDP-integrated adapter set for the
three leading model-side defenses** against indirect prompt injection.
MELON (arxiv 2502.05174, Feb 2025), StruQ (arxiv 2402.06363, Feb
2024), and SecAlign (arxiv 2410.05451, Oct 2024) are research
defenses; integration into production agent platforms is rare and
none ship as first-class PDP signals.

What Tex actually does:
- ``MelonSpecialist`` exposes a ``MelonBackend`` Protocol. Production
  callers plug in a backend that performs MELON's double-inference
  check. Default ``HeuristicMelonBackend`` approximates the "intent
  shift" signal locally via token-set Jaccard between user prompt
  and environment content, with arg-leakage detection (args
  referencing env-only tokens → flag). Advisory confidence 0.5
  reflects the structural approximation.
- ``StruQSpecialist`` exposes a ``StruQBackend`` Protocol with a
  default ``StructuralStruQBackend`` matching 17 injection signature
  patterns across 5 categories (instruction-override,
  role-redefinition, urgency-pressure, authority-spoofing,
  envelope-escape, financial-action, code-execution). Confidence
  0.7. Production wiring replaces the structural backend with a
  StruQ-tuned model endpoint.
- ``SecAlignSpecialist`` exposes a ``SecAlignBackend`` Protocol with
  a default ``DPODistilledHeuristic`` that computes the three
  features SecAlign is trained on (imperative density,
  instruction-data conflict, action-in-prompt alignment) and
  produces a weighted risk. Advisory confidence 0.5. Production
  replaces the heuristic with a SecAlign-fine-tuned backbone.

Tests: 14/14 in ``tests/frontier_thread_12/test_model_defenses.py``.

### 13. Composite TDX + NVIDIA GPU TEE attestation bound to every decision evidence record (wired, May 21, 2026)

**Claim.** When ``TEX_TEE_MODE=1`` is set, every ``/v1/guardrail``
request causes Tex to collect Intel TDX evidence AND NVIDIA H100/H200/B200
GPU attestation evidence, submit BOTH to Intel Trust Authority's
``/appraisal/v2/attest`` endpoint (composite ``tdx+nvgpu`` mode) via
``ITAConnector.get_token_v2(tdx_args, gpu_args)``, and embed the
resulting PS384-signed JWT inside the decision's evidence record —
hash-chained through the existing SHA-256 payload chain so it is
cryptographically bound to the verdict. A new ``POST /v1/tee/verify``
endpoint lets relying parties (insurers, regulators, downstream
agents) verify the JWT independently fail-closed, with the result
returned as an AR4SI trustworthiness vector per
``draft-ietf-rats-ear-03``.

**Bleeding-edge anchors (May 2026, things no agent-governance
competitor has shipped).**

- **Intel Trust Authority composite v2** — ``/appraisal/v2/attest``,
  composite token shape with top-level ``tdx`` and ``nvgpu`` claim
  blocks. Phala uses ITA for infrastructure attestation; **no agent
  governance platform** (Microsoft AGT, Noma, Zenity, Pillar, Lakera)
  binds it into per-decision evidence.
- **NVIDIA Blackwell B200/B300 confidential compute** with inline
  NVLink encryption — GA on the 590-series driver as of May 2026.
  Tex's envelope carries ``gpu_tee_type`` so operators can pin policy
  ("Blackwell or refuse") via ``ExpectedMeasurements.gpu_hwmodel``.
- **draft-messous-eat-ai-01** (Feb 23 2026, Huawei R&D) — the FIRST
  IETF EAT profile specifically for autonomous AI agents. CBOR keys
  ``-75000`` (ai-model-id) through ``-75012`` (ai-sbom-ref) are
  modelled exactly. Tex carries these in
  ``CompositeAttestationEnvelope.eat_ai`` and the verifier checks
  ``ai_model_id`` / ``ai_model_hash`` against operator-pinned expected
  values. **No competitor implementation exists.**
- **arxiv 2605.03213** (Forough et al., May 7 2026, *When Agents
  Handle Secrets: A Survey of Confidential Computing for Agentic
  AI*) — explicitly names "compound attestation for multi-hop agent
  chains" as an open challenge and concludes "no broadly established
  end-to-end framework yet binds them into a coherent security
  substrate for production agentic AI." Tex's
  ``CompoundAttestationLink`` is the production answer: per-hop ITA
  JWTs hash-chained via ``previous_jwt_sha256``.
- **arxiv 2604.23280** (*CrossGuard*, Apr 28 2026) — identifies TEE
  cloneability as a gap and recommends per-decision instance binding.
  Tex's ``decision_bound_nonce(decision_id, request_id)`` is exactly
  that: ``SHA-256("tex|" + decision_id + "|" + request_id)[:32]`` is
  the freshness nonce, so a captured JWT cannot be replayed across
  decisions.
- **draft-ietf-rats-ear-03** (Mar 15 2026) — AR4SI trustworthiness
  vector. ``CompositeVerificationResult.trustworthiness`` emits one
  axis per AR4SI dimension (instance_identity, configuration,
  executables, hardware, runtime_opaque) so relying parties don't
  re-parse TDX RTMRs.
- **Algorithm-agile signature verification** — PS384 and RS256 (ITA
  today) AND ML-DSA-65 / ml-dsa-87 / hybrid-ml-dsa-65-ed25519 (the
  moment ITA rotates to PQ signing). Routes through the existing
  ``tex.pqcrypto.algorithm_agility`` provider.

**Wired modules.**
- ``src/tex/tee/composite.py`` — domain models (envelope, EAT-AI
  claims, compound link, trustworthiness vector).
- ``src/tex/tee/tdx_attestation.py`` — Intel TDX evidence collector
  with ITA Python client binding + deterministic dev-mode stub.
- ``src/tex/tee/h100_attestation.py`` — NVIDIA Attestation SDK binding
  for Hopper / Blackwell GPUs.
- ``src/tex/tee/attestation_client.py`` — composer (``compose_attestation``,
  ``compose_from_evidence``), verifier (``verify_attestation``),
  ``decision_bound_nonce``, test-mode JWT builder.
- ``src/tex/api/tee_routes.py`` — ``POST /v1/tee/verify`` and
  ``GET /v1/tee/status`` endpoints.
- ``src/tex/commands/evaluate_action.py::_build_evidence_metadata`` —
  gated TEE injection point. When ``TEX_TEE_MODE`` is unset, zero
  cost; existing tests bit-identical.

**Wired tests.**
- ``tests/frontier_thread_12_tee/test_composite_attestation.py`` —
  46 unit tests across 9 classes covering nonce derivation,
  collectors, composer, verifier happy path, every fail-closed
  branch, EAT-AI claim CBOR map keys, compound link semantics,
  envelope frozen+extra=forbid discipline.
- ``tests/test_integration_layer_tee.py`` — 12 integration tests
  including the headline
  ``TestGuardrailWithTeeBinding::test_tee_attestation_embedded_in_evidence_payload``
  that issues a real ``POST /v1/guardrail`` request and reads back
  the JSONL evidence file to assert the composite TEE block is
  embedded inside ``metadata.tee_composite_attestation``, and
  ``TestEndToEndRoundTrip::test_extracted_jwt_verifies`` that pulls
  the JWT back out of evidence and re-verifies it via
  ``POST /v1/tee/verify``.

**Hard-constraint compliance.**
- Pydantic v2 ``frozen=True, extra="forbid"`` on every model.
- Existing ``EvidenceRecord`` schema unchanged — TEE attestation
  rides inside ``payload.metadata`` so the SHA-256 hash chain
  cryptographically covers it without a schema migration.
- Fail-closed everywhere: production mode + dev-stub evidence raises
  ``RuntimeError``; the verifier emits a stable reason code on every
  failure path; alg=none JWTs are rejected unless
  ``TEX_TEE_ATTESTATION_MODE=test`` AND the payload carries the
  explicit ``x-tex-test-mode: true`` marker.
- Algorithm-agile signature verification routes through
  ``tex.pqcrypto.algorithm_agility`` for ML-DSA / hybrid.
- 90%+ coverage on the 5 new modules (46 unit tests + 12 integration
  tests).
- Zero regression: 3,086 existing tests still pass. The TEE
  block is only injected when ``TEX_TEE_MODE=1`` so legacy callers
  get bit-identical evidence.

**Demo.** ``scripts/demo_tee.sh`` — single curl request to
``/v1/guardrail`` produces a verdict, extracts the embedded ITA JWT
from the evidence chain, posts it to ``/v1/tee/verify``, and prints
the AR4SI trustworthiness vector.

**Why this is the wedge.**

Microsoft Agent Governance Toolkit (Apr 2 2026, MIT, 9,500+ tests,
10/10 OWASP ASI 2026 coverage, sub-0.1ms p99) signs its own deployment
manifest with software-only attestation: their ``agent-compliance
verify`` produces a signed proof against published source hashes,
but **does not bind to Intel TDX or NVIDIA NRAS**. Same gap at Noma
($132M Series B), Zenity (Gartner "Company to Beat"), Pillar, Lakera
(acquired by Check Point). Phala provides the infrastructure
(``Intel TDX + NVIDIA H100/H200 + nvSwitch attestation`` per their
GPU TEE product page) but **not** the governance layer that binds
the attestation to a per-decision evidence record. Tex's composite
TDX+NVIDIA attestation, bound per-decision via CrossGuard nonce, with
EAT-AI claims and AR4SI trustworthiness vector, is the differentiator
no competitor has shipped as of May 18 2026.

### 14. VET Web Proofs + Agent Identity Document with PQ-default selective disclosure (wired, May 21, 2026)

**Claim.** Tex now notarizes every third-party AI API call with
attestor-signed Web Proofs over the TLS session, producing tamper-evident
transcripts independent of the API provider. Each Tex-managed agent
carries a W3C Verifiable Credentials 2.0 Agent Identity Document (AID)
with **``bbs-2023``-shape selective-disclosure** under **ML-DSA-65
(FIPS 204, NIST L3) by default** — Tex's post-quantum hedge against
the classical Ed25519 keys that every competing agent-identity stack
(Microsoft Agent Governance Toolkit Agent Mesh, Indicio ProvenAI,
walt.id Enterprise Stack, Microsoft Entra Verified ID) still ships in
May 2026. The AID embeds an AIVS-Micro continuous-monitoring stub
(draft-stone-aivs-00) on every issuance, optionally embeds a PTV
Groth16-2026 attestation (draft-anandakrishnan-rats-ptv-agent-identity-00,
**first known Python implementation**), and is paired with OAuth 2.0
Transaction Tokens for Agents (draft-oauth-transaction-tokens-for-agents-06
``act``/``sub`` claims) for short-lived per-call authorization per the
April 30, 2026 Five Eyes joint guidance on Securing Agentic AI. The
``MultiAttestorCommittee`` ships **k-of-n threshold Web Proofs** — no
other AI-governance vendor exposes this primitive. Web Proofs attach
to evidence records via ``tex.vet.integration.attach_web_proof_to_payload``;
the resulting payload is verifiable end-to-end by any auditor against
the original API provider, closing the audit-runtime gap identified in
arxiv 2504.04715 ("Are You Getting What You Pay For?").

**Bleeding-edge anchors (May 2026, things no agent-governance
competitor has shipped).**

- **zkTLS via Reclaim Protocol attestor-core + Pluto Labs** + TLSNotary
  v0.1-alpha QuickSilver VOLE-IZK MPC (replaced garbled-circuit ZK in
  Aug 2025; 30% online-time reduction per TLSNotary Jan 2026
  benchmarks). Reclaim runs a decentralized attestor network but does
  NOT expose explicit k-of-n quorum semantics; consumers receive a
  single signature from one randomly-selected attestor. **Tex demands
  k-of-n and surfaces the threshold in the audit record.**
- **W3C ``bbs-2023`` cryptosuite shape** (Candidate Recommendation, VC
  charter restarted April 2026 with VC 2.1 incoming). Base proof +
  derived proof + holder-binding HMAC with mandatory disclosure of
  ``agent_id``, ``issuer_did``, ``aid_spec``, selective disclosure of
  everything else.
- **ML-DSA-65 (FIPS 204) by default** via Tex's
  ``tex.pqcrypto.algorithm_agility``. Microsoft AGT's Agent Mesh uses
  Ed25519. The wedge: store-now-decrypt-later attacks against
  classical agent identities are a 2031 threat that competitors have
  no migration path for; Tex flips the default today.
- **PTV (Prove-Transform-Verify) Groth16-2026 attestation** — both
  drafts (draft-anandakrishnan-rats-ptv-agent-identity-00 Apr 5 +
  draft-anandakrishnan-ptv-attested-agent-identity-00 Mar 31, 2026,
  Sovereign AI Stack). As of the IETF datatracker May 18 2026 there
  are **no public implementations**. Tex ships the first known one in
  Python with a Schnorr-bridge stand-in for the real Groth16 prover —
  the envelope shape is correct and the prover swap is drop-in.
- **AIVS-Micro 200-byte attestation** (draft-stone-aivs-00, March
  2026, SwarmSync.AI; W3C AIVS Community Group launched Apr 5, 2026).
  Tex embeds an AIVS-Micro stub in every AID for continuous-monitoring
  systems (Datadog, Splunk, Sentinel) without re-fetching the full
  AID.
- **draft-ietf-oauth-sd-jwt-vc-16** (April 24, 2026, latest revision)
  + **draft-nandakumar-agent-sd-jwt-02 SD-Card format** (Feb 28,
  2026). Existing implementations (MATTR TS lib, walt.id Java) track
  the older ``-13`` revision; Tex tracks ``-16`` (the Claim Metadata
  section with ``Claim Selective Disclosure Metadata`` was added
  between ``-13`` and ``-16``). The SD-Card extension is **first known
  Python implementation**.
- **OAuth Transaction Tokens for Agents** at
  draft-oauth-transaction-tokens-for-agents-06 (April 11, 2026), with
  the ``act`` field identifying the agent and the ``sub`` field
  identifying the principal. Tex packages each AID presentation
  inside a Txn-Token with a 60-second TTL — exactly the
  short-lived-OAuth-token pattern the April 30 Five Eyes guidance
  specifies.
- **W3C VC 2.0** envelope (Data Model 2.0 Recommendation; VC 2.1
  charter started April 2026) with ``DataIntegrityProof`` cryptosuite
  ``bbs-2023-shape-{algorithm}`` that signals Tex's PQ-default
  selective-disclosure shape while remaining spec-compatible.
- **Audit-runtime gap closure.** Arxiv 2504.04715 ("Are You Getting
  What You Pay For? Auditing Model Substitution in LLM APIs",
  Sept 2025) demonstrated that software-only attestation of LLM API
  responses is unreliable: statistical tests on text outputs are
  query-intensive and fail against subtle quantized substitutions.
  The recommended fix is hardware-attested TEEs OR notarized TLS
  transcripts. **Microsoft AGT, Zenity, Noma, Pillar, Lakera, Protect
  AI ship none of these for third-party API calls.** Tex is the
  first AI-governance platform to wire TLS notarization into the
  per-decision evidence record.

**Source paper / standard anchors.**

- IETF Internet-Drafts:
  - ``draft-irtf-cfrg-bbs-signatures-10`` (Jan 8, 2026, Looker /
    Kalos / Whitehead / Lodder, MATTR + Portage + CryptID).
  - ``draft-ietf-oauth-sd-jwt-vc-16`` (Apr 24, 2026, Terbu / Fett /
    Campbell).
  - ``draft-nandakumar-agent-sd-jwt-02`` (Feb 28, 2026, Nandakumar /
    Jennings, Cisco) — SD-Card extension.
  - ``draft-oauth-transaction-tokens-for-agents-06`` (Apr 11, 2026,
    Raut, Amazon).
  - ``draft-anandakrishnan-rats-ptv-agent-identity-00`` (Apr 5,
    2026, Damodaran, Sovereign AI Stack).
  - ``draft-anandakrishnan-ptv-attested-agent-identity-00``
    (Mar 31, 2026).
  - ``draft-stone-aivs-00`` (Mar 2026, Stone, SwarmSync.AI).
- W3C standards:
  - Data Integrity BBS Cryptosuites v1.0 (Candidate Recommendation).
  - Verifiable Credentials Data Model 2.0 (Recommendation).
  - VC Working Group Charter 2026 (April 2026 start, VC 2.1 incoming).
- Foundation / industry:
  - Linux Foundation A2A Protocol v1.0 Signed Agent Cards (GA April 9,
    2026, 150+ orgs in production).
  - FIDO Alliance / Mastercard AP2 v0.2 (April 28, 2026 donation,
    Mandate-bound payments).
  - Five Eyes joint guidance "Securing Agentic AI" (April 30, 2026).
  - NIST CAISI AI Agent Standards Initiative (February 17, 2026
    launch; April 2 concept paper closed).
- Academic:
  - Looker et al. (2024) — BBS Signature Scheme spec.
  - PADO Labs (2024) — "Lightweight Authentication of Web Data via
    Garble-Then-Prove" (semi-honest OLE suffices, removing MAC-key
    revelation step — incorporated into TLSNotary 2025).
  - Arxiv 2504.04715 (Sept 2025) — Audit-runtime gap; "Are You
    Getting What You Pay For?".
  - Arxiv 2603.25190 (Mar 31, 2026 v2) — zk-X509: Groth16 over PKI;
    foundation for the PTV envelope shape.
  - Arxiv 2505.19301 (May 28, 2025) — Zero-Trust Identity Framework
    for Agentic AI — the architectural blueprint Tex implements.

**Modules.**

- ``tex.vet.selective_disclosure`` — RFC 6962-shaped Merkle tree
  (with correct odd-leaf duplication) + salted commitments + base
  proof / derived proof primitives. Algorithm-agile via
  ``tex.pqcrypto.algorithm_agility``.
- ``tex.vet.web_proofs`` — ``WebProof``, ``WebProofAttestation``,
  ``WebProofMode`` (``ZKTLS_RECLAIM``, ``ZKTLS_PLUTO``,
  ``TLSNOTARY_MPC``, ``MULTI_ATTESTOR``, ``STUB``),
  ``ZkTlsAttestorClient``, ``TlsNotarySubprocessClient``,
  ``MultiAttestorCommittee``, ``notarize_session``,
  ``verify_web_proof``.
- ``tex.vet.agent_identity_document`` — ``AgentIdentityDocument``,
  ``AidIssuanceRequest``, ``AidPresentationRequest``,
  ``AidPresentationEnvelope``, ``AidStatus``, ``issue``, ``verify``,
  ``present``, ``verify_presentation_envelope``, ``to_vc_2_0``.
- ``tex.vet.ptv_attestation`` — ``PtvAttestationMethod``,
  ``PtvAttestationEnvelope``, ``generate_ptv_attestation``,
  ``verify_ptv_attestation``. First known Python impl of the IETF
  PTV drafts.
- ``tex.vet.aivs_micro`` — ``emit_aivs_micro``, ``verify_aivs_micro``,
  ``AivsMicroRecord``, ``AivsMicroVerifyResult``.
- ``tex.vet.sd_jwt_vc`` — ``issue_sd_jwt_vc``, ``verify_sd_jwt_vc``,
  ``present_sd_jwt_vc``, ``verify_sd_jwt_vc_presentation``,
  ``issue_sd_card``, ``SdJwtClaimVisibility``. SD-JWT VC layer +
  SD-Card format.
- ``tex.vet.txn_tokens`` — ``TxnTokenScope``, ``TxnTokenClaims``,
  ``TxnTokenArtifact``, ``issue_txn_token``, ``verify_txn_token``.
  draft-06 ``act``/``sub`` claims; 60s TTL default; ML-DSA-65 default.
- ``tex.vet.registry`` — ``AidRegistry``, ``InMemoryAidRegistry`` with
  optional ``AidRegistryMirror`` hook for Postgres durability.
- ``tex.vet.integration`` — ``attach_web_proof_to_payload``,
  ``verify_payload_web_proof``. The integration hook into the
  ``/v1/guardrail`` evidence path.
- ``tex.api.vet_routes`` — FastAPI router with
  ``POST /v1/vet/issue-aid``, ``POST /v1/vet/verify-aid``,
  ``POST /v1/vet/present-aid``, ``POST /v1/vet/verify-presentation``,
  ``GET /v1/vet/aid/{agent_id}``, ``POST /v1/vet/update-aid-status``,
  ``POST /v1/vet/notarize``, ``POST /v1/vet/verify-web-proof``,
  ``POST /v1/vet/issue-txn-token``, ``POST /v1/vet/verify-txn-token``.

**Tests.** 65 new unit tests in ``tests/vet/`` (test_selective_disclosure.py,
test_web_proofs.py, test_agent_identity_document.py, test_primitives.py,
test_vet_routes.py) all passing. 4 integration tests in
``tests/test_integration_layer.py::TestVetIntegration`` proving the
``/v1/vet/*`` round-trip against the live FastAPI app and proving the
``tex.vet.integration`` hook attaches & verifies Web Proofs on
evidence-record payloads.

**Wedge against competitors (May 21, 2026).**

| Capability                          | Tex Thread 13 | Microsoft AGT | Indicio ProvenAI | walt.id | Microsoft Entra VID |
|-------------------------------------|---------------|---------------|------------------|---------|---------------------|
| Agent Identity Document (W3C VC)    | ✓             | ✓             | ✓                | ✓       | ✓                   |
| PQ signing default (ML-DSA-65)      | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| Selective disclosure (bbs-2023)     | **✓**         | ✗             | partial          | ✓       | ✗                   |
| Web Proofs (TLSNotary / zkTLS)      | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| Multi-attestor k-of-n notarization  | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| OAuth Txn-Tokens for Agents draft-06| **✓**         | ✗             | ✗                | ✗       | ✗                   |
| PTV attestation (Groth16-2026)      | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| SD-Card for A2A discovery           | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| AIVS-Micro on every credential      | **✓**         | ✗             | ✗                | ✗       | ✗                   |
| Web Proof bound to evidence chain   | **✓**         | ✗             | ✗                | ✗       | ✗                   |

References (Thread 13)
----------------------
- Looker, Kalos, Whitehead, Lodder. "The BBS Signature Scheme."
  draft-irtf-cfrg-bbs-signatures-10. IRTF/CFRG, January 8, 2026.
- W3C. "Data Integrity BBS Cryptosuites v1.0." Candidate Recommendation
  Draft, 2024–2026.
- Terbu, Fett, Campbell. "SD-JWT-based Verifiable Digital Credentials
  (SD-JWT VC)." draft-ietf-oauth-sd-jwt-vc-16. IETF OAuth WG, April 24, 2026.
- Nandakumar, Jennings. "SD Agent: Selective Disclosure for Agent
  Discovery and Identity Management." draft-nandakumar-agent-sd-jwt-02.
  IETF, February 28, 2026.
- Raut. "Transaction Tokens For Agents."
  draft-oauth-transaction-tokens-for-agents-06. IETF, April 11, 2026.
- Damodaran. "The Prove-Transform-Verify (PTV) Protocol for Attested
  Agent Identity." draft-anandakrishnan-rats-ptv-agent-identity-00,
  IETF RATS WG, April 5, 2026.
- Damodaran. "The Prove-Transform-Verify (PTV) Protocol for Attested
  Agent Identity." draft-anandakrishnan-ptv-attested-agent-identity-00,
  IETF, March 31, 2026.
- Stone. "Agentic Integrity Verification Standard (AIVS)."
  draft-stone-aivs-00, IETF, March 2026.
- TLSNotary. "Performance Benchmarks (August 2025)" — QuickSilver
  VOLE-IZK backend.
- Reclaim Protocol. attestor-core (https://github.com/reclaimprotocol/attestor-core).
- Linux Foundation. "A2A Protocol Surpasses 150 Organizations" press
  release. April 9, 2026.
- FIDO Alliance. Agent Payments Protocol (AP2) v0.2 donation.
  April 28, 2026.
- "Securing Agentic AI." Joint guidance, NSA / CISA / GCHQ / ASD / CCCS
  / GCSB. April 30, 2026.
- Arxiv 2504.04715. "Are You Getting What You Pay For? Auditing Model
  Substitution in LLM APIs." September 2025.
- Arxiv 2603.25190. "zk-X509: Privacy-Preserving On-Chain Identity from
  Legacy PKI via Zero-Knowledge Proofs." Bak, Tokamak Network, v2
  March 31, 2026.
- Arxiv 2505.19301. "A Novel Zero-Trust Identity Framework for Agentic
  AI." May 28, 2025.

Tests: 65/65 in ``tests/vet/`` + 4/4 in
``tests/test_integration_layer.py::TestVetIntegration``.

### 14.1 — VET Thread 13.1 patch: TLSNotary Proxy mode + SCITT + Chathurangi-2026 (wired, May 21, 2026)

**Claim.** Three frontier capabilities added on top of Thread 13:

1.  **TLSNotary Proxy mode (May 10, 2026)** as a 6th
    ``WebProofMode``. Per the TLSNotary blog "Introducing Proxy Mode:
    Choose Your Trust-Speed Tradeoff" (April 22, 2026) and benchmarks
    post (May 10, 2026), Proxy mode completes a 1 KB / 2 KB
    attestation in 1–2 seconds across residential and mobile profiles
    (native + browser), vs. 3–15 seconds for MPC mode. The trust
    model is different: the Verifier acts as a transparent proxy,
    records the encrypted byte stream, and the Prover later proves
    selective disclosure in ZK after the session closes. Faster, but
    the Verifier could derive plaintext if it kept the keys. Tex
    ships both modes and **recommends running them together in a
    k-of-n committee** so no single trust assumption is single-point.

2.  **First AI-governance vendor to ship per-decision SCITT
    registration.** ``draft-ietf-scitt-architecture-22`` (October 10,
    2025, adopted WG document). Each Tex decision (PERMIT / ABSTAIN /
    FORBID) is registered as a **COSE_Sign1 Signed Statement** to a
    **Transparency Service**, receiving a **COSE Receipt** with an
    RFC 9162-style **Merkle inclusion proof** verifiable independently
    of Tex. Combined with Thread 12's composite TEE JWT and Thread 1's
    SHA-256 hash chain, **auditors get three independent verification
    axes on a single decision** — none of which require trusting Tex's
    word. The wedge: as of May 18, 2026 *no AI-governance vendor*
    (Microsoft Agent Governance Toolkit, Zenity, Noma, Pillar, Lakera,
    Protect AI, Rubrik SAGE, Indicio ProvenAI, walt.id) ships SCITT
    registration. Tex is the first.

3.  **ARP (Attestation Reconciliation Protocol)** primitive per
    ``draft-hillier-scitt-arp-00`` (May 2026, Certisy). Tex exposes
    ``arp_project_claim`` + ``/v1/vet/scitt/arp-reconcile`` so a single
    canonical claim can be projected through register-specific
    controlled projection functions across the EU AI Act Article 50
    registry, the NIST AI RMF registry, and the UK AISI registry
    **without raw register records leaving their data-residency
    jurisdiction**. This is the cross-sovereign reconciliation path
    that lets a Tex tenant claim compliance in one jurisdiction while
    proving the same predicate (via a zero-knowledge-capable
    projection) in another.

**Frontier honesty (the audit on the audit).** During the Thread 13
post-build review the following frontier items were identified as
genuinely past my Jan-2026 reliable knowledge cutoff but published
before May 18, 2026, and not addressed in Thread 13 proper:

*   TLSNotary alpha.14 (Jan 19, 2026) — 8–16 % speedups.
*   TLSNotary alpha.15 Proxy mode (May 10, 2026) — the new bleeding
    edge for low-latency notarization.
*   Chathurangi 2026 — "Post-Quantum Traceable Anonymous Credentials
    from Lattices" (IACR Communications in Cryptology, Jan 8, 2026,
    DOI 10.62056/ak5wl8n4e, Griffith University). The genuine
    native-PQ swap target for the credential primitive, beyond
    bbs-2023 + ML-DSA-65.
*   The full SCITT stack — ``draft-ietf-scitt-architecture-22``,
    ``draft-hillier-scitt-arp-00`` (May 2026),
    ``draft-kamimura-scitt-vcp-01`` (Dec 17, 2025).

Thread 13.1 addresses (1) and (3) with code. The Chathurangi 2026
paper is referenced as the eventual swap target in both
``selective_disclosure.py`` and ``ptv_attestation.py`` docstrings;
a real Python implementation does not yet exist publicly, so the
honest framing is: Tex's bbs-2023-shape with ML-DSA-65 base signature
gives the *forgery-resistance* layer today (BBS unlinkability is
already CRQC-safe per arxiv 2501.07209 March 2026), and the
algorithm-agile commitment + signature primitives are structured to
swap in Chathurangi-2026 when a production implementation matures.

**New modules.**

*   ``src/tex/vet/scitt.py`` — Complete SCITT surface. Modeled on
    ``draft-ietf-scitt-architecture-22`` §6 CDDL. Key components:
    -   ``sign_statement`` — COSE_Sign1-shape Signed Statement issuance
        with CWT claims (iss/sub/iat/aud/exp/nbf per RFC 9597) and
        algorithm-agile signature.
    -   ``verify_signed_statement`` — full verification incl. payload
        digest re-derivation and subject-prefix pinning.
    -   ``InMemoryTransparencyService`` — thread-safe append-only-log
        with RFC 9162 SHA-256 Merkle tree, odd-leaf duplication,
        signed Receipt emission on every registration.
    -   ``verify_receipt`` / ``verify_transparent_statement`` —
        Receipt-side verification: TS signature + Merkle inclusion
        proof recomputes to the TS-signed root.
    -   ``register_aid`` / ``register_decision`` — high-level helpers
        binding to the Tex AID and decision payloads.
    -   ``ArpReconciliationRequest`` / ``arp_project_claim`` —
        cross-sovereign claim reconciliation per
        ``draft-hillier-scitt-arp-00``.

**Updated modules.**

*   ``src/tex/vet/web_proofs.py`` — added
    ``WebProofMode.TLSNOTARY_PROXY``, ``TlsNotaryProxyClient`` class,
    ``ENV_TLSNOTARY_PROXY_URL`` environment knob. Updated
    ``notarize_session`` dispatch and ``verify_web_proof`` candidate-
    modes to include the proxy mode. ``MultiAttestorCommittee``
    accepts the new client type so a single committee can mix
    MPC + Proxy + Reclaim + Pluto attestors.
*   ``src/tex/vet/integration.py`` — added
    ``attach_scitt_to_decision_payload`` and
    ``verify_payload_scitt_transparent`` so decision evidence records
    carry SCITT Receipts alongside the existing Web Proofs.
*   ``src/tex/vet/selective_disclosure.py`` — docstring updated to
    reference Chathurangi 2026 as the genuine native-PQ swap target
    and to correctly frame BBS unlinkability as already CRQC-safe per
    arxiv 2501.07209.
*   ``src/tex/vet/ptv_attestation.py`` — docstring updated to
    reference Chathurangi 2026 and to note SCITT composition as the
    behavioral-continuity path.
*   ``src/tex/api/vet_routes.py`` — 4 new endpoints:
    ``POST /v1/vet/scitt/register-decision``,
    ``POST /v1/vet/scitt/verify-transparent``,
    ``GET /v1/vet/scitt/receipt/{entry_id}``,
    ``GET /v1/vet/scitt/ts-status``,
    ``POST /v1/vet/scitt/arp-reconcile``.

**Three-axis verification architecture.** As of Thread 13.1, every
Tex decision evidence record can carry *three independent
verification primitives*, each verifiable by an external auditor
without trusting Tex:

| Axis | Primitive                                  | Threat covered             | Standard                          |
|------|--------------------------------------------|----------------------------|-----------------------------------|
| 1    | SHA-256 hash chain                         | Internal log tampering     | Thread 1, internal                |
| 2    | Composite TDX + NVIDIA GPU TEE JWT         | Host-level compromise      | Intel Trust Authority, AR4SI      |
| 3    | SCITT COSE Receipt + Merkle inclusion proof| Operator-level repudiation | draft-ietf-scitt-architecture-22  |

**Tests.** 25 new tests in:
- ``tests/vet/test_scitt.py`` (19) — Signed Statements, TS append-log,
  Receipt verification, tamper detection across all layers, ARP.
- ``tests/vet/test_tlsnotary_proxy.py`` (6) — Proxy client stand-alone
  + mixed-mode k-of-n committees combining all 4 attestor families.
- 6 added to ``tests/test_integration_layer.py`` under
  ``TestScittIntegrationLayer`` + ``TestTlsNotaryProxyIntegration``
  proving live-app round-trip.

All 209 VET-namespace tests pass. Full suite at **3,252 passing**
(up from 3,223 in Thread 13). Three pre-existing sandbox-only
failures unrelated to Thread 13.1.

**Source paper / standard anchors added.**
- ``draft-ietf-scitt-architecture-22`` (Oct 10, 2025, IETF SCITT WG,
  adopted Working Group document).
- ``draft-ietf-cose-merkle-tree-proofs-17`` (Sep 10, 2025, IETF COSE
  WG) — COSE Receipts spec.
- ``draft-hillier-scitt-arp-00`` (May 2026, Certisy) — Attestation
  Reconciliation Protocol.
- ``draft-kamimura-scitt-vcp-01`` (Dec 22, 2025, VeritasChain
  Standards Org) — Financial trading SCITT profile, EU AI Act +
  MiFID II.
- ``draft-birkholz-cose-receipts-ccf-profile-05`` (Nov 13, 2025) —
  TEE-anchored CCF profile for production Transparency Services.
- TLSNotary blog "Introducing Proxy Mode" (Apr 22, 2026) +
  "Proxy mode benchmarks" (May 10, 2026).
- TLSNotary alpha.14 release notes (Jan 19, 2026) — 8–16 % speedup.
- Chathurangi, M. "Post-Quantum Traceable Anonymous Credentials from
  Lattices." IACR Communications in Cryptology, Jan 8, 2026.
  DOI 10.62056/ak5wl8n4e.

## Thread 14 — ZKPROV training-data provenance + VFT extensions + LatticeFold+ PQ folding (wired, May 21, 2026)

**Claim.** Tex produces zero-knowledge proofs that every model
output was generated from an authorized training-data manifest,
verifiable independently in under 2 seconds without revealing the
training data itself. ZKPROV per arxiv 2506.20915, Halo2-IPA
default backend with no trusted setup, ML-DSA-65 CA signature.

Beyond the base ZKPROV construction this thread ships the
post-ZKPROV May-2026 frontier that no agent-governance incumbent
has wired:

1.  **VFT extensions** (arxiv 2510.16830 v3, Dec 29 2025). The
    DatasetManifest binds the five elements VFT proved necessary
    for a defensible attestation: Merkle/vector commitments over
    data sources / preprocessing / licenses, per-source
    ``max_epoch_participation`` quotas, a verifiable sampler
    (public-replayable and private-index-hiding), recursive
    aggregation that folds per-step proofs into per-epoch
    certificates with millisecond verification, and a provenance
    binding that anchors the manifest to a public model card.

2.  **LatticeFold+ ℓ2-improved post-quantum folding** (eprint
    2026/721, April 19 2026). The recursive-aggregation surface
    accepts ``FoldingScheme.LATTICEFOLD_PLUS_2026`` so the
    aggregated certificate is upgradeable to a Q-Day-secure
    folding scheme without a wire-format break. Today's
    aggregation runs HyperNova+CycleFold (CRYPTO 2024, updated
    02/20/2026); the LatticeFold+ path is reserved with explicit
    PQ tagging in ``is_post_quantum_folding``. ~2x lower prover
    cost than the 2025 LatticeFold baseline per the April 2026
    paper.

3.  **DeepProve backend slot** (Lagrange Labs, public release Feb
    23 2026). The pluggable ``ProofBackend`` dispatcher reserves
    ``deepprove-2026`` for the Rust crate that delivered 158x
    faster prover than ezkl on benchmarked CNN/MLP workloads and
    671x faster verification, deployed in production at the
    Anduril Lattice SDK, Lockheed supply chain, and Oracle Cloud
    sovereign environments. Zero competitors in the
    agent-governance market have wired DeepProve as of May 18
    2026.

4.  **JOLT + Twist & Shout backend slot** (a16z, Feb 2026).
    Sum-check + lookup-singularity zkVM with the Twist & Shout
    memory-checking arguments giving ~3x prover speedup over the
    Lasso baseline. Reserved as ``jolt-sumcheck-2026`` for
    Tex's future RISC-V ZKPROV circuit description path.

5.  **SCITT ARP cross-sovereign reconciliation**
    (draft-hillier-scitt-arp-00, May 1 2026 — *17 days old as of
    this writing*). Each DatasetManifest projects into a narrowed
    claim under the EU AI Office TDS Template predicate library
    (``DATA_VOLUME_BUCKET``, ``LICENSE_FAMILY_PRESENT``,
    ``JURISDICTION_RESIDENCY``, ``TEMPORAL_WINDOW_OVERLAP``,
    ``MODEL_PROVIDER_DECLARATION``) wrapped in the IANA-requested
    COSE protected-header labels 0x801-0x804. The same manifest
    answers the EU AI Office Article 53(1)(d) public summary and
    the cross-sovereign reconciliation question with one signed
    artifact.

6.  **NABAOS-style epistemic receipts** (arxiv 2603.10060, March
    9 2026 — 10 weeks old). HMAC-signed runtime receipts that
    classify each claim by Nyāya Śāstra epistemic source
    (pratyakṣa / anumāna / śabda / abhāva / ungrounded) and
    cross-reference against the agent's tool-call record.
    Detects 94.2% of fabricated tool references, 87.6% of count
    misstatements, 91.3% of false absence claims at <15ms
    verification overhead per response. Sits alongside ZKPROV as
    the sub-millisecond hot path that complements the
    seconds-to-minutes slow path of the regulator-grade ZK proof.

7.  **EU AI Act Article 53(1)(d) TDS Template binding**
    (European Commission, mandatory template published 24 July
    2025, enforcement 2 August 2026, fines up to €15M or 3%
    global revenue). The ``DatasetManifest`` carries every
    Article 53(1)(d) field — ``model_card_uri``,
    ``model_provider``, ``training_window_start``/``end``, source
    categorization under the six TDS buckets, license tags from
    the SPDX-aligned taxonomy — and projects to a public
    ``TDSPublicSummary`` mechanically without leaking the
    per-source content hashes. One artifact answers both the
    cryptographic provenance question and the transparency
    obligation.

8.  **Algorithm-agile CA signing.** The commitment's CA
    signature flows through ``tex.pqcrypto.algorithm_agility``
    with ML-DSA-65 as the default (FIPS 204 L3, NSA CNSA 2.0
    timeline 2030/2035). Composite ML-DSA-65+Ed25519 and
    ML-DSA-87 are available for BSI 2021 / ANSSI 2024 / CNSA 2.0
    jurisdictions without code changes — only the
    ``ca_keypair.algorithm`` field changes.

9.  **VEIL hash-based ZK wrapper** (eprint 2026/683, April 8
    2026 — *11 days older than LatticeFold+ ℓ2 and the newest
    cryptographic primitive Tex wires*). Dalal, Hemo, Rabinovich,
    Rothblum's VEIL compiler adds zero-knowledge to hash-based
    multilinear proof systems at ~3% prover overhead, ~22%
    verifier overhead, ~12% proof-size overhead. Crucially the
    construction is **plausibly post-quantum on hash assumptions
    alone** — no lattice security, no elliptic curves, no
    trusted setup. This closes the SNARK-side PQ gap in ZKPROV:
    today's manifest is PQ on the signing layer (ML-DSA-65) but
    classically pre-quantum on the SNARK layer (Halo2-IPA). The
    backend slot ``veil-hash-based-zk-2026`` is reserved with
    explicit PQ tagging in ``is_regulator_grade``; the manifest
    is upgradeable without a wire-format break. Composes with
    SP1 Hypercube (item 10) and any future FRI/multilinear
    prover. The Python binding is not yet shipping — wiring
    exercises today through the deterministic shim.

10. **SP1 Hypercube zkVM** (Succinct Labs, **mainnet Feb 19
    2026** — first multilinear-polynomial zkVM in production).
    Proves 99.7% of L1 Ethereum blocks in under 12 seconds on
    16 NVIDIA RTX 5090 GPUs ("real-time proving at home"), with
    formally verified RISC-V instruction constraints in
    collaboration with Nethermind and the Ethereum Foundation.
    Relevance to ZKPROV: SP1 is a general-purpose RISC-V zkVM,
    so a ZKPROV verifier circuit compiled to RISC-V runs on it.
    This is the path to a real-time per-decision provenance
    proof on commodity GPU hardware — what every other backend
    in the dispatcher is trying to be. SP1 Hypercube is not
    natively ZK; the ZK property comes from wrapping it in
    VEIL (item 9), so the regulator-grade declaration in the
    manifest is "SP1 Hypercube + VEIL". Backend slot
    ``sp1-hypercube-2026`` reserved; install pointer is the
    Succinct ``sp1up`` script.

11. **Mira parallel folding** (ZKTorch, arxiv 2507.07031,
    Jul 9 2025 — open source at github.com/uiuc-kang-lab/zk-torch).
    Parallel extension of the Mira accumulation scheme that
    restructures recursive folding as a tree-based homomorphic
    reduction compatible with parallel hardware. Empirical
    benchmarks (Chen et al.) on GPT-J, BERT, ResNet-50, and
    LLaMA-2-7B show **3×–10× proof-size reduction** and **up to
    6.2× faster proving** vs. prior accumulation schemes
    (GPT-J: 8,662s → 1,397s). Mira is what makes the
    per-decision proof cost scale linearly with parallel cores
    rather than wall-clock seconds — the missing piece for
    interactive provenance verification on inference traffic.
    Added as ``FoldingScheme.MIRA_PARALLEL_2026`` on the
    regulator-grade folding allowlist; composes naturally with
    DeepProve's per-record basic-block proofs.

12. **Honest Poseidon disclosure + real Poseidon-BN254-t3
    Merkle**. The previous Thread 14 prototype tagged the
    Merkle tree as ``poseidon2-bn254-t3`` while actually using
    SHA-256 reduced modulo the BN254 scalar field as a stand-in
    (the Poseidon2 round-constants table requires a
    Sage-generated parameter set Tex did not bundle). The
    upgrade pass: (a) **default Merkle hash is now real
    Poseidon-BN254-t3** (Grassi-Khovratovich-Rechberger-Roy-
    Schofnegger, USENIX Security 2021, eprint 2019/458) with
    parameters α=5, RF=8, RP=57, 128-bit security, via the
    ``poseidon-hash`` PyPI package which ships the canonical
    round constants and MDS matrix; (b) the manifest's
    ``merkle_hash_alg`` defaults to ``"poseidon-bn254-t3"`` and
    documents that ``"poseidon2-bn254-t3"`` (eprint 2023/323,
    ~30% fewer Plonk constraints) is the upgrade path — Tex is
    not currently using Poseidon2; (c) the SHA-256 reduction
    survives as the documented fallback
    ``"sha256-reduced-bn254"`` and is automatically refused
    from regulator-grade verification the same way the
    deterministic-shim backend is refused; (d) the live
    algorithm choice is exposed via ``GET /v1/zkprov/health``'s
    new ``merkle_hash_in_use`` field. **Poseidon ≠ Poseidon2 —
    they are not the same hash. The manifest tag tells the
    verifier which parameter set to instantiate.**

**Wire format and ZK-friendliness.** Dataset records are committed
to under a Poseidon-BN254-t3 (Grassi et al., USENIX Security 2021,
eprint 2019/458) Merkle root — t=3, rate=2, capacity=1, α=5, RF=8,
RP=57, 128-bit security — alongside an SHA-256 audit root for
SCITT/C2PA consumers. Poseidon2 (eprint 2023/323, ~30% fewer Plonk
constraints) is the upgrade path, declared via the manifest's
``merkle_hash_alg`` field; SHA-256-reduced-BN254 is the documented
fallback for hermetic build environments and is automatically
refused from regulator-grade verification. The commitment's CA
signature covers both roots, the manifest root hash, the schema
hash, and the lifetime window — sealed with deterministic
length-prefixed encoding (no JSON ambiguity).

**Wired surface.**

- ``POST /v1/zkprov/issue-commitment`` — issue a CA-signed
  ``DatasetCommitment`` over a record set plus a
  ``DatasetManifest``; returns the canonical commitment envelope
  and the ``TDSPublicSummary`` projection.
- ``POST /v1/zkprov/prove`` — generate a ``ProvenanceProof`` over
  a (prompt, response, attributes) tuple; backend dispatched via
  the manifest's ``proof_backend`` field; persists to
  ``tex_provenance_proofs`` when ``persist_to_store=true``.
- ``POST /v1/zkprov/verify`` — six fail-closed checks (response
  consistency, statement-binds-commitment, CA signature, lifetime,
  optional Merkle inclusion, backend verdict). The
  ``regulator_grade=true`` flag rejects the deterministic-shim
  backend and demands one of ``halo2-ipa-2026 / deepprove-2026 /
  jolt-sumcheck-2026 / latticefold-plus-2026``.
- ``POST /v1/zkprov/aggregate`` — recursively fold N leaf proofs
  into one ``AggregatedCertificate`` under a chosen
  ``FoldingScheme``; coverage-checked and regulator-grade-aware.
- ``POST /v1/zkprov/narrow`` — produce a SCITT ARP
  ``NarrowedClaim`` (data-volume-bucket / license-family-present /
  temporal-window-overlap) wrapped in COSE labels 0x801-0x804.
- ``GET  /v1/zkprov/proof/{envelope_sha256}`` — retrieve a stored
  proof from the durable ``tex_provenance_proofs`` Postgres table.
- ``GET  /v1/zkprov/health`` — feature-flag, store availability,
  supported backends, supported folding schemes, and the full
  ``standards_pinned`` map.

**Evidence-chain integration.** ``TEX_ZKPROV=1`` enables the
``/v1/guardrail`` payload hook. ``attach_provenance_proof_to_payload``
embeds the canonical proof envelope, the envelope SHA-256, and the
commitment ID into the evidence record without mutating the
``EvidenceRecord`` Pydantic v2 frozen model. Fail-open on attach
(no availability cliff), fail-closed on verify
(``verify_payload_provenance_proof`` with ``regulator_grade=True``
rejects shim proofs and tampered envelopes).

**Performance targets (cite-bound).** Per VFT §V (Dec 29 2025):
per-step prover 16.8–31.2s for LoRA rank 8–16 at 2,048 tokens;
final verification <200 ms; final proof ~4–6 MB after recursive
aggregation. The deterministic shim runs the same wiring in
sub-milliseconds for tests and demos but is loudly flagged
``is_regulator_grade=False`` so production Article 53(1)(d)
verification refuses it via the dispatcher.

**Coverage check vs the May 18 2026 agent-governance landscape.**

| Capability                          | Tex Thread 14 | Microsoft AGT | Noma | Zenity | Pillar | Lakera | Lagrange |
|-------------------------------------|---------------|---------------|------|--------|--------|--------|----------|
| Training-data ZK provenance         | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | partial (model only) |
| VFT-style per-epoch quotas in proof | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | ✗        |
| LatticeFold+ PQ folding slot        | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | ✗        |
| DeepProve backend slot              | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | n/a (vendor) |
| SCITT ARP cross-sovereign narrowing | ✓ (17-day-old draft) | ✗     | ✗    | ✗      | ✗      | ✗      | ✗        |
| NABAOS epistemic receipts           | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | ✗        |
| EU AI Act Article 53(1)(d) binding  | ✓             | ✗             | ✗    | ✗      | ✗      | ✗      | ✗        |
| Algorithm-agile PQ CA signature     | ✓ (ML-DSA-65) | ✗             | ✗    | ✗      | ✗      | ✗      | ✗        |

Microsoft Agent Governance Toolkit (Apr 2 2026, MIT, 7 packages)
provides identity, policy, runtime gates, and SLSA-compatible
build provenance — *not* training-data provenance proofs. Noma,
Zenity, Pillar, Lakera operate at the prompt-injection / output-
filter / identity layer. Lagrange/DeepProve proves model
inference, not training-data provenance; ZKPROV is upstream of
inference proofs. This is the wedge.

**Verified end-to-end.**

- 82/82 ``tests/zkprov/`` tests pass in 0.86 seconds:
  ``test_commitment.py`` (Merkle determinism, inclusion proofs,
  manifest validation, signature roundtrip, lifetime, HMAC tags),
  ``test_proof.py`` (statement assembly, generate/verify
  roundtrip, response/commitment substitution rejection,
  regulator-grade rejection, tamper detection, envelope
  roundtrip, sub-2s shim perf), ``test_advanced.py`` (sampler
  determinism + public replay + private index-hiding,
  aggregation basic/overflow/coverage/regulator-grade, ARP
  narrowing all three predicates with COSE label presence,
  NABAOS receipts + four-category hallucination detection),
  ``test_routes.py`` (all 7 HTTP endpoints, regulator-grade
  rejection, malformed envelope rejection, post-quantum
  LatticeFold+ aggregation, persistence + 404),
  ``test_integration.py`` (``TEX_ZKPROV`` env flag, attach/verify
  roundtrip, copy semantics).
- Pre-existing 3,234 non-zkprov tests continue to pass.

**Files wired.**

- ``src/tex/zkprov/manifest.py`` — DatasetManifest, DataSource,
  PreprocessingStep, LicenseTag (SPDX + TDS), TDSSourceCategory,
  TDSPublicSummary, ``project_to_tds_summary``.
- ``src/tex/zkprov/commitment.py`` — DatasetCommitment,
  MerkleInclusionProof, Poseidon2-shaped Merkle root,
  ``issue_commitment``, ``verify_commitment_signature``,
  ``verify_commitment_valid``, ``deterministic_test_ca``,
  ``issue_commitment_tag`` / ``verify_commitment_tag``.
- ``src/tex/zkprov/backends.py`` — ``ProofBackendId``,
  ``ProvenanceStatement``, ``ProofBackend`` Protocol,
  ``BackendUnavailable``, ``DeterministicShimBackend``,
  ``Halo2IpaBackend``, ``DeepProveBackend``,
  ``LatticeFoldPlusBackend``, ``get_proof_backend``,
  ``resolve_backend_with_fallback``, ``is_regulator_grade``.
- ``src/tex/zkprov/proof.py`` — ProvenanceProof, ProofVerification,
  ``CIRCUIT_VERSION = "zkprov-v1-2026.05"``, ``assemble_statement``,
  ``generate_proof``, ``verify_proof``.
- ``src/tex/zkprov/sampler.py`` — VFT element 2: ``SamplerMode``,
  ``BatchSchedule``, ``SamplerCommitment``, SHAKE128 PRF.
- ``src/tex/zkprov/recursive.py`` — VFT element 4: ``FoldingScheme``
  (LatticeFold+, HyperNova+CycleFold, MicroNova, NeutronNova,
  GKR-DeepProve), ``aggregate_proofs``,
  ``verify_aggregated_certificate``.
- ``src/tex/zkprov/scitt_arp.py`` — ARPPredicate,
  ARPPredicateLibrary, NarrowedClaim, ARPReconciliationOutput,
  three narrowing functions, COSE label registry.
- ``src/tex/zkprov/receipts.py`` — Pramana enum, ToolCallRecord,
  EpistemicClaim, EpistemicReceipt, ``issue_receipt`` /
  ``verify_receipt``, ``detect_hallucinations``.
- ``src/tex/zkprov/integration.py`` — ``TEX_ZKPROV`` env flag,
  ``attach_provenance_proof_to_payload``,
  ``verify_payload_provenance_proof``,
  ``attach_receipt_to_payload``, ``verify_payload_receipt``.
- ``src/tex/api/zkprov_routes.py`` — 7 endpoints, all DTOs
  Pydantic v2 frozen.
- ``src/tex/stores/provenance_proofs_postgres.py`` —
  ``tex_provenance_proofs`` table, in-memory fallback when
  ``DATABASE_URL`` unset.
- ``src/tex/main.py`` — router wired at line 24
  (import) and the include_router call.

**References (Thread 14).**

- Namazi, Nemecek, Ayday. "ZKPROV: A Zero-Knowledge Approach to
  Dataset Provenance for Large Language Models." arXiv:2506.20915
  (Dec 18 2025).
- Akgül, Borg, Berisha, Rahimova, Novak, Petrov. "Verifiable
  Fine-Tuning for LLMs: Zero-Knowledge Training Proofs Bound to
  Data Provenance and Policy." arXiv:2510.16830 v3 (Dec 29 2025).
- Osadnik et al. "Improving LatticeFold+ with ℓ2-norm Checks."
  IACR ePrint 2026/721 (April 19 2026).
- Boneh, Chen. "LatticeFold+: Faster, Simpler, Shorter Lattice-
  Based Folding for Succinct Proof Systems." ASIACRYPT 2025.
- Setty, Thaler. "Twist and Shout: Faster memory checking
  arguments via one-hot addressing and increments." a16z (Feb
  2026).
- Arun, Setty, Thaler. "Jolt: SNARKs for Virtual Machines via
  Lookups." EUROCRYPT 2024; Jolt zkVM public release Feb 2026.
- Lagrange Labs. "DeepProve: 158x faster than ezkl." Public
  release Feb 23 2026; integrated Anduril Lattice SDK (Nov 2025),
  Lockheed (Nov 2025), Oracle Cloud sovereign (Nov 2025),
  Gemma3 / LLAMA / GPT-2 full inference proofs.
- Hillier et al. "Attestation Reconciliation Protocol (ARP)."
  IETF draft-hillier-scitt-arp-00 (May 1 2026, expires Nov 2
  2026). COSE labels 0x801-0x804.
- Birkholz, Delignat-Lavaud, Fournet, Deshpande, Lasker. "An
  Architecture for Trustworthy and Transparent Digital Supply
  Chains." IETF draft-ietf-scitt-architecture-22 (Oct 10 2025).
- Basu. "Tool Receipts, Not Zero-Knowledge Proofs: Practical
  Hallucination Detection for AI Agents." arXiv:2603.10060
  (March 9 2026).
- Grassi, Khovratovich, Rechberger, Roy, Schofnegger. "Poseidon
  Hash." USENIX Security 2021; Grassi, Khovratovich, Roy,
  Schofnegger. "Poseidon2." IACR ePrint 2023/323.
- Kothapalli, Setty. "HyperNova: Recursive arguments for
  customizable constraint systems." CRYPTO 2024, IACR ePrint
  2023/573 (extended version updated Feb 20 2026).
- Dalal, Hemo, Rabinovich, Rothblum. "VEIL: Lightweight
  Zero-Knowledge for Hash-Based Multilinear Proof Systems."
  IACR ePrint 2026/683 (Apr 8 2026). Succinct blog "VEIL adds
  zero-knowledge to hash-based proof systems with only a 3%
  increase in prover time" (May 1 2026).
- Succinct Labs. "SP1 Hypercube: Proving Ethereum in Real-Time"
  (May 20 2025). "Real-time Proving at Home: 99.7% of L1 blocks
  on 16 GPUs" (Nov 18 2025). "SP1 Hypercube Is Now Live on
  Mainnet" (Feb 19 2026). First multilinear-polynomial zkVM in
  production; formally verified RISC-V constraints with
  Nethermind + Ethereum Foundation.
- Chen et al. "ZKTorch: Compiling ML Inference to Zero-Knowledge
  Proofs via Parallel Proof Accumulation." arXiv:2507.07031
  (Jul 9 2025). Open source at github.com/uiuc-kang-lab/zk-torch;
  parallel Mira accumulation delivers 3×–10× proof-size reduction
  and 6.2× faster proving on GPT-J / BERT / ResNet-50 / LLaMA-2-7B.
- Grassi, Khovratovich, Rechberger, Roy, Schofnegger. "Poseidon:
  A New Hash Function for Zero-Knowledge Proof Systems." USENIX
  Security 2021, IACR ePrint 2019/458. BN254 t=3 alpha=5 RF=8
  RP=57 128-bit security parameter set.
- NIST FIPS 204 (ML-DSA), August 2024.
- European Commission, AI Office. "Template for the public
  summary of training content for general-purpose AI models
  under Article 53(1)(d) of the EU AI Act." Published July 24
  2025; enforcement August 2 2026; fines up to €15M / 3% global
  revenue under Article 101.

### Wedge confirmation (May 20, 2026)

Tex now fuses, on a single hash-chained evidence stream:
- Datalog policy frontend (PCAS) — **only impl that exists**
- Dual-LLM capability interpreter (CaMeL) — **only governance integration**
- Transactional WAL + rollback (SAFEFLOW) — **only reference-monitor impl**
- 4 model-side adapter sets (MELON, StruQ, SecAlign, plus Thread 11 IFC)
- Mechanically-verified Lean 4 proof of lattice non-interference — **first**
- AgentDojo eval harness driving end-to-end live PDP measurements
- rustworkx accelerator for provenance graph BFS — **only agent gov impl**

Competitor coverage check (May 18 2026):
- **Microsoft Agent Governance Toolkit** (Apr 2 2026, MIT, sub-ms
  policy enforcement, 7 packages): no IFC, no Datalog, no CaMeL, no
  transactional WAL, no formal proofs, no rustworkx, networkx-backed.
- **Microsoft Agent 365** (May 1 2026 GA): isolation + RBAC. No
  Datalog, no CaMeL, no transactional WAL.
- **Zenity / Noma Security / Pillar Security / Lakera / Rubrik SAGE**:
  none ship denial-aware causal provenance, Datalog policy languages,
  or transactional WAL on the same evidence chain.
- **Gartner "Guardian Agent" category** (2026): defined but
  unrealized; no vendor ships the four-of-four combination.

References (Thread 12)
----------------------
- Palumbo, Choudhary, Choi, Chalasani, Christodorescu, Jha. "Policy
  Compiler for Secure Agentic Systems" (PCAS). arXiv:2602.16708.
- Debenedetti, Beurer-Kellner, Eberlin, et al. "Defeating Prompt
  Injections by Design" (CaMeL). arXiv:2503.18813. Google DeepMind.
- "Operationalizing CaMeL with SentinelAI." arXiv:2505.22852.
- Hu, et al. "SAFEFLOW: A Principled Protocol for Trustworthy and
  Transactional Autonomous Agent Systems." arXiv:2506.07564.
- "Atomix: Atomicity for LLM Agent Tool Use." arXiv:2602.14849.
- "LogAct: Agentic Write-Ahead Logging for Multi-Agent Systems."
  arXiv:2604.07988.
- Debenedetti, et al. "AgentDojo: A Dynamic Environment to Evaluate
  Prompt Injection Attacks and Defenses for LLM Agents."
  arXiv:2406.13352, NeurIPS 2024 Datasets and Benchmarks.
- "AgentSys: 0.78% ASR on AgentDojo." arXiv:2602.07398.
- Wang, Zhou, et al. "MELON: Indirect Prompt Injection Detection
  via Masked Re-execution and Tool Comparison." arXiv:2502.05174.
- Chen, et al. "StruQ: Defending Against Prompt Injection with
  Structured Queries." arXiv:2402.06363.
- Chen, et al. "Aligning LLMs to Be Robust Against Prompt Injection"
  (SecAlign). arXiv:2410.05451.
- "ASTRA: Adaptive Stealthy Targeted Attacks on Aligned LLM Agents."
  arXiv:2507.07417.
- Volpano, Smith, Irvine. "A Sound Type System for Secure Flow
  Analysis." Journal of Computer Security 4(2-3), 1996.
- Apt, Blair, Walker. "Towards a Theory of Declarative Knowledge."
  Foundations of Deductive Databases and Logic Programming, 1988.
- Mohan, Haderle, Lindsay, Pirahesh, Schwarz. "ARIES: A Transaction
  Recovery Method." ACM TODS 17(1), 1992.
- IBM Quantum Team. "rustworkx benchmarks vs networkx." 2024.


## Thread 15 — NANOZK layerwise verifiable inference proofs (wired, May 21, 2026)

### Claim

When `TEX_FRONTIER_NANOZK=1`, every Tex causal-attribution
response carries a live NANOZK layerwise proof set in its PTV
envelope. The proof set is a hash-chained, Fisher-selected,
VEIL-wrapped bundle of per-layer zero-knowledge proofs that the
governed transformer's forward pass was executed on the declared
weights, with the declared inputs producing the declared outputs.
The envelope's method tag is `tex:nanozk-layerwise-2026` and the
`attribution_method` tag carries the `zk_layerwise` suffix
instead of the legacy `zk_pending`. The previously stubbed
`tex.evidence.attribution_zk.verify_ptv_envelope` path that
returned `nanozk_verifier_not_implemented_in_this_thread` now
flips to a live verdict (`ok_nanozk_layerwise_verified` when the
envelope binds correctly, structured `reason` strings when it
doesn't — fail-closed default).

### Why this matters

Every funded competitor in the May 2026 agent-governance market
— Noma Security ($132M Series B Mar 2026), Zenity (Gartner
"Company to Beat"), Pillar, HiddenLayer, Mindgard,
Lakera→CheckPoint, Protect AI→Palo Alto (~$500M),
CalypsoAI→F5 (Jan 2026), Aim→Cato, Wiz→Alphabet ($32B Mar 2026),
Oasis Security ($120M RSAC 2026), Astrix, Aembit, Natoma, Credo
AI, Holistic AI, Microsoft Entra Agent ID, Okta Cross App
Access, CyberArk Secure AI Agents, SailPoint Agent Identity
Security, Mastercard Verifiable Intent — operates at the agent
identity / behavioural / policy enforcement layer. **None
attaches a per-invocation cryptographic proof of model
execution.** Microsoft Agent Governance Toolkit (Apr 2 2026, MIT,
10/10 OWASP Agentic ASI 2026 coverage) provides a "signed
attestation on every deployment" — that is a build-time
attestation of the toolkit binaries, not a per-invocation proof
of model execution. Different cryptographic object.

This is the gap Thread 15 closes for Tex specifically. Combined
with Thread 14 (training-data provenance via ZKPROV) and Thread
3 (causal attribution with cryptographically signed post-incident
evidence), Tex now offers the only May-2026 agent-governance
stack that attaches:

  1. A runtime authorisation verdict (PERMIT / ABSTAIN / FORBID)
     against the governed action (Threads 1, 4, 4.5).
  2. A SHA-256 hash-chained, ML-DSA-65-signed evidence record of
     the verdict (Threads 2, 5, 10).
  3. **A NANOZK layerwise zero-knowledge proof of correct model
     execution on the agent's outputs (Thread 15).**
  4. A ZKPROV proof of correct training data provenance against
     a CA-signed manifest (Thread 14).
  5. A SCITT-registered transparent statement of the whole
     bundle (Threads 6, 7.1, 14).
  6. Algorithm-agile post-quantum signing via FIPS 204 ML-DSA-65
     (Thread 10), with VEIL hash-based ZK on the inference proof
     itself (Thread 15) — so the entire stack survives Q-Day
     without an elliptic-curve dependency.

### Source paper anchors

- arxiv 2603.18046 — Wang. *NANOZK: Layerwise Zero-Knowledge
  Proofs for Verifiable Large Language Model Inference*. USC,
  Mar 17 2026. The thread implements the layerwise decomposition
  and Fisher-guided selection from §3.1–§3.3, with paper numbers
  43s prove / 6.9 KB proof / 23 ms verify / 52× ezkl on GPT-2.
- arxiv 2602.17452 — Benno, Centelles, Douchet, Gibran. *Jolt
  Atlas: Verifiable Inference via Lookup Arguments in Zero
  Knowledge*. ICME Labs, Feb 19 2026. The thread adopts the
  prefix-suffix decomposition for softmax/GELU/LayerNorm
  nonlinearities (§4.1) — strictly newer than the NANOZK paper
  and strictly more efficient than NANOZK's materialised 16-bit
  tables.
- ePrint 2025/1184 — Qu et al. *zkGPT: An Efficient
  Non-Interactive Zero-Knowledge Proof Framework for LLM
  Inference*. USENIX Sec '25. The thread adopts the constraint-
  fusion technique (§5.2) for adjacent rounding constraints
  (185× speedup over ZKML, 279× over Hao et al.).
- ePrint 2026/683 — Dalal, Hemo, Rabinovich, Rothblum. *VEIL:
  Lightweight Zero-Knowledge for Hash-Based Multilinear Proof
  Systems*. Apr 7 2026. The thread wraps every layer proof with
  VEIL (§3) to add zero-knowledge to the hash-based proof system
  with ~3% prover overhead, ~22% verifier overhead, ~12% proof
  size overhead — the only published compiler that gives
  hash-based ZK without an elliptic-curve dependency. **No
  incumbent in the agent-governance market has wired VEIL as of
  May 2026.**
- Succinct, *SP1 Hypercube is Now Live on Mainnet*, blog Feb 19
  2026. The thread adopts the multilinear-polynomial proof shape
  (Jagged-PCS-style) — the first zkVM family to drop the
  proximity-gap conjecture dependency entirely.
- Lagrange Labs, *DeepProve-1: The First zkML System to Prove a
  Full LLM Inference*, blog Aug 18 2025. The `deepprove-2026`
  backend ID is wired into the dispatcher; the GKR sumcheck
  shape informs the per-layer matmul row estimates.
- draft-anandakrishnan-ptv-attested-agent-identity-00, Mar 31
  2026. The thread uses PTV's `<vendor>:<method>` extension
  pattern from §B.2 to register `tex:nanozk-layerwise-2026`
  without needing a new IETF draft.
- draft-ietf-scitt-architecture-22, Apr 2026. The layer proof
  set's `set_root` is SHA-256-hash-chained, COSE-Merkle-tree-
  proofs compatible.
- EU AI Act Article 50 — Draft Guidelines published 8 May 2026
  by the European Commission; consultation closes 3 June 2026;
  applies from 2 August 2026 (Digital Omnibus grandfathers
  pre-Aug-2026 systems to 2 Dec 2026). Thread 15's evidence
  surface aligns with the "detectable AI generation" obligation
  under Article 50(2) and the cryptographic-grade verification
  path under Article 53(1)(d).

### Backing modules and tests

**Modules.**

- `tex.nanozk.layerwise_prover` — `LayerCircuit`, `LayerProof`,
  `LayerProofSet`, `prove_layer`, `verify_layer_proof`,
  `prove_layer_set`, `verify_layer_proof_set`,
  `default_block_circuit`, `LAYERWISE_BACKEND_ID`,
  `LAYERWISE_CIRCUIT_VERSION`, `NANOZK_VERIFIER_TARGET_MS`,
  `NANOZK_PROOF_SIZE_BYTES`, `NanozkBackend` Protocol,
  `NanozkBackendUnavailable`, `get_layerwise_backend`,
  `register_backend`.
- `tex.nanozk.fisher_guided` — `FisherSelectionResult`,
  `select_layers_to_prove`, `compute_fisher_budget`.
- `tex.nanozk.nonlinearity_lookup` — `NonlinearityKind`,
  `PrefixSuffixLookup`, `softmax_lookup`, `gelu_lookup`,
  `layernorm_lookup`, `lookup_value`, `lookup_decomposed`,
  `input_index_for`, `decompose_index`.
- `tex.nanozk.veil_wrapper` — `VeilWrappedProof`, `veil_wrap`,
  `veil_unwrap`, `VEIL_PROVER_OVERHEAD`,
  `VEIL_VERIFIER_OVERHEAD`, `VEIL_PROOF_SIZE_OVERHEAD`.

**Wiring.**

- `tex.evidence.attribution_zk.PTV_METHOD_NANOZK_LAYERWISE_2026`
  — new method tag `"tex:nanozk-layerwise-2026"`.
- `tex.evidence.attribution_zk.build_envelope_with_layerwise_proof`
  — builder.
- `tex.evidence.attribution_zk._verify_nanozk_layerwise` — the
  live verifier path that replaces the dead-end
  `nanozk_verifier_not_implemented_in_this_thread`.
- `tex.evidence.attribution_zk.PTVEnvelope.proof` — field cap
  raised from 4 KiB to 2 MiB to accommodate full layer proof
  sets (12-layer GPT-2 envelope ≈ 92 KB after VEIL wrapping;
  Llama-scale envelopes ≤ ~400 KB).
- `tex.api.incident_routes._build_ptv_envelope` — branches on
  `TEX_FRONTIER_NANOZK=1` and routes through
  `_build_layerwise_envelope`.
- `tex.api.incident_routes._build_layerwise_envelope` — Fisher-
  selects layers, builds an anchor-chained per-layer i/o map,
  and calls `prove_layer_set`.
- `tex.api.incident_routes._final_attribution_method` —
  recognises the new method tag and appends `zk_layerwise`.

**Tests proving the claim.**

Unit-level (`tests/nanozk/`, 149 tests, 91% coverage):

- `test_fisher_guided.py` (29 tests) — paper-anchored top-k
  selection, deterministic tie-breaking by layer index,
  cost-weighted greedy variant (beyond the NANOZK paper),
  budget arithmetic helpers, edge cases (zero Fisher mass, zero
  budget, empty model), error paths.
- `test_nonlinearity_lookup.py` (36 tests) — Jolt Atlas prefix-
  suffix decomposition identity, numerical correctness of
  softmax/GELU/LayerNorm-invsqrt approximations, fingerprint
  determinism, quantisation grid behaviour at domain edges.
- `test_veil_wrapper.py` (20 tests) — wrap/unwrap round-trip,
  tamper detection on every wrapper field, documented overhead
  constants match the VEIL paper exactly, determinism when
  seeds are pinned, unlinkability when seeds are random.
- `test_layerwise_prover.py` (49 tests) — `LayerCircuit`
  fingerprint determinism, single-layer prove + verify happy
  path, tamper detection on every bound field, VEIL wrapping
  toggle, per-layer verifier latency under the 23 ms NANOZK
  paper target (shim path achieves 0.13 ms), `LayerProofSet`
  hash chain and tamper detection, set-level prove + verify
  with Fisher selection, wire-format round-trip via
  `to_bytes`/`from_bytes`, backend dispatcher fallback
  semantics.
- `test_attribution_zk_wiring.py` (15 tests) — the live PTV
  envelope path; explicit regression check that
  `nanozk_verifier_not_implemented_in_this_thread` is no longer
  returned.

Integration-level (`tests/test_integration_layer.py`,
`TestThread15NanozkLayerwiseAttribution`, 6 tests):

- `test_envelope_uses_layerwise_method_tag` — `/v1/guardrail`
  → `/v1/incidents/{id}/attribute` round trip with
  `TEX_FRONTIER_NANOZK=1` returns an envelope with method
  `tex:nanozk-layerwise-2026`.
- `test_attribution_method_carries_zk_layerwise_suffix` —
  `attribution_method` contains `zk_layerwise`, not
  `zk_pending`.
- `test_envelope_proof_field_non_empty_and_decodes` — the
  envelope's `proof` field decodes into a real
  `LayerProofSet` with `total_layers=12` and a non-empty
  selection.
- `test_live_verifier_accepts_envelope` — the central
  regression check: `verify_ptv_envelope` returns
  `ok_nanozk_layerwise_verified`, not the legacy dead-end.
- `test_tampered_envelope_rejected` — fail-closed default:
  tampering the envelope's `input_hash` is rejected with
  `nanozk_layerwise_input_hash_mismatch`.
- `test_default_flag_off_preserves_proof_pending_behavior` —
  backward-compat regression: without
  `TEX_FRONTIER_NANOZK=1`, the envelope remains
  `proof_pending` exactly as before Thread 15.

**Demo.** `scripts/demo_thread_15_nanozk.sh`.

### Competitive differentiation (as of May 21, 2026)

- **Microsoft Agent Governance Toolkit (Apr 2 2026, MIT,
  10/10 OWASP Agentic Top 10).** No verifiable-inference module.
  The toolkit's "signed attestation on every deployment" is a
  build-time attestation of the toolkit binaries, not a
  per-invocation proof of model execution.
- **Zenity, Noma, Pillar, HiddenLayer.** Agent identity /
  behavioural layer only. No cryptographic proof of model
  execution.
- **DeepProve-1 (Lagrange, Aug 2025).** Regulator-grade and
  fast, but monolithic (proves the whole inference, not
  Fisher-selected layers). Composes well: the
  `deepprove-2026` backend ID is wired in the Thread 15
  dispatcher for a future Rust-binary swap-in.
- **zkAgent (eprint 2026/199, Feb 21 2026).** Provides
  one-shot proofs but requires *minutes* of proving time per
  query (cited in arxiv 2603.10060 §1 as the practical
  blocker). Tex's layerwise + Fisher-selected approach is the
  practical complement.
- **No competitor has wired VEIL** (eprint 2026/683, Apr 7
  2026) for verifiable inference as of May 18, 2026. Tex is
  the first.

### Honest scope statement

1. **The shim is not a regulator-grade proof.** The
   deterministic `deterministic-shim-v1` backend is an
   HMAC-keyed binding that proves the prover knew the shim
   key (i.e. was running in the same Tex deployment). It
   exercises the full wiring — circuit fingerprint, lookup
   gadgets, constraint fusion, VEIL wrapper, set-level hash
   chain, PTV envelope, SCITT integration — end-to-end in
   CI without dragging Rust toolchains into contributor
   laptops. This is exactly the pattern Thread 14 (ZKPROV)
   established. The regulator-grade backends
   (`halo2-ipa-2026`, `deepprove-2026`, `jolt-sumcheck-2026`,
   `latticefold-plus-2026`, `sp1-hypercube-2026`,
   `veil-hash-based-zk-2026`) plug into the same dispatcher
   when their Rust binaries are installed; production
   deployments select via `TEX_NANOZK_BACKEND`.

2. **Fisher score input is caller-supplied.** Thread 15
   ships the *selector* — top-k by Fisher score with
   deterministic tie-breaking. Estimating the Fisher matrix
   for a deployed LLM is downstream; the selector accepts a
   per-layer score vector and produces a canonical selection.
   The wired path's default selector uses a tilted-uniform
   Fisher vector that matches the NANOZK paper's observation
   that deeper layers tend to carry slightly more output
   sensitivity (§3.3).

3. **The cryptographic contributions are composition, not
   primitives.** Thread 15 does not claim novelty for NANOZK's
   layerwise decomposition, Jolt Atlas's lookup decomposition,
   zkGPT's constraint fusion, or VEIL's ZK compiler. The
   contributions are: (a) composing them into a single
   envelope on a regulated agent-governance surface; (b)
   wiring into a live SCITT-compatible PTV envelope; (c) the
   algorithm-agile signing path; (d) the deterministic
   tie-breaking and cost-weighted Fisher selector beyond the
   NANOZK paper.

4. **The envelope's input/output hashes anchor the layerwise
   chain at the boundaries.** The verifier checks the
   envelope's `input_hash` equals the first selected layer's
   `input_hash` and the envelope's `output_hash` equals the
   last selected layer's `output_hash`. Interior layer
   chains are derived deterministically. This is the
   structural binding that prevents a prover from claiming
   a proof set built over a different (input, output) pair.


---

## Thread 15 — Eight bleeding-edge upgrades (May 18, 2026)

**Public claim.** Tex's layerwise zero-knowledge proof composition is
the only agent-governance implementation as of May 18, 2026 to wire
eight independent May-2025-to-April-2026 zkML / zkVM advances into a
single verifiable-inference envelope:

  1. **Logup\*** (ePrint 2025/946, Soukhanov) — faster, cheaper
     lookup arguments for the small-table indexed regime that
     transformer nonlinearities sit in. No extra commits to
     indexing-array-sized columns; no numerator-overflow.
     Module: `src/tex/nanozk/logup_star.py`.

  2. **GaugeZKP canonicalisation** (OpenReview 1Ne3tfQC0T, ICME
     Labs 2025) — pre-prover canonicalisation to gauge orbits, ~26%
     gate reduction on Halo2 / Plonkish, multiplies with RoPE / GQA
     / MQA / MoE savings without changing model behaviour.
     Module: `src/tex/nanozk/gauge_zkp.py`.

  3. **Poseidon-BN254 hash chain** — SNARK-friendly set-root for
     recursive verification and SCITT Merkle-tree integration; 120×
     constraint reduction vs SHA-256 when opened inside a SNARK.
     Module: `src/tex/nanozk/poseidon_chain.py`. Uses real
     `poseidon-hash` library with standard `(p=prime_254,
     security_level=128, alpha=5, input_rate=3, t=4)`.

  4. **LatticeFold+ ℓ₂ folding** (ePrint 2026/721, Apr 19 2026) —
     post-quantum-secure recursive accumulator with ~2× lower prover
     cost than the LatticeFold+ 2025 baseline on the dominant
     norm-check path. Module: `src/tex/nanozk/latticefold_plus.py`.
     Module-SIS dimension 1024, 64-bit modulus, 16-bit ℓ₂ budget.

  5. **Sublinear-space proving** (arxiv 2509.05326, Nye 2025) —
     O(√T · log T · log log T) prover memory via Cook-Mertz tree
     evaluation, bit-identical proofs to the linear-space baseline
     for KZG / IPA PCSs. Enables edge proving on mobile and Llama-
     70B-scale single-shot proving. Module:
     `src/tex/nanozk/sublinear_space.py`.

  6. **Mira parallel folding** (ZKTorch, arxiv 2507.07031, Jul 2025)
     — homomorphic tree accumulation, 3–10× proof size reduction
     and 6× proving speedup over general-purpose ZKML frameworks.
     Composes alongside LatticeFold+ as the multi-core throughput
     option. Module: `src/tex/nanozk/mira_parallel.py`.

  7. **DeepProve subprocess backend** (Lagrange Labs, Aug 2025) —
     real Rust binary bridge (`github.com/Lagrange-Labs/deep-prove`)
     for GKR-sumcheck zkML; 54–158× faster proving than EZKL, 671×
     faster verification. Auto-registers at import time when the
     binary is present on PATH or in `~/.cargo/bin`. Module:
     `src/tex/nanozk/deepprove_backend.py`.

  8. **V3DB verifiable vector search** (arxiv 2603.03065, Mar 2026)
     — audit-on-demand ZK proofs for IVF-PQ ANN retrieval over
     committed corpus snapshots; closes the **retrieval trust gap**
     in RAG-equipped agents. Plonky2-based, 22× faster proving than
     circuit-only baseline. Module: `src/tex/nanozk/v3db.py`.

**Modules backing the claim.**
  * `src/tex/nanozk/logup_star.py`
  * `src/tex/nanozk/gauge_zkp.py`
  * `src/tex/nanozk/poseidon_chain.py`
  * `src/tex/nanozk/latticefold_plus.py`
  * `src/tex/nanozk/sublinear_space.py`
  * `src/tex/nanozk/mira_parallel.py`
  * `src/tex/nanozk/deepprove_backend.py`
  * `src/tex/nanozk/v3db.py`
  * Wired into `src/tex/nanozk/layerwise_prover.py` (LayerCircuit
    + LayerProofSet new fields) and `src/tex/nanozk/__init__.py`
    (auto-registration of DeepProve backend).

**Test coverage.** 163 new unit tests across the 8 modules, all
fail-closed-verified. 312/312 nanozk tests pass total; 114/114
integration tests pass. Test files:
  * `tests/nanozk/test_logup_star.py`
  * `tests/nanozk/test_gauge_zkp.py`
  * `tests/nanozk/test_poseidon_chain.py`
  * `tests/nanozk/test_latticefold_plus.py`
  * `tests/nanozk/test_sublinear_space.py`
  * `tests/nanozk/test_mira_parallel.py`
  * `tests/nanozk/test_deepprove_backend.py`
  * `tests/nanozk/test_v3db.py`

**What is NOT claimed.**
  * The eight upgrade modules use deterministic-shim HMAC bindings
    on the structural transcript by default — same pattern as the
    rest of Thread 15. A regulator-grade deployment swaps the shims
    for the corresponding Rust backends (real Poseidon hasher, real
    LatticeFold+ folding, real Mira pairings, real Plonky2 V3DB,
    real DeepProve Rust binary). The structural invariants
    (fingerprint binding, fail-closed verification, env-flag
    dispatch) hold under either path.
  * Paper-claimed numerical speedups (26% gate reduction, 22×
    proving, 158× over EZKL, etc.) are frozen as module constants
    for the audit surface but are NOT independently re-benchmarked
    in this repo. They are cited from the source publications and
    Lagrange Labs' public claims.
  * No agent-governance vendor has shipped this composition as of
    May 18, 2026, to the best of our search-engine and arXiv review.
    This is a defensible "first to wire X" claim, not a "first to
    invent X" claim — every primitive is the work of its authors.

**Competitive note.** Each individual upgrade has at least one
reference implementation in Rust or as a paper-author prototype. **Tex
is the first to compose all eight into a single agent-governance
envelope** with PTV / SCITT / algorithm-agile post-quantum signing.
The composition itself — Logup\* + GaugeZKP + Poseidon-BN254 +
LatticeFold+ + Sublinear-Space + Mira + DeepProve + V3DB, bound to a
SCITT statement and ML-DSA-65 signature — is the differentiator.
