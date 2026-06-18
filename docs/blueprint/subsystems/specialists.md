# Subsystem Dossier: `specialists` (Specialist evaluators / AgentEvaluationSuite layer)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/specialists/` (26 `.py` files, ~10,504 LOC).
> Branch: `feat/proof-carrying-gate`. All claims below are traced to code; docstring/`.md` claims are labelled `(claim, unverified)` unless confirmed in code.
> Verification command for imports: `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src python ...`

---

## Overview

The `specialists` package is **Layer 4 (Execution Governance)** of Tex's six-layer PDP pipeline (`src/tex/specialists/__init__.py:9` sets `__layer__ = 4`, `__layer_kind__ = 'execution_governance'`). It is a fleet of **narrow risk detectors** ("judges"). Each judge produces an advisory `SpecialistResult` (a risk_score ∈ [0,1] + confidence + structured evidence). A `SpecialistSuite` runs all configured judges and returns one `SpecialistBundle`. Specialists never own the final verdict — they feed:

1. The **router's weighted-sum fusion** via `SpecialistBundle.max_risk_score`, augmented by a cross-specialist corroboration layer (`fusion.py::fuse`, wired live at `engine/router.py:214`).
2. A **structural FORBID floor** (`structural_floor.py::detect_structural_floor`, wired live at `engine/pdp.py:340`) that lets the four *deterministic-proof* specialists (PCAS / CaMeL / IFC / ARGUS) short-circuit to FORBID instead of being diluted in the weighted sum.

**Default suite size: 20 judges** (verified at runtime — see [Internal Architecture](#internal-architecture)). Note this contradicts the `__init__.py` docstring "17 specialist judges" `(claim, unverified — actual = 20)` and the `judges.py` docstring comments.

The judges split into three behavioral classes:

| Class | Judges | Behavior |
|---|---|---|
| **Lexical voting** (inline) | `secret_and_pii`, `external_sharing`, `unauthorized_commitment`, `destructive_or_bypass` | keyword + retrieved-entity matching → small additive risk |
| **Lexical/heuristic voting** (frontier) | `owasp_skills_top10`, `mcp_injection`, `clawguard`, `mcpshield`, `planguard`, `mage`, `agentarmor`, `argus`, `attriguard`, `vigil`, `melon`, `struq`, `secalign` | lexical scan ± optional dispatch to a wrapped runtime module / LLM / structural primitive |
| **Deterministic proof** (structural-floor eligible) | `pcas`, `camel`, `ifc`, `argus` | delegate to a real reference monitor / interpreter / IFC engine / influence-provenance graph; a deny signature short-circuits to FORBID |

Several files are **infrastructure**, not judges: `base.py` (contracts), `judges.py` (suite + inline judges + helpers), `llm_dispatch.py` / `llm_bridge.py` / `conformal_escalation.py` (LLM escalation plumbing), `fusion.py` (cross-specialist corroboration), `human_review.py` (Five-Eyes escalation), `structural_floor.py` (FORBID floor), `metaguard.py` (reflexive self-governance signatures — wired into `selfgov`, **not** the PDP suite).

---

## File Inventory

| File | LOC | Role | In default suite? |
|---|---:|---|---|
| `__init__.py` | 11 | Layer marker only (`__layer__=4`). No re-exports. | n/a |
| `base.py` | 246 | Pydantic contracts: `SpecialistEvidence`, `SpecialistResult`, `SpecialistBundle`, `SpecialistJudge` Protocol. | n/a |
| `judges.py` | 699 | `SpecialistSuite`, `default_specialist_judges()`, `build_default_specialist_suite()`, 4 inline lexical judges, keyword/entity/clause-overlap helpers, stopword set. | hosts 4 |
| `agentarmor_specialist.py` | 483 | `AgentArmorSpecialist` — IFC lexical signals + ARGUS provenance codes + optional PDG `TypeSystem.check`. | ✅ `agentarmor` |
| `argus_specialist.py` | 727 | `ArgusSpecialist` — builds a real influence-provenance graph (IPG) + counterfactual test. | ✅ `argus` |
| `attriguard_specialist.py` | 542 | `AttriGuardSpecialist` — per-observation causal attribution via control-attenuation scoring. | ✅ `attriguard` |
| `vigil_specialist.py` | 517 | `VigilSpecialist` — verify-before-commit (intent divergence + tool-stream poison). | ✅ `vigil` |
| `clawguard_specialist.py` | 477 | `ClawGuardSpecialist` — IPI lexical scan + optional `ToolCallBoundaryEnforcer` DENY short-circuit. | ✅ `clawguard` |
| `mcpshield_specialist.py` | 578 | `McpShieldSpecialist` — MCP property lexical scan + optional LTS `verify_property` short-circuit. | ✅ `mcpshield` |
| `planguard_specialist.py` | 583 | `PlanGuardSpecialist` — InjecAgent Type I/II lexical + `IntentVerifier` + LLM Stage II. | ✅ `planguard` |
| `mage_specialist.py` | 682 | `MageSpecialist` — long-horizon attack lexical + shadow-memory cross-turn + LLM J_θ. | ✅ `mage` |
| `ifc_specialist.py` | 372 | `IfcSpecialist` — delegates to `IfcEngine`; stashes IFC labels in a process LRU cache. | ✅ `ifc` |
| `pcas_specialist.py` | 263 | `PcasSpecialist` — projects request → `PcasMonitor.authorize` (Datalog). | ✅ `pcas` |
| `camel_specialist.py` | 169 | `CamelSpecialist` — runs a CaMeL `Plan` through `CamelInterpreter` when supplied. | ✅ `camel` |
| `melon_specialist.py` | 227 | `MelonSpecialist` + `HeuristicMelonBackend` — masked-eval approximation. | ✅ `melon` |
| `struq_specialist.py` | 183 | `StruQSpecialist` + `StructuralStruQBackend` — data-envelope pattern verifier. | ✅ `struq` |
| `secalign_specialist.py` | 248 | `SecAlignSpecialist` + `DPODistilledHeuristic` — instruction/data-conflict scorer. | ✅ `secalign` |
| `mcp_injection_specialist.py` | 530 | `McpInjectionSpecialist` — SSRF/CVE/RCE/cred-theft/tool-poisoning lexical+regex scan. | ✅ `mcp_injection` |
| `owasp_skills_top10_specialist.py` | 640 | `OwaspSkillsTop10Specialist` — AST01–10 lexical + Lethal-Trifecta override. | ✅ `owasp_skills_top10` |
| `structural_floor.py` | 368 | `detect_structural_floor()` — recognises deterministic deny signatures → FORBID floor. | infra (live) |
| `fusion.py` | 207 | `fuse()`, `FusionVerdict`, `fusion_reason_codes()` — cross-specialist corroboration. | infra (`fuse` live; `fusion_reason_codes` orphan) |
| `human_review.py` | 227 | `HumanReviewEscalation.from_bundle()`, `build_specialist_human_review_flag()` — Five-Eyes escalation. | infra (flag-builder live; `from_bundle` orphan) |
| `llm_dispatch.py` | 538 | `SpecialistLLMDispatcher`, providers, `DispatchRequest/Result` — async LLM dispatch (off by default). | infra |
| `llm_bridge.py` | 423 | Sync↔async bridge + conformal-gated PlanGuard/MAGE judge builders. | infra |
| `conformal_escalation.py` | 193 | `ConformalEscalationGate`, split-CP quantile — calibrated LLM-escalation gate. | infra |
| `metaguard.py` | 371 | `evaluate_metaguard()` — deterministic deny/caution signatures over **controller mutations** (not content). | infra (wired into `selfgov`, NOT the PDP suite) |

---

## Internal Architecture

### Contracts (`base.py`)

- **`SpecialistEvidence`** (`base.py:11`): frozen Pydantic model — `text` (1–2000 chars), optional `start_index`/`end_index` (must come as a pair, `end > start`, `base.py:38-46`), optional `explanation`.
- **`SpecialistResult`** (`base.py:49`): frozen — `specialist_name`, `risk_score ∈ [0,1]`, `confidence ∈ [0,1]`, `summary`, optional `rationale`, tuples of `evidence`, `matched_policy_clause_ids`, `matched_entity_names`, `uncertainty_flags`. Sequence validators dedupe case-insensitively (`base.py:102-125`). Helper props: `has_evidence`, `should_escalate` (= `risk ≥ 0.5 or confidence < 0.5`, `base.py:131-133`).
- **`SpecialistBundle`** (`base.py:136`): frozen — tuple of results with a **uniqueness validator on `specialist_name`** (`base.py:158-163` — duplicate names raise). Reducer properties the router/PDP consume: `max_risk_score` (`:170`), `min_confidence` (`:174`), deduped `matched_policy_clause_ids` (`:178`), `matched_entity_names` (`:193`), `uncertainty_flags` (`:208`).
- **`SpecialistJudge`** (`base.py:227`): `@runtime_checkable` Protocol — every judge has `name: str` and `evaluate(*, request, retrieval_context) -> SpecialistResult`.

### Suite orchestration (`judges.py`)

- **`SpecialistSuite`** (`judges.py:317`): holds a tuple of judges; `evaluate()` (`:328`) runs each judge in declaration order and wraps results in a `SpecialistBundle`. Pure sequential fan-out — no async, no parallelism at this layer.
- **`default_specialist_judges()`** (`judges.py:344`): returns the 20-judge tuple in a deliberately ordered sequence — deterministic-DENY class (`clawguard`, `mcpshield`) before voting class, then IFC/Thread-12 frontier modules last (`judges.py:356-405`).
- **Inline lexical judges** (all in `judges.py`):
  - `SecretAndPiiSpecialist` (`:30`) — 16 disclosure keywords (`ssn`, `password`, `api key`, …) + retrieved-entity matching (`_match_entities`). Risk = `0.08 + 0.18·keyword_hits + 0.10·entity_hits` (`:80`).
  - `ExternalSharingSpecialist` (`:108`) — 12 export/forward keywords + policy-clause overlap.
  - `UnauthorizedCommitmentSpecialist` (`:175`) — 13 commitment phrases + channel bonus (+0.08 for email-class channels, `:216`).
  - `DestructiveOrBypassSpecialist` (`:246`) — 14 destructive/bypass keywords + production-environment bonus (+0.10, `:287`).
- **Shared helpers**: `_match_keywords` (`:413`, substring find-all with span dedupe), `_match_entities` (`:453`), `_clause_ids_with_overlap` (`:522`), `_policy_clause_tokens` (`:548`, ≥6-char tokens), and a **65-entry stopword set** `_CLAUSE_TOKEN_STOPWORDS` (`:580`) that prevents generic policy boilerplate ("review", "approval", "require") from matching. (This stopword set is also imported by `semantic/fallback.py:591` — a cross-subsystem reuse.)

### Frontier voting specialists — common shape

`clawguard`, `mcpshield`, `planguard`, `mage`, `agentarmor`, `mcp_injection` all share a near-identical lexical engine: per-category pattern tuples → `_match_pattern_set` (substring find-all) → additive `risk_accum` with per-category severity weights → `risk = min(1.0, risk_accum)`, `confidence = min(cap, floor + per_hit·|evidence|)`. Each emits an observability event (`emit_event("specialist.<name>.evaluated", …)`). Reason codes + OWASP-ASI tags are packed into `matched_policy_clause_ids`. They differ in their **optional second path** (the "expensive-hit"):

- **ClawGuard** (`clawguard_specialist.py:174`): 5 IPI pattern sets (instruction injection, tool hijack, observation-trust, skill-file injection, ARGUS-provenance). Second path: when `metadata['tool_call']`/`['proposed_tool_call']` is present, dispatches to `ToolCallBoundaryEnforcer.check_call` (`:276`); a DENY **short-circuits risk to 1.0** (`_SEV_BOUNDARY_DENY = 1.00`, `:302`). Default enforcer denies AWS IMDS `169.254.169.254` and `rm -rf /` / `curl|bash` (`:378-394`).
- **MCPShield** (`mcpshield_specialist.py:280`): 4 property classes (P1–P4: tool integrity, data confinement, privilege boundedness, context isolation) + 8 MCP-protocol attack categories. Second path: when `metadata['mcpshield']['lts_model']` is an `LtsModel`, runs `verify_property` for each property; a verification failure **short-circuits to 1.0** with the counterexample path embedded (`:390`). Verifier exceptions fail-closed (`:514-517`).
- **PlanGuard** (`planguard_specialist.py:159`): InjecAgent Type I/II lexical + reasoning-hijack + fake-preapproval. Second path A: `metadata['planguard']` carries a `ReferencePlan` → `IntentVerifier.verify_action` (`:516`); a block adds `+0.55`. Second path B (Stage II LLM): only fires when ≥1 lexical reason code AND `dispatcher.enabled` (`:299-301`); a `malicious` verdict adds `+0.60`, a fail-closed dispatch adds `+0.18`. Constructor lazily builds `IntentVerifier` with the conformal-gated LLM judge from `llm_bridge` only when `TEX_SPECIALIST_LLM_MODE ∈ {tiered, dual_tiered}` (`:199-208`).
- **MAGE** (`mage_specialist.py:184`): 5 long-horizon families (MINJA memory-poisoning, STAC tool-chain, PI2 persistence, GoalDrift, observation-authority). Second path A: `metadata['mage']['shadow_memory']`/`['entries']` cross-turn STAC consult — fires only when a prior-turn entry scored ≥0.6 AND has ≥2-token overlap with the current action (`mage_specialist.py:600-604`); each match adds `+0.45`. Second path B (J_θ LLM): same cheap-miss/expensive-hit gate; `reject` adds `+0.65`.
- **AgentArmor** (`agentarmor_specialist.py:167`): lexical IFC signals (untrusted→exec, secret→network, integrity downgrade) + 3 ARGUS provenance codes. Second path: `metadata['agentarmor']['annotated_pdg']` → `TypeSystem.check` (`:369`); each `TypeViolation` adds `+0.55`. Exceptions swallowed → `[]` (`:370-371`).
- **MCP-Injection** (`mcp_injection_specialist.py:245`): a **boundary-checked IPv4 regex** `_IP_OCTET_BOUNDARY` (`:62`, avoids `v10.5`/`2.10.0` false positives) covering RFC-1918 + loopback + AWS IMDS, plus non-IPv4 SSRF targets (GCP metadata, ECS task metadata `169.254.170.2`, IPv6 link-local), 4 CVE fingerprints (CVE-2025-49596 MCP Inspector RCE, CVE-2026-22252 LibreChat, CVE-2025-54136 Cursor, CVE-2026-22688 WeKnora), the 3 arxiv-2504.03767 categories (RCE / remote access / credential theft), and tool-poisoning markers.

### Substantive structural specialists

- **ARGUS** (`argus_specialist.py`): the one frontier judge that ships a **real graph algorithm**, not just lexical patterns. `InfluenceProvenanceGraph` (`:96`) with `IPGNode`/`IPGEdge` dataclasses, BFS `justification_path` (`:118`), `observation_ancestors` (`:140`), `has_contradiction` (`:163`). `_build_lightweight_ipg` (`:487`) splits content into sentences, classifies each as user/obs/decision/evidence node using `_INSTRUCTION_LIKE_RE`/`_EXTERNAL_SOURCE_RE`/`_REASONING_HIJACK_RE`/`_DECISION_MARKERS`, wires `derives_from`/`justified_by` edges. `_build_counterfactual` (`:662`) strips `justified_by` edges touching untrusted obs nodes. Per decision node it emits `ARGUS_DECISION_OBSERVATION_DRIVEN` (justified before, dies in counterfactual, `+0.45`), `ARGUS_DECISION_NO_JUSTIFICATION` (`+0.40`), `ARGUS_DECISION_CONTRADICTED` (`+0.30`), `ARGUS_HIGH_RISK_ANCESTRY` (`+0.30`). If `metadata['argus']['ipg']` is a constructed graph, it's used directly (`:478-485`). Node cap = 64.
- **AttriGuard** (`attriguard_specialist.py`): per-observation **causal attribution**. `_attribute` (`:425`) scores each observation sentence: token overlap with the action + authority-lift (`+0.30`) + action-inheritance (`+0.25`) + external-source (`+0.15`). Score ≥ 0.35 = causal driver. `_action_signature` deliberately uses **decision sentences only** (not whole content) to avoid benign self-attribution (`:388-400`). ≥2 independent drivers raises a `REQUIRES_HUMAN_REVIEW` flag via `build_specialist_human_review_flag` (`:324-334`). Emits `AttributionScore` (a public Pydantic audit type, `:189`).
- **VIGIL** (`vigil_specialist.py`): **verify-before-commit** on the outbound tool stream. `_verify` (`:343`) computes intent divergence (token disjointness between proposed tool and `metadata['vigil']['user_intent']`), poison score (count of `_POISON_MARKERS`, 0.25 each), cross-obs contamination (≥50% sentence-pair token overlap), cascade chaining (strong markers fire alone; weak markers need a co-signal, `:447-461`), metadata-claim mismatch. Intent divergence only fires when there's *independent* poison evidence (`:201-206`) — a deliberate false-positive guard. A `deny` decision raises a human-review flag (`:304-315`). `VigilVerification` is a public Pydantic audit type (`:154`).
- **IFC** (`ifc_specialist.py`): a **thin wrapper** that delegates to `tex.governance.private_data_exec.ifc.IfcEngine.evaluate` (`:188`). The real flow algebra (provenance graph, FIDES dual-lattice, NeuroTaint cross-session, CA-CI norms, Rule-of-Two) lives in `governance/private_data_exec/ifc/engine.py` (confirmed real implementation — `engine.py:163-202` builds a `ProvenanceGraph`, materializes source nodes, runs NeuroTaint memory lookup). Maps 6 `IfcViolation` codes to ASI tags (`:128-141`). Side-effect: stashes serialized labels in a process-wide **bounded LRU cache** `_IfcLabelsCache` (`:68`, capacity 1024) keyed by request_id, consumed by the PDP's `_build_decision_metadata` and exposed via `get_ifc_labels_cache()` (imported by `engine/pdp.py:71`).
- **PCAS** (`pcas_specialist.py`): projects the request into a `CandidateAction` + a `DependencyGraphView` (preferring `metadata['ifc_provenance']` if present, `:189-204`) and calls `PcasMonitor.authorize` (`:151`). FORBID→risk 1.0, ABSTAIN→0.5, PERMIT→0.0 (`:208-227`). Ships a default Datalog toxic-flow policy inline (`_DEFAULT_POLICY`, `:58-104`) resolvable from `TEX_PCAS_POLICY_PATH`. Confidence = 1.0 unless the policy compiler reported a diagnostic (then 0.5, fail-closed).
- **CaMeL** (`camel_specialist.py`): runs `metadata['camel_plan']` (a `Plan`) through `CamelInterpreter` with a frozen `ToolPolicyRegistry` and a `StubQuarantinedLLM` default. `trace.halted`→risk 1.0, untrusted-tainted final→0.5, clean→0.0 (`:121-141`). Interpreter errors fail-closed to risk 1.0 (`:108-117`). **Abstains (risk 0.0, conf 0.0) when no plan is supplied** (`:88-97`) — the common case.

### Model-side adapter specialists (Thread 12)

`melon`, `struq`, `secalign` are **interface adapters** with a `Protocol` backend and a heuristic fallback that explicitly self-labels as *not the real defense*:
- **MELON** (`melon_specialist.py`): `MelonBackend` Protocol + `HeuristicMelonBackend` (token-Jaccard between user prompt and env content + arg-leakage on a high-risk-tool set). Reads `metadata['user_prompt'|'environment_content'|'candidate_tool'|'candidate_args']`. Abstains if no `candidate_tool`. Heuristic confidence fixed at 0.5.
- **StruQ** (`struq_specialist.py`): `StruQBackend` Protocol + `StructuralStruQBackend` (17 injection-pattern + envelope-escape signature match over aggregated untrusted content). Abstains if no data. Confidence 0.7.
- **SecAlign** (`secalign_specialist.py`): `SecAlignBackend` Protocol + `DPODistilledHeuristic` (imperative-density + instruction/data-conflict + action-in-prompt). Abstains if no untrusted content. Confidence fixed at 0.5; raises `heuristic_backend` flag when conf < 0.7.

### OWASP Skills Top 10 (`owasp_skills_top10_specialist.py`)

Pure lexical: AST01–AST10 pattern tables (`_AST_TABLE`, `:239-247`) with Critical/High/Medium weights (0.45/0.30/0.18). **Lethal-Trifecta override** (`:388-418`): if all three legs (private-data + untrusted-content + network-egress) match, returns `risk=0.92, conf=0.92, reason=LETHAL_TRIFECTA`, overriding AST aggregation and the floor.

### LLM escalation plumbing (infrastructure)

- **`llm_dispatch.py`**: `SpecialistLLMDispatcher` (`:270`) — async, budget-enveloped (default 50ms), semaphore-bounded (default 8, per-event-loop), JSON-mode, temperature=0, fail-closed on timeout/error/parse/schema. **Off by default** — `DEFAULT_DISPATCH_ENABLED = _env_bool("TEX_SPECIALIST_LLM_DISPATCH", False)` (`:91`). Providers: `StaticVerdictCompletion` (test), `_LazyOpenAICompletion` (lazy `from openai import AsyncOpenAI`, `:225`). Module singleton `get_default_dispatcher()` (`:517`).
- **`conformal_escalation.py`**: `ConformalEscalationGate` (`:112`) — split-CP quantile `conformal_quantile` (`:95`, `ceil((n+1)(1-α))/n` finite-sample correction) decides when the lexical layer's calibrated **upper bound** crosses the decision threshold (0.5). Ships engineered default half-widths (α=0.10→0.18, α=0.05→0.27) when no calibration set is supplied (`:136-149`).
- **`llm_bridge.py`**: `specialist_llm_mode()` (`:67`, reads `TEX_SPECIALIST_LLM_MODE`, default `disabled`) + `build_planguard_stage_ii_judge` (`:143`) / `build_mage_judge_callable` (`:297`). Each gates dispatch through a `ConformalEscalationGate`, runs the async dispatcher sync via `_run_sync` (`:82`, handles both event-loop and non-loop contexts), and fail-closes to the lexical verdict on any miss. Returns `None` when mode is `disabled`.

### `fusion.py`, `human_review.py`, `structural_floor.py`, `metaguard.py`

- **`fusion.py::fuse`** (`:125`): `fused_risk = max_risk_score + corroboration_bonus`. A specialist "fires" when `risk ≥ 0.10` AND it has `matched_policy_clause_ids` (`:137`). Base bonus by firing count (2→+0.05, 3→+0.10, 4→+0.15, 5→+0.18). Frontier specialists (`{argus, attriguard, vigil, agentarmor, mage}`) get a 1.5× multiplier + a solo-frontier +0.08; 5 named pair bonuses (e.g. MAGE×AgentArmor +0.08). Bonus capped at 0.20; never decreases base risk. ASI08 cascade signal when ≥3 firing incl. a frontier one. **Monotone-increasing only** — by construction it cannot relax a verdict.
- **`human_review.py::HumanReviewEscalation.from_bundle`** (`:110`): Five-Eyes escalation policy (explicit flag / high-risk+structural / ≥3 cascade / ASI08). `build_specialist_human_review_flag` (`:185`) builds the `REQUIRES_HUMAN_REVIEW: <reason>` uncertainty-flag string.
- **`structural_floor.py::detect_structural_floor`** (`:286`): scans the bundle for deterministic deny **signatures** (never a mere high score). PCAS/CaMeL deny = `risk ≥ 1.0 − 1e-9` (`:154`,`:164`); IFC = one of 6 hard violation codes (`:81-90`); ARGUS = `ARGUS_DECISION_OBSERVATION_DRIVEN` only (`:96`). When `request` is passed, also activates label-driven proofs from `tex.contracts`: Rule-of-Two trifecta, RV4 permanent path violations, action-class FORBID cell, action-cadence HARD threshold (`:325-335`). Emits `Finding(severity=CRITICAL)` per deny. **Can only raise severity** (`:46-48`).
- **`metaguard.py::evaluate_metaguard`** (`:240`): the *reflexive* structural-floor sibling — signatures over **controller-mutation descriptors** (policy writes, lifecycle flips, key mutations), NOT content. FLOOR signatures (`governor_self_target`, `revoked_resurrection`) force FORBID; CAUTION signatures (`quarantine_lift`, `governance_weakening`, `capability_widening`, `key_material_mutation`, `evidence_destruction`) demote PERMIT→ABSTAIN. Helpers `weakening_axes` (`:135`) and `widened_dimensions` (`:177`) do typed comparisons only.

---

## Public API / Entrypoints

Symbols imported by code **outside** `specialists/`:

| Symbol | Defined | Imported by |
|---|---|---|
| `SpecialistSuite`, `build_default_specialist_suite` | `judges.py:317,408` | `engine/pdp.py:72` |
| `SpecialistBundle` | `base.py:136` | `engine/pdp.py:70`, `engine/router.py:15`, `engine/verdict_transcript.py:91`, `domain/determinism.py:24`, `domain/asi_builder.py:43` |
| `fuse` (as `_fuse_specialists`) | `fusion.py:125` | `engine/router.py:214` |
| `detect_structural_floor`, `StructuralFloorResult` | `structural_floor.py:286,129` | `engine/pdp.py:73`, `engine/verdict_transcript.py:92` |
| `get_ifc_labels_cache` | `ifc_specialist.py:113` | `engine/pdp.py:71` |
| `_CLAUSE_TOKEN_STOPWORDS` | `judges.py:580` | `semantic/fallback.py:591` |
| `evaluate_metaguard`, mutation-class constants, `MetaguardResult`, `weakening_axes`, `widened_dimensions`, … | `metaguard.py` | `selfgov/governor.py:122-136` |

Intra-package public symbols (consumed by sibling specialist files): `SpecialistEvidence`/`SpecialistResult`/`SpecialistJudge` (`base.py`), the LLM dispatch types (`llm_dispatch.py`), `build_planguard_stage_ii_judge`/`build_mage_judge_callable` (`llm_bridge.py`), `ConformalEscalationGate`/`CalibrationData` (`conformal_escalation.py`), `build_specialist_human_review_flag` (`human_review.py`).

---

## Wiring

### Wired status: **LIVE** (with one DEMO/TEST-ONLY caveat per file)

The specialist suite is on the hot path of every `/v1/...` evaluation request.

### Live call path (cited)

```
api/routes.py:117  evaluate_action()         (also api/guardrail.py:825)
  → commands/evaluate_action.py:214  EvaluateActionCommand.execute → self._pdp.evaluate(...)
    → engine/pdp.py:289  PolicyDecisionPoint.evaluate → self._specialist_suite.evaluate(request, retrieval_context)
        → specialists/judges.py:328  SpecialistSuite.evaluate → runs all 20 judges → SpecialistBundle
    → engine/pdp.py:340  detect_structural_floor(specialist_bundle, request=request)   # structural FORBID floor
    → engine/router.py:214  fuse(specialist_bundle)   # cross-specialist corroboration → fused_risk
```

Construction:
- `main.py:876` `PolicyDecisionPoint(...)` is built inside `build_runtime()` (`main.py:519`), which is called by `create_app()` (`main.py:1309`, eager at `main.py:2016 app = create_app()`).
- The PDP constructor (`engine/pdp.py:188,205`) defaults `specialist_suite` to `build_default_specialist_suite()` — `build_runtime` does **not** override it, so the default 20-judge suite is what runs in production.
- `EvaluateActionCommand` is built at `main.py:962` and attached to app state at `main.py:1656`; the API route resolves it via `_get_evaluate_action_command` (`api/routes.py:581`).

### Lazy/conditional guards (named)

- **LLM dispatch (PlanGuard Stage II, MAGE J_θ)**: gated by `TEX_SPECIALIST_LLM_DISPATCH` (default off, `llm_dispatch.py:91`) AND `TEX_SPECIALIST_LLM_MODE` (default `disabled`, `llm_bridge.py:73`). In default production config these paths are inert — the specialists run their deterministic-offline lexical fallback. Optional budget/concurrency/model envs: `TEX_SPECIALIST_LLM_BUDGET_MS`, `TEX_SPECIALIST_LLM_CONCURRENCY`, `TEX_SPECIALIST_LLM_MODEL`.
- **PCAS policy**: `TEX_PCAS_POLICY_PATH` (else inline default toxic-flow policy).
- **Runtime-module second paths** (ClawGuard enforcer, MCPShield LTS, PlanGuard verifier, MAGE shadow memory, AgentArmor PDG, CaMeL plan, ARGUS preset IPG): all **opt-in via `request.metadata`** — absent metadata means lexical/heuristic-only.
- **`metaguard.py`** is wired through `selfgov/governor.py:519 evaluate_metaguard(descriptor)`, a **separate live surface** (reflexive self-governance), NOT through the PDP specialist suite.

### Wiring OUT — dependencies

Internal `tex` subsystems this unit calls:
- `tex.domain.evaluation` (`EvaluationRequest`), `tex.domain.retrieval` (`RetrievalContext`), `tex.domain.owasp_asi` (ASI tag constants), `tex.domain.finding`/`severity` (structural floor), `tex.domain.owasp_asi.ASI_CASCADING_FAILURE` (fusion/human_review).
- `tex.runtime.clawguard.*`, `tex.runtime.mcpshield.*`, `tex.runtime.planguard.*`, `tex.runtime.mage.*`, `tex.runtime.agentarmor.*` (the wrapped runtime modules — all confirmed present and real).
- `tex.governance.private_data_exec.ifc.*` (IFC engine — confirmed real).
- `tex.pcas.monitor`, `tex.pcas.graph.adapter` (Datalog reference monitor).
- `tex.camel.interpreter`/`plan`/`policy`/`q_llm`/`value` (CaMeL dual-LLM interpreter).
- `tex.contracts.rule_of_two`/`rv4_path`/`action_class`, `tex.deterministic.cadence` (structural-floor label-driven proofs).
- `tex.observability.telemetry` (`emit_event`, `get_logger`).

External libraries: `pydantic` (all models), `openai` (lazy, only when LLM dispatch enabled), `networkx` (transitively via the agentarmor type system), Python stdlib (`re`, `asyncio`, `threading`, `math`, `json`).

---

## Implementation Reality

**Overall: REAL.** Most of the package is genuine, exercised logic; the LLM/model-tuned backends ship honest heuristic fallbacks that self-label as advisory.

### Real logic (verified)
- All 20 judges return schema-valid `SpecialistResult`s with non-trivial scoring (verified at runtime — see suite enumeration below).
- **ARGUS** ships a real influence-provenance graph + BFS justification path + counterfactual reconstruction (`argus_specialist.py:96-167, 487-611, 662-688`) — not lexical-only.
- **AttriGuard** / **VIGIL** ship real per-observation attribution + verify-before-commit scoring with deliberate false-positive guards (`attriguard_specialist.py:425-472`, `vigil_specialist.py:201-206, 447-461`).
- **IFC / PCAS / CaMeL** delegate to confirmed-real engines (`governance/.../ifc/engine.py:163`, `pcas/monitor.py`, `camel/interpreter.py`).
- **Wrapped runtime modules are real, not stubs**: `agentarmor/type_system.py:86 check_detailed` runs assign→infer→check over a networkx PDG; `mcpshield/verifier.py:73 verify_property` walks the LTS and returns counterexample paths; `planguard/intent_verifier.py:86 verify_with_reasoning` implements paper Algorithm 1 Stage I (exact-match / unauthorized-tool / parameter-mismatch→Stage II). **Stale-TODO flag**: `intent_verifier.py:72-73` still carries `TODO(P1): Stage 1/Stage 2…` comments even though the body below them (`:99-140`) implements exactly that — comment lies, code is real.
- **`conformal_escalation.py`** implements a genuine split-conformal quantile with finite-sample correction (`:95-109`).
- **`structural_floor.py`** / **`metaguard.py`** are real deterministic signature recognisers with monotone-lowering invariants.

### Heuristic fallbacks (honest, advisory)
- `HeuristicMelonBackend` (`melon_specialist.py:81`), `StructuralStruQBackend` (`struq_specialist.py:83`), `DPODistilledHeuristic` (`secalign_specialist.py:135`): explicitly documented as *not the real defense* (e.g. melon docstring `:36` "This is NOT real MELON"). They run by default (no real model backend is wired anywhere in `build_runtime`), confidence pinned ≤0.7 so the PDP treats them as advisory. **This is a graceful-fallback, not a hollow stub** — they compute a defensible signal.
- LLM dispatch (`llm_dispatch.py` / `llm_bridge.py`): real async OpenAI integration behind env flags; off by default, fail-closed. The default production run never calls an LLM from a specialist.

### Stubs / no-ops at runtime (by config, not by code defect)
- `CamelSpecialist` abstains (risk 0.0, conf 0.0) unless `metadata['camel_plan']` is supplied (`camel_specialist.py:88-97`) — in default request flow it contributes nothing.
- `melon`/`struq`/`secalign` abstain unless their `metadata['user_prompt'|'environment_content'|…]` keys are present — also typically silent in the default content-only flow.
- `PcasSpecialist` with no provenance graph returns an empty `DependencyGraphView`; the default policy then authorizes anything that isn't a toxic flow (`pcas_specialist.py:204`).

### No `NotImplementedError` / `raise NotImplementedError` anywhere in the package
Confirmed by reading. The package contains genuine logic end-to-end; the only "TODO" markers are: stale (planguard verifier), or signature-set expansion notes (`mcp_injection_specialist.py:287` BlueRock telemetry, `owasp_skills_top10_specialist.py:79,363` Vidar signatures / platform context). None of these gate the live path.

---

## Technology / SOTA

- **Conformal prediction**: split-CP quantile with finite-sample correction (Vovk/Gammerman/Shafer; Angelopoulos & Bates) — `conformal_escalation.py:95`. Calibrated LLM-escalation gating (cheap-miss / expensive-hit).
- **Information-flow control** (delegated to `governance/.../ifc`): Bell-LaPadula confidentiality join + Biba integrity meet, FIDES dual-axis lattice, NeuroTaint cross-session taint, CA-CI six-tuple contextual integrity, Rule-of-Two trifecta.
- **Datalog reference monitor**: PCAS toxic-flow policy with stratified negation (`pcas_specialist.py:58-104`, delegated to `pcas/monitor.py`).
- **Capability-based dual-LLM interpreter**: CaMeL (DeepMind arXiv:2503.18813) capability tracking with fail-closed halts (`camel/interpreter.py`).
- **Influence-provenance graph + counterfactual attribution**: ARGUS (arXiv:2605.03378) — real IPG with `justified_by` edge BFS and counterfactual redaction.
- **Formal verification**: MCPShield labeled-transition-system property checking (`runtime/mcpshield/verifier.py`).
- **Cross-specialist corroboration fusion**: defense-in-depth weighting with frontier multipliers and named pairwise bonuses (`fusion.py`).
- **Design patterns**: Protocol-based judge contract (structural typing, `base.py:227`); pluggable backend Protocols for model-side defenses; lazy/conditional dispatch; fail-closed everywhere; frozen Pydantic value objects; per-event-loop semaphore; bounded LRU side-channel cache.
- **Threat taxonomies referenced and operationalized**: OWASP ASI 2026 (ASI01–ASI09 tags), OWASP Agentic Skills Top 10 (AST01–AST10), InjecAgent Type I/II, MITRE-style CVE fingerprints, "Lethal Trifecta" (Willison/PAN). `(Benchmark ASR numbers in docstrings — e.g. MAGE "STAC 100%→8.3%", ClawGuard "AgentDojo →0%" — are paper claims, unverified; no benchmark harness in this package reproduces them.)`

---

## Persistence

The specialist layer is **almost entirely stateless and in-memory**:

- Judges hold only immutable config (keyword tuples, severity constants, optional injected backends). `SpecialistResult`/`SpecialistBundle` are frozen and ephemeral per request.
- **`_IfcLabelsCache`** (`ifc_specialist.py:68`): the one stateful element — a **process-wide bounded LRU** (capacity 1024, thread-safe via `threading.Lock`) of serialized IFC labels keyed by request_id. Consume-once (`pop`) by the PDP; **in-memory, not durable** — lost on process restart.
- `llm_dispatch._loop_semaphores` (`:98`) and `_default_dispatcher` singleton (`:513`): process-local mutable state, not persisted.
- `ConformalEscalationGate` is constructed per-bridge and stateless across requests (`conformal_escalation.py:116`).
- Durable persistence happens **downstream**: the specialist summary (`engine/pdp.py:1186 _summarize_specialists`) and IFC labels are folded into the PDP's `Decision` record, which is what gets hash-chained / sealed by the evidence layer. Shadow memory (MAGE), the IFC `MemoryStream`, and CaMeL traces are owned by their respective runtime/governance subsystems, not `specialists/`.

---

## Notable Findings

1. **Count mismatch (overstatement in docs)**: `__init__.py:2` says "17 specialist judges"; `default_specialist_judges()` actually returns **20** (verified at runtime). The `judges.py` docstring comments describe the Thread-4/11/12 groupings but never state the total. Treat "17" as stale.

2. **`fusion_reason_codes` is an ORPHAN.** `fusion.py:193` is defined and exported but has **zero callers** in `src/tex` (grep confirmed). Only `fuse()` itself is wired (router.py:214). The `FusionVerdict.pair_signals` / `cascading_failure_signal` it would surface as reason codes are computed but never propagated as codes. Dead code.

3. **`HumanReviewEscalation.from_bundle` is effectively DEMO/TEST-ONLY.** `human_review.py:110` has no live caller in `src/tex` outside the module. The `requires_human_review` hits in `domain/{evaluation,decision,verdict}.py` are a **separate** mechanism on `Verdict`, unrelated to `human_review.py`. What *is* live is `build_specialist_human_review_flag` (called by `attriguard_specialist.py:329` and `vigil_specialist.py:309`) — but the flag string it produces is only aggregated by the orphaned `from_bundle`, so the Five-Eyes escalation *policy* (the 4 rules) is not actually evaluated on the live path. The flag survives in the evidence chain as a plain uncertainty flag, but no code acts on the `REQUIRES_HUMAN_REVIEW:` semantics. **Likely unintended gap.**

4. **Stale TODO contradicts implemented code**: `runtime/planguard/intent_verifier.py:72-73` carries `TODO(P1): Stage 1 / Stage 2` comments directly above a fully-implemented Stage I + Stage II body (`:99-140`). The verifier the PlanGuard specialist wraps is real; the comment lies.

5. **Default model-side defenses are heuristic, by design and honestly labelled.** `melon`/`struq`/`secalign` never receive a real fine-tuned backend in `build_runtime`, so they always run their `HeuristicMelonBackend`/`StructuralStruQBackend`/`DPODistilledHeuristic`. Confidence is pinned (0.5–0.7) and docstrings say "This is NOT real MELON" (`melon_specialist.py:36`). Not a stub — a graceful fallback — but worth flagging that the paper-faithful versions are not active.

6. **Most "second paths" are dormant in default flow.** ClawGuard enforcer, MCPShield LTS, AgentArmor PDG, PlanGuard verifier, MAGE shadow memory, CaMeL plan, ARGUS preset IPG — all require opt-in `request.metadata` that the standard content-only API request does not carry. In production, these frontier specialists usually run **lexical/heuristic-only**; the structural muscle (e.g. CaMeL interpreter, MCPShield verifier) fires only when a caller supplies the structured inputs. The capability is real and reachable; the default request shape rarely triggers it.

7. **Surprise — IFC is the only structural-floor source that fires off content alone.** PCAS needs a provenance graph (else permissive), CaMeL needs a plan (else abstains), ARGUS needs a decision node. IFC (`ifc_specialist.py`) runs the full `IfcEngine` on every request from content + retrieval context, so it is the structural-floor leg most likely to actually FORBID in the default flow.

8. **Benchmark ASR numbers throughout the docstrings are paper claims, not measured here.** Every frontier specialist cites SOTA ASR reductions (MAGE STAC 100%→8.3%, ClawGuard AgentDojo →0%, SecAlign 70%→1%). These are `(claim, unverified)` — no in-package harness reproduces them, and the shipped detectors are lexical approximations of the cited papers, not the papers' trained models.

9. **`metaguard.py` lives in `specialists/` but is not a PDP specialist.** It is the reflexive-self-governance signature engine, wired into `selfgov/governor.py`. Filing it under `specialists/` is an organizational choice (shared structural-floor pattern), not a suite membership. Anyone auditing "what runs in the specialist suite" must exclude it.

10. **Fusion is provably monotone-safe.** `fuse()` only ever adds a capped (≤0.20) corroboration bonus on top of `max_risk_score` and `min(1.0, …)` clamps the result — it can never lower risk. Same invariant holds for `structural_floor` (only raises to FORBID) and `metaguard` (only lowers the verdict). This is a genuine, code-enforced safety property of the layer, not just a docstring claim (`fusion.py:128-176`, `structural_floor.py:46-48`).
