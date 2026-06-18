# Subsystem Dossier: `semantic`

**Path:** `/Users/matthewnardizzi/dev/tex/src/tex/semantic/`
**Branch:** `feat/proof-carrying-gate`
**Architectural layer (self-declared):** Layer 4 — Execution Governance (`src/tex/semantic/__init__.py:9-10`)
**Reachability:** **LIVE** (verified — see Wiring).

---

## Overview

The `semantic` subsystem is Tex's **content-intelligence judge**: it reads the *actual action content* about to be released (an email body, an API payload, a tool argument) and scores it across five fixed risk dimensions, producing a schema-locked `SemanticAnalysis` object plus a recommended `Verdict` (PERMIT / ABSTAIN / FORBID). This is **one of the parallel evidence streams** the PDP feeds into the router for verdict fusion (`src/tex/engine/pdp.py:295-300`, `src/tex/engine/router.py:217,365`).

Despite the prompt's framing ("embeddings / semantic firewall"), **there are no embeddings, no vector store, and no cosine-similarity anywhere in this unit.** "Semantic" here means *LLM-judged or lexical-heuristic content adjudication against a fixed dimension taxonomy*, not vector semantics. The unit is a clean **boundary/adapter** design:

- **Tex owns** prompt construction (`prompt.py`) and output schema/validation (`schema.py`).
- **The provider owns** only transport + model execution (`openai.py`), behind a narrow `Protocol`.
- A **deterministic, LLM-free fallback** (`fallback.py`) guarantees a schema-valid result even with no model, no network, and no API key.

The default runtime configuration ships with **no provider configured** (`semantic_provider=None`, `src/tex/config.py:70-72`), so **the deterministic keyword heuristic is the live primary path out of the box** — the OpenAI provider is opt-in via `TEX_SEMANTIC_PROVIDER=openai`.

---

## File Inventory

| File | Lines | Role |
|---|---:|---|
| `src/tex/semantic/__init__.py` | 11 | Package marker only. Declares `__layer__=4`, `__layer_kind__='execution_governance'`. Exports **no** symbols / no `__all__`. |
| `src/tex/semantic/schema.py` | 464 | Pydantic output contract: `SemanticEvidenceSpan`, `SemanticDimensionResult`, `SemanticVerdictRecommendation`, `SemanticAnalysis`, the slim `SemanticAnalysisParseTarget` for OpenAI structured output, and `semantic_dimensions()`. The 5 canonical dimensions live here. |
| `src/tex/semantic/prompt.py` | 257 | Deterministic prompt construction: `build_semantic_system_prompt()`, `build_semantic_user_prompt()`, `semantic_prompt_bundle()`. Serializes the request + retrieval context to stable JSON. |
| `src/tex/semantic/analyzer.py` | 442 | Orchestration boundary: `DefaultSemanticAnalyzer` (provider→validate→fallback→decorate), `SemanticExecutionMode`/`SemanticExecutionTrace` audit metadata, the `StructuredSemanticProvider` and `SemanticAnalyzer` protocols, and the `build_default_semantic_analyzer()` factory. |
| `src/tex/semantic/fallback.py` | 601 | `HeuristicSemanticFallback` — deterministic, LLM-free keyword/clause adjudicator. Real logic (not a stub): per-dimension keyword tables, calibrated score/confidence ramps, verdict recommendation cascade. |
| `src/tex/semantic/openai.py` | 317 | `OpenAIStructuredSemanticProvider` — OpenAI Responses-API `responses.parse(...)` adapter with strict `text_format=SemanticAnalysisParseTarget`, graceful import guard, typed error mapping into `SemanticProviderError`. |

No subpackages. No `__pycache__`-only artifacts of note.

---

## Internal Architecture

### Data flow (one analysis pass)

```
EvaluationRequest + RetrievalContext
        │
        ▼
DefaultSemanticAnalyzer.analyze()            analyzer.py:140
        │
        ├─ build_prompts() → semantic_prompt_bundle()   prompt.py:241
        │       (system_prompt, user_prompt)            prompt.py:11 / :134
        │
        ├─ provider is None ?  ── yes ─►  HeuristicSemanticFallback.analyze()  fallback.py:113
        │                                  → mode = DEFAULT_FALLBACK
        │
        └─ no ─► provider.analyze(system_prompt, user_prompt)   analyzer.py:178
                    │  (OpenAIStructuredSemanticProvider.analyze, openai.py:102)
                    │
                    ├─ success → _coerce_provider_result()  analyzer.py:236
                    │             → mode = PRIMARY_PROVIDER
                    │
                    └─ Exception → allow_fallback ?
                          ├─ no  → raise SemanticProviderError   analyzer.py:185
                          └─ yes → fallback.analyze() → mode = FAILURE_FALLBACK
        │
        ▼
_decorate_analysis()  analyzer.py:255
   - merges metadata["semantic_runtime"] (mode, sha256 fingerprints, request/retrieval counts)
   - fills provider_name / model_name when absent
        │
        ▼
SemanticAnalysis (frozen, schema-locked)  → consumed by router/PDP
```

### `schema.py` — the output contract

The schema is the **load-bearing artifact** of this unit; the provider can be arbitrarily sophisticated but its emitted shape cannot escape this contract (`schema.py:198-205`).

- **Canonical dimensions** (`schema.py:10-18`): `_ALLOWED_DIMENSIONS = ("policy_compliance", "data_leakage", "external_sharing", "unauthorized_commitment", "destructive_or_bypass")`. Exposed via `semantic_dimensions()` (`schema.py:462`).
- **`SemanticEvidenceSpan`** (`schema.py:84`): frozen, `extra="forbid"`. Optional half-open `[start_index, end_index)` char offsets; a model-validator enforces both-or-neither and `end>start` (`schema.py:105-113`).
- **`SemanticDimensionResult`** (`schema.py:116`): one dimension's `score`∈[0,1], `confidence`∈[0,1], summary, optional rationale, evidence spans, matched policy-clause IDs, uncertainty flags. A field-validator (`schema.py:140-146`) rejects any dimension not in the canonical set. Convenience properties `is_high_risk` (≥0.8), `is_low_confidence` (<0.5), `has_evidence` (`schema.py:158-168`).
- **`SemanticVerdictRecommendation`** (`schema.py:171`): advisory `Verdict` + confidence + summary. Comment is explicit that the router still owns the final verdict (`schema.py:173-176`).
- **`SemanticAnalysis`** (`schema.py:198`): the boundary object. A `model_validator(mode="after")` (`schema.py:252-289`) enforces **exact coverage** — each of the 5 dimensions present exactly once, no duplicates, no extras. `analyzed_at` must be timezone-aware (`schema.py:245-250`). Rich derived properties: `dimension_scores`, `dimension_confidences`, `matched_policy_clause_ids` (deduped, order-preserving, `schema.py:304-309`), `all_uncertainty_flags`, `max_dimension_score`, `min_dimension_confidence`, `high_risk_dimensions`, `all_evidence_spans` (`schema.py:291-363`). These properties are exactly what the router reads.
- **`SemanticAnalysisParseTarget`** (`schema.py:365`): a *slimmed* twin used only as OpenAI's strict `text_format`. It drops the runtime-populated fields (`metadata`, `provider_name`, `model_name`, `analyzed_at`) because OpenAI strict JSON schema cannot represent `dict[str, Any]`. `to_full_analysis()` (`schema.py:441`) rehydrates a full `SemanticAnalysis` after parse. Its `validate_dimension_coverage` (`schema.py:402-439`) is a **near-verbatim copy** of `SemanticAnalysis`'s validator (see Notable Findings — duplication).

### `prompt.py` — deterministic prompt builder

- `build_semantic_system_prompt()` (`prompt.py:11`): a fixed, strict adjudication prompt that names the 5 dimensions, the 3 verdicts, retrieval-grounding rules, and "return only structured data, no markdown, no extra keys." Pulls the dimension list from `semantic_dimensions()` so prompt and schema can't drift.
- `build_semantic_user_prompt()` (`prompt.py:134`): serializes the `EvaluationRequest` and the full `RetrievalContext` (policy clauses, precedents, entities, warnings) into stable JSON via `json.dumps(..., sort_keys=True, indent=2)` (`prompt.py:164`). Deterministic serialization is what makes the `system_prompt_sha256` / `user_prompt_sha256` fingerprints in the trace meaningful.
- `semantic_prompt_bundle()` (`prompt.py:241`): the `(system, user)` tuple helper used by the analyzer.

### `analyzer.py` — orchestration boundary

- **`DefaultSemanticAnalyzer`** (`analyzer.py:93`): `__slots__`-based. Holds a provider (optional), a fallback analyzer (defaults to `HeuristicSemanticFallback`, `analyzer.py:129`), and an `allow_fallback` flag. `analyze()` (`analyzer.py:140`) implements the three-mode flow above.
  - `_coerce_provider_result()` (`analyzer.py:236`): accepts a `SemanticAnalysis` directly or a `Mapping` it re-validates through `SemanticAnalysis.model_validate`; anything else → `SemanticProviderError`.
  - `_decorate_analysis()` (`analyzer.py:255`): attaches `metadata["semantic_runtime"]` — mode, `used_fallback`, provider error, request action/channel/environment, `request_content_sha256`, retrieval counts, matched-clause count, and both prompt SHA-256 fingerprints (`analyzer.py:270-286`). Then resolves provider/model identity, preferring the analysis's own values, then ctor-supplied labels, then inferred labels (`heuristic_fallback` / `heuristic-deterministic` for fallback modes, `analyzer.py:322-355`).
- **`SemanticExecutionMode`** (`analyzer.py:26`) / **`SemanticExecutionTrace`** (`analyzer.py:40`): the audit triple {`PRIMARY_PROVIDER`, `DEFAULT_FALLBACK`, `FAILURE_FALLBACK`} plus prompt fingerprints; `used_fallback` property (`analyzer.py:54`).
- **Protocols**: `StructuredSemanticProvider` (`analyzer.py:62`, transport-only contract) and `SemanticAnalyzer` (`analyzer.py:80`, the boundary contract PDP types against). Both `@runtime_checkable`.
- **`build_default_semantic_analyzer()`** (`analyzer.py:381`): the factory the PDP calls. Reads settings, builds a provider via `_build_semantic_provider_from_settings()` (`analyzer.py:420`), passes `allow_fallback=settings.allow_semantic_fallback`. The provider builder returns `None` when `semantic_provider is None`, raises on any value ≠ `"openai"`, and otherwise lazily imports and constructs `OpenAIStructuredSemanticProvider` with all settings wired through (`analyzer.py:431-442`). The local import breaks the `analyzer ↔ openai` circular import (`openai.py:9` imports `SemanticProviderError` from `analyzer`).

### `fallback.py` — deterministic heuristic (REAL logic)

`HeuristicSemanticFallback.analyze()` (`fallback.py:113`) is the unit's most substantive non-schema logic and is **not a stub**:

- Five keyword tables, one per risk area (`fallback.py:48-111`): data-leakage terms (ssn, password, api key…), external-sharing terms (send externally, export, public link…), unauthorized-commitment terms (we guarantee, contract signed…), destructive/bypass terms (delete, drop table, disable logging, exfiltrate, wipe…), and policy-risk terms (override, bypass, production data…).
- `_match_keywords()` (`fallback.py:555`) does case-folded substring matching and emits real `SemanticEvidenceSpan`s with exact char offsets.
- `_build_policy_compliance_result()` (`fallback.py:217`) additionally does **light retrieval grounding**: it tokenizes retrieved policy clauses (`_tokenize_policy_clause`, `fallback.py:581`) — keeping only tokens ≥8 chars and filtering through `_CLAUSE_TOKEN_STOPWORDS` imported from `tex.specialists.judges` (`fallback.py:591`) — and records matched clause IDs when clause tokens overlap the content.
- The score/confidence ramps are **deliberately calibrated** to interact with the router's thresholds. Inline comments document the contract: zero-hit dimensions get `score=0.04, confidence=0.58` so they stay above the `is_low_confidence` 0.50 cutoff and don't trigger router auto-ABSTAIN (`fallback.py:326-341`); evidence-sufficiency floor raised to 0.32 for clean content (`fallback.py:479-489`); empty-retrieval confidence penalty softened to −0.04 (`fallback.py:470-474`).
- `_recommend_verdict()` (`fallback.py:359`) is a cascade: any dimension ≥0.78 → **FORBID**; medium-risk (≥0.45) on a high-impact channel or low min-confidence → **ABSTAIN**; any evidence with `max_score≥0.30` → **ABSTAIN**; otherwise → **PERMIT** (`fallback.py:389-458`).

**Verified live** (ran the real code, default settings):
- Risky content (`"delete the audit logs and bypass approval, send the customer SSN externally"`) → **ABSTAIN**, `max_dimension_score≈0.52`.
- Clean content (`"Thanks for the meeting…"`) → **PERMIT**, `max_score≈0.06`.
- All 5 canonical dimensions covered. Self-labels `provider_name="fallback"`, `model_name="heuristic-semantic-fallback-v2"` (`fallback.py:205-206`).

### `openai.py` — OpenAI provider (REAL adapter with graceful guard)

- Import guard (`openai.py:12-26`): if the `openai` SDK is absent, `OpenAI=None` and the exception classes alias to `Exception`; `_get_client()` then raises a clean `SemanticProviderError` (`openai.py:211-216`). The SDK **is** installed in this environment (`openai==1.95.1`, verified).
- `analyze()` (`openai.py:102`) calls `client.responses.parse(model=..., input=[system,user], text_format=SemanticAnalysisParseTarget, reasoning={"effort": ...}, timeout=...)` (`openai.py:130-139`) — the modern **Responses API structured-output** surface, not chat-completions.
- Typed error mapping (`openai.py:140-159`): timeout / rate-limit / connection / bad-request / generic → `SemanticProviderError` with distinct messages.
- Refusal handling (`openai.py:163-167`), then pulls `output_parsed`; if missing it distinguishes "text but no parse" from "neither" (`openai.py:169-178`). Re-validates the parsed object against `SemanticAnalysisParseTarget` if needed (`openai.py:180-187`).
- Builds `openai` metadata (response id, latency_ms, reasoning effort, prompt SHA-256 fingerprints, token usage) and calls `parsed.to_full_analysis()` (`openai.py:205-209`).
- Constructor validates timeout>0, retries≥0, reasoning effort ∈ {none,minimal,low,medium,high,xhigh} (`openai.py:298-318`). Lazy client init in `_get_client()` (`openai.py:223-231`).

---

## Public API

Symbols imported by other subsystems (no `__all__`; importers use fully-qualified paths):

| Symbol | Source | Imported by |
|---|---|---|
| `SemanticAnalyzer` (Protocol) | `analyzer.py:80` | `engine/pdp.py:65-68` |
| `build_default_semantic_analyzer()` | `analyzer.py:381` | `engine/pdp.py:65-68` |
| `SemanticAnalysis` | `schema.py:198` | `engine/pdp.py:69`, `engine/router.py:14`, `engine/verdict_transcript.py:90` (TYPE_CHECKING), `domain/determinism.py:23`, `domain/asi_builder.py:42`, `capstone/flow.py:80` |
| `SemanticDimensionResult`, `SemanticVerdictRecommendation`, `semantic_dimensions` | `schema.py` | `capstone/flow.py:80-85` |
| `SemanticProviderError` | `analyzer.py:22` | `semantic/openai.py:9` (intra-unit) |
| `SemanticAnalysisParseTarget` | `schema.py:365` | `semantic/openai.py:10` (intra-unit) |
| `OpenAIStructuredSemanticProvider` | `openai.py:37` | `semantic/analyzer.py:431` (lazy, intra-unit) |
| `HeuristicSemanticFallback`, `SemanticFallbackAnalyzer` | `fallback.py:30,18` | `semantic/analyzer.py:13` (intra-unit default) |
| `build_semantic_prompts()`, `build_semantic_system_prompt`, `build_semantic_user_prompt`, `semantic_prompt_bundle` | `analyzer.py:402` / `prompt.py` | intra-unit (no external importers found) |

The **practically external** surface is just two things: the `SemanticAnalysis` schema type (read widely) and the `(SemanticAnalyzer, build_default_semantic_analyzer)` pair consumed by the PDP.

---

## Wiring

### Wired status: **LIVE**

### Live call path (from app build to this unit)

```
src/tex/main.py:2016                app = create_app()
src/tex/main.py:1309                create_app(...)  → build_runtime(...)
src/tex/main.py:519,876             build_runtime: pdp = PolicyDecisionPoint(...)
src/tex/engine/pdp.py:150,189-206   PolicyDecisionPoint.__init__:
                                        self._semantic_analyzer =
                                          semantic_analyzer or build_default_semantic_analyzer()
                                        └─► src/tex/semantic/analyzer.py:381
src/tex/main.py:962-963             EvaluateActionCommand(pdp=pdp, ...)
src/tex/api/routes.py:117-128       POST evaluate_action route →
                                        command.execute(domain_request)
src/tex/commands/evaluate_action.py:214   self._pdp.evaluate(...)
src/tex/engine/pdp.py:295-300       semantic_analysis =
                                        self._semantic_analyzer.analyze(request=..., retrieval_context=...)
```

The result is then summarized into the decision record (`pdp.py:1214-1236`, `_summarize_semantic`) and fed to the router for fusion: the router reads `semantic_analysis.max_dimension_score` (`router.py:217,369`), `.recommended_verdict` (`router.py:365`), `.overall_confidence` (`router.py:501`), and `.evidence_sufficiency` (`router.py:370`). So the semantic stream is a **first-class input to the final verdict**, not decorative.

`SemanticAnalysis` is also consumed by the **determinism fingerprint** (`domain/determinism.py:71-75,145-148` — dimension scores hashed into the canonical decision fingerprint) and the **ASI builder** (`domain/asi_builder.py:67`), both reachable from the same PDP/engine path.

### Guard / flag controlling which path runs

| Setting (`src/tex/config.py`) | Default | Effect |
|---|---|---|
| `semantic_provider` (`:70-72`, `Literal["openai"] | None`) | **`None`** | `None` ⇒ no provider ⇒ **`DEFAULT_FALLBACK` is the live path**. `"openai"` ⇒ OpenAI provider. Any other value ⇒ `ValueError` (`analyzer.py:426-429`). |
| `allow_semantic_fallback` (`:74-77`) | `True` | If a provider fails and this is `False`, `analyze()` raises `SemanticProviderError` (`analyzer.py:184-187`) — fail-closed. |
| `semantic_model` (`:78-81`) | `"gpt-5-mini"` | Passed to the provider; **overrides** openai.py's own `_DEFAULT_MODEL="gpt-5.4-mini"` (`openai.py:29`) — see Notable Findings. |
| `semantic_timeout_seconds` / `semantic_max_retries` / `semantic_reasoning_effort` (`:82-91`) | `30.0` / `2` / `"minimal"` | Wired through `analyzer.py:436-441`. |
| `openai_api_key` (`:` env `OPENAI_API_KEY`) | `None` | Provider raises if `"openai"` selected without a key (`config.py:305`, `openai.py:218-221`). |

**Default-runtime reality:** with stock settings, every live `evaluate_action` request runs the deterministic `HeuristicSemanticFallback` in `DEFAULT_FALLBACK` mode. The LLM judge is real and wired but dormant until `TEX_SEMANTIC_PROVIDER=openai` + a key are set.

### Wiring out (this unit's dependencies)

**Internal tex subsystems:**
- `tex.config.get_settings` (`analyzer.py:10`) — provider selection + tuning.
- `tex.domain.evaluation.EvaluationRequest`, `tex.domain.retrieval.RetrievalContext` (`analyzer.py:11-12`, `fallback.py:6-7`, `prompt.py:6-7`) — inputs.
- `tex.domain.verdict.Verdict` (`schema.py:8`, `fallback.py:8`) — the recommendation enum.
- `tex.specialists.judges._CLAUSE_TOKEN_STOPWORDS` (`fallback.py:591`, lazy import) — shared stopword set for clause grounding. **Note:** this reaches into a private (`_`-prefixed) symbol of another subsystem.

**External libraries:**
- `pydantic` (`schema.py:6`, `analyzer.py:8`) — the entire schema/validation layer.
- `openai` SDK (`openai.py:12-16`, optional/guarded) — `OpenAI`, `responses.parse`, typed exceptions.
- stdlib: `hashlib` (sha256 fingerprints), `json` (prompt serialization), `datetime`, `enum`, `dataclasses`, `os`, `time`, `textwrap.dedent`.

---

## Implementation Reality

**Verdict: REAL.** Every file contains substantive, exercised logic. No `NotImplementedError`, no `TODO`/`FIXME`, no placeholder stubs anywhere in the package.

Evidence:
- **Schema** — full Pydantic v2 models with field + model validators, exact-coverage enforcement, ~25 derived properties. Exercised by every consumer.
- **Fallback** — real keyword/clause heuristic; ran it end-to-end and got correct discriminating output (ABSTAIN on risky, PERMIT on clean, all dimensions covered). This is the **default live path**.
- **OpenAI provider** — real Responses-API `responses.parse` adapter with strict structured output, typed error mapping, refusal/parse handling, metadata capture. SDK is installed. The only graceful degradation is the import guard (`openai.py:12-26`) and the `_get_client()` guards (`openai.py:211-221`), which are correct fail-fast behavior, not hollow stubs.
- **Analyzer** — full three-mode orchestration with audit trace; verified that `build_default_semantic_analyzer()` constructs and returns a working analyzer with `provider=None` under default settings.

**The single `pass` in scope** is benign: `openai.py:261` swallows a `usage.model_dump()` exception to fall through to manual field extraction in `_serialize_usage()` — defensive serialization, not a stub.

**No crypto/zk/tee in this unit.** The only cryptographic operation is `hashlib.sha256` used for **content/prompt fingerprinting** in audit metadata (`analyzer.py:376-378`, `openai.py:280-282`) — not a security primitive, just tamper-evident provenance hashing.

---

## Technology / SOTA

- **Schema-locked LLM adjudication** — the model is constrained to a fixed 5-dimension taxonomy with exact-coverage validation; the provider can be sophisticated but its output shape cannot escape `SemanticAnalysis`. This is the "structured output as a safety boundary" pattern.
- **OpenAI Responses API structured output** — `responses.parse(text_format=PydanticModel)` with `reasoning={"effort": ...}` (`openai.py:130-139`), the current SOTA surface for typed reasoning-model output (distinct from legacy chat-completions function-calling).
- **Dual-model trick for strict schemas** — `SemanticAnalysisParseTarget` strips `dict[str, Any]` fields so OpenAI's strict JSON-schema mode accepts it, then rehydrates via `to_full_analysis()` (`schema.py:365-460`). A pragmatic workaround for strict-schema limitations.
- **Graceful degradation / provider-agnostic adapter** — `Protocol`-based provider contract + always-available deterministic fallback. Calibrated heuristic scores deliberately tuned against downstream router thresholds (documented inline, `fallback.py:326-341,479-489`).
- **Audit-first design** — every pass records execution mode, prompt SHA-256 fingerprints, request content hash, and retrieval-context counts (`analyzer.py:270-286`); the OpenAI path adds response id, latency, token usage.
- **Uncertainty as first-class output** — explicit `uncertainty_flags` at span/dimension/recommendation/analysis levels, surfaced through `all_uncertainty_flags` (`schema.py:312-323`).

No embeddings, vector search, ANN, or ML-trained classifier. "Semantic firewall" describes the *role* (gating action content) — the mechanism is LLM-or-lexical adjudication, not vector semantics.

---

## Persistence

**None within this unit.** Entirely **in-memory / stateless**:
- `SemanticAnalysis` and all schema models are frozen Pydantic objects returned up the call stack; the unit never writes to disk, DB, or ledger.
- The OpenAI client is lazily cached on the provider instance (`openai.py:223-231`) but is transport state, not persisted data.
- Durable persistence of the analysis happens **downstream** — the PDP summarizes it into the decision record (`pdp.py:1214-1236`) and the evidence/ledger subsystems persist that, and `domain/determinism.py` folds dimension scores into the decision fingerprint. The semantic unit itself holds no state between calls.

---

## Notable Findings

1. **"Embeddings / semantic firewall" is a misnomer for this code.** There are zero embeddings, vector stores, or similarity search in the unit. "Semantic" = LLM/lexical content adjudication against a fixed taxonomy. Anyone reading the subsystem name expecting vector semantics will be surprised. (Not a defect — just a naming caveat for the bible.)

2. **The default live path is deterministic, not an LLM.** `semantic_provider` defaults to `None` (`config.py:70-72`), so stock Tex runs `HeuristicSemanticFallback` as the *primary* path in `DEFAULT_FALLBACK` mode — verified by running `build_default_semantic_analyzer()` (provider is `None`). The OpenAI "semantic judge" is real and fully wired but **dormant by default**. Any claim that "Tex uses an LLM to judge content" is, out of the box, false until `TEX_SEMANTIC_PROVIDER=openai` is set.

3. **Two conflicting default model names.** `openai.py:29` hardcodes `_DEFAULT_MODEL="gpt-5.4-mini"` but `config.py:78-81` defaults `semantic_model="gpt-5-mini"`. Because `build_default_semantic_analyzer()` always passes `settings.semantic_model` (`analyzer.py:438`), the **config value wins** and openai.py's default is effectively dead unless the provider is constructed directly. Minor dead-default / drift. (Both names are speculative future model IDs, consistent with the project's "lead don't follow" R&D doctrine.)

4. **Provider-name labeling is slightly inconsistent.** The fallback self-labels `provider_name="fallback"` (`fallback.py:205`), but the analyzer's `_infer_provider_name` would label fallback modes `"heuristic_fallback"` (`analyzer.py:327`). Because `_decorate_analysis` prefers the analysis's own value (`analyzer.py:288-292`), the persisted label stays `"fallback"` — the inference path is shadowed. Not a bug, but the two naming conventions for the same component could confuse audit consumers.

5. **Schema duplication.** `SemanticAnalysis.validate_dimension_coverage` (`schema.py:252-289`) and `SemanticAnalysisParseTarget.validate_dimension_coverage` (`schema.py:402-439`) are near-identical ~38-line copies, as are the shared scalar fields. A change to coverage rules must be made in both places. Maintenance hazard, not a correctness issue today.

6. **Cross-subsystem private import.** `fallback.py:591` imports `_CLAUSE_TOKEN_STOPWORDS` (a `_`-prefixed private) from `tex.specialists.judges`. This couples the semantic fallback to specialists' internals; a refactor there could silently break clause grounding here.

7. **Stale docstring reference to a non-existent module.** `vet/integration.py:29` (outside this unit, but referencing it) names `tex.semantic.openai_provider` as the notarization call site. **No such module exists** — the real file is `tex.semantic.openai` and it has no TLS-notarization hook. This is an aspirational/stale doc note, not a wiring claim; do not treat it as evidence that semantic notarizes WebProofs.

8. **`__init__.py` exports nothing.** All consumers import fully-qualified paths (`tex.semantic.analyzer`, `tex.semantic.schema`). The package marker only exposes `__layer__`/`__layer_kind__`. There is no curated public surface, which is fine given the small set of real importers.

9. **Self-declared Layer 4 vs spine classification.** The unit declares itself Layer 4 "execution_governance" (`__init__.py:9-10`), and the spine pass classifies `semantic=LIVE`. Both confirmed: it executes inside the PDP's per-decision evaluation and its output gates the router. Consistent.
