# Contradictions surfaced during audit

> Code-evidence only. Every contradiction below has a file:line citation that can be re-verified.
> Generated: 2026-05-27

---

## 1. "Six-layer pipeline" vs "seven-stream contract"

Both phrases appear in the codebase. They refer to the same PDP pipeline, but the agent layer was split into three sub-streams (identity, capability, behavioral) and the docs are not all updated.

### Current canonical naming (from code)
- `engine/pdp.py:719` — "Captures the **seven-stream contract**: identity, capability, and behavioral risk and confidence..."
- `engine/pdp.py:602-611` — actual `evaluation_order` list names eight stages: `deterministic_recognizers`, `policy_retrieval`, `agent_governance_streams`, `specialist_judges`, `semantic_judge`, `behavioral_contracts`, `routing`, `decision_materialization`
- `domain/agent_signal.py:288` — "fusion across the seven layers"

### Stale "six-layer" references in code (still active)
- `main.py:237` — "six-layer ``RoutingResult``"
- `ecosystem/engine.py:4` — "six-layer-pipeline verdict"
- `ecosystem/engine.py:121` — "existing six-layer pipeline runs untouched"
- `ecosystem/bridge.py:2,5,22,59,71,84,172` — multiple references to "six-layer"
- `specialists/fusion.py:33` — "PDP's existing 6-layer fusion math"
- `specialists/clawguard_specialist.py:5,360` — "Layer 3 of Tex's six-layer PDP"
- `specialists/pcas_specialist.py:6` — "existing six-layer pipeline"
- `specialists/ifc_specialist.py:5` — "six-layer PDP"

### Different "six-layer" — the MCP syscall gate
- `governance/kernel_mcp/syscall_gate.py:8,428,464` — describes a different six-layer pipeline (schema / trust / rate / prefilter / semantic / constitutional). This is NOT the PDP six layers — it's the MCP syscall stages.

### "Five-layer platform" in pitch routes
- `api/pitch_routes.py:5` — "Tex is a **five-layer** AI agent governance platform deployed at companies running AI agents (Layer 1 discovery → Layer 2 identity → Layer 3 monitoring → Layer 4 execution governance → **Layer 5 reporting**)"

This is the most consequential contradiction. The user describes Tex as six architectural layers (discovery / identity / monitoring / execution-governance / evidence / learning). `pitch_routes.py` undercounts to five — collapsing evidence and learning into "reporting." The code substantively implements all six (Learning has its own `learning/` package with 12 files and dedicated HTTP surface `/v1/learning/*`).

### Resolution

Three orthogonal concepts share the word "layer" in the codebase:

| Concept | Count | Where |
|---|---|---|
| Architectural layer (user's model) | 6 | `discovery/`, `agent/`, monitoring spread across packages, `engine/`+`specialists/`, `evidence/`+`memory/`+`c2pa/`+`vet/`+`zkprov/`+`tee/`, `learning/` |
| PDP evaluation pipeline | 7 streams / 8 stages | `engine/pdp.py` |
| MCP syscall gate stages | 6 | `governance/kernel_mcp/syscall_gate.py` |

Recommended fix: use distinct words. The PDP is "streams" or "stages" — never "layers". The MCP gate is "stages". "Layer" reserved for architectural layers.

---

## 2. `FrontierFlags` class is decorative

`src/tex/frontier_config.py` defines a 12-flag dataclass (`pqcrypto, c2pa, receipts, zkprov, nanozk, tee, vet, runtime, governance, interop, compliance, pitch`) and a `_flag()` parser.

### Evidence
```
$ grep -rln "from tex.frontier_config" src/ --include="*.py" | grep -v src/tex/frontier_config.py
src/tex/compliance/_common.py
```

Only one file outside `frontier_config.py` imports the module — `compliance/_common.py:392` does a deferred import. No router and no command consults the flags. The runtime ships all 12 capabilities unconditionally regardless of flag state (verified by reading `main.py:1168-1221`).

The orphan registry classifies `frontier_config.py` itself as TEST_ONLY (imported by `tests/frontier/test_scaffolding_imports.py` but not by `main.py`).

---

## 3. `EcosystemFlags` class is decorative

`src/tex/ecosystem_config.py` defines a 10-flag dataclass and an `is_flag_on()` parser.

### Evidence
```
$ grep -rln "EcosystemFlags" src/ --include="*.py" | grep -v src/tex/ecosystem_config.py
(no results)
```

The dataclass is never instantiated outside its own file. Only `is_flag_on()` is consumed externally, and only by one file: `ecosystem/engine.py:70`.

---

## 4. Two distinct flag parsers exist despite warnings against drift

`ecosystem_config.py:36-40`:
```python
def is_flag_on(name: str) -> bool:
    return os.environ.get(name) == "1"
```

`frontier_config.py:14-15`:
```python
def _flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"
```

`ecosystem_config.py:8-17` explicitly warns: "Modules that need to read the same flag at runtime ... MUST import `is_flag_on` from this module rather than re-implementing the parse."

`frontier_config.py` reimplements the parse anyway. The two are functionally equivalent for current inputs but the structural duplication is real.

---

## 5. `enforcement/` package describes itself as the gate; not invoked by main.py

`src/tex/enforcement/__init__.py:1-12`:
> "Tex's PDP returns a verdict (PERMIT / ABSTAIN / FORBID). The enforcement package is what makes that verdict *actually stop the action* before it reaches the real world. Without it, Tex is a decision layer; with it, Tex is a decision-and-enforcement layer end-to-end."

### Evidence
```
$ grep -rln "from tex.enforcement\|import tex.enforcement" src/ --include="*.py" | grep -v src/tex/enforcement/
(no results)
```

The package's 1,691 lines are TEST_ONLY per the orphan registry. The runtime never invokes `TexGate`, `@tex_gated`, the framework adapters, or the ASGI proxy.

The customer-facing integration is instead via `sdks/python/tex_guardrail/` which is a separate HTTP-only client. Two enforcement primitives exist; only the SDK one is in the integration path.

---

## 6. `compliance/` emitters are tested but never fire

The package re-exports nothing usable. Its individual emitter modules (e.g. `compliance/eu_ai_act/article_50.py`, `compliance/state/california_sb942.py`) define `emit_*_evidence(...)` functions that are imported by tests in `tests/frontier/test_compliance*.py` but by no module in `src/tex/`.

### Evidence
```
$ grep -rln "emit_article_50_evidence\|emit_article_17\|emit_article_26\|emit_california_sb942\|emit_colorado_ai_act" src/ --include="*.py" | grep -v src/tex/compliance/
(no results)
```

The intended call site (presumably in `commands/evaluate_action.py` after `recorder.record_decision`) does not exist.

---

## 7. `governance/{path_policy, kernel_mcp, stpa_specs}` are tested but never invoked

`governance/__init__.py` describes four subpackages. Only `private_data_exec/ifc` is actually invoked at runtime (via `specialists/ifc_specialist.py:57`).

### Evidence
```
$ grep -rln "from tex.governance.path_policy\|from tex.governance.kernel_mcp\|from tex.governance.stpa_specs" src/ --include="*.py"
(no results outside the governance package itself)
```

Most consequential within this group: `governance/kernel_mcp/syscall_gate.py` (771 lines) implements the MCP syscall gate. `api/mcp_server.py` exposes the MCP server endpoint. The two are not connected — the gate that's supposed to protect the MCP server is not wired in front of it.

---

## 8. `vet/integration.py` is the documented Web Proof glue; never invoked

`vet/integration.py:1-3`:
> "VET integration hook for the `/v1/guardrail` evidence path. When Tex routes a decision through a third-party LLM API the evidence record should carry a Web Proof of the upstream call so auditors can verify the response Tex received was actually produced by the named provider."

### Evidence
```
$ grep -rn "attach_web_proof_to_payload" src/ --include="*.py" | grep -v src/tex/vet/integration.py
(no results)
```

The exported function is not called by any other module in `src/tex/`. The function's entire purpose is integration, and the integration is not done.

---

## 9. `safeflow/` implements a paper, never invoked

`safeflow/__init__.py` describes itself as an implementation of arXiv:2506.07564 (SAFEFLOW, June 2025). The 892 lines have tests but no runtime caller.

### Evidence
```
$ grep -rln "from tex.safeflow\|import tex.safeflow" src/ --include="*.py" | grep -v src/tex/safeflow/
(no results)
```

---

## 10. Two database connection layers

`src/tex/db/connection.py` (used by `db/arcade_leaderboard_repo.py` and `db/leaderboard_repo.py`) and `src/tex/memory/_db.py` (used by everything in `tex/memory/`) both manage Postgres connections. Each `*_postgres.py` store in `src/tex/stores/` opens its own connection as well.

Three independent connection-management approaches. Not breaking anything today, but a unification candidate.

---

## 11. `bench/agentdojo/__main__.py` is FULL_ORPHAN but runnable

The file is invokable directly via `python -m tex.bench.agentdojo`. No `.py` file imports it because it's an entry point. The "orphan" label is correct by static analysis but misleading — this is a CLI tool.

Same for `bench/agentdojo/harness.py` (TEST_ONLY) and the entire `adversarial/` package (TEST_AND_SCRIPT_ONLY) — these are tooling, not runtime code, and their "non-wired" status is correct.

---

## 12. Postgres store branching is asymmetric

`main.py:519-527` swaps to Postgres backends for: `PostgresActionLedger`, `PostgresAgentRegistry`, `PostgresDiscoveryLedger`, `PostgresPrecedentStore`.

It does NOT swap decision_store or policy_store at this site — but they DO get Postgres durability through `tex.memory.MemorySystem` (per main.py:504-510). The two pathways achieve the same goal differently. The code comment at `main.py:509-513` explains this:

> "Decision and policy stores ARE the memory-system's stores. Two parallel implementations (e.g. PostgresDecisionStore + DurableDecisionStore) would write the same rows twice; we use one."

Not actually a bug — but the existence of confusing parallel structures (the deleted `stores/decision_store_postgres.py` was the now-deprecated path) is a real-world signal of unfinished refactor.

---

## 13. `OpenAIAssistantsLiveConnector` is a mock

`src/tex/discovery/connectors/openai_assistants.py:1-3`:
> "Mock connector for OpenAI Assistants / Custom GPTs / Agents."

But the class inside is named `OpenAIAssistantsLiveConnector`. The "Live" in the class name suggests real API calls; the docstring says mock.

The actual live connector is `discovery/connectors/openai_live.py` which defines `OpenAIConnector` (without "Live" in the name).

Two naming inversions in adjacent files.

---

## 14. Empty `.env.example`

`.env.example` is 0 bytes despite extensive env-var-driven configuration. New operators have no scaffold to copy.

---

## Summary

| Category | Examples | Action |
|---|---|---|
| Documentation drift (terminology) | "six-layer" / "seven-stream" / "five-layer" / different "six-layer" | Update docstrings to one canonical naming |
| Decorative flag systems | `FrontierFlags`, `EcosystemFlags` | Either consult them at runtime or delete |
| Self-described integration glue not invoked | `vet/integration.py`, `enforcement/__init__.py`, compliance emitters | Wire or remove |
| Naming inversions | `OpenAIAssistantsLiveConnector` (mock), `OpenAIConnector` (live) | Rename for clarity |
| Empty scaffold | `.env.example` | Populate |
