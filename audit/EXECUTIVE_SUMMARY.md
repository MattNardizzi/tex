# Executive Summary — Tex Audit

> Generated: 2026-05-27
> Method: AST-parse every `.py` file in `src/tex/`, `tests/`, `scripts/`, `sdks/`. Build directed import graph. BFS-reach from `main.py`, tests, and scripts to classify every file. **No claims from docstrings or MD files were used.**

## Headline numbers

| | |
|---|---|
| Total `src/tex/` Python files | **462** |
| Total `src/tex/` lines | ~211,000 |
| Files reachable from `main.py` (WIRED) | **377** |
| Files imported only by tests (TEST_ONLY) | **47** (~9,700 lines) |
| Files imported by tests + demo scripts only | **9** (~3,130 lines) |
| Files with NO importer anywhere (FULL_ORPHAN) | **29** (~675 lines, mostly stubs) |

## The single most important finding

Most of the codebase is wired — 377 of 462 files (~82%) are reachable from `main.py`. The substantial gap is **not "dead code"** — it's **"code that has tests but no production caller."**

About **12,830 lines** of code falls into this category: it's correct in isolation (tests pass), but no runtime path invokes it. Most prominently:

- The entire `enforcement/` package (~1,691 lines) — `TexGate`, `@tex_gated`, framework adapters, ASGI proxy. Per its own design, this is what converts Tex from "decision layer" to "decision-and-enforcement layer." Currently never invoked by main.py.
- The entire active `compliance/` emitter set (~1,768 lines) — EU AI Act articles 17/26/50, FTC, California SB-942, Colorado AI Act, NY AI disclosure. Every emitter is tested. No runtime path fires any emitter.
- The `governance/{kernel_mcp, path_policy, stpa_specs}` subpackages (~2,727 lines) — the MCP syscall gate, path-policy LTLf checker, STPA hazard manifest loader. Tested. Not invoked by `api/mcp_server.py` or the PDP.
- The entire `safeflow/` package (~892 lines) — transactional execution with WAL.
- `vet/integration.py` (241 lines) — the documented integration hook for attaching Web Proofs to live evidence records. Never called.
- Six post-quantum crypto modules (~2,185 lines) — talus_tee, hqc, ml_kem, composite_cms, threshold_ml_dsa, evidence_quorum. Have tests and demos; not added to the lazy-import dispatcher in `algorithm_agility.py`.

## What's truly dead (29 files, ~675 lines)

The FULL_ORPHAN list is mostly small stubs:

- 6 files in `src/tex/_pending/interop/` — A2A, Okta, Microsoft, Ping, NIST stubs (each 11-39 lines, `NotImplementedError` bodies)
- 3 graph/events stubs (`graph/postgres_backend.py`, `graph/janusgraph_backend.py`, `events/quorum_shard.py`) — `class X: pass` bodies
- 4 compliance stubs (`naic/cyber_rider.py`, `naic/model_bulletin.py`, `nist/agent_standards.py`, `nist/ai_rmf.py`) — single function returning empty dict
- 13 `__init__.py` files that nothing imports
- 2 substantive files: `compliance/state/california_ab853_platforms.py` (68 lines) and `california_ab853_capture.py` (55 lines)
- `bench/agentdojo/__main__.py` (137 lines) — runnable as `python -m`, so not really dead

## What's solidly wired

- The seven-stream PDP evaluation (`engine/pdp.py`)
- Hash-chained JSONL evidence log + Postgres mirror (`evidence/`)
- Discovery layer (`discovery/` — connectors, scheduler, alerts, reconciliation, presence tracking)
- Learning loop (`learning/`)
- C2PA Content Credentials emission (`c2pa/`)
- 17 specialist judges (`specialists/`)
- All 22 routers (`api/`) with ~80 HTTP endpoints
- V18 unified memory orchestrator (`memory/`)
- TEE attestation composition (`tee/`)
- Python SDK with `@gate` decorator (`sdks/python/tex_guardrail/`)
- Behavioral contracts via `engine/contract_bridge.py` ← `contracts/`
- The ecosystem engine (`ecosystem/`) — Thread 7 — IS wired and runs eight steps; steps 3-8 invoke their respective packages (`contracts`, `institutional`, `causal`, `drift`, `systemic`, `intervention`) but the deep work in those packages is gated as P1/P2 stubs

## Layer-count clarification

The user describes Tex as a **six-layer architecture**: discovery / identity / monitoring / execution governance / evidence / learning.

The code substantively implements all six:

| Layer | Code home |
|---|---|
| 1. Discovery | `src/tex/discovery/` |
| 2. Identity | `src/tex/agent/` + `stores/agent_registry*.py` + `api/agent_routes.py` |
| 3. Monitoring | `discovery/scheduler.py` + `discovery/alerts.py` + `discovery/presence.py` + `learning/drift.py` + `observability/telemetry.py` |
| 4. Execution governance | `engine/` + `specialists/` (core wired); `governance/path_policy`, `governance/kernel_mcp`, `governance/stpa_specs` (tested, not wired) |
| 5. Evidence | `evidence/` + `memory/` + `c2pa/` + `vet/` (partial — integration glue is TEST_ONLY) + `zkprov/` + `tee/` |
| 6. Learning | `learning/` |

Code-text references to "six-layer pipeline" or "seven streams" refer to the **PDP evaluation pipeline**, which is a different concept from the six architectural layers. The PDP today is seven streams: deterministic / retrieval / agent-identity / agent-capability / agent-behavioral / specialists / semantic.

## Suggested actions (ordered by impact)

### Wire the integration glue (highest leverage)

1. **`vet/integration.py`** → `commands/evaluate_action.py` after semantic-layer call. ~15 lines. Activates Web Proof attestation on every PERMIT decision when the semantic provider is OpenAI.
2. **Compliance emitter registry** → `commands/evaluate_action.py` after `recorder.record_decision`. ~100 lines. Activates EU AI Act / FTC / CA / CO / NY evidence emission.
3. **`governance/kernel_mcp/syscall_gate.py`** → `api/mcp_server.py` wrapped around every JSON-RPC `tools/call`. ~30 lines.
4. **Decide enforcement path** — is `enforcement/` the SDK integration target, or is the Python SDK (`sdks/python/tex_guardrail/`) the one? Currently both exist; only the SDK is wired.

### Cleanup

5. Move the four non-`_pending` stubs (`graph/postgres_backend.py`, `graph/janusgraph_backend.py`, `events/quorum_shard.py`, four compliance NAIC/NIST stubs) into `_pending/` for consistency, OR complete them.
6. Decide whether to wire or remove `safeflow/`. Currently 892 lines of unused transactional-execution machinery.
7. Decide whether the six unused pqcrypto extensions (talus_tee, hqc, ml_kem, composite_cms, threshold_ml_dsa, evidence_quorum) should be added to the `algorithm_agility.py` dispatcher or removed.
