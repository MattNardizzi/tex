# Tex Wiring Fix — Thread Map

> A plan for fixing the integration gaps the audit found, broken into discrete Claude threads.
> Each thread is scoped to be completable in one session without context overflow.
> Read this file at the start of any wiring-fix thread.

## Status as of 2026-05-27

| Thread | Status |
|---|---|
| 1. Wire `vet/integration.py` | **PENDING — highest priority** |
| 2. Wire compliance emitter registry | **PENDING** |
| 3. Wire MCP syscall gate | **PENDING** |
| 4. Decide enforcement direction | **PENDING (decision thread)** |
| 5. Move stray stubs to `_pending/` | ✅ **DONE 2026-05-27** |
| 6. Decide pqcrypto extensions | **PENDING (decision thread)** |
| 7. Wire path policies | **PENDING (lower priority)** |
| 8. Docs hygiene rule + CI check | **PENDING** |
| 9. Pivot residue sweep | ✅ **DONE 2026-05-27** (old `pitch/` package parked in `_pending/pitch/`; all "Tex Aegis" / "AI-SDR" / "VP Marketing" / "cyber-insurance" stale references cleaned) |

## How to use this

For each thread below:

1. Open a new Claude conversation
2. Attach the Tex repo (or paste the relevant files)
3. Open with: **"Read `WIRING_FIX_THREAD_MAP.md`, then execute Thread N. Use only verified code evidence — no claims from any doc unless the code confirms it."**
4. Claude does the work, runs the verification commands, returns the changed files
5. You review, commit, move to the next thread

**Order matters.** Threads 1-4 are the high-impact wiring fixes. Threads 5-7 are cleanup. Threads 8-9 are deferred-decision threads — do those after the wiring works.

Each thread has:
- **Goal** — what the thread accomplishes in one sentence
- **Files to touch** — exact paths
- **Verification** — how to confirm the thread worked
- **Estimated effort** — Claude-time, not your time
- **Risk** — what could break

---

## Thread 1: Wire `vet/integration.py` into the live evidence path

**THIS IS THE HIGHEST-IMPACT SINGLE CHANGE IN THE CODEBASE.**

### Goal
When the semantic layer makes an OpenAI API call during a PDP evaluation, attach a Web Proof of that call to the evidence record. Activates the "Tex proves it" capability for every production-mode decision.

### Files to touch
- `src/tex/commands/evaluate_action.py` — add ~15 lines of integration code after the semantic layer call
- `src/tex/vet/integration.py` — verify `attach_web_proof_to_payload` signature; adjust if needed
- `src/tex/api/schemas.py` — possibly add `web_proof` field to the evidence-bundle response model
- `tests/test_thread13_integration.py` (or new file) — integration test confirming Web Proof is attached on PERMIT-with-OpenAI

### Approach for Claude
1. Read `vet/integration.py` top to bottom — understand the existing `attach_web_proof_to_payload` and any helpers
2. Read `commands/evaluate_action.py` — find the point AFTER `_run_semantic_layer` returns and BEFORE `recorder.record_decision` is called
3. Check `semantic/openai_provider.py` (or similar) — confirm we can capture the request/response pair needed for Web Proof
4. Insert the integration: if semantic provider was OpenAI and verdict is PERMIT, build a Web Proof and attach it to the evidence payload
5. Add a unit test that asserts: given a PERMIT decision with `TEX_SEMANTIC_PROVIDER=openai`, the resulting evidence record contains a `web_proof` field with a valid structure
6. Run the existing test suite to confirm no regression

### Verification
```bash
pytest tests/vet/ tests/test_pdp.py tests/test_thread13_integration.py
grep -n "attach_web_proof_to_payload" src/ tests/ --include="*.py"
# After fix, should show at least one call from commands/evaluate_action.py
```

### Estimated effort
1 thread, ~30 minutes of Claude time. Self-contained.

### Risk
- Low. The integration is additive — if Web Proof generation fails, fall back silently (log and continue). Don't let Web Proof failure block a decision.
- Verify the "fail-soft" behavior is explicit in the code.

---

## Thread 2: Wire the compliance emitter registry

### Goal
After every decision is recorded, fire applicable compliance emitters (EU AI Act Articles 17/26/50, FTC, California SB-942, Colorado AI Act, NY AI Disclosure) to produce parallel regulatory evidence records.

### Files to touch
- `src/tex/compliance/registry.py` — NEW FILE. Builds the emitter registry and applicability rules.
- `src/tex/commands/evaluate_action.py` — call the registry after `recorder.record_decision`
- `src/tex/evidence/recorder.py` — possibly add `record_compliance(parent_decision_id, record)` method that chains the new record to the parent
- `tests/test_compliance_wired.py` — NEW. Integration test that asserts a decision produces N additional evidence records when N emitters apply.

### Approach for Claude
1. Read all files in `src/tex/compliance/` to understand the emitter API
2. Read `compliance/_common.py` for shared base classes
3. Design `ComplianceEmitterRegistry`:
   - Each emitter declares its applicability (jurisdiction, decision type, agent attributes)
   - Registry iterates applicable emitters for a given request/decision pair
   - Returns list of (emitter_name, evidence_record) tuples
4. Modify `commands/evaluate_action.py` to call the registry after the main evidence record is written, and write each emitter's output as a child evidence record linked to the parent
5. Add tests for: (a) decision with no applicable emitters produces 1 record (b) decision with 3 applicable emitters produces 4 records (c) emitter failure does not block the decision

### Verification
```bash
pytest tests/test_compliance_wired.py tests/frontier/test_compliance.py
# Should see EU AI Act, FTC, California emitter coverage
```

### Estimated effort
1-2 threads, ~60-90 minutes of Claude time. The registry design needs care; the integration is straightforward.

### Risk
- Medium. If an emitter raises, must NOT block the decision. Wrap each emitter in try/except, log on failure, continue.
- Don't fire emitters for environments where they don't apply (dev/test). Gate by `TEX_APP_ENV`.

---

## Thread 3: Wire `governance/kernel_mcp/syscall_gate.py` into the MCP server

### Goal
Every JSON-RPC `tools/call` arriving at the `/mcp` endpoint must pass through the six-stage MCP syscall gate before being processed.

### Files to touch
- `src/tex/api/mcp_server.py` — wrap the `tools/call` handler with the syscall gate
- `src/tex/governance/kernel_mcp/syscall_gate.py` — verify the `SyscallGate.gate(call)` async API is suitable for HTTP request context; adjust signature if needed
- `tests/test_mcp_server_gated.py` — NEW. Tests confirming: (a) benign `tools/call` passes through (b) malicious `tools/call` is blocked (c) gate failure is fail-closed (no passthrough)

### Approach for Claude
1. Read `api/mcp_server.py` end to end — find the JSON-RPC `tools/call` dispatch
2. Read `governance/kernel_mcp/syscall_gate.py` to understand the gate API
3. Read `governance/kernel_mcp/capability.py` for capability token semantics
4. Construct a `SyscallGate` instance in the MCP server initialization
5. Before dispatching to the underlying tool, call `gate.evaluate(call_context)`. On FORBID, return JSON-RPC error. On PERMIT, proceed.
6. On any exception in the gate, fail closed (return JSON-RPC error). Do not let gate failure result in tool execution.
7. Add tests with example malicious payloads (use AgentDojo or MCPSafeBench fixtures from `tex.adversarial.fixtures`)

### Verification
```bash
pytest tests/test_mcp_server_gated.py tests/governance/
# Manual: curl an MCP tools/call that's known to be blocked and verify FORBID response
```

### Estimated effort
1 thread, ~45 minutes.

### Risk
- Medium-high. The MCP endpoint is on the live customer path. A bug in the gate that incorrectly blocks legitimate calls would be a real outage.
- Mitigation: ship behind a feature flag `TEX_MCP_GATE_MODE` with values `off | shadow | enforce`. Start in `shadow` (gate runs, logs decisions, but does not block). Promote to `enforce` after a week of clean shadow data.

---

## Thread 4: Decide the enforcement direction

### Goal
Resolve the duplication between `src/tex/enforcement/` and `sdks/python/tex_guardrail/`. Either wire `enforcement/` into the runtime as a first-party integration target, or consolidate to the SDK and delete `enforcement/`.

### Files to touch
- Depends on the decision.

### Approach for Claude
**This is a decision thread, not a coding thread.** Have Claude produce a decision document with:

1. Side-by-side comparison of `enforcement/` and `sdks/python/tex_guardrail/`:
   - Which integration patterns each supports (decorator, framework adapter, ASGI proxy, HTTP client)
   - Which one has tests
   - Which one is more aligned with how customers actually integrate
2. Two concrete proposals:
   - **Path A: Keep both.** `enforcement/` is the in-process integration; SDK is the HTTP integration. Document the choice explicitly. Add a chapter to ARCHITECTURE.md saying when to use which.
   - **Path B: Consolidate to the SDK.** Delete `enforcement/`. The SDK becomes the canonical integration. Migrate any unique value from `enforcement/adapters.py` (LangChain/CrewAI/MCP middleware) into the SDK.
3. Recommendation with reasoning.

You make the call. Then a follow-up thread implements the chosen path.

### Estimated effort
1 thread for the decision doc (~30 min). 1-3 threads for execution depending on the path chosen.

### Risk
- The decision matters more than the execution. Don't let Claude pick — Claude can lay out the options, but the choice is yours.

---

## Thread 5: Move stray stubs into `_pending/`

### Goal
The `_pending/` convention (underscore prefix = parked work) is good. Apply it consistently. Move the 4 non-`_pending` stubs into `_pending/` for visual clarity.

### Files to touch
- Move: `src/tex/graph/postgres_backend.py` → `src/tex/_pending/graph/postgres_backend.py`
- Move: `src/tex/graph/janusgraph_backend.py` → `src/tex/_pending/graph/janusgraph_backend.py`
- Move: `src/tex/events/quorum_shard.py` → `src/tex/_pending/events/quorum_shard.py`
- Move: `src/tex/compliance/naic/cyber_rider.py` → `src/tex/_pending/compliance/naic/cyber_rider.py`
- Move: `src/tex/compliance/naic/model_bulletin.py` → `src/tex/_pending/compliance/naic/model_bulletin.py`
- Move: `src/tex/compliance/nist/ai_rmf.py` → `src/tex/_pending/compliance/nist/ai_rmf.py`
- Move: `src/tex/compliance/nist/agent_standards.py` → `src/tex/_pending/compliance/nist/agent_standards.py`
- Update any references in `tests/ecosystem/test_ecosystem_imports.py` and `src/tex/events/ledger.py` docstring

### Approach for Claude
1. For each file, grep all references in `src/`, `tests/`, `scripts/`, `sdks/`
2. Move the file
3. Update references (with care — test_ecosystem_imports might be checking that these modules CAN be imported; that test may need to be deleted or moved)
4. Run full test suite

### Verification
```bash
pytest
python3 audit/orphans/build_code_evidence_registry.py
# All moved files should now show under _pending/, not as stand-alone FULL_ORPHANs
```

### Estimated effort
1 thread, ~30 minutes. Mechanical.

### Risk
- Low, if references are updated correctly.

---

## Thread 6: Decide the pqcrypto extensions (wire or remove)

### Goal
Six pqcrypto modules are TEST_AND_SCRIPT_ONLY: `talus_tee`, `hqc`, `ml_kem`, `composite_cms`, `threshold_ml_dsa`, `evidence_quorum`. ~2,185 lines total. Decide per-module: add to the `algorithm_agility.py` dispatcher, or move to `_pending/`.

### Approach for Claude
**Decision thread.** Produce a per-module recommendation:

| Module | Decision criteria |
|---|---|
| `evidence_chain_signer.py` | Currently the most plausible "next wire-in" — replaces ECDSA in the events ledger with ML-DSA. WIRE recommended. |
| `talus_tee.py` | TALUS-TEE threshold ML-DSA. Has tests + demo. Wire only if a customer demand path exists. |
| `evidence_quorum.py` | Quorum signing for high-stakes records. Wire if customer wants multi-party signed evidence. |
| `hqc.py`, `ml_kem.py` | KEM/encryption. Wire only when encrypted evidence transport is a customer ask. |
| `composite_cms.py` | CMS format for X.509/PKI. Wire only on PKI integration ask. |
| `threshold_ml_dsa.py` | Underlying Mithril threshold scheme. Wired by `talus_tee.py`. Decision is downstream of TALUS. |

Implementation: one or two follow-up threads to either wire the keepers into `algorithm_agility.py` lazy dispatch or move the rest to `_pending/pqcrypto/`.

### Estimated effort
1 decision thread + 1 implementation thread.

### Risk
- Low. PQ modules are not on the critical path. Deletions are safe; wiring is additive.

---

## Thread 7: Wire `governance/path_policy/` (deferred, lower priority)

### Goal
Path policies (LTLf temporal logic over agent action sequences) are tested but not invoked. Wire `PathPolicyChecker` into the PDP as an 8th evaluation stream OR as a sibling check to behavioral contracts.

### Files to touch
- `src/tex/engine/pdp.py` — add path policy check
- `src/tex/governance/path_policy/checker.py` — verify the check API is suitable
- `tests/governance/` — integration tests

### Approach for Claude
1. Read all files in `governance/path_policy/` end to end
2. Determine: is this conceptually closer to behavioral contracts (gate on session history) or a new evaluation stream?
3. If the former: wire alongside `engine/contract_bridge.py`
4. If the latter: add to `pdp.py:evaluation_order`
5. Decide based on the actual LTLf semantics in the code, not on intuition

### Estimated effort
1-2 threads.

### Risk
- Medium. Adding a stream changes routing weights. May need calibration. Ship in shadow mode first.

---

## Thread 8: Documentation hygiene rule

### Goal
Prevent the documentation drift problem from recurring.

### Approach for Claude
Produce a `DOCS_RULE.md` at the repo root with three rules:

1. **No claim files.** Any markdown that describes what the code does must be either (a) generated from code on every build, or (b) reviewed every week. Otherwise it gets deleted.
2. **Every new package gets a `__layer__` constant and an `[Architecture: ...]` docstring header.** Enforce via a pre-commit hook.
3. **`audit/orphans/build_code_evidence_registry.py` runs in CI.** If a file moves from WIRED to FULL_ORPHAN without an explicit `# orphan: intentional` marker, CI fails.

Then write the CI check.

### Estimated effort
1 thread for the rule, 1 thread for the CI check.

### Risk
- Low. Process hygiene, not runtime risk.

---

## Thread 9: Pivot residue cleanup

### Goal
Audit the codebase for fossilized GTM language from previous pivots.

### Approach for Claude
1. Grep for "AI-SDR", "Tex Aegis", "VP Marketing", "cyber insurance" (and any other previous-positioning terms) in all `.py`, `.md`, `.toml`, `.sh` files
2. For each hit, classify: (a) genuinely stale claim → fix or delete, (b) historical context that's still accurate → leave alone, (c) ambiguous → flag for your review
3. Produce a list with the recommended action per file

### Estimated effort
1 thread, ~30 minutes.

### Risk
- Low. Cosmetic. Don't auto-delete; flag and let you review.

---

## Recommended execution order

If you can only do four threads, do **1, 2, 3, 5** in that order. Those are the highest leverage and lowest risk.

If you have time for all nine, the order is:

1. **Thread 1** — vet/integration.py (THE single most important wire-up)
2. **Thread 2** — compliance emitter registry (your regulatory pitch)
3. **Thread 3** — MCP syscall gate (governs the MCP endpoint)
4. **Thread 5** — move stubs to `_pending/` (cleanup, low risk, makes the codebase visually honest)
5. **Thread 4** — enforcement vs SDK decision (do after 1-3 so you can decide with more clarity about what "wired" means in your codebase)
6. **Thread 6** — pqcrypto decision (less urgent, can wait)
7. **Thread 8** — docs hygiene rule + CI (prevent regression)
8. **Thread 9** — pivot residue cleanup (cosmetic but worth doing)
9. **Thread 7** — path policies (most complex, do last)

## After every thread

Run:
```bash
python3 audit/orphans/build_code_evidence_registry.py
pytest
```

If the orphan registry moves files from TEST_ONLY into WIRED, you're winning. The goal is for the TEST_ONLY count to drop from ~47 today to under 20 over the course of these threads.

## What success looks like at the end

- `vet/integration.py` is called from `commands/evaluate_action.py`
- Compliance emitters fire on every applicable decision
- MCP syscall gate sits in front of the MCP server
- `enforcement/` either wired or deleted (one path, not two)
- All non-`_pending` stubs moved to `_pending/` or completed
- CI runs the orphan check and fails on regression
- The "evidence on demand" demo works end-to-end against a live deployment

When all that's true, your code matches your pitch. That's the goal.
