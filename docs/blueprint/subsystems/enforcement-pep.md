# Subsystem Dossier: Enforcement / PEP body / safeflow

> Scope: `src/tex/enforcement`, `src/tex/pep`, `src/tex/safeflow`
> Branch: `feat/proof-carrying-gate`
> Method: code-read and grep-traced. Every claim is cited `file:line`. Docstring/`.md` claims are labelled `(claim, unverified)` unless confirmed in code.

---

## Overview

This unit is the **body** in Tex's brain→body split. The *brain* (the PDP — `StandingGovernance` at `governance/standing.py`, served at `/v1/govern`) decides PERMIT / ABSTAIN / FORBID. This unit is what makes a verdict *physically stop or allow an action*, plus the proof-carrying receipt and the transactional-undo discipline around it.

Three packages, three deployment shapes of one idea:

1. **`enforcement`** — the **in-process gate**. `TexGate` wraps a Python callable so it cannot run unless the PDP permits. `StandingGovernanceTransport` is the brain→body join (routes the gate check through the full two-tier standing PDP). `seal.py` adds the **proof-carrying** layer: a `SealingGateObserver` seals one `SealedFact(ENFORCEMENT)` per gate decision into the real `SealedFactLedger`.
2. **`pep`** — the **network data-plane PEP**: a transparent MCP/HTTP enforcement proxy (`TexEnforcementProxy`) run as a sidecar (`python -m tex.pep`). For every egress request it maps to a `Decision`, asks the PDP via a `DecisionClient`, and obeys `released` — forward upstream on PERMIT, 403 otherwise.
3. **`safeflow`** — **transactional execution**: a WAL + inverse-op rollback executor (`TransactionalExecutor`) implementing the SAFEFLOW paper's ACID-style discipline so a multi-step agent plan can be undone deterministically.

**Headline wiring reality (verified):**
- The **plain in-process gate** is **LIVE**: `main.py:1756` builds it into `app.state.standing_gate` during app construction — but **no route or other code reads `app.state.standing_gate`** (`grep` over `src/tex/api/` returns nothing). It is constructed-and-parked.
- The **proof-carrying gate** (`build_proof_carrying_gate` / `SealingGateObserver` — the branch's headline feature) is **NOT wired into the running app**: its only callers are the package itself and one test. **DEMO_TEST_ONLY.**
- The **network PEP** (`tex.pep`) is **ORPHAN to the Python app**: nothing imports it except its own `__main__`; it is referenced only as a container `command` string in a k8s sidecar spec (`operator/webhook.py:81`), and `tex.operator` is itself an orphan package.
- **`safeflow`** is **ORPHAN to the app**: no non-test, non-self importer anywhere.

The spine pass classified `enforcement=LIVE, pep=ORPHAN, safeflow=INDIRECT`. My verification: `enforcement` is LIVE-but-parked (constructed, never consumed); `pep` ORPHAN confirmed; `safeflow` is DEMO_TEST_ONLY (only a test imports it) — I downgrade it from INDIRECT.

---

## File Inventory

### `src/tex/enforcement/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 116 | Package facade; re-exports gate/transport/seal/errors/events; `__layer__=4`. Docstring concedes "built but not invoked by the runtime today". |
| `gate.py` | 582 | **Core primitive.** `TexGate` (sync) + `TexGateAsync`, `GateConfig`, `AbstainPolicy`, `tex_gated`/`tex_gated_async` decorators. Turns a verdict into "the action did/didn't happen". |
| `transport.py` | 257 | `TexEvaluationTransport` protocol + 3 transports: `DirectCommandTransport`, `HttpClientTransport`, `CallableTransport`. `TransportResult` dataclass. |
| `standing_transport.py` | 146 | `StandingGovernanceTransport` (the brain→body join) + `build_standing_gate` one-call constructor. Routes every check through the full two-tier PDP. |
| `seal.py` | 125 | **Proof-carrying layer.** `SealingGateObserver` + `build_proof_carrying_gate` — seals one ENFORCEMENT fact per gate decision into a `SealedFactLedger`. |
| `events.py` | 112 | `GateEvent` (frozen audit record), `GateEventObserver` protocol, `NullObserver`, `CollectingObserver`. |
| `errors.py` | 104 | Typed error hierarchy: `TexEnforcementError` → `TexForbiddenError` / `TexAbstainError` / `TexUnavailableError`. |
| `adapters.py` | 291 | Framework adapters: LangChain (sync+async), CrewAI, MCP server middleware. Lazy framework imports. |

### `src/tex/pep/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 15 | Package doc; `__all__ = []`. Notes the eBPF kernel-floor PEP lives outside the Python package under `pep/kernel`. |
| `__main__.py` | 81 | `python -m tex.pep` entrypoint. Builds the proxy from env vars (http vs inprocess PDP mode), serves via uvicorn. |
| `proxy.py` | 385 | `TexEnforcementProxy` (the PEP core), `ProxyConfig`, `Forwarder`/`HttpxForwarder`, `build_proxy_app` (Starlette catch-all). MCP-aware; filtered tool discovery. |
| `decision_client.py` | 168 | `Decision`/`DecisionResult` DTOs + `DecisionClient` interface + `InProcessDecisionClient` (calls `StandingGovernance.decide`) and `HttpDecisionClient` (POST `/v1/govern/decide`). |

### `src/tex/safeflow/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 102 | Package facade; `__layer__=4`. Docstring cites SAFEFLOW arxiv 2506.07564; concedes "built but not invoked by the runtime today". |
| `executor.py` | 388 | `TransactionalExecutor` (begin/step/commit/abort/recover lifecycle), `TransactionOutcome`, `SafeflowError`. Drives WAL + rollback. |
| `transaction.py` | 103 | `Transaction` / `TransactionStep` / `TransactionState` (pydantic frozen value objects); SHA-256 hash over step sequence. |
| `wal.py` | 224 | `WALEntry`/`WALEntryKind`, `WAL` protocol, `InMemoryWAL`, `FileWAL` (newline-JSON, fsync per append), `replay()` for recovery. Per-entry `prev_hash` chain. |
| `rollback.py` | 85 | `InverseOpRegistry` (process-global) + `register_inverse`/`get_inverse`/`default_registry`. Inverse-op contract for undo. |

---

## Internal Architecture

### enforcement — the gate

**`TexGate` (`gate.py:121`)** is the smallest unit that converts "Tex returned a verdict" into "the action did or did not happen." It is stateless except for a `GateConfig` reference (`gate.py:144-147`). Two interfaces:

- **Imperative `check()` (`gate.py:151`):** builds an `EvaluationRequest` (`gate.py:180`), calls `self._config.transport.evaluate(request)` (`gate.py:193`), and branches on the verdict:
  - `Verdict.PERMIT` (`gate.py:211`) → emit `outcome="executed"`, return the response.
  - `Verdict.FORBID` (`gate.py:221`) → emit `outcome="blocked"`, `raise TexForbiddenError` (`gate.py:229`). **No flag overrides this** — there is no code path that lets FORBID through.
  - `ABSTAIN` → governed by `AbstainPolicy` (`gate.py:241`): `ALLOW` returns the response with `abstain_overridden=True`; `BLOCK`/`REVIEW` raise `TexAbstainError` (`gate.py:262`).
  - Transport failure (`result.response is None`, `gate.py:197`) → `_handle_transport_failure` (`gate.py:322`): fail-closed (default) raises `TexUnavailableError`; fail-open returns a synthetic ABSTAIN response (`_synthetic_unavailable_response`, `gate.py:555` — verdict=ABSTAIN, *never* PERMIT, `gate.py:570`).
- **`wrap()` (`gate.py:276`):** returns a `functools.wraps`-decorated callable that pulls `content` (and optional `recipient`) from kwargs, calls `check()`, and only invokes the wrapped `fn` if `check()` did not raise (`gate.py:308-316`).

Every gated execution emits **exactly one** `GateEvent` via `_emit` (`gate.py:352`), inside a `try/except` that swallows observer failures (`gate.py:387-390`) so a buggy observer can never break enforcement. This single-event guarantee is what the proof layer hangs off.

**`TexGateAsync` (`gate.py:398`)** wraps `TexGate` and dispatches the sync `check` onto a thread via `asyncio.to_thread` (`gate.py:430`).

**Transports (`transport.py`):** the gate is transport-agnostic. `DirectCommandTransport` (`transport.py:69`) calls `EvaluateActionCommand.execute` in-process; `HttpClientTransport` (`transport.py:111`) POSTs to a remote `/evaluate` (duck-typed client, no hard httpx dep); `CallableTransport` (`transport.py:218`) wraps any callable. All catch every exception and return `response=None` so the gate's fail-closed logic owns the policy decision (`transport.py:89,159,243`).

**The brain→body join — `StandingGovernanceTransport` (`standing_transport.py:69`):** this is the load-bearing adapter. Its `evaluate` (`standing_transport.py:84`) calls `self._governance.decide_for_request(request, tenant=...)` (`standing_transport.py:87`) — the full two-tier PDP. The deep tier carries an authoritative `EvaluationResponse` (`outcome.response`); a floor (Tier-1) verdict has no rich response, so `_floor_response` (`standing_transport.py:40`) synthesizes one tagged `policy_version=f"standing-floor:{tier}"` (`standing_transport.py:63`). `build_standing_gate` (`standing_transport.py:112`) is the one-call constructor that assembles `GateConfig(transport=StandingGovernanceTransport(...))`.

**The proof layer — `seal.py`:** `build_proof_carrying_gate` (`seal.py:86`) = `build_standing_gate(...)` **plus** a `SealingGateObserver` (`seal.py:44`) installed as the gate's observer. On each `GateEvent` the observer calls `seal_enforcement(ledger, event, ...)` (`seal.py:73`, implemented in `provenance/enforcement_seal.py:116`) and accumulates `SealedFactRecord`s. Per the observer contract it **never raises** — a sealing failure lands in `self.last_error` (`seal.py:78-79`). Returns `(gate, observer)`; the durable proof lives in `observer.ledger`.

**`build_enforcement_fact` (`provenance/enforcement_seal.py:56`)** maps one `GateEvent` → a `SealedFact(SealedFactKind.ENFORCEMENT)` with a deliberately narrow claim: it asserts only that the gate **allowed/blocked** the action and (when an `AttestedIdentity` was verified) *who* took it — and explicitly **"verdict correctness NOT proven"** (`enforcement_seal.py:86-87`). Maturity is pinned `EvidenceMaturity.RESEARCH_SOLID` (`enforcement_seal.py:53`) precisely because the ledger is not yet externally time-anchored.

### pep — the network proxy

**`TexEnforcementProxy.handle` (`proxy.py:140`)** is the data-plane core (frame-agnostic; `build_proxy_app` at `proxy.py:352` wraps it in a Starlette catch-all route). Flow:
1. Resolve upstream from `X-Tex-Upstream` header or reconstruct from `Host` (`proxy.py:150`); refuse with FORBID if none ("refusing to forward blind", `proxy.py:152`).
2. Resolve identity/tenant/session from `X-Tex-*` headers, with sidecar defaults from `ProxyConfig` (`proxy.py:156-161`).
3. `_to_decision` (`proxy.py:197`) maps the request to a `Decision`. **MCP-aware:** a JSON-RPC `tools/call` is keyed by tool name (action) + arguments (content) (`proxy.py:219-224`); `tools/list` becomes a filtered-discovery action (`proxy.py:225-228`); plain HTTP folds a bounded body slice into content (`proxy.py:233-235`).
4. `result = self._decide.decide(decision)` (`proxy.py:174`). If `not result.released` → `_refuse(...)` returns a 403 with `{"forbidden": true, "verdict": ..., "spoken": reason}` (`proxy.py:301`).
5. PERMIT → strip hop-by-hop + routing headers (`_STRIP_HEADERS`, `proxy.py:104`) and forward via the `Forwarder` (`proxy.py:179-181`).
6. **Filtered discovery (`_filter_tools_list`, `proxy.py:252`):** only when the governor is in-process. Resolves the agent's `capability_surface` (`_resolve_surface`, `proxy.py:283`, calls `gov._resolve_agent` — a private method) and strips tools the agent may not call from the `tools/list` response so it "never learns a tool it may not call exists" (`proxy.py:14-15`).

**`DecisionClient` (`decision_client.py:63`):** `InProcessDecisionClient.decide` (`decision_client.py:78`) calls `self._governance.decide(...)` and is **fail-closed on any exception** (`decision_client.py:91-92`). `HttpDecisionClient.decide` (`decision_client.py:135`) POSTs to `/v1/govern/decide` and treats any transport/HTTP≥400/parse error as `DecisionResult.fail_closed(...)` (`decision_client.py:151-159`). The one field the proxy obeys is `released` (`decision_client.py:50`).

### safeflow — transactional execution

**`TransactionalExecutor` (`executor.py:102`)** drives one `Transaction` (one executor per transaction, `__slots__` at `executor.py:108`). Lifecycle mirrors the SAFEFLOW paper §4 (claim in docstring `executor.py:11`, not independently verified against the paper):
- `begin()` (`executor.py:145`) → WAL `BEGIN`.
- `step()` (`executor.py:156`) → validates state PENDING and that any declared `inverse_op` is registered (`executor.py:168`) and the tool impl exists (`executor.py:173`); writes `STEP_BEFORE`, runs the tool, writes `STEP_AFTER`. On tool exception: writes `STEP_AFTER` with the error and calls `abort()` (`executor.py:192-214`). On success: stashes `{tool,args,result}` for the inverse (`executor.py:229-230`).
- `commit()` (`executor.py:242`) → state COMMITTED, WAL `COMMIT`.
- `abort()` (`executor.py:261`) → idempotent re-abort guard; marks FAILED, WAL `ABORT`, runs `_rollback`, transitions to ROLLED_BACK if no inverse failures.
- `_rollback()` (`executor.py:303`) → iterates `reversed(self._txn.steps)`, skips steps with no `inverse_op` or with a forward error, looks up the inverse fn, writes `ROLLBACK_BEFORE`, invokes `inverse(tool=, args=, result=)`, writes `ROLLBACK_AFTER`. **Inverse failures are recorded but do not stop the loop** (`executor.py:334-339`).
- `recover()` (`executor.py:295`) → `replay(self._wal.read_all())` (`wal.py:194`) returns per-txn terminal state.

**WAL chain (`wal.py`):** every `WALEntry` carries `prev_hash` and a derived `hash` (SHA-256 of canonical JSON, `wal.py:71-82`). `InMemoryWAL.append` and `FileWAL.append` both enforce sequence monotonicity and `prev_hash` continuity, raising on mismatch (`wal.py:107-117`, `wal.py:164-170`). `FileWAL` writes newline-delimited canonical JSON and **`os.fsync`s on every append** (`wal.py:172-176`) — the load-bearing durability property.

**Rollback registry (`rollback.py`):** `InverseOpRegistry` is a process-global dict (`rollback.py:36`, instance at `rollback.py:63`). `register` validates name is alnum/underscore and forbids re-registration (`rollback.py:44-51`). The docstring states irreversible tools (`send_email`, `transfer_funds`) cannot participate — this is enforced by *omission* (no inverse registered → `step()` rejects at `executor.py:168`), not by a hardcoded denylist.

---

## Public API

**`tex.enforcement`** (`__init__.py:95`): `TexGate`, `TexGateAsync`, `GateConfig`, `AbstainPolicy`, `tex_gated`, `tex_gated_async`, `DirectCommandTransport`, `HttpClientTransport`, `TexEvaluationTransport`, `StandingGovernanceTransport`, `build_standing_gate`, `SealingGateObserver`, `build_proof_carrying_gate`, `GateEvent`, `GateEventObserver`, `NullObserver`, and the four error types. (`CallableTransport`, `CollectingObserver`, and the framework adapters in `adapters.py` are public-importable but not in `__all__`.)

**`tex.pep`** (`__init__.py:15`): `__all__ = []` — nothing exported at package level. The usable surface is `tex.pep.proxy` (`ProxyConfig`, `Forwarder`, `HttpxForwarder`, `TexEnforcementProxy`, `build_proxy_app`) and `tex.pep.decision_client` (`Decision`, `DecisionResult`, `DecisionClient`, `InProcessDecisionClient`, `HttpDecisionClient`). The de-facto entrypoint is `python -m tex.pep` (`__main__.py:72`).

**`tex.safeflow`** (`__init__.py:88`): `TransactionalExecutor`, `TransactionOutcome`, `SafeflowError`, `Transaction`, `TransactionState`, `TransactionStep`, `WAL`, `WALEntry`, `WALEntryKind`, `InMemoryWAL`, `FileWAL`, `InverseOpRegistry`, `register_inverse`.

**Cross-unit dependency:** `tex.enforcement.seal` and `tex.provenance.enforcement_seal` are two halves of one feature — `seal.py:33` imports `seal_enforcement` from provenance; provenance avoids the reverse import cycle by importing `GateEvent`/`AttestedIdentity` only under `TYPE_CHECKING` (`enforcement_seal.py:44-46`).

---

## Wiring

### In (who imports the public symbols)

grep across `src/tex` for importers of each unit's public symbols (excluding the units' own files):

- **enforcement:** the **only** non-self importer in `src/tex` is **`main.py:1754`** (`from tex.enforcement.standing_transport import build_standing_gate`). Nothing else in the app imports `TexGate`, the adapters, the transports, or the seal. (`provenance/enforcement_seal.py:45` imports `GateEvent` only under `TYPE_CHECKING`.)
- **pep:** **no Python importer** anywhere except `pep/__main__.py` (self). The only other reference is a **string** `"command": ["python", "-m", "tex.pep"]` in the k8s sidecar spec at `operator/webhook.py:81`. `tex.operator` is itself an orphan package (its sole non-test footprint is this webhook builder; nothing in `main.py`/`build_runtime` imports it).
- **safeflow:** **no non-test, non-self importer** anywhere in `src/tex`.

### Live call path

**Plain in-process gate — LIVE but parked.** The one real call chain into this unit:

```
create_app()                       main.py:1309
  └─ _attach_runtime_to_app(app, runtime)   main.py:1377 / 1389 / 1428  → 1586
       ├─ app.state.standing_governance = StandingGovernance(...)   main.py:1739
       └─ build_standing_gate(app.state.standing_governance)         main.py:1756
            └─ app.state.standing_gate = <TexGate>
```

`build_standing_gate` (`standing_transport.py:112`) constructs a real `TexGate` whose transport is `StandingGovernanceTransport`, so a check would route through the live PDP. **However:** `grep -rn "standing_gate" src/tex/api/` returns **nothing** — `app.state.standing_gate` is **set and never read** by any route or other runtime code. The gate is constructed during boot and parked on app state with no consumer. So: the unit is *reachable from `create_app`* (hence "LIVE" in the import-graph sense) but *not exercised by any request path*.

**Proof-carrying gate — DEMO_TEST_ONLY.** `build_proof_carrying_gate` / `SealingGateObserver` (the branch's headline) have **zero** callers outside the `enforcement` package itself. Sole exerciser: `tests/enforcement/test_proof_carrying_gate.py` (which drives the *real* `StandingGovernance` PDP and `SealedFactLedger`, doubling only the agent registry + deep evaluator — confirmed in the test's own docstring `lines 1-10`). It is **not** invoked from `main.py`, `build_runtime`, or any API route.

**Network PEP — ORPHAN to the app.** `TexEnforcementProxy`/`build_proxy_app` are only assembled in `pep/__main__.py:54-69`, reachable solely via `python -m tex.pep` as a standalone sidecar process. It is never mounted into the FastAPI app and never imported by `main.py`. The k8s `operator` webhook would inject it as a sidecar container at deploy time (`operator/webhook.py:81`), but that path is a deployment artifact, not a Python call edge, and `operator` is itself orphaned.

**safeflow — DEMO_TEST_ONLY.** Only `tests/frontier_thread_12/test_safeflow.py` imports it.

### Out (dependencies)

**enforcement depends on (internal):** `tex.domain.evaluation` (`EvaluationRequest`/`EvaluationResponse`), `tex.domain.verdict` (`Verdict`), `tex.commands.evaluate_action` (`EvaluateActionCommand`, used by `DirectCommandTransport`), `tex.governance.standing` (`StandingGovernance`, `DecisionOutcome` — the brain), and for the seal: `tex.provenance.enforcement_seal`, `tex.provenance.ledger` (`SealedFactLedger`), `tex.provenance.models` (`SealedFact`/`SealedFactKind`/`SealedFactRecord`), `tex.domain.evidence` (`EvidenceMaturity`), `tex.identity.agent_credential` (`AttestedIdentity`, type-only).
**External libs:** stdlib only in the core (`asyncio`, `functools`, `dataclasses`, `enum`, `hashlib`). `adapters.py` imports `langchain`/`crewai` **lazily** inside functions (`adapters.py:56,129,264`) with actionable `ImportError`s; `HttpClientTransport` is duck-typed (no hard httpx).

**pep depends on (internal):** `tex.pep.decision_client`; in-process mode pulls `tex.main.build_runtime`, `tex.governance.standing.StandingGovernance` (`__main__.py:42-47`).
**External libs:** `starlette` (in `build_proxy_app`, imported lazily at `proxy.py:357`), `httpx` (lazy in `HttpxForwarder.send` `proxy.py:92`, and `__main__.py:58`), `uvicorn` (lazy in `main()` `__main__.py:73`). All lazy — the package imports clean with none installed.

**safeflow depends on (internal):** nothing outside `safeflow` (self-contained).
**External libs:** `pydantic` (models), stdlib `hashlib`/`json`/`os`/`pathlib`/`time`.

---

## Implementation Reality

**Real logic (not stubs):**

- **The gate's enforcement is real.** FORBID raises with no override path (`gate.py:221-238`); PERMIT passes through; fail-closed transport failure raises `TexUnavailableError` (`gate.py:342-350`); fail-open returns a synthetic ABSTAIN (never PERMIT) (`gate.py:570`). Single-`GateEvent` guarantee holds with observer-failure suppression (`gate.py:387-390`).
- **The brain→body join is real.** `StandingGovernanceTransport.evaluate` actually calls `decide_for_request` (`standing_transport.py:87`), which exists and runs the two-tier PDP (`governance/standing.py:333`, delegating to `decide` at `standing.py:261`). `DecisionOutcome` carries the real deep `response` for Tier-2 and is synthesized for floor verdicts.
- **The proof/crypto is real, with a graceful PQ fallback.** The ENFORCEMENT seal lands on a genuine `SealedFactLedger` whose `append` (`provenance/ledger.py:424`) builds a SHA-256 record hash chaining `payload_sha256 + previous_hash` and **ECDSA-signs** it (`ledger.py:445`), with **optional ML-DSA dual-sign** when a PQ sealer is active (`ledger.py:449-452`, `None` when ECDSA-only so the chain is identical). `verify_chain` (`ledger.py:485`) replays and recomputes hashes; `verify_signatures` (`ledger.py:514`) checks ECDSA. This is a real crypto path with a graceful fallback, **not a hollow stub.** `SealedFactKind.ENFORCEMENT` is a real enum member (`provenance/models.py:304`). `AttestedIdentity` (verify-signed-credential-against-allow-listed-issuer) is a real module (`identity/agent_credential.py`).
- **The PEP proxy is real and fail-closed.** Real MCP JSON-RPC parsing, real header stripping, real 403 refusal, real filtered tool discovery. Both decision clients fail closed on every error class (`decision_client.py:91-92,151-159`).
- **safeflow is real.** Real WAL with `prev_hash` SHA-256 chaining and sequence-monotonicity enforcement, real `os.fsync` durability (`wal.py:175`), real reverse-order inverse-op rollback with per-failure capture, real crash-recovery replay.

**Stubs / NotImplemented / honesty caveats:**

- `DecisionClient.decide` base method `raise NotImplementedError` (`decision_client.py:67`) — an **abstract interface guard**, both concrete subclasses implement it. Not dead.
- `_GatedAsyncTool._run` `raise NotImplementedError("This tool is async-only…")` (`adapters.py:286`) — **intentional**, async-only tool.
- **Self-declared honesty (verified in code):** the seal proves *authorship + integrity* of "the gate allowed/blocked this action," **not verdict correctness**, and the ledger is **not externally time-anchored** (RFC-3161 anchoring is "the next phase"). This is stated in `seal.py:21-23` and `enforcement_seal.py:22-27` **and** is faithfully reflected in code: maturity pinned to `RESEARCH_SOLID` (`enforcement_seal.py:53`), and the claim string literally ends `"verdict correctness NOT proven"` (`enforcement_seal.py:87`). The honesty caveats are accurate, not overstated.
- **No `pass`-only bodies, no `TODO`, no placeholder returns** in any of the three packages' substantive logic.

---

## Technology

- **Reference-monitor / PEP-PDP pattern.** Classic XACML-style split: PDP decides, PEP enforces. Three PEP shapes (in-process gate, network proxy, would-be eBPF kernel-floor) all obey one contract: call the PDP, obey `released`.
- **Proof-carrying enforcement.** Per-decision tamper-evident receipts: SHA-256 hash-chained, ECDSA-P256 signed `SealedFact` records, with optional **ML-DSA** (Dilichium / FIPS-204 post-quantum) dual-signature. Single ledger, single offline verifier — no new chain per the seal's design.
- **Observer pattern** for audit fan-out (`GateEvent` → `GateEventObserver`), with the proof layer implemented as just another observer — clean composition.
- **WAL / ARIES discipline** (`safeflow`): write-ahead logging with compensation (inverse) ops in reverse order, fsync-before-effect, hash-chained log; cites ARIES (Mohan et al. 1992) and SAFEFLOW (arxiv 2506.07564) `(citations, unverified against the papers)`.
- **MCP-aware policy mediation:** JSON-RPC `tools/call` adjudication + `tools/list` capability-surface filtering so an agent can't even discover forbidden tools.
- **Defensive engineering:** universal fail-closed defaults, lazy optional-dep imports, duck-typed HTTP clients (no framework lock-in), `__slots__` + frozen dataclasses on the hot path.

---

## Persistence

- **enforcement gate:** **stateless.** `GateEvent`s are constructed in memory and handed to observers; the default `NullObserver` discards them.
- **proof seal:** durability is **entirely the ledger's.** `SealingGateObserver.records` is an in-memory `list` (`seal.py:68`); the real proof lives in whatever `SealedFactLedger` is passed in. The default `SealedFactLedger()` (`seal.py:113`) is **in-memory** (`self._entries` list in `provenance/ledger.py`), so absent an externally-backed ledger the receipts vanish on restart. Since the proof-carrying gate is unwired, no app-level durable enforcement ledger exists today.
- **pep:** **stateless** request handler; no persistence of decisions (provenance is the PDP's job).
- **safeflow:** dual. `InMemoryWAL` (list-backed, ephemeral); `FileWAL` writes append-only fsynced newline-JSON to a path the caller supplies (docstring says `var/safeflow/wal/<txn_id>.log` — `__init__.py:49` `(claim, unverified)`; the code takes an arbitrary path, `wal.py:143`). `InverseOpRegistry` is process-global, lost on restart.

---

## Notable Findings

1. **The headline feature of this branch is not wired in.** `feat/proof-carrying-gate` adds `build_proof_carrying_gate` / `SealingGateObserver` / `seal_enforcement`, but nothing in `main.py`, `build_runtime`, or any API route constructs or uses them. Sole exerciser is `tests/enforcement/test_proof_carrying_gate.py`. **DEMO_TEST_ONLY.** The implementation is real and green; it is simply not connected to a request path.

2. **Even the plain in-process gate is constructed-and-parked.** `app.state.standing_gate` is set at `main.py:1756` and **never read** anywhere in `src/tex`. The spine pass marks `enforcement=LIVE`; that is true only in the weak sense that `create_app` imports and calls `build_standing_gate`. No agent action in the running system is actually gated through it. The package `__init__.py:2` docstring is honest about this: *"built but not invoked by the runtime today."* — **(claim, confirmed in code).**

3. **`pep` is orphaned from the Python app, against the impression the docstrings give.** `enforcement/__init__.py:35` says the network PEP is *"auto-injected by `tex.operator`"* — true only as a k8s container `command` string (`operator/webhook.py:81`), and `tex.operator` is itself an orphan. No FastAPI mount, no import edge. The proxy only runs as a standalone `python -m tex.pep` sidecar process. The spine pass `pep=ORPHAN` is correct.

4. **`safeflow` is a self-contained island.** No non-test importer anywhere. I downgrade the spine's `safeflow=INDIRECT` to **DEMO_TEST_ONLY** — the only importer is `tests/frontier_thread_12/test_safeflow.py`. The code quality is high (real WAL, real fsync, real rollback) but it is not plumbed into any agent execution path.

5. **The honesty caveats are accurate — a positive finding.** Unlike audits where docstrings oversell, here the `seal.py`/`enforcement_seal.py` self-descriptions *understate or exactly match* reality: maturity is correctly pinned `RESEARCH_SOLID`, the claim text says verdict correctness is not proven, and the "not externally time-anchored yet" caveat is real (no RFC-3161 anchoring exists in this code).

6. **`_resolve_surface` reaches into a private PDP method.** `proxy.py:290` calls `gov._resolve_agent(...)` (note the `# noqa: SLF001`). Filtered tool discovery is coupled to a private `StandingGovernance` internal — a brittle seam if that method's signature changes.

7. **`tools/list` filtering trusts the upstream response shape and silently no-ops on mismatch** (`proxy.py:261-268`): if the surface can't be resolved or the body isn't the expected shape, the *unfiltered* tool list is returned. Fail-open for *discovery* (not for the call itself, which is still adjudicated) — worth noting as a confidentiality, not an enforcement, gap.

8. **Irreversible-tool rejection is by omission, not denylist.** The `rollback.py` docstring names `send_email`/`transfer_funds` as non-participants, but there is no hardcoded denylist — a tool simply can't be stepped with an `inverse_op` that isn't registered (`executor.py:168`). A tool stepped with `inverse_op=None` runs fine and is just not rolled back. So "irreversible tools cannot participate" is a *convention enforced by the absence of an inverse*, not a guard. **(docstring claim, partially true in code.)**

9. **Dead-ish helper:** `_synthetic_unavailable_response` (`gate.py:555`) only runs on the fail-open path (`fail_closed=False`), which is never the default and not configured anywhere live. Reachable, but never exercised in the current wiring.
