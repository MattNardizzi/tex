# Subsystem Dossier: `camel` + `gateway`

**Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/camel/` and `/Users/matthewnardizzi/dev/tex/src/tex/gateway/`
**Branch:** `feat/proof-carrying-gate`
**Unit role:** CaMeL capability/dual-LLM prompt-injection-defense pattern (`camel`) + self-hosted speech/ingress gateway (`gateway`).

> Method note: every claim below was verified by reading code and tracing imports/call-sites with grep. Claims taken from docstrings/markdown that were NOT confirmed in code are explicitly labelled `(claim, unverified)`. file:line citations are absolute under `/Users/matthewnardizzi/dev/tex`.

---

## Overview

Two unrelated subsystems share this dossier:

1. **`camel`** — a *capability-tracking dual-LLM interpreter*. It implements the CaMeL pattern (Debenedetti et al., arXiv:2503.18813) augmented with a FIDES dual-axis (integrity × confidentiality) lattice (arXiv:2505.23643). A "Privileged LLM" emits a typed, side-effect-free `Plan`; an interpreter executes it while propagating `CapabilitySet` taint labels through every value; tool calls are gated against a frozen `ToolPolicyRegistry` (fail-closed). The Quarantined-LLM (Q-LLM) processes untrusted strings and has no tool access. The unit ships its own primitives only — the *runtime entrypoint* into the running app is `CamelSpecialist` (in the `specialists` subsystem, out of scope), which is registered LIVE in the PDP specialist suite.

2. **`gateway`** — Tex's *self-hosted voice ingress*: a browser→server WebSocket recognizer (`voice_gateway.py`), pluggable STT/TTS backends (`backends.py`), and a short-lived HMAC voice-token grant (`grant.py`). The HTTP surface that consumes it (`/v1/voice/token`, `/v1/ask`, `/v1/speak`, `/v1/speak/timed`) lives in `tex.api.voice_routes`, which IS mounted in `create_app`.

Both are wired LIVE, but with very different "exercise" profiles (see Notable Findings): the gateway's TTS path runs on every `/v1/speak` call, while the camel *interpreter* runs only when a request carries a `camel_plan` in its metadata — which **no production caller currently sets** (only tests do).

---

## File Inventory

### `camel/` (1,210 LOC)

| File | LOC | Role |
|---|---|---|
| `camel/__init__.py` | 120 | Package facade; re-exports the public API; declares `__layer__ = 4` (`execution_governance`). |
| `camel/capability.py` | 319 | FIDES dual-axis lattice: `CapabilityLevel` (integrity), `ConfidentialityLevel`, `Capability`, `FidesLabel`, `CapabilitySet`. Join = high-water-mark. |
| `camel/value.py` | 91 | `CapValue` — a value + `CapabilitySet`; `derived()` joins ancestor caps (central CaMeL invariant). |
| `camel/plan.py` | 155 | Plan AST: `Literal/Var/Read` (exprs), `Assign/Call/QLLM/Return` (nodes), `Plan` with `validate_structure()`. |
| `camel/policy.py` | 105 | `ToolPolicy` (per-arg max level + forbidden sources) and `ToolPolicyRegistry` (freezable, fail-closed default). |
| `camel/q_llm.py` | 87 | Q-LLM protocol + `StubQuarantinedLLM` (deterministic) + `CallableQuarantinedLLM` (real-model adapter). |
| `camel/interpreter.py` | 333 | `CamelInterpreter` — capability-tracking executor; `ExecutionTrace`/`TraceEntry`; `CamelInterpreterError`. |

### `gateway/` (991 LOC)

| File | LOC | Role |
|---|---|---|
| `gateway/__init__.py` | 22 | Docstring-only module marker; `__all__ = []`. No exports. |
| `gateway/backends.py` | 717 | STT/TTS backend protocols + impls: `OfflineSTT/TTS`, `WhisperSTT`, `KokoroTTS`, `ParakeetSTT`, `ElevenLabsTTS`; `select_stt/select_tts/synthesize_tts`. |
| `gateway/grant.py` | 99 | HMAC-SHA256 voice-token mint/verify; `is_production_like` fail-closed posture. |
| `gateway/voice_gateway.py` | 153 | Async WebSocket recognizer server (`handle_connection`, `serve`, `main`); push-to-talk wire protocol. |

---

## Internal Architecture

### `camel` — the capability core

**Lattice (`capability.py`).**
- `CapabilityLevel(IntEnum)` (`capability.py:73`): integrity axis `TRUSTED=0 < USER=1 < UNTRUSTED=2`, `join = max` ("most-tainted wins", `capability.py:88-89`). `is_untrusted_level` at `:91`.
- `ConfidentialityLevel(IntEnum)` (`capability.py:97`): `PUBLIC=0 < INTERNAL=1 < CONFIDENTIAL=2 < RESTRICTED=3`, `join = max`. `is_sensitive` = `>= CONFIDENTIAL` (`:116-119`). The docstring asserts these names/ordering are kept identical to `tex.governance.private_data_exec.ifc.lattice.ConfidentialityLevel` — **verified consumed**: `ifc/classifier.py:63` imports a `ConfidentialityLevel` (a separate but isomorphic definition; the camel module deliberately does NOT import the IFC one, `capability.py:26-30`).
- `Capability(BaseModel, frozen)` (`capability.py:122`): carries `level`, `confidentiality` (default `PUBLIC`, additive — `:124-129`), `source` (1–128 chars), `provenance_id`. Factory methods `trusted/user/untrusted/sensitive` (`:138-199`).
- `FidesLabel` (`capability.py:202`): `(integrity, confidentiality)` projection; `is_flow_violation` = `is_untrusted ∧ is_sensitive` (`:230-239`) — the canonical FIDES prompt-injection-to-exfiltration predicate.
- `CapabilitySet(BaseModel, frozen)` (`capability.py:242`): immutable `frozenset[Capability]`; `.level`/`.confidentiality` are high-water-marks over members (`:257-268`); `.join`/`__or__` are set union (`:297-304`); empty set ⇒ `TRUSTED`/`PUBLIC` (`:259-260`, `:266-267`).

**Value (`value.py`).** `CapValue(frozen)` (`value.py:30`) restricts `value` to `str|int|bool|None|tuple` (canonical-JSON subset, `:35`). The load-bearing method is `CapValue.derived(value, from_values=...)` (`value.py:61-76`): merges all ancestor `CapabilitySet`s by `|`. This is the taint-propagation primitive every derivation funnels through. Factories `trusted/user/untrusted` mirror the `Capability` factories.

**Plan AST (`plan.py`).** Deliberately tiny, NO general control flow (`plan.py:27-38` rationale: untrusted data must never influence plan structure). Exprs: `Literal` (`:64`), `Var` (`:70`), `Read(source, key)` (`:76`). Nodes: `Assign` (`:91`), `Call(tool, args, result_var)` (`:98`), `QLLM(query, inputs, result_var)` (`:106`), `Return` (`:114`). `Plan.validate_structure()` (`:131-140`) enforces exactly one `Return`, last. All models are `frozen, extra="forbid"`.

**Policy (`policy.py`).** `ToolPolicy.check(arg_caps)` (`policy.py:40-62`): arity must match (`:42-47`); each arg's `caps.level` must be `<=` the per-position `max_arg_levels` (`:48-54`); any arg `source` in `forbidden_sources` denies (`:55-61`). `ToolPolicyRegistry` (`:65`) is mutable until `freeze()` (`:81-83`); `register` raises if frozen or duplicate (`:74-79`). **Fail-closed default**: `policy_for(tool, arity)` for an unregistered tool returns a synthetic policy requiring `TRUSTED` on every argument (`:92-102`) — so any USER/UNTRUSTED arg to an unpoliced tool is denied.

**Q-LLM (`q_llm.py`).** `QuarantinedLLM` is a `runtime_checkable Protocol` with one method `answer(query, inputs) -> str` (`q_llm.py:33-38`). `StubQuarantinedLLM` (`:41`) concatenates inputs after the query, truncated to 2,048 chars (`:58-61`) — deterministic, NOT a real model. `CallableQuarantinedLLM` (`:64`) wraps any `Callable[[str, tuple[str,...]], str]` and type-checks the return (`:78-84`) — the seam for a real LLM bridge.

**Interpreter (`interpreter.py`).** `CamelInterpreter` (`:108`) is `__slots__`-based. Construction **requires a frozen registry** or raises (`:137-140`). `run(plan, user_prompt)` (`:148-204`):
1. `plan.validate_structure()` first (`:150`); a `PlanError` becomes `CamelInterpreterError` (`:151-152`).
2. Injects `user_prompt` into `untrusted_env["user_prompt"]` (`:163`) as a USER-level read source.
3. Iterates `plan.nodes`, calling `_step` (`:165-192`); appends a `TraceEntry` per node.
4. **On any `CamelInterpreterError`: fail-closed** — sets `halted=True`, emits a halt trace entry, and overwrites `final_value` with an **empty UNTRUSTED** `CapValue` tagged `camel:halt` (`:184-192`) so no downstream consumer can trust it.
5. Returns `(final_value, ExecutionTrace)`.

`_step` (`:208-292`) handles each node type:
- `Assign` → evaluate expr, bind in `env` (`:211-220`).
- `Call` → evaluate args, fetch policy via `policy_for(tool, arity=len(args))`, run `policy.check(...)` **before** invoking; deny raises (`:222-242`, "no implementation" also raises at `:238-242`); a raw (non-`CapValue`) tool return is wrapped via `CapValue.derived` from the inputs (`:244-246`).
- `QLLM` → evaluate input `Var`s, stringify, call `q_llm.answer`, wrap result via `CapValue.derived` from inputs (taint union, `:258-277`).
- `Return` → evaluate expr, return its value (`:279-287`).
- Unknown node ⇒ `CamelInterpreterError` (`:289-292`).

`_eval_expr` (`:296-324`): `Literal` ⇒ `CapValue.trusted(source="plan_literal")`; `Var` ⇒ lookup or "unbound variable" error; `Read` ⇒ key lookup in `untrusted_env`, missing ⇒ error, `source=="user"` ⇒ USER level else UNTRUSTED (`:307-321`).

**Data flow within `camel`:** `Plan` (from a trusted P-LLM, never built here) → `CamelInterpreter.run` → per-node `_step`/`_eval_expr` producing `CapValue`s whose `CapabilitySet` is joined via `CapValue.derived` → tool calls gated by `ToolPolicy.check` against the frozen `ToolPolicyRegistry` → `(final CapValue, ExecutionTrace)`. The trace is structured for emission into an evidence ledger (`interpreter.py:28-30`, docstring claim — no ledger write happens inside this unit).

### `gateway` — the voice ingress

**Backends (`backends.py`).** Two `Protocol` seams: `STTBackend` (`:82`) and `TTSBackend` (`:91`), each with `name`, `requires`, `available()`, and `session()`/`synthesize()`. `_deps_present(*modules)` (`:62-63`) uses `importlib.util.find_spec` to gate on optional deps.

- `OfflineSTT` (`:121`): `available()` always True; `session()` returns `_OfflineSTTSession` which **does NOT transcribe** — `feed` returns a `"…"` partial, `finish` returns a fixed canned string (`:103-136`). Honest placeholder.
- `OfflineTTS` (`:139`): emits a valid but content-free WAV — a 220 Hz quiet sine whose length scales with text (`:150-166`). stdlib `wave`/`struct`/`math` only.
- `ParakeetSTT` (`:172`): pure seam; `requires=("torch","nemo_toolkit")`; `session()` raises `RuntimeError` (`:182-186`). Never runs here.
- `WhisperSTT` (`:241`): **real** faster-whisper/CTranslate2 STT. `available()` requires `faster_whisper` importable AND `model.bin` on disk under `$TEX_WHISPER_DIR` (`:275-279`). `_load` lazily builds `WhisperModel(device="cpu", compute_type="int8")` under a lock (`:281-293`). `_WhisperSTTSession._transcribe` (`:222-238`) does real ASR with numpy resampling to 16 kHz mono float32. `name` reports `"faster-whisper"` only when available, else `"faster-whisper(seam)"` (`:265-267`).
- `KokoroTTS` (`:304`): **real** Kokoro-82M ONNX TTS. `available()` requires `onnxruntime`+`soundfile`+`kokoro_onnx` importable AND both model files on disk under `$TEX_KOKORO_DIR` (`:352-358`). `synthesize` lazy-loads the ONNX session under a lock, produces 24 kHz audio, linearly resamples to the caller's rate, writes WAV via soundfile (`:360-410`). Refuses (raises) if called while unavailable (`:365-370`). Docstring flags the bundled libespeak-ng is GPLv3 (`:322-323`).
- `ElevenLabsTTS` (`:478`): cloud TTS via raw `urllib`. `requires=()` — the live gate is `ELEVENLABS_API_KEY` (`:512`, `:533-539`). `synthesize` POSTs the **exact sealed text** with `model_id=eleven_flash_v2_5` pinned and `apply_text_normalization="off"` (`:622-628`), requesting raw PCM, then WAV-wraps with optional resample (`:541-569`). `synthesize_timed` (`:571-612`) uses the `/with-timestamps` endpoint and rolls character alignment up into per-word timings via `_chars_to_words` (`:449-475`). Refuses if no key (`:546-552`).

Selection: `_STT_PREFERENCE = (ParakeetSTT(), WhisperSTT())` (`:654`); `_TTS_PREFERENCE = (ElevenLabsTTS(), KokoroTTS())` (`:657`). `select_stt`/`select_tts` (`:660-686`) pick the first `available()`, logging every skip, falling back to the offline placeholder. `synthesize_tts` (`:689-717`) is the resilient path: tries each available backend, **falls THROUGH on a runtime synth exception** to the next, ending at the always-available `OfflineTTS`; returns `(wav_bytes, name_of_backend_that_actually_spoke)`.

**Grant (`grant.py`).** `is_production_like()` (`:41-46`): True if `TEX_REQUIRE_AUTH=1` or `TEX_APP_ENV` ∉ `{dev,development,test,testing,local}`. `voice_secret()` (`:49-60`): returns `TEX_VOICE_GATEWAY_SECRET` if set; in production with no secret returns `None` (fail closed); in dev with no secret returns a per-process ephemeral `secrets.token_hex(32)` (`:38`, `:56-60`) with a warning. `make_token(tenant, ttl_seconds=120)` (`:72-80`): builds `{tenant, exp}` JSON, base64url-encodes, signs with HMAC-SHA256, returns `f"{body}.{sig}"`; returns `None` if no secret. `verify_token` (`:83-99`): constant-time `hmac.compare_digest` signature check, JSON decode, expiry check; **never raises**, returns `(ok, tenant)`.

**WebSocket server (`voice_gateway.py`).** `handle_connection(websocket, stt=None, require_token=None)` (`:69-126`):
1. Selects backend via `stt or select_stt()` (`:77`); enforcement = `is_production_like()` unless overridden (`:78`).
2. Extracts `?token=` from the connection path (`:80`, helpers `_query_token`/`_connection_path` `:52-66` tolerate websockets ≥13 and older), verifies it; if enforcing and invalid → `close(code=4401)` (`:82-84`).
3. Wire protocol loop (`:91-115`): binary frames → `session.feed`, emit `{"type":"partial"}` every `_PARTIAL_EVERY=5` frames (`:49`, `:96-97`); `{"type":"start"}` may reset sample rate (`:106-110`); `{"type":"end"}` → `session.finish()` → `{"type":"final"}` and break (`:111-115`).
4. `finally` (`:118-126`): if no final was sent (released mid-stream), best-effort emit a final so the client never hangs. Never raises out (`:116-117`).

`serve` (`:129-144`) imports `websockets` locally (the API process doesn't need it), binds `$TEX_VOICE_GATEWAY_HOST`/`PORT` (default `0.0.0.0:8765`). `main` (`:147-149`) runs it; `python -m tex.gateway.voice_gateway` is the standalone entrypoint (`:152-153`).

---

## Public API

### `camel` (re-exported from `camel/__init__.py:99-120`, 20 symbols)
`Capability`, `CapabilityLevel`, `CapabilitySet`, `CamelInterpreter`, `CamelInterpreterError`, `ExecutionTrace`, `CapValue`, `Plan`, `PlanNode`, `PlanError`, `Assign`, `Call`, `Literal`, `Read`, `Return`, `Var`, `ToolPolicy`, `ToolPolicyRegistry`, `QuarantinedLLM`, `StubQuarantinedLLM`.
Also queryable: `__layer__ = 4`, `__layer_kind__ = "execution_governance"` (`__init__.py:68-69`).

> Note: `ConfidentialityLevel`, `FidesLabel`, `QLLM` (plan node), `CallableQuarantinedLLM`, `ToolFn`, `TraceEntry` are exported from their own modules' `__all__` but **NOT** re-exported from the package `__init__`. Consumers that need them import the submodule directly (e.g. `from tex.camel.capability import ConfidentialityLevel`).

### `gateway`
- `gateway/__init__.py` exports **nothing** (`__all__ = []`, `:22`).
- `gateway.backends`: `Transcript`, `STTSession`, `STTBackend`, `TTSBackend`, `OfflineSTT`, `OfflineTTS`, `ParakeetSTT`, `WhisperSTT`, `KokoroTTS`, `ElevenLabsTTS`, `select_stt`, `select_tts`, `synthesize_tts` (`backends.py:43-57`).
- `gateway.grant`: `voice_secret`, `make_token`, `verify_token`, `is_production_like` (`grant.py:30`).
- `gateway.voice_gateway`: `handle_connection`, `serve`, `main` (`voice_gateway.py:43`).

---

## Wiring

### Wiring IN — who imports these units

**`camel`** consumers (grep across `src/tex`, excluding `camel/`):
- `specialists/camel_specialist.py:31-39` — imports `CamelInterpreter`, `CamelInterpreterError`, `ExecutionTrace`, `Plan`, `ToolPolicyRegistry`, `QuarantinedLLM`, `StubQuarantinedLLM`, `CapValue`. **This is the live entrypoint.**
- `contracts/rule_of_two.py:83` — `from tex.camel.capability import CapabilityLevel, ConfidentialityLevel`.
- `bench/wave2_corpus/builders.py:36` and `loaders.py:43` — `CapabilityLevel, ConfidentialityLevel` (the L4 benchmark corpus; bench is INDIRECT).
- `contracts/action_class.py:31` — docstring reference only (no import of camel symbols in code).

**`gateway`** consumers:
- `api/voice_routes.py:39-40` — `from tex.gateway import grant` and `from tex.gateway.backends import ElevenLabsTTS, synthesize_tts`. **This is the live HTTP entrypoint.**
- `voice_gateway.py:40-41` imports `gateway.backends` and `gateway.grant` internally.

### Wiring — LIVE call paths

**`camel` LIVE path (via the PDP specialist suite):**
```
tex.main.build_runtime  (main.py:519)
  └─ PolicyDecisionPoint(...)              main.py:876
       └─ self._specialist_suite = ... or build_default_specialist_suite()   engine/pdp.py:205
            └─ build_default_specialist_suite() → SpecialistSuite(default_specialist_judges())   judges.py:408-410
                 └─ default_specialist_judges() registers CamelSpecialist()    judges.py:399
  PDP request handling:
  PolicyDecisionPoint.evaluate → self._specialist_suite.evaluate(...)   engine/pdp.py:289
       └─ CamelSpecialist.evaluate(request, retrieval_context)   camel_specialist.py:72
            └─ reads request.metadata['camel_plan'] / 'camel_untrusted_env'   camel_specialist.py:84-86
            └─ if a Plan is present: CamelInterpreter(...).run(plan)   camel_specialist.py:99-107
```
`CamelSpecialist` is **registered LIVE** in the default suite (`judges.py:399`) and the PDP is instantiated in `build_runtime` (`main.py:876`). **However**, the interpreter only fires when `request.metadata['camel_plan']` is a `Plan` (`camel_specialist.py:88`); otherwise it abstains (risk 0.0, confidence 0.0, `:89-97`). See Notable Findings — no production caller sets `camel_plan`.

**Second `camel` LIVE path (lattice vocabulary, always-on):** `camel.capability.ConfidentialityLevel`/`CapabilityLevel` are consumed by `contracts/rule_of_two.py:83,166-167`, and `evaluate_rule_of_two` is called by the PDP's structural floor:
```
PolicyDecisionPoint.evaluate → detect_structural_floor(...)   engine/pdp.py:339
  └─ structural_floor.py:63-66 imports evaluate_rule_of_two from contracts.rule_of_two
       └─ rule_of_two reads metadata, classifies confidentiality via ConfidentialityLevel.is_sensitive   rule_of_two.py:166-167
```
So the `ConfidentialityLevel` lattice **does** run on real requests (whenever Rule-of-Two metadata is present), independent of the interpreter.

**`gateway` LIVE path (HTTP voice surface):**
```
tex.main.create_app  (main.py:1309)
  └─ app.include_router(build_voice_router())   main.py:1459
       └─ build_voice_router()   api/voice_routes.py:100
            ├─ GET /v1/voice/token  → grant.make_token(tenant)        voice_routes.py:113
            ├─ POST /v1/ask         → voice.voice_ask.answer_question  voice_routes.py:143  (STT transcript → sealed answer)
            ├─ GET /v1/speak        → synthesize_tts(text, ...)        voice_routes.py:173
            └─ GET /v1/speak/timed  → ElevenLabsTTS().synthesize_timed voice_routes.py:201
```
The **WebSocket recognizer** (`voice_gateway.serve`) is a SEPARATE process — `python -m tex.gateway.voice_gateway` (`voice_gateway.py:152`) — NOT mounted in `create_app`. The browser connects to it directly using the token minted by `/v1/voice/token`. The gateway URL is `$TEX_VOICE_GATEWAY_URL` (default `ws://localhost:8765`, `voice_routes.py:47`).

`wired_status` summary:
- `gateway` = **LIVE** (TTS path runs on every `/v1/speak`; recognizer is a standalone live process reachable via the minted token).
- `camel` = **LIVE but largely DORMANT**: the lattice vocabulary runs via Rule-of-Two; the interpreter is registered but only executes on requests carrying `camel_plan` (tests only today).

### Wiring OUT — dependencies

**`camel` internal deps:** `capability ← value, policy, interpreter`; `plan ← interpreter`; `q_llm, policy ← interpreter`. No cross-subsystem `tex.*` imports inside `camel` (deliberately self-contained, `capability.py:26-30`). External: `pydantic` only (`BaseModel/ConfigDict/Field`), stdlib `enum`/`typing`.

**`gateway` internal deps:** `voice_gateway ← backends, grant`. Cross-subsystem `tex.*` imports inside `gateway`: **none** (it's a leaf). External libs: stdlib (`asyncio`, `wave`, `struct`, `math`, `hmac`, `hashlib`, `base64`, `secrets`, `urllib`, `importlib.util`, `threading`); optional/lazy (`websockets`, `numpy`, `faster_whisper`, `kokoro_onnx`, `onnxruntime`, `soundfile`) — all imported inside functions so the unit imports cleanly without them (verified: `import tex.gateway.*` succeeds with none installed).

---

## Implementation Reality

**`camel` — REAL.** The interpreter, lattice, taint propagation, and policy gate are fully implemented, deterministic, and exercised by `tests/frontier_thread_12/test_camel.py` (292 LOC) and `test_capability_fides.py` (136 LOC). Empirically verified end-to-end:
```
Plan(Assign x = Read(email), Return x) over untrusted_env{email:"attacker text"}
  → final level: UNTRUSTED, halted: False, sources: ('email',)
```
i.e. taint propagated correctly. No `NotImplementedError`/`TODO`/`pass`-stub anywhere in `camel/`. The Q-LLM `StubQuarantinedLLM` is an honest, labelled placeholder (`q_llm.py:41-61`), with `CallableQuarantinedLLM` as the real-model seam.

*Acknowledged gaps in code/docstrings (not stubs, just bounded scope):*
- Declassification is **not implemented** — `interpreter.py:16-19` ("We do not implement declassification ops here; that's a Thread 13 frontier item"). The `CapValue` docstring (`value.py:14-18`) describes declassification that does not exist in code.
- `FidesLabel`, `Capability.sensitive()`, `is_flow_violation`, and the confidentiality axis on the interpreter are **defined but the interpreter's tool-call gate uses the integrity axis alone** (`capability.py:42-44`, confirmed in `policy.py:48-54` which only checks `.level`). The confidentiality axis is consumed by Rule-of-Two (`rule_of_two.py:166-167`) and the bench corpus, but `FidesLabel`/`is_flow_violation` themselves are referenced only inside `camel` + tests — effectively dead-but-defined production-wise.

**`gateway` — REAL with honest fallbacks.**
- `OfflineSTT`/`OfflineTTS` are **explicitly labelled non-functional placeholders** — `OfflineSTT` returns a canned transcript and "DOES NOT TRANSCRIBE" (`backends.py:104,121-124`); `OfflineTTS` emits a sine tone, "NOT a spoken voice" (`:139-142`). These are the default in this environment (verified: `select_stt()` → `offline-placeholder(no-asr)`, `select_tts()` → `offline-tone(no-voice)`).
- `WhisperSTT` and `KokoroTTS` are **real implementations** (faster-whisper CTranslate2 ASR `:222-238`; Kokoro-82M ONNX synthesis `:360-410`) with a strict double gate: deps importable AND model weights on disk. They refuse rather than fake when unavailable (`:296-300`, `:365-370`). This is a genuine "real path + honest fallback", not a hollow stub.
- `ElevenLabsTTS` is a **real cloud call** via `urllib` (`:614-648`), gated on `ELEVENLABS_API_KEY`.
- `ParakeetSTT` is a pure declared seam that raises (`:182-186`).
- `grant.py` HMAC mint/verify is real (`:72-99`) with a genuinely fail-closed production posture (`voice_secret()` returns `None` in prod with no secret, `:53-55`).
- `voice_gateway.handle_connection` is a complete, real async WS server with defensive never-crash handling (`:116-126`).

No TODO/NotImplementedError/pass-only stubs in `gateway/` except the intentional `ParakeetSTT` seam.

---

## Technology

- **CaMeL** (Capabilities for Machine Learning) dual-LLM prompt-injection defense — arXiv:2503.18813 (DeepMind). P-LLM/Q-LLM separation; plan with no untrusted-influenced control flow.
- **FIDES dual-axis IFC** — arXiv:2505.23643. Product lattice (integrity × confidentiality); the canonical injection-to-exfiltration attack becomes a typed flow violation (`is_flow_violation`).
- **Denning 1976 lattice model** of secure information flow (cited `capability.py:63`); high-water-mark join semantics.
- **Fail-closed reference monitor**: unregistered tools default to TRUSTED-only (`policy.py:97-102`).
- **HMAC-SHA256 bearer tokens** with constant-time compare (`grant.py:79,91`); short TTL (120 s).
- **faster-whisper / CTranslate2** int8 CPU ASR; **Kokoro-82M** ONNX TTS; **ElevenLabs `eleven_flash_v2_5`** with text-normalization disabled to voice the exact sealed string.
- **Push-to-talk wire protocol** — RELEASE = end-of-turn, eliminating VAD/end-of-turn detection (`voice_gateway.py:18-21` rationale).
- Design patterns: `typing.Protocol` seams (Q-LLM, STT/TTS backends), frozen Pydantic value objects, registry-with-freeze, immutable lattice with monoidal `join`.

---

## Persistence

**Both units are entirely in-memory / stateless.**
- `camel`: every model is `frozen`; `CamelInterpreter` holds transient `env`/`entries` per `run` and an injected `untrusted_env` dict — nothing persisted. `ToolPolicyRegistry` is an in-process dict, frozen at startup; not durable. The `ExecutionTrace` is *designed* for emission into Tex's hash-chained evidence ledger (`interpreter.py:28-30`, claim) but this unit performs **no ledger write** — that would be the specialist/PDP layer's job (out of scope, and not observed).
- `gateway`: tokens are stateless HMACs (no server-side session store); the `_EPHEMERAL_DEV_SECRET` is per-process and lost on restart (`grant.py:38`). STT sessions hold a transient PCM buffer in memory for the duration of one utterance. Model weights live on disk under `$TEX_WHISPER_DIR`/`$TEX_KOKORO_DIR` (read-only, provisioned out-of-band by `scripts/provision_*.sh` — referenced, not in scope).

---

## Notable Findings

1. **The CaMeL interpreter is registered LIVE but never actually invoked by production code.** `CamelSpecialist.evaluate` runs the interpreter only if `request.metadata['camel_plan']` is a `Plan` (`camel_specialist.py:88`). A grep across all of `src/tex` shows `camel_plan`/`camel_untrusted_env`/`camel_user_prompt` are referenced **only inside `camel_specialist.py` itself** — no producer anywhere sets them. So on every real request the specialist takes the abstain branch (`:89-97`). The interpreter is exercised solely by tests. The `__init__.py:62` claim "Priority: P0 — wired into the PDP via `CamelSpecialist`" is technically true (it's in the suite) but **overstates** real-world exercise: it is dormant pending a P-LLM that emits plans into request metadata.

2. **The lattice IS live even though the interpreter is dormant.** `ConfidentialityLevel`/`CapabilityLevel` from `camel.capability` are consumed by the always-on Rule-of-Two structural floor (`rule_of_two.py:166-167` → `pdp.py:339`). So `camel` as a *vocabulary provider* is genuinely on the hot path; `camel` as an *executor* is not.

3. **Stale docstring reference in `q_llm.py`.** The docstring says production passes a callable that hits a model "through `tex.llm_bridge`" (`q_llm.py:16-17`). There is **no `tex.llm_bridge` module** — the real module is `tex.specialists.llm_bridge` (`src/tex/specialists/llm_bridge.py`). (claim in docstring, contradicted by code layout.)

4. **`ConfidentialityLevel`/`FidesLabel`/`QLLM`/`CallableQuarantinedLLM` are not re-exported from `camel/__init__.py`** despite being public in their submodules. Minor API-surface inconsistency, not a bug.

5. **Two parallel `ConfidentialityLevel` definitions exist by design.** `camel.capability.ConfidentialityLevel` (`capability.py:97`) is deliberately a *copy* of `tex.governance.private_data_exec.ifc.lattice.ConfidentialityLevel` (imported at `ifc/classifier.py:63`) to keep `camel` dependency-free (`capability.py:26-30`). The docstring claims they are "tested to agree" in `tests/frontier_thread_12/test_capability_fides.py` (claim — the test file exists, 136 LOC, but I did not read its assertions). A drift risk: two enums that must stay identical by convention, not by import.

6. **The WebSocket recognizer is NOT part of the FastAPI app.** `voice_gateway.serve` is a standalone process (`voice_gateway.py:129-153`); only the *token mint* and *TTS synthesis* live in `create_app`. This is intentional (a serverless proxy can't hold a streaming socket, `gateway/__init__.py:5-7`) but means the "gateway is LIVE" status splits: HTTP TTS/token = mounted; WS STT = separately-launched live process.

7. **Honesty engineering is unusually rigorous and matches the code.** Every "this is a placeholder / vendor in the path / fail-closed" docstring claim in `gateway` was verified true in code: `OfflineSTT` really returns canned text; `available()` gates really require model files on disk; `X-Tex-Voice-Backend` really names the backend that actually produced bytes (`backends.py:715`, `voice_routes.py:177`); `synthesize_tts` really falls through on runtime failure (`:698-715`). No overstatement found in `gateway`.

8. **No declassification path despite `value.py` docstring implying one.** `value.py:14-18` says caps are stripped "via an explicit declassification step authorized by the policy," but no such op exists in `interpreter.py`/`policy.py` (confirmed by `interpreter.py:16-19`). Capabilities are monotonic in practice; the only way taint "resets" is the fail-closed halt path.
