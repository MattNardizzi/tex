# Subsystem Dossier — `voice` (the grounded spoken-answer cascade)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/voice/` (7 `.py` files).
> Branch: `feat/proof-carrying-gate`. All line references verified against code on this branch.
> Verification command for any runtime claim: `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src python ...`

---

## Overview

The `voice` unit is Tex's **"it may only say what it can prove"** boundary. It turns a speech transcript into a *grounded* spoken answer, or an honest abstention/refusal, with **zero LLM on the load-bearing path**. The doctrine is enforced structurally, not by prompt:

1. **Route** the transcript to a sealed-fact source deterministically (keyword/handle, no model) — `intent.py`.
2. **Fetch** sealed facts through a `provider=None` vigil `Explainer` (deterministic floor, never a model) — `voice_ask.py`.
3. **Fill** one *authored* template with sealed slot values via the vigil IRON RULE (`template.format(**sealed_slots)`) — `answer_forms.py`.
4. **Gate** the result: prove `answer == template.format(**slots)` (faithfulness), FORBID an asserted contradiction, ABSTAIN on anything unprovable — `voice_gate.py`.
5. **Seal** every outcome (PERMIT/ABSTAIN/FORBID) into a separate hash-chained, ECDSA-P256-signed voice-attestation chain — `attestation.py`.

A sixth file, `entailment_cert.py`, is a **research-grade seal-half** that commits the entailment scorer's *identity* into the attestation chain. It is **NOT on the live `/v1/ask` path** (verified below) — it is consumed only by `tex.capstone`, which is itself test/bench-reachable only.

**Live status:** `wired_status = LIVE`. The unit is reachable from `tex.main.create_app` via `tex.api.voice_routes.build_voice_router()`, included **unconditionally** at `main.py:1459`. There is **no `VOICE_ENABLED` flag in this backend repo** — `grep -rn VOICE_ENABLED src/` returns nothing. The "voice muted via VOICE_ENABLED" fact from project memory refers to the *frontend* `tex-systems-lightup` repo (claim, unverified here — out of scope), not to this backend. The backend `/v1/ask`, `/v1/speak`, `/v1/voice/token` endpoints are always mounted.

TTS/STT live in the **`gateway` subsystem** (`tex.gateway.backends`), invoked by the voice routes — not in `voice/` itself. The `voice/` unit is pure text-grounding + attestation; speech I/O is the gateway's job.

---

## File Inventory

| File | Lines | Role (one line) |
|------|------:|-----------------|
| `__init__.py` | 42 | Package docstring (dependency-order map of the cascade). `__all__ = []` — exports nothing; not a re-export hub. |
| `intent.py` | 201 | Deterministic, zero-LLM router: transcript → one of 6 vigil dimensions, a record handle (sha256/UUID), or ABSTAIN; also extracts an *asserted* verdict/hash. |
| `answer_forms.py` | 258 | The complete authored answer registry: 6 dimension templates + 1 record template + 4 fixed decline/refusal strings; fills only from sealed slots via `vigil.utterances.fill`. |
| `voice_gate.py` | 531 | The faithfulness gate (exact-match reconstruction proof + structural FORBID + fail-closed neural seam) **and** the Mohri–Hashimoto split-conformal calibration helpers. |
| `voice_ask.py` | 224 | The `/v1/ask` pipeline: route → fetch sealed facts → fill template → gate → seal. Owns the process-singleton `VoiceAttestor`. |
| `attestation.py` | 222 | The voice-attestation chain: append-only, hash-chained, ECDSA-P256 per-record signed log of every spoken act; reuses `evidence.seal` primitives. |
| `entailment_cert.py` | 663 | (OFF live path) Pydantic `EntailmentCommitment` — seals the entailment scorer's identity/calibration into the chain; capstone-only consumer. |

Total: 2141 lines across 7 files.

---

## Internal Architecture

### `intent.py` — deterministic routing (zero-LLM)

The router (`route_intent`, `intent.py:131`) **never raises** — silence/garbage → ABSTAIN, not an error (`intent.py:140-141`).

- **Handle precedence:** a UUID (`_UUID_RE`, `intent.py:65`) is matched first and wins over a bare SHA-256 (`_SHA256_RE`, `intent.py:64`) because "the id is the addressable record" (`intent.py:144-165`). Either yields `IntentKind.RECORD`.
- **Dimension vote:** a frozen keyword→dimension table (`_KEYWORDS`, `intent.py:74-99`) over the six dimensions (`DIMENSIONS`, `intent.py:41-48`: `execution, human_decision, evidence, identity, monitoring, discovery`), compiled to whole-word case-insensitive patterns (`_KEYWORD_PATTERNS`, `intent.py:102-106`). The unique top-scoring dimension wins (`intent.py:168-201`).
- **ABSTAIN on ambiguity:** zero keyword hits → ABSTAIN (`intent.py:174-181`); a **tie** between dimensions → ABSTAIN (`intent.py:183-192`), never broken arbitrarily.
- **Asserted-claim extraction:** `_asserted_handles` (`intent.py:123-128`) pulls a verdict word (`_VERDICT_RE`) and any sha256 the *speaker* baked into the question; this feeds Rule B in the gate.

`Intent` (`intent.py:109-120`) is a frozen slotted dataclass carrying `kind, dimension, handle, handle_kind, asserted_verdict, asserted_hashes, scores, reason`.

The module docstring (`intent.py:15-22`) **honestly enumerates the limitation**: "keyword routing, not language understanding… it can confidently route to the wrong but still sealed dimension (a relevance error), but it can never invent a fact." Verified: the only failure mode is "answered a slightly different true question," never fabrication, because every answer is filled from whatever sealed source it lands on and the gate re-derives every handle.

### `answer_forms.py` — the authored registry (THE IRON RULE)

`answer_forms.py` is "the complete, auditable set of sentences Tex is allowed to say" (`answer_forms.py:15-16`). No template engine, no model call, no free-text concat (`answer_forms.py:10-13`).

- **6 dimension forms** (`_FORMS`, `answer_forms.py:134-165`), each a `_DimensionForm(template, required_slots, extract)` (`answer_forms.py:69-76`). Each `extract` reads slots from the **structured `details` dict by exact key, never re-parsed from the headline string** (`answer_forms.py:18-20`) — e.g. `_extract_execution` (`answer_forms.py:83-87`) requires `forbidden_total`, `_extract_monitoring` (`answer_forms.py:118-123`) counts by structure (`"connector" in it`) not by headline.
- **`build_dimension_answer`** (`answer_forms.py:186-216`): builds a `UtteranceForm` and calls `tex.vigil.utterances.fill` (`answer_forms.py:206`); returns `None` (→ ABSTAIN) when there's no form, the slot is absent, or `fill` refuses. The `fill` function (verified at `vigil/utterances.py:150-180`) **raises if any required sealed slot is missing** (`utterances.py:158-163`) then does `form.template.format(**sealed)` over only the required keys — this is the load-bearing "no improvisation" point.
- **`build_record_answer`** (`answer_forms.py:223-258`): verbalizes one sealed `Decision` via `RECORD_TEMPLATE = "Decision {decision_id} resolved to {verdict}."` (`answer_forms.py:220`). The spoken meaning is the verdict; the *object* handed over is the content hash (a thing to grab, not comprehend, `answer_forms.py:246-250`). Both read verbatim from the sealed record.
- **4 fixed decline strings** (`answer_forms.py:47-50`): `ABSTAIN_NO_ROUTE`, `ABSTAIN_NO_FACT`, `ABSTAIN_NO_RECORD`, `FORBID_CONTRADICTION` — no slots, no object, no proof_ref.
- **`AnswerBuild`** (`answer_forms.py:53-66`) carries `answer`, `template`, `slots`, `object`, `proof_ref` so the gate can **re-prove** the reconstruction rather than trust it.

### `voice_gate.py` — the faithfulness gate

`VoiceGate.evaluate` (`voice_gate.py:431-531`) is **one-sided**: it begins at PERMIT and can only lower (PERMIT → ABSTAIN → FORBID, `voice_gate.py:420`). Three rules, in caution order:

- **RULE B — structural FORBID** (`voice_gate.py:447-465`): fires only when the speaker asserted a verdict (`asserted_verdict`) about a record and the sealed verdict (`sealed_verdict`) differs (casefold-compared). Deterministic; **never neural-overridable**. Returns `Verdict.FORBID` with a `contradiction` claim.
- **RULE A — reconstruction proof** (`voice_gate.py:468-488`): the deterministic happy path. If `template.format(**slots) == answer`, then every non-template token is sealed *by construction* → `Verdict.PERMIT`, reason `reconstruction-exact`. Wrapped in `try/except (KeyError, IndexError, ValueError)` to fall through on any format error.
- **FAIL-CLOSED fallback** (`voice_gate.py:490-531`): any answer that is *not* a clean reconstruction (prose, injection) is decomposed token-by-token via `_extract_handles` (`voice_gate.py:131-144`). Each handle must equal a sealed slot value (`_which_field`, `voice_gate.py:158-168` — casefold loosening allowed ONLY for verdict labels, never a hash). Unsealed tokens are asked the exact scorer then the neural scorer (off → `None`). Even if **every** handle is sealed, the answer is still `ABSTAIN` (`handles-sealed-but-prose-uncertified`, `voice_gate.py:513-524`) because the prose residue cannot be certified without a working entailment scorer. Any unsealed token → `ABSTAIN` (`unsealed-token-in-answer`, `voice_gate.py:525-531`). **The gate can never emit PERMIT off the reconstruction path** — confirmed by reading all return statements.

**Handle token classes** (`voice_gate.py:90-96`): int, sha256, uuid, verdict (`PERMIT|ABSTAIN|FORBID`), algorithm (`ecdsa-p256|ml-dsa-65|ed25519|composite-ml-dsa-65-ed25519`). Verdict/algorithm matched before ints so they're not double-caught (`voice_gate.py:140-143`).

**Scorers:**
- `ExactMatchScorer` (`voice_gate.py:171-180`): `entails` returns True if the hypothesis token is in the space-joined sealed-value bag (tolerance 0; casefold fallback). `name = "exact-match"`.
- `NeuralNLIScorer` (`voice_gate.py:190-279`): a **real** cross-encoder NLI scorer (DeBERTa/MiniCheck-class MNLI). `load()` (`voice_gate.py:224-251`) lazy-imports `torch`/`transformers`, constructs `AutoModelForSequenceClassification`, and refuses to claim availability unless a model object is actually built (`voice_gate.py:238-251` — "imports alone are NOT availability"). `score()` (`voice_gate.py:253-265`) runs the model and returns softmax P(entailment). `entails()` (`voice_gate.py:273-279`) returns `None` when not loaded **or loaded-but-uncalibrated** (`self._lambda_hat is None`). `name` is `"neural-nli(off)"` until a model loads (`voice_gate.py:219-222`). `_entailment_label_index` (`voice_gate.py:282-301`) reads the model's own `label2id`/`id2label` and **raises rather than guess** the entailment index.

**Conformal calibration** (`voice_gate.py:304-413`):
- `conformal_lambda_hat(nonconformity, alpha)` (`voice_gate.py:330-349`): the Mohri–Hashimoto / Vovk split-conformal quantile — λ̂ = the ⌈(n+1)(1-α)⌉-th smallest score; returns `1.0` (maximally conservative) when the rank exceeds n. Pure order statistic, no numpy. **Verified at runtime:** `conformal_lambda_hat([0.2,0.8,0.5], 0.1) == 1.0` (rank 4 > n=3).
- `calibrate(scorer, pairs, *, alpha, model_id)` (`voice_gate.py:359-413`): fail-closed — raises if the scorer isn't loaded (`voice_gate.py:382-386`) or returns `None` for any pair (`voice_gate.py:395-399`). Records `model_loaded = (backend == neural and load())` (`voice_gate.py:412`) so a stub λ̂ can never masquerade as the real model's.
- `Calibration` (`voice_gate.py:307-328`) is a frozen record of the λ̂ + α + n + model_id + backend + model_loaded.

`THRESHOLD_LABEL` (`voice_gate.py:82-85`) is the honest "UNCALIBRATED — no proven coverage" label, surfaced in the sealed attestation, **never in a user-facing answer** (the module docstring at `voice_gate.py:54` claims the words "guarantee", "coverage", "1-alpha" appear in no user-facing string — verified: the only user-facing strings are the 4 fixed decline lines in `answer_forms.py:47-50`, none containing those words).

### `voice_ask.py` — the `/v1/ask` pipeline

Module-level singletons (`voice_ask.py:52-53`): `_FACTS_EXPLAINER = Explainer(provider=None)` and `_GATE = VoiceGate()`. The `provider=None` Explainer is the structural zero-LLM enforcement — verified at `vigil/explainer.py:171` the `_provider is None` branch takes the **deterministic floor** and never calls a model.

`answer_question(request, *, transcript, tenant)` (`voice_ask.py:132-224`) — never raises on a bad transcript:
1. `route_intent(transcript)` → `intent`.
2. Get the process-singleton attestor via `get_attestor` (`voice_ask.py:70-84` — double-checked-locked lazy attach to `app.state.voice_attestor`).
3. ABSTAIN intent → seal `ABSTAIN_NO_ROUTE` (`voice_ask.py:166-172`).
4. RECORD intent → `_lookup_decision` (`voice_ask.py:105-129`): UUID → `store.get(UUID(handle))`; bare hash → scan `store.list_recent(limit=500)` for a matching `content_sha256`/`evidence_hash`. Then `build_record_answer` → gate (with `asserted_verdict`/`sealed_verdict` so Rule B can fire) → seal PERMIT/FORBID/ABSTAIN (`voice_ask.py:174-198`).
5. DIMENSION intent → `_FACTS_EXPLAINER.explain(...)`, read **`.facts` only** (`voice_ask.py:202-204` — never the provider narration), `build_dimension_answer` → gate with `asserted_verdict=None, sealed_verdict=None` (Rule B structurally cannot fire on a dimension, `voice_ask.py:215-220`) → seal PERMIT or ABSTAIN (`voice_ask.py:222-224`).

`AskOutcome` (`voice_ask.py:58-67`) carries verdict, answer, object, proof_ref, routed_dimension, attestation_anchor (the `record_hash`), attestation_algorithm, and the gate summary dict. The inner `_seal` closure (`voice_ask.py:143-163`) seals **every** outcome — even declines — so a refusal is provable.

### `attestation.py` — the voice-attestation chain

A **separate** chain from the main evidence ledger, deliberately so: a spoken machine answer is neither a PDP `Decision` nor a human resolution act (`attestation.py:6-11`). It reuses `evidence.seal` primitives rather than reinventing.

`VoiceAttestor` (`attestation.py:82-223`):
- `__init__` (`attestation.py:85-98`): if no signer is passed, generates a keypair via `default_signature_provider().generate_keypair("tex-voice-attest")` and wraps it in `EvidenceChainSigner`. Optional JSONL mirror path from `TEX_VOICE_ATTEST_PATH`.
- `seal(...)` (`attestation.py:114-169`): builds a payload (`record_type="voice_attestation"`, sequence, tenant, **`transcript_sha256` — the transcript is hashed, never stored verbatim**, `attestation.py:140`/`128-130`), signs over it with `sign_payload` (which strips the signature field internally), embeds the `pq_signature` block, computes `payload_sha256` and a `record_hash` over `{payload_sha256, previous_hash}` (`attestation.py:153-159`) — the **same chain shape as `provenance/ledger.py` / `evidence/seal.py`** (`attestation.py:18-20`).
- `verify_chain()` (`attestation.py:194-212`): replays the hash chain (integrity + ordering).
- `verify_signatures()` (`attestation.py:214-222`): per-record authorship via `evidence.seal.verify_payload_signature`.

`_stable_json` (`attestation.py:58-62`) is byte-identical to `evidence.seal._stable_json` (a regression test asserts the byte-equality, claim at `attestation.py:60-61`). Verified the symbols exist: `evidence/seal.py:82` (`PQ_SIGNATURE_FIELD`), `:95` (`_stable_json`), `:113` (`EvidenceChainSigner`), `:130` (`sign_payload`), `:150` (`verify_payload_signature`).

**Honest crypto limits** (all verified in code, `attestation.py:28-39`): **ECDSA-P256 today, NOT post-quantum** (`is_post_quantum` = `signer.is_post_quantum`, `attestation.py:106-107`; `algorithm` reads what actually signed, `attestation.py:102-103`); **key management is weak** — generated per-`VoiceAttestor`, ephemeral or from `TEX_VOICE_ATTEST_KEY`, **no rotation** (rotation is unbuilt); in-memory by default with best-effort JSONL mirror (`_maybe_persist`, `attestation.py:171-182` — swallows `OSError`, never blocks the seal).

### `entailment_cert.py` — the seal-half (OFF the live path)

A `pydantic.BaseModel` `EntailmentCommitment` (`entailment_cert.py:171-325`, schema `tex.voice/entailment_commitment.v2`) that commits the scorer's *identity* — `model_id`, `model_loaded`, threshold label, λ̂, calibration corpus digest — into the voice chain so a model swap or corpus-byte flip **fails replay**. The artifact is deliberately named a **commitment, not a certificate** — "a sealed statement of WHAT WOULD SCORE, never a certificate that anything was scored" (`entailment_cert.py:17-22`).

- **Coherence validator** (`_validate`, `entailment_cert.py:230-314`): refuses every dishonest combination — calibrated without a λ̂, λ̂ out of [0,1], `model_loaded` without the neural backend, a partial calibration block, a `"field"` corpus kind without a real loaded neural calibration (the **load-bearing field-pin**, `entailment_cert.py:305-313`).
- **Builders:** `commitment_for_scorer` (`entailment_cert.py:349-378`) builds the **absence** (uncalibrated, not-loaded) and raises if `scorer.load()` is True; `commitment_from_corpus` (`entailment_cert.py:381-414`) binds a synthetic M0b corpus; `commitment_from_calibration` (`entailment_cert.py:417-463`) is the GREEN-eligible path carrying a real λ̂.
- **`entailment_half_status`** (`entailment_cert.py:328-346`): the single rule capstone/compose/verify share — GREEN only for `calibrated ∧ model_loaded ∧ backend=neural ∧ corpus_kind=field`; everything else BLOCKED. In this env the live commitment is the absence → BLOCKED.
- **`seal_entailment_commitment`** (`entailment_cert.py:469-506`): rides the `gate` dict of `VoiceAttestor.seal()` under keys `entailment_commitment` / `entailment_commitment_sha256`; refuses to overwrite a prior commitment.
- **`verify_entailment_commitment`** (`entailment_cert.py:558-663`): replays chain + signatures + key-pin + commitment hashes + model_id + manifest, keeping the three proofs **separate** (`EntailmentCommitmentVerification`, `entailment_cert.py:512-555` — `authorship_ok is None` = UNVERIFIED when no key pin supplied).

The module docstring itself admits **"Live wiring is DEFERRED to the voice track"** (`entailment_cert.py:68`). Confirmed by grep: neither `voice_ask.py` nor `voice_routes.py` imports `entailment_cert` (`grep` returned NONE).

---

## Public API

Symbols other code imports from this unit (verified via `grep -rn "tex\.voice" src/tex`):

| From | Symbol(s) | Consumed by |
|------|-----------|-------------|
| `tex.voice.voice_ask` | `answer_question` (also `AskOutcome`, `get_attestor`) | `tex.api.voice_routes` (LIVE) |
| `tex.voice.voice_gate` | `NeuralNLIScorer` | `tex.pqcrypto._backend_probe` (`:325`), `tex.capstone.flow` (`:92`) |
| `tex.voice.voice_gate` | `THRESHOLD_LABEL`, `ENTAILMENT_BACKEND_NEURAL` | `tex.capstone.compose` (`:90`), `tex.capstone.manifest` (`:65`) |
| `tex.voice.attestation` | `VoiceAttestor`, `VoiceAttestationRecord` | `tex.capstone.{compose,flow,verify,tamper}`; `tex.voice.{voice_ask,entailment_cert}` internally |
| `tex.voice.entailment_cert` | `EntailmentCommitment`, `commitment_for_scorer`, `entailment_half_status`, `verify_entailment_commitment`, … | `tex.capstone.{compose,manifest,flow,verify,tamper}` only |
| `tex.voice.intent` | `route_intent`, `Intent`, `IntentKind`, `HandleKind`, `DIMENSIONS` | `tex.voice.voice_ask` internally |
| `tex.voice.answer_forms` | `build_dimension_answer`, `build_record_answer`, `ABSTAIN_*`, `FORBID_CONTRADICTION`, `RECORD_TEMPLATE` | `tex.voice.voice_ask` internally |

`tex/voice/__init__.py` exports **nothing** (`__all__ = []`, `__init__.py:42`) — it's documentation only; consumers import submodules directly.

---

## Wiring

### In (who calls this unit)

**LIVE consumer:** `tex.api.voice_routes` (`voice_routes.py:41` `from tex.voice import voice_ask`). The `/v1/ask` handler calls `voice_ask.answer_question(request, transcript=..., tenant=...)` at `voice_routes.py:143`.

**INDIRECT consumer:** `tex.capstone.*` imports `attestation`, `entailment_cert`, and `voice_gate` symbols (5 modules). Capstone has **no importer in `src/tex` outside itself** — `grep -rln "tex.capstone" src` (excluding `src/tex/capstone/`) returns nothing; it is reached only by `tests/capstone/*` and bench/CLI. So `entailment_cert.py` and the `verify_*`/`Calibration` paths in `voice_gate.py` are **NOT reachable from the running app** — they are test/bench-only. This matches the spine pass (`capstone=INDIRECT`).

**PROBE consumer:** `tex.pqcrypto._backend_probe` imports `NeuralNLIScorer` (`_backend_probe.py:325`) as a reference example of the "imports-aren't-availability" probe pattern.

### Live call path (cited)

```
tex.main.create_app
  └─ main.py:1459  app.include_router(build_voice_router())          # UNCONDITIONAL — no flag
       └─ voice_routes.py:100  build_voice_router()
            └─ voice_routes.py:124-145  POST /v1/ask handler `ask(...)`
                 └─ voice_routes.py:143  voice_ask.answer_question(request, transcript=..., tenant=...)
                      ├─ voice_ask.py:140  route_intent(transcript)              # intent.py
                      ├─ voice_ask.py:202  _FACTS_EXPLAINER.explain(...)         # vigil Explainer(provider=None)
                      ├─ voice_ask.py:182/209  answer_forms.build_*_answer(...)  # vigil.utterances.fill
                      ├─ voice_ask.py:189/217  _GATE.evaluate(...)               # voice_gate.VoiceGate
                      └─ voice_ask.py:149  attestor.seal(...)                    # attestation.VoiceAttestor
```

Import of `build_voice_router` is at `main.py:31`. **No `VOICE_ENABLED`/conditional guard wraps line 1459** — verified by `grep -rn VOICE_ENABLED src/` (empty) and reading `main.py:1450-1465`. The voice surface is always mounted in this backend.

Sibling endpoints in the same router (also LIVE): `GET /v1/voice/token` (`voice_routes.py:103-122`, mints an HMAC-SHA256 gateway grant via `tex.gateway.grant.make_token`, **503 fail-closed when no secret in production**); `GET /v1/speak` (`voice_routes.py:158-178`, TTS via `tex.gateway.backends.synthesize_tts`); `GET /v1/speak/timed` (`voice_routes.py:180-205`, ElevenLabs word-timed, 503 when not configured). **These TTS/STT engines live in `gateway`, not `voice/`.**

**Auth gating** (`voice_routes.py:124-145`): `/v1/ask` requires **both** `decision:read` AND `evidence:read` scopes (`voice_routes.py:136-141`) because it returns sealed `evidence_hash` anchors. In keyless dev the anonymous principal carries every scope.

### Out (what this unit depends on)

Internal `tex` subsystems:
- `tex.domain.verdict.Verdict` (`voice_gate.py:64`, `voice_ask.py:40`) — the PERMIT/ABSTAIN/FORBID enum (verified `domain/verdict.py:6-25`).
- `tex.vigil.Explainer` (`voice_ask.py:41`) — deterministic facts via `provider=None`.
- `tex.vigil.utterances.{UtteranceForm, fill}` (`answer_forms.py:29`) — the IRON RULE filler (verified raises on missing slot, `utterances.py:158`).
- `tex.evidence.seal.{EvidenceChainSigner, verify_payload_signature, PQ_SIGNATURE_FIELD}` (`attestation.py:52`, `entailment_cert.py:82`) — the production signing/canonicalisation primitives.
- `tex.events._ecdsa_provider.default_signature_provider` (`attestation.py:53`) — keypair source.
- `tex.bench.wave2_corpus.loaders.LoadedCorpus` (`entailment_cert.py:97-98`, **TYPE_CHECKING only — no runtime import**).

Indirectly via `voice_routes` (gateway, not `voice/`): `tex.gateway.grant`, `tex.gateway.backends.{ElevenLabsTTS, synthesize_tts}`, `tex.api.auth`, `tex.api.vigil_routes._resolve_effective_tenant`.

External libraries:
- **stdlib only on the live path:** `hashlib`, `json`, `os`, `threading`, `re`, `math`, `dataclasses`, `datetime`, `pathlib`, `enum`, `uuid`, `collections.abc`, `typing`.
- `pydantic` — only in `entailment_cert.py` (OFF live path).
- `torch` / `transformers` — **lazy-imported inside `NeuralNLIScorer.load()` only**, never at module import. **Verified they RAISE `ImportError` in this environment** (torch `_C` dylib fails to load), so the neural seam is fail-closed by default.

---

## Implementation Reality

**REAL (runs by default, on the live path):**
- The full deterministic cascade: `route_intent`, `build_dimension_answer`/`build_record_answer`, `VoiceGate.evaluate` (Rules A/B + fail-closed fallback), `VoiceAttestor.seal`/`verify_chain`/`verify_signatures`. **71/71 tests pass** (`pytest tests/voice -q` → `71 passed in 2.87s`).
- Runtime-verified behaviors: reconstruction → `PERMIT`/`reconstruction-exact`; contradiction → `FORBID`/`asserted-verdict-FORBID-contradicts-sealed-PERMIT`; `NeuralNLIScorer().load() == False`, `name == "neural-nli(off)"`; `route_intent('how many were forbidden')` → DIMENSION/execution; `route_intent('hello there')` → ABSTAIN/no-keyword-match.
- The attestation chain is a real hash-chain + real ECDSA-P256 signature (reuses the production `evidence.seal` signer, not a mock).
- The conformal math is real and computable (`conformal_lambda_hat([0.2,0.8,0.5],0.1) == 1.0` verified) — it is a genuine order-statistic quantile, not a stub.

**REAL-BUT-FAIL-CLOSED (present, does not run here):**
- `NeuralNLIScorer` (`voice_gate.py:190-279`) is a **real cross-encoder implementation** (lazy `transformers`/`torch`, constructs the model, reads the entailment index from the model's own config, runs softmax). It is **not a hollow stub**. It is OFF only because `import transformers` raises in this env (verified). `entails()` returns `None` → the gate ABSTAINs. It can **never raise a verdict to PERMIT** even if loaded, because `entails()` requires a calibrated λ̂ (`voice_gate.py:277-279`) and the gate only ever uses neural `True` to *keep* a token sealed, never to promote prose to PERMIT.
- `calibrate`/`commitment_from_calibration` are real and fail-closed (refuse to compute a quantile from an unloaded scorer or missing scores).

**NOT on the live path (dead-for-the-app, alive-for-capstone):**
- `entailment_cert.py` entirely — its own docstring says "Live wiring is DEFERRED" (`:68`), and neither `voice_ask` nor `voice_routes` imports it. Reachable only from `tex.capstone` (itself test/bench-only). This is a deferred seam, **not dead code** in the rot sense — it has 663 lines of validated logic and a test file (`tests/voice/test_entailment_cert.py`), but it is **ORPHAN with respect to the running app**.
- `voice_gate.py` calibration helpers (`calibrate`, `Calibration`, `conformal_lambda_hat`) and `NeuralNLIScorer.{score, set_lambda_hat, entails-when-loaded}` — constructible and tested, but never executed by `/v1/ask` because the neural scorer never loads in-env.

**No `NotImplementedError` / `TODO` / `pass`-only stubs found** in `voice/`. The `except … pass` at `voice_gate.py:487-488` is a deliberate fall-through (reconstruction failed → token decomposition), not a swallowed bug. The `except OSError: pass` at `attestation.py:179-182` is deliberate best-effort persistence (in-memory chain stays authoritative).

---

## Technology / SOTA

- **Faithfulness-by-construction:** the PERMIT path is `answer == template.format(**slots)` — a reconstruction proof that makes every non-template token a sealed value tautologically. This is stronger than any learned faithfulness classifier; it is the unit's core idea.
- **Split-conformal factuality** (Mohri & Hashimoto, "Language Models with Conformal Factuality Guarantees", ICML 2024, arXiv:2402.10978): λ̂ = ⌈(n+1)(1-α)⌉-th order statistic of per-example nonconformity (`voice_gate.py:330-349`). Implemented as a pure order statistic. **Honestly labelled UNCALIBRATED** for the live gate because (1) the scorer can't run in-env and (2) only a synthetic corpus exists — a synthetic quantile certifies only the synthetic distribution. The module even cites arXiv:2512.15068 ("The Semantic Illusion") showing embedding/NLI conformal detectors collapse on real hallucinations (`voice_gate.py:50`, `entailment_cert.py:11-15`).
- **Cross-encoder NLI** (DeBERTa-v3 MNLI, `MoritzLaurer/DeBERTa-v3-base-mnli`, `voice_gate.py:210`): the entailment upgrade seam, with a self-locating entailment-class index (never hard-coded).
- **Hash-chained, per-record-signed evidence log** (`attestation.py`): Merkle-style append-only chain (`record_hash` commits to `payload_sha256` + `previous_hash`) with ECDSA-P256 (NIST P-256) per-record signatures, separating integrity/ordering (chain) from authorship (signature) — and, in `entailment_cert`, a third proof (key-pin) for "Tex wrote this."
- **Pydantic coherence validator** (`entailment_cert.py:230-314`) as a structural honesty enforcer — a dishonest commitment is *unconstructible*, not merely discouraged.
- **Design patterns:** frozen slotted dataclasses throughout; Protocol-based scorer interface (`Scorer`, `voice_gate.py:118-125`); double-checked-locked lazy singleton (`get_attestor`, `voice_ask.py:70-84`); deterministic-floor provider pattern (zero-LLM via `provider=None`).

---

## Persistence

- **Voice-attestation chain:** **in-memory by default** (`self._records: list`, `attestation.py:92`), one `VoiceAttestor` per process pinned to `app.state.voice_attestor` (`voice_ask.py:82`) so the chain is continuous across requests within a process but **lost on restart**. An **append-only JSONL mirror** is written only when `TEX_VOICE_ATTEST_PATH` is set (`attestation.py:97-98`, `_maybe_persist` at `:171-182`) — best-effort, swallows `OSError`.
- **Signing key:** ephemeral per-`VoiceAttestor` unless `TEX_VOICE_ATTEST_KEY` is set; **no rotation, no KMS** (weaker than the main ledger — `attestation.py:32-36`). Losing the key makes signatures unverifiable (chain integrity survives, authorship does not).
- **Decision lookups** read from `app.state.decision_store` (`voice_ask.py:109`) — that store's durability is owned by another subsystem, not `voice/`.
- **Everything else** (`intent`, `answer_forms`, `voice_gate`) is pure/stateless — frozen tables and frozen dataclasses, no mutable module state except the two shared stateless singletons in `voice_ask.py:52-53`.
- **Transcripts are never stored verbatim** — only `transcript_sha256` is sealed (`attestation.py:140`), a deliberate privacy choice.

---

## Notable Findings

1. **No `VOICE_ENABLED` flag exists in this backend repo.** `grep -rn VOICE_ENABLED src/` is empty; `build_voice_router()` is mounted unconditionally at `main.py:1459`. The "voice muted via VOICE_ENABLED" memory refers to the *frontend* `tex-systems-lightup` repo (claim, unverified — out of scope). **The backend voice cascade is fully wired and live.** STT/TTS are gated *operationally* (503 when no gateway secret / no ElevenLabs key) but never code-disabled here.

2. **TTS/STT are NOT in `voice/`.** They live in `tex.gateway.backends` — `WhisperSTT` (faster-whisper/CTranslate2, real when `faster_whisper` + model files present), `KokoroTTS` (Kokoro-82M ONNX, real local speech), `ElevenLabsTTS` (cloud signature voice), with an honest `OfflineTTS` content-free tone fallback (`gateway/backends.py:139-150`) that **labels itself** `"offline-tone(no-voice)"` so a placeholder is never mislabeled as real speech. The `voice/` unit is pure text-grounding + attestation; `/v1/speak` in `voice_routes` calls into the gateway.

3. **`entailment_cert.py` (663 lines, 27% of the unit) is OFF the live path.** Its own docstring concedes "Live wiring is DEFERRED" (`:68`). It is consumed only by `tex.capstone`, which has zero importers in `src/tex` outside itself — so it is reachable only from tests/bench. Substantial, validated, tested — but **ORPHAN with respect to `tex.main`**. Anyone reading the package docstring (`__init__.py`) would not learn this; the `__init__` lists `attestation` as the fifth piece and omits `entailment_cert` entirely (consistent, but the file's prominence could mislead).

4. **Docstrings are unusually honest and match the code.** Every "honest limit" claim I checked held: ECDSA-P256-not-PQ (verified `is_post_quantum` plumbing), neural-seam-fails-closed (verified `import transformers` raises), UNCALIBRATED threshold label (verified no "guarantee/coverage/1-alpha" in user-facing strings — the only user-facing strings are 4 fixed decline lines), transcript-hashed-not-stored (verified `attestation.py:140`). This is the *opposite* of the overstated-audit pattern the ground rules warn about — the voice unit under-claims if anything.

5. **The gate is provably one-sided.** Reading every `return` in `VoiceGate.evaluate`: PERMIT is emitted **only** from the reconstruction path (`voice_gate.py:480`). Every other branch returns ABSTAIN or FORBID. There is **no path** by which prose or a neural score can promote an answer to PERMIT — the neural scorer can only *keep a token sealed*, never certify prose. The "fail closed" doctrine is structurally true, not aspirational.

6. **`__init__.py` exports nothing** (`__all__ = []`). Not a defect — consumers import submodules — but worth noting the package is documentation-first; there is no façade.

7. **Key-management weakness is real and self-disclosed** (`attestation.py:32-36`): ephemeral per-process key, no rotation, no KMS. The hash chain proves integrity regardless, but signature *authorship* is only as durable as the (currently ephemeral) key. `entailment_cert.verify_entailment_commitment` reports `authorship_ok=None` (UNVERIFIED) absent a pinned public key (`entailment_cert.py:607-611`) — an honest treatment of the re-mint-around-a-swap attack it names (`:56-60`).

8. **No dead code in the rot sense.** No `NotImplementedError`, no `TODO`, no `pass`-only placeholders on the live path. The two bare `except: pass` sites are deliberate (reconstruction fall-through; best-effort persistence).
