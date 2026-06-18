# Subsystem Dossier: TEE Attestation & External Verifier

**Scope:** `src/tex/tee/` and `src/tex/verifier/`
**Branch:** `feat/proof-carrying-gate`
**Layer:** Evidence (`tex.tee.__layer__ = 5`, `__layer_kind__ = 'evidence'`, [`tee/__init__.py:26-27`](../../../src/tex/tee/__init__.py))

> Audit discipline: every claim below is traced from code. Docstring/`.md` claims that were not confirmed in code are explicitly labelled "(claim, unverified)". File:line references are absolute under `/Users/matthewnardizzi/dev/tex`.

---

## Overview

Two distinct units share this dossier because the task scopes them together, but **they are architecturally independent and do not import each other**:

1. **`tex.tee`** — Composite hardware-attestation client. Collects Intel **TDX** (CPU TEE) + NVIDIA **H100/H200/B200/B300** (GPU TEE) evidence, submits it to **Intel Trust Authority (ITA)** for a composite JWT, and provides a **fail-closed verifier** for that JWT (issuer/nonce/expiry/debuggable/TCB/GPU/EAT-AI/signature checks producing an **AR4SI trustworthiness vector**). It also adds a **verdict-binding** layer that folds the categorical PERMIT/ABSTAIN/FORBID verdict into the TDX `report_data` the quoting hardware signs, plus a large catalog of "SOTA-2026" frontier augmentation data structures. **Wired LIVE** via the `/v1/tee/*` API router and the decision-path evidence recorder.

2. **`tex.verifier`** — A *separate*, minimal-TCB **standalone offline verdict-bundle checker**. It re-derives the canonical-JSON / SHA-256 hash-chain / ECDSA-or-ML-DSA signature checks of a sealed Tex ledger bundle **from scratch**, importing only stdlib + `cryptography` and **zero** Tex decision-engine code. It is reachable only as a CLI (`python -m tex.verifier`) and from tests. **It has no in-tree `src/` importer** (confirmed orphan within `src`). Note: it is NOT the `verify_bundle` that the capstone/bench/adversarial subsystems call — that is a *different* function in `tex.bench.evidence_bundle` (see Notable Findings).

The two share a conceptual mission (offline-verifiable, fail-closed evidence) but no code.

---

## File Inventory

### `src/tex/tee/`

| File | Lines | Role |
|------|------:|------|
| [`__init__.py`](../../../src/tex/tee/__init__.py) | 140 | Layer marker (`__layer__=5`); re-exports the public surface from the 5 substantive modules; 43-symbol `__all__`. |
| [`attestation_client.py`](../../../src/tex/tee/attestation_client.py) | 1014 | Core composer + verifier. `compose_attestation`/`compose_from_evidence`, ITA submission, test-mode + signed JWT builders, `verify_attestation` (fail-closed), JWS signature verification (PS384/RS256/ES384/ES256 + ML-DSA via pqcrypto), `decision_bound_nonce`, `ExpectedMeasurements`. |
| [`composite.py`](../../../src/tex/tee/composite.py) | 588 | Pydantic-v2 on-the-wire models: `CpuTeeType`/`GpuTeeType` enums, `EatAiDigest`/`EatAiClaims` (draft-messous-eat-ai-01), `CompoundAttestationLink`, `CompositeAttestationEnvelope`, `TrustworthinessVector` + `_TrustState` (AR4SI), `CompositeVerificationResult`. |
| [`h100_attestation.py`](../../../src/tex/tee/h100_attestation.py) | 158 | NVIDIA GPU evidence collector. `GpuEvidence`, `collect_gpu_evidence` (nv_attestation_sdk real path + dev stub), `is_gpu_cc_capable`, NVML hwmodel detection. |
| [`tdx_attestation.py`](../../../src/tex/tee/tdx_attestation.py) | 135 | Intel TDX evidence collector. `TdxEvidence`, `collect_tdx_evidence` (Intel client real path + dev stub), `is_tdx_capable`, `fresh_user_data`. |
| [`verdict_binding.py`](../../../src/tex/tee/verdict_binding.py) | 492 | Proof-of-Guardrail layer. Folds verdict + policy digest + input hash + prior ledger hash into TDX `report_data`; `verify_verdict_binding`, `verdict_bound_nonce`, test + signed builders. Consumed only by `tex.capstone`. |
| [`sota_2026.py`](../../../src/tex/tee/sota_2026.py) | 854 | Frontier augmentation data structures + verifier: `MeasuredComponent`, `CoRimReferenceValue`, COSE/JOSE PQ alg IDs, `GpuTeePlatform`, `DriverPinning`, `TdispEvidence`, `MultiGpuBatch`, `PersistentMemoryRegion`, `TsmEventLog`, `ScittReceipt`, `check_tcb_advisories`, `LongHaulNonce`, `Sota2026Augmentation`, `verify_sota_2026`. |
| [`_mode_probe.py`](../../../src/tex/tee/_mode_probe.py) | 136 | Never-raising probe reporting `TEX_TEE_ATTESTATION_MODE` + whether real TDX capability exists. Shares `ProbeResult` with `tex.pqcrypto._backend_probe`. No consumer on any verdict path (by design). |

### `src/tex/verifier/`

| File | Lines | Role |
|------|------:|------|
| [`__init__.py`](../../../src/tex/verifier/__init__.py) | 35 | Re-exports the *checker only* (`verify_bundle`, `load_bundle`, `check_monotonicity_witness`, report shapes). Deliberately does NOT re-export `export.py` to keep the TCB tiny. |
| [`check.py`](../../../src/tex/verifier/check.py) | 760 | The whole TCB. `verify_bundle` (hash-chain replay + signature pin + monotonicity witness), `check_monotonicity_witness`, `verify_no_identity_gaps`, `_verify_signature` (ECDSA-P256 + FIPS-204 ML-DSA), report dataclasses. stdlib + `cryptography` only. |
| [`export.py`](../../../src/tex/verifier/export.py) | 137 | Producer-side bridge (NOT in the checker TCB). Duck-typed conversion of a live `SealedFactLedger` / `SealedFactBundle` into the portable `tex-offline-verdict/1` JSON schema. |
| [`__main__.py`](../../../src/tex/verifier/__main__.py) | 94 | CLI entry: `python -m tex.verifier <bundle.json> --pin <key.pem> [--pq-pin alg=pem] [--require-witness] [--json]`. Exit 0 iff valid. |

---

## Internal Architecture

### `tex.tee` data flow (compose path)

```
decision_id, request_id
   │
   ▼ decision_bound_nonce()            attestation_client.py:99   (SHA-256("tex|did|rid")[:32])
   │
   ▼ user_data = nonce(upper32) ++ SHA-256(upper32)   attestation_client.py:157-159
   │
   ├─ collect_tdx_evidence(user_data)  tdx_attestation.py:80   → TdxEvidence(quote, is_dev_mode)
   ├─ collect_gpu_evidence(nonce)      h100_attestation.py:62  → GpuEvidence(blob, hwmodel, is_dev_mode)
   │
   ▼ compose_from_evidence()           attestation_client.py:177
   │   is_dev = tdx.is_dev_mode or gpu.is_dev_mode
   │   mode   = TEX_TEE_ATTESTATION_MODE (default "production")
   │   ┌─ is_dev & mode!="test" → RuntimeError (refuse to emit)  :196-201
   │   ├─ is_dev & mode=="test" → build_test_mode_composite_jwt (alg=none)  :202
   │   └─ not is_dev            → _request_ita_composite_token (ITA network) :209
   │
   ▼ parse JWT, extract tdx/nvgpu blocks → CompositeAttestationEnvelope  :230-249
```

**Key functions / classes:**

- **`decision_bound_nonce(decision_id, request_id)`** [`attestation_client.py:99`](../../../src/tex/tee/attestation_client.py) — CrossGuard freshness nonce = `sha256("tex|{decision_id}|{request_id}")[:32]`. Raises on blank `decision_id`. This is the anti-replay primitive cited throughout.
- **`compose_attestation` / `compose_from_evidence`** [`:144` / `:177`](../../../src/tex/tee/attestation_client.py) — the two-stage composer. `compose_from_evidence` enforces the **production guard** at `:196` — dev-stub evidence is refused unless `TEX_TEE_ATTESTATION_MODE=test`. This is a real, code-enforced fail-closed posture, not a docstring promise.
- **`_request_ita_composite_token`** [`:262`](../../../src/tex/tee/attestation_client.py) — the only outbound-network path. Imports `inteltrustauthorityclient.connector.*` lazily; raises `RuntimeError` if SDK absent or `TEX_ITA_API_URL`/`TEX_ITA_API_KEY` unset. Calls `connector.get_token_v2(tdx_args, gpu_args)`. EAT-AI claims are attached as TDX `runtime_data`. Never invoked in dev/test.
- **`build_test_mode_composite_jwt`** [`:440`](../../../src/tex/tee/attestation_client.py) — deterministic `alg=none` JWT mirroring the ITA composite claim shape, carrying `x-tex-test-mode: true`. Measurements at `:360-364` are SHA-256 over the (stub) evidence bytes — explicitly NOT real Intel measurements.
- **`build_signed_composite_jwt`** [`:577`](../../../src/tex/tee/attestation_client.py) — a genuinely SIGNED JWT (`alg != none`, default PS384). Reuses `_composite_claims` verbatim so test-mode and signed tokens carry byte-identical claim structure (`:344`). Signs `header_b64.payload_b64` via `_sign_signing_input` [`:533`]. Does NOT set `x-tex-test-mode`, so it verifies through the real signature path.
- **`generate_standin_ita_keypair`** [`:495`](../../../src/tex/tee/attestation_client.py) — generates a local RSA/EC keypair as a STAND-IN for Intel's real ITA signing key (honest residual documented in-code: it exercises the signed *path*, not a real Intel attestation).
- **`verify_attestation(jwt, *, expected_issuer, expected_nonce, expected)`** [`:649`](../../../src/tex/tee/attestation_client.py) — the fail-closed verifier. **11 ordered gates**, each returning `_fail(code, detail)` early:
  1. Parse (`:663`) → `parse_error`.
  2. **`alg=none` gate** (`:672`): rejected in production (`test_mode_in_prod`); allowed in test env only with the `x-tex-test-mode` marker. An `x-tex-test-mode` marker in production is also rejected (`:677`).
  3. Issuer match (`:681`) → `issuer_mismatch`.
  4. Nonce match (`:686`, via `_nonce_matches` consulting `nvgpu.eat_nonce`/`eat_nonce`/`verifier_nonce`, `:781`) → `nonce_mismatch`.
  5. Expiry (`:690`) → `expired`.
  6. TDX debuggable (`:697`) → `tdx_debuggable`.
  7. TCB status in {OutOfDate, OutOfDateConfigurationNeeded, Revoked} (`:702`) → `tcb_out_of_date`.
  8. GPU `measres == comparison-successful` AND report-signature-verified (`:709-712`) → `gpu_measres_failed`/`gpu_signature_unverified`.
  9. EAT-AI model-id/hash vs `ExpectedMeasurements` (`:717-730`).
  10. Operator-pinned MRTD/RTMR0/hwmodel (`:733-744`).
  11. **Signature** (`:747`): for `alg != none`, verify via `_verify_signature`; **rejected only if `not ok and not is_test_env`** (`:753`).
  Then maps to an AR4SI `TrustworthinessVector` via `_build_trust_vector` (`:799`) and returns a `CompositeVerificationResult`.
- **`_verify_signature`** [`:855`](../../../src/tex/tee/attestation_client.py) — algorithm-agile JWS verification. Resolves the pinned key from `TEX_ITA_PUBLIC_KEY_PEM` or `TEX_ITA_JWKS_PATH` (`:862-863`; returns `no_ita_public_key_configured` if neither). ML-DSA-44/65/87 + `hybrid-ml-dsa-65-ed25519` delegate to `tex.pqcrypto.algorithm_agility.get_signature_provider` (`:883-914`). Classical PS384 (PSS/SHA-384), RS256 (PKCS1v15/SHA-256), ES384/ES256 (raw r‖s re-DER'd, `:957-969`) via `cryptography`. Accepts a PEM cert or raw public key. `_jwks_to_pem` (`:976`) converts the first RSA JWK to PEM.
- **`_build_trust_vector`** [`:799`](../../../src/tex/tee/attestation_client.py) — maps raw ITA claims to the 5 AR4SI axes (instance_identity, configuration, executables, hardware, runtime_opaque) using `_TrustState` {affirming, warning, contraindicated, none}.

### `composite.py` models

All models are `frozen=True, extra="forbid"` (pydantic-v2 strict). `EatAiClaims` ([`:175`](../../../src/tex/tee/composite.py)) implements the draft-messous-eat-ai-01 generic claims with a `to_cwt_int_map()` ([`:261`]) serializing to CBOR integer keys −75000…−75012. `CompositeAttestationEnvelope` ([`:356`]) is the payload mirrored into `EvidenceRecord.payload_json`; its authenticity derives from the embedded ITA JWT signature plus the parent record's hash chain (docstring `:370-375`). `CompoundAttestationLink` ([`:307`]) carries `previous_jwt_sha256` for multi-hop agent chains.

### `verdict_binding.py` (Proof-of-Guardrail)

The narrow delta over `attestation_client`: bind the **verdict content** into the one field TDX hardware signs.

- **`verdict_bound_nonce`** [`:145`](../../../src/tex/tee/verdict_binding.py) = `sha256("tex-poguard|v1|{verdict}|{policy_digest}|{input_sha256}|{prev}")[:32]`. Domain-separated from `decision_bound_nonce`'s `"tex|"` prefix so verdict and decision nonces can never collide.
- **`report_data_for_nonce`** [`:181`] expands the 32-hex nonce → 64-byte `report_data` (upper32 ‖ SHA-256(upper32)), mirroring `compose_attestation`.
- **`verify_verdict_binding`** [`:277`] — the load-bearing verifier. **Step 2** (`:342-354`) recomputes the expected `report_data` and `hmac.compare_digest`'s it (constant-time) against `tdx.tdx_report_data` — **never** `eat_nonce`. **Step 3** (`:357`) delegates to `verify_attestation` for the hardware posture. Then re-checks the JWS signature directly (`:383-388`) to record `signature_verified` posture-independently. The module docstring (`:31-42`) explicitly documents the bug it fixes: a verifier gating on the soft `eat_nonce` JSON field gives a *hollow* binding because a host can re-wrap a captured token and set `eat_nonce` arbitrarily; `report_data` is covered by the TDX quote signature.
- **Builders** `build_verdict_bound_test_jwt` ([`:408`], unsigned) and `build_verdict_bound_signed_jwt` ([`:444`], real PS384 JWS) set the TDX dev `user_data` to the verdict's `report_data` so an honest composer's quote carries the expected binding.

### `sota_2026.py`

A catalog of frontier data structures + one verifier `verify_sota_2026` ([`:725`](../../../src/tex/tee/sota_2026.py)). The verifier performs **real checks** on present-but-optional sub-fields: driver pinning (blocklist/allowlist/`_semver_lt` min-version, `:743-759`), TDISP run-locked (`:761-765`), TCB advisory blocklist (`:767-772`), TSM event-log RTMR0..3 consistency (`:774-785`), SCITT presence (`:787-789`). `check_tcb_advisories` ([`:495`]) reads the `TEX_TEE_BLOCKED_ADVISORY_IDS` env blocklist. `_semver_lt` ([`:805`]) does numeric-tuple driver-version comparison. `LongHaulNonce.build` ([`:596`]) composes decision+transcript+fleet nonces. The COSE/JOSE PQ algorithm IDs (`:224-237`) are hard-coded constants from in-flight IETF drafts.

### `_mode_probe.py`

`probe_attestation_mode` ([`:116`](../../../src/tex/tee/_mode_probe.py)) is a never-raising availability probe. It mirrors `is_tdx_capable`'s two components (ITA SDK importable, quote device present) AND conjoins the oracle itself (`:97-101`) so a drifted mirror can only under-report. Reports `TEX_TEE_ATTESTATION_MODE` raw but never lets the mode affect `available` (`:78-80`). Builds on `tex.pqcrypto._backend_probe.ProbeResult`.

### `tex.verifier` data flow (offline check)

```
bundle JSON (tex-offline-verdict/1)  +  optional pinned ECDSA key  +  optional --pq-pin
   │
   ▼ verify_bundle()                  check.py:464
   │  per record:
   │   1. recompute payload_sha256 = sha256(stable_json(canonical_payload))   :530
   │      recompute record_hash    = sha256(stable_json({payload_sha256, previous_hash}))  :531
   │      chain_ok iff claimed previous_hash/payload_sha256/record_hash all match  :536
   │   2. verify each signature over the RECOMPUTED record_hash against the PINNED key  :552-587
   │      (ECDSA-P256 live; ML-DSA tri-state True/False/None)
   │   3. extract monotonicity_witness from signed canonical_payload only  :596
   │      check_monotonicity_witness() invariants  :342
   │
   ▼ VerificationReport (chain_intact, signatures_valid, key_matches_pin, pq_*, witness_*)
```

- **`_stable_json`** [`check.py:94`](../../../src/tex/verifier/check.py) — re-implements (does not import) the ledger's canonical JSON (`sort_keys, separators=(",",":"), default=str`) so the TCB stays one file. The docstring claims byte-for-byte parity with `provenance/ledger.py` (claim, partially verified: the canonical form and the two-field record-hash construction are re-derived here; I did not diff against `provenance/ledger.py` line-by-line — see Notable Findings).
- **`verify_bundle`** [`:464`] — never raises on tampered input; every failure is a field on `VerificationReport`. Recomputes hashes and **never trusts the claimed ones** (`:525`). Verifies signatures over the recomputed `record_hash` against the **pinned** key, not the bundle's embedded key (`:559`). Once the chain breaks, later records are marked untrusted (`chain_live = False`, `:550`).
- **`_verify_signature`** [`:286`] — dispatches on the *loaded key type* (robust to a mislabeled `algorithm` tag): EC key → ECDSA-P256+SHA-256; ML-DSA key → FIPS-204 pure verify (guarded import of `cryptography.hazmat.primitives.asymmetric.mldsa`, available only on cryptography ≥ 48). Returns `None` (not False) when no backend can interpret the key — honest tri-state.
- **`check_monotonicity_witness`** [`:342`] — validates a sealed witness against monotone-lowering invariants: caution never decreases toward PERMIT (`raised_toward_permit`), per-stage chain continuity (`broken_stage_chain`), structural floor forces FORBID and only a *structural* (not probabilistic) stage may fire it (`probabilistic_fired_floor`), and the declared `structural_floor_fired` flag matches reality. All malformed shapes are violations, never exceptions.
- **`verify_no_identity_gaps`** [`:704`] + `GapReport` [`:664`] — negative-space check: per-identity `identity_seq` values (read from the signed `canonical_payload.detail`) must be contiguous from 0 with no duplicates. A missing seq = a missing receipt = a possible bypass. Note: `bool` excluded from `int` check (`:736`) so True/False can't pose as a seq.
- **`VerificationReport`** [`:143`] — fine-grained tri-state reporting: `is_valid` (baseline court-exhibit guarantee), `fully_verified` (+ PQ pinned), `fully_witnessed` (+ all decisions witnessed). Fail-closed: an empty/unparseable bundle is never `is_valid` (`:180`).

---

## Public API

### `tex.tee` (`__init__.py` `__all__`, 43 symbols)

Composer/verifier: `compose_attestation`, `compose_from_evidence`, `verify_attestation`, `decision_bound_nonce`, `build_test_mode_composite_jwt`, `ExpectedMeasurements`, `ITA_PROD_ISSUER`.
Models: `CompositeAttestationEnvelope`, `CompositeVerificationResult`, `CompoundAttestationLink`, `CpuTeeType`, `EatAiClaims`, `EatAiDigest`, `GpuTeeType`, `TrustworthinessVector`.
Collectors: `GpuEvidence`, `TdxEvidence`, `collect_gpu_evidence`, `collect_tdx_evidence`, `fresh_user_data`, `is_gpu_cc_capable`, `is_tdx_capable`.
SOTA-2026: `MeasuredComponent`, `CoRimReferenceValue`, COSE alg constants, `cose_alg_id_for`, `GpuTeePlatform`, `DriverPinning`, `TdispEvidence`, `MultiGpuBatch`, `PersistentMemoryRegion`, `TsmEventLog`, `ScittReceipt`, `TcbAdvisoryCheckResult`, `check_tcb_advisories`, `LongHaulNonce`, `Sota2026Augmentation`, `Sota2026VerifyOutcome`, `verify_sota_2026`.

**Not re-exported from `__init__` but imported by callers:** `build_signed_composite_jwt`, `generate_standin_ita_keypair` (capstone), `verdict_binding.*` (capstone), `_mode_probe.probe_attestation_mode` (tests), and the private `_parse_jwt`/`_verify_signature`/`_ENV_MODE` (reused by `verdict_binding` and `_mode_probe`).

### `tex.verifier` (`__init__.py` `__all__`)

`PORTABLE_BUNDLE_VERSION` (`"tex-offline-verdict/1"`), `RecordReport`, `SignatureResult`, `VerificationReport`, `check_monotonicity_witness`, `load_bundle`, `verify_bundle`. The producer bridge `export.py` (`portable_bundle*`) is intentionally NOT re-exported.

---

## Wiring

### Wiring In — `tex.tee` is **LIVE**

**Live call path #1 — `/v1/tee/*` API router:**

```
tex.main.create_app
  → app.include_router(tee_router)                  src/tex/main.py:1508
       tee_router = tex.api.tee_routes.router        src/tex/main.py:26
  → POST /v1/tee/verify  → verify()                  src/tex/api/tee_routes.py:188
       → verify_attestation(...)                     src/tex/api/tee_routes.py:205
  → GET  /v1/tee/status  → status_endpoint()         src/tex/api/tee_routes.py:241
       → is_tdx_capable() / is_gpu_cc_capable()      src/tex/api/tee_routes.py:252-253
```
Both routes carry `RequireScope("evidence:read")` ([`tee_routes.py:59`](../../../src/tex/api/tee_routes.py)). This is a real, mounted FastAPI router — confirmed at [`main.py:1508`](../../../src/tex/main.py).

**Live call path #2 — decision-path evidence recorder (gated):**

```
tex.main.build_runtime
  → EvaluateActionCommand(...)                       src/tex/main.py:962
  → app.state.evaluate_action_command = ...          src/tex/main.py:1656
  → EvaluateActionCommand._build_decision_metadata
       if os.environ["TEX_TEE_MODE"] == "1":         src/tex/commands/evaluate_action.py:679
          from tex.tee import compose_attestation     :681
          envelope = compose_attestation(decision_id, request_id)  :683
          metadata["tee_composite_attestation"] = envelope.model_dump(...)  :686
```
Gated by `TEX_TEE_MODE=1` ([`evaluate_action.py:679`](../../../src/tex/commands/evaluate_action.py)); failures are caught and recorded as a metadata flag, never blocking the decision (`:692-700`). `EvaluateActionCommand` is the canonical decision command constructed in `build_runtime` — so when the flag is set this is genuinely on the hot decision path.

**Other importers of `tex.tee`:**
- `tex.pqcrypto._backend_probe` references `tex.tee._mode_probe` ([`_backend_probe.py:9`](../../../src/tex/pqcrypto/_backend_probe.py)) — the probe registry.
- `tex.config:252` (docstring reference only).
- `tex.capstone.{compose,tamper,verify}` import `verdict_binding` + `generate_standin_ita_keypair` — see below.

**`verdict_binding` reachability:** consumed **only** by `tex.capstone` (compose.py:79-82, tamper.py:48, verify.py:574). `tex.capstone` has **no** `__main__.py`, no router, and no importer in `tex.main` (verified: `grep capstone src/tex/main.py` → empty). So `verdict_binding` is **DEMO_TEST_ONLY / capstone-only**, not on any live request path. The verdict-bound signed path is what the capstone composes ([`capstone/compose.py:400`](../../../src/tex/capstone/compose.py)).

### Wiring In — `tex.verifier` is **ORPHAN within `src`**

`grep -rn "tex\.verifier" src --include="*.py"` returns **nothing** outside `src/tex/verifier/` itself. The module's only consumers are:
- The CLI `python -m tex.verifier` ([`__main__.py`](../../../src/tex/verifier/__main__.py)).
- Tests: `tests/test_offline_verifier.py:40-41` imports `tex.verifier.check` and `tex.verifier.export`.

It is therefore **ORPHAN as a library symbol** but **LIVE as a CLI tool** (a real, runnable entrypoint with `cryptography`-backed verification). The spine pass classified it `INDIRECT`; the precise truth is: *no `src` importer; reachable only via its own CLI and tests.* This is **by design** — the whole pitch is that the checker has the smallest possible TCB and imports zero engine code ([`check.py:3-11`](../../../src/tex/verifier/check.py), [`__init__.py:1-13`](../../../src/tex/verifier/__init__.py)).

### Wiring Out — dependencies

**`tex.tee` → internal:**
- `tex.tee.attestation_client` → `tex.pqcrypto.algorithm_agility` (`SignatureAlgorithm`, `get_signature_provider`) for the ML-DSA/hybrid verify branches ([`attestation_client.py:885,903`](../../../src/tex/tee/attestation_client.py)) — lazy import.
- `tex.tee.verdict_binding` → `tex.domain.verdict.Verdict` ([`verdict_binding.py:81`](../../../src/tex/tee/verdict_binding.py)) and the private `attestation_client._parse_jwt/_verify_signature/build_*`.
- `tex.tee._mode_probe` → `tex.pqcrypto._backend_probe` (`ProbeResult`, `_guarded`, `_safe_bool`, `TIER_NONE`).

**`tex.tee` → external libraries (all lazy / optional):**
- `cryptography` (RSA/EC/PSS/ECDSA, x509) — for JWS signing/verification.
- `pydantic` v2 — model layer (hard dep, imported at module load in `composite.py`/`sota_2026.py`).
- `inteltrustauthorityclient` (`trustauthority-client-for-python`) — ITA submission + real TDX quote, lazy/optional ([`attestation_client.py:278`](../../../src/tex/tee/attestation_client.py), [`tdx_attestation.py:91`](../../../src/tex/tee/tdx_attestation.py)).
- `nv_attestation_sdk` — real GPU evidence, lazy/optional ([`h100_attestation.py:77`](../../../src/tex/tee/h100_attestation.py)).
- `pynvml` — GPU model detection, lazy/optional ([`h100_attestation.py:137`](../../../src/tex/tee/h100_attestation.py)).

**`tex.verifier` → internal:** `export.py` imports `PORTABLE_BUNDLE_VERSION` from `check.py`; otherwise duck-typed against ledger objects (no static import). `check.py` imports **nothing** from Tex.
**`tex.verifier` → external:** stdlib only + `cryptography` (lazy, only for signature verify, [`check.py:294-297`](../../../src/tex/verifier/check.py)).

---

## Implementation Reality

**Verdict: REAL.** No `NotImplementedError`, `TODO`, `FIXME`, or `pass`-only placeholder exists anywhere in `src/tex/tee` or `src/tex/verifier` (verified by grep). All imports load cleanly (`PYTHONPATH=src python -c "import ..."` succeeded for all 9 modules).

### Real logic vs. fallbacks (TEE)

- **Native hardware path is real but optional.** Both collectors import the vendor SDK lazily and call genuine evidence APIs:
  - TDX: `IntelTDXAdapter(user_data).collect_evidence(nonce)` ([`tdx_attestation.py:95-96`](../../../src/tex/tee/tdx_attestation.py)).
  - GPU: `attestation.Attestation()...get_evidence()` ([`h100_attestation.py:79-88`](../../../src/tex/tee/h100_attestation.py)).
  - ITA: `ITAConnector(config).get_token_v2(tdx_args, gpu_args)` ([`attestation_client.py:330`](../../../src/tex/tee/attestation_client.py)).
- **Dev-stub fallback is honestly flagged.** When hardware/SDK is absent, `collect_tdx_evidence`/`collect_gpu_evidence` return deterministic stubs with `is_dev_mode=True` ([`tdx_attestation.py:115-122`](../../../src/tex/tee/tdx_attestation.py), [`h100_attestation.py:124-131`](../../../src/tex/tee/h100_attestation.py)). The flag **propagates** and **gates emission**: `compose_from_evidence` raises in production mode rather than emitting a stub-derived token ([`attestation_client.py:196-201`](../../../src/tex/tee/attestation_client.py)). This is the right "real-impl-with-graceful-fallback" pattern, not a hollow stub.
- **Signature verification is real cryptography.** PS384/RS256/ES384/ES256 use `cryptography`'s actual verify primitives ([`attestation_client.py:932-969`](../../../src/tex/tee/attestation_client.py)); ML-DSA delegates to the real pqcrypto provider. The signed builders genuinely sign ([`:533-574`]).
- **`verify_sota_2026` performs real comparisons** ([`sota_2026.py:725`](../../../src/tex/tee/sota_2026.py)) — driver semver, TDISP lock state, advisory blocklist, RTMR equality. The SOTA structures themselves are pydantic data carriers (no logic), but the verifier over them is genuine.

### Honest residuals documented in-code (not bugs — disclosed limits)

- **Stand-in ITA key.** `generate_standin_ita_keypair` and the signed builders document (in code, [`attestation_client.py:498-506`](../../../src/tex/tee/attestation_client.py), [`verdict_binding.py:56-64`](../../../src/tex/tee/verdict_binding.py)) that off real TDX the signature proves authorship by a *local stand-in* key, and measurements are dev-stub — hardware unforgeability stays "RUNTIME-DEPENDENT." This is disclosed, not hidden.
- **Test-mode signature leniency (worth flagging).** In `verify_attestation`, a *signed* token (`alg != none`) with an **invalid** signature is **NOT rejected when `is_test_env` is true** — the gate is `if not ok and not is_test_env` ([`attestation_client.py:753`](../../../src/tex/tee/attestation_client.py)). In production (`TEX_TEE_ATTESTATION_MODE` ≠ `test`) a bad signature fails closed; under `TEX_TEE_ATTESTATION_MODE=test` it does not. `verify_verdict_binding` compensates by separately re-checking and recording the raw crypto result ([`verdict_binding.py:383-388`](../../../src/tex/tee/verdict_binding.py)), but the base `verify_attestation` result can report `ok=True` on a bad signature in test mode.

### Real logic (verifier)

`tex.verifier.check` is fully real: hash-chain recomputation ([`check.py:530-540`]), ECDSA + FIPS-204 ML-DSA verification ([`:306-336`]), monotonicity-invariant checking ([`:342-416`]), identity-gap detection ([`:704-760`]). The ML-DSA path is the one runtime-dependent branch (returns `None`/unverifiable on cryptography < 48), reported honestly — never silently passed ([`check.py:115-118`, `:286-293`]).

---

## Technology / SOTA

- **Composite CPU+GPU TEE attestation** via Intel Trust Authority `get_token_v2` (`attest_type=tdx+nvgpu`), a single verifier-issued PS384 JWT carrying both `tdx` and `nvgpu` claim blocks.
- **AR4SI trustworthiness vector** (draft-ietf-rats-ear-03) — 5 axes × {affirming, warning, contraindicated, none}, computed in `_build_trust_vector`.
- **EAT-AI profile** (draft-messous-eat-ai-01) — AI-agent attestation claims with CBOR keys −75000…−75012 and a CWT serializer.
- **CrossGuard per-decision nonce binding** (cited arxiv 2604.23280) — `decision_bound_nonce` folds `decision_id` into the attestation nonce to defeat cross-decision JWT replay; `LongHaulNonce` extends it with transcript + fleet nonces.
- **Proof-of-Guardrail / verdict binding** (cited arxiv 2603.05786) — folds the verdict + policy + input + ledger-prev into the TDX `report_data` (the hardware-signed field), with constant-time `hmac.compare_digest` comparison; the regression target is the "hollow `eat_nonce`" forgery.
- **Frontier draft data structures** (sota_2026): EAT measured-components (draft-ietf-rats-eat-measured-component-12), CoRIM reference values (draft-ietf-rats-corim-10), COSE-Dilithium/JOSE-PQ-composite algorithm IDs, TDISP evidence, SCITT receipts (draft-ietf-scitt-architecture-22), TSM ConfigFS event-log binding, driver-pinning, TCB advisory blocklist.
- **Post-quantum agility** — ML-DSA-44/65/87 + hybrid-ml-dsa-65-ed25519 verify branches delegate to `tex.pqcrypto`; the offline verifier verifies FIPS-204 ML-DSA second signatures.
- **Minimal-TCB offline verifier pattern** — canonical-JSON + SHA-256 hash-chain + pinned-key signature re-derived from scratch with zero engine imports; tri-state signature reporting; negative-space gap detection.
- **Design patterns:** strict frozen pydantic-v2 DTOs; fail-closed early-return gate chains with stable machine-readable reason codes; lazy optional native dependencies with deterministic dev fallbacks; domain-separated hash prefixes (`tex|`, `tex-poguard|v1|`, `tex-transcript:v1|`, `tex-fleet:v1|`).

---

## Persistence

**Both units are stateless / in-memory.** Neither has a database, file store, or durable state of its own.

- `tex.tee` produces in-memory `CompositeAttestationEnvelope` objects. Durability happens **downstream**: the envelope is `model_dump`'d into `EvidenceRecord` metadata ([`evaluate_action.py:686`](../../../src/tex/commands/evaluate_action.py)), so persistence is the evidence recorder's responsibility, not this unit's.
- Configuration comes from environment variables only: `TEX_TEE_MODE`, `TEX_TEE_ATTESTATION_MODE`, `TEX_ITA_ISSUER`, `TEX_ITA_PUBLIC_KEY_PEM`, `TEX_ITA_JWKS_PATH`, `TEX_ITA_API_URL`, `TEX_ITA_API_KEY` ([`attestation_client.py:86-91`](../../../src/tex/tee/attestation_client.py)), `TEX_TEE_BLOCKED_ADVISORY_IDS` ([`sota_2026.py:485`](../../../src/tex/tee/sota_2026.py)), `TEX_SCITT_TS_URL` (claim, referenced only in docstring `sota_2026.py:460`).
- `tex.verifier` reads a bundle file (or stdin) and an optional pinned-key PEM file at the CLI boundary ([`__main__.py:24-27,70-74`](../../../src/tex/verifier/__main__.py)); the library functions hold only their arguments and return reports. `tex.verifier.export` reads a live ledger's records but writes nothing.

---

## Notable Findings

1. **Two unrelated `verify_bundle` functions — easy to conflate.** `tex.verifier.check.verify_bundle` (this scope) is **NOT** what the capstone / bench / adversarial subsystems call. Those call `tex.bench.evidence_bundle.verify_bundle` ([`bench/evidence_bundle.py:233`](../../../src/tex/bench/evidence_bundle.py), used at `capstone/compose.py:43,473`, `capstone/verify.py:54,703`, `bench/*`, `adversarial/__main__.py:78`). The signatures even differ (`pinned_public_key_pem=` vs `pinned_public_key_b64=`). So the heavily-wired "offline verifier" in the capstone is a *different* module; the `tex.verifier` package in this dossier has no `src` importer at all.

2. **`tex.verifier` is an orphan-as-library but live-as-CLI by design.** The spine classification `INDIRECT` overstates its in-tree coupling: nothing under `src/` imports it. Its only non-test consumer is `python -m tex.verifier`. This is intentional (smallest-TCB pitch, [`check.py:3-11`](../../../src/tex/verifier/check.py)), but a reader expecting it to be called from the engine will not find that call.

3. **`verdict_binding` is capstone-only, not on a live request path.** Despite being the most sophisticated security primitive in the unit (hardware-rooted `report_data` binding), its only consumers are `tex.capstone.{compose,tamper,verify}`, and capstone has no router/`__main__`/`main.py` wiring. So the verdict-bound attestation is exercised in the capstone demo + tests, never in `/v1/tee/verify` or the decision recorder (which use the plainer `compose_attestation`/`verify_attestation`).

4. **Test-mode signature leniency in `verify_attestation`.** Under `TEX_TEE_ATTESTATION_MODE=test`, a signed token with an invalid signature still yields `ok=True` (gate `if not ok and not is_test_env`, [`attestation_client.py:753`](../../../src/tex/tee/attestation_client.py)). Production fails closed correctly. `verify_verdict_binding` records the bare crypto result separately to compensate, but a direct `verify_attestation` caller in test mode does not get signature enforcement. Worth a comment/hardening if test-mode tokens are ever signed.

5. **Dev-stub measurements are clearly non-production and gated.** The test-mode JWT's `tdx_mrtd`/`tdx_rtmr0`/GPU measurements are SHA-256 over stub bytes, not real Intel/NVIDIA measurements ([`attestation_client.py:360-364`](../../../src/tex/tee/attestation_client.py)), and the composer refuses to emit them in production mode ([`:196-201`]). The docstrings are honest about this. No overstatement found here.

6. **Heavy reliance on forward-dated / in-flight standards.** Docstrings cite numerous 2026 IETF drafts and arxiv preprints (draft-messous-eat-ai-01, draft-ietf-rats-ear-03, draft-ietf-rats-corim-10, arxiv 2605.03213, 2604.23280, 2603.05786) with specific dates. These are **(claims, unverified)** — the *code structures* implementing them are real and self-consistent, but I did not (and per ground rules cannot from code) confirm the citations correspond to real published documents. `verdict_binding.py:28-30` itself marks its novelty citation `UNVERIFIED-FROM-MEMORY`.

7. **`_stable_json` parity is asserted but not diffed here.** [`check.py:94-99`](../../../src/tex/verifier/check.py) claims byte-for-byte parity with `provenance/ledger.py`'s canonical JSON. The re-derived form (`sort_keys, separators=(",",":"), default=str`) and the two-field record-hash construction are plausible and internally consistent, and `tests/test_offline_verifier.py` exercises round-trips against the real `SealedFactLedger` + `export_sealed_fact_bundle` (so the parity is test-covered), but I did not line-by-line diff the two canonicalizers in this pass.

8. **`sota_2026` is mostly inert data structures.** Of its 854 lines, the bulk are pydantic models that are exported and importable but have **no live consumer** beyond `tests/frontier_thread_12_tee/test_sota_2026.py`. `verify_sota_2026` is real logic but is not called from any live path (no `Sota2026Augmentation` is ever populated by the composer). It is forward-looking scaffolding, not wired into the decision flow. Not dead (tests + exports use it), but not load-bearing today.

9. **No contradictions between docstrings and code behavior were found** in the core verifier gates — the fail-closed gate chain, nonce binding, and dev-mode flagging all do what their docstrings claim. The honest-residual disclosures (stand-in key, runtime-dependent hardware unforgeability) are accurate to the code.
