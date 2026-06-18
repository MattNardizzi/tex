# Subsystem Dossier: `tex.c2pa` — C2PA Content Provenance

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/c2pa/` (17 `.py` files).
> Branch: `feat/proof-carrying-gate`. All evidence cited `file:line`.
> Self-described layer: **Layer 5 (Evidence)** — `__init__.py:42-43` sets `__layer__ = 5`, `__layer_kind__ = 'evidence'`.

---

## Overview

`tex.c2pa` implements the **Coalition for Content Provenance and Authenticity (C2PA)** content-credential stack for outbound AI-generated artifacts (primarily email). It does three things, all verified-real in code:

1. **Build + sign a spec-shaped C2PA manifest.** A pydantic data model (`manifest.py`) is canonicalized (`_canonical_claim.py`) and wrapped in a real `COSE_Sign1_Tagged` envelope (`signer.py` + `_cbor.py`), using a classical ECDSA-P256 / Ed25519 signature drawn from the algorithm-agile provider in `tex.pqcrypto`. A spec-conformant verifier (`verifier.py`) re-derives the signed bytes and validates the signature, cert validity window, optional OCSP staples, optional RFC 3161 v2 timestamps, and optional trust-list anchoring.

2. **Add a Tex-private post-quantum "evidence cosign"** (`evidence_emission.py`, `cosign_verifier.py`, `cosign_context_tree.py`) — a second, ML-DSA-65-by-default signature carried *inside* the C2PA claim, signing a Merkle root over seven typed leaves that bind the timestamp, full-file hash, canonicalization version, retention anchor, and revocation proof. This is Tex's response to the Sherman/UMBC/NSA paper "Why the C2PA Specifications Fall Short" (cited throughout as arxiv 2604.24890).

3. **Frontier add-ons:** OCSP stapling (`ocsp.py`), RFC 3161 v2 timestamps (`timestamp.py`), hardware EAT-JWT attestation (`attestation.py`), text-watermark detection + cross-layer desync audit (`watermark.py`), durable TrustMark image watermarking (`durable_credentials.py`), CPSA formal-verification shape loading (`cpsa_shapes.py`), and a buyer-facing Sherman-2026 defense-matrix attestation (`sherman_2026_defenses.py`).

**Wiring verdict: LIVE.** The package is reachable from the running FastAPI app two independent ways: (a) the `c2pa_routes` router is mounted in `create_app` at `tex/main.py:1521-1522`; (b) the write side runs inside `EvidenceRecorder.record_decision` via a `C2paEmitter` wired in `build_runtime` (`tex/main.py:609,631`). A full real sign→verify round-trip with a live ECDSA-P256 key was executed and returned `is_valid=True`.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 285 | Package facade. Re-exports ~98 public symbols (`__all__`, lines 171-285); sets `__layer__`/`__layer_kind__`. |
| `_canonical_claim.py` | 90 | Claim canonicalization. Converts `C2paClaim` → JSON → RFC 8785 JCS → deterministic CBOR (`canonical_claim_cbor`). |
| `_cbor.py` | 265 | Hand-rolled deterministic CBOR encoder + tolerant decoder (RFC 8949 subset) for COSE_Sign1. No 3rd-party CBOR dep. |
| `_cose_alg.py` | 97 | Maps `tex.pqcrypto.SignatureAlgorithm` → COSE `alg` int; restricts to the C2PA 2.2 §13.2 allow-list; rejects ML-DSA. |
| `attestation.py` | 612 | Hardware-attestation binding via EAT JWT (NRAS / Intel TA / Veraison). Real JWT parse + ES/RS/EdDSA signature verify. |
| `cosign_context_tree.py` | 246 | Merkle context tree (v2 cosign signing input): 7 typed leaves → root, inclusion proofs, selective disclosure. |
| `cosign_verifier.py` | 367 | Verifies the `tex.evidence_cosign` assertion; reports the five attack-class defenses; PQ signature check via provider. |
| `cpsa_shapes.py` | 206 | Loads vendored CPSA shapes JSON (`cpsa_models/tex_cosign_v2_shapes.json`); builds `tex.formal_verification` assertion data. |
| `durable_credentials.py` | 265 | Multi-layer image marking: C2PA manifest + TrustMark perceptual watermark + fingerprint. Lazy TrustMark/Pillow. |
| `evidence_emission.py` | 362 | **Orchestrator.** Builds outer COSE sign + inner PQ cosign in one pass; serializes manifest for Postgres storage. |
| `manifest.py` | 460 | Pydantic data model (`C2paManifest`/`C2paClaim`/`C2paAssertion`/`C2paIngredient`) + assertion builders + email manifest. |
| `ocsp.py` | 558 | RFC 6960 OCSP request build + DER response parse/validate (status, freshness, RFC 9277 nonce, responder authority). |
| `sherman_2026_defenses.py` | 335 | Documentation/attestation only. Six-class defense matrix; probes module importability; renders buyer dossier JSON. |
| `signer.py` | 304 | COSE_Sign1_Tagged construction + in-process keystore (`register_signing_key`/`set_keystore`), governed by `selfgov`. |
| `timestamp.py` | 449 | RFC 3161 v2 TSA request build + TimeStampResp parse/validate. Hand-rolled ASN.1 via `pyasn1`. |
| `verifier.py` | 679 | Spec-conformant C2PA verifier: envelope decode → sig verify → validity → OCSP → TSA → trust-list anchoring. |
| `watermark.py` | 549 | Text-watermark detection adapters (SynthID-Text, TextSeal) + recorded-score fallback + cross-layer desync audit. |

**Total: 17 files, ~6,129 lines.**

---

## Internal Architecture

### Data flow (signing path)

```
build_email_manifest()  [manifest.py:238]
        │  builds 3 assertions: c2pa.actions.v2, cawg.creative_work, tex.verdict
        ▼
C2paManifest(claim=...)  [manifest.py:121, frozen pydantic]
        │
        ▼
build_signed_manifest_with_cosign()  [evidence_emission.py:209]   ← THE orchestrator
        │  1. full_file_hash = sha256(artifact)
        │  2. cosign signing input = Merkle root v2  [cosign_context_tree.py:141]
        │  3. cosign_signature = provider.sign(root, cosign_key)  (ML-DSA-65 default)
        │  4. build tex.evidence_cosign assertion  [manifest.py:334]
        │  5. append extras + cosign to claim
        │  6. outer COSE sign over full claim CBOR
        ▼
sign_manifest()  [signer.py:210]
        │  payload = canonical_claim_cbor(claim)  [_canonical_claim.py:77]
        │  Sig_structure = ["Signature1", protected, b"", payload]  [signer.py:179]
        │  signature = provider.sign(sig_input, key)  (ECDSA/Ed25519)
        │  COSE_Sign1_Tagged (tag 18) → base64  [signer.py:194, _cbor.py:128]
        ▼
C2paManifest(signature_b64=..., certificate_chain_pem=...)
        ▼
serialize_manifest_for_storage()  [evidence_emission.py:325]  → JSON-safe dict for Postgres
```

### Core data model — `manifest.py`

- `C2paAssertion` (`manifest.py:85`), `C2paIngredient` (`:94`), `C2paClaim` (`:106`), `C2paManifest` (`:121`). All `frozen=True, extra="forbid"` pydantic models. Mutations go through `model_copy(update=...)` (e.g. `attach_cosign_assertion` `:439`, `sign_manifest` `:292`).
- `build_ai_generation_assertion` (`:131`) emits `c2pa.actions.v2` with the IPTC `trainedAlgorithmicMedia` digital-source-type (`:68-70`) — the EU AI Act Art. 50(2) machine-readable marker.
- `build_email_manifest` (`:238`) validates inputs (64-hex body sha, non-empty from/to/verdict) and assembles exactly three assertions in fixed order; the email envelope (recipients, subject, body sha) is nested under a `provenance.delivery` block on the CAWG assertion (`:295-308`). **Body bytes are never included** — only the SHA-256 (privacy/data-minimization, `:37-38`).
- `build_tex_evidence_cosign_assertion` (`:334`) — validates `full_file_sha256` length, requires `retention_anchor['record_hash']`, and embeds a `defends_against` block naming arxiv:2604.24890 and five attack strings (`:420-429`).

### Canonicalization — `_canonical_claim.py`

`canonical_claim_cbor` (`:77`) runs claim → plain dict (`_claim_to_canonicalizable` `:41`, datetimes → ISO, tuples → lists) → RFC 8785 JCS via `tex.events._canonical.canonical_json` (`:88`) → `json.loads` → deterministic CBOR (`_cbor.encode` `:90`). The doctring explains the JSON-then-CBOR choice ties C2PA's signed bytes and the Tex evidence chain to the same canonical intermediate (`:13-22`). A `TODO(spec-verify)` (`:24-27`) flags that a CDDL-direct serializer is the eventual deliverable — i.e. the exact byte layout is **not** claimed to be c2patool-conformant yet.

### CBOR codec — `_cbor.py`

Real, self-contained RFC 8949 subset. Encoder (`encode` `:133`) supports uint/negint/bytes/text/array/map/tag/null, rejects floats, sorts map keys bytewise on encoded form for determinism (`_encode_map` `:107-125`). Decoder (`decode` `:234`) is tolerant, rejects indefinite-length (`:186`), and surfaces tags as `("__tag__", n, value)` triples; `unwrap_tag` (`:250`) matches COSE_Sign1 tag 18. **Note:** `COSE_SIGN1_TAG = 18` (`:61`) is correct; docstrings in two places say "tag 61" (`_cbor.py:14`) / "61" — see Notable Findings.

### COSE algorithm mapping — `_cose_alg.py`

`_TEX_TO_COSE` (`:55`) registers only `ECDSA_P256 → ES256 (-7)` and `ED25519 → EdDSA (-8)`. `cose_alg_for` (`:61`) raises `NotImplementedError` with a §13.2 pointer for anything else (ML-DSA/SLH-DSA/hybrid) — this is the deliberate **spec-compliance guard**, not a stub. Confirmed at runtime: `cose_alg_label(ML_DSA_65)` raises `NotImplementedError`.

### Signer — `signer.py`

- Keystore: process-local dict (`_LOCAL_KEYSTORE` `:97`) under an `RLock`; pluggable via `set_keystore` (`:122`). `register_signing_key`/`clear_signing_keys`/`set_keystore` are each gated through `tex.selfgov.governor.gate_controller_mutation` (`:108,116,126`) — a real governance hook (`tex/selfgov/governor.py:464`). If the gate denies, the mutation silently no-ops.
- `sign_manifest` (`:210`) resolves the key, maps the algorithm via `cose_alg_for`, splits the PEM chain to DER (`_split_pem_chain` `:148`), builds the protected header with x5chain label 33 (`_build_protected_header` `:161`), builds the `Sig_structure` (`:179`), signs via the provider, and assembles the tagged envelope with optional OCSP staples (`ocsp_vals`) / TSA tokens (`sigTst2`) in the **unprotected** header (`:263-270`). Emits `c2pa.manifest.signed` telemetry (`:279`).

### Verifier — `verifier.py`

`verify_manifest` (`:339`) is a real, ordered pipeline, each step returning a structured `C2paVerificationResult` (`:78`) with verbatim C2PA §15.7 failure codes (`:68-76`):
1. Missing signature → `claimSignature.missing` (`:381`).
2. Decode COSE envelope (`_decode_envelope` `:96`).
3. Resolve algorithm; reject off-allow-list → `algorithm.unsupported` (`:433-448`).
4. Extract x5chain (accepts label 33 or string `"x5chain"`, `:137`); zero certs → `signingCredential.invalid` (`:467`).
5. Re-derive signed bytes from the **live manifest model** and `provider.verify` (`:501-510`) — this re-canonicalization is the structural defense against assertion-injection (Sherman C4).
6. Validity-window check using TZ-aware accessors (`_is_within_validity` `:179`).
7. OCSP staple validation if present (or `require_ocsp_staple`) via `tex.c2pa.ocsp` (`:550-594`).
8. TSA v2 token validation if present (or `require_timestamp`) via `tex.c2pa.timestamp` (`:596-649`).
9. Trust-list anchoring (`_is_anchored_to_trust_list` `:268`) — a **deliberately partial** RFC 5280 path check (subject/issuer linkage + signature via `verify_directly_issued_by`), with a `TODO(P1)` to swap in `cryptography.x509.verification.PolicyBuilder` (`:280-282`). Reaches `Trusted` only when `trust_list_pem_paths` is supplied.

### Cosign orchestration — `evidence_emission.py`, `cosign_context_tree.py`, `cosign_verifier.py`

- `_canonical_cosign_signing_input` (`evidence_emission.py:103`) dispatches on canonicalization version: **v2 (default)** → Merkle root (`canonical_cosign_signing_input_v2` `cosign_context_tree.py:141`); **v1 (legacy)** → sorted-keys compact JSON (`:159-174`).
- `cosign_context_tree.py`: 7 stable leaf labels (`:64-70`), `MerkleLeaf.digest = sha256(label || 0x00 || value_json)` (`:78-84`), standard single-SHA Merkle root with Bitcoin odd-arity duplication (`merkle_root` `:117`), plus `merkle_proof`/`verify_merkle_proof` (`:172,208`) for selective disclosure. The module docstring is explicit it is **not** Bitcoin-style double-SHA (`:38-41`).
- `_select_cosign_key` (`evidence_emission.py:177`) prefers ML-DSA-87 > 65 > 44 > hybrid > Ed25519; **ECDSA is deliberately excluded** as a cosign fallback (`:184-187`) so the cosign always provides PQ coverage. `DEFAULT_COSIGN_ALGORITHM = ML_DSA_65`, `FALLBACK = ED25519` (`:95-96`).
- `cosign_verifier.verify_evidence_cosign` (`:137`) re-derives the same signing input and verifies the PQ signature via the provider (`_verify_signature` `:110`, swallows provider-unavailable into `False`). It computes a per-attack `defenses_satisfied` map; on signature failure **all** defenses are forced false (`:319-330`). `is_valid` requires signature OK AND timestamp-bound AND canonicalization-match (`:338-340`).

### Frontier modules

- **`ocsp.py`** — real RFC 6960 via `cryptography.x509.ocsp`. Builds requests with RFC 9277 16-byte nonce (`build_request_der` `:162`), parses responses, checks status/freshness/nonce, and validates responder authority through three RFC 6960 §4.2.2 paths including delegated `id-kp-OCSPSigning` EKU + issuer-signature checks (`_check_responder_authority` `:216`). **Does not** do network I/O by design (`:44-51`). Note: `_check_responder_authority` has a convoluted RSA-verify expression at `:252-263` (a conditional-expression-as-statement) — functional but stylistically fragile.
- **`timestamp.py`** — real RFC 3161 v2 via hand-rolled `pyasn1` ASN.1 schemas (`:117-196`). v2 messageImprint = `sha256(COSE signature bytes)` (`v2_payload_digest` `:202`), binding the timestamp to the exact signature. Parses TimeStampResp, extracts TSTInfo from the CMS SignedData by positional walk (`_extract_tst_info` `:383`), checks PKIStatus/messageImprint/nonce/genTime-vs-cert-validity. **Does not** POST to the TSA (`:32-38`).
- **`attestation.py`** — real EAT-JWT path. `parse_eat_jwt` (`:195`) splits + base64url-decodes header/payload (no sig check). `verify_attestation_assertion` (`:319`) checks `user_data == expected claim sha256`, `exp`/`nbf`, and (when trusted public keys are supplied) the JWT signature via `_verify_jwt_signature` (`:444`, real ES256/384/512 + RS256 + EdDSA with r||s→DER conversion). **CWT path is explicitly not implemented** (`:366-380`, "P1 upgrade"). `synthesize_test_eat_jwt` (`:520`) is test-only and labelled as such.
- **`watermark.py`** — detection-only. The two production adapters (`SynthIDTextDetectorAdapter` `:207`, `TextSealDetectorAdapter` `:253`) **raise `NotImplementedError`** after lazily importing the heavy library (`:245,277`): in-process detection needs a model-specific watermarking config the gateway holds. The **real, runnable** path is `RecordedScoreDetector` (`:146`) — packages a gateway-recorded score, bound to the asset by the outer signature. `cross_layer_audit` (`:419`) is real logic detecting the arxiv 2603.02378 desync attack (human-authored-but-watermarked / AI-generated-but-unwatermarked).
- **`durable_credentials.py`** — `attach_durable_marks` (`:160`) always applies a fingerprint (sha256), attempts a TrustMark watermark via lazy `trustmark`+`Pillow` import (`_try_trustmark_embed` `:108`), and records the C2PA-manifest layer. `require_watermark_layer=True` fails closed if TrustMark is unavailable (`:217`); default best-effort. `_perceptual_hash` (`:95`) is **sha256 of raw bytes**, not a real perceptual hash — the docstring honestly states production should swap in `imagehash` (`:98-104`).
- **`cpsa_shapes.py`** — loads the vendored CPSA JSON (does not run CPSA; `:33-35`). `DEFAULT_SHAPES_PATH` (`:47`) resolves to `cpsa_models/tex_cosign_v2_shapes.json` — **the file exists** (verified: `cpsa_models/tex_cosign_v2_shapes.json` 3,287 bytes + `tex_cosign_v2.scm` 5,261 bytes). `model_provenance_assertion_data` (`:151`) builds the `tex.formal_verification` assertion.
- **`sherman_2026_defenses.py`** — pure documentation/attestation; "does NOT implement new cryptographic primitives" (`:8-11`). `assess_current_posture` (`:236`) probes each defense's `wired_modules` dotted paths for importability (`_all_modules_importable` `:262`) and flips `wired=False` on a regression. `render_buyer_dossier` (`:297`) emits JSON for buyer materials. **The `wired=True` literals in `_build_defense_table` (`:114`) are author-asserted defaults; the live truth comes only from the importability probe.**

---

## Public API

Imported by other Tex code (verified call-sites in Wiring-In). The headline surface:

- **Data model:** `C2paManifest`, `C2paClaim`, `C2paAssertion`, `C2paIngredient`.
- **Builders:** `build_email_manifest`, `build_ai_generation_assertion`, `build_cawg_creative_work_assertion`, `build_tex_verdict_assertion`, `build_tex_evidence_cosign_assertion`, `attach_cosign_assertion`.
- **Signer/keystore:** `sign_manifest`, `register_signing_key`, `clear_signing_keys`, `set_keystore`.
- **Verifier:** `verify_manifest`, `C2paVerificationResult`.
- **Cosign orchestration:** `build_signed_manifest_with_cosign`, `cosign_manifest_hash`, `serialize_manifest_for_storage`, `get_cosign_assertion`, `CosignError`.
- **Cosign verify:** `verify_evidence_cosign`, `CosignVerificationResult`, `full_file_sha256`, `ALL_ATTACKS`.
- **OCSP/TSA:** `build_ocsp_request_der`, `parse_and_validate_ocsp_response`, `validate_staple`, `build_tsa_request_der`, `parse_and_validate_tsa_response`, `v2_payload_digest`.
- **Thread-6:** Merkle helpers, watermark detectors/audit, attestation verify, CPSA loaders, Sherman dossier, TrustMark `attach_durable_marks`/`trustmark_available`.
- **Internal (underscored, but imported across packages):** `_cbor.decode`/`encode`, `_canonical_claim.canonical_claim_cbor`, `_cose_alg.cose_alg_for`, `evidence_emission._canonical_cosign_signing_input`.

`__init__.py:171-285` lists 98 names in `__all__` (runtime-confirmed `len == 98`).

---

## Wiring

### Wiring In (who imports `tex.c2pa`)

External (non-test) importers, from `grep` across `src/tex`:

| Importer | What it uses |
|----------|--------------|
| `tex/api/c2pa_routes.py:34,43` | `ALL_ATTACKS, C2paAssertion, C2paClaim, C2paManifest, full_file_sha256, verify_evidence_cosign, verify_manifest`, `_cbor.decode` — **HTTP surface** |
| `tex/evidence/c2pa_emitter.py:214` (lazy) | `build_email_manifest, build_signed_manifest_with_cosign, cosign_manifest_hash, get_cosign_assertion, serialize_manifest_for_storage` — **emission/write path** |
| `tex/evidence/scitt_statement.py:87` | `_cbor` (reuses the deterministic CBOR codec) |
| `tex/evidence/scitt_cose_alg.py:4,51,114` | doc/companion references; deliberately separate mapping |
| `tex/compliance/_common.py:40`, `eu_ai_act/article_50.py:45`, `ftc/policy_statement.py:52`, `state/california_sb942.py:53` | `C2paManifest` type — `compliance` is **DEMO_TEST_ONLY** (not imported by api/main; grep confirms) |
| `tex/_pending/pitch/insurer_export.py:86` | `C2paManifest` — **`_pending` is ORPHAN** |

Test footprint: 18 test files reference `tex.c2pa` (`tests/c2pa/`, `tests/frontier/`, `tests/test_c2pa_*`, `tests/test_thread5_integration.py`, `tests/test_thread6_integration.py`).

### Live call path (from the running app)

**Path A — HTTP read/verify (router mounted in `create_app`):**
```
tex/main.py:1521  from tex.api.c2pa_routes import router as c2pa_router
tex/main.py:1522  app.include_router(c2pa_router)
        → tex/api/c2pa_routes.py:54  router = APIRouter(tags=["c2pa"])
        → GET  /v1/evidence/{record_id}/c2pa   [c2pa_routes.py:70]  reads runtime.manifest_mirror
        → POST /v1/c2pa/verify                 [c2pa_routes.py:316] calls verify_manifest + verify_evidence_cosign
```

**Path B — emission/write (inside the evidence recorder, built in `build_runtime`):**
```
tex/main.py:608  manifest_mirror = PostgresManifestMirror()
tex/main.py:609  c2pa_emitter   = C2paEmitter()
tex/main.py:628  recorder = EvidenceRecorder(..., c2pa_emitter=c2pa_emitter, manifest_mirror=manifest_mirror, ...)
        → tex/evidence/recorder.py:176  _maybe_emit_c2pa(emitter=self._c2pa_emitter, ...)
                guard: outbound_artifact is not None  [recorder.py:168]  AND verdict==PERMIT  AND emitter wired (main.py:600-602)
        → tex/evidence/c2pa_emitter.py:214 (lazy import)  build_signed_manifest_with_cosign(...)
        → tex/evidence/recorder.py:223  self._manifest_mirror.record(...)  (best-effort)
tex/main.py:1681 app.state.manifest_mirror = runtime.manifest_mirror   (read back by the GET route)
```

Both paths are unconditionally constructed; emission only *fires* when the caller passes `outbound_artifact` + a full `C2paEmissionContext` and the verdict is PERMIT (`tex/main.py:598-607`, `recorder.py:114-126`). The Postgres mirror no-ops cleanly without `DATABASE_URL` (`main.py:605-607`); the GET route then 503s with a clear message (`c2pa_routes.py:128-135`).

**Status: `wired_status = LIVE`** — confirmed by both the mounted router and the recorder emission path, and by a real end-to-end ECDSA sign→verify executed against the live package (returned `is_valid=True`, `issues=('claimSignature.validated',)`).

### Wiring Out (dependencies)

**Internal Tex subsystems:**
- `tex.pqcrypto.algorithm_agility` — `SignatureAlgorithm`, `SignatureKeyPair`, `get_signature_provider` (the actual sign/verify engine; `signer.py:74`, `verifier.py:55`, `evidence_emission.py:69`, `cosign_verifier.py:53`).
- `tex.events._canonical.canonical_json` — RFC 8785 JCS (`_canonical_claim.py:38`).
- `tex.observability.telemetry.emit_event` — structured events from nearly every module.
- `tex.selfgov.governor` — `gate_controller_mutation`, `describe_key_mutation` gate keystore mutations (`signer.py:78`).

**External libraries:**
- `cryptography` (x509, OCSP, EC/Ed25519/RSA primitives, `serialization`) — signer, verifier, ocsp, attestation.
- `pyasn1` (`codec.der`, `type.univ/namedtype/...`) — RFC 3161 ASN.1 in `timestamp.py:57-59`.
- `pydantic` — data model (`manifest.py:57`) and route schemas.
- **Lazy/optional:** `transformers` (SynthID), `textseal`, `trustmark`, `Pillow` (`PIL`) — all import-guarded; absence raises a clear `RuntimeError`/`NotImplementedError` rather than crashing the package.

---

## Implementation Reality

**Verdict: REAL** (with a clearly-fenced set of intentional fallbacks/guards).

### Proven-real (executed)
A live ECDSA-P256 self-signed cert + keypair was used to `build_email_manifest → sign_manifest → verify_manifest`, returning `is_valid=True`. This exercises the real CBOR codec, JCS canonicalization, COSE_Sign1_Tagged construction, the cryptography-backed ECDSA provider, x5chain round-trip, and validity-window check. Telemetry events `c2pa.manifest.signed` and `c2pa.manifest.verified` fired with `signature_bytes=70`, `envelope_bytes=385`.

### Real with native/optional fallback (not stubs)
- **Cosign PQ signature** (`evidence_emission.py:260`, `cosign_verifier.py:110`): ML-DSA-65 via the `tex.pqcrypto` provider when liboqs/OpenSSL-3.5 is present; falls back to Ed25519 (`FALLBACK_COSIGN_ALGORITHM`). The provider stack (`tex/pqcrypto/ml_dsa.py:270 MlDsaProvider`, `_ed25519_provider.py:30 Ed25519Provider`) is a real graceful-fallback impl, not a hollow stub. `_verify_signature` swallows provider-unavailability into `False` (`cosign_verifier.py:126`) rather than crashing CI.
- **OCSP / TSA** (`ocsp.py`, `timestamp.py`): full real parse/validate logic; the only omission is network I/O, which is intentionally externalized (`ocsp.py:44-51`, `timestamp.py:32-38`).

### Guards (NotImplementedError that are correct, not gaps)
Five `NotImplementedError` sites in-package (grep-confirmed):
- `_cose_alg.py:74` — rejects non-C2PA-allowed algorithms. **Spec guard.** (verified raises at runtime)
- `verifier.py:334` — `pragma: no cover`, only reachable on `cryptography<40`, which is pinned out.
- `watermark.py:245` and `:277` — `SynthIDTextDetectorAdapter`/`TextSealDetectorAdapter` in-process detection. **Documented production-wiring hooks**; the runnable path is `RecordedScoreDetector`.

### Honest stubs / not-yet-real (flagged in code)
- **CWT attestation path** not implemented (`attestation.py:366-380`) — JWT only; CWT is a P1.
- **`_perceptual_hash` is sha256, not perceptual** (`durable_credentials.py:95-105`) — docstring says swap in `imagehash`. Same for `text_perceptual_hash` (`watermark.py:290`, "intentionally simple", P1 upgrade to PDQ/SimHash).
- **`_cbor` is a custom subset**, not `cbor2` (`_cbor.py:38-41` TODOs).
- **Trust-list anchoring is partial path validation**, not full RFC 5280 (`verifier.py:280-282` TODO P1).
- **Canonical claim CBOR is not yet CDDL-conformant** (`_canonical_claim.py:24-27`) — byte-stable internally, but not verified against c2patool. This is the single biggest honesty caveat: the manifests are self-consistent and Tex-verifiable, but **not yet proven interoperable** with external C2PA tooling.
- **`sherman_2026_defenses.py` `wired=True`** literals are author-asserted; only the runtime importability probe (`assess_current_posture`) reflects real wiring.

---

## Technology / SOTA

- **C2PA 2.2–2.4 Content Credentials**: COSE_Sign1_Tagged (RFC 9052) detached-payload signing, x5chain (RFC 9360) in the protected header, `c2pa.actions.v2` / `cawg.creative_work` assertions, IPTC `trainedAlgorithmicMedia` digital-source-type for EU AI Act Art. 50(2).
- **Deterministic encoding**: RFC 8949 core-deterministic CBOR (hand-rolled) + RFC 8785 JSON Canonicalization (via `tex.events`).
- **Revocation/timestamping**: RFC 6960 OCSP + RFC 9277 nonces; RFC 3161 v2 timestamps (messageImprint over the signature field) parsed via `pyasn1`.
- **Post-quantum**: ML-DSA-65 (FIPS 204) cosign by default; algorithm-agile provider abstraction.
- **Merkle context tree** (single-SHA, typed leaves) for the cosign signing input, with inclusion proofs for selective disclosure — directly derived from the Sherman/UMBC recommendation.
- **Remote attestation**: RFC 9334 RATS / EAT JWT (NVIDIA NRAS V3, Intel Trust Authority, Veraison EAR profiles).
- **Watermarking**: SynthID-Text (Nature 2024), TextSeal (arxiv 2605.12456), TrustMark image watermark (C2PA Soft Binding Algorithm List).
- **Formal methods**: CPSA (Cryptographic Protocol Shapes Analyzer) model + vendored shapes JSON for the cosign protocol.
- **Design patterns**: pluggable provider/keystore (Protocol + `set_keystore`), frozen immutable models with copy-on-write, lazy imports to keep cold-start fast, strict separation of crypto logic from network I/O.

---

## Persistence

- **In-process, ephemeral:** the signing keystore (`signer.py:97 _LOCAL_KEYSTORE`) lives in a module-global dict behind an `RLock`; cleared by `clear_signing_keys`. Lost on restart unless a custom `set_keystore` lookup (HSM/KMS) is installed.
- **Durable:** the signed manifest is serialized by `serialize_manifest_for_storage` (`evidence_emission.py:325`) into a JSON-safe dict and written to the **Postgres `evidence_manifests` mirror** by `PostgresManifestMirror` (constructed `main.py:608`, written in `recorder.py:223`, read by the GET route via `mirror.fetch_by_record_id`). The mirror no-ops without `DATABASE_URL`.
- **Hash-chained anchor:** the manifest's claim SHA-256 is written into the evidence chain payload under `c2pa.manifest_hash` (`recorder.py:182-195`), making the (append-only, signed) Tex evidence chain the retention anchor — so a manifest cannot be substituted for a `record_id` without breaking the chain (this is the Sherman C5 / "cert-expiry-before-retention" defense in practice).
- **Vendored static artifact:** CPSA shapes JSON at `cpsa_models/tex_cosign_v2_shapes.json` (on disk, confirmed) + the `.scm` source of truth.
- The c2pa package itself holds **no other long-lived state**; manifests are otherwise built and returned, not cached.

---

## Notable Findings

1. **Strongest honesty caveat — not yet c2patool-interoperable.** `_canonical_claim.py:24-27` and `manifest.py:41-49` openly flag that the exact claim CBOR byte layout and the `c2pa.actions.v2`/`cawg.creative_work` schemas have **not** been run against a conformance tool. The signing/verifying loop is internally byte-stable and self-consistent (proven), but the "spec-conformant C2PA manifest" framing in docstrings is **aspirational on interop**. Treat external-verifier compatibility as unproven.

2. **CBOR tag docstring contradiction (cosmetic).** `_cbor.py:14` docstring says COSE_Sign1_Tagged is "(61)" and `_cbor.py:60` comment references "tag … 4.2"; the actual constant is `COSE_SIGN1_TAG = 18` (`_cbor.py:61`), which is **correct** per RFC 9052. `signer.py` and `verifier.py` both use 18. The "61" in the docstring is a typo, not a code bug — but it's a wrong reference an auditor could trip on.

3. **Dead assertion in `_cose_alg.cose_alg_label`.** `_cose_alg.py:88-92`: when `pair is None` it calls `cose_alg_for(algorithm)` (which always raises) then `assert pair is not None`. The assert line is unreachable. Runtime-confirmed the function raises `NotImplementedError` for ML-DSA — behaviorally correct, but the post-raise code is dead.

4. **`sherman_2026_defenses.py` is attestation theater unless the probe runs.** Every row hardcodes `wired=True` in `_build_defense_table` (`:123-232`). Only `assess_current_posture()` (`:236`) replaces those with the real importability probe. If a consumer reads `render_buyer_dossier()` output, it *does* run the probe — but a casual reader of the table literals could over-trust. The module itself implements **no** crypto (it says so, `:8-11`).

5. **`compliance` importers are not live.** Four `tex.compliance.*` modules import `C2paManifest` (`_common.py:40`, etc.), but `compliance` is classified DEMO_TEST_ONLY and grep confirms nothing in `tex/api` or `tex/main.py` imports `tex.compliance`. So the C2PA→compliance binding (EU AI Act Art. 50, FTC, CA SB942) exists as types but is **not wired into the running app**.

6. **`_pending/pitch/insurer_export.py` is orphan.** It imports `C2paManifest` (`:86`) but `_pending` is ORPHAN — dead relative to the app.

7. **Cosign is one-directional and explicitly so.** The cosign signs the bound fields but **not** the outer COSE signature value, to avoid self-reference (`evidence_emission.py:131-146`, `cosign_verifier.py:166-175`). The binding direction is: outer signs claim CBOR which contains the cosign assertion. This is a deliberate, documented design choice — worth flagging because a naive reviewer might expect mutual binding.

8. **`ocsp._check_responder_authority` has a fragile expression-statement.** Lines 252-263 use a `... if ... else None` conditional *as a statement* for the RSA branch, then a separate `if isinstance(...EllipticCurve...)` for EC. Functional, but easy to misread and a refactor hazard. Not a correctness bug found.

9. **The frontier surface is broad but the runnable core is narrow.** Watermark in-process detection, CWT attestation, and real perceptual hashing are all stubbed/NotImplemented with honest docstrings. The genuinely-exercised production path is: build manifest → outer ECDSA/Ed25519 sign → ML-DSA-65 (or Ed25519) cosign over a Merkle root → store in Postgres mirror → serve/verify over HTTP. That path is real and end-to-end functional.

10. **Governance hook is real.** Keystore mutations route through `selfgov.governor.gate_controller_mutation` (`signer.py:108,116,126`) — denied mutations silently no-op. This is a live integration, not decoration (`tex/selfgov/governor.py:464`).
