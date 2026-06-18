# Subsystem Dossier: `vet` — Verifiable Execution Traces (Evidence Layer 5)

> Code root: `/Users/matthewnardizzi/dev/tex/src/tex/vet/`
> Branch: `feat/proof-carrying-gate`
> Verified by reading every `.py` in scope; wiring traced by grep + import-path tracing; one crypto smoke test run.

---

## ⚠️ Scope-vs-context discrepancy (READ FIRST)

The task brief described this unit as **"reporter_reputation, poisoning_detector, outcome_validator — the integrity gate on learning inputs."** **That description does not match the code in `src/tex/vet/`.** It describes a *different* subsystem.

- The reputation/poisoning/outcome-validator code lives in **`src/tex/learning/`** — `reporter_reputation.py`, `poisoning_detector.py`, `outcome_validator.py` — wired into `build_runtime` in `src/tex/main.py:106-108`, `:988-1018`, `:1210-1215`, `:1665-1670`. Verified by grep: `grep -rln "ReporterReputation\|PoisoningDetector\|OutcomeValidator" src/tex` returns only `main.py`, `selfgov/governor.py`, and files under `learning/` — **never `vet/`**.
- The actual `src/tex/vet/` directory is **VET = Verifiable Execution Traces** (`src/tex/vet/__init__.py:6`): host-independent authentication of agent outputs (Agent Identity Documents, selective disclosure, Web Proofs / TLS notarization, SCITT transparency receipts, PTV/AIVS/Txn-Token frontier shims).

This dossier documents **the code that is actually in `src/tex/vet/`** (the directory named in "Scope directories"), not the learning-integrity unit named in the context line. The `vet` reachability classification (`vet=LIVE`) in the spine pass refers to this VET directory, and is confirmed below.

---

## Overview

`tex.vet` is the **evidence-credential layer**: it produces and verifies cryptographic artifacts that let an external party (insurer, regulator, auditor, downstream agent) confirm facts about Tex and its decisions **without trusting the host that ran Tex**. It is reachable on the wire through one router, `tex.api.vet_routes`, mounted at `/v1/vet` in `tex.main` (`src/tex/main.py:27`, `:1509`).

The unit splits into four functional clusters:

1. **Agent Identity Document (AID)** — a W3C VC-2.0-shaped "passport" for an agent, built on an in-house **selective-disclosure primitive** (salted Merkle commitments + algorithm-agile signature). `agent_identity_document.py`, `selective_disclosure.py`, `registry.py`.
2. **Web Proofs** — TLS-session notarization (zkTLS / TLSNotary-MPC / proxy / k-of-n committee) so a third-party LLM-API response is independently verifiable. `web_proofs.py`, `integration.py`.
3. **SCITT** — IETF Supply-Chain Integrity Transparency & Trust: per-decision/per-AID Signed Statements registered to an append-only Merkle log returning COSE-style Receipts; plus an ARP (Attestation Reconciliation Protocol) shim. `scitt.py`.
4. **Frontier shims** layered onto the AID — PTV attestation, AIVS-Micro, OAuth Txn-Tokens, SD-JWT-VC / SD-Card. `ptv_attestation.py`, `aivs_micro.py`, `txn_tokens.py`, `sd_jwt_vc.py`.

**Implementation reality is high.** The cryptography is real and runs by default on a native FIPS-204 ML-DSA-65 backend (verified: smoke test below shows `backend=pyca-cryptography-native`, 1952-byte public key, 3309-byte signature). Merkle trees, salted commitments, inclusion proofs, replay binding, and fail-closed verification are all genuinely implemented. The "stubs" that exist are **clearly-marked, honestly-flagged graceful fallbacks** for external notary infrastructure (TLSNotary Rust binary, Reclaim/Pluto attestor URLs) that are absent in the sandbox — not hollow `pass` placeholders. The 90-test `tests/vet/` suite passes (`90 passed in 2.71s`).

---

## File Inventory

| File | Lines | Role | App-wiring |
|---|---|---|---|
| `__init__.py` | 41 | Layer marker (`__layer__=5`, `evidence`); re-exports only `AgentIdentityDocument`. | LIVE (pkg) |
| `agent_identity_document.py` | 650 | AID model + `issue`/`verify`/`present`/`verify_presentation_envelope`/`to_vc_2_0`. The headline artifact. | **LIVE** |
| `selective_disclosure.py` | 647 | Core SD primitive: salted SHA-256 commitments, RFC-6962-style Merkle tree, base/derived proof split, presentation HMAC binding. | **LIVE** (via AID) |
| `web_proofs.py` | 1081 | TLS-session notarization: 4 attestor clients + k-of-n committee + `notarize_session`/`verify_web_proof`. | **LIVE** |
| `scitt.py` | 1113 | SCITT Signed Statements, in-memory Transparency Service, COSE Receipts, inclusion-proof verify, ARP shim. | **LIVE** |
| `registry.py` | 142 | `InMemoryAidRegistry` + `AidRegistry`/`AidRegistryMirror` Protocols; process-wide `default_registry()`. | **LIVE** |
| `ptv_attestation.py` | 408 | PTV agent-identity attestation envelope (Schnorr/ML-DSA bridge in lieu of real Groth16). | **LIVE** (lazy, opt-in) |
| `aivs_micro.py` | 261 | AIVS-Micro ~200-byte Ed25519 continuous-monitoring stub. | **LIVE** (default-on in AID) |
| `txn_tokens.py` | 237 | OAuth 2.0 Transaction Tokens for Agents (`act`/`sub` claims, 60s TTL). | **LIVE** |
| `integration.py` | 241 | Glue to attach Web Proofs / SCITT statements to `/v1/guardrail` evidence payloads. | **ORPHAN-in-app** (tests only) |
| `sd_jwt_vc.py` | 560 | SD-JWT-VC + SD-Card (draft-nandakumar) selective-disclosure JWT credentials. | **ORPHAN-in-app** (tests only) |

Total: **5,381 lines** across 11 files. No `__pycache__`-only or empty files.

---

## Internal Architecture

### 1. Selective disclosure primitive (`selective_disclosure.py`) — the cryptographic spine

This is the load-bearing module; the AID is a thin domain wrapper over it.

- **`canonical_json(value)`** (`selective_disclosure.py:128`) — RFC-8785-JCS-subset serialization (sorted keys, no whitespace, UTF-8). Used everywhere as the stable hashing basis.
- **Data models** (Pydantic v2, `frozen=True, extra="forbid"`):
  - `ClaimDisclosure` (`:149`) — one salted commitment: `SHA-256(canonical_json([salt, name, value]))`, 16-byte CSPRNG salt (`:431`).
  - `BaseProof` (`:178`) — issuer artifact held by the holder, **never shipped to verifiers**: cryptosuite string, algorithm, issuer pubkey/key-id, the full commitment tuple, Merkle root, signature over the root.
  - `DerivedProof` (`:207`) — the presentation-time selective disclosure: only revealed `ClaimDisclosure`s, their Merkle inclusion paths, `revealed_indices`, `total_leaves`, the (re-used) base signature, and a per-presentation HMAC binding.
- **Merkle tree** — RFC-6962-style binary tree with odd-leaf duplication and **domain separation** (`_hash_leaf` prefixes `\x00`, `_hash_pair` prefixes `\x01`; `:255-262`) to block leaf/internal-node confusion attacks. `_merkle_root_and_proofs` (`:265`) builds the root and one sibling-chain per leaf via a parallel position map; `_verify_merkle_inclusion` (`:320`) reconstructs layer widths to correctly handle the duplicated odd edge.
- **Issuance** — `issue_credential` (`:402`): flattens nested claim dict to RFC-6901 JSON-Pointer triples (`_flatten_claims`, `:361`), salts/commits each, Merkle-roots them, then signs `b"AID-BASE-PROOF\x00" + root + b"\x00" + header` with the algorithm-agile provider (default ML-DSA-65). Cryptosuite tag is `bbs-2023-shape-{alg}` (`:463`).
- **Verification** — `verify_base_proof` (`:474`) recomputes commitments (constant-time `hmac.compare_digest`), rebuilds the root, verifies the issuer signature. Fail-closed: any `ValueError/RuntimeError` → `False`.
- **Presentation** — `derive_presentation` (`:519`) selects revealed pointers, copies their inclusion paths, and computes a **replay-binding MAC** keyed by the Merkle root itself: `HMAC(root, b"AID-PRES-BINDING\x00" + presentation_header)` (`:553`). `verify_presentation` (`:577`) re-checks commitments, inclusion proofs, issuer signature, and (if an expected header is supplied) the binding.

> **Honest design note in the docstring (`:39-54`):** this is **not** native BBS+ over BLS12-381. The author states py-ecc lacks the F_{p²} sqrt needed for correct G2 decompression and that shipping "half-correct BBS+" would create a silent verification-failure mode, so they implement the *credential shape* (base/derived split, unlinkable salted disclosure, holder binding) over a hash-based commitment scheme. This is an accurate, defensible engineering claim — verified by reading the code, which is genuinely a Merkle+HMAC scheme, not a stubbed pairing op.

### 2. Agent Identity Document (`agent_identity_document.py`)

- Models: `AidStatus` enum (`:143`), `AgentIdentityDocument` (`:152`, embeds the held `BaseProof`), request/result DTOs (`AidIssuanceRequest`, `AidPresentationRequest`, `AidVerificationResult`), and `AidPresentationEnvelope` (`:465`, the on-wire artifact).
- `_FIELD_POINTERS` (`:258`) maps friendly field names → JSON Pointers so callers never see pointer mechanics.
- **`issue(...)`** (`:293`): resolves/generates the agent signing key, builds the canonical claim set, **optionally** attaches a PTV attestation (`include_ptv_attestation`, lazy import at `:350`) and an AIVS-Micro stub (`include_aivs_micro` default `True`, `:362`), then calls `issue_credential` to mint the base proof. AIVS session root = SHA-256 over the canonical claim set (`_aivs_root_for_aid`, `:397`).
- **`verify(aid)`** (`:408`): expiry → status → base-proof signature → recompute commitments. **`present(aid, request)`** (`:488`): always force-discloses `agent_id`, `issuer_did`, `aid_spec`; binds `aud/nonce/iat/exp` into the presentation header. **`verify_presentation_envelope(...)`** (`:552`): fail-closed with `hmac.compare_digest` on audience/nonce/agent_id, then the derived-proof check.
- **`to_vc_2_0(aid)`** (`:618`): renders a W3C VC-2.0 JSON doc with a `DataIntegrityProof` block carrying the cryptosuite, Merkle root, and signature.

### 3. Web Proofs (`web_proofs.py`)

- `WebProofMode` enum (`:127`) — `ZKTLS_RECLAIM`, `ZKTLS_PLUTO`, `TLSNOTARY_MPC`, `TLSNOTARY_PROXY`, `MULTI_ATTESTOR`, `STUB`. Models `WebProofAttestation` (`:180`) and `WebProof` (`:198`) carry only SHA-256 commitments, never plaintext.
- **Attestor clients** — `ZkTlsAttestorClient` (`:327`), `TlsNotarySubprocessClient` (`:469`, shells out to the Rust binary via `subprocess.run`), `TlsNotaryProxyClient` (`:597`). Each has `is_live()` (checks env var / binary on PATH) and a `_notarize_live`/`_notarize_stub` pair. **Live paths are real** (urllib POST to attestor URL; subprocess to `TEX_TLSNOTARY_BIN`) but `# pragma: no cover` because the external infra is absent in CI. The stub path signs the canonical `_attestor_signing_input` with a locally-generated Ed25519 key and the result is flagged `mode=STUB` in metadata.
- **`MultiAttestorCommittee`** (`:755`) — real k-of-n quorum: validates `1 ≤ k ≤ n`, notarizes across all clients, raises if fewer than `k` attestations return.
- **`notarize_session(...)`** (`:827`) — backwards-compatible with the VET-paper `(target_host, session_log)` signature; derives commitments, dispatches to committee or a single client, and **marks the proof `STUB` whenever the chosen client `is_live()` is false** (`:931`).
- **`verify_web_proof(...)`** (`:956`) — fail-closed: rejects `STUB` unless `allow_stub=True`; constant-time host + response-commitment compare; deduplicates attestors by id; verifies each attestation's signature (trying candidate modes since the signing input embeds the mode); requires `verified_count >= threshold_k`. Supports optional `trusted_attestor_pubkeys` pinning.

### 4. SCITT (`scitt.py`)

- COSE-style models (JSON-encoded, not yet true CBOR — stated at `:489-491`): `ScittIssuer`, `ScittClaims`, `ScittSignedStatement`, `ScittReceipt`, `ScittTransparentStatement`, `ScittRegistrationResult`, `ScittVerificationResult`.
- **Issuer side**: `sign_statement(...)` (`:437`) builds a protected header with CWT claims and signs a JSON analogue of the COSE `Sig_structure` `["Signature1", protected, external_aad, payload]`. `verify_signed_statement(...)` (`:512`) checks iss/sub/exp/nbf, recomputes the payload digest, verifies the signature. Fail-closed.
- **Transparency Service**: `TransparencyService` Protocol (`:578`) + `InMemoryTransparencyService` (`:623`) — thread-safe (`RLock`), append-only list of `_LogEntry`, RFC-9162 Merkle root + inclusion path (`_merkle_root_and_proof`, `:348`). `register(...)` (`:665`) appends, signs a Receipt over the tree state (`_sign_receipt`, `:701`), returns a `ScittRegistrationResult`. Receipts are **recomputed on every read** (the docstring honestly flags this as O(n) and suggests an incremental Merkle tree for >10⁴ entries, `:633-635`).
- **`default_transparency_service()`** (`:789`) — lazy process-wide singleton; **uses Ed25519 by default** "so it works without liboqs" in the sandbox (`:790-792`), while production is expected to instantiate ML-DSA-65.
- **Verification**: `verify_receipt` (`:807`) checks ts_uri/pubkey pins, statement-digest, VDS algorithm, inclusion proof, and TS signature. `verify_transparent_statement` (`:889`) chains statement + receipt verification, requiring ≥1 receipt to pass.
- **Tex helpers**: `register_aid` (`:956`), `register_decision` (`:985`) — used live by the route.
- **ARP shim** (`:1023-1113`): `ArpReconciliationRequest/Response`, `arp_canonicalize_claim`, `arp_project_claim`. The `glb-default` projection is a real (if simplistic) `SHA-256(target_register || canonical_claim)`; any other projection name raises `ValueError` (`:1113`).

### 5. Registry & frontier shims

- **`registry.py`**: `InMemoryAidRegistry` (`:73`) — dict + `RLock`, optional best-effort `AidRegistryMirror` (mirror errors logged, never raised, `:96`). `default_registry()` (`:140`) is the process-wide singleton the route writes to.
- **`ptv_attestation.py`**: `generate_ptv_attestation` (`:221`) produces a 3-part JWS-like string; docstring **explicitly states (`:38-46`) there is no real Groth16** — it emits a Schnorr/ML-DSA signature in the same wire envelope as a drop-in target. `verify_ptv_attestation` (`:313`) does full fail-closed JWS + inner-proof + expiry + pin checks.
- **`aivs_micro.py`**: `emit_aivs_micro` (`:144`) — 6-field Ed25519 record, ~200 bytes, domain-separated signing input (`:121`). `verify_aivs_micro` (`:204`) checks version, age window (with 5-min skew), identity-fingerprint, and signature.
- **`txn_tokens.py`**: `issue_txn_token` (`:149`) — compact JWS with `act`/`sub`/`scope`, default ML-DSA-65, 60s TTL. `verify_txn_token` (`:197`) fail-closed on aud/exp/iat/act/sub + signature.
- **`sd_jwt_vc.py`**: full SD-JWT-VC issuance (`issue_sd_jwt_vc`, `:184`), SD-Card variant (`issue_sd_card`, `:290`), presentation with KB-JWT holder binding (`present_sd_jwt_vc`, `:390`), and verification. Real `~`-delimited compact serialization and `_sd` digest set per draft-16.

---

## Public API / Entrypoints

Symbols imported by **runtime** code outside the unit (all from `tex.api.vet_routes`):

- From `agent_identity_document`: `AgentIdentityDocument`, `AidIssuanceRequest`, `AidPresentationEnvelope`, `AidPresentationRequest`, `AidStatus`, `AidVerificationResult`, `issue`, `present`, `to_vc_2_0`, `verify`, `verify_presentation_envelope` (`vet_routes.py:50-62`).
- From `registry`: `default_registry` (`:63`).
- From `txn_tokens`: `TxnTokenArtifact`, `TxnTokenScope`, `TxnTokenVerifyResult`, `issue_txn_token`, `verify_txn_token` (`:64-70`).
- From `web_proofs`: `WebProof`, `WebProofMode`, `notarize_session`, `verify_web_proof` (`:71-76`).
- From `scitt` (E402 deferred block, `:454-471`): `ArpReconciliationRequest/Response`, `ScittClaims`, `ScittIssuer`, `ScittReceipt`, `ScittRegistrationResult`, `ScittSignedStatement`, `ScittTransparentStatement`, `ScittVerificationResult`, `arp_project_claim`, `default_transparency_service`, `register_decision`, `sign_statement`, `verify_receipt`, `verify_signed_statement`, `verify_transparent_statement`.
- `__init__.py` re-exports only `AgentIdentityDocument`.

`ptv_attestation.generate_ptv_attestation` and `aivs_micro.emit_aivs_micro` are public but reached only via **lazy imports inside `agent_identity_document.issue()`** (`:350`, `:362`).

`sd_jwt_vc.*` and `integration.*` are public but have **no runtime importer** (see Wiring).

---

## Wiring

### In

`tex.vet` is reached on the wire through exactly one router: **`tex.api.vet_routes.router`** (prefix `/v1/vet`). Whole-router auth dependency `RequireScope("evidence:read")` (`vet_routes.py:87-90`); mutating endpoints add `evidence:write`.

15 live endpoints (`vet_routes.py`):
`POST /issue-aid` (`:235`), `POST /verify-aid` (`:248`), `POST /present-aid` (`:258`), `POST /verify-presentation` (`:281`), `GET /aid/{agent_id}` (`:299`), `POST /update-aid-status` (`:314`), `POST /notarize` (`:344`), `POST /verify-web-proof` (`:371`), `POST /issue-txn-token` (`:396`), `POST /verify-txn-token` (`:429`), `POST /scitt/register-decision` (`:532`), `POST /scitt/verify-transparent` (`:563`), `GET /scitt/receipt/{entry_id}` (`:583`), `GET /scitt/ts-status` (`:599`), `POST /scitt/arp-reconcile` (`:619`).

### Live call path (from the running app)

```
tex.main.create_app / build_runtime
  → src/tex/main.py:27   from tex.api.vet_routes import router as vet_router
  → src/tex/main.py:1509 app.include_router(vet_router)            # mounts /v1/vet/*
      → POST /v1/vet/issue-aid  (vet_routes.py:241 issue_aid)
          → agent_identity_document.issue(request=req)             # vet_routes.py:245
              → selective_disclosure.issue_credential(...)         # agent_identity_document.py:371
                  → pqcrypto.algorithm_agility.get_signature_provider(ML_DSA_65).sign(...)
              → [opt] ptv_attestation.generate_ptv_attestation(...) # lazy, :350
              → [opt] aivs_micro.emit_aivs_micro(...)               # default-on, :362
          → registry.default_registry().register(aid)              # vet_routes.py:246
      → POST /v1/vet/notarize  (vet_routes.py:357 notarize_session)
      → POST /v1/vet/scitt/register-decision (vet_routes.py:548 register_decision)
          → InMemoryTransparencyService.register(...)              # scitt.py:665
```

**`wired_status = LIVE`** for the AID/selective-disclosure/web-proofs/scitt/registry/txn-tokens/ptv/aivs cluster — confirmed end-to-end from `create_app` to the cryptographic primitives.

### Out (dependencies)

- **Internal tex**: only `tex.pqcrypto.algorithm_agility` (`SignatureAlgorithm`, `SignatureKeyPair`, `SignatureProvider`, `get_signature_provider`) — imported by every substantive module. No other `tex.*` import in the unit. (Other subsystems mention `tex.vet` only in docstrings: `zkprov/integration.py:10`, `zkprov/scitt_arp.py:43` — verified these are **comments, not imports**.)
- **External libraries**: `pydantic` (v2 strict models); stdlib only otherwise — `hashlib`, `hmac`, `secrets`, `base64`, `json`, `struct`, `uuid`, `subprocess`, `shutil`, `urllib`, `threading`, `enum`, `dataclasses`, `datetime`, `logging`, `os`, `time`. **No third-party crypto, networking, or notary library is hard-bundled.**
- **External infra (optional, env-gated)**: TLSNotary Rust binary (`TEX_TLSNOTARY_BIN`), TLSNotary proxy (`TEX_TLSNOTARY_PROXY_URL`), Reclaim attestor (`TEX_RECLAIM_ATTESTOR_URL` + app id/secret), Pluto notary (`TEX_PLUTO_NOTARY_URL`). All absent → graceful stub.

---

## Implementation Reality

**Verdict: REAL with honest, clearly-flagged graceful fallbacks. No hollow stubs, no `NotImplementedError`, no TODO/`pass`-only bodies.** (`grep -rn "NotImplementedError\|raise NotImplemented" src/tex/vet` → none.)

Real, runs by default:
- **Crypto.** Smoke test (`PYTHONPATH=src python` against `get_signature_provider(ML_DSA_65)`) emits `backend=pyca-cryptography-native`, public key 1952 bytes, signature 3309 bytes, `verify: True` — genuine FIPS-204 ML-DSA-65, not an Ed25519 fallback. The AID base proof, Txn-Tokens, PTV (ML-DSA bridge), SD-JWT-VC all default to ML-DSA-65 and execute it natively.
- **Merkle / commitments / inclusion proofs / replay binding.** Fully implemented in `selective_disclosure.py` and `scitt.py`, with domain separation and fail-closed verification. 90/90 `tests/vet/` pass.
- **Multi-attestor k-of-n quorum.** Real threshold logic (`web_proofs.py:755`, verify at `:1079`).
- **SCITT transparency log + receipts.** Real append-only Merkle log with signed inclusion proofs (`scitt.py:623`).

Honest fallbacks (flagged in code, not silent):
- **Web-proof notaries** (`web_proofs.py`): live `urllib`/`subprocess` paths exist and are real, but with no external infra configured the client returns a self-signed Ed25519 attestation **marked `mode=STUB`**; `verify_web_proof` rejects STUB unless `allow_stub=True` (`:1001`). The `/notarize` route surfaces the mode to callers.
- **PTV** (`ptv_attestation.py:38-46`): docstring states there is no Python Groth16 toolchain yet; emits a Schnorr/ML-DSA signature in the same JSON wire envelope as the swap-in target. The "~200ms" perf claim is explicitly called *aspirational* (`:45`).
- **Selective disclosure** (`selective_disclosure.py:39-54`): explicitly **not** native BBS+; a hash-based commitment scheme of equivalent shape, with the swap point documented.
- **SCITT default TS uses Ed25519** in the sandbox (`scitt.py:790-792`), not the ML-DSA-65 the prose elsewhere implies for production — an honest sandbox accommodation, but worth noting that the *default* path is therefore classical, not PQ.
- **SCITT "COSE"** is a JSON analogue of the COSE `Sig_structure`, not real CBOR/COSE_Sign1 (`scitt.py:487-491`). Wire-format claim is shape-compatible, not byte-compatible.

---

## Technology / SOTA

- **Post-quantum signatures**: ML-DSA-65 (FIPS 204, NIST L3) default, via `tex.pqcrypto.algorithm_agility`; Ed25519 / ECDSA-P256 supported for legacy/attestor interop. Algorithm carried in every artifact for agile dispatch.
- **Selective disclosure**: SD-JWT-VC salted-disclosure construction (`SHA-256([salt,name,value])`) + RFC-6962 binary Merkle tree with odd-leaf duplication and domain separation; base/derived proof split modeled on W3C `bbs-2023`.
- **TLS notarization**: zkTLS (Reclaim, Pluto), TLSNotary MPC (QuickSilver VOLE-IZK, via Rust subprocess), TLSNotary proxy mode, and a k-of-n Byzantine-tolerant attestor committee.
- **Transparency**: IETF SCITT (`draft-ietf-scitt-architecture-22`) Signed Statements + COSE Receipts (`draft-ietf-cose-merkle-tree-proofs-17`) with RFC-9162 Merkle inclusion proofs; ARP cross-sovereign reconciliation shim (`draft-hillier-scitt-arp-00`).
- **Frontier identity drafts**: PTV (`draft-anandakrishnan-rats-ptv-agent-identity-00`), AIVS-Micro (`draft-stone-aivs-00`), OAuth Txn-Tokens for Agents (`draft-oauth-transaction-tokens-for-agents-06`), SD-Card (`draft-nandakumar-agent-sd-jwt-02`).
- **Patterns**: Pydantic v2 strict frozen models everywhere; `Protocol` + `@runtime_checkable` for swappable registry/TS backends; constant-time `hmac.compare_digest`; uniform fail-closed verification; lazy imports to avoid import-cost/cycles.

---

## Persistence

**Entirely in-memory; no durable store wired in this unit.**

- `InMemoryAidRegistry` (`registry.py:73`) — dict + `RLock`; process-wide `_DEFAULT_REGISTRY` (`:137`). Optional `AidRegistryMirror` Protocol exists for a durable sink (e.g. Postgres) but **no concrete mirror is implemented or wired** — it is a best-effort hook only.
- `InMemoryTransparencyService` (`scitt.py:623`) — append-only Python list + `RLock`; process-wide `_DEFAULT_TS` singleton (`:785`). Merkle root recomputed on every read. **Log does not survive process restart**; production CCF/Sigstore swap is a documented Protocol target, not implemented here.
- AID base proofs, Web Proofs, SCITT receipts: ephemeral request/response objects. The intent (per docstrings) is that SCITT receipts and Web Proofs are persisted *by the evidence layer* (`tex.evidence`) when attached via `integration.py`, but that attachment path is not live (see below).

---

## Notable Findings

1. **Scope/context mismatch (most important).** The unit is **VET = Verifiable Execution Traces**, not the learning-integrity (reputation/poisoning/outcome-validator) gate the brief described. Those live in `src/tex/learning/`. Any "Tex bible" entry for this directory must be titled VET. The spine classification `vet=LIVE` is correct for *this* directory.

2. **`sd_jwt_vc.py` (560 lines) is ORPHAN-in-app.** Grep for runtime importers in `src/tex` returns only the file itself. It is exercised only by `tests/vet/test_primitives.py` and friends. A complete, non-trivial SD-JWT-VC/SD-Card implementation that nothing on the live wire calls — **dead code from the app's perspective**, kept alive by tests. (`tests/frontier/test_scaffolding_imports.py` also imports it.)

3. **`integration.py` (241 lines) is ORPHAN-in-app.** It is the documented glue to attach Web Proofs / SCITT statements onto `/v1/guardrail` evidence payloads, but **no runtime module imports it** (grep for `from tex.vet.integration` / `attach_web_proof_to_payload` in `src/tex` → only the file itself; importers are `tests/test_integration_layer.py`, `tests/vet/test_primitives.py`). The decision-evidence path therefore does **not** currently carry vet Web Proofs or SCITT receipts in production, despite the AID/SCITT routes existing. This is the gap between "the primitives exist and are LIVE on `/v1/vet`" and "decisions actually embed them."

4. **Default SCITT TS is Ed25519, not PQ** (`scitt.py:790-792`). The module's own prose markets ML-DSA-65 PQ-by-default, but the *default* Transparency Service that `register_decision`/`register_aid` use when no TS is passed signs receipts with classical Ed25519. The `/scitt/register-decision` route's *statement* signature defaults to ML-DSA-65, but the *receipt* (TS) signature is Ed25519. Mixed PQ posture; not wrong, but the "PQ by default" framing is partial here.

5. **Heavy marketing prose in docstrings is unverifiable competitive positioning.** Repeated "no AI-governance vendor ships X… Tex is the first" claims (`web_proofs.py:44-47`, `scitt.py:34-39`, `txn_tokens.py:43-45`, etc.) are **(claim, unverified)** — market assertions, not code facts. The code itself does implement the named primitives; the "first/only" superlatives are not code-checkable.

6. **SCITT "COSE" is JSON, not CBOR** (`scitt.py:487-491`) and selective disclosure is **not** native BBS+ (`selective_disclosure.py:39-54`). Both are honestly disclosed in-code as shape-compatible analogues with documented swap points. Not a contradiction — but a "Tex implements SCITT/COSE/BBS+" headline would over-state byte-level conformance.

7. **`InMemoryTransparencyService.get_root()` / receipts recompute O(n) on every call** (`scitt.py:633-635`, recomputed in `register`, `get_receipt`, `get_root`). The docstring flags this; fine for demo/single-node, would not scale. Inclusion paths can grow as the log appends, so receipts are not stable artifacts over time — verifiers must refetch (`:738-741`).

8. **No `NotImplementedError`, no TODO-only bodies, no bare `pass` stubs** in the entire unit — consistent with the spine note that vet's NotImplementedError count is 0. Every function has a real body. The only "fallbacks" are the env-gated notary stubs, which are explicitly labelled and rejected-by-default at verify time.

9. **CONTRADICTION (potential over-exposure): `GET /aid/{agent_id}` returns the held `base_proof`, contradicting the registry docstring.** `registry.py:17-21` asserts "registry lookups return only the AID *envelope*… `/v1/vet/aid/{agent_id}` does NOT expose [the held base proof]." But the route (`vet_routes.py:299-311`) is declared `response_model=AgentIdentityDocument` and returns the full `aid` object via `default_registry().get(agent_id)`. `base_proof` is a **required field** on `AgentIdentityDocument` (`agent_identity_document.py:193`), so it is serialized in the response. The `agent_identity_document.py:191-193` comment is explicit: *"The held base proof. NEVER ship this to verifiers — only derived presentations cross trust boundaries."* The GET route ships it. The route does carry `RequireScope("evidence:read")` so it is not unauthenticated, but any principal with `evidence:read` receives the holder secret that lets them mint arbitrary presentations for that agent. **Worth a security review** — the code does the opposite of what its own docstring and the model comment say.
