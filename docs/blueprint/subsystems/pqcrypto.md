# Subsystem Dossier: `pqcrypto` — Post-Quantum Crypto Spine

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/pqcrypto/` (20 `.py` files)
> Branch: `feat/proof-carrying-gate`
> Reachability: **LIVE** (confirmed by tracing the call path from `tex.main:build_runtime` → `engine.pdp` and from `tex.api` routes; see Wiring).
> All claims below are code-verified. Statements drawn only from docstrings/`.md` are tagged **(claim, unverified)**.

---

## 1. Overview

`pqcrypto` is the algorithm-agile post-quantum signing/KEM layer for Tex's evidence chain and outbound content. It is marked architectural **Layer 5 (Evidence)** (`__init__.py:36-37`: `__layer__ = 5`, `__layer_kind__ = 'evidence'`).

The unit's spine is a single dispatcher — `algorithm_agility.get_signature_provider` — that resolves a `SignatureAlgorithm` enum into a concrete provider implementing a structural `SignatureProvider` Protocol (`sign`/`verify`/`generate_keypair`). Everything else is either:

- a **real provider** behind that dispatcher (ML-DSA, BLAKE3-ML-DSA, SLH-DSA, composite ML-DSA, hybrid ML-DSA+Ed25519, quorum ML-DSA, Ed25519), or
- a **standalone primitive family** not behind the signature dispatcher (ML-KEM, HQC + hybrid KEM combiner, Mithril MPC threshold, TALUS-TEE, CMS/DER codecs, code-signing, evidence-quorum glue, LMS), or
- **governance/probe glue** (`pq_durability`, `_backend_probe`).

**Reality verdict: REAL.** The ML-DSA and ML-KEM cores run on a genuine native backend on this host (verified at runtime: `pyca-cryptography-native`, FIPS 204/203 via OpenSSL 3.5). Native fallback to `liboqs` exists; a hard `RuntimeError` is raised when neither is present — there is no silent heuristic degradation. SLH-DSA/HQC/Mithril require optional native libs and fail-closed loudly when absent. Two modules are honest scaffolds: `lms.py` is an explicit `NotImplementedError` stub pointing at `code_signing`, and `talus_tee.py`'s native BCC+CEF path is gated behind an env flag that raises `NotImplementedError`.

**The "stale key" concern is REAL and confirmed on this checkout** — see Notable Findings §9.1. The live evidence-chain seal is currently **ECDSA-P256, not post-quantum**, because a persisted classical key (`var/tex/keys/evidence_seal_key.json`, `algorithm: ecdsa-p256`) short-circuits the preferred composite-ML-DSA path — even though the ML-DSA backend is present and durable.

---

## 2. File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 51 | Package facade. Exports `SignatureAlgorithm`, `SignatureKeyPair`, `SignatureProvider`, `get_signature_provider`. Sets `__layer__=5`. |
| `algorithm_agility.py` | 219 | **The spine.** `SignatureAlgorithm` enum (all schemes), `SignatureKeyPair`, `SignatureProvider` Protocol, and `get_signature_provider` lazy dispatcher. |
| `ml_dsa.py` | 368 | **FIPS 204 ML-DSA primary path.** `MlDsaProvider` + `_NativeBackend` (pyca) / `_LiboqsBackend`. Import-time backend selection. `active_backend_id()`. |
| `ml_kem.py` | 356 | **FIPS 203 ML-KEM.** `MlKemProvider` (encap/decap) + native/liboqs backends. `get_kem_provider`. |
| `pq_durability.py` | 620 | **L10 governance gate.** Maps live backend id → `SignerDurability`; `apply_pq_durability_hold` demotes PERMIT→ABSTAIN when a PQ-non-repudiation claim can't be honored; seals a fail-closed fact. Plus a real OpenSSL-CLI composite ML-DSA-87+ECDSA-P384 round-trip (feasibility proof). |
| `_backend_probe.py` | 406 | Fail-closed, never-raising availability probes (ezkl/Halo2, ML-DSA maturity, torch+NLI). Reporter-only; **no verdict-path consumer**. |
| `_ed25519_provider.py` | 79 | `Ed25519Provider` (RFC 8032). Classical half of hybrid + standalone dispatcher option. |
| `hybrid.py` | 237 | `HybridMlDsaEd25519Provider` — ML-DSA-65 ‖ Ed25519 length-prefixed concat; both halves must verify. |
| `blake3_ml_dsa.py` | 267 | `Blake3MlDsaProvider` — FIPS 204 §5.4 HashML-DSA with BLAKE3 pre-hash, delegating to `MlDsaProvider`. |
| `slh_dsa.py` | 298 | `SlhDsaProvider` — FIPS 205 SPHINCS+ via **liboqs only**, with sign-then-verify fault-detection guard. |
| `composite_ml_dsa.py` | 437 | `CompositeMlDsaProvider` — draft-ietf-lamps-pq-composite-sigs-18 composite (ML-DSA + Ed25519/ECDSA-P384), SHA-512 domain-bound. |
| `composite_cms.py` | 314 | ASN.1 DER codec for composite signatures (`pyasn1`/`pyasn1_modules`). `CompositeSignatureValue`, AlgorithmIdentifier, minimal CMS SignerInfo. |
| `quorum_ml_dsa.py` | 611 | `QuorumMlDsaProvider` — k-of-n quorum *certificate* over independent ML-DSA keys (NOT a single FIPS 204 sig). `ThresholdMlDsaProvider` alias. |
| `threshold_ml_dsa.py` | 314 | Mithril **genuine MPC threshold** ML-DSA-44 via vendored Rust PyO3 `.so`. `distributed_keygen`, `MithrilThresholdSdk`, `verify_fips204`. |
| `talus_tee.py` | 506 | TALUS-TEE 1-round threshold harness: attestation interface + Mithril-inside-TEE. Native BCC+CEF path raises `NotImplementedError`. |
| `hqc.py` | 413 | `HqcProvider` (HQC KEM, liboqs only) + `MlKemHqcHybridProvider` (ML-KEM ‖ HQC combiner via HKDF-SHA-512). |
| `lms.py` | 175 | **Stub.** LMS (SP 800-208) API surface; all 3 crypto functions raise `NotImplementedError`. Points callers to `code_signing`. |
| `code_signing.py` | 256 | Release/skill-manifest signing wrapper over `SlhDsaProvider`. `sign_release_artifact`/`verify_release_artifact`. |
| `evidence_chain_signer.py` | 230 | Detached-then-embed `pq_signature` over RFC 8785 canonical evidence records via the dispatcher. **No live importer** (only tests). |
| `evidence_quorum.py` | 282 | Env-gated (`TEX_EVIDENCE_QUORUM_K`) glue: quorum-sign evidence records + serialize/deserialize. **No live importer** (only tests). |

Total: **6,481 LOC** across 20 files (sum of the table).

---

## 3. Internal Architecture

### 3.1 The dispatcher (`algorithm_agility.py`)

- `SignatureAlgorithm(str, Enum)` (`:29-79`) enumerates every scheme: ML-DSA-44/65/87, BLAKE3-ML-DSA-65, SLH-DSA-128s/128f/192s/256s, THRESHOLD-ML-DSA-44/65/87 (Mithril), QUORUM-ML-DSA-44/65/87, two COMPOSITE sets, HYBRID, ED25519, ECDSA-P256.
- `SignatureKeyPair` (`:83-90`): frozen dataclass `(algorithm, public_key, private_key, key_id)`.
- `SignatureProvider` (`:93-104`): `@runtime_checkable` Protocol with `sign/verify/generate_keypair`.
- `get_signature_provider(algorithm)` (`:129-219`): lazy-imports and returns the concrete provider. **All provider imports are inside the function body** so the dispatcher is importable on hosts lacking liboqs; the crypto failure surface is deferred to first method call (`:148-151`).
  - THRESHOLD-ML-DSA-* deliberately **raises `NotImplementedError`** with a redirect to `threshold_ml_dsa.distributed_keygen` (`:180-187`) — it does not fit the single-key Protocol.
  - ECDSA-P256 is delegated out of the package to `tex.events._ecdsa_provider.EcdsaP256Provider` (`:214-217`).

### 3.2 ML-DSA core (`ml_dsa.py`) — the headline path

- Two backends selected once at import time (`_select_backend`, `:232-242`; `_BACKEND = _select_backend()`, `:245`):
  1. `_NativeBackend` (`:95-182`) — `cryptography.hazmat.primitives.asymmetric.mldsa` (pyca ≥48 / OpenSSL ≥3.5). `backend_id = "pyca-cryptography-native"`. Uses `from_seed_bytes` for the 32-byte seed wire format (`:138`); `_load_public` accepts raw FIPS 204 §5.3 **or** SPKI/PEM/DER for c2pa interop (`:159-182`).
  2. `_LiboqsBackend` (`:185-229`) — `oqs.Signature`. `backend_id = "liboqs"`.
- No backend → `_require_backend` raises a hard `RuntimeError` with remediation text (`:253-264`). **No heuristic fallback.**
- `MlDsaProvider` (`:270-350`): stateless, parameter-set-validated; `sign`/`verify`/`generate_keypair` dispatch to `_BACKEND` and emit `pqcrypto.ml_dsa.*` telemetry. Size constants per FIPS 204 Table 2 (`:72-81`) and COSE alg ids -48/-49/-50 (`:84-92`).
- `active_backend_id()` (`:248-250`) — the single source of truth consumed by `pq_durability` and `_backend_probe`.

### 3.3 ML-KEM core (`ml_kem.py`)

- `KemAlgorithm` (`:49-52`): ML-KEM-512/768/1024. Native pyca backend exposes only 768/1024 (`_NativeKemBackend`, `:82-131`); liboqs covers 512 (`:134-160`). Both probed at import (`_NATIVE`, `_LIBOQS`, `:179-180`).
- `MlKemProvider` (`:212-345`): `encapsulate` returns `(ciphertext, shared_secret)` (the pyca native order is swapped internally, `:121-123`). Hard length validation on pk/ct/ss; private-key length must be the 64-byte seed or the expanded `_SK_BYTES[alg]` (`:315-322`). Implicit-rejection per FIPS 203 §7.3 noted (`:289-291`).
- `get_kem_provider` (`:348-356`) is the KEM-side analog of `get_signature_provider`.

### 3.4 Provider family (all delegate to `MlDsaProvider`)

- **`HybridMlDsaEd25519Provider`** (`hybrid.py:89-237`): `u32_be(len(ml_dsa)) ‖ ml_dsa ‖ classical` layout (`_concat_length_prefixed`, `:84-86`); `verify` returns True only if both halves verify (`:188`). Layout version constant `_HYBRID_LAYOUT_VERSION="1"` (`:65`).
- **`Blake3MlDsaProvider`** (`blake3_ml_dsa.py:122-268`): `_blake3_prehash` (`:95-119`) computes `BLAKE3(domain_tag ‖ len_le8 ‖ message)` (32 bytes), domain-separated by `b"tex-ml-dsa-b/v1\x00"` (`:84`), then signs the digest via the underlying `MlDsaProvider(ML_DSA_65)`. Requires the `blake3` Python binding; raises `RuntimeError` if absent (`:107-112`).
- **`SlhDsaProvider`** (`slh_dsa.py:137-298`): liboqs `SLH_DSA_PURE_SHA2_*` names (`:78-83`). `sign` validates exact FIPS 205 §11 length (`:201-208`) and, when `fault_check=True` (default) and a public key is present, re-verifies in-process and raises `SlhDsaFaultDetected` on mismatch (`:210-239`) — the ePrint 2026/759 countermeasure pattern **(claim, unverified for the academic attribution; the re-verify logic itself is real and present)**. If no public key is on the keypair, the fault check is skipped with a telemetry warning (`:240-246`).
- **`CompositeMlDsaProvider`** (`composite_ml_dsa.py:239-438`): `_bind_message` (`:195-236`) builds `Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA512(M)` per draft-18 §2.1; both halves (ML-DSA + Ed25519/ECDSA-P384) sign that binding; `verify` requires both (`:425`). Fixed prefix `b"CompositeAlgorithmSignatures2025"` (`:110`), per-algorithm labels (`:114-117`), and IANA OIDs (`:122-125`).
- **`QuorumMlDsaProvider`** (`quorum_ml_dsa.py:292-611`): the `distributed_keygen → partial_sign → aggregate → verify_quorum` flow. `QuorumDescriptor` is SHA-256-bound over `(k,n,base_alg,sorted members)` (`:174-199`); `verify_quorum` re-derives the commitment to catch tampering, rejects duplicate/unknown indices, and requires ≥k valid partials (`:468-574`). The single-key Protocol methods (`sign`/`verify`/`generate_keypair`) raise `NotImplementedError` with redirects (`:584-606`). `ThresholdMlDsaProvider = QuorumMlDsaProvider` alias (`:611`).

### 3.5 Mithril genuine MPC (`threshold_ml_dsa.py`)

- Loads a vendored PyO3 `.so` at `vendor/mithril/tex_mithril.so` (`_VENDOR_DIR`, `:92`). **Verified present on disk: 13.7 MB, built for x86_64 Linux** (`Jun 9`). Lazy-loaded (`_get_native`, `:128-132`) so import never fails on hosts without the ext.
- `distributed_keygen(t,n,...)` (`:251-298`) validates `(t,n) ∈ SUPPORTED_PARAMS` (15 combos, `:157-161`) → `MithrilThresholdSdk` (`:164-248`) wrapping the Rust `MithrilSdk`. `threshold_sign` enforces strictly-ascending active set of length `t` (`:203-211`) and produces a bit-for-bit FIPS 204 ML-DSA-44 signature **(claim, unverified — the Rust crate's standards-compliance is not executable on this macOS arm64 host; the `.so` is x86_64 Linux)**.
- `verify_fips204` (`:301-314`) is the property entry point and is reused by `talus_tee.verify_talus_signature`.

### 3.6 TALUS-TEE (`talus_tee.py`)

- Attestation interface (`TeeType`, `AttestationQuote`, `AttestationVerifier`) with a **fail-closed default verifier** that rejects everything unless `TeeType.NONE_TEST_ONLY` AND `TEX_TALUS_ALLOW_INSECURE_TEE=1` (`_default_reject_verifier`, `:144-171`).
- `TalusTeeSdk.__init__` (`:274-325`) verifies the attestation and binds `SHA256(mithril_sdk.public_key)` into the first 32 bytes of `report_data`, raising on mismatch (`:299-314`). `online_sign` (`:373-437`) checks attestation freshness, raises `NotImplementedError` when `TEX_TALUS_NATIVE_BCC=1` (native path unbuilt, `:407-413`), and otherwise delegates to `mithril_sdk.threshold_sign`.

### 3.7 Governance gate (`pq_durability.py`) — the most consequential module

- `SignerDurability` ladder NONE < RESEARCH_ONLY < DURABLE (`:106-115`).
- `durability_for_backend_id` (`:133-146`) is a **fail-closed allow-list**: only `"pyca-cryptography-native"` → DURABLE, only `"liboqs"` → RESEARCH_ONLY, **everything else (incl. `None`/`""`) → NONE**. This is the documented "nanozk trap" defense.
- `probe_backend` (`:149-159`) = `durability_for_backend_id(ml_dsa.active_backend_id())` — a pure function of the backend the live signer actually dispatches to.
- `apply_pq_durability_hold` (`:257-329`) — **the verdict-path consumer**. Opt-in via `request.metadata["pq_non_repudiation"]`. Monotone-lowering guard: only a `Verdict.PERMIT` can be demoted (`:288`); when a PQ-non-repudiation claim is asserted but the signer isn't DURABLE, demotes to ABSTAIN, adds a `Finding`, sets `scores["pq_durable"]=0.0`, and seals a `PQ-durable=false` fact into the decision ledger fail-closed (`:315-329`).
- The OpenSSL-CLI composite round-trip (`composite_sign_chain_head`/`composite_verify_chain_head`, `:507-620`) is a **real ML-DSA-87 (OpenSSL CLI) + ECDSA-P384 (pyca)** sign/verify over the production draft-18 binding — but it is deliberately **NOT** wired into `active_backend_id()`, so it cannot raise `probe_backend()` off NONE. `find_openssl_mldsa` (`:437-462`) fail-closes on version <3.5 and rejects macOS LibreSSL.

---

## 4. Public API / Entrypoints

Symbols imported by other Tex code (verified by grep, see §5):

- **From `algorithm_agility`** (the dominant surface): `SignatureAlgorithm`, `SignatureKeyPair`, `SignatureProvider`, `get_signature_provider`. Re-exported at `__init__.py:39-51`.
- **From `ml_dsa`**: `active_backend_id`, `cose_alg_id`, `MlDsaProvider`, size helpers.
- **From `pq_durability`**: `apply_pq_durability_hold` (consumed by the PDP), plus `probe_backend`/`SignerDurability` (consumed by `_backend_probe`).
- **From `_backend_probe`**: `ProbeResult` shape (shared with `tee._mode_probe`).
- **From `ml_kem`** / `hqc`: `MlKemProvider`/`KemAlgorithm` and HQC types (referenced internally; few external live importers).

The provider classes for the exotic schemes (`Blake3MlDsaProvider`, `SlhDsaProvider`, `CompositeMlDsaProvider`, `QuorumMlDsaProvider`, `HybridMlDsaEd25519Provider`) are reached **only** through `get_signature_provider`, not by direct import from live code.

---

## 5. Wiring

### 5.1 Wiring In — importers

72 non-test source files under `src/tex` import `tex.pqcrypto.*` (the prompt's "85 importers" includes tests). The overwhelming majority import only `algorithm_agility` symbols (`SignatureAlgorithm`, `SignatureProvider`, `get_signature_provider`, `SignatureKeyPair`). Notable live consumers:

- `tex/engine/pdp.py:78` — `from tex.pqcrypto.pq_durability import apply_pq_durability_hold`
- `tex/provenance/ledger.py:33` — `SignatureKeyPair, SignatureProvider`
- `tex/events/ledger.py:49` — `SignatureProvider`
- `tex/api/vet_routes.py:49,406,472`, `tex/api/incident_routes.py:123`, `tex/api/zkprov_routes.py:248` — `SignatureAlgorithm`, `get_signature_provider`
- `tex/c2pa/verifier.py:55`, `tex/c2pa/signer.py`, `tex/c2pa/cosign_verifier.py` — `SignatureAlgorithm`, `get_signature_provider`
- `tex/institutional/_pq_signing.py:60` — selection chain over `get_signature_provider`
- `tex/tee/_mode_probe.py` — imports `_backend_probe`'s `ProbeResult` shape

### 5.2 Live call path (from `build_runtime` / api route)

**Path A — the PDP (decision brain), LIVE:**
```
tex/main.py:69        from tex.engine.pdp import PolicyDecisionPoint
tex/main.py:876       pdp = PolicyDecisionPoint(... decision_ledger=decision_ledger ...)
   (decision_ledger = SealedFactLedger() if seal_decisions else None — main.py:873)
tex/engine/pdp.py:78  from tex.pqcrypto.pq_durability import apply_pq_durability_hold
tex/engine/pdp.py:432 routing_result = apply_pq_durability_hold(
                          base=routing_result, request=request,
                          decision_ledger=self._decision_ledger)
```
This runs inside the PDP's evaluate path on every decision; `apply_pq_durability_hold` is a zero-cost no-op unless `request.metadata["pq_non_repudiation"]` is set (`pq_durability.py:240-244`).

**Path B — api signing routes, LIVE:**
```
tex/api/vet_routes.py:406,472  get_signature_provider(...).sign/verify  (HTTP-reachable)
```

**Path C — evidence seal, LIVE (but currently classical — see §9.1):**
```
tex/main.py:624  evidence_chain_signer = build_evidence_chain_signer(...)
tex/evidence/seal.py:258-261  get_signature_provider(COMPOSITE_ML_DSA_65_ED25519).generate_keypair(...)
```
Note: `tex/evidence/seal.py` reaches `pqcrypto` **only through `algorithm_agility`** — it does *not* import `tex.pqcrypto.evidence_chain_signer` (that reference at `seal.py:5,35` is docstring-only; `seal.py` reimplements the embed-pattern directly).

**Path D — ML-DSA verify in C2PA cosign, LIVE:** `tex/c2pa/verifier.py:55` → `get_signature_provider` → `MlDsaProvider.verify`.

`wired_status = LIVE`.

### 5.3 Wiring Out — dependencies

- **Internal Tex:** `tex.observability.telemetry.emit_event` (every module); `tex.domain.evidence.EvidenceMaturity`, `tex.provenance.ledger.SealedFactLedger`, `tex.provenance.models.SealedFact/SealedFactKind` (pq_durability); `tex.domain.verdict/finding/severity` + `tex.engine.router.RoutingResult` (lazy, in `apply_pq_durability_hold`); `tex.events._canonical.canonical_json` (evidence_chain_signer, evidence_quorum); `tex.events._ecdsa_provider.EcdsaP256Provider` (dispatcher delegation); `tex.voice.voice_gate.NeuralNLIScorer` + `tex.zkprov` (in `_backend_probe`); `tex.ecosystem` preload (evidence_quorum:49).
- **External libs:** `cryptography` (pyca, hard dep — native ML-DSA/ML-KEM/Ed25519/ECDSA); `oqs` (liboqs-python, optional — SLH-DSA/HQC/ML-KEM-512/ML-DSA fallback); `blake3` (optional — BLAKE3-ML-DSA); `pyasn1`/`pyasn1_modules` (composite_cms DER); the vendored Rust `tex_mithril.so` (threshold). The OpenSSL ≥3.5 **CLI** is shelled out to by `pq_durability` only.

---

## 6. Implementation Reality

| Module | Real / Stub | Native path | Pure-python / fallback | Runs by default (this host) |
|--------|-------------|-------------|------------------------|------------------------------|
| `ml_dsa` | **REAL** | pyca native (FIPS 204) **or** liboqs | none — hard `RuntimeError` if neither | **pyca-cryptography-native (DURABLE)** ✓ |
| `ml_kem` | **REAL** | pyca native (768/1024) **or** liboqs (512) | none — `RuntimeError` if unsupported | pyca native for 768/1024; **512 → None** (no liboqs) |
| `hybrid` | **REAL** | via ml_dsa + pyca Ed25519 | n/a | runs |
| `blake3_ml_dsa` | **REAL** | via ml_dsa; needs `blake3` binding | `RuntimeError` if `blake3` absent | runs if `blake3` installed |
| `slh_dsa` | **REAL** | **liboqs only** | `RuntimeError` if liboqs absent | **inert here** (no liboqs) |
| `composite_ml_dsa` | **REAL** | via ml_dsa + pyca Ed25519/ECDSA-P384 | n/a | runs |
| `composite_cms` | **REAL** | `pyasn1` DER codec | n/a | runs |
| `quorum_ml_dsa` | **REAL** | via ml_dsa | n/a | runs |
| `threshold_ml_dsa` | **REAL impl, native-gated** | vendored Rust `.so` (x86_64 Linux) | `RuntimeError` if `.so` unloadable | **inert here** (arm64 macOS; `.so` is x86_64 Linux) |
| `talus_tee` | **REAL harness; native crypto stub** | Mithril-inside-TEE | `NotImplementedError` on `TEX_TALUS_NATIVE_BCC=1` | depends on Mithril |
| `hqc` | **REAL** | **liboqs only** | `RuntimeError` if HQC not built | **inert here** (no liboqs) |
| `code_signing` | **REAL** | via `SlhDsaProvider` (liboqs) | inherits SLH-DSA dep | inert here (no liboqs) |
| `evidence_chain_signer` | **REAL logic, ORPHAN wiring** | via dispatcher | n/a | not wired live |
| `evidence_quorum` | **REAL logic, env-gated** | via quorum | n/a | off unless `TEX_EVIDENCE_QUORUM_K` set |
| `pq_durability` | **REAL** | reads ml_dsa backend id; shells OpenSSL CLI | n/a | runs (DURABLE) |
| `_backend_probe` | **REAL reporter** | delegates to in-tree oracles | n/a | runs; reports availability |
| `lms` | **STUB** | none | all 3 crypto fns raise `NotImplementedError` (`:128,137,147`) | n/a |

**Runtime verification (this host, `PYTHONPATH=src`):**
```
ml_dsa.active_backend_id()    = pyca-cryptography-native
pq_durability.probe_backend() = durable
ml_kem 768 backend            = pyca-cryptography-native
ml_kem 512 backend            = None
find_openssl_mldsa()          = /Users/.../miniforge3/bin/openssl   (real OpenSSL ≥3.5 CLI present)
```

**NotImplementedError inventory (15 — all interface/registry guards or honest deferrals, none hollow):**
- `algorithm_agility.py:181,219` — THRESHOLD redirect + unknown-algorithm guard.
- `ml_kem.py:356` — unknown KEM guard.
- `quorum_ml_dsa.py:585,597,603` — single-key Protocol methods that don't apply to quorum.
- `lms.py:128,137,147` — deferred LMS (3 functions; honest stub pointing to `code_signing`).
- `talus_tee.py:408` — native BCC+CEF path, env-gated.
- `evidence_chain_signer.py:209` — *handles* a dispatcher `NotImplementedError` (not a raise).
These match the spine pass's "pqcrypto=15 guards" count.

---

## 7. Technology / SOTA

- **NIST standards:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA); SP 800-208 (LMS, stubbed). HQC noted as the NIST 4th-round non-lattice KEM (FIPS 207 draft) **(claim, unverified)**.
- **IETF/wire formats:** draft-ietf-cose-dilithium-11 (COSE alg ids -48/-49/-50, `ml_dsa.py:84-92`); RFC 8785 JSON canonicalization (evidence signer); draft-ietf-lamps-pq-composite-sigs-18 binding + OIDs; RFC 5280/5652 DER (composite_cms); RFC 8032 Ed25519; RFC 9334 attestation (talus_tee).
- **Frontier schemes:** BLAKE3-pre-hash ML-DSA (Project Eleven/Taurus); Mithril MPC threshold (ePrint 2026/013) via vendored Rust; TALUS-TEE (arxiv 2603.22109); ML-KEM+HQC hybrid KEM combiner via HKDF-SHA-512 (`hqc.py:304-316`).
- **Design patterns:** Strategy/Protocol (pluggable `SignatureProvider`); lazy import-time backend selection with graceful degradation; fail-closed allow-list (durability); non-separable composite/hybrid (both-halves-must-verify); sign-then-verify fault guard; length-prefixed self-describing wire layouts with version constants.
- **Cryptographic hygiene observed in code:** private keys held as 32-byte seeds, never serialized expanded across the API (`ml_dsa.py:26-30` doc + `from_seed_bytes` usage); descriptor commitments re-derived on verify; implicit-rejection KEM semantics flagged to callers.

---

## 8. Persistence

The unit is almost entirely **in-memory / stateless** — providers hold no mutable per-call state. Durable state surfaces:

- **Evidence seal private key** — `var/tex/keys/evidence_seal_key.json` (written by `tex/evidence/seal.py`, outside this package but driven by it). Persisted on first use; **confirmed present** with `algorithm: ecdsa-p256`, `key_id: evidence-seal-key-v2`. This is the "stale key" surface (§9.1).
- **Sealed PQ-durable facts** — `apply_pq_durability_hold` appends to a `SealedFactLedger` (durability of that ledger is owned by `tex.provenance`, not here).
- **Vendored native artifact** — `vendor/mithril/tex_mithril.so` (13.7 MB, x86_64 Linux), loaded at runtime by `threshold_ml_dsa`.
- **Telemetry** — every operation emits `pqcrypto.*` events via `emit_event`; durability of those is the observability layer's concern.

No databases, caches, or queues are owned by `pqcrypto`.

---

## 9. Notable Findings

### 9.1 The "stale key" concern — CONFIRMED REAL on this checkout (highest-priority finding)

The live evidence-chain seal is **classical ECDSA-P256, not post-quantum**, despite a durable ML-DSA backend being present:

- `build_evidence_chain_signer` (`tex/evidence/seal.py:225-298`) prefers `COMPOSITE_ML_DSA_65_ED25519` (`:91`) but **`_load_key` short-circuits** on any persisted key (`:243-256`) *before* the preferred-algorithm loop runs.
- The persisted key `var/tex/keys/evidence_seal_key.json` has `algorithm: ecdsa-p256`. So the live seal uses ECDSA-P256, `is_post_quantum=False`, and `seal.py:249-255` logs a downgrade warning every boot.
- The code is **honest** about it (the `pq_signature.algorithm` field reads `ecdsa-p256`, never the PQ label — `seal.py:33-40`), but the headline "evidence chain is post-quantum signed" is **not currently true at runtime**. To activate the composite seal: delete the stale key file (the wiring then upgrades with no code change).
- This is fully consistent with `pq_durability.py:51-60`'s own "capability-vs-use" disclaimer: a DURABLE *probe* asserts backend availability, **not** that the bytes sealed on a decision are PQ. The live `SealedFactLedger` primary signer is also ECDSA-P256 (`provenance/ledger.py:32` `default_signature_provider`), with PQ dual-signing only when a `pq_signing_provider` is injected.

**Net:** the PQ *capability* is real and durable; the PQ *seal-in-use* is gated behind a stale on-disk key. The memory-note concern ("PQ stale key") is accurate.

### 9.2 Two modules have real logic but **no live wiring (effective orphans)**

- `evidence_chain_signer.py` — referenced only in docstrings of `evidence/seal.py`; the actual seal reimplements the pattern. Live importers: **none** (tests only). The dossier-relevant detail: the production seal path bypassed it.
- `evidence_quorum.py` — **no importer at all** outside the package, even in non-test src. Quorum signing of evidence is off unless `TEX_EVIDENCE_QUORUM_K` is set, and nothing wires it into the recorder. It is forward-looking glue, not a live path.

### 9.3 Exotic provider modules are reachable only via the dispatcher, and several need absent native libs

`blake3_ml_dsa`, `slh_dsa`, `composite_ml_dsa`, `quorum_ml_dsa`, `hqc`, `code_signing`, `threshold_ml_dsa`, `talus_tee`, `composite_cms` have **zero direct external importers** (grep §5). They are exercised only through `get_signature_provider` (for the ones in the dispatch table) or by tests. On this host, the liboqs-only ones (`slh_dsa`, `hqc`, `code_signing`) and the x86_64-Linux Mithril `.so` (`threshold_ml_dsa`, and thus `talus_tee`) are **inert** — they raise loud `RuntimeError`/return `is_native_available()=False` rather than degrade. This is correct fail-closed behavior, not a bug, but it means the "ships SLH-DSA/HQC/threshold in the live path" framing in their docstrings is **(claim, unverified)** for this environment.

### 9.4 `lms.py` is a documented stub, not a regression

All three crypto functions raise `NotImplementedError` with a redirect to `code_signing` (`:128,137,147`). The docstring is explicit that SLH-DSA is the production code-signing primitive and LMS is deferred until a buyer requests it. Honest.

### 9.5 `_backend_probe.py` is a genuine reporter with zero verdict-path consumers — by design

`:18-19`: "No probe here has ANY consumer on the verdict path." Verified: no live code consumes `probe_ezkl_halo2/probe_ml_dsa_backend/probe_torch_nli`; only `tee/_mode_probe.py` reuses the `ProbeResult` *shape*. The ML-DSA probe purely delegates to `pq_durability.probe_backend` (`:257`). This is the "nanozk lesson" defense and it holds.

### 9.6 Docstring frontier/competitor claims are marketing, not verifiable in code

Modules repeatedly assert "no shipping AI governance product implements this" / "Tex is first" / specific competitor names (Microsoft Agent Governance Toolkit, Asqav) and dated academic citations. These are **(claim, unverified)** — they are documentation, not code behavior, and should not be read as audit-grade facts.

### 9.7 Minor surprises (not defects)

- `ThresholdMlDsaProvider` is an **alias** for `QuorumMlDsaProvider` (`quorum_ml_dsa.py:611`), while the *genuine* threshold scheme lives in `threshold_ml_dsa.py` (Mithril). The naming is intentional but a known footgun — the docstrings call it out at length.
- `ml_kem.py:126` carries a leftover `# check` comment in `decapsulate` backend code (`_NativeKemBackend.decapsulate`); harmless but a code-smell artifact.
- `hqc.py` places `import hmac`/`import hashlib`/`from tex.pqcrypto.ml_kem import ...` mid-file (`:279-282`) rather than at top — works, but unusual.
- The `pq_durability` OpenSSL-CLI round-trip is real crypto but **only ever exercised by its own benchmark/tests**; it is deliberately not on any live path and does not influence maturity.
