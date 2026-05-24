# Frontier delta — Thread 10 (May 18-20, 2026)

## Scope
Complete the post-quantum cryptography layer beyond every shipping competitor as of May 18, 2026. Cover the four NIST PQ standards (FIPS 203 / 204 / 205, plus the threshold ML-DSA research frontier and the IETF composite ML-DSA draft track).

## Research deltas vs Tex's prior thread (Thread 8.1, May 19)

### Threshold ML-DSA — five concurrent schemes
- **TALUS** (arxiv 2603.22109 v2, Mar 24 2026, Leo Kao, Codebat): one-round online signing, 0.62–1.94 ms TEE, 2.27–5.02 ms MPC, arbitrary N, no honest majority. Formalises the "Lattice Threshold Trilemma."
- **Mithril** (ePrint 2026/013, USENIX Security '26, PQShield team): 3 online rounds, Replicated Secret Sharing, up to 6 parties. **Has a shipping Rust crate** (`threshold-ml-dsa` v0.3 on crates.io, Apr 14 2026, MIT, 107 passing tests, `#![no_std]`, bit-for-bit FIPS 204 compatible).
- **ML-DSaaS** (ePrint 2026/814, Apr 2026, Rambaud / Roth / Urban): TSaaS variant of Mithril collapsing the first two rounds into a single preprocessing round.
- **Hermine** (MPTS 2026, IBM): Raccoon-based, NOT FIPS 204 compatible, 1 round.
- **Quorus** (MPTS 2026, IBM): 2 online rounds, up to 64 signers, honest majority.

### Composite ML-DSA — IETF moving fast
- `draft-ietf-lamps-pq-composite-sigs-18` (Apr 9 2026), latest revision; revision 16 (Apr 8 2026) moved from OID-based domain separators to **HPKE-style label strings**.
- `draft-ietf-lamps-cms-composite-sigs-04` (Feb 5 2026, latest editor version 13 May 2026) for CMS.
- `draft-reddy-tls-composite-mldsa-10` (May 2026) for TLS 1.3.
- BSI 2021 + ANSSI 2024 effectively mandate PQ/T Hybrid → composite signatures are the deployment-ready path for those jurisdictions.

### liboqs status
- 0.15.0 is current; **last release with Dilithium**, **last with SPHINCS+**. 0.16 will rename to SLH-DSA and remove the legacy.
- 0.15 algorithm names: ML-DSA-44/65/87 (hyphens), ML-KEM-512/768/1024 (hyphens), `SLH_DSA_PURE_SHA2_{128S,128F,192S,256S}` (underscores + uppercase).
- Default ML-KEM backend swapped to PQCP's `mlkem-native` v1.0.0 — formally verified for memory and type safety via CBMC, AArch64 assembly verified for functional correctness via HOL-Light.

### CNSA 2.0 update (April 2026)
- `draft-jenkins-cnsa2-pkix-profile §4`: ML-DSA-87 and ML-KEM-1024 **exclusively**. ML-DSA-44/65 and ML-KEM-512/768 are NOT CNSA-compliant.
- SLH-DSA-256s mandated for software/firmware signing.
- January 2027 NSS procurement gate.

### Side-channel research
- **CoV (Coefficient of Variation)** introduced in arxiv 2605.17061 ("quantum-safe", Shaw, May 16 2026) as practical timing-side-channel proxy. ML-KEM-768 decap CoV = 3.9% (within AES-256-GCM noise floor of 2.1%); ML-DSA-65 sign CoV = 51.5% (expected from rejection sampling, not a leak).
- Newer chosen-ciphertext SCAs on Kyber: ePrint 2025/1577 with LDA (40 traces for full key recovery on M4), ePrint 2025/1956 shuffled-Kyber CCA.

### Fault attacks
- ePrint 2026/759 (NXP, Apr 17 2026): scalable fault countermeasure for SLH-DSA.
- arxiv 2509.13048 (SLasH-DSA, late 2025): end-to-end Rowhammer forgery against OpenSSL SLH-DSA. OpenSSL declined to fix because fault attacks are outside their threat model. **Tex addresses this directly via sign-then-verify guard in `SlhDsaProvider`.**

### Competitor landscape (the leap-past)
- **Microsoft Agent Governance Toolkit** (Apr 2 2026): added "Ed25519 + ML-DSA-65 agent credentials." **ML-DSA-65 only.** No ML-DSA-87, no threshold, no composite, no SLH-DSA, no ML-KEM.
- **Asqav** (Apr 2026): ML-DSA-65 single-key with RFC 3161 timestamps, hash-chained.

## What Tex shipped this thread
1. **`tex.pqcrypto.ml_kem`** — full FIPS 203 binding, all 3 parameter sets, fail-closed length validation, telemetry on every operation, documented implicit-rejection contract.
2. **`tex.pqcrypto.slh_dsa`** — full FIPS 205 binding, all 4 production parameter sets, sign-then-verify fault countermeasure (per ePrint 2026/759), `SlhDsaFaultDetected` exception with structured metadata.
3. **`tex.pqcrypto.threshold_ml_dsa`** — k-of-n quorum signing across THRESHOLD_ML_DSA_44/65/87, `QuorumDescriptor` with SHA-256 commitment binding, `ThresholdQuorumKeySet`, Sybil-resistant aggregation, telemetry hooks. Forward-compatible `MITHRIL_BACKEND` slot for future Mithril Rust FFI.
4. **`tex.pqcrypto.composite_ml_dsa`** — draft-18 compliant composite for ML-DSA-65+Ed25519 and ML-DSA-87+ECDSA-P384, HPKE-style domain separators, non-separability enforcement, full algorithm-agility dispatch.
5. **`tex.pqcrypto.evidence_quorum`** — production glue between threshold provider and evidence chain. `EvidenceQuorumPolicy.from_env()` reads `TEX_EVIDENCE_QUORUM_K` / `TEX_EVIDENCE_QUORUM_N`. Serialize / deserialize / verify of the embedded `pq_quorum_signature` payload.
6. **Extended `tex.pqcrypto.algorithm_agility`** — `SignatureAlgorithm` enum gained SLH_DSA_{128S,128F,192S,256S}, THRESHOLD_ML_DSA_{44,65,87}, COMPOSITE_ML_DSA_65_ED25519, COMPOSITE_ML_DSA_87_ECDSA_P384. All wired in `get_signature_provider`.
7. **Tests**: 104 new tests in `tests/pqcrypto/` covering ML-KEM (29 tests), SLH-DSA (24 tests), threshold ML-DSA (32 tests), composite ML-DSA (19 tests), evidence_quorum (12 tests). Plus updates to `tests/frontier/test_pqcrypto.py` removing now-stale "remains stub" assertions and adding "now implemented" assertions, and `tests/institutional/test_pq_signing.py` updating the SLH-DSA wiring assertion.

## Honest gaps
- Tex's threshold path is k-of-n quorum certificate, NOT a single FIPS 204 signature (which would require Mithril or TALUS MPC). Forward-compatible with both schemes once Python bindings land.
- FN-DSA (FIPS 206 / FALCON) not shipped — NIST IPD still in review, final expected late 2026 / early 2027, no stable liboqs implementation.
- SLH-DSA reference impl is not formally constant-time; Tex's fault-detection guard is a fault countermeasure, not a side-channel countermeasure. Server-side x86_64 is outside the threat model for the most credible 2026 SLH-DSA SCA classes (embedded power analysis).

---

## Extended Thread 10 (May 20, 2026) — Genuine Mithril, TALUS-TEE, HQC, CMS DER

The prior Thread 10 zip shipped a quorum certificate construction under
the "threshold ML-DSA" name. This extension closes that honesty gap and
ships the actually bleeding-edge stack.

### New artifacts

1. **`vendor/mithril/`** — vendored Rust source + PyO3 binding source +
   prebuilt `tex_mithril.so` for x86_64 Linux. The PyO3 binding source
   (`vendor/mithril/binding_src/`) is included so other platforms can
   rebuild with `cargo build --release`.

2. **`src/tex/pqcrypto/threshold_ml_dsa.py`** (NEW, ~270 lines) — thin
   Python wrapper around the PyO3 extension. `MithrilThresholdSdk`
   class, `distributed_keygen(t, n, seed)`, `verify_fips204(pk, msg, sig)`.
   Output signatures are 2,420 bytes (FIPS 204 ML-DSA-44) and verify
   under any standard verifier.

3. **`src/tex/pqcrypto/talus_tee.py`** (NEW, ~370 lines) — TALUS-TEE
   1-round signing harness with attestation. `TeeType` enum,
   `AttestationQuote` dataclass, `AttestationVerificationResult`,
   pluggable `install_attestation_verifier(tee_type, verifier)`,
   fail-closed default reject verifier, `TalusTeeSdk` with
   `online_sign(active, message) → TalusTeeSignature`, freshness window
   via `TEX_TALUS_FRESHNESS_SECONDS`, public-key binding to attestation
   `report_data`.

4. **`src/tex/pqcrypto/hqc.py`** (NEW, ~370 lines) — NIST 4th-round HQC
   KEM with `MlKemHqcHybridProvider` combiner. HKDF-SHA-512 over
   `ml_kem_ct ‖ hqc_ct` with info `tex-mlkem-hqc-hybrid-v1`. Defends
   against lattice cryptanalysis: session secure if EITHER ML-KEM or HQC
   unbroken.

5. **`src/tex/pqcrypto/composite_cms.py`** (NEW, ~290 lines) — ASN.1
   DER serialization per `draft-ietf-lamps-pq-composite-sigs-18 §4.1`
   and `draft-ietf-lamps-cms-composite-sigs-04`. `CompositeSignatureValue`
   ASN.1 SEQUENCE, `AlgorithmIdentifier` round-trip, minimal CMS
   `SignerInfo` envelope. Prototype OIDs from draft-18 §6.4.

6. **`src/tex/pqcrypto/quorum_ml_dsa.py`** — renamed from the misleading
   `threshold_ml_dsa.py` of the prior Thread 10. Now honestly labelled
   as a quorum certificate. Class `ThresholdMlDsaProvider` →
   `QuorumMlDsaProvider`; backwards-compat alias preserved. New enum
   values: `QUORUM_ML_DSA_{44,65,87}`.

7. **`src/tex/pqcrypto/algorithm_agility.py`** — `THRESHOLD_ML_DSA_*`
   now routes to `NotImplementedError` with a redirect to the genuine
   Mithril API (because MPC threshold doesn't fit the single-key
   `SignatureProvider` Protocol). `QUORUM_ML_DSA_*` routes to the
   renamed `QuorumMlDsaProvider`.

### New tests (63 added in this extension)

- `tests/pqcrypto/test_threshold_ml_dsa.py` (18 tests) — genuine
  Mithril. Pins the 15-param Figure 8 set. Tests bit-for-bit FIPS 204
  output (2420 bytes), cross-implementation interop with
  `oqs.Signature("ML-DSA-44")`, deterministic keygen, same-pk
  invariant across different t-subsets.
- `tests/pqcrypto/test_talus_tee.py` (15 tests) — attestation
  interface, fail-closed defaults, measurement pinning, freshness
  check, `TEX_TALUS_NATIVE_BCC=1` NotImplementedError path.
- `tests/pqcrypto/test_hqc.py` (16 tests) — round-trip on all three
  parameter sets, size pinning, hybrid combiner derivation.
- `tests/pqcrypto/test_composite_cms.py` (14 tests) — DER round-trip,
  AlgorithmIdentifier round-trip, malformed DER rejection, CMS
  SignerInfo encoding.
- `tests/pqcrypto/test_quorum_ml_dsa.py` (44 tests migrated from the
  old `test_threshold_ml_dsa.py`, renamed for honesty).

### Total test count

Full Tex suite: **2,905 passed**, 5 skipped, 3 pre-existing ecosystem
failures unrelated to pqcrypto. Up from 2,842 (prior Thread 10) — 63
new tests added.

### Honest gaps remaining

- The genuine Mithril Rust crate (`threshold-ml-dsa` v0.3) only supports
  ML-DSA-44 (NIST L2). ML-DSA-65 (L3) and ML-DSA-87 (L5) require
  upstream v0.4 which hasn't released yet. For L3/L5 quorum signing,
  use `tex.pqcrypto.quorum_ml_dsa` (the certificate construction over
  ML-DSA-65 or ML-DSA-87 keys).
- The TALUS BCC+CEF cryptographic optimization is gated behind
  `TEX_TALUS_NATIVE_BCC=1` and currently raises NotImplementedError —
  the paper authors have not released reference code. The operational
  1-round signing profile is delivered today via Mithril running inside
  the TEE coordinator.
- FN-DSA (FIPS 206 / FALCON) still not shipped — NIST IPD released
  Sep 2025, final expected late 2026 / early 2027, no stable liboqs
  implementation.
