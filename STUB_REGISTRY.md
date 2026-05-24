# STUB_REGISTRY

Every unfinished site in `src/tex/`. Three categories:

- **NotImplementedError sites:** raises on call.
- **P0 TODOs:** code may run, but the comment marks a load-bearing gap.
- **P1 TODOs:** tracked but lower urgency.

**The column that matters:** **`Blocks current claim?`** This is the only triage criterion. If yes, prioritize. If no, the stub can sit indefinitely.

Current active claims (from CLAIMS_CURRENT.md + active GTM):

- **GTM-A:** VP Marketing / Head of Brand at AI-SDR-using SaaS (Series B/C/D) — needs brand-safety dossier + AI Act Article 50 + NY disclosure + CA SB 942.
- **GTM-B:** Evidence on demand for cyber insurance AI riders — needs cyber rider packet + signed audit chain + C2PA manifests.
- **Differentiation:** "Evidence-grade adjudication" — needs working C2PA signer, ML-DSA hybrid signatures, signed evidence bundles.
- **Regulatory positioning:** EU AI Act Aug 2026 — needs Articles 17, 26, 50.

---

## May 2026 frontier upgrade — status update

This section reflects the May 18, 2026 frontier work landed in this revision. **All items below moved from "blocks current claim" to "wired"** during the upgrade. See `CLAIMS_CURRENT.md` §3–§9 for the new claim language.

| stub | claim it was blocking | resolution |
|---|---|---|
| `c2pa/signer.py` OCSP staple + TSA token | C2PA differentiation | **WIRED** — `ocsp_staples_der=`, `tsa_tokens_der=` kwargs; placed under canonical C2PA 2.4 §14 unprotected-header labels. |
| `c2pa/verifier.py` OCSP + TSA validation | Same | **WIRED** — `require_ocsp_staple=`, `require_timestamp=` kwargs; surfaces C2PA 2.4 §15.8/§15.9 failure codes verbatim. |
| `c2pa/ocsp.py` (new) | RFC 6960 + RFC 9277 stapling | **WIRED** — request build, parse, authority delegation per RFC 6960 §4.2.2. |
| `c2pa/timestamp.py` (new) | C2PA 2.4 §10.3.2.5 v2 TSA | **WIRED** — RFC 3161 with v2 messageImprint = SHA-256(signature field). |
| `c2pa/sherman_2026_defenses.py` (new) | Sherman 2026 (arxiv 2604.24890) | **WIRED** — six-class attack matrix + JSON dossier exporter + audit-pipeline regression guard. |
| `c2pa/durable_credentials.py` | TrustMark + EU CoP §Watermark-2 | **WIRED** — three-layer durable marking; TrustMark embed when available, fingerprint always. |
| `pqcrypto/ml_dsa.py` (full rewrite) | Native PQ signing | **WIRED** — pyca/cryptography 48 native (OpenSSL 3.5+), liboqs fallback. |
| `pqcrypto/ml_kem.py` (full rewrite) | Native PQ KEM | **WIRED** — pyca native (768/1024), liboqs (512). |
| `pqcrypto/composite_ml_dsa.py` | draft-18 alignment | **WIRED** — `CompositeAlgorithmSignatures2025` prefix, real labels, IANA OIDs `1.3.6.1.5.5.7.6.48`/`.49`, draft-18 §2.1 M' construction. |
| `pqcrypto/hybrid.py` (3 stale P0 TODOs) | Hybrid composite signing | **WIRED** — concat layout; TODO markers removed (code was already complete). |
| `pqcrypto/evidence_chain_signer.py` (6 stale P0 TODOs) | Evidence chain signing | **WIRED** — same; TODO markers removed. |
| `pqcrypto/code_signing.py` | LMS / PQ code signing | **WIRED** — SLH-DSA (FIPS 205, CNSA 2.0 §2) replaces the NotImplementedError stub. LMS scaffolded separately at `pqcrypto/lms.py`. |
| `compliance/eu_ai_act/article_50.py` (2 stale P0 TODOs) | EU AI Act Article 50 | **WIRED** — TODO markers replaced with wiring notes. |
| `compliance/eu_ai_act/article_17.py` (NIE) | QMS | **WIRED** — full 11-component packet + corrective-action log + post-market monitoring window. |
| `compliance/eu_ai_act/article_26.py` (NIE) | Deployer obligations | **WIRED** — §26(2)/(3)/(5)/(6)/(11) constraints enforced fail-closed. |
| `compliance/state/california_sb942.py` (1 stale P0 TODO) | CA SB 942 | **WIRED** — TODO marker replaced with wiring notes. |
| `compliance/state/new_york_ai_disclosure.py` (NIE) | NY §1700-A | **WIRED** — placement-presumption guardrails. |
| `compliance/state/colorado_ai_act.py` (NIE) | Colorado SB 24-205 | **WIRED** — 8 consequential-decision categories. |
| `compliance/ftc/policy_statement.py` (1 stale P0 TODO) | FTC §5 | **WIRED** — TODO marker replaced with wiring notes. |
| `events/crypto_provenance.py` (4 stale P0 TODOs) | Crypto provenance | **WIRED** — TODO markers replaced with wiring notes. |
| `c2pa/manifest.py` (2 stale P0 TODOs) | CAWG 1.2 + email manifest | **WIRED** — TODO markers replaced with wiring notes. |

Test count moved from 421 passing / 26 skipped at session start → **490+ passing / 28 skipped** at the end of the May 2026 frontier upgrade.

---

## Remaining stubs

These are P1/P2 items not blocking any current claim.

### NotImplementedError sites — intentional adapter hooks

| file | NIE count | reason it stays |
|---|---|---|
| `c2pa/watermark.py` (SynthIDTextDetectorAdapter, TextSealDetectorAdapter) | 2 | Production adapter hooks for `transformers` / `textseal`. Tex's path is `RecordedScoreDetector` — production deployments override these adapters when wiring direct in-process detection. |
| `compliance/nist/ai_rmf.py`, `nist/agent_standards.py` | 2 | US enterprise procurement track — not current GTM. |
| `compliance/state/california_ab853_capture.py`, `california_ab853_platforms.py` | 2 | AB 853 obligations come into force 2027 / 2028. |
| `compliance/naic/cyber_rider.py` | 1 | NAIC pivoted off current GTM-B (Matthew's GTM is now Option B — VP Marketing at AI-SDR SaaS, not insurance directly). Restore if returning to insurance. |
| `pqcrypto/lms.py` (`generate_keypair`, `sign_with_lms`, `verify_with_lms`) | 3 | LMS implementation deferred behind SLH-DSA per the recommendation in the module docstring. The deferred functions raise with a clear pointer to `code_signing`. |
| `discovery/connectors/_base.py`, `enforcement/_base.py`, `causal/_base.py`, `systemic/_base.py`, `evidence/_base.py`, `institutional/_base.py`, `ecosystem/_base.py` | 7 | Abstract bases — NIE is intentional. |
| `events/quorum_shard.py` | 1 | Future-proofing. |
| `interop/microsoft/`, `interop/okta/`, `interop/ping/`, `interop/nist/`, `interop/a2a/` | 7 total | Not current GTM. Moved to `_pending/` in the next maintenance pass. |

### P1 TODOs

P1 tracking is in code only; run `python scripts/audit.py --list-p1` to enumerate.

Notable P1 items kept on the live tree:

- `c2pa/manifest.py` — TODO(spec-verify) digitalSourceType cross-check against C2PA 2.4 actions schema once the schema lands in scope.
- `compliance/eu_ai_act/article_50.py` — TODO(spec-track) pin against the FINAL Code of Practice when it publishes in June 2026.
- `compliance/state/california_sb942.py` — TODO(AB-853-2027) + TODO(AB-853-2028) for the next two phases of AB 853 obligations.
- `compliance/ftc/policy_statement.py` — TODO(P1) wire `supporting_evidence_digests` to the Thread 6 ingredient chain.
- `events/crypto_provenance.py` — P1 cleanup of I-JSON number serialization in `_canonical.py`.

### Pitch route wiring (one-day task, not a stub)

`pitch/vp_marketing.py`, `pitch/ciso.py`, `pitch/insurer_export.py` — the underlying functions produce real signed artifacts. The HTTP routes (`/v1/exports/vp-marketing`, `/v1/exports/ciso`, `/v1/exports/insurer`) are not yet exposed. This is a wiring task, not an implementation gap.

---

## Tier D directories — recommended dispositions

| directory | files | recommended action |
|---|---|---|
| `src/tex/interop/microsoft/` | 1 NIE | move to `src/tex/_pending/interop/microsoft/` or delete |
| `src/tex/interop/okta/` | 1 NIE | same |
| `src/tex/interop/ping/` | 1 NIE | same |
| `src/tex/interop/nist/` | 1 NIE | same |
| `src/tex/interop/a2a/` | 2 NIE | same |

Mechanical move with import-path updates. Done in the next maintenance pass.

---

## Maintenance

When you finish a stub:

1. Move its row from "Remaining stubs" → "May 2026 frontier upgrade" or delete it.
2. Update CLAIMS_CURRENT.md with the new claim language.
3. Run `python -m pytest tests/` to confirm no regression.
4. Run `python scripts/audit.py --rebuild-data` to refresh counts.
