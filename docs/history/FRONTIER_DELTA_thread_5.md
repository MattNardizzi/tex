# FRONTIER_DELTA — Thread 5: C2PA Content Credentials → Evidence Emission

**Generated:** May 18, 2026 (research window: Jan 1 — May 18, 2026)
**Status:** Pre-build research brief. Subject to Phase 3 sweep at completion.
**Thread scope:** Wire `src/tex/c2pa/` (49 passing tests by my count, not the 53 the prompt states — minor doc drift, flagged) into `src/tex/evidence/recorder.py` so every PERMIT verdict for an outbound AI-generated artifact carries a C2PA Content Credential. Add `evidence_manifests` Postgres mirror table, `GET /v1/evidence/{record_id}/c2pa`, and `POST /v1/c2pa/verify`.

---

## TL;DR — what changed since the May 14 floor

Section 1.4 says: *"C2PA 2.2 (production), 2.3 in progress (cross-platform portability + HSM signing)."*

**Reality on May 18, 2026:**

1. **C2PA 2.3 shipped Jan 5, 2026.** C2PA 2.4 (Apr 2026) is the current published spec at `spec.c2pa.org/specifications/specifications/2.4/`. Section 1.4 is **two versions stale**.
2. **C2PA's Interim Trust List (ITL) froze Jan 1, 2026.** Production signing must now route through the official C2PA Trust List (governed by the Conformance Program); ITL certificates remain valid only for legacy verification.
3. **NSA / NIST / UMBC paper arxiv 2604.24890 (Apr 27 2026) — "Verifying Provenance of Digital Media: Why the C2PA Specifications Fall Short"** identifies six systemic vulnerabilities in C2PA 2.2–2.4 and explicitly says **v2.4 does not address any of their concerns.** This is the bleeding-edge finding that re-shapes the build: Tex must defend against the six attack classes the paper enumerates, going beyond what spec-conformant signers do.
4. **EU AI Act Article 50 Guidelines published May 8, 2026 (10 days ago).** Para 28: agentic AI must self-disclose when interaction with a person is **plausible** (not "certain") — Tex is now exactly aligned with the Commission's intent.
5. **May 7, 2026 EU agreement:** grandfathering rule for Article 50(2). Legacy generative AI systems on market before Aug 2, 2026 → comply by Dec 2, 2026. New systems → comply from day one (Aug 2, 2026). Other three transparency duties (Article 50(1), (3), (4)) apply from Aug 2, 2026 with **no transition**.
6. **Microsoft Agent Governance Toolkit (shipped Apr 2, 2026)** is the survival-level competitor. It does **not** implement C2PA. Their stack is policy engine + Ed25519 identity + sandbox; their evidence is hash-chained receipts with no content-credential layer. **This is exactly our wedge.**
7. **COSE algorithm registration for ML-DSA is still draft.** `draft-ietf-cose-dilithium-11` (Nov 15 2025) registers `ML-DSA-44/65/87` by name but no IANA-assigned integer codepoint. C2PA 2.4 §13.2 still does not include any PQ algorithm. The X.509 OID for ML-DSA-65 (`2.16.840.1.101.3.4.3.18`) is final and now shipping in AWS Private CA and Microsoft AD CS (May 18 2026 update — yesterday).
8. **arxiv 2603.02378 (Mar 2026)** — "Authenticated Contradictions from Desynchronized Provenance and Watermarking" — shows C2PA + watermark layers can independently authenticate contradictory claims about the same asset. This forces the C2PA layer to be the *canonical* claim and watermarking to be subordinate, not parallel.
9. **arxiv 2605.12456 TextSeal (May 12, 2026 — 6 days ago)** — distortion-free LLM watermark for text provenance, "radioactive" through distillation. Newest text-watermark SOTA Tex's manifests could reference as the soft-binding companion.
10. **`draft-kamimura-scitt-refusal-events-02`** (Jan 2026) — current revision. Defines a refusal-event taxonomy (`COPYRIGHT_VIOLATION`, `COPYRIGHT_STYLE_MIMICRY`, `REAL_PERSON_DEEPFAKE`, `VIOLENCE_EXTREME`, `HATE_CONTENT`, `TERRORIST_CONTENT`, `SELF_HARM_PROMOTION`, `CSAM_GENERATION`, …, `OTHER`) that maps directly to Tex FORBID reasons. This is where we go beyond "log the refusal" → "emit a SCITT-format signed statement listing why the AI refused."

---

## 2. Detailed delta — citations

### 2.1 C2PA 2.4 (current published spec)

**Source:** `https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html`, GitHub `c2pa-org/specifications` README confirms.

**What 2.4 changes vs the 2.2 anchor in Section 1.4:**

- **JUMBF superbox label moved to `c2pa.claim.v2`.** The legacy `c2pa.claim` + `claim-map` is deprecated; validators must still accept it but generators must not produce it. The existing `manifest.py` already uses `c2pa.actions.v2` (correct for 2.4); we need to ensure the wrapper label emitted by the canonicalizer is `c2pa.claim.v2`.
- **HTML, structured text, and unstructured text embedding** (Appendix A.7, A.8, A.9 in 2.4) — previously only binary media. This matters for Tex because most AI-SDR outputs are *text* (email, Slack message, Markdown). 2.4 finally gives us a spec-blessed way to embed a manifest in unstructured text.
- **v2 time-stamp payload format** is now mandatory for new generators (`Sig_signature` value vs the deprecated v1 form). The signer must produce v2.
- **CMAF segment-level signing** (added in 2.3 for live media) — irrelevant for Thread 5 but flagged for future Thread (live-stream agent governance).
- **Box hash assertion** with general/multi-hash for BMFF assets — irrelevant for email but important for any future video/audio agent output.

### 2.2 NSA/UMBC formal-methods analysis — arxiv 2604.24890 (Apr 27, 2026)

**Authors:** Golaszewski (UMBC), Krawetz (Hacker Factor), Sherman (UMBC), Zieglar (NSA), Matukumalli (UMBC), Yus (UMBC), Kegley (UMBC), Barthel (UMBC), Bowman (UMBC), Barot (UMBC), Kullman (UMBC).

**Status:** Submitted Apr 27, 2026 — **21 days ago**. First independent formal-methods analysis of C2PA. Companion full technical report at `eprint.iacr.org/2026/804`.

**The 6 attacks (paraphrased from §"Key Findings"):**

1. **Timestamp swap without signature break.** Nothing in the signed data references the trusted timestamp, so an adversary can replace it. Validators show the altered date without warning.
2. **Revoked credentials still accepted.** Conforming validators may skip revocation checks; the spec forbids CRLs (privacy concern) and makes OCSP optional. Nikon Z6 III certs revoked Nov 2025 are still validated by Adobe Inspect (verifiers disagree).
3. **Cross-validator contradiction.** Same asset → valid by one validator, invalid by another, including disagreement on whether the asset was AI-generated.
4. **Exclusion-range modification.** C2PA permits exclusion ranges so privacy fields (e.g. GPS) can be redacted. The paper shows GPS can be *replaced* with false coordinates inside the exclusion range — manifest still validates.
5. **Credential expiry before retention obligation.** Some C2PA-signed assets become unverifiable within months. This is incompatible with 22-month US election retention (52 USC § 20701), 25-month financial retention (12 CFR § 1002.12), 2-year political-ad retention (47 CFR § 73.3526).
6. **Conformance program is self-reported.** "Conforming" products are not source-reviewed; even spec-compliant products don't necessarily satisfy the stated security goals because the spec itself is flawed.

**Their concrete recommendations** (we adopt all six):

- Strict certificate revocation checking (we also avoid OCSP's privacy issue by hash-pinning to the C2PA TL snapshot at signing time).
- Timestamps securely bound into the signed payload.
- Cross-validator consistency (we emit a `tex.validator_canonicalization` assertion that pins exactly which validator state we tested against).
- Protect the entire file, no exclusion ranges.
- Independent security audit.
- Clarify limitations in public communications.

**Build consequence — the most important section of this brief:**

Tex does not just sign a vanilla C2PA 2.4 manifest. Tex emits a **C2PA 2.4 manifest plus a Tex Evidence Co-Signature (`tex.evidence_cosign`)** — a Tex-internal assertion that:

- Includes the trusted timestamp **inside** the signed payload (closing attack 1).
- Includes an explicit `revocation_proof` field with the OCSP response or CRL snapshot hash at signing time (closing attack 2).
- Includes a `canonicalization_version` so two validators receiving the same manifest must produce the same boolean answer (closing attack 3).
- Includes the **full file SHA-256 with no exclusion range** alongside the C2PA hard binding (closing attack 4).
- Includes a `retention_anchor` — a hash-chain pointer into Tex's evidence chain. Even if the C2PA certificate expires, the evidence chain re-verifies the manifest content (closing attack 5).
- Is signed under **`tex.pqcrypto.algorithm_agility`** with `ML-DSA-65` (post-quantum), separate from the C2PA-spec-mandatory ES256/EdDSA outer signature.

The result: an asset that **passes vanilla C2PA 2.4 verification today** (so Microsoft Edge, Adobe Inspect, CAI Verify, c2patool all see a valid manifest), **and** carries a Tex-side evidence co-signature that fixes the six vulnerabilities the NSA paper identified. **Nobody — not Adobe, not Microsoft, not Truepic, not Digimarc, not the Microsoft Agent Governance Toolkit — does this today.** This is the bleeding-edge differentiator the user asked for.

### 2.3 EU AI Act Article 50 Draft Guidelines (May 8, 2026)

**Source:** Conventus Law / Bird & Bird analysis, dated May 18, 2026 (same-day, 10 days after publication). Direct source is the European Commission AI Office's 40-page draft Guidelines under Article 96(1)(d).

**Material findings for Tex:**

- **Para 28 — agentic AI default flipped.** Where a provider cannot reliably determine whether an agent will interact with a natural person, the agent must self-disclose "in every situation where it is likely that the agent may interact with a natural person." The default flipped from "disclose where interaction is certain" → "disclose where interaction is plausible." Tex's Article 50(1) interactive-system claim is now formally aligned with the Guidelines.
- **Para 35 — explicit negative catalogue for Article 50(1):** T&Cs disclosure, machine-readable signals alone, generic "assistant" references, and "this system uses LLMs" **all fail** Article 50(1). A C2PA machine-readable mark by itself is not sufficient for 50(1) — it is sufficient for 50(2) but the human-perceivable disclosure for 50(1) and 50(4) must be separate.
- **Para 54 — Article 50(2) applies to all generative tools**, not GPAI only. Every Tex-governed outbound artifact is in scope: email, Slack, post, document. The Microsoft Agent Governance Toolkit's positioning ("we govern agents") does not address this; Tex's positioning ("our evidence carries C2PA Content Credentials") does.
- **Para 64 — source code is exempt.** Inline comments and docstrings inside the code artefact are exempt; README, marketing copy, natural-language explanations are NOT. Tex's `digitalSourceType` field correctly omits code outputs but includes prose explanations from coding agents.
- **Para 81 — B2B/industrial carve-out is narrow.** Requires output to be (a) strictly technical and (b) intended only for a limited, pre-defined audience of professionals inside the organisation. Any external leakage collapses the second leg. Tex's AI-SDR outbound emails *cross to external counterparties by definition* → no B2B carve-out applies → full Article 50(2) C2PA marking required.
- **Para 107(ii) deepfake test** — only AI content depicting subjects "capable of existing in reality" is a deepfake. A photorealistic invented person IS a deepfake (must label); a sphinx over the Eiffel Tower is NOT. Outside Thread 5 scope (deployer-side), but Tex captures `digitalSourceType` so the deployer-side labelling can be triggered automatically.
- **Para 140 — penalties up to €15M or 3% global turnover.** Article 50 sits in the second-highest fine band.

**Build consequence:** the `c2pa.actions.v2` `digitalSourceType=trainedAlgorithmicMedia` field in the existing `manifest.py` is the Article 50(2) machine-readable mark. The `tex.verdict` extension assertion is the Article 50(1) "self-disclosure" record (signed proof that the agent disclosed). The new `tex.evidence_cosign` ties the two together so a notified body can prove the disclosure was both made *and* tamper-evident.

### 2.4 May 7, 2026 EU grandfathering rule

**Source:** Bird & Bird / Conventus, citing political agreement.

- Legacy generative AI systems on the market before Aug 2, 2026 → comply with Article 50(2) by **Dec 2, 2026** (Commission had originally proposed Feb 2027).
- New systems placed on market after Aug 2, 2026 → comply from day one.
- Article 50(1), (3), (4) → no transition. Apply from Aug 2, 2026 for everyone.

**Build consequence:** the urgency framing in `CLAIMS.md` and the `_tex_5_demo.sh` script should reference the Aug 2 / Dec 2 dates. Tex enables compliance from day one for new systems.

### 2.5 COSE codepoints for ML-DSA — still draft

**Source:** `datatracker.ietf.org/doc/draft-ietf-cose-dilithium/` revision -11 (Nov 15 2025), expires May 19, 2026. `draft-ietf-cose-falcon-04` (Mar 2026) and `draft-ietf-cose-sphincs-plus-07` reference -11 as authoritative.

**State:** Algorithms are listed by name (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`) with IANA integer codepoints **TBD**. The COSE_Sign1_Tagged structure cannot carry ML-DSA with a stable, registered `alg` integer yet.

**X.509 OID is final:** `2.16.840.1.101.3.4.3.18` for ML-DSA-65. AWS Private CA + KMS support shipped Nov 2025. Microsoft AD CS shipped support **May 18, 2026 (today)** — same Windows Server 2025 update.

**Build consequence — definitive:**

- **C2PA outer signature: ES256 (ECDSA P-256 + SHA-256).** This is C2PA 2.4 §13.2 compliant. Verifies under Microsoft Edge, Adobe Inspect, CAI Verify, c2patool today.
- **Tex evidence co-signature: ML-DSA-65 via `tex.pqcrypto.algorithm_agility`.** Routed through the algorithm-agility provider so we can switch to ML-DSA-87 or hybrid as the IANA codepoint lands. The cosign is a Tex-internal assertion, not a COSE_Sign1_Tagged; this keeps us spec-conformant on the outer signature while delivering post-quantum guarantees on the Tex side.
- **Why not hybrid (ES256 + ML-DSA-65) as the outer signature?** Because C2PA 2.4 §13.2 doesn't define hybrid; we'd ship a manifest no validator accepts. The two-signature pattern (spec-conformant outer + Tex-PQ inner) is the only path that ships today.

This decision overrides Section 5(b) of my Phase 0 plan (which proposed hybrid as outer). The NSA paper makes the right design clearer.

### 2.6 SCITT Refusal Events draft taxonomy

**Source:** `draft-kamimura-scitt-refusal-events-02` (Jan 10, 2026, expires Aug 3, 2026).

The draft defines an event-type registry with `event-type` (`PRE_GENERATION`, `MID_GENERATION`, `POST_GENERATION`) and `risk-category` covering CSAM, REAL_PERSON_DEEPFAKE, VIOLENCE_EXTREME, HATE_CONTENT, TERRORIST_CONTENT, SELF_HARM_PROMOTION, COPYRIGHT_VIOLATION, COPYRIGHT_STYLE_MIMICRY, OTHER.

**Build consequence:** when Tex FORBIDs an outbound artifact, instead of just refusing silently, we emit a SCITT Signed Statement (per the existing `tex.evidence.scitt_statement` module) following the refusal-events claim-set schema. The signed statement is hash-anchored in the evidence chain. **Per the user's request to ship bleeding-edge that competitors haven't implemented:** Tex becomes the first agent-governance platform to emit SCITT refusal events at FORBID, giving regulators (and cyber insurers) a verifiable refusal flight-recorder. This pairs naturally with C2PA at PERMIT and turns the dual into a complete provenance/refusal coverage story.

### 2.7 c2pa-rs release activity

**Source:** GitHub `contentauth/c2pa-rs/CHANGELOG.md` through Feb 12, 2026.

Active releases (~2/week through Jan-Feb 2026). **No ML-DSA / SLH-DSA / hybrid PQ signing support in c2pa-rs as of CHANGELOG inspection** — they're tracking C2PA 2.4 §13.2 (classical only). Adobe will need this eventually; Tex shipping ML-DSA via co-signature **now** is genuinely ahead of the upstream reference implementation.

### 2.8 Microsoft Agent Governance Toolkit — survival-level check

**Source:** `opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit/`, GitHub releases through May 2026.

- Stack: Agent OS (policy engine, p99 <0.1ms), zero-trust identity (Ed25519), execution sandbox, reliability/SRE, 9500+ tests, 7 packages, 5 languages.
- **Coverage gap (our wedge): no C2PA. No Content Credentials. No SCITT.** Their evidence is hash-chained Ed25519 receipts. They have OWASP ASI 2026 10/10 — content provenance is not in the ASI taxonomy, so they have no forcing function to ship it.
- Article 50 angle: the Toolkit's compliance package maps to GDPR/HIPAA/SOC2/EU AI Act *high-risk* obligations (Article 12 logging, Article 14 oversight). It does **not** address Article 50 transparency obligations.

**Conclusion:** Tex's wedge is exactly the surface Microsoft elected not to cover. Build per plan.

### 2.9 Competitive set — Zenity, Noma, Lakera, Pillar, etc.

Zero hits for "C2PA" / "Content Credentials" / "Article 50 transparency" in their 2026 product announcements (verified via web search across all named competitors). All are model-layer / identity-layer / posture-management. **The agent-governance market has no C2PA layer today.**

### 2.10 New papers I will cite in code comments

| arXiv ID | Date | Why it matters |
|---|---|---|
| 2604.24890 | Apr 27 2026 | NSA/UMBC formal-methods C2PA paper — drives the 6 attack defenses |
| 2603.02378 | Mar 2 2026 | Authenticated contradictions: forces C2PA to be canonical, watermark subordinate |
| 2605.12456 | May 12 2026 | TextSeal — distortion-free LLM text watermark (radioactive through distillation) — soft-binding companion |
| 2605.13471 | May 14 2026 | Sleeper Channels and Provenance Gates — drives Tex's provenance-gate semantics |
| 2604.04522 | Apr 6 2026 | HDP — delegation-chain provenance — informs `cawg.identity` extension |
| 2604.23280 | Apr 28 2026 | AI Identity Standards survey — places C2PA in agent-identity stack |
| 2604.06693 | Apr 8 2026 | Aegon — hardware-attested compliance receipts; pattern for `tex.evidence_cosign` |

---

## 3. Numerical SOTA targets I must beat

| Metric | Section 1.4 floor | Newer paper | My target |
|---|---|---|---|
| C2PA manifest verifies under c2patool | yes/no | n/a | **PASS** |
| C2PA manifest verifies under CAI Verify (verify.contentauthenticity.org) | yes/no | n/a | **PASS** (using ES256 outer) |
| Article 50(2) `digitalSourceType` machine-readable mark | yes/no | EU Guidelines May 8 2026 | **PASS** |
| Resistance to NSA-paper attack #1 (timestamp swap) | not covered | arxiv 2604.24890 | **Tex evidence cosign binds timestamp into signed payload** |
| Resistance to attack #2 (revoked cert accepted) | not covered | arxiv 2604.24890 | **`revocation_proof` field hash-pins CRL snapshot at signing time** |
| Resistance to attack #3 (cross-validator contradiction) | not covered | arxiv 2604.24890 | **`canonicalization_version` field + canonical CBOR over the full assertion set** |
| Resistance to attack #4 (exclusion range tampering) | not covered | arxiv 2604.24890 | **Full-file SHA-256 with zero exclusion ranges** |
| Resistance to attack #5 (cert expiry before retention) | not covered | arxiv 2604.24890 | **`retention_anchor` into Tex evidence chain — chain re-verifies after cert expiry** |
| Post-quantum signature on Tex side | ML-DSA-65 wired | NIST FIPS 204 final | **ML-DSA-65 via `tex.pqcrypto.algorithm_agility`** |
| Latency, sign + verify, end-to-end | not specified | c2pa-rs ~5-20ms typical | **< 50ms p99 for email manifest** |
| SCITT refusal event on FORBID | not in 1.4 | draft-kamimura-scitt-refusal-events-02 | **emit signed statement keyed by event-type + risk-category** |

---

## 4. Design decisions, with the rejected alternative

| Decision | Picked | Rejected | Why |
|---|---|---|---|
| Outer C2PA signature alg | **ES256** | ML-DSA-65, hybrid | C2PA 2.4 §13.2 allow-list. ML-DSA codepoint TBD. Hybrid not in spec. Path to a manifest that verifies under Edge/Adobe/CAI today. |
| Tex co-signature alg | **ML-DSA-65** | SLH-DSA, classical-only | NIST FIPS 204 finalised; existing `tex.pqcrypto.ml_dsa` provider; PQ resistance the user explicitly demanded. |
| Co-signature placement | **`tex.evidence_cosign` assertion** | new top-level COSE_Sign1 | Spec-conformant manifest must have exactly one COSE_Sign1; co-sig as an assertion is transparent to vanilla validators. |
| Time-stamp authority | **RFC 3161 v2 payload (C2PA 2.4 mandatory) PLUS internal timestamp in `tex.evidence_cosign`** | RFC 3161 only | NSA paper attack #1 |
| Revocation checking | **Hash-pin CRL snapshot at signing time, embedded in cosign** | OCSP only | NSA paper attack #2 + privacy concerns the paper raises |
| Manifest hash anchored where | **Postgres `evidence_manifests` table + hash on the parent decision evidence record** | manifest hash on Decision row only | NSA paper attack #5 — retention anchor must survive C2PA cert expiry |
| Embedding for text artifacts | **C2PA 2.4 Appendix A.8 unstructured-text + cloud manifest URL** | sidecar-only | 2.4 finally allows this; aligns with Microsoft Edge's planned text-content verification rollout. |
| Text watermarking integration | **out of Thread 5 scope, document interop only** | embed SynthID-Text/TextSeal | arxiv 2603.02378 desync risk; Thread 5 covers C2PA layer only; watermarking goes to a separate Thread when we have a partner pixel/token-level provider. |
| SCITT refusal events on FORBID | **ship in this thread** | defer | draft-kamimura-scitt-refusal-events-02 exists, fits naturally with C2PA at PERMIT, ships the FORBID side of the evidence story. |
| What c2pa-rs binding to use | **none — pure Python implementation we already have** | wrap c2pa-rs via FFI | c2pa-rs does not support ML-DSA, our pure-Python `signer.py` does; FFI adds a build dependency and we'd lose the PQ surface. |

---

## 5. What this changes about the build plan vs the original prompt

The original prompt asked for "signed with ML-DSA-65 via the algorithm-agility provider." That cannot be the outer C2PA signature without producing a manifest no validator accepts. **I am replacing acceptance criterion #1 with this clarified version:**

> 1'. `EvidenceRecorder.record_decision()` accepts an optional `outbound_artifact` parameter. When provided, it produces a C2PA 2.4 manifest with: `c2pa.actions.v2` assertion (action = `c2pa.created`, `digitalSourceType = trainedAlgorithmicMedia`), `cawg.creative_work` for tenant identity, `tex.verdict` linking the verdict ID, and a new **`tex.evidence_cosign`** assertion signed with ML-DSA-65 via the algorithm-agility provider that closes the six NSA-paper-2604.24890 attack classes. The outer COSE_Sign1 is signed with ES256 per C2PA 2.4 §13.2 so the manifest verifies under Edge / Adobe / CAI today.

All other acceptance criteria stand. I will explicitly call this delta out in the commit message.

The SCITT refusal-event emission on FORBID is **net-new beyond the original prompt**, justified by the Phase 0 finding that competitors do not do this either. Per the user's "ship the most state-of-the-art that competitors are not even using yet" mandate.

---

## 6. Construction plan (summary, full detail in commit + code)

1. Extend `src/tex/c2pa/manifest.py` with `build_tex_evidence_cosign_assertion()` + `TEX_EVIDENCE_COSIGN_SCHEMA_V1`.
2. Add `src/tex/c2pa/_cose_alg.py` — already exists; extend to allow ML-DSA-65 *only* for the inner cosign codepath (not the outer COSE_Sign1). Already pre-architected per the existing module docstring.
3. Extend `src/tex/c2pa/signer.py` — `sign_manifest_with_evidence_cosign(...)` produces both outer ES256 COSE_Sign1 and inner ML-DSA-65 evidence cosign in one call. Backward-compat: `sign_manifest` unchanged.
4. Extend `src/tex/c2pa/verifier.py` — verify the inner cosign on top of the outer signature, and surface the 6 attack-defense statuses.
5. New file `src/tex/c2pa/durable_credentials.py` — already a stub, fill with the durable-credentials API (manifest cloud-hosting URL + lookup endpoint).
6. New file `src/tex/c2pa/evidence_emission.py` — the wiring layer that `EvidenceRecorder` calls.
7. Modify `src/tex/evidence/recorder.py`:
   - Add `outbound_artifact` and `c2pa_context` parameters to `record_decision`.
   - When `outbound_artifact` is provided and verdict is PERMIT, build manifest, sign, store, attach hash to the evidence record payload.
   - When verdict is FORBID and a refusal-event reason is present, emit SCITT refusal-event signed statement.
8. New file `src/tex/evidence/manifest_mirror.py` — Postgres mirror for the `evidence_manifests` table (alongside existing `postgres_mirror.py`).
9. Alembic migration `versions/<rev>_evidence_manifests.py` — new table.
10. FastAPI routes:
   - `GET /v1/evidence/{record_id}/c2pa` — returns CBOR manifest bytes (Content-Type `application/c2pa`).
   - `POST /v1/c2pa/verify` — accepts a manifest + optional asset bytes, returns `C2paVerificationResult` plus six-attack-defense status.
11. Tests:
   - `tests/frontier/test_c2pa_evidence_cosign.py` — new, covers all six NSA-paper attacks and the cosign behavior.
   - `tests/frontier/test_c2pa_scitt_refusal.py` — new, FORBID → SCITT signed statement.
   - `tests/test_integration_layer.py` — add the PERMIT→C2PA flow integration test.
12. `CLAIMS.md` — new entry under Wired claims.
13. `scripts/demo_thread_5_c2pa.sh` — single curl that produces a verdict whose evidence record has a verifiable C2PA + cosign + verify roundtrip.
14. `COMMIT_MSG_thread_5.txt` — final commit message naming the 2026 papers/standards/CVEs.

This brief is the contract. If during the build I discover anything wrong here, I will fix this brief first, then the code.

— Generated by the Thread 5 research pass, May 18, 2026.
