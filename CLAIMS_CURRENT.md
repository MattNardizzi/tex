# CLAIMS_CURRENT.md

**This is the file to read when prepping outreach, a pitch, or a customer call.**

Every claim below is wired into the live `/v1/guardrail` request path and
proven by an automated test. Anything that isn't in this file is not a
current claim — even if it appears in `CLAIMS_HISTORY.md` (which logs when
each claim was added but doesn't gate them today).

For:
- Historical record of when each claim was added → `CLAIMS_HISTORY.md`
- Claims tied to unfinished work, not yet defensible → `CLAIMS_ASPIRATIONAL.md`
- The codebase organization behind each claim → `MODULES.md`, `TIER_OWNERSHIP.md`
- Stubs that block specific claims → `STUB_REGISTRY.md` (blocks-claim column)

Discipline reminder: outreach copy must not exceed what's listed here.

---

# CLAIMS.md — Tex public-facing capability claims

This file is the single source of truth for what Tex actually does in the
live ``/v1/guardrail`` request path. Every claim names the wired module
and the test that proves it. Outreach copy must not exceed what's listed
here.

Discipline:
  * **Wired** = exercised by an actual ``/v1/guardrail`` (or ``/evaluate``)
    request and asserted in ``tests/test_integration_layer.py``.
  * **Built-but-unwired** = passing unit tests in ``tests/``, but not yet
    consumed by ``PolicyDecisionPoint`` (or equivalent live endpoint).
  * Anything not in this file is not a claim. If outreach references a
    capability, it must show up here first.

---

## Wired claims

### 1. Behavioral contracts in LTLf temporal logic with session-scoped (p, δ, k)-satisfaction (Thread 1 + Thread 1.5)

**Claim.** Every ``/v1/guardrail`` request is evaluated against the
active set of ``BehavioralContract``s using a finite-trace LTLf runtime
verifier (LTL3 three-valued semantics) over the Agent Behavioral
Contracts 6-tuple (preconditions / hard invariants / soft invariants /
hard governance / soft governance / recovery). Hard violations
short-circuit the pipeline to FORBID before fusion. Soft violations
propagate as findings + an uncertainty flag and promote PERMIT to
ABSTAIN. Per-``(agent_id, session_id)`` enforcer instances maintain
the recovery-counter state across requests, so ABC's bounded-recovery
semantics ``G(violated -> F<=k recovered)`` work end-to-end across an
agent session. Default behavior is preserved bit-for-bit for callers
not configuring contracts (default registry is None → zero-cost
neutral branch).

**Source paper anchors.**
- Bhardwaj 2026, *Agent Behavioral Contracts: Formal Specification and
  Runtime Enforcement for Reliable Autonomous AI Agents* (arxiv
  2602.22302) — §3 6-tuple structure; §3.3 Def 3.7
  (p, δ, k)-satisfaction; §5.3 per-turn enforcement loop.
- De Giacomo & Vardi 2013 — LTLf finite-trace semantics.
- Bauer, Leucker, Schallhart 2011 / arxiv 2411.14581 — LTL3
  three-valued runtime-verification semantics.
- Felicia et al. 2026 / arxiv 2601.22136 (StepShield) — temporal
  detection metrics; session-scoped ``step_index`` enables Early
  Intervention Rate / Intervention Gap measurement.

**Modules.**
  * Spec: ``tex.contracts.BehavioralContract``,
    ``tex.contracts.ContractEnforcer``, ``tex.contracts.ContractViolation``,
    ``tex.contracts._ltl.LTLFormula``, ``tex.contracts._atoms.ContractContext``.
  * Wiring: ``tex.engine.pdp.PolicyDecisionPoint``,
    ``tex.engine.contract_bridge.evaluate_contracts_for_request``,
    ``tex.engine.contract_bridge.SessionEnforcerRegistry``.
  * Composition root: ``tex.main.build_runtime`` (env vars
    ``TEX_CONTRACTS_DISABLE=1`` opts out; ``TEX_CONTRACTS_MODE=stateless``
    reverts to Thread 1 single-enforcer behaviour).

**Tests proving the claim.**
  * ``tests/test_integration_layer.py::TestBehavioralContracts`` (4 tests)
    — clean PERMIT, hard-FORBID, soft-ABSTAIN, env-disable.
  * ``tests/test_integration_layer.py::TestBehavioralContractsSessionScoping``
    (5 tests) — step_index accumulation across requests in a session,
    independent state across different sessions of the same agent,
    session_key in violation metadata, stateless-mode env var reverts
    behavior, **bounded-recovery discharges within k window** (the ABC
    §3.3 signature mechanism).

**Demo.** ``scripts/demo_thread_1.sh``.

**Competitive differentiation.**
Microsoft Agent Governance Toolkit (Apr 2 2026, MIT, 10/10 OWASP Agentic
ASI 2026 coverage) evaluates propositional rules over single tool calls:
equality, inequality, numeric, set-membership, boolean composition. Tex
evaluates LTLf temporal formulas over a finite trace of events with
``G`` (always), ``F`` (eventually), ``F<=k`` (bounded eventually),
``U`` (until), ``X`` (next), ``R`` (release), session-scoped across
agent activity. This is a strict expressiveness superset. The
AgentSpec ICSE 2026 paper (Wang/Poskitt/Sun) explicitly admits its
rule DSL "lacks support for trajectory-based safety analysis, i.e.,
estimating whether an action sequence might lead to unsafe states
several steps into the future" — LTLf with session-scoped state
provides exactly that.

**Honest scope statement.**
The Verifier Tax study (arxiv 2603.19328, Mar 2026) found that runtime
enforcement intercepts up to 94% of non-compliant actions on τ-bench but
delivers strictly-safe goal completion in <5% of settings. Tex's claim
is the *enforcement mechanism*: hard-violation FORBID with cryptographic
evidence, soft-violation ABSTAIN with uncertainty propagation, and the
ABC paper's bounded-recovery window k surfaced as a contract field. We
do not claim Tex closes the goal-completion gap; that requires
agent-side recovery logic, which is the agent's responsibility, not the
enforcement layer's.

**Replay limitation surfaced honestly.**
The action ledger preserves ``content_sha256`` rather than raw content
(privacy-preserving audit by design). Past-event atoms that read
``field:content~contains:...`` will not match against the replayed
window — they will still match correctly against the *live* event, but
historical content semantics require contracts written against the
fields the ledger preserves (action_type, channel, environment,
recipient, content_sha256, verdict, scores, capability_violations,
asi_short_codes, policy_version, evidence_hash).

---

### 2. Cryptographic evidence-on-demand for behavioral contract violations (Thread 2)

**Claim.** Every behavioral contract violation produces its own
first-class evidence record in the SHA-256 hash chain, with its own
``payload_sha256`` and its own ``record_hash``, linked to the parent
decision evidence record by both the linear chain edge
(``previous_hash``) and a semantic cross-reference
(``parent_evidence_hash``). A buyer (or a regulator) can verify a
single violation receipt in isolation, query the chain by
``decision_id`` or ``contract_id`` to retrieve all matching receipts,
and present selective disclosure proofs without exposing unrelated
decision payloads.

**Source paper anchors.**
- Bhardwaj 2026, arxiv 2602.22302 §5.2 — AgentAssert evidence model:
  every contract violation is a discrete, signable, cryptographically
  chained event.
- The Tex implementation strengthens the paper's model by keeping the
  linear-chain integrity property of the JSONL evidence log intact:
  the contract violation row is itself a fully-validated link in the
  hash chain, not a side-channel attachment.

**Modules.**
  * Append API: ``tex.evidence.recorder.EvidenceRecorder.record_contract_violation``.
  * Query API: ``tex.evidence.recorder.EvidenceRecorder.read_contract_violations``
    (filters by ``decision_id`` and/or ``contract_id``).
  * Wiring: ``tex.commands.evaluate_action.EvaluateActionCommand._record_contract_violation_evidence``
    — runs immediately after the parent decision evidence row is written,
    in both the ``memory_system`` and direct-recorder branches.

**Tests proving the claim.**
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_hard_violation_writes_first_class_evidence_row``
    — a hard violation produces exactly one ``contract_violation`` row
    chained immediately after the parent ``decision`` row, with all
    semantic cross-references intact (decision_id, contract_id,
    clause_ltl, parent_evidence_hash).
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_evidence_chain_remains_verifiable_with_contract_rows``
    — ``verify_evidence_chain`` passes over the combined chain of
    decision and contract_violation rows; the contract violation
    record is a fully-validated link, not a side channel.
  * ``tests/test_integration_layer.py::TestContractViolationEvidence::test_read_contract_violations_filter_by_decision``
    — the query helper correctly filters by ``decision_id`` and
    ``contract_id``, returning ``()`` for unmatched filters.

**Buyer-meaningful framing.**
"Tex doesn't just log that a contract violation happened — it issues a
cryptographically signed receipt for it. Each receipt is independently
verifiable, addressable by ``decision_id`` or ``contract_id``, and
chained into the same tamper-evident SHA-256 hash chain that protects
every other audit event. Selective disclosure to regulators or insurers
becomes trivial: hand them the receipt plus the chain segment up to its
parent, without exposing any unrelated content or decisions."

---

### 3. Native post-quantum signing without liboqs (May 2026 frontier upgrade)

**Claim.** All ML-DSA (FIPS 204) and ML-KEM (FIPS 203) signing in Tex
dispatches through **pyca/cryptography 48.0.0 native bindings** backed
by OpenSSL 3.5+, with liboqs available only as a fallback. This is the
same EVP-layer path that AWS KMS (Sep 2025), Microsoft AD CS (May 2026
update), and the Linux kernel module-signing patches (v16, Feb 2026)
ship. Tex no longer requires the five-minute liboqs CMake compile to
come up on a fresh dev environment.

**Wire format (FIPS 204).**
- ML-DSA-44: 1 312-byte public key, 32-byte seed private key,
  2 420-byte sig.
- ML-DSA-65: 1 952-byte public key, 32-byte seed, 3 309-byte sig.
- ML-DSA-87: 2 592-byte public key, 32-byte seed, 4 627-byte sig.
- COSE algorithm ids per draft-ietf-cose-dilithium-11: -48 / -49 / -50.
- Pure ML-DSA — HashML-DSA is prohibited per NSA CNSA 2.0 (April 2026).

**Modules.**
- ``tex.pqcrypto.ml_dsa.MlDsaProvider`` — dual-backend (native + liboqs).
- ``tex.pqcrypto.ml_dsa.active_backend_id()`` — reports which backend is
  resolved at import time.
- ``tex.pqcrypto.ml_kem.MlKemProvider`` — same pattern; ML-KEM-768 and
  ML-KEM-1024 native, ML-KEM-512 still routes to liboqs.

**Tests proving the claim.**
- ``tests/frontier/test_pqcrypto.py`` (44 tests) — all run against the
  native backend, zero skips on a clean ``pip install`` of Tex's deps.
- ``tests/pqcrypto/test_ml_kem.py`` (15 tests) — ML-KEM-512 case skips
  cleanly when liboqs is absent.

---

### 4. C2PA 2.4 OCSP stapling and TSA v2 timestamps

**Claim.** Tex's C2PA signer places OCSP staples (RFC 6960) and v2 TSA
timestamp tokens (C2PA 2.4 §10.3.2.5) in the unprotected COSE header
of a signed manifest, and Tex's verifier extracts and validates them
with C2PA 2.1 §15.7 / 2.4 §15.9 failure codes surfaced verbatim into
the verification result.

This closes the largest gap documented in Sherman et al., *Verifying
Provenance of Digital Media: Why the C2PA Specifications Fall Short*
(arxiv 2604.24890, 27 Apr 2026): the v1 timestamp + missing OCSP
staple combination was the dominant validator attack class.

**Wire format.**
- OCSP staples in the unprotected header under text key ``"ocsp_vals"``
  as an array of DER-encoded OCSPResponse bytes (C2PA 2.4 §15.9 + RFC
  9277 nonce).
- TSA v2 tokens under ``"sigTst2"`` as an array of DER-encoded
  TimeStampResp tokens. v2 messageImprint is **SHA-256 of the
  COSE_Sign1 signature field** (not the v1 Sig_structure payload),
  binding the timestamp to the exact signature bytes.

**Modules.**
- ``tex.c2pa.ocsp`` — request build, response parsing,
  authority-delegation check (RFC 6960 §4.2.2), C2PA 2.4 §15.9
  failure codes via ``OcspFailureCode``.
- ``tex.c2pa.timestamp`` — RFC 3161 v2 request build with policy OID +
  nonce, response parsing with messageImprint / genTime / cert
  validity checks, C2PA 2.4 §15.8 failure codes via
  ``TimestampFailureCode``.
- ``tex.c2pa.signer.sign_manifest`` — new ``ocsp_staples_der=`` and
  ``tsa_tokens_der=`` kwargs.
- ``tex.c2pa.verifier.verify_manifest`` — new ``require_ocsp_staple=``
  and ``require_timestamp=`` kwargs.

**Tests proving the claim.**
- ``tests/c2pa/test_ocsp.py`` (4 tests).
- ``tests/c2pa/test_timestamp.py`` (8 tests).
- ``tests/c2pa/test_signer_unprotected_header.py`` (6 tests).

---

### 5. Composite ML-DSA per draft-ietf-lamps-pq-composite-sigs-18

**Claim.** Tex's composite signatures align with the IETF LAMPS
draft-18 (9 Apr 2026; latest revision 20 May 2026, IESG Evaluation::
AD Followup). Canonical prefix ``CompositeAlgorithmSignatures2025``,
real per-algorithm Labels (``COMPSIG-MLDSA65-Ed25519-SHA512`` /
``COMPSIG-MLDSA87-ECDSA-P384-SHA512``), IANA-assigned OIDs
``1.3.6.1.5.5.7.6.48`` / ``.49``. M' construction follows draft-18
§2.1 (``Prefix || Label || len(ctx) || ctx || PH(M)`` with SHA-512
pre-hash).

**Modules.**
- ``tex.pqcrypto.composite_ml_dsa.CompositeMlDsaProvider``
- ``tex.pqcrypto.composite_ml_dsa.draft_18_oid()``,
  ``draft_18_label()``.

**Tests proving the claim.**
- ``tests/pqcrypto/test_composite_ml_dsa.py`` (20 tests), including
  ``test_draft_18_oids_match_iana_registrations`` pinning the
  ``1.3.6.1.5.5.7.6.48`` / ``.49`` OIDs.

---

### 6. EU AI Act + state AI disclosure compliance modules

**Claim.** Tex emits structured, machine-readable compliance records
for the four overlapping AI disclosure regimes coming into force in
mid-2026:

- **EU AI Act Article 50** (effective 2 August 2026) — disclosure
  attestation bound to C2PA manifest, IPTC ``trainedAlgorithmicMedia``
  digitalSourceType, four-criteria self-assessment per Article 50(2),
  Code of Practice alignment.
- **EU AI Act Article 17** (effective 2 August 2026) — full QMS
  evidence packet covering all 11 §17(1)(a)-(k) components, corrective
  action log, post-market monitoring window.
- **EU AI Act Article 26** (effective 2 August 2026) — deployer record
  with §26(6) 6-month log retention minimum, §26(5) 72-hour incident
  SLA, §26(2) human-oversight roster, §26(3) input-data attestation.
- **California SB 942** (operative 2 August 2026) — disclosure record
  bound to C2PA manifest, four required fields plus media type +
  permanent-website-link option + detection-tool flag.
- **New York §1700-A AI Advertising Disclosure** (effective 1 June
  2026) — placement-presumption guardrails, $1 000 / $5 000 civil
  penalty surface.
- **Colorado AI Act SB 24-205** (effective 30 June 2026) — deployer
  record across the 8 consequential-decision categories.

All six modules emit C2PA-bound records so a single ingestion pipeline
at the customer's side can fan out to all jurisdictions without
re-extracting underlying fields.

**Modules.**
- ``tex.compliance.eu_ai_act.article_50`` / ``article_17`` / ``article_26``
- ``tex.compliance.state.california_sb942`` / ``new_york_ai_disclosure``
  / ``colorado_ai_act``

**Tests proving the claim.**
- ``tests/frontier/test_compliance_new_jurisdictions.py`` (23 tests)
  spanning NY §1700-A, Colorado, Article 17, Article 26, and
  cross-jurisdiction binding-convention assertions.

---

### 7. Sherman 2026 attack-class defense matrix

**Claim.** Tex closes all six attack classes documented in Sherman et
al., *Verifying Provenance of Digital Media: Why the C2PA
Specifications Fall Short* (arxiv 2604.24890, 27 Apr 2026):

- **C1 timestamp-replay** → v2 TSA timestamps (signature-field binding).
- **C2 stale-OCSP** → mandatory staple freshness +
  ``require_ocsp_staple``.
- **C3 chain-truncation** → C2PA 2.4 §13.2 + RFC 9360 x5chain.
- **C4 assertion-injection** → RFC 8785 canonicalization + COSE
  Sig_structure re-derivation on verify.
- **C5 ingredient-forgery** → ``tex.evidence_cosign`` parent-hash
  binding + recursive parent validation.
- **C6 cross-manifest-replay** → ``full_file_sha256`` binding inside
  ``tex.evidence_cosign`` + v2 messageImprint binding.

The compliance posture is exported as a JSON dossier for buyer-facing
materials (GTM-A brand-safety pitch, GTM-B cyber-insurance evidence
packet) and is monitored by the audit pipeline — any module move that
breaks a defense flips ``sherman_2026_compliant`` to False.

**Modules.**
- ``tex.c2pa.sherman_2026_defenses.assess_current_posture()``
- ``tex.c2pa.sherman_2026_defenses.render_buyer_dossier()``

**Tests proving the claim.**
- ``tests/c2pa/test_sherman_2026_defenses.py`` (8 tests), including
  ``test_all_six_defenses_are_currently_wired`` as the headline
  regression guard.

---

### 8. Post-quantum code signing (SLH-DSA / FIPS 205, CNSA 2.0 §2)

**Claim.** Tex signs release artifacts and skill manifests with
SLH-DSA (FIPS 205, stateless hash-based) via
``tex.pqcrypto.code_signing``. Default parameter set: SLH-DSA-128s
(7 856-byte signatures); CNSA 2.0 §2 NSS deployments select
SLH-DSA-256s (29 792-byte signatures).

SLH-DSA matches the production path Microsoft Windows Insider (March
2026), Linux kernel v16 (Feb 2026), and NSA CNSA 2.0 §2 (April 2026
update) chose for code signing — same hash-function-only security
foundation, no stateful key management. LMS (NIST SP 800-208) is
scaffolded as a future option in ``tex.pqcrypto.lms`` for the
firmware-signing-in-HSM case, but is not the default — counter-reuse
on LMS is catastrophic and unnecessary for Tex's threat model.

**Modules.**
- ``tex.pqcrypto.code_signing.sign_release_artifact``,
  ``verify_release_artifact``, ``recommended_algorithm``.
- ``tex.pqcrypto.lms`` — documented future-options module with a
  clear pointer back to the SLH-DSA recommendation.

**Tests proving the claim.**
- ``tests/pqcrypto/test_code_signing.py`` (4 structural tests run
  everywhere; 2 cryptographic round-trips gated on liboqs).
- ``tests/pqcrypto/test_lms.py`` (6 tests) — pins the API surface
  + the SLH-DSA-recommendation guard rail.

---

### 9. Durable multi-layer content credentials (C2PA Trust Markers + EU CoP §Watermark-2)

**Claim.** Tex emits three independent durable-marking layers on
outbound AI-generated images:

1. **Embedded C2PA manifest** (primary, stripped by social platforms).
2. **Invisible perceptual watermark** via **TrustMark** (University of
   Surrey + Microsoft, on the C2PA Soft Binding Algorithm List, PyPI
   ``trustmark``). 100-bit payload at PSNR ≥ 40 dB; survives JPEG
   quality-40 and ~50% downscaling.
3. **Fingerprint** registered to Tex's provenance database — catches
   laundered-content cases where both manifest and watermark are lost.

The three-layer scheme is presumptively-compliant under the EU Code of
Practice second draft (3 March 2026) §Watermark-2(a)+(b)+(c), and
matches the multi-layer marking the 7 May 2026 Digital Omnibus
expects to enforce in December 2026.

**Modules.**
- ``tex.c2pa.durable_credentials.attach_durable_marks``,
  ``trustmark_available``.

**Tests proving the claim.**
- ``tests/c2pa/test_durable_credentials.py`` (9 tests) — layer
  enumeration, fingerprint stability, ``require_watermark_layer``
  fail-close behaviour, non-image content tolerance.

---

