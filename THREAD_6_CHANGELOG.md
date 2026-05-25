# Thread 6 — Demo Polish: Jailbreak Recognizers + Slice Verifier (Changelog)

**Date:** May 24, 2026
**Author:** Thread 6 work session
**Scope:** Per Section 14 of TEX_CANONICAL.md — close the two
demo-blocking defects identified in KNOWN_BUGS:

- **Bug #7:** the canonical DAN-style jailbreak payload returned
  ABSTAIN with zero deterministic findings, which made technical-
  buyer demos visibly weak on the most-googled prompt-injection
  pattern on the internet.
- **Bug #5:** `GET /decisions/{id}/evidence-bundle` reported
  `is_chain_valid: False` on every single-record slice that wasn't
  the global genesis. The verifier was treating each filtered slice
  as if it were the start of a fresh chain. Single-record bundles
  are the highest-frequency audit pull, so this directly contradicted
  the "evidence-grade adjudication" claim.

After this thread:

- Two new deterministic recognizers (`jailbreak_persona`,
  `invisible_unicode`) cover the May 2026 jailbreak attack surface
  — instruction-override family, the DAN/STAN/AIM/Evil-Confidant
  persona zoo, Policy Puppetry XML/JSON/INI persona-config shapes,
  Time Bandit temporal confusion, many-shot priming inside a single
  user turn, fictional-frame bypass, explicit safety-disable
  language, Unicode Tag Block ASCII smuggling
  (U+E0000–U+E007F), the variation-selector steganography channel
  (U+E0100–U+E01EF), bidi overrides (Trojan Source at the LLM
  layer), and dense zero-width sequences. The invisible-Unicode
  recognizer **decodes the hidden payload back into the finding
  metadata** so the audit trail records what the attacker tried to
  hide, not just that hiding was attempted.
- The canonical DAN payload now produces three findings
  (`instruction_override`, `dan_family`, `dan_family`) and the verdict
  is ABSTAIN-with-audit-evidence instead of ABSTAIN-with-no-signal.
- `tex.evidence.chain.verify_evidence_chain_slice(records, *,
  prior_link_witness=...)` is the new slice verifier. It follows the
  Certificate Transparency / Sigstore Rekor / Microsoft AGT
  MerkleAuditChain inclusion-proof-with-witness pattern. The
  `EvidenceExportBundle` envelope now carries the witness so
  external verifiers can independently confirm slice continuity
  against the parent chain. `EvidenceExporter.build_slice_bundle()`
  looks up the predecessor record automatically; the existing
  `/decisions/{id}/evidence-bundle` route uses it.
- The original `verify_evidence_chain()` is unchanged so the five
  pre-existing callers (`exporter.py`, `commands/export_bundle.py`,
  `memory/evidence_store.py`, and two tests) see no behavioral
  drift.

---

## 1. State-of-the-art grounding (May 24, 2026)

Before touching code, Thread 6 grounded itself on current frontier
research, since training data predates May 2026 and the canonical
doc's prescribed fix list for Bug #7 (drawn from January-era
training data) was narrower than what the May 2026 attack surface
actually requires.

### Jailbreak taxonomy (Jan 2026 – April 2026)

- **Repello AI red-team data (March 2026):** Claude Jailbreaking in
  2026 — DAN-family persona attacks survived 12+ iterations,
  modern DAN combines persona with encoded payloads, "Evil
  Confidant" / "AntiGPT" categories survive vocabulary-based input
  filters because they use entirely benign words.
- **WitnessAI (March 2026):** Role-play / persona manipulation,
  many-shot jailbreaking (long-context flooding with fabricated
  prior turns), character-level obfuscation (emoji smuggling,
  Unicode tags, zero-width), multi-turn Crescendo, indirect
  injection through tool inputs.
- **BeyondScale (April 2026):** documents Policy Puppetry (April
  2025) — XML/JSON/INI prompts that exploit how models parse
  structured system-like content; and Time Bandit (January 2025) —
  fictional date references creating temporal confusion to bypass
  post-2021 safety training.
- **Reddog Security (April 2026):** "LLM Security in 2026: A
  Complete Attack Map" — OWASP LLM01:2025 mapping and EU AI Act
  high-risk system compliance lens.
- **Sapienza Università arxiv 2510.13893:** "Guarding the
  Guardrails: A Taxonomy-Driven Approach" — single-turn vs
  multi-turn split, jailbreak as misalignment induction.
- **MITRE ATLAS AML.T0054 LLM Jailbreak Injection:** the canonical
  technique mapping cyber and compliance teams check against.

### Invisible Unicode (the May 2026 frontier vector)

- **Cisco AI Defense skill-scanner advisory (March 2026):** PR #94
  detects ASCII smuggling via Unicode Tag Block — every printable
  ASCII codepoint has an invisible twin at U+E0000 + codepoint.
  No legitimate use in skill files. Tex applies the same logic to
  agent-evaluated content.
- **AWS Security Blog (September 2025):** "Defending LLM
  applications against Unicode character smuggling" — Tag Block
  range U+E0000–U+E007F is the canonical exploit channel.
- **arxiv 2603.00164 (Reverse CAPTCHA, USC, February 2026):**
  evaluates LLM susceptibility to invisible Unicode injection.
  Recommends input sanitization to strip Tag Block characters
  and suspicious zero-width sequences before they reach the model.
- **arxiv 2510.05025 "Imperceptible Jailbreaking against LLMs":**
  variation selectors as a steganographic jailbreak channel
  (U+E0100–U+E01EF — 240 codepoints, enough for any byte value).
  The ASCII Smuggler tool documented at velio.binbash.buzz uses
  this channel; encoded text survives copy-paste.
- **CVE-2021-42574 "Trojan Source":** bidi-override class —
  Tex applies the same defect class at the LLM input layer.

### Audit-log slice verification (the standard pattern)

- **Certificate Transparency RFC 6962 audit proofs:** the canonical
  inclusion-proof pattern. External verifiers receive a slice plus
  a witness; they reproduce the witness against their own copy of
  the log to confirm continuity.
- **Sigstore Rekor:** same pattern, applied to software-artifact
  provenance — the precedent Tex follows.
- **Microsoft Agent Governance Toolkit MerkleAuditChain
  (April 2026):** uses Merkle audit proofs over agent action logs;
  same shape as what Tex now ships.
- **arxiv 2605.00065 (IoT Edge Merkle pipeline, May 2026):**
  resource-aware adaptive chunking with O(log n) inclusion-proof
  generation; reinforces witness pattern as the standard.

Tex was already SHA-256 hash-chained; the slice verifier just
needed to learn how to validate a sub-range with an out-of-band
witness instead of pretending each slice was a fresh chain.

---

## 2. Files changed

| File | Change |
|---|---|
| `src/tex/deterministic/recognizers.py` | +2 recognizer classes (`JailbreakPersonaRecognizer`, `InvisibleUnicodeRecognizer`); both added to `default_recognizers()`. ~+450 LOC. |
| `src/tex/policies/defaults.py` | Added `jailbreak_persona` and `invisible_unicode` to `_DEFAULT_ENABLED_RECOGNIZERS`. |
| `src/tex/evidence/chain.py` | Added `verify_evidence_chain_slice()`, `_verify_witness_link()`, `_normalize_witness()`. `verify_evidence_chain()` unchanged. New issue codes: `missing_prior_link_witness`, `prior_link_witness_mismatch`. |
| `src/tex/evidence/exporter.py` | Extended `EvidenceExportBundle` with `prior_link_witness: str \| None = None` field; `to_dict()` exposes it. Added `EvidenceExporter.build_slice_bundle()` that looks up the predecessor and builds a witnessed slice bundle. |
| `src/tex/api/routes.py` | `/decisions/{id}/evidence-bundle` switched to `exporter.build_slice_bundle()`. The inline `verify_evidence_chain` + manual `EvidenceExportBundle` construction is gone. |
| `tests/test_jailbreak_recognizers.py` | **New file**, 66 tests. Covers KNOWN_BUGS #7 regression, every documented jailbreak family, every invisible-Unicode category, false-positive guards for benign content (emoji ZWJ, "ignore the typo", "forget how stressful"), audit-grade metadata contracts, end-to-end through the gate. |
| `tests/test_evidence_bundle_slice.py` | **New file**, 16 tests. Covers KNOWN_BUGS #5 regression: pure-function slice verifier semantics, witness pattern, tampered-witness rejection, malformed-witness parse-time rejection, internal-record-tamper detection, `EvidenceExporter.build_slice_bundle()` integration, full FastAPI round-trip through `/decisions/{id}/evidence-bundle`. |
| `KNOWN_BUGS.md` | Bug #5 and Bug #7 marked ✅ RESOLVED with full fix narratives. |

---

## 3. Design decisions and what they cost

### 3.1 Two recognizers, not one

`JailbreakPersonaRecognizer` (WARNING) and `InvisibleUnicodeRecognizer`
(CRITICAL) are deliberately split. The frontier research treats them
as distinct attack classes with distinct defenses; folding them into
one recognizer would have forced a single severity decision that's
wrong for half the surface.

DAN-family patterns appear in legitimate red-team, security-research,
and Tex Arena contexts. A FORBID-on-pattern severity would cause
demo-killing false positives in exactly the markets Tex is meant to
serve. WARNING surfaces the signal and lets the router fuse it.

Invisible Unicode in agent-evaluated user content has no legitimate
use case (the May 2026 Cisco, AWS, and USC advisories all converge
on this). CRITICAL is correct; the default policy hard-blocks. The
audit record carries the decoded payload so the buyer can see what
was hidden.

### 3.2 Each finding carries a family tag

Every jailbreak finding sets `metadata["jailbreak_family"]` to one of
eight values (`instruction_override`, `dan_family`, `persona_swap`,
`system_prompt_shape`, `temporal_confusion`, `many_shot_priming`,
`fictional_frame`, `safety_disable`). Every invisible-Unicode finding
sets `metadata["unicode_category"]` to one of five values
(`tag_block`, `variation_selector_supplement`,
`variation_selector_base`, `bidi_override`, `zero_width_density`).
This gives Tex Arena, evidence dashboards, and compliance reports
a stable aggregation key without re-parsing pattern strings.

### 3.3 Decode-and-include is the right call for invisible Unicode

The `InvisibleUnicodeRecognizer` doesn't just flag that invisible
codepoints exist — it reverses the Tag Block and variation-selector-
supplement encodings and stores the decoded ASCII string in
`metadata["decoded_preview"]`. This is the audit-grade signal a
buyer actually needs at a CISO conversation: not "we detected
hidden Unicode" but "the attacker tried to inject 'ignore safety'
into your model." The preview is truncated at 200 characters for
evidence-bundle hygiene.

### 3.4 Density thresholds for ambiguous Unicode categories

VS-base codepoints (U+FE00–U+FE0F) and the four zero-width
characters have legitimate uses (emoji ZWJ sequences, Indic
scripts). The recognizer fires only above density thresholds (3
for VS-base, 4 for zero-width) that are inconsistent with normal
text. The threshold choice is documented inline. Result: emoji
content and multilingual content pass clean; steganographic
channels trip.

### 3.5 Witness pattern over alternative slice-verifier designs

The KNOWN_BUGS #5 fix prescription listed three options:

1. Embed the slice in a full-chain re-verification at request time.
   Rejected: scales linearly with chain size, doesn't help offline
   verifiers.
2. Have the verifier accept a list of records and an optional
   prior-link witness. This is the option chosen.
3. Have the API embed the witness in the bundle envelope so an
   external verifier can validate the first link. **Also** chosen,
   in combination with (2).

(2) and (3) together is the inclusion-proof pattern that
Certificate Transparency, Sigstore Rekor, and Microsoft AGT all
ship. (1) was rejected; (2) without (3) leaves external verifiers
without the data they need; (3) without (2) makes Tex unable to
self-verify slices.

### 3.6 Backward compatibility was a hard constraint

`verify_evidence_chain()` has five callers across the codebase
(`exporter.py`, `commands/export_bundle.py`, `memory/evidence_store.py`,
`tests/test_integration_layer.py`, `tests/test_memory_system.py`,
`tests/test_runtime_memory_integration.py`). Touching its signature
or semantics would have rippled through every full-chain
verification path. The new `verify_evidence_chain_slice()` is a
sibling function, not a replacement. Default behavior of the route
handler changes (it now passes a witness automatically), but the
underlying full-chain verifier behaves identically.

### 3.7 What I left alone deliberately

- The 22 specialist judges already have prompt-injection signal
  (clawguard, vigil, struq, argus, mage have "ignore previous"
  patterns built in). Adding a deterministic-layer recognizer is
  the cheapest, most reliable, fastest-fail layer — but it doesn't
  replace the specialists. The PDP fuses both streams, which is
  the right architecture.
- The frontend (Tex Arena) was not touched. The recognizer emits a
  stable `jailbreak_family` metadata key that Arena can key off
  for "Tex caught it" scoring; the wiring on the frontend side is
  a separate workstream.
- The `EcosystemEngine`, the digital twin, SAFEFLOW, and the
  intervention engine were not touched. Thread 7 owns
  EcosystemEngine wiring; Thread 6 stayed in its lane.

---

## 4. Verification matrix

| What | How verified | Result |
|---|---|---|
| Canonical DAN payload from Bug #7 reproduces before fix | Manual run against `default_recognizers()` | 0 findings (bug reproduces) |
| Canonical DAN payload produces findings after fix | `tests/test_jailbreak_recognizers.py::test_canonical_dan_payload_produces_findings` | 3 findings: `instruction_override`, `dan_family`, `dan_family` |
| DAN payload severity is WARNING not CRITICAL | `test_canonical_dan_payload_via_gate_is_warning_not_critical` | All jailbreak findings WARNING, gate.blocked=False |
| Tag-block ASCII smuggling decodes hidden payload | `test_tag_block_ascii_smuggling_fires_and_decodes` | Recognizer decodes "ignore safety" into metadata |
| Variation-selector-supplement smuggling decodes | `test_variation_selector_supplement_smuggling_fires_and_decodes` | Recognizer decodes "pwned" into metadata |
| Bidi override fires | `test_bidi_override_fires` | CRITICAL finding with category `bidi_override` |
| Emoji ZWJ does not false-positive | `test_invisible_unicode_does_not_fire_on_benign[content2]` | 0 findings on `👨‍👩‍👧` |
| Benign "ignore the typo" does not false-positive | `test_jailbreak_recognizer_does_not_fire_on_benign[content2]` | 0 findings |
| Bug #5 reproduces before fix | Manual `verify_evidence_chain([records[1]])` | `unexpected_previous_hash` (bug reproduces) |
| Single-record non-genesis slice valid after fix | `test_non_genesis_slice_with_witness_validates` | `is_valid=True` |
| Tampered witness fails | `test_tampered_witness_fails` | `prior_link_witness_mismatch` |
| Tampered record content fails | `test_internal_record_integrity_still_verified` | `payload_sha256_mismatch` |
| Slice without witness emits explicit issue | `test_non_genesis_slice_without_witness_emits_explicit_issue` | `missing_prior_link_witness` |
| Full HTTP round-trip works | `test_evidence_bundle_endpoint_returns_valid_for_non_genesis_slice` | 200, `is_chain_valid=True`, 64-char witness |
| Existing `verify_evidence_chain` unchanged | `test_existing_full_chain_verifier_is_unchanged` | Full-chain still valid; legacy single-record-non-genesis behavior preserved |
| Existing deterministic tests still pass | `pytest tests/test_deterministic.py` | 14/14 pass |
| Full test suite passes | `pytest tests/ --ignore=tests/pqcrypto` then `pytest tests/pqcrypto` | **3,983 passed, 110 skipped, 0 failures** |

---

## 5. Tex Arena coordination note

The recognizer emits `metadata["jailbreak_family"]` on every
jailbreak-persona finding and `metadata["unicode_category"]` on every
invisible-Unicode finding. Tex Arena's scoring layer (see
`tex-frontend/` and the `/arcade/leaderboard/submit` endpoints) can
key off these to award "Tex caught it" points by attack class. No
schema change required on the Arena side; the metadata keys are
stable.

Recommended Arena scoring: `dan_family` and `instruction_override`
worth fewer points (well-known, deterministic-detectable);
`many_shot_priming`, `system_prompt_shape`, `temporal_confusion`
worth more (require more sophistication to construct);
`tag_block` and `variation_selector_supplement` worth the most
(May 2026 frontier vector, audit-grade decoded preview is the
buyer demo headline).

---

## 6. Canonical-doc reconciliation

TEX_CANONICAL.md Section 17 lists Bug #7 ("Canonical DAN/jailbreak
prompt → ABSTAIN with empty findings") and Bug #5 ("Single-record
evidence bundle slice → `is_chain_valid: False`") as Thread 6
targets. Both are now ✅ RESOLVED.

The canonical doc's Section 11 ("Layer 4 — Execution Governance,
Gaps") listed:

> Canonical jailbreak prompt returns ABSTAIN with empty findings → Thread 6

This row should be removed in the next reconciliation pass. The
Section 12 ("Layer 5 — Reporting") row:

> Single-record evidence bundle slice → `is_chain_valid: False` → Thread 6

should also be removed.

The Section 14 work-plan row for Thread 6 should be marked complete.
Thread 8 (documentation cleanup sweep) will pick this up as part of
the broader doc reconciliation; Thread 6 leaves the canonical doc
untouched on purpose to stay in its lane.

---

## 7. Honest-scope notes

- **Jailbreak patterns are not jailbreak resistance.** The
  recognizer emits signal; the model's safety alignment is the
  actual defense. Tex's role is governance and evidence, not model
  alignment. The deterministic layer catches the textbook attack
  cheap and fast; the LLM-backed specialists catch the
  sophisticated variants; the model's own training catches the rest.
  Defense-in-depth.
- **Invisible-Unicode decoding is best-effort.** The recognizer
  decodes Tag Block and variation-selector-supplement reliably
  (these are deterministic encodings). For variation-selector-base
  and bidi overrides, the recognizer reports the codepoints found
  but does not attempt a semantic decoding because there is no
  canonical inverse.
- **The slice verifier's witness is only as trustworthy as the
  source supplying it.** When the witness comes from Tex's own
  recorder (as it does via `build_slice_bundle()`), it's
  trustworthy in proportion to the recorder's mirror — same trust
  surface as the parent chain. When an external party supplies a
  witness for offline verification, they need their own copy of
  the chain or a SCITT receipt to validate it. This is the standard
  inclusion-proof trust model.

---

**End of Thread 6 changelog.**
