# CLAIMS_ASPIRATIONAL

**Claims that are written about Tex but are not currently fully defensible.**

Do not include any of these in outreach copy, pitch decks, or customer
conversations until the underlying work moves to `CLAIMS_CURRENT.md`.

This file exists so you can see what's *almost* ready, what's blocking
it, and what would need to happen to promote it. Cross-reference with
`STUB_REGISTRY.md`.

---

## What changed in the May 2026 audit

The previous version of this file listed the VP Marketing, CISO, and
insurer evidence packets as aspirational. **That was wrong.** An
end-to-end audit (running real code, not just reading docstrings)
confirmed all three packet builders work and produce signed,
round-trippable artifacts. The P0 TODO markers in `pitch/*.py` are
stale `[done]` tracking-marks, not open holes.

What's actually aspirational about the pitch surfaces is **HTTP
exposure** — the functions exist and work, but there are no routes
for `/v1/exports/vp-marketing`, `/v1/exports/ciso`, or
`/v1/exports/insurer`. That's a one-day wiring task, tracked here.

---

## Pending: HTTP exposure for the pitch packet builders

**The aspirational claim.** "A buyer can request their tailored evidence
packet via a single HTTP call: `POST /v1/exports/insurer`,
`POST /v1/exports/ciso`, `POST /v1/exports/vp-marketing`."

**Status.** Functions exist and verified working:
- `tex.pitch.insurer_export.build_insurer_evidence_packet()` — produces
  ECDSA-P256-signed packet; offline-verifiable via
  `verify_insurer_evidence_packet()`
- `tex.pitch.ciso.build_mcp_risk_dossier()` — produces CISO dossier
- `tex.pitch.vp_marketing.build_brand_safety_dossier()` — produces
  VP Marketing dossier

What's missing: three FastAPI route handlers that call the existing
functions, plus the circular-import fix from `KNOWN_BUGS.md` #4.

**Estimated cost.** One day for all three routes plus the circular
import. Tier B work (buyer-facing surface).

---

## Pending: EU AI Act Article 50 disclosure attestation

**The aspirational claim.** "Every AI-generated output produced through
a Tex-governed agent is bound to a machine-readable Article 50
disclosure attestation, signed and verifiable end-to-end."

**Status.** Article 50 wrapper exists at
`src/tex/compliance/eu_ai_act/article_50.py`. 2 P0 TODOs gate the claim:
- `article_50.py:146` — bind c2pa_manifest → Article 50 disclosure attestation
- `article_50.py:149` — include the machine-readable disclosure flag

**Why this matters.** EU AI Act enforcement begins August 2026. The
VP Marketing pitch leans on this as a regulatory tailwind.

**What needs to happen.** Wire the C2PA manifest binding (depends on
the C2PA signer P0s also being addressed — see below). Then write the
integration test covering the full chain (action → disclosure → C2PA
manifest → verifier round-trip).

**Estimated cost.** Half-day if the C2PA signer is already done. 1–2
days otherwise.

---

## Pending: C2PA 2.2 regulator-grade content provenance

**The aspirational claim.** "Tex outputs C2PA 2.2-compliant content
credentials on every AI-generated message, with hybrid ML-DSA +
Ed25519 signing for post-quantum readiness."

**Status.** C2PA signer and verifier exist at `src/tex/c2pa/`. 8 P0
TODOs across signer, verifier, and manifest gate the regulator-grade
claim:
- `c2pa/signer.py:217–220` — canonicalize claim bytes per C2PA 2.2 §13,
  COSE_Sign1 envelope per §14, hybrid signing, OCSP staple
- `c2pa/verifier.py:273–274` — full COSE_Sign1 verification, trust list
  anchor validation
- `c2pa/manifest.py:148, 256` — CAWG 1.2 emission, complete manifest
  assembly

**Current state.** The C2PA layer signs and verifies in a structurally
correct mode but the wire format is not yet regulator-grade per the
C2PA 2.2 spec. The file's own docstring is honest about this.

**Why this matters.** This is the "evidence-grade adjudication"
differentiator vs. Noma / Zenity / Cisco AGT. Without working full-spec
C2PA, the differentiation is structural rather than wire-correct.

**What needs to happen.** Land the signer's COSE_Sign1 implementation
first (deepest dependency). Verifier and manifest assembly are then a
day each. Hybrid signing depends on the pqcrypto/ML-DSA P0s also
resolving.

**Estimated cost.** 3–5 days. Highest-leverage block of work for the
regulator-grade story.

---

## Pending: ML-DSA hybrid post-quantum evidence signing

**The aspirational claim.** "Every evidence record is signed with a
hybrid ML-DSA + Ed25519 signature; the chain is verifiable today and
remains verifiable after a quantum-capable adversary breaks Ed25519."

**Status.** Provider abstractions exist at `src/tex/pqcrypto/`. 12 P0
TODOs gate the claim:
- `pqcrypto/ml_dsa.py:119, 144, 166` — liboqs binding for
  sign/verify/keygen
- `pqcrypto/hybrid.py:115, 159, 204` — composite signature
  emit/split/keypair
- `pqcrypto/evidence_chain_signer.py:124–176` — canonicalization +
  ML-DSA sign/verify

**Why this matters.** Post-quantum signing is a defensible "and here's
why Tex is durable" point. Without it, the evidence chain is signed
with Ed25519 + HMAC alone — fine for today, not fine for a regulator
who asks about 2030+ verifiability.

**What needs to happen.** Requires `liboqs` in the deployment
environment. Code-side change is ~1 day; environment + CI plumbing is
the bigger lift.

**Estimated cost.** 2–3 days including env work.

---

## Pending: NAIC cyber-rider compliance wrapper

**The aspirational claim.** "Tex can emit a NAIC-vocabulary cyber
insurance AI rider packet on demand."

**Status.** Underlying capability already exists in
`tex.pitch.insurer_export.build_insurer_evidence_packet()` (verified
working, produces ECDSA-signed packets). What's missing is the
NAIC-named wrapper at `src/tex/compliance/naic/cyber_rider.py`
(currently a 15-line `NotImplementedError` stub).

**What needs to happen.** Turn `cyber_rider.py` into a thin wrapper
that calls `build_insurer_evidence_packet()` and re-shapes the output
to NAIC vocabulary. Then either expose it as `POST
/v1/compliance/naic/cyber-rider` or wire it into the pitch HTTP routes
(item above).

**Estimated cost.** Half-day. The hard part (signed evidence
assembly) is done.

---

## Pending: EU AI Act Article 17 + 26 evidence emitters

**The aspirational claim.** "Tex emits Article 17 (QMS) and Article 26
(deployer obligations) evidence packets for EU AI Act compliance."

**Status.** Both are `NotImplementedError` stubs:
- `src/tex/compliance/eu_ai_act/article_17.py`
- `src/tex/compliance/eu_ai_act/article_26.py`

**Why this matters.** Full EU AI Act August 2026 positioning needs
these plus Article 50.

**What needs to happen.** Implement each as an emitter that pulls
relevant fields from the evidence chain and governance snapshots and
shapes them per the regulation. Pattern similar to the existing
`article_50.py` (which is partial but the shape is established).

**Estimated cost.** 2–3 days each. Lower priority than the C2PA
signer work because Article 50 is the load-bearing one for current
GTM.

---

## Pending: NIST AI RMF profile emitter

**The aspirational claim.** "Tex emits a NIST AI RMF profile evidence
packet for US enterprise procurement."

**Status.** `src/tex/compliance/nist/ai_rmf.py` is a
`NotImplementedError` stub.

**Why this matters.** US enterprise buyers (especially federal
adjacent) ask for this by name during procurement.

**What needs to happen.** Map Tex defenses to NIST AI RMF
Govern/Map/Measure/Manage functions and emit a packet binding the
chain.

**Estimated cost.** 2 days.

---

## How to promote a claim from this file to CLAIMS_CURRENT.md

1. Land the underlying code (the P0 TODOs in the relevant files
   resolved or the missing route wired).
2. Add a test that exercises the live `/v1/guardrail` (or
   `/evaluate` or the new route) path end-to-end and asserts the
   claim.
3. Write the claim entry in `CLAIMS_CURRENT.md` using the existing
   format (claim text, source paper anchors if any, modules, tests,
   demo, competitive differentiation, honest scope statement).
4. Remove the corresponding entry from this file.
5. Run `python scripts/audit.py --rebuild-data` to refresh the audit
   data file.
