# Tex Roadmap — Proof-Carrying Control Plane

> Consolidated build checklist derived from a full-thread audit + research synthesis (June 2026).
> Direction: **Tex can only ever say or do what it can prove from a sealed, replayable fact.** Beat the
> detect-and-dashboard incumbents (Zenity / Noma / Pillar / Palo Alto / Lasso) by being *structural +
> cryptographic*, not a better classifier. See `MEMORY` notes `tex-sota-blueprint`, `tex-abstain-boundary`.

**Tags:** `[today]` buildable now on verified code · `[research]` net-new / research-grade (scope as a real project) ·
`[cut]` do not build / delete. **Effort:** S = days · M = 1–2 wk · L = 3 wk+.

---

## Already real & verified (NOT remaining — do not rebuild)
Fail-closed PDP (`engine/pdp.py`) · hash-chained ECDSA evidence ledger (`provenance/ledger.py`) · in-kernel eBPF PEP
(`pep/kernel/`) · RCPS/CRC math (`engine/crc_gate.py`) · anytime-valid OPE (`learning/ope.py`) · two-sided certified
band · CaMeL/IFC structural floor (`camel/`, `specialists/structural_floor.py`) · DTMC lookahead (`systemic/probguard.py`,
unwired) · e-process organ (`drift/_anytime_valid.py`, unwired to risk streams) · grounded text-voice + Bayesian-surprise
selector (`vigil/`) · Vigil hold/seal surface (`tex-systems`).

---

## Top 5 (start here)
- [ ] Phase 0 credibility floor — CI + close the no-auth routes (§A)
- [ ] Cut `nanozk` — the one reputation-risky thing in the repo (§B)
- [ ] WSR bound + LTT joint certificate — the publishable guarantee, ~1–2 days (§E)
- [ ] Durability — wire Postgres so a restart doesn't erase the evidence chain (§C)
- [ ] The spoken-voice loop — keystone demo, client already written (§F)

---

## A. Credibility floor — do first  `[today]`
- [ ] Add CI (GitHub Actions) running the ~242 existing tests — none exists today · S
- [ ] Close the 4 no-auth route groups: `ecosystem_twin / tee / vet / zkprov` (incl. unauthenticated identity-doc revocation, `vet_routes.py:288`) · S
- [x] Flip auth fail-closed — no `_ANONYMOUS`-gets-all-scopes default in prod · S — done: the anonymous everything-allowed fallback is reachable ONLY in a non-production `TEX_APP_ENV`; production-like env (or `TEX_REQUIRE_AUTH=1`) with no keys fails closed (401). `api/auth.py:_is_production_like`. Tests: `tests/test_unblock_auth_failclosed.py`.
- [ ] Lock down CORS — `allow_origins=["*"]` + `allow_credentials=True` (`main.py:1291`) · S
- [~] delete stale `_pending` test — **done** (`tests/_pending/` removed: imported nonexistent `tex.pitch`, wired nowhere; −23 failures). Fix brittle/leaky tests — **partly deferred**: root cause is the discovery scheduler auto-starting + seeding stores during the test app lifespan (fresh stores are independent — verified), not simple cross-instance leakage; `governance_history`(5)/`discovery`(4) + order-dependent `causal/`(1) need the scheduler quiesced / store-lifecycle reset, which is discovery/durable-track architecture. · S

## B. Cut the theater / honesty  `[cut]`
- [ ] Delete `nanozk` (`nanozk/layerwise_prover.py` + `latticefold_plus.py`) — HMAC-as-lattice + fabricated norm; replace source-label need with real HMAC-SHA-256 trust tags · S
- [ ] Quarantine `synthesize_test_eat_jwt` to tests only · S
- [ ] Stop presenting ML-DSA as live (ECDSA-P256 actually runs) and attestation as producing real tokens (verifier-only) · doc
- [ ] Fix factual errors: `c2pa/ledger.py` does not exist → it's `provenance/ledger.py`; say "the **chain** proves integrity," not the standalone signature · doc
- [ ] Stop marketing keyword specialists (`agentarmor/attriguard/clawguard`) as "semantic reasoning" · doc
- [ ] Prune dead weight: `_pending/` tree (34 modules) + unwired compliance layer (14 modules / ~1,900 LOC, 0 wired) · M
- [ ] Publish a `SELF_AUDIT` documenting all the above (owning limits = differentiation) · S

## C. Durability / production-readiness  `[today–research]`
- [ ] Wire the existing Postgres write-through stores as default (behind `DATABASE_URL`) so state/evidence survives restart — or explicitly position as single-process pilot · M
- [ ] Fix Helm contradiction — `replicas: 2` is impossible with in-memory state (inconsistent verdicts, broken chains) · S
- [ ] Provide a real Dockerfile for the web image (`ghcr.io/...tex:latest` has none); `render.yaml` only defines the worker; `.env.example` is empty · M
- [ ] Real observability export (OTel/Prometheus) — today it's homegrown in-process counters · M

## D. Core "truth model" upgrade — Proof-Carrying Control Plane  `[mixed]`
- [ ] Sealed truth object — generalize `provenance/ledger.py` into typed `SealedFact`s (DECISION/ENFORCEMENT/DRIFT/BLAME/IDENTITY/ANSWER), serialized as one canonical PCVR per action · L
- [ ] Multiplicative e-value spine — compose CRC + OPE + drift + per-agent deviation + voice-error into one Ville-bounded sealed scalar · M
- [ ] Durable Governance State Vector Σ — path-dependent governance, reconstructible-by-replay (also fixes in-memory gap) · M
- [ ] Wire the EXISTING `systemic/probguard.py` DTMC+PCTL lookahead into the PDP as a predictive ABSTAIN dimension · M
- [ ] Four-valued RV4 LTLf (permanent-violation=FORBID vs recoverable=ABSTAIN) feeding `engine/hold.py` · M
- [ ] FIDES dual-axis lattice (confidentiality × integrity) upgrade to `camel/capability.py` · M
- [ ] Rule-of-Two structural contract (untrusted-input ∧ sensitive-access ∧ state-change → FORBID) · S
- [ ] Route CaMeL interpreter denial → PDP structural FORBID (instead of deciding locally) · S
- [ ] Offline evidence bundle + standalone verifier (court-exhibit core; mostly packaging what's verified) · M
- [ ] `[research]` SCITT transparency log + witness cosigning (external non-equivocation; Go sidecar + actual witnesses) · L
- [ ] `[research]` Real TEE attestation producer (needs a confidential VM) · L
- [ ] Banzhaf alongside Shapley (`causal/lsh_shapley.py`); Koopman spectrum + ResDMD residual alarm (`systemic/_koopman.py`) · S–M

## E. The abstain boundary — the trust-critical layer  `[mixed]`
**Buildable today (on verified code):**
- [ ] WSR betting confidence sequence into `learning/ope.py:190` (current Howard bound is loose) · S — do first
- [ ] LTT joint two-sided certificate replacing the two independent sweeps in `engine/crc_gate.py`, + ε-collar · S (~1–2 days)
- [ ] SCRC acted-set conditioning of the risk estimand (measure "unsafe among emitted PERMITs") · S
- [ ] Rewrite `_determine_verdict` / `_should_abstain` (`engine/router.py:428/507`) to the unified R0–R4 rule (magic constants → one selective-risk object) · M
- [ ] Wire the EXISTING `drift/_anytime_valid.py` e-process to false-permit + abstain-rate streams → auto-tighten on breach · S–M
- [ ] Seal-as-label return path — add the `CalibrationRecord` constructor from a human seal (zero exist today); gate loosening through PENDING→APPROVED lifecycle; tightening is free · M

**Research-grade (scope honestly — not grafts):**
- [ ] `[research]` Action-class structural ABSTAIN floor (irreversible/high-blast) — the #1 adversarial defense; net-new ontology project (nothing exists in any verdict path) · L
- [ ] `[research]` Credal-conformal typed hold (epistemic/aleatoric via per-decision p-values) · M
- [ ] `[research]` EPIG decision-targeted resolving-question (needs a Layer-6 posterior; keep deterministic map as fallback) · M
- [ ] `[research]` Worst-case-valid CRC (ε-collar calibrated on an adversarial red-team corpus) · M

**Cut:** `[cut]` pseudo-random hold-widening (fights determinism) · runtime L2D learned head (guarantee comes from the gate) · autonomous loosening (must stay human-gated).

### Invariant to enforce (the trust contract)
- [ ] Hard rule in the PDP→voice boundary: **only an ABSTAIN may ever produce a user-facing hold** — no PERMIT/FORBID ever surfaces to the operator · S
- [ ] Hard rule: uncertainty may only ever resolve to ABSTAIN; probabilistic signals may only LOWER a verdict, never raise it (already enforced by CRC gate — make it an explicit, tested invariant) · S

## F. The voice layer (keystone)  `[research]`
- [ ] Build the server-side spoken loop: `/v1/voice/token`, `/v1/ask`, `/v1/speak` + self-hosted STT/TTS gateway (React client already written in `tex-systems`) · L + GPU infra
- [ ] NLI faithfulness/entailment gate on the grounded answerer (drop any claim not entailed by a sealed fact → abstain) · M
- [ ] Deterministic verbalization of load-bearing facts (verdict/hash/bound — zero LLM in that path) · S
- [ ] Seal each spoken answer as a voice-attestation record; add `learning:write` scope to the production proxy key · S

## G. Proof-of-superiority / validation  `[mixed]`
- [ ] Adaptive red-team harness (AgentDojo + "The Attacker Moves Second") in CI, results sealed into the ledger · M
- [ ] The "Replay Trial" flagship demo (structural FORBID survives 10 paraphrases → in-kernel block → offline tamper-verify) · M
- [ ] The honest-decline demo (Tex refuses a question with no sealed evidence, names the missing fact) · S

---

## Suggested sequence
1. **A** + **B** — clear the deck and cut the lie (the credibility floor blocks every provability claim).
2. **E (buildable-today)** + **D (core)** — the joint guarantee + the sealed truth model.
3. **C** — durability (so the evidence survives a restart).
4. **F** — the spoken-voice loop.
5. **G** — the proof harness + flagship demos.
6. **Research organs last** (D/E/F `[research]` items) — each must fail closed to today's behavior.

## Key references
Policies on Paths (arXiv:2603.16586) · Pro2Guard (2508.00500) · CaMeL (2503.18813) · FIDES (2505.23643) ·
"The Attacker Moves Second" (Nasr 2025) · Safe Testing (Grünwald, JRSS-B 2024) · Game-Theoretic Statistics (Ramdas 2023) ·
RCPS (Bates/Angelopoulos, JACM 2021) · Learn-then-Test (2110.01052) · WSR betting CS (2023) · conformal factuality
(Mohri–Hashimoto, ICML 2024) · AI-control (2501.17315) · adaptive monitor attacks (2510.09462, 2511.02997) · SCITT
(draft-ietf-scitt-architecture).
