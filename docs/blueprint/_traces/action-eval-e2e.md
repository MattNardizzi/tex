# Trace: action-eval-e2e

**Claim under test:** The brain (PDP) and body (PEP/enforcement) are merged into one
live path that blocks forbidden actions AND emits an offline-verifiable receipt per
decision.

**Branch:** `feat/proof-carrying-gate`
**Verdict:** **PARTIAL** — the merged path EXISTS, is LIVE-wired, genuinely blocks, and
the receipt crypto is real and offline-verifiable, BUT the receipt is emitted only when
`TEX_SEAL_DECISIONS=1`, which **defaults OFF**. In the default deploy the
"emits a receipt per decision" half of the claim is a no-op. The receipt is emitted on
the `/v1/govern/decide` route (the network PEP), not on the strict `/evaluate` route.

---

## There are TWO request entrypoints; only one seals an ENFORCEMENT receipt

### Entrypoint A — strict typed `/evaluate` (brain only, no ENFORCEMENT receipt)
- `src/tex/api/routes.py:110` — `@router.post("/evaluate", ...)`
- `src/tex/api/routes.py:117-148` — `evaluate_action()` → `command.execute(domain_request)` (line 128)
- `src/tex/commands/evaluate_action.py:187` — `EvaluateActionCommand.execute()`
- `src/tex/commands/evaluate_action.py:214` — `self._pdp.evaluate(request=, policy=)` → PDP (brain)
- **No `seal_enforcement` call exists in `routes.py`** (grep: empty). The only seal on this
  path is the PDP's internal `seal_decision` (a `SealedFact(DECISION)`, not ENFORCEMENT),
  and it is itself flag-gated (see below). So `/evaluate` does NOT satisfy the "emits an
  ENFORCEMENT receipt per decision" half of the claim even when the flag is on — it seals a
  DECISION fact, a different kind.

### Entrypoint B — `/v1/govern/decide` (the PEP route — brain + body + ENFORCEMENT receipt)
This is the path that actually merges brain+body+receipt. Full call chain:

1. **Route (LIVE, mounted):**
   - `src/tex/main.py:1511-1512` — `from ...governance_standing_routes import build_governance_standing_router` / `app.include_router(build_governance_standing_router())`
   - `src/tex/api/governance_standing_routes.py:69-73` — `@router.post("/decide")` → `def decide(...)`
2. **Brain (two-tier PDP):**
   - `src/tex/api/governance_standing_routes.py:80-90` — `gov.decide(tenant=, action_type=, content=, ...)`
   - `src/tex/governance/standing.py:322` (`decide` → `_adjudicate_deep`) — Tier-2 deep adjudication
   - `src/tex/governance/standing.py:393` — `result = self._evaluate.execute(request)` → **EvaluateActionCommand.execute** (same brain as Entrypoint A)
   - `src/tex/commands/evaluate_action.py:214` — `self._pdp.evaluate(...)`
   - `src/tex/engine/pdp.py:243` — `PolicyDecisionPoint.evaluate(...)`
3. **Body / blocking (the boolean the PEP obeys = `released`):**
   - `src/tex/governance/standing.py:406-416` — `Verdict.PERMIT` → `released=True`
   - `src/tex/governance/standing.py:455-465` — `Verdict.ABSTAIN` → `released=False` (held for human)
   - `src/tex/governance/standing.py:468-477` — `Verdict.FORBID`/non-PERMIT → `released=False` (fail-closed)
   - `src/tex/governance/standing.py:479-489` — `_forbid_floor(...)` → `released=False` (Tier-1 structural floor, unsealed/off-surface agent — never reaches the deep evaluator)
4. **Receipt (proof-carrying ENFORCEMENT seal):**
   - `src/tex/api/governance_standing_routes.py:96` — `ledger = getattr(request.app.state, "decision_ledger", None)`
   - `src/tex/api/governance_standing_routes.py:97` — **`if ledger is not None:`** ← the gate
   - `src/tex/api/governance_standing_routes.py:99-122` — `seal_enforcement_decision(ledger, ..., verdict=, released=, ...)`
   - `src/tex/provenance/enforcement_seal.py:179-258` — `seal_enforcement_decision()` builds a `SealedFact(ENFORCEMENT)` and `ledger.append_sequenced(...)`
5. **SealedFact ledger (real crypto):**
   - `src/tex/provenance/ledger.py:384` — `class SealedFactLedger`
   - `src/tex/provenance/ledger.py:491-533` — `append_sequenced(fact, identity_key=, claimed_seq=)` (per-identity monotonic seq → a missing receipt is a detectable gap)
   - `src/tex/provenance/ledger.py:535-574` — `_append_locked()`: SHA-256 hash-chain (`record_hash` over `payload_sha256` + `previous_hash`) + ECDSA-P256 signature (`self._provider.sign`, line 551) + optional ML-DSA dual-sign envelope
   - `src/tex/events/_ecdsa_provider.py:29-40` — real `cryptography` lib, SECP256R1, SHA-256, DER (NOT a stub)
   - Offline verify: `verify_chain` (ledger.py:598), `verify_signatures` (ledger.py:653), `verify_no_gaps` (ledger.py:627)

---

## The defaults-off break (where the receipt half fails)

- `src/tex/main.py:875-878`:
  ```
  seal_decisions = os.environ.get("TEX_SEAL_DECISIONS","").strip().lower() in {"1","true","yes"}
  decision_ledger = SealedFactLedger() if seal_decisions else None
  ```
  `TEX_SEAL_DECISIONS` is **unset by default → `decision_ledger = None`**.
- `src/tex/main.py:881-888` — `decision_ledger` is passed into the PDP (`PolicyDecisionPoint(..., decision_ledger=decision_ledger)`).
- `src/tex/main.py:1755` — `app.state.decision_ledger = getattr(runtime.pdp, "_decision_ledger", None)` — the SAME (None-by-default) ledger is exposed for `/v1/govern/decide`.
- Therefore both seal paths short-circuit by default:
  - `src/tex/provenance/decision_seal.py:116-117` — `seal_decision`: `if ledger is None: return None` (DECISION seal, brain side)
  - `src/tex/provenance/enforcement_seal.py:208-209` — `seal_enforcement_decision`: `if ledger is None: return None` (ENFORCEMENT seal, body side)
  - `src/tex/api/governance_standing_routes.py:97` — the route's `if ledger is not None:` is False, so `seal_enforcement_decision` is never even called.

**Runtime confirmation (default flag off):**
```
$ PYTHONPATH=.../src python -c "from tex.main import build_runtime; rt=build_runtime(); print(rt.pdp._decision_ledger)"
pdp._decision_ledger (default): None
```

**Runtime confirmation (flag on — the mechanism is real):**
```
$ PYTHONPATH=.../src TEX_SEAL_DECISIONS=1 python   # seal a FORBID enforcement decision
sealed record_hash: 091426da13395491 kind: enforcement
verify_chain:      {'intact': True, 'checked': 1, 'break_at': None}
verify_signatures: {'valid': True, 'checked': 1, 'invalid_at': None}
verify_no_gaps:    {'complete': True, 'identities': 1, 'sequenced_records': 1, 'gaps': {}, 'duplicates': {}}
enforcement facts: 1
```
The seal, hash-chain, ECDSA-P256 signature, and the negative-space gap check are all real
and offline-verifiable when the ledger is wired.

---

## What is NOT wired (orphan body paths)

The proof-carrying-gate memory describes a `SealingGateObserver` / `build_proof_carrying_gate`
that turns every `TexGate` ruling into a sealed receipt. That observer is **NOT attached on
the live path**:

- `src/tex/main.py:1765-1767` — `app.state.standing_gate = build_standing_gate(app.state.standing_governance)` is called with **no `observer=` argument**.
- `src/tex/enforcement/standing_transport.py:121,144` — `observer` defaults to `None` → the gate uses its default `NullObserver`, so the in-process `standing_gate` seals **nothing**.
- `src/tex/enforcement/seal.py` (`SealingGateObserver`, `build_proof_carrying_gate`) and `src/tex/pep/sealing.py` (`seal_enforcement_decision` via the network PEP) are **never constructed by `tex.main` or any `api/` route** (grep: zero non-test, non-`enforcement/` construction sites). `tex.pep` is imported by nothing (ORPHAN). The in-process `TexGate` is also not invoked (`.check`/`.wrap`) by any live route — `app.state.standing_gate` is exposed for SDK callers to wrap their own callables, not driven by an HTTP request.
- The ENFORCEMENT receipt that DOES fire on a live request fires via the route-level
  `seal_enforcement_decision` call inside `/v1/govern/decide` (governance_standing_routes.py:99),
  i.e. wired directly in the route, not through the gate-observer abstraction.

The reflexive self-governor (`src/tex/selfgov/governor.py:692` `_seal_enforcement`) seals
ENFORCEMENT facts for **controller mutations**, not agent actions — a different (also real)
surface, reached via lazy imports from stores/evidence/c2pa, not from the action-eval route.

---

## Verdict rationale

- **Blocks forbidden actions: CONFIRMED, LIVE.** `/v1/govern/decide` → `StandingGovernance.decide`
  → deep PDP, with FORBID/ABSTAIN/floor → `released=False` (standing.py:457,470,484). The PDP
  itself sets `Verdict.FORBID` on any hard structural/contract/path violation
  (pdp.py:343-373, `_build_hard_forbid_routing_result` → `verdict=Verdict.FORBID` at pdp.py:738).
  This half holds regardless of the flag.
- **Emits an offline-verifiable receipt per decision: PARTIAL.** The mechanism is real,
  LIVE-wired, and offline-verifiable (ECDSA-P256 + SHA-256 hash-chain + per-identity gap
  detection), but it is **dormant by default** (`TEX_SEAL_DECISIONS` off → `ledger=None` →
  no-op). "Per decision" is true only with the flag on, and only on `/v1/govern/decide` — the
  strict `/evaluate` route emits no ENFORCEMENT receipt at all (only a DECISION fact, also
  flag-gated, also a different `SealedFactKind`).
- **"Merged into one live path": CONFIRMED for the structure, with the caveat above.** The
  brain (`EvaluateActionCommand` → `PolicyDecisionPoint`) and the body (`StandingGovernance`
  released-boolean + route-level `seal_enforcement_decision`) sit on a single mounted route
  (`/v1/govern/decide`). The seal is wired in-line in that route; it is the activation flag,
  not a missing wire, that gates the receipt.

**Net:** the proof-carrying gate is built and live-wired but ships **default-dormant**. Calling
the claim CONFIRMED would overstate a deploy that, out of the box, blocks but emits no receipt.
