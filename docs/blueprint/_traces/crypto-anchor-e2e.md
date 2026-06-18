# Trace: crypto-anchor-e2e

**Claim under test:** Sealed facts are signed with post-quantum crypto, hash-chained, and anchored to an external un-backfillable source.

**Verdict: PARTIAL** — every leg of the spine is REAL code (not stubs), and on
this machine the default signature scheme for a `SealedFactLedger` is genuinely
**dual ECDSA-P256 + post-quantum ML-DSA-65** (FIPS 204, native backend), with a
real SHA-256 hash chain and a real, offline-verified RFC-3161 external anchor.
The claim falls short of CONFIRMED on two wiring facts: (1) the sealed-fact ledger
is **default-OFF in the running app** (`TEX_SEAL_DECISIONS` unset ⇒
`decision_ledger = None`, the PDP/PEP seal nothing); and (2) the external anchor
that is actually **committed on disk** binds the **gix decision-log** tree-head
(`origin=tex.local/gix-decision-log`), and the auto-anchor wiring of the
sealed-fact ledger's own chain is gated behind TWO default-off flags. Anchoring
of a `SealedFactLedger` chain is proven to work end-to-end only via scripts /
capstone, and against a REAL TSA only for the gix log.

---

## The three legs, code-verified

### Leg 1 — Post-quantum signing (REAL, dual-signs by default on this box)

- `SealedFact` / `SealedFactRecord` carry an additive `seal_envelope: SealEnvelope | None`
  over `record_hash` — `src/tex/provenance/models.py:316-383` (record at `:359-383`,
  envelope models `SealSignature`/`SealEnvelope` at `:90-138`).
- `SealedFactLedger._append_locked` signs the `record_hash` with the **primary
  ECDSA-P256** provider, then dual-signs the SAME `record_hash` via a
  `CryptoAgileSealer` **when a PQ backend is live** —
  `src/tex/provenance/ledger.py:551-560`. `enable_pq=True` is the constructor
  default (`:421`), and the sealer is built at `:439-446`.
- `CryptoAgileSealer.from_primary` adds an ML-DSA-65 signer via `make_pq_signer`,
  which returns `None` (degrade to ECDSA-only, logged WARNING) when no backend
  exists — `src/tex/provenance/seal_envelope.py:98-163`. Default PQ algorithm =
  `ML_DSA_65` (`:71`).
- The ML-DSA provider is a real implementation with graceful fallback:
  `_NativeBackend` (pyca/cryptography ≥48, OpenSSL ≥3.5) → `_LiboqsBackend`
  (liboqs) → `None`; hard `RuntimeError` on use if no backend, never a heuristic
  — `src/tex/pqcrypto/ml_dsa.py:95-264`. Signing dispatches to the backend at
  `:295-311`. The dispatcher resolving `ML_DSA_65 → MlDsaProvider` is
  `src/tex/pqcrypto/algorithm_agility.py:153-160`.

**Default scheme on THIS machine (empirically run, PYTHONPATH=src):**
- `active_backend_id()` ⇒ `pyca-cryptography-native`.
- A default `SealedFactLedger()` reports `is_dual_signed=True`,
  `pq_signing_key_id='tex-sealed-fact-ledger-ml-dsa'`, ML-DSA pubkey = 1952 bytes
  (FIPS 204 ML-DSA-65), signature = 3309 bytes.
- `append()` produces a record whose `seal_envelope.algorithms() ==
  ('ecdsa-p256','ml-dsa-65')`, `is_dual=True`, `seal_version='2'`.
- `verify_signatures()` (ECDSA) and `verify_seal_envelopes()` (ECDSA+ML-DSA both
  valid: `dual_signed=True, ecdsa_valid=True, pq_valid=True`) pass.

So the default scheme that ACTUALLY RUNS for a `SealedFactLedger` here is
dual ECDSA-P256 + ML-DSA-65 — the post-quantum claim is true for this object.

> CAVEAT (separate ledger): the `evidence` chain (`evidence/seal.py`) is a
> DIFFERENT signer that loads a **persisted key** and on startup logs
> `"chain signer active with CLASSICAL algorithm ecdsa-p256 (no post-quantum
> guarantee)"` (`src/tex/evidence/seal.py:250-253`). It is ECDSA-only. Do not
> conflate the two: the SealedFactLedger dual-signs; the evidence chain does not.

### Leg 2 — Hash chaining (REAL)

- `record_hash = SHA256(stable_json({payload_sha256, previous_hash}))`, append-only,
  `previous_hash` = prior record's hash — `src/tex/provenance/ledger.py:540-550`.
- `verify_chain()` replays from genesis and reports `break_at` on any
  reorder/delete/tamper (recomputes `payload_sha256` from the fact's own
  `canonical_payload()`, so a tamper inside the fact breaks it) — `:598-625`.
- The dual signature is explicitly OUTSIDE the chained payload (additive), so the
  chain is byte-identical whether or not PQ is active — `:553-560`.
- `verify_no_gaps()` is the negative-space (per-identity sequence) check —
  `:627-651`, fed by `append_sequenced` (`:491-533`).
- Empirically: a 1-field tamper inside a sealed fact yields
  `verify_chain → intact=False, break_at=0` (selftest run, below).

### Leg 3 — External anchor (REAL crypto, REAL freetsa token on disk; binds the gix log)

- `src/tex/interchange/external_anchor.py` is a self-contained RFC-3161 verifier
  that does the **full CMS signature check** against a **pinned** TSA cert —
  `verify_anchor_receipt` `:394-566`; CMS verify `_verify_cms_signature`
  `:615-678`, public-key verify `:681-732`, pin check `_is_pinned` `:735-750`,
  sole-`id-kp-timeStamping`-EKU `:753-763`. It recomputes the messageImprint from
  structured checkpoint fields (`:286-289`), never trusting the stored digest.
- The bundle layer wires anchor into the sealed-fact path:
  `anchor_ledger_checkpoint(ledger, anchor_fn=...)` builds a gix checkpoint over
  the ledger's own `record_hash`es (`src/tex/provenance/bundle.py:231-253`), and
  `verify_sealed_fact_bundle(..., pinned_tsa_cert_der=...)` recomputes the Merkle
  root from the records and verifies the token, setting `externally_anchored`
  only on success (`:437-461`, report field `:186`).
- On-disk artifacts (`anchors/`): `checkpoint_anchors.jsonl` (a real 4641-byte
  freetsa.org TimeStampResp), `PUBLISHED_TREE_HEADS.jsonl`, pinned
  `tsa/freetsa_cacert.pem` + `tsa/PIN_STATEMENT.md`.

**Empirically verified (PYTHONPATH=src):** loading the first
`checkpoint_anchors.jsonl` record and calling `verify_anchor_receipt` against the
pinned freetsa cert ⇒ `ok=True`, `authority='freetsa.org'`,
`gen_time=2026-06-17 15:40:50+00:00`, fingerprint
`32e841a9...` (matches `PUBLISHED_TREE_HEADS.jsonl` and the PIN_STATEMENT). This
is a genuine, externally-attested, key-independent time anchor — NOT a stub.

> CAVEAT (which chain is anchored): the on-disk anchor binds
> `origin="tex.local/gix-decision-log"`, `tree_size=7` — the **gix decision-log**
> tree-head, not demonstrably the `SealedFactLedger`'s chain. The gix publisher
> CAN be pointed at the sealed-fact ledger (`build_checkpoint_publisher` reads
> `decision_ledger.list_all()` record_hashes — `src/tex/interchange/gix.py:680-685`),
> so the architecture supports anchoring the sealed-fact chain, but the committed
> evidence anchors the gix log.

---

## End-to-end call path (the wired-when-enabled spine)

```
# in-process gate path
enforcement/seal.py:build_proof_carrying_gate (:86)
  -> SealingGateObserver.__call__ (:71)
    -> provenance/enforcement_seal.py:seal_enforcement (:138)
      -> build_enforcement_fact -> SealedFact(kind=ENFORCEMENT)  (:56)
      -> SealedFactLedger.append_sequenced (:167)
        -> _append_locked: SHA256 chain + ECDSA sign + ML-DSA dual-sign
           provenance/ledger.py:551-560

# api/PEP path  (LIVE route, mounted)
main.py:1511-1512  app.include_router(build_governance_standing_router())
  -> api/governance_standing_routes.py POST /v1/govern/decide (:73)
    -> ledger = app.state.decision_ledger  (:96)   # None unless TEX_SEAL_DECISIONS=1
    -> seal_enforcement_decision(ledger, ...)  (:99-122)
      -> SealedFactLedger.append_sequenced -> _append_locked (dual-sign + chain)

# reflexive self-governor path (selfgov=LIVE)
selfgov/governor.py:_seal_enforcement (:692) -> binding.ledger.append (:737)
   # binding.ledger is the SAME opt-in decision_ledger (default None, :33)

# anchor (scripts / capstone; not auto in the request path)
provenance/bundle.py:anchor_ledger_checkpoint (:231)
  -> interchange/external_anchor.submit_anchor / verify_anchor_receipt
scripts/anchor_checkpoint.py (daily job, gated TEX_EVIDENCE_ANCHOR_ENABLE)
  -> anchors/checkpoint_anchors.jsonl  (real freetsa token, origin=gix-decision-log)
```

**App-state binding (real):** `main.py:878` `decision_ledger = SealedFactLedger()
if seal_decisions else None`; `main.py:1755`
`app.state.decision_ledger = getattr(runtime.pdp, "_decision_ledger", None)`.
Built `create_app()` with `TEX_SEAL_DECISIONS=1` ⇒ `app.state.decision_ledger` is
a `SealedFactLedger` with `is_dual_signed=True`. With the flag unset ⇒ `None`.

---

## Where the path breaks / is gated (the reasons this is PARTIAL not CONFIRMED)

1. **Sealing is default-OFF in the running app.** `TEX_SEAL_DECISIONS` unset ⇒
   `decision_ledger = None` (`main.py:869-878`); the PDP, the `/v1/govern/decide`
   PEP route (`governance_standing_routes.py:96-97`), and the reflexive governor
   (`selfgov/governor.py:33,708`) all seal NOTHING by default. So in a default
   deployment, no sealed facts are produced at all — the PQ/chain/anchor
   guarantees apply only once the operator opts in. (The flag is documented as
   default-off because the ledger is in-memory and unbounded without the Postgres
   write-through track.)

2. **Auto-anchoring of the sealed-fact chain needs TWO default-off flags.** The
   gix publisher that would feed the sealed-fact ledger's record_hashes to the
   anchor job requires BOTH `TEX_SEAL_DECISIONS=1` AND `TEX_GIX_WITNESS=1`
   (`interchange/gix.py:663-687`), and the daily anchor job itself is gated on
   `TEX_EVIDENCE_ANCHOR_ENABLE` (`scripts/anchor_checkpoint.py:153-155`). None of
   these is on by default; "dev stays fully offline."

3. **The committed real anchor binds the gix decision-log, not a demonstrated
   sealed-fact chain.** `anchors/checkpoint_anchors.jsonl` has
   `origin=tex.local/gix-decision-log`. End-to-end anchoring of a
   `SealedFactLedger` chain is proven only via `scripts/verify_enforcement_receipt.py`
   and `capstone/` — and there against a **LOCAL throwaway TSA**
   (`mint_local_tsa`, `verify_enforcement_receipt.py:171-183`), which the script
   itself says "proves nothing about real wall-clock time (only the freetsa path
   does that)". The REAL-TSA path is exercised for the gix log, not (in committed
   evidence) for a SealedFactLedger.

4. **Maturity tags are honest and sub-production.** Enforcement seal is
   `RESEARCH_SOLID` and its docstring states "NOT externally time-anchored yet —
   RFC-3161 anchoring of this ledger is the next phase"
   (`provenance/enforcement_seal.py:22-27,53`); `enforcement/seal.py:18-23` says
   the same. `external_anchor.py:76-78` self-labels `research-early`. These are
   "real live crypto, newly wired, not yet a production default" — consistent
   with the code, not overstated.

---

## Empirical confirmations (all run with PYTHONPATH=/Users/matthewnardizzi/dev/tex/src)

- `active_backend_id() == 'pyca-cryptography-native'` (native FIPS-204 ML-DSA live).
- Default `SealedFactLedger().append()` ⇒ `seal_envelope.algorithms() ==
  ('ecdsa-p256','ml-dsa-65')`, `is_dual=True`; `verify_chain` / `verify_signatures`
  / `verify_seal_envelopes` all pass (`pq_valid=True`).
- `create_app()` with `TEX_SEAL_DECISIONS=1` ⇒ `app.state.decision_ledger`
  dual-signed; without the flag ⇒ `None`.
- On-disk freetsa anchor record ⇒ `verify_anchor_receipt(ok=True,
  gen_time=2026-06-17T15:40:50Z, authority=freetsa.org)` against the pinned cert.
- `scripts/verify_enforcement_receipt.py --selftest` ⇒ "ALL CLAIMS HELD": FORBID
  blocked, PERMIT ran, identity attested, chain+signatures verified,
  `externally_anchored=True` (local demo TSA), tamper rejected (`break_at=0`).

## Bottom line

All three legs are REAL implementations, not hollow stubs, and the default
signature scheme for a `SealedFactLedger` on this machine genuinely runs
post-quantum ML-DSA-65 alongside ECDSA-P256 over a SHA-256 hash chain, with a
real RFC-3161 verifier and a real freetsa.org token committed on disk. The claim
is PARTIAL because in the default running app no sealed facts are produced
(`TEX_SEAL_DECISIONS` off), the sealed-fact chain's auto-anchoring is double-gated
off, and the committed real-TSA anchor binds the gix decision-log rather than a
demonstrated sealed-fact chain (whose real-TSA anchoring is a "next-phase",
honestly-labelled, library-only-today capability).
