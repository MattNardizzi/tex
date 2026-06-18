# Subsystem Dossier: `provenance` — the Provenance Engine

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/provenance/` (15 `.py` files).
> Branch: `feat/proof-carrying-gate`. All claims below are code-verified; `.md`/docstring
> claims that could not be confirmed in code are tagged **(claim, unverified)**.
> Crypto behaviour was confirmed by running the code with
> `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src` (see Implementation Reality).

---

## Overview

The `provenance` package is two interlocking primitives sharing one cryptographic substrate:

1. **Identity-by-behaviour** (`signature.py`, `distance.py`, `engine.py`, `feed.py`,
   `delegation.py`, `intent.py`): derive a *content-free* behavioural fingerprint of an
   agent from the gate's action-ledger stream, resolve it against known identities, and
   seal the outcome (BIRTH / SIGHTING / REIDENTIFIED / DRIFT / SLEPT / WOKE) into an
   append-only, hash-chained, signed transparency log. This is "Certificate Transparency
   for agents." Survives credential rotation, rename, and total absence of a self-declared
   identity, because the behaviour is what it is.

2. **The sealed-truth object / PCVR** (`models.py`, `ledger.py`, `seal_envelope.py`,
   `bundle.py`, and the four seal seams `decision_seal.py`, `attempt_seal.py`,
   `enforcement_seal.py`, `transcript_seal.py`): a typed `SealedFact`
   (ATTEMPT/DECISION/ENFORCEMENT/DRIFT/BLAME/IDENTITY/ANSWER/VERDICT_TRANSCRIPT) sealed
   into a `SealedFactLedger` becomes a **Proof-Carrying Verdict Record (PCVR)** —
   the claim, an optional embedded e-value proof, and the cryptographic linkage, all
   verifiable offline by anyone holding the public key. `bundle.py` packages a ledger into
   a portable court-exhibit JSON artifact with a *standalone, runtime-free* verifier.

The whole package's discipline is the **witness stance**: it never asserts identity, it
states a graded confidence and seals the evidence; the merge/split decision is a human's,
surfaced as a held decision. Crypto degrades **honestly** to ECDSA-only when no
post-quantum backend is present (it never fakes a PQ signature).

**Wiring at a glance:** the behavioural engine + feed + delegation graph are **LIVE**
(built in `main.py:build_runtime`, fed off the live evaluate hot path via
`feed.note_action`, surfaced at `/v1/provenance/*` and `/v1/discovery/.../held`). The
`SealedFactLedger` is **conditionally LIVE** — built only under `TEX_SEAL_DECISIONS=1`,
wired to the PDP, which then seals ATTEMPT + DECISION facts. `enforcement_seal`,
`transcript_seal`, and `bundle` are real, fully implemented, and reachable through public
APIs but their live-runtime callers (`enforcement/seal.py` observer, `tex.pep`,
`selfgov.governor`, capstone) are **not wired into `build_runtime`** in the default boot —
they are INDIRECT/opt-in (see Wiring).

---

## File Inventory

| File | Lines | Role |
|---|---:|---|
| `__init__.py` | 93 | Public surface re-exports + `build_default_provenance_engine()` factory. |
| `signature.py` | 324 | `BehavioralSignature` — content-free behavioural fingerprint built from `ActionLedgerEntry` windows; stable SHA-256 signature hash; `WARM_OBSERVATION_THRESHOLD=8`. |
| `distance.py` | 162 | `behavioral_confidence(a,b)` — fused, calibrated same-actor confidence in [0,1]; anchor floors + no-anchor cap; Jaccard + cosine + scalar proximity. |
| `engine.py` | 827 | `BehavioralProvenanceEngine` — stateful resolver: observe → resolve → seal; BIRTH/SIGHTING/REIDENTIFIED/DRIFT; discovery `register_birth`; SLEPT/WOKE; coverage boundary; intent drift; event-sourcing replay (`rebuild_from_ledger`). |
| `ledger.py` | 545 | `BehavioralProvenanceLedger` (identity events) **and** `SealedFactLedger` (typed PCVRs) — append-only, SHA-256 hash-chained, ECDSA-P256 + optional ML-DSA-65 dual-signed; `verify_chain`/`verify_signatures`/`verify_seal_envelopes`. |
| `models.py` | 382 | Pydantic models: `ProvenanceEventKind`, `ProvenanceMatch`, `ProvenanceResolution`, `ProvenanceRecord`, `BehavioralBirthCertificate`, `CoverageBoundary`, `SealSignature`/`SealEnvelope`/`SealPublicKey`, `SealedFactKind`, `SealedFact`, `SealedFactRecord`. |
| `seal_envelope.py` | 350 | `CryptoAgileSealer` (ECDSA-P256 primary + ML-DSA-65 PQ) → `SealEnvelope`; `verify_envelope` against *pinned* keys; honest degrade when no PQ backend. |
| `feed.py` | 353 | `ContinuousProvenanceFeed` — fires `engine.observe()` off the gate stream on a background worker; `note_action` (hot-path, non-blocking); `HeldDecision`/`HeldDecisionSink` (the one voice surface). |
| `delegation.py` | 284 | `SealedDelegationGraph` — append-only, hash-chained, ECDSA-signed agent→agent delegation edges; `is_load_bearing` for the dormancy controller. |
| `intent.py` | 280 | Declared-vs-observed intent: `CAPABILITY_TAXONOMY`, `TaxonomyIntentScorer` (deterministic, content-free, offline), `IntentScorer` protocol, `IntentAlignment`. |
| `bundle.py` | 483 | `SealedFactBundle` (portable JSON) + `verify_sealed_fact_bundle` (standalone offline verifier: chain replay, pinned-key authorship, e-value composition replay, PQ envelope check, RFC-3161 external anchor check). |
| `decision_seal.py` | 130 | M0 seam: `build_decision_fact`/`seal_decision` — seal one `SealedFact(DECISION)` per verdict. Fail-closed, observation-only. |
| `attempt_seal.py` | 152 | Attempt-hook seam: `build_attempt_fact`/`seal_attempt` — seal one `SealedFact(ATTEMPT)` at `evaluate()` entry (L3 count-conservation upstream half). |
| `enforcement_seal.py` | 226 | `build_enforcement_fact`/`seal_enforcement` (from a `GateEvent`) + `seal_enforcement_decision` (from a PEP decision) — seal `SealedFact(ENFORCEMENT)`. |
| `transcript_seal.py` | 159 | Opt-in (`TEX_SEAL_VERDICT_TRANSCRIPT`) seam: `seal_verdict_transcript` — seal `SealedFact(VERDICT_TRANSCRIPT)` (transcript hash + monotonicity witness). |

Total: **4,750** lines.

---

## Internal Architecture

### Data flow (identity-by-behaviour)

```
ActionLedgerEntry[]  ──BehavioralSignature.from_actions──▶  BehavioralSignature
                                                               │
                          behavioral_confidence(a,b)  ◀────────┤  (distance.py)
                                                               ▼
   engine.observe(agent_id, entries, signal_tier)  ──resolve──▶  _seal_* ──▶ ledger.append
                                                               │            (ProvenanceRecord, chained+signed)
                                                               ▼
                                                   ProvenanceResolution (graded)
                                                               │ requires_human?
                                                               ▼
                          feed._route ──▶ HeldDecisionSink (the only outward surface)
```

#### `signature.py` — the fingerprint

- `BehavioralSignature` (`signature.py:66`) is a frozen, slotted dataclass of *distributions,
  sets, scalar moments, and stable hashes* — never content. Facets:
  `action_type_dist`, `channel_dist`, `environment_dist`, `verdict_mix` (each ~sums to 1),
  `tool_set`/`mcp_set`/`data_scope_set` (frozensets for Jaccard), `score_mean`/`score_std`/
  `violation_rate`, `cadence_median_s`/`cadence_dispersion`, and the three strong anchors
  `system_prompt_hash`/`tool_manifest_hash`/`memory_hash`.
- `from_actions` (`signature.py:115`) folds a window of `ActionLedgerEntry` into counters,
  normalizes (`_normalize`, `signature.py:54`), quantizes floats for hash stability
  (`_quantize`, `signature.py:61`), computes cadence (`_cadence`, `signature.py:303`,
  median inter-action gap + bounded coefficient of variation ≤4.0), then `_with_hash`.
- `_with_hash` (`signature.py:196`) builds a canonical quantized payload and SHA-256s it →
  `signature_hash`. Crucial: `from_jsonable` (`signature.py:244`) rebuilds and re-hashes
  identically, so a replayed signature's hash matches the sealed one (verified live — see
  Implementation Reality).
- `is_warm` (`signature.py:235`) = `observation_count >= 8` (`WARM_OBSERVATION_THRESHOLD`,
  `signature.py:300`) — the cold-start honesty floor.

#### `distance.py` — the graded confidence

- `behavioral_confidence` (`distance.py:104`): returns `0.0` if either signature is empty.
  Fuses weighted components (`distance.py:41-49`): tools(.22)/mcp(.14)/scopes(.14) by
  Jaccard, action(.20)/channel(.08)/env(.06)/verdict(.08) by bounded cosine over the union,
  score proximity(.04), log-scale cadence proximity(.04).
- Anchor fusion (`distance.py:148-158`): `_shared_anchors` (`distance.py:92`) counts matching
  present anchors. Two anchors → floor `_TWO_ANCHOR_FLOOR=0.93`; one → floor
  `_ANCHOR_FLOOR=0.85`; **no anchor → hard cap `_NO_ANCHOR_CONFIDENCE_CAP=0.80`**. That cap
  is the documented "behaviour is strong evidence, not proof" honesty, enforced in code.

#### `engine.py` — the resolver + projection

- `BehavioralProvenanceEngine` (`engine.py:102`) is a dataclass holding `ledger`, an
  in-memory `_known: dict[str, _KnownIdentity]` projection, an `RLock`, and an injectable
  `intent_scorer` (default `DEFAULT_INTENT_SCORER`). `_KnownIdentity` (`engine.py:82`) holds
  current signature, signal tier, birth anchor, confirmed-tier union, declared intent.
- `observe` (`engine.py:120`) is the core decision tree:
  - empty window → `SIGHTING` confidence 0.0, note "no observations".
  - **known agent_id** (`engine.py:149`): self-confidence; if both warm and
    `drift = 1 - conf >= DRIFT_THRESHOLD (0.40)` → `_seal_drift`; else `_seal_sighting`.
  - **unknown agent_id** (`engine.py:157`): `_best_cross_match`; if best ≥
    `REIDENTIFY_THRESHOLD (0.86)` → `_seal_reidentified`; if best ≥ `MERGE_REVIEW_LOWER
    (0.72)` → `_seal_birth` with an *ambiguous-merge flag* (`requires_human=True`); else a
    plain `_seal_birth`. Thresholds at `engine.py:67-79`.
- Sealers (`_seal_birth` :199, `_seal_sighting` :248, `_seal_reidentified` :283,
  `_seal_drift` :330) each `ledger.append(...)` then update `_known` and return a frozen
  `ProvenanceResolution`. `requires_human` is set for ambiguous merges, near-threshold
  re-ids (`engine.py:326`), and all drift (`engine.py:359`).
- `register_birth` (`engine.py:412`) — the **discovery→provenance fusion**: seals a *cold*
  BIRTH for an agent the instant reconciliation promotes it, anchored to attested anchors
  (not claimed metadata). Idempotent: a second call widens the coverage union and seals no
  second birth (`engine.py:445-455`). Builds an observation-free signature from anchors so a
  later behavioural sighting confirms the *same* identity.
- Lifecycle seals `seal_sleep`/`seal_wake` (`engine.py:521`/`543`) → SLEPT/WOKE records;
  `_signature_hash_for` (`engine.py:511`) gives a never-witnessed agent a stable
  content-free anchor (`sha256("agent:"+id)`).
- Reads: `reidentify` (top-k matches, :364), `birth_certificate` (:384 →
  `BehavioralBirthCertificate`), `coverage_boundary` (:575 → graded edge-of-sight),
  `intent_drift` (:626 → declared-vs-observed via the injected scorer).
- **Event-sourcing memory** (`engine.py:672-827`): `_known` is a *projection* over the sealed
  ledger (the event store). `rebuild_from_ledger` (:688) replays the log
  (optionally from a `snapshot`) and folds each record via `_apply_record` (:714).
  `_signature_from_detail` (:771) reconstructs a signature (or a cold anchors-only one for a
  discovery birth). `snapshot` (:803) is a deliberately-dormant performance hook ("KISS until
  replay is slow"). This is what makes the "continuous witness" claim real across restart.

#### `feed.py` — the primitive made alive

- `ContinuousProvenanceFeed` (`feed.py:136`) wires the gate's decision stream into the engine.
  Three documented constraints, all enforced in code:
  1. **Never touches hot-path latency**: `note_action` (`feed.py:183`) does a counter bump
     under a short lock and at most one `queue.put_nowait` when the per-agent count reaches
     `batch_size` (default 4); all signature derivation + sealing run on the background
     worker `_run` (`feed.py:252`). Any error is swallowed (`feed.py:222`).
  2. **Seals in silence**: `_route` (`feed.py:295`) has **exactly one** outward branch —
     `if not resolution.requires_human: return`. There is deliberately no path that emits an
     ordinary finding.
  3. **Only a held decision leaves**: a `requires_human` resolution is appended to the
     `HeldDecisionSink` (`feed.py:105`) — a thread-safe queue the surface pulls from.
- `drain` (`feed.py:330`)/`flush` (`feed.py:321`) process inline for deterministic tests
  without the worker. The feed also seals agent→agent edges into the delegation graph from
  `note_action` (`feed.py:198-209`).

#### `delegation.py` — the edge log

- `SealedDelegationGraph` (`delegation.py:100`) is an independent append-only, hash-chained,
  ECDSA-signed log (same chain construction as the identity ledger) plus a live adjacency
  view. `observe_delegation` (:138) re-seals on every observation (witnesses persistence,
  bumps `observation_count`), rejects self-delegation (:152). `is_load_bearing` (:226) backs
  the dormancy controller's "does anything depend on this agent?" question.
  `verify_chain`/`verify_signatures` (:244/:273) mirror the ledger. **Note: ECDSA-only — no
  crypto-agile `SealEnvelope` here** (unlike the two ledgers).

#### `intent.py` — declared-vs-observed alignment

- `CAPABILITY_TAXONOMY` (`intent.py:59`): 12 coarse behavioural categories (communication,
  data_read/write/delete, file_ops, code_execution, finance, identity_admin,
  **observability_tamper**, scheduling, web_browse, tool_use), each with keyword stems.
- `_categories_for_tokens` (`intent.py:128`) maps tokens to categories by exact stem then
  bounded prefix match. `TaxonomyIntentScorer.score` (`intent.py:210`) classifies the
  declared-intent text and weights each *observed category* by action-distribution mass,
  computing `coverage` (mass inside declaration) and `divergence = 1 - coverage`.
  Uncategorized action mass counts as divergent. Rename-resistance is real and
  deterministic: `suppress_logs` and `disable_monitoring` both land on `observability_tamper`.
- `INTENT_DIVERGENCE_REVIEW_THRESHOLD=0.5` (`intent.py:280`) routes consequential divergence
  to the held path via `engine.intent_drift` (`engine.py:651`).

### Data flow (sealed-truth / PCVR)

```
SealedFact(kind, claim, evidence?, maturity, detail)
        │ canonical_payload()  (embeds evidence.canonical_payload())
        ▼
SealedFactLedger.append ──▶ payload_sha256 ─chain─▶ record_hash ─sign─▶ ECDSA sig (signature_b64)
                                                          │
                                          CryptoAgileSealer.envelope_with_primary
                                                          ▼
                                          SealEnvelope{ECDSA mirror + ML-DSA-65}  (None if no PQ backend)
                                                          ▼
                                          SealedFactRecord (the PCVR)
        │
export_sealed_fact_bundle ──▶ SealedFactBundle (JSON, + components, + seal_public_keys, + anchor)
        │
verify_sealed_fact_bundle (standalone, runtime-free): chain replay + pinned-key authorship
        + e-value composition replay + PQ envelope check + RFC-3161 anchor check
```

#### `models.py` — the sealed records

- `SealedFact` (`models.py:316`): frozen, `extra="forbid"`. `kind` (`SealedFactKind`,
  `models.py:296`: ATTEMPT/DECISION/ENFORCEMENT/DRIFT/BLAME/IDENTITY/ANSWER/VERDICT_TRANSCRIPT),
  `claim` (descriptive prose), `evidence: CombinedEvidence | None` (the proof-carrying part
  from the e-value spine), `maturity`, `detail`. `canonical_payload` (`models.py:344`) embeds
  the evidence's own canonical payload so the proof is sealed *inside* the fact and any
  tamper inside it breaks chain replay.
- `SealEnvelope` (`models.py:108`): `seal_version` + tuple of `SealSignature` (per-algorithm).
  `is_dual` (`models.py:134`) = ≥2 distinct algorithms. `SealPublicKey` (`models.py:140`) is a
  *claimed* key carried in a bundle — explicitly "not a basis of trust on its own."
- `ProvenanceRecord` (`models.py:156`) and `SealedFactRecord` (`models.py:359`) carry the chain
  fields (`payload_sha256`, `previous_hash`, `record_hash`, `signature_b64`, `signing_key_id`)
  plus the additive `seal_envelope: SealEnvelope | None`. The envelope is *never* part of
  `payload_sha256`/`record_hash`, so adding it leaves the chain byte-for-byte unchanged.
- Honesty is documented at `models.py:289-293`: the ledger proves the fact was sealed
  unaltered + authored by Tex; the prose `claim` is producer-asserted and the type does
  **not** verify the claim matches the evidence.

#### `ledger.py` — the two ledgers

- `BehavioralProvenanceLedger` (`ledger.py:101`) and `SealedFactLedger` (`ledger.py:332`)
  are structurally identical chains. `append`
  (`ledger.py:173` / `ledger.py:424`): `sequence`, `previous_hash` from the last record;
  `payload_sha256 = sha256(stable_json(payload))`; `record_hash = sha256(stable_json({
  payload_sha256, previous_hash}))`; ECDSA-sign the record_hash → `signature_b64`; then
  dual-sign with `CryptoAgileSealer.envelope_with_primary` (the ECDSA entry *reuses* the
  already-computed signature byte-for-byte because ECDSA is randomized) **only when
  `self._sealer.is_dual`** else `seal_envelope=None`.
- Verifiers: `verify_chain` (`ledger.py:262`/`485`) recomputes the chain from each record's
  own canonical payload; `verify_signatures` (`ledger.py:298`/`514`) checks ECDSA;
  `verify_seal_envelopes` (`ledger.py:319`/`535`) checks the PQ envelopes via the
  module helper `_verify_seal_envelopes` (`ledger.py:52`) — returns
  `{dual_signed, ecdsa_valid, pq_valid, checked, invalid_at, mismatch_at}`, honestly
  dropping `dual_signed`/`pq_valid` to False for any ECDSA-only record.
- The signing keypair is generated at construction via `default_signature_provider()`
  (`ledger.py:122-127`) unless injected (`signing_key=`). PQ signer added by
  `CryptoAgileSealer.from_primary` with `enable_pq=True` by default.

#### `seal_envelope.py` — the crypto-agile sealer

- `CryptoAgileSealer` (`seal_envelope.py:123`) holds an ordered list of `_Signer`
  (provider+key). `from_primary` (:138) makes signer 0 = ECDSA primary, appends an ML-DSA
  signer via `make_pq_signer` (:98) which resolves `get_signature_provider(ML_DSA_65)` and
  returns `None` (logged WARNING) on any backend-absent failure — the honest degrade.
- `envelope_with_primary` (:212) mirrors the legacy ECDSA `signature_b64` into the envelope
  and freshly signs the PQ entries over the same `record_hash`. `is_dual` (:178),
  `pq_signer` (:170), `public_keys` (:187), `pinned_keys` (:200).
- `verify_envelope` (:284): verifies each signature by dispatching the provider for its
  *claimed* algorithm against the *pinned* key for that algorithm. A relabelled/forged sig
  fails → `mismatch=True`. Unpinned algorithms are reported as honest "cannot confirm," not
  tamper. `EnvelopeVerification` (:249) exposes `ecdsa_verified`/`pq_verified`/`dual_verified`.
- `is_post_quantum_algorithm` (:80): everything except `ecdsa-p256`/`ed25519` counts as PQ.

#### `bundle.py` — the court exhibit

- `SealedFactBundle` (`bundle.py:97`): frozen JSON model — version, name, exported_at,
  *claimed* `signing_key_id`/`public_key_b64`, the `SealedFactRecord` tuple, optional
  `components` (the `TexEvidence` that fed each e-value, for composition replay), optional
  `seal_public_keys`, optional RFC-3161 `anchor: CheckpointAnchorRecord`.
- `verify_sealed_fact_bundle` (`bundle.py:283`) is **standalone** (imports no live ledger/DB/
  runtime). For each record it (1) recomputes `payload_sha256` from the fact's own canonical
  payload and re-links the chain (`bundle.py:355-369`), never trusting claimed hashes; (2)
  verifies the ECDSA signature over the *recomputed* hash against the **pinned** key
  (`bundle.py:371-379`); (3) verifies the PQ envelope against pinned seal keys
  (`bundle.py:386-404`); (4) replays the e-value composition with the *sealed* combiner
  (`compose_product_independence`/`compose_arithmetic_mean`) and checks the scalar matches
  to `rel_tol=1e-9` (`bundle.py:405-425`). The external anchor path
  (`bundle.py:437-460`) recomputes the Merkle root from the records' own recomputed hashes,
  compares to the anchored tree-head, and verifies the RFC-3161 token against a *pinned* TSA
  cert. `BundleVerificationReport` (`bundle.py:141`) reports every check separately;
  `is_valid` (`bundle.py:190`) is defined by ECDSA-level checks only (so legacy bundles are
  unaffected); `pq_secured`/`fully_replayable`/`externally_anchored` are stronger,
  separately-reported properties.

#### The four seal seams

All four follow the *identical* fail-closed, observation-only contract
(`ledger is None` → no-op `None`; append failure logged and returns `None`, never raised into
the host path) and tag maturity `EvidenceMaturity.RESEARCH_SOLID` ("real live crypto, newly
wired, not yet externally anchored / not a production default"):

- `decision_seal.build_decision_fact`/`seal_decision` (`decision_seal.py:54`/`100`) — one
  `DECISION` per verdict; folds an optional `AbstentionCertificate` into the same fact's
  detail (one record, not two — preserves the ATTEMPT→DECISION kind sequence consumers rely
  on).
- `attempt_seal.build_attempt_fact`/`seal_attempt` (`attempt_seal.py:88`/`126`) — one
  `ATTEMPT` at `evaluate()` entry. Its `detail` deliberately omits `"verdict"` (L1/L3 filter
  by DECISION kind); `content_sha256` mirrors the PDP hashing so an auditor can link
  ATTEMPT→DECISION beyond the shared `request_id`.
- `enforcement_seal` (`enforcement_seal.py`): `build_enforcement_fact`/`seal_enforcement`
  (:56/:116) from a `GateEvent`, and `seal_enforcement_decision` (:144) from a PEP decision
  (no `GateEvent`). Optional `attested_identity` is sealed honestly (verified or not). The
  claim is narrow: "gate allowed/blocked X (verdict, outcome) — authorship+integrity sealed;
  verdict correctness NOT proven."
- `transcript_seal` (`transcript_seal.py`): **opt-in** — seals only when
  `TEX_SEAL_VERDICT_TRANSCRIPT` is truthy (`transcript_sealing_enabled`, :70) AND a ledger is
  wired. Seals the canonical transcript hash + monotonicity witness self-contained in detail
  for offline re-check.

---

## Public API / Entrypoints

`__init__.py` (`provenance/__init__.py:55-82`, `__all__`) re-exports:
`BehavioralSignature`, `behavioral_confidence`, `BehavioralProvenanceLedger`,
`BehavioralProvenanceEngine`, `BehavioralBirthCertificate`, `ProvenanceEventKind`,
`ProvenanceMatch`, `ProvenanceRecord`, `ProvenanceResolution`, `SealedFact`,
`SealedFactKind`, `SealedFactRecord`, `SealedFactLedger`, `SealEnvelope`, `SealSignature`,
`SealPublicKey`, `CryptoAgileSealer`, `EnvelopeVerification`, `verify_envelope`,
`is_post_quantum_algorithm`, `SEAL_VERSION_AGILE`, `WARM_OBSERVATION_THRESHOLD`,
`REIDENTIFY_THRESHOLD`, `MERGE_REVIEW_LOWER`, `DRIFT_THRESHOLD`,
`build_default_provenance_engine`.

Imported directly (not via `__init__`) by the rest of the codebase:
`ContinuousProvenanceFeed`/`HeldDecisionSink`/`HeldDecision` (`feed.py`),
`SealedDelegationGraph` (`delegation.py`), `seal_attempt`/`seal_decision`/
`seal_verdict_transcript`/`seal_enforcement`/`seal_enforcement_decision` (the seams),
`export_sealed_fact_bundle`/`verify_sealed_fact_bundle`/`SealedFactBundle`/
`anchor_ledger_checkpoint` (`bundle.py`).

**HTTP surface** (`api/provenance_routes.py:build_provenance_router`, prefix `/v1/provenance`):
`POST /observe`, `GET /identity/{agent_id}`, `POST /reidentify`, `GET /ledger/verify`,
`GET /ledger`. Held-decision surface: `GET /v1/discovery/.../held`
(`api/discovery_surface_routes.py:331`).

---

## Wiring

### Wiring In (who imports + LIVE call path)

**LIVE — behavioural engine + feed + delegation graph** (default boot):

`main.py:build_runtime` constructs them eagerly:
- `main.py:681` `provenance_engine = build_default_provenance_engine()`
- `main.py:688` `provenance_engine.rebuild_from_ledger()` (event-sourcing rehydration)
- `main.py:689-690` `held_decision_sink = HeldDecisionSink()`; `delegation_graph = SealedDelegationGraph()`
- `main.py:691-696` `provenance_feed = ContinuousProvenanceFeed(engine=..., action_ledger=..., held_sink=..., delegation_graph=...)`
- `main.py:1177` `provenance_feed.start()` (background worker)
- `main.py:1703-1704` attaches `app.state.provenance_engine` / `app.state.provenance_feed`.

Live hot-path call path (the witness firing on every agent action):
`api` evaluate route → `EvaluateActionCommand.execute`
→ `commands/evaluate_action.py:337-339` `self._provenance_feed.note_action(request.agent_id)`
→ `feed.note_action` → enqueue → worker `_seal_for` → `engine.observe` → `ledger.append`
→ `_route` → `HeldDecisionSink`. The feed is passed into the command via
`main.py:974` `provenance_feed=provenance_feed`.

Live discovery→provenance fusion:
`discovery/service.py:673` `self._provenance_engine.register_birth(...)`
(`_seal_discovery_birth`, `discovery/service.py:669`), with the engine injected at
`main.py:752`. Discovery is LIVE.

Live dormancy lifecycle seals:
`DormancyController` (built `main.py:763-770`, injected `provenance_engine`,
`delegation_graph`, `held_sink`) calls `engine.seal_sleep`/`seal_wake`
(`discovery/dormancy.py:205,250,259`) and reads `is_load_bearing` / `HeldDecisionSink`.

Held surface read: `api/discovery_surface_routes.py:338-345` reads
`app.state.provenance_feed.held` / `app.state.held_decision_sink`.

HTTP identity surface: `app.include_router(build_provenance_router())` (`main.py:1460`);
routes read `app.state.provenance_engine` (`api/provenance_routes.py:43-49`).

**CONDITIONALLY LIVE — `SealedFactLedger` + DECISION/ATTEMPT seams** (flag-gated):

- `main.py:870-873` `seal_decisions = os.environ.get("TEX_SEAL_DECISIONS", ...)`;
  `decision_ledger = SealedFactLedger() if seal_decisions else None`.
- `main.py:876-883` the PDP is constructed with `decision_ledger=decision_ledger`.
- `engine/pdp.py:261` `seal_attempt(self._decision_ledger, ...)` (at evaluate entry) and
  `engine/pdp.py:542` `seal_decision(...)`. With the flag **off (default)** the ledger is
  `None` and both seams are zero-cost no-ops — the verdict path is byte-for-byte unchanged.
- `transcript_seal.seal_verdict_transcript` is reachable from the PDP but additionally gated
  by `TEX_SEAL_VERDICT_TRANSCRIPT` (double opt-in).

**INDIRECT / NOT wired into default `build_runtime`:**

- **`enforcement_seal` ENFORCEMENT observer**: `enforcement/seal.SealingGateObserver` /
  `build_proof_carrying_gate` call `seal_enforcement`, but `main.py:1756` builds the live
  in-process gate via `build_standing_gate(app.state.standing_governance)` **without** the
  optional `observer=` argument (`enforcement/standing_transport.py:121,141-144`). So the
  per-action ENFORCEMENT seal is not active in the default boot — it is exercised by
  `build_proof_carrying_gate` and tests. (Consistent with the spine pass `pep=ORPHAN`.)
- **`seal_enforcement_decision`**: only caller is `pep/sealing.py:63`; `tex.pep` is **not**
  imported by `main.py`/`build_runtime` — INDIRECT.
- **`selfgov.governor`** uses `SealedFact(ENFORCEMENT)` (`selfgov/governor.py:388…623` via
  `_seal_enforcement`) but no `bind_reflexive_governor` caller exists in `main.py` — the
  governor is inert-until-bound and not bound at boot.
- **`bundle.py`** (`export_/verify_sealed_fact_bundle`): consumed by `capstone/*` (compose,
  tamper, verify) — INDIRECT (capstone is INDIRECT in the spine pass).
- **Postgres mirror** `stores/behavioral_provenance_ledger_postgres.py`
  (`PostgresBehavioralProvenanceLedger`) exists but is **not** wired into `main.py`; the
  default ledger is the in-memory one from `build_default_provenance_engine()`.

Other importers: `engine/risk_spine.py` (DRIFT facts), `evidence/negative_knowledge.py`,
`zkpdp/arbiter.py`, `interchange/gix_merge.py` (reuses `_sha256_hex`/`_stable_json`),
`pqcrypto/pq_durability.py`, `api/discovery_surface_routes.py` (ProvenanceEventKind).

### Wiring Out (dependencies)

**Internal tex subsystems:**
- `tex.domain.agent.ActionLedgerEntry` (signature/engine substrate)
- `tex.domain.signal_trust.SignalTrustTier` (admissibility grade; ordering used in
  `coverage_boundary`)
- `tex.domain.evidence` (`CombinedEvidence`, `EvidenceMaturity`, `TexEvidence`,
  `compose_arithmetic_mean`, `compose_product_independence`)
- `tex.domain.decision.Decision`, `tex.domain.abstention_certificate.AbstentionCertificate`,
  `tex.domain.evaluation.EvaluationRequest`, `tex.domain.policy.PolicySnapshot` (seams)
- `tex.engine.verdict_transcript` (`VerdictTranscript`, `MonotonicityWitness`)
- `tex.events._ecdsa_provider.default_signature_provider` (the ECDSA-P256 primary signer)
- `tex.pqcrypto.algorithm_agility` (`SignatureAlgorithm`, `SignatureKeyPair`,
  `SignatureProvider`, `get_signature_provider`) and (via dispatch) `tex.pqcrypto.ml_dsa`
- `tex.interchange.external_anchor` (`CheckpointAnchorRecord`, `verify_anchor_receipt`) and
  `tex.interchange.gix` (`merkle_root`, `CheckpointPublisher`) — bundle external anchor
- `tex.identity.agent_credential.AttestedIdentity` (TYPE_CHECKING only, enforcement_seal)

**External libraries:** `pydantic` (frozen models), stdlib `hashlib`/`json`/`base64`/
`threading`/`queue`/`math`/`re`/`logging`/`dataclasses`/`uuid`/`datetime`/`enum`. The
post-quantum path uses `pyca/cryptography>=48` (native ML-DSA) or `liboqs-python` as a
fallback, resolved inside `tex.pqcrypto`.

---

## Implementation Reality

**This package is REAL, not stub-heavy.** There are zero `NotImplementedError`, `TODO`, or
placeholder `pass`-only bodies in any of the 15 files (verified by reading every file). The
`except: pass` blocks are all *intentional* fail-closed/best-effort swallows in the feed and
seam paths, documented as "provenance must never break the gate."

**Crypto is real and runs by default in this environment** (verified live with
`PYTHONPATH=...`):
- Both ledgers report `is_dual_signed == True` on a fresh build; the active ML-DSA backend
  is `pyca-cryptography-native` (ML-DSA-65, FIPS 204, public key 1952 bytes). So the default
  path is genuinely **ECDSA-P256 + ML-DSA-65 dual-signed**, not ECDSA-only, on this machine.
- A round-trip test (register a discovery birth → `rebuild_from_ledger` → re-check): the
  reconstructed signature hash **matches** the sealed one; `verify_chain` →
  `{intact: True}`; `verify_signatures` → `{valid: True}`; `verify_seal_envelopes` →
  `{dual_signed: True, ecdsa_valid: True, pq_valid: True, mismatch_at: None}`. The ML-DSA-65
  signature verified (`ok: true`, 3309-byte signature).
- The honest-degrade path is **real**: `make_pq_signer` (`seal_envelope.py:98-120`) returns
  `None` on backend absence (logged WARNING), and `append` then writes
  `seal_envelope=None`. The chain is byte-identical either way (the envelope is never part of
  `payload_sha256`/`record_hash`). This is a *real graceful fallback*, not a hollow stub.
- `make_pq_signer`'s `try/except Exception` (`seal_envelope.py:113`) is the only "guard," and
  it degrades honestly — it does not fabricate a signature. (The spine-pass note "pqcrypto
  NotImplementedError counts are interface/registry guards" lives in `tex.pqcrypto`, not here;
  this package contains none.)

**Real algorithmic logic** (not heuristic hand-waving): the fused confidence
(`distance.py`), the deterministic capability-taxonomy intent scorer (`intent.py`), the
SHA-256 hash chain + ECDSA + ML-DSA envelope (`ledger.py`/`seal_envelope.py`), the
standalone offline bundle verifier with composition replay and RFC-3161 anchor check
(`bundle.py`), and the event-sourcing projection rebuild (`engine.py`) are all fully
implemented and self-consistent.

**Honest documented limits that the code actually enforces:**
- The no-anchor confidence cap `0.80` (`distance.py:54,158`).
- The cold-start warm floor `8` (`signature.py:300`).
- `SealedFact.canonical_payload` embeds the e-value proof but the type does **not** verify
  the prose claim matches the evidence (`models.py:289-293`) — stated, not hidden.
- Seam maturity is `RESEARCH_SOLID` because the ledger is not externally time-anchored at
  seal time (anchoring is a separate, bundle-level RFC-3161 step). Stated in every seam
  docstring (e.g. `enforcement_seal.py:24-27`).

---

## Technology / SOTA

- **Certificate-Transparency-style transparency log**: append-only, SHA-256 hash-chained,
  per-record signed (RFC-9162-adjacent construction; `bundle.py:84` even uses the RFC-9162
  empty-tree root). Integrity (chain) + authorship (signature) are separate, separately
  verifiable properties.
- **Crypto-agility / post-quantum migration**: ECDSA-P256 primary + ML-DSA-65 (NIST FIPS 204,
  Security Level 3) dual signature in a versioned `SealEnvelope`, designed so an algorithm
  can be added/retired without disturbing the existing hash chain. Verification dispatches by
  *claimed* algorithm against a *pinned* key, so a relabelled signature is caught as a
  mismatch.
- **E-value / anytime-valid evidence**: `SealedFact.evidence` carries a `CombinedEvidence`
  scalar from the e-value spine; the bundle replays the composition
  (`compose_product_independence` = product-of-independent e-values, `compose_arithmetic_mean`).
- **External time anchoring**: RFC-3161 timestamp over a gix/Merkle tree-head of the ledger,
  checked against a pinned TSA cert (`bundle.py:437-460`).
- **Behavioural biometrics for agents**: distributional fingerprint (action/channel/env/
  verdict mix), capability-surface Jaccard, behavioural-moment proximity, cadence on a log
  scale — fused into a calibrated same-actor confidence. Anchors (prompt/tool/memory hashes)
  dominate when present (the rename/rotation-resistant signal).
- **Deterministic, offline, content-free intent scoring** via a capability taxonomy — a
  deliberate alternative to a non-deterministic embedding/LLM-judge (so the seal re-derives
  identically on replay), with an injectable `IntentScorer` escape hatch.
- **Event sourcing**: the engine's `_known` map is a projection rebuilt by replaying the
  sealed log; snapshot/resume interface present but dormant ("KISS until replay is slow").

---

## Persistence

- **In-memory by default.** `BehavioralProvenanceLedger`, `SealedFactLedger`, and
  `SealedDelegationGraph` all hold `self._entries`/`self._records` lists under an `RLock`
  (`ledger.py:120,372`; `delegation.py:117`). The engine's `_known` projection is
  process-local (`engine.py:111`).
- **Durability story is event sourcing, not yet a wired durable store.** `rebuild_from_ledger`
  (`engine.py:688`) replays the ledger to reconstruct identity state, so durability follows
  from durability of the ledger. A `PostgresBehavioralProvenanceLedger` mirror exists
  (`stores/behavioral_provenance_ledger_postgres.py`) — "served from the in-memory cache,
  writes flush synchronously to Postgres" **(claim, unverified beyond the docstring)** — but
  it is **not wired into `main.py`**, so the running default keeps everything in process
  memory and loses it on restart unless an explicit durable ledger is injected.
- **The PCVR ledger is opt-in** (`TEX_SEAL_DECISIONS=1`) and likewise in-memory; durable
  persistence of sealed facts is the portable `SealedFactBundle` JSON export (`bundle.py`)
  plus the (un-wired) Postgres mirror.
- Signing keys are generated per-process at construction (`ledger.py:125-127`,
  `delegation.py:125`) unless `signing_key=` is injected. `build_default_provenance_engine`
  (`__init__.py:85`) generates a fresh key — production is expected to inject an HSM/keystore
  key (documented `__init__.py:88-92`; **unverified** that any deployment does so).

---

## Notable Findings

1. **The ENFORCEMENT seal is fully built but NOT live in the default boot.** Despite the
   branch name `feat/proof-carrying-gate` and the rich `enforcement_seal.py` / proof-carrying
   memory note, `main.py:1756` builds the live in-process gate *without* the
   `SealingGateObserver`. So in the default runtime no per-action `SealedFact(ENFORCEMENT)`
   is sealed. It is real, tested, and one constructor argument away — but currently INDIRECT,
   matching the spine pass `pep=ORPHAN`. (Memory note "Phase 0 BUILT+green … transport +
   ENFORCEMENT-kind already existed" is consistent: the *kind* and *seam* exist; the live
   wiring into the default gate does not.)

2. **The default crypto is genuinely dual-signed (PQ), exceeding the conservative docstrings.**
   The docstrings repeatedly hedge "ECDSA-P256 (the live signer), optional ML-DSA when a PQ
   backend is live." On this machine the PQ backend (pyca native) *is* live, so the default is
   ECDSA + ML-DSA-65. The conservative prose is honest, not an overstatement — but a reader
   should know the strong path is the actual default here.

3. **`SealedFactLedger` sealing is OFF by default.** The most-cited governance ledger in the
   docstrings (DECISION/ATTEMPT/ENFORCEMENT facts) seals nothing unless `TEX_SEAL_DECISIONS=1`
   (`main.py:870-873`). The seam docstrings claim live wiring; the *wiring exists* but is
   flag-gated and default-off. Not a contradiction — but the "every verdict is sealed" mental
   model is false by default.

4. **`SealedDelegationGraph` is ECDSA-only — no crypto-agile envelope.** Unlike the two
   ledgers, `delegation.py` never builds a `CryptoAgileSealer`/`SealEnvelope`
   (`delegation.py:138-207`). Its docstring says "ECDSA-signed," which is accurate, but it
   means the delegation log is *not* post-quantum protected while the identity/fact ledgers
   are. Worth noting for any "everything is PQ-sealed" claim.

5. **`_seal_reidentified` reads back from the ledger immediately after appending.**
   `engine.py:314-315` calls `self.ledger.list_for_agent(agent_id)[0]` right after the
   append at :291. This is correct (append precedes the read and the new alias's first record
   is its BIRTH-equivalent), but it is a subtle ordering dependency and indexes `[0]`
   assuming the just-appended record is the agent's first — true only because an unknown
   `agent_id` reaches this path. Not a bug, but fragile if the call order ever changes.

6. **The "silent by construction" claim is real and enforced.** `feed._route`
   (`feed.py:295-318`) has literally one outward branch and returns early on
   `not requires_human`. There is no code path that emits an ordinary finding — the voice
   discipline is structural, exactly as the docstrings claim.

7. **The standalone bundle verifier genuinely re-derives everything and pins keys.**
   `verify_sealed_fact_bundle` never trusts the bundle's claimed hashes or embedded key — it
   recomputes the chain and verifies signatures against the caller-supplied *pinned* key
   (`bundle.py:309,374`), flagging key substitution via `key_matches_pin`/`pq_key_matches_pin`.
   This is the load-bearing honesty point and it is implemented as documented.

8. **No dead code found in scope.** Every symbol is either re-exported, imported by another
   subsystem, or part of a verifier/replay path. `snapshot`/`rebuild_from_ledger(snapshot=)`
   is "dormant" by design (documented `engine.py:680-686`) but is a real, tested interface,
   not dead code.

9. **The Postgres mirror's "drop-in" claim is unverified at runtime.** It is not wired into
   `main.py`, so the durability guarantee it advertises is not exercised by the default
   application; treat durable behavioural provenance as not-yet-live in the default boot.
