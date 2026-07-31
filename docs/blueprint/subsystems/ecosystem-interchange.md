# Subsystem Dossier: Ecosystem twin & interchange

Scope: `src/tex/ecosystem/` and `src/tex/interchange/`
Branch: `feat/proof-carrying-gate`
Method: code read in full; wiring traced by grep over actual import/call sites with `file:line`. Markdown/docstring claims are labelled `(claim, unverified)` unless confirmed in code.

---

## Overview

Two cooperating packages that together form Tex's "ecosystem-state governance" layer and its cross-organization evidence interchange.

- **`tex.ecosystem`** — an eight-step `EcosystemEngine` that subsumes per-action PDP verdicts into ecosystem-state assessment. Every six-layer-pipeline `RoutingResult` is converted into a typed `ProposedEvent`, evaluated against an in-memory temporal knowledge graph + append-only event ledger, scored across six axes, and (when an intervention engine is wired) gated to FORBID/SANCTION/REMEDIATE. The engine also produces SCITT-shaped, offline-verifiable **state attestations** over a time window using an RFC 9162 Merkle root.
- **`tex.interchange`** — "GIX" (inter-org governance interchange, called Wave 2 / L6 in banners): an RFC 9162 transparency log over sealed governance verdicts (inclusion + consistency proofs), C2SP signed-note / tlog-checkpoint / tlog-witness / tlog-cosignature wire formats, an authenticated federated mean-merge of cross-org e-values, and an **external RFC 3161 timestamp anchor** that binds a checkpoint tree-head to a TSA key independent of Tex's own signing key (the "provable-age moat").

Both packages are reachable from the running app. The ecosystem engine/bridge are constructed unconditionally in `build_runtime` and invoked on the request path **only when `TEX_ECOSYSTEM=1`** (default off → inert PERMIT). The interchange GIX publisher seam is called in `build_runtime` (inert `None` unless `TEX_GIX_WITNESS=1` and a decision ledger exists), and a second, always-on interchange consumer is the conduit provenance chain (`ConduitProvenanceChain`) wired for the `/v1/conduit/*` routes.

The shared crypto primitive — the RFC 9162 Merkle Tree Hash in `ecosystem/_window.py` — is the single source of tree-hash truth that `interchange/gix.py` imports and builds inclusion/consistency proofs on top of. This is the structural link between the two packages.

Honesty banners are accurate to the code: `interchange` repeatedly and correctly states `federated=False` is **structurally unreachable** in-tree (no constructor for `EXTERNAL_FEDERATED`), the local TSA is demo-only, and the engine's P1/P2 axis scorers are honest about being axis inputs, not hard gates.

---

## File Inventory

### `src/tex/ecosystem/` (2,454 LOC)

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 42 | Package surface; re-exports `EcosystemEngine`, `EcosystemBridge`, `EcosystemVerdict(Kind)`, `EcosystemState`, `ProposedEvent`, `routing_result_to_proposed_event`. Sets `__layer__=4`. |
| `engine.py` | 1,579 | `EcosystemEngine`: the eight-step pipeline `evaluate()` + window attestation `attest_state()`. The substantive file. |
| `bridge.py` | 198 | `EcosystemBridge` + `routing_result_to_proposed_event()`: the only coupling point between the six-layer router and the engine; serializes a `RoutingResult` into a `VERDICT_EMITTED` `ProposedEvent` (fixed-point ints to survive float-rejecting canonical JSON). |
| `verdict.py` | 162 | `EcosystemVerdict`, `EcosystemVerdictKind` (PERMIT/ABSTAIN/FORBID/SANCTION/REMEDIATE), `EcosystemAxisScores` (six axes + computed `viability_index` + `graduated_level`), `GraduatedEnforcementLevel` (L0..L4). |
| `state.py` | 32 | `EcosystemState`: frozen Pydantic read-only graph snapshot (entity/capability ids, drift signals, compromise ratio, `state_hash`). |
| `proposed_event.py` | 28 | `ProposedEvent`: frozen Pydantic candidate event (kind, actor, target, payload, timestamps, upstream ids). |
| `_attestation.py` | 263 | SCITT-shaped signed-statement envelope builder/signer/parser (`build_attestation_payload`, `build_envelope`, `sign_envelope`, `parse_envelope`); JSON-with-trailer wire format. |
| `_window.py` | 150 | RFC 9162 §2.1 Merkle Tree Hash (`merkle_root`, `leaf_hash`, `empty_root`). Pure stdlib `hashlib`. The single source of tree-hash truth (imported by `interchange/gix.py`). |

### `src/tex/interchange/` (2,770 LOC)

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 85 | GIX surface; re-exports checkpoints/notes/proofs (from `gix`), witness/cosign types (from `gix_witness`), federated-merge types (from `gix_merge`). |
| `gix.py` | 693 | RFC 9162 inclusion/consistency proof **generation + verification**; C2SP `tlog-checkpoint` note body + `signed-note` Ed25519; `CheckpointPublisher` (pull-based STH); `build_checkpoint_publisher` main.py seam. |
| `gix_witness.py` | 589 | C2SP `tlog-witness` add-checkpoint state machine (`Witness`), `cosignature/v1` signing/verification, `verify_cosigned_checkpoint` (quorum), structural `federated=False` gate. |
| `gix_merge.py` | 424 | Authenticated federated **mean-merge** of cross-org e-values; three-proof `verify_org_evidence` (non-equivocation + integrity/authorship + inclusion) + disjointness guard. |
| `external_anchor.py` | 789 | RFC 3161 request build + **offline CMS-signature-verifying** TSA token verifier pinned to an external cert (`verify_anchor_receipt`); `CheckpointAnchorRecord` persisted unit. The "provable-age moat". |
| `_local_tsa.py` | 190 | DEMO/DEV/TEST-only self-issued RFC 3161 TSA that mints real CMS `SignedData` tokens so the verifier can be exercised offline; exposes adversarial knobs. |

---

## Internal Architecture

### Ecosystem package

#### Data model (`state.py`, `proposed_event.py`, `verdict.py`)

All three are frozen, `extra="forbid"` Pydantic models.

- `ProposedEvent` (`proposed_event.py:17`) is the **candidate** input to `evaluate()`: `event_kind`, `actor_entity_id`, optional `target_entity_id`, free-form `payload: dict[str, Any]`, `proposed_at`, optional `session_id`, `upstream_event_ids`.
- `EcosystemState` (`state.py:20`) is a **read-only projection** of the temporal KG at timestamp T: active agent/tool/capability ids, governance graph id, `aggregate_drift_signals`, `sliding_window_compromise_ratio∈[0,1]`, and a `state_hash`.
- `EcosystemVerdict` (`verdict.py:149`) carries the kind, axis scores, pre/post state hashes, rationale, optional `recommended_intervention_id` and `evidence_record_id`.
- `EcosystemAxisScores` (`verdict.py:81`) stores six raw axes and **computes** two surfaces:
  - `viability_index` (`verdict.py:119`) = `1 - max(U, SB, RG)` clamped to [0,1], where `U=drift_delta`, `SB=max(contract_violation_severity, 1-governance_graph_legality)`, `RG=systemic_risk_under_event`. This is the RiskGate "Aubin viability" decomposition (`(claim, unverified)` citation arxiv 2604.24686 — the *formula* is real and verifiable in code; the academic attribution is not checkable here).
  - `graduated_level` (`verdict.py:138` → `_graduated_level_from_viability` at `verdict.py:68`) maps viability to L0_ALLOW (≥0.90) … L4_QUARANTINE (<0.25).

#### `EcosystemEngine.evaluate()` — the eight-step pipeline (`engine.py:453`)

Dependency-injected collaborators (`engine.py:197`). The engine is tri-state-enabled (`enabled=None` reads env, else override). When **disabled** (`engine.py:488`) it returns an inert PERMIT with `ecosystem_state_hash_before="ecosystem_disabled"`, no mutation, one telemetry event — this is the load-bearing backward-compat guarantee.

When enabled, `_assert_p0_collaborators_wired()` (`engine.py:1437`) guarantees ontology/graph/projection/events/provenance are present, then:

1. **Step 1 — ontology** (`engine.py:508`): `self._ontology.validate_event(proposed)`; any failure is a hard FORBID (`engine.py:514`).
2. **Step 2 — graph projection** (`engine.py:524`): `self._projection.project_at(proposed.proposed_at)` produces `state_before`; projection failure → FORBID (`engine.py:533`). A frontier addition (`engine.py:547`) requires the actor to be a registered graph entity (`self._graph._has_entity(...)`), else FORBID `unknown_actor`.
3. **Step 3 — behavioral contracts** (`engine.py:583`): if a contracts collaborator is wired, calls `self._contracts.compliance_scores(...)` (deliberately the *pure* method, not `check_pre`), severity = `1 - min(c_hard, c_soft)`. **Fail-closed**: enforcer error → severity 1.0 (`engine.py:612`), not FORBID (axis input, not gate).
4. **Step 4 — governance LTS** (`engine.py:619`): if `self._oracle` wired, resolves the actor's effective institutional state through the subagent spawn-chain (`resolve_effective_state`, `engine.py:640`), calls `self._oracle.evaluate_transition(...)`. Oracle error → **FORBID** fail-closed (`engine.py:661`). Illegal transition → FORBID with sanction id (`engine.py:697`). Every assessment (legal **and** illegal) is recorded to a signed governance log via `_record_step4_assessment` (`engine.py:1496`).
5. **Step 5 — fast causal attribution** (`engine.py:720`): if `self._causal` wired, `fast_attribute(...)` over `upstream_event_ids` + active agents; confidence clamped [0,1]. Fail-closed to 0.0.
6. **Step 6 — drift detection** (`engine.py:762`): if `self._drift` wired, lazily imports `tex.drift.signal_registry.evaluate_drift` and produces `drift_delta`. Fail-closed to 0.0; when no collaborator, emits an explicit `drift_skipped_no_collaborator` event rather than touching a module singleton.
7. **Step 7 — systemic risk** (`engine.py:828`): **flag-gated, default OFF** via `is_flag_on("TEX_ECOSYSTEM_SYSTEMIC")`. If on and `self._systemic` wired, `self._systemic.score(state=state_before)` clamped [0,1]. Distinct telemetry for scored / `NotImplementedError` / error / skipped sub-cases. Never short-circuits to FORBID.
8. **Step 8 — intervention selection + axis-derived FORBID gate** (`engine.py:922`): active **only** when `intervention_calc` was supplied at construction (gating dependency; otherwise strict pass-through). Computes a FORBID predicate `dominant_axis = max(sb, drift, systemic) ≥ 0.5` (`engine.py:966`). On trigger, calls `self._intervention_engine.select(...)`:
   - no satisfying candidate → FORBID fail-closed (`engine.py:1005`);
   - chosen → `.apply()` (apply failure → FORBID, `engine.py:1028`); computes `bounded_compromise_score = 1 - eta*` from the calc; for `RESTORATIVE_PATH` kinds, optionally walks the path via `restorative_executor`;
   - kind mapping: `{QUARANTINE, HUMAN_APPROVAL_GATE, RESTORATIVE_PATH}` → **REMEDIATE** (block; no ledger append, `engine.py:1131`), else **SANCTION** (admit but flag, falls through to ledger append).

**PERMIT / SANCTION path** (`engine.py:1154`): `self._events.append_proposed(...)` (LedgerAppendError → FORBID), then `self._graph.add_event(...)` (GraphMutationError/UnknownActorError → **ABSTAIN**, because the ledger record is already durable, `engine.py:1180`). Recomputes `state_hash_after`. RiskGate P3 monotonic-restriction floor (`engine.py:1207`) updates a per-actor minimum viability and emits `floor_enforced` telemetry when the current evaluation is more permissive than the recorded floor — but **does not mutate the axis scores** (floor is reflected only in rationale + `viability_floor_for()`).

`record_recovery()` (`engine.py:434`) clears a floor; `viability_floor_for()` (`engine.py:419`) reads it.

#### `attest_state()` (`engine.py:1296`)

The audit-plane artifact. Requires the engine enabled. Parses RFC-3339-aware period bounds (`_parse_iso_aware`, `engine.py:1564`), computes the graph state hash at `period_end`, linearly scans the ledger for events in `[start, end]`, sorts by `(timestamp, event_id)`, builds an RFC 9162 `merkle_root` over their `record_hash`es (`_window.merkle_root`), anchors the window into the global hash chain (head sequence + record hash, genesis sentinel when empty), builds a SCITT-shaped payload+envelope (`_attestation.build_*`), and **signs through the same provenance provider the ledger uses** (`sign_envelope`, accessing `self._provenance._key` / `.provider`, `engine.py:1421`). Returns the wire packet bytes.

#### `_window.py` — RFC 9162 MTH

`merkle_root` (`_window.py:96`) implements MTH with correct `0x00` leaf / `0x01` inner domain separation and the largest-power-of-two-below split (`_mth`, `_window.py:139`). `empty_root` = `SHA-256("")`. `leaf_hash` validates 64-hex input. Docstring TODOs (`_window.py:32-33`) say inclusion/consistency proof generation is deferred to P1 — **that gap is exactly what `interchange/gix.py` fills** (see below).

#### `_attestation.py` — SCITT envelope

Builds a canonical-JSON envelope with CWT claims (`iss/sub/iat/nbf/exp`), signs `SHA-256(canonical_envelope)` hex bytes via an injected `SignatureProvider` (from `tex.pqcrypto.algorithm_agility`), and appends a four-line greppable trailer (`signature`/`key_id`/`algorithm`). `parse_envelope` is the reference inverse. Wire format is JSON-with-trailer, not COSE/CBOR; docstring `(claim)` says migration is a serializer swap.

#### `bridge.py`

`routing_result_to_proposed_event()` (`bridge.py:49`) is the serialization boundary. Because `EventKind.VERDICT_EMITTED` flows through float-rejecting canonical JSON, it encodes all scores as fixed-point ints (`round(value * 10_000)`, `bridge.py:103`) and stores **counts** of findings/asi_findings/etc. rather than the objects. Reserved-key collision protection on `extra_payload` (`bridge.py:124`). `EcosystemBridge.emit_verdict()` (`bridge.py:156`) builds the proposed event, calls `engine.evaluate()`, emits `ecosystem.bridge.verdict_emitted` telemetry, returns the verdict.

### Interchange package

#### `gix.py` — the transparency log

- **Proof generation** (`inclusion_path` `gix.py:139`, `consistency_path` `gix.py:166`, `_subproof` `gix.py:187`) recurses exactly per RFC 9162 §2.1.3.1/§2.1.4.1, computing subtree hashes via `_window.merkle_root` over slices — keeping all tree hashing in `_window.py`.
- **Succinct verification** (`verify_inclusion` `gix.py:222`, `verify_consistency` `gix.py:264`) implement §2.1.3.2/§2.1.4.2; both fail-closed on any malformed/non-32-byte input. `_node` (`gix.py:203`) uses the imported normative `_INNER_PREFIX`.
- **C2SP tlog-checkpoint** (`Checkpoint` `gix.py:333`): origin/tree_size/32-byte root + extension lines, with strict `note_text()`/`parse()` (no-leading-zero decimal, base64 root, control-char rejection).
- **C2SP signed-note Ed25519** (`Ed25519NoteSigner` `gix.py:438`, `Ed25519NoteVerifier` `gix.py:413`, `verify_note` `gix.py:508`): real `cryptography` Ed25519; key-id = `SHA-256(name || 0x0A || 0x01 || pubkey)[:4]`. `verify_note` adds one deliberate fail-closed tightening over the spec (a known key with a bad signature rejects the whole note).
- **`CheckpointPublisher`** (`gix.py:589`): pull-based STH publisher over a `read_record_hashes` callable; `current_signed_checkpoint()` snapshots hashes, builds + signs the checkpoint, retains the snapshot's record hashes so proofs are torn-read-free; `build_add_checkpoint_request()` emits the C2SP tlog-witness wire body.
- **main.py seam** (`build_checkpoint_publisher` `gix.py:663`): module-global registered publisher behind a lock; inert `None` unless a decision ledger is passed **and** `_flag_enabled()` (`TEX_GIX_WITNESS`). The flag gates wiring only — never read by any verifier.

#### `gix_witness.py` — non-equivocation

`Witness.add_checkpoint()` (`gix_witness.py:291`) implements the C2SP tlog-witness state machine with outcomes named after HTTP analogs (`WitnessOutcome` `gix_witness.py:130`): parse → MALFORMED, unknown origin → UNKNOWN_LOG, unauthenticated → LOG_UNAUTHENTICATED, old_size > size → MALFORMED, old_size ≠ latest → CONFLICT (returns latest size), equal-size different roots → CONFLICT (equivocation), bad consistency proof → BAD_CONSISTENCY_PROOF, else COSIGNED. Check-and-persist runs **under one lock** (`gix_witness.py:322`). `_cosign` (`gix_witness.py:391`) produces a `cosignature/v1` line over `header + time <t> + note body`; timestamp floored to ≥1. `verify_cosignature_line` (`gix_witness.py:407`) requires exactly 76-byte blob (4 key id + 8 timestamp + 64 sig) and rejects zero timestamps. `verify_cosigned_checkpoint` (`gix_witness.py:510`) checks the log note signature + ≥quorum distinct valid cosigners.

The **structural federation gate**: `WitnessProvenance.EXTERNAL_FEDERATED` exists as an enum value (`gix_witness.py:120`) but both `WitnessDescriptor.__post_init__` (`gix_witness.py:181`) and `Witness.__init__` (`gix_witness.py:256`) **raise** on it, so `federated=True` (`gix_witness.py:570`) is unreachable in-tree. `FEDERATED_FALSE_REASON` (`gix_witness.py:102`) documents this honestly.

#### `gix_merge.py` — authenticated federated mean-merge

`verify_org_evidence` (`gix_merge.py:134`) runs three different proofs in order, fail-closed:
1. **non-equivocation** via `verify_cosigned_checkpoint`;
2. **integrity + authorship** — re-derives `payload_sha256`/`record_hash` using the **imported, not mirrored** ledger helpers `_sha256_hex`/`_stable_json` (`gix_merge.py:72`; deliberately importing module-private names so a ledger rename fails loudly), then verifies the ECDSA-P256 signature against the org's pinned ledger key;
3. **inclusion** via `verify_inclusion` under the cosigned root.
It then enforces e-value honesty: only `CombinedEvidence.is_true_e_value` may enter (`gix_merge.py:246`).

`merge_federated_evidence` (`gix_merge.py:298`) requires ≥2 distinct orgs, refuses any failing submission (`GixMergeRefused` with a stable `reason_code`), enforces a disjointness guard (no duplicate origins / stream ids / combination ids / component ids — accidental double-counting only, **not** Sybil defense per banner), then computes the **arithmetic mean in log space** (`_log_mean_exp` `gix_merge.py:287`) — the only admissible merge under arbitrary dependence. Merged maturity is capped at the weaker of weakest-input and `RESEARCH_EARLY` (`gix_merge.py:402`). `federated` propagates from checkpoint verification and is structurally False.

#### `external_anchor.py` — the provable-age moat

`anchor_subject_bytes/digest` (`external_anchor.py:166/178`) timestamp the **C2SP checkpoint note body** (reusing `Checkpoint.note_text`), deliberately not the Tex-signed note, so age is provable without Tex's key. `build_timestamp_request` (`external_anchor.py:188`) builds a DER RFC 3161 `TimeStampReq`; `submit_anchor` (`external_anchor.py:227`) POSTs via an **injected** `Poster` callable (no network library imported). `CheckpointAnchorRecord` (`external_anchor.py:249`) is the persisted additive unit (frozen Pydantic), carrying enough to recompute the digest from structured fields.

`verify_anchor_receipt` (`external_anchor.py:394`) is the load-bearing offline path, all fail-closed: recompute imprint from structured fields → parse `TimeStampResp` + PKIStatus → require CMS `SignedData` carrying `TSTInfo` → messageImprint match → **verify the TSA's CMS signature** (`_verify_cms_signature` `external_anchor.py:615`, signed-attrs SET-OF re-tagging per RFC 5652 §5.4, then real RSA/ECDSA verify in `_verify_public_key` `external_anchor.py:681`) → require signer cert **pinned** (exact fingerprint or directly issued by pinned CA, `_is_pinned` `external_anchor.py:735`) → require **sole** id-kp-timeStamping EKU (`external_anchor.py:753`) → genTime within cert validity → optional nonce binding. `AnchorFailureCode` (`external_anchor.py:323`) enumerates 14 distinct fail reasons. The module banner explicitly contrasts this with `c2pa/timestamp.py`, which defines but never uses its signature-check codes.

`_local_tsa.py` mints a throwaway CA+TSA and issues **real** CMS `SignedData` tokens for offline tests, with adversarial knobs (`sign_key` override, `eku` omission, validity window, `status`). The banner is explicit: "this proves NOTHING about real time… Never pin a `LocalTSA` cert in production."

---

## Public API

### `tex.ecosystem` (`__init__.py:34`)
`EcosystemEngine`, `EcosystemBridge`, `EcosystemVerdict`, `EcosystemVerdictKind`, `EcosystemState`, `ProposedEvent`, `routing_result_to_proposed_event`.
Helper modules also expose (not in package `__all__`, but imported directly by callers): `ecosystem._window.{merkle_root, leaf_hash, empty_root, _INNER_PREFIX}` and the `ecosystem._attestation` builders/parsers.

### `tex.interchange` (`__init__.py:53`)
From `gix`: `Checkpoint`, `CheckpointPublisher`, `Ed25519NoteSigner/Verifier`, `SignedCheckpoint`, `build_add_checkpoint_body`, `build_checkpoint_publisher`, `consistency_path`, `inclusion_path`, `split_signed_note`, `verify_consistency`, `verify_inclusion`, `verify_note`, `get_active_checkpoint_publisher`, plus re-exported `merkle_root`/`empty_root`.
From `gix_witness`: `Witness`, `WitnessDescriptor`, `WitnessOutcome`, `WitnessProvenance`, `WitnessResponse`, `CosignedCheckpoint`, `CheckpointVerification`, `gather_cosignatures`, `verify_cosignature_line`, `verify_cosigned_checkpoint`, `FEDERATED_FALSE_REASON`.
From `gix_merge`: `FederatedMeanMerge`, `GixMergeRefused`, `OrgEvidenceSubmission`, `SubmissionVerification`, `merge_federated_evidence`, `verify_org_evidence`.
From `external_anchor` (not in package `__all__` but the module's): `verify_anchor_receipt`, `submit_anchor`, `build_timestamp_request`, `CheckpointAnchorRecord`, `AnchorVerification`, `AnchorFailureCode`, `anchor_subject_bytes/digest`, `Poster`.

---

## Wiring

### Wiring In — who imports these packages

**Ecosystem.** `ProposedEvent`/`EcosystemState` are widely consumed type contracts across the codebase (the data model is genuinely central): `graph/projection.py:27`, `ontology/validator.py:20`, `contracts/runtime_enforcement.py:43`, `contracts/_atoms.py:82`, `institutional/oracle.py:44`, `institutional/governance_log.py:40`, `drift/signal_registry.py:306`, `drift/change_point.py:65`, `causal/arm.py:71`, `compliance/_common.py:41`, `events/crypto_provenance.py:40`, `events/ledger.py:62`, `engine/contract_bridge.py:96`, `systemic/{risk_evaluator,probguard,digital_twin}.py`, `observability/governance_span.py:41` (`EcosystemVerdict`), and the API route `api/ecosystem_twin_routes.py:65` (`EcosystemState`). The engine + bridge themselves are imported only by `main.py:82-83` and tests.

**Interchange.** `main.py:43` (`build_checkpoint_publisher`); `discovery/conduit/seal.py:45,52` (`external_anchor` + `gix`); `provenance/bundle.py:70-71,247` (`external_anchor` + `gix.merkle_root` + `CheckpointPublisher`); `capstone/{compose,flow,verify,tamper}.py` (gix + gix_witness); plus tests and `scripts/anchor_checkpoint.py` / `scripts/anchor_demo.py`. `gix.py:85` imports `ecosystem._window` — the cross-package link.

### Live call path (from `tex.main`)

**Ecosystem (LIVE, flag-gated):**
1. `build_runtime()` constructs the engine collaborators (`main.py:926-944`) and `EcosystemEngine(... enabled=None ...)` at `main.py:946` (reads `TEX_ECOSYSTEM` at construction), then `EcosystemBridge(engine=...)` at `main.py:960`.
2. The bridge is injected into `EvaluateActionCommand(... ecosystem_bridge=ecosystem_bridge)` at `main.py:981`.
3. On every action evaluation, the command's post-PDP hook reaches `evaluate_action.py:957`; it short-circuits unless `os.environ.get("TEX_ECOSYSTEM","0") == "1"` (`evaluate_action.py:961`), auto-registers the actor in the graph, then calls `bridge.emit_verdict(routing_result=..., ...)` at `evaluate_action.py:999`, folding axis scores into `response.scores` under the `ecosystem.*` namespace and a `ecosystem_graduated_level:<L>` uncertainty flag.
4. `EvaluateActionCommand` is the body behind the live evaluate route (the PDP request path). With `TEX_ECOSYSTEM` unset (default), the path is bit-for-bit identical to pre-Thread-7.

Separately, the ecosystem **twin** route `POST /v1/ecosystem/twin/simulate` (`api/ecosystem_twin_routes.py`, registered `main.py:1528`) reads a live `EcosystemState` via `app.state.ecosystem_state_factory` (`main.py:1687` region; the factory `_build_ecosystem_state` at `main.py:1086`). The twin itself (`EcosystemDigitalTwin`) lives in `systemic/digital_twin.py`, **out of this scope**, but it consumes `EcosystemState` from this package.

**Interchange (LIVE on two paths):**
1. **GIX publisher seam** — `build_runtime()` calls `build_gix_checkpoint_publisher(decision_ledger)` at `main.py:874`. Inert `None` unless `TEX_SEAL_DECISIONS=1` (so `decision_ledger` exists) **and** `TEX_GIX_WITNESS` is set. Pull-based; never on the verdict path. This is genuinely wired but gated off by default → DEMO/opt-in in practice.
2. **Conduit provenance chain (always-on when conduit routes build)** — `main.py:1471` imports `ConduitProvenanceChain` from `discovery/conduit/seal.py`, constructed at `main.py:1492` and attached as `app.state.conduit_chain` (`main.py:1495`) behind the `/v1/conduit/*` routes (`build_conduit_router`, `main.py:1468`). `seal.py` uses `CheckpointPublisher`, `Ed25519NoteSigner`, `external_anchor.{CheckpointAnchorRecord, verify_anchor_receipt, SignedCheckpoint, build_timestamp_request, submit_anchor}`. So `interchange.gix` + `interchange.external_anchor` execute on the conduit grant-seal path.
3. **Provenance bundle** — `provenance/bundle.py` uses `verify_anchor_receipt` + `merkle_root` + `CheckpointPublisher` when assembling/verifying anchored evidence bundles.

`gix_witness` + `gix_merge` are reachable from `capstone/*` (the Wave-2 twelve-leap composition, classified INDIRECT in the spine pass) and from the conduit/anchor scripts, but I found **no direct `main.py`/api-route call** that gathers cosignatures or runs `merge_federated_evidence` on a live request. Their LIVE status (per the spine BFS) comes from being imported into the live `interchange.__init__` surface and the capstone module graph; the *federated cosign/merge behavior itself is exercised by tests and capstone flows, not a production route*.

**`wired_status` = MIXED.** The data-model types (`ProposedEvent`, `EcosystemState`, `EcosystemAxisScores`) and `_window.merkle_root` are LIVE and load-bearing across many subsystems. The engine's eight-step `evaluate()` and the bridge are LIVE-but-flag-gated (`TEX_ECOSYSTEM=1`, default off). The GIX publisher is LIVE-but-flag-gated (`TEX_GIX_WITNESS`, default off). The external anchor + checkpoint publisher run LIVE through the conduit chain. `gix_witness`/`gix_merge` federated behavior is effectively DEMO/TEST/capstone-only.

### Wiring Out — dependencies

**Internal (ecosystem):** `tex.ontology.validator` (step 1), `tex.graph.{projection, temporal_kg, exceptions}` (step 2 + mutation), `tex.events.{ledger, event, crypto_provenance, exceptions, _canonical}` (ledger append + canonical JSON), `tex.intervention.{kinds, engine, bounded_compromise, restorative}` (step 8, all under `TYPE_CHECKING` + lazy ctor), `tex.institutional.{oracle, governance_graph, governance_log, subagent_inheritance, _pq_signing}` (step 4, lazy), `tex.drift.signal_registry` (step 6, lazy import inside `evaluate`), `tex.pqcrypto.algorithm_agility` (attestation signing), `tex.ecosystem_config.is_flag_on`, `tex.observability.telemetry.emit_event`, `tex.domain.verdict.Verdict` (bridge re-export), `tex.engine.router.RoutingResult` (bridge). Notable: several imports are deferred to `TYPE_CHECKING` / lazy specifically to break import cycles (`engine.py:72-129` documents the `tex.pitch → c2pa → events → ecosystem → events.crypto_provenance` cycle).

**Internal (interchange):** `tex.ecosystem._window` (the one Merkle source), `tex.domain.evidence.{CombinedEvidence, EvidenceMaturity}`, `tex.events._ecdsa_provider.default_signature_provider`, `tex.provenance.{ledger._sha256_hex/_stable_json, models.SealedFactRecord}` (gix_merge).

**External libraries:** `cryptography` (Ed25519, RSA, ECDSA, X.509, CMS via hazmat), `pyasn1` + `pyasn1_modules` (rfc3161/rfc5280/rfc5652 ASN.1 for TSA tokens), `pydantic` (models), stdlib `hashlib`/`base64`/`threading`/`math`. No network library is imported by `interchange` (network is injected as `Poster`).

---

## Implementation Reality

**Real logic (verified in code):**
- RFC 9162 Merkle root (`_window.merkle_root`) + inclusion/consistency proof gen & succinct verify (`gix.py`) — concrete bit-level algorithms, not stubs.
- Real Ed25519 signed-notes and `cosignature/v1` cosigning/verification using `cryptography` (`gix.py`, `gix_witness.py`).
- The C2SP tlog-witness add-checkpoint state machine with atomic check-and-persist under a lock (`gix_witness.py:291`).
- Full offline CMS-signature-verifying RFC 3161 anchor verifier (`external_anchor.verify_anchor_receipt`) with real RSA/ECDSA verification, signed-attrs SET-OF re-tagging, cert pinning, and sole-EKU enforcement. The module banner claims this was VERIFIED 2026-06-17 against a real freetsa.org token `(claim, unverified here — the network round-trip is out of the unit tests by design)`, but the *verification code itself* is real and complete.
- `_local_tsa.py` mints **real** CMS `SignedData` tokens (not fake bytes) — honestly labelled demo-only.
- SCITT-shaped attestation envelope signing through a real pluggable signature provider (`_attestation.sign_envelope`).
- The engine's eight steps are all wired to real collaborators when injected; steps 3/5/6 invoke real contract/causal/drift logic.
- The systemic scorer the engine calls (`systemic/risk_evaluator.score`, `risk_evaluator.py:74`) is a **real** DTMC reachability computation (`reachability_probability`), **not** a `NotImplementedError` stub — the engine's `NotImplementedError` branch (`engine.py:873`) is a defensive guard for unvalidated per-tenant models, not the current behavior.

**Stubs / fallbacks / flags (honest in code):**
- `_neutral_axis_scores` (`engine.py:163`) — the P0 neutral PERMIT scores; the disabled path returns these.
- Steps 3-8 are **no-ops unless their collaborator is injected**. In the default `build_runtime` wiring, only `contracts=contract_enforcer` is passed (`main.py:958`); **no oracle, causal, drift, systemic, or intervention_calc** is wired. So even with `TEX_ECOSYSTEM=1`, steps 4-8 are pass-throughs in the shipped composition root — the engine PERMITs on aggregate with a contract-severity axis only. This is a real gap between the eight-step narrative and the default wiring.
- `_window.py:32-33` TODOs (inclusion/consistency proof gen) are **resolved by `gix.py`**, not actually missing — but the TODO comment in `_window.py` is now stale.
- `_attestation.py` TODOs (COSE/CBOR wire format, VDF time anchor, zk_proof_id) are genuine future work; the JSON-with-trailer format is what runs.
- `bridge.py` reverse direction (ecosystem FORBID → kill-switch) is a documented unimplemented "slot reserved" (`bridge.py:21`).
- `federated=True` is **structurally unreachable** in `interchange` by construction (the strongest honesty signal in the codebase) — not a stub so much as a deliberate, enforced ceiling.
- GIX publisher and external anchor run only under env flags / the conduit path; default deployments do not anchor.

No leetspeak-bypass / `rm -rf` permit / inert-governance patterns appear in this scope.

---

## Technology / SOTA

- **RFC 9162 (Certificate Transparency v2)** Merkle Tree Hash, inclusion proofs (§2.1.3), consistency proofs (§2.1.4), with correct `0x00`/`0x01` domain separation — bit-compatible with CT verifiers.
- **C2SP wire formats** (re-fetched 2026-06-11 per banners): `tlog-checkpoint` note body, `signed-note` (Ed25519, 4-byte key id), `tlog-witness` add-checkpoint state machine, `cosignature/v1`.
- **RFC 3161** Time-Stamp Protocol + **RFC 5652 CMS** `SignedData` verification + **RFC 5280** X.509 — full ASN.1 via pyasn1; the signed-attrs IMPLICIT-[0]→SET-OF re-tag (RFC 5652 §5.4) is handled correctly.
- **IETF SCITT architecture draft -22** Signed-Statement / CWT-claims shape for the ecosystem attestation envelope.
- **E-value statistics**: arithmetic-mean merge of e-values under arbitrary dependence (Vovk & Wang 2021 cited; the *only* admissible merge under dependence), in log space for numerical stability.
- **RiskGate viability index** (`1 - max(U,SB,RG)`) and **GAAT graduated enforcement** (L0..L4) surfaces — formulas real and code-verified; academic citations `(claim, unverified)`.
- Crypto: Ed25519, ECDSA-P256, RSA-PKCS1v15, SHA-256/384/512, all via the `cryptography` hazmat layer (real native primitives, no hollow fallback).
- Design patterns: dependency injection throughout (testable fakes), fail-closed everywhere, structural-unconstructibility for honesty ceilings, pull-based STH publishing, injected network boundary (`Poster`), single-source-of-truth for tree hashing.

---

## Persistence

Everything in scope is **in-memory / process-local**, with one durable-export path:

- The ecosystem engine's graph (`InMemoryTemporalKG`) and ledger (`InMemoryLedger`) are fresh per process (`main.py:930-935`); state accumulates across the process lifetime and is lost on restart. `attest_state` linearly scans this in-memory ledger.
- The GIX decision ledger (`SealedFactLedger`) is in-memory and opt-in (`TEX_SEAL_DECISIONS`); the banner (`gix.py:62`) is explicit that a restart starts a fresh chain which witnesses correctly treat as a fork. **Checkpoint continuity across restarts is NOT claimed** — and that is honestly stated.
- `Witness._latest` (origin → size/root) is in-memory under a lock; restart drops it.
- The only durable artifact is `CheckpointAnchorRecord` (`external_anchor.py:249`), persisted as JSONL by the daily job `scripts/anchor_checkpoint.py` (out of scope), plus the conduit chain's sealed records via `discovery/conduit/seal.py`. The anchor record is **additive — never inside the hash chain**.

No database, no ORM, no Postgres in this scope. Durable backing is repeatedly noted as a future ("Thread 9+", "M0 durable track") concern.

---

## Notable Findings

1. **Eight-step engine is only ~one-and-a-half steps in the default wiring.** Even with `TEX_ECOSYSTEM=1`, `build_runtime` injects only `contracts=` (`main.py:958`) — no oracle/causal/drift/systemic/intervention_calc. So steps 4-8 are pass-throughs and step 8's FORBID/SANCTION/REMEDIATE gate is dormant by default (the `intervention_calc` gating dependency is `None`). The pipeline is real and fully implemented, but the shipped composition root does not light it up. This is the most important reality gap to flag against the engine docstring's "Thread 7 complete / steps 1-7 wired" narrative (`engine.py:457`).

2. **Default-default is inert.** `TEX_ECOSYSTEM` off → inert PERMIT; `TEX_GIX_WITNESS` off → no publisher; `TEX_SEAL_DECISIONS` off → no decision ledger. Out of the box, the ecosystem engine and GIX log do nothing on the request path. This matches the banners and is a deliberate fail-closed-to-legacy posture, not a defect — but it means production behavior depends entirely on three env flags.

3. **`_window.py` TODOs are stale.** `_window.py:32-33` say inclusion/consistency proof generation is "TODO(P1)" — but `gix.py` fully implements both and imports `_window` for the leaf/inner hashing. The TODO comment should be retired (it now contradicts shipped code in the sibling package). The `gix.py` banner (`gix.py:8-9`) correctly notes it fills exactly this gap.

4. **Honesty discipline is genuinely enforced, not decorative.** `federated=True` is unreachable because `EXTERNAL_FEDERATED` has no constructor (`gix_witness.py:181,256` both raise). The local TSA banner says it "proves NOTHING about real time." The anchor module explicitly calls out that `c2pa/timestamp.py` defines but never uses its signature-check codes, and does the full CMS check here instead. `gix_merge` imports module-private ledger helpers on purpose so a rename fails loudly. These are strong positive signals — the code does what the banners say.

5. **Two truthful-but-unverifiable interop claims.** `external_anchor.py:67-74` claims the verifier returned `ok=True` against a real freetsa.org token on 2026-06-17, and `gix.py:18-21` admits cross-implementation interop (vs Go's `sumdb/note`) has **NOT** been exercised. Both are appropriately hedged. The verification *code* is real and complete regardless; only the live-interop assertion is `(claim, unverified)` from a static read.

6. **`gix_witness`/`gix_merge` federated behavior has no live production route.** They are LIVE in the import graph (via `interchange.__init__` and `capstone/*`) and heavily tested, but no `main.py`/api path gathers cosignatures or runs `merge_federated_evidence` on a request. In practice this is capstone/demo/test surface, consistent with the `research-early` maturity tag on every interchange module.

7. **Engine ABSTAIN-vs-FORBID nuance is deliberate.** A ledger append that succeeds but whose graph edge is rejected yields ABSTAIN (`engine.py:1191`), not FORBID, because the audit record is already durable — a subtle, correct design choice worth preserving.

8. **The cross-package coupling is the Merkle root.** `interchange.gix` builds its entire transparency-log proof stack on `ecosystem._window`'s MTH (`gix.py:85`), and the external anchor timestamps the C2SP note body that wraps that same root. The two packages are one cryptographic spine: ecosystem produces window roots, interchange proves/anchors them.
