# Subsystem Dossier: Events Bus & Receipts

**Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/events/` and `/Users/matthewnardizzi/dev/tex/src/tex/receipts/`
**Branch:** `feat/proof-carrying-gate`
**Layer (self-declared):** Layer 5 "Evidence" (`events/__init__.py:29-30`, `receipts/__init__.py:40-41`)
**Verification standard:** every claim below is traced to source `file:line`. Docstring/`.md` claims are labelled `(claim, unverified)` unless confirmed in code.

---

## Overview

Two sibling units that both self-declare as the "Evidence" layer but are wired very differently:

- **`tex.events`** is a **REAL, LIVE** append-only cryptographic event ledger. Every admitted ecosystem event is hash-chained, canonicalized (RFC 8785 / JCS subset), ECDSA-P256 signed, and verified at append time and on demand. It is instantiated in `tex.main.build_runtime` and feeds the `EcosystemEngine` PERMIT path. The cryptography is genuine (`cryptography` library, SECP256R1 + SHA-256, DER signatures), verified live below.

- **`tex.receipts`** is a **REAL but NOT-LIVE** HMAC-SHA-256 tool-receipt subsystem ("NabaOS-style", per arxiv 2603.10060 claim in `receipts/__init__.py:20`). The issuance/verification logic is fully implemented and works (smoke-tested below), including fabrication detection, HMAC tamper detection, epistemic-source routing (Nyaya pramana taxonomy), and count-misstatement detection. **But no LIVE code path constructs `ReceiptIssuer`/`ReceiptVerifier`.** Its only non-self importer is `tex._pending.pitch.insurer_export` (an ORPHAN under `_pending/`). The spine pass classified `receipts=INDIRECT`; the code shows it is effectively **DEMO/TEST-ONLY** (exercised only by `tests/frontier/test_receipts.py` and `test_scaffolding_imports.py`).

The two units share a conceptual seam — `Event.tool_receipt_id` (`events/event.py:59`) is meant to link a ledger event to a tool receipt — but **that field is never populated from a real receipt anywhere in LIVE code** (verified below).

---

## File Inventory

### `tex/events/` (995 LOC)

| File | LOC | Role |
|------|-----|------|
| `__init__.py` | 94 | Package init. Eager re-exports of `Event`, `genesis_ledger_hash`, exception hierarchy; **PEP 562 lazy** (`__getattr__`) re-exports of `CryptoProvenance`, `EventLedger`, `InMemoryLedger` to avoid dragging the ecosystem/telemetry chain onto the clean-room verify path (`__init__.py:54-73`). |
| `event.py` | 79 | `Event` pydantic model (frozen, `extra="forbid"`) — the immutable signed ledger record; `genesis_ledger_hash()` sentinel (64 zero hex); `canonical_record_input()` defines the tamper surface. |
| `exceptions.py` | 38 | Exception hierarchy rooted at `LedgerAppendError` (6 subclasses: SequenceGap, ChainLink, MissingUpstream, SignatureVerification, RecordHashMismatch, PayloadHashMismatch). |
| `_canonical.py` | 90 | RFC 8785 JCS-subset canonicalizer (`canonical_json`, `sha256_hex`, `canonical_sha256`). Pure stdlib. **Rejects floats** (`_canonical.py:71-75`). Widely reused across the codebase (c2pa, graph, pqcrypto, compliance, institutional, receipts). |
| `_ecdsa_provider.py` | 157 | `EcdsaP256Provider` (SECP256R1 + SHA-256 + DER, PKCS8/PEM keys) implementing the `SignatureProvider` protocol; `default_signature_provider()` dispatcher; `ml_dsa_not_yet_wired()` honest stub; `signature_algorithm_for()`. |
| `crypto_provenance.py` | 183 | `CryptoProvenance` — attaches payload hash + record hash + signature to a `ProposedEvent`, producing a fully-formed `Event`. The canonical engine path. |
| `ledger.py` | 354 | `EventLedger` Protocol + `InMemoryLedger` (append-only, hash-chained, signature-verifying). The system of record. Also satisfies `tex.ontology.validator.EventLookup`. |

### `tex/receipts/` (707 LOC)

| File | LOC | Role |
|------|-----|------|
| `__init__.py` | 55 | Package init. Eager re-exports of all public symbols. **No lazy machinery** (unlike events). |
| `epistemic_source.py` | 35 | `EpistemicSource(str, Enum)` — Nyaya pramana taxonomy: PRATYAKSHA / ANUMANA / SHABDA / ABHAVA / UNGROUNDED. |
| `receipt.py` | 74 | `ToolExecutionReceipt` pydantic model (frozen, `extra="forbid"`, field-length validated); `canonical_signing_input()` excludes `hmac_signature` + `hmac_key_id`. |
| `runtime.py` | 451 | `ReceiptIssuer` (HMAC-SHA-256 sign on issue) + `ReceiptVerifier` (resolve, HMAC-verify, epistemic routing, count-misstatement regex check) + helpers. The substantive logic. |
| `store.py` | 92 | `ReceiptStore` Protocol + `InMemoryReceiptStore` (append-only dict, `RLock`-guarded, rejects re-append of same id). |

---

## Internal Architecture

### Events — data flow

**1. `Event` model (`event.py:40-79`).**
Frozen pydantic model. Fields of note: `record_hash`, `payload_sha256`, `pq_signature_b64`, `pq_signing_key_id`, `pq_signature_algorithm` (default `"ecdsa-p256"`, `event.py:58`), `previous_ledger_hash`, `upstream_event_ids`, `tool_receipt_id` (default `None`, `event.py:59`).
`canonical_record_input()` (`event.py:61-79`) returns the dict whose canonical JSON is hashed into `record_hash`. It deliberately **excludes the signature fields** (they are computed *over* this dict) and includes `tool_receipt_id` so receipt linkage is bound by the hash. The `kind` field is a bare `str` (`event.py:46`) — there is no `EventKind` enum in this unit; the canonical event/entity type registries live in `tex.ontology.event_types` / `tex.ontology.entity_types` (out of scope).

**2. Canonicalization (`_canonical.py`).**
`canonical_json` (`_canonical.py:28-48`) is `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False)`, guarded by `_assert_canonicalizable` (`_canonical.py:64-90`) which walks the value and rejects floats, non-str dict keys, and any non-JSON leaf (datetime/set/custom). `canonical_sha256` = SHA-256 hex of that string.

**3. Provenance attachment (`crypto_provenance.py:81-170`).**
`CryptoProvenance.attach()` is **stateless w.r.t. sequence** — the caller passes `sequence_number` and `previous_ledger_hash`. Steps (matching the docstring `crypto_provenance.py:93-99`):
- `payload_sha256 = canonical_sha256(proposed.payload)` (line 122)
- build `record_input` dict covering every identity/lineage field (lines 124-134)
- `record_hash = sha256_hex(canonical_json(record_input))` (line 135)
- `signature_bytes = self._provider.sign(record_hash.encode("utf-8"), self._key)` (line 137) — **the signature is over the record_hash UTF-8 bytes, not the payload**
- base64-encode for model storage (line 140)
- assemble the frozen `Event` (lines 144-160)
- emit `events.crypto_provenance.attached` telemetry (lines 162-169).
`public_key`, `signing_key_id`, `provider` are exposed as properties (lines 172-183) for verifier wiring.

**4. The ledger (`ledger.py`).**
`InMemoryLedger.__init__` (`ledger.py:94-104`) holds `_events: list[Event]`, `_index: dict[str, Event]`, optional `verifying_public_key` + `signing_provider`, and a one-shot `_warned_no_verification` flag.

`append()` (`ledger.py:108-158`) enforces six invariants in order (documented `ledger.py:112-119`, implemented 121-150):
1. `sequence_number == len(self) + 1` else `SequenceGapError` (121-126)
2. `previous_ledger_hash` matches prior record's `record_hash` (or genesis sentinel) else `ChainLinkError` (128-138)
3. every `upstream_event_id` is in `_index` else `MissingUpstreamError` (140-144)
4. `_verify_record_integrity` re-derives `payload_sha256` + `record_hash` (146 → 295-308)
5. `_verify_signature` (147 → 310-341)
6. then store + index + emit `events.ledger.appended` (149-158).

`append_proposed()` (`ledger.py:160-188`) is the convenience engine path: it computes the next sequence + chain head, calls `provenance.attach(...)` (duck-typed — note `CryptoProvenance` is `TYPE_CHECKING`-only here, `ledger.py:51-52`, to break an import cycle), then runs the full `append()`.

Read path: `get` (192), `stream_after` (195-205, O(k) scan, `seq<0` returns all), `exists` (207-209, satisfies `EventLookup`), `__len__` (211).

`verify_chain()` (`ledger.py:216-291`) re-verifies an inclusive `[from_sequence, to_sequence]` slice: range guards (226-242), establishes predecessor hash (244-250), then for each record re-runs `_verify_record_integrity`, checks `previous_ledger_hash` linkage against the rolling `prior_hash`, and runs `_verify_signature(..., force=True)`. **`force=True`** (line 274) means: if no provider/key is configured, `verify_chain` *raises* `SignatureVerificationError` rather than silently skipping (`ledger.py:318-323`) — a deliberate "you asked for a full re-verify, I can't fulfill it" stance. Emits `verify_chain.failed` (with reason + offending sequence) or `verify_chain.ok`.

`_verify_signature()` (`ledger.py:310-341`): if no provider/key, emit a **one-shot** soft-warning `events.ledger.signature_verification_skipped` and return (unless `force`). Otherwise base64-decode the signature and call `provider.verify(record_hash.encode("utf-8"), signature, verifying_public_key)`.

### Receipts — data flow

**1. `ToolExecutionReceipt` (`receipt.py:26-71`).**
Frozen, validated field lengths (`receipt_id` 16-64, hashes exactly 64 hex, `result_count >= 0`). `canonical_signing_input()` (lines 49-71) excludes `hmac_signature` and `hmac_key_id` (per `_UNSIGNED_FIELDS`, line 23) — the key id is an opaque pointer, not part of the authenticated body.

**2. `ReceiptIssuer` (`runtime.py:98-216`).**
Constructor (101-121) validates `hmac_key >= 16 bytes`, non-empty `key_id`/`runtime_version`. `issue()` (131-206):
- validates inputs, parses+validates ISO timestamps **requiring a timezone** (`_parse_iso`, 208-216), rejects `completed_at < started_at`
- `tool_input_hash = canonical_sha256(tool_input)`, `tool_output_hash = canonical_sha256(_canonicalize_output(tool_output))` (165-166)
- `result_count = _result_count_of(tool_output)` (167) — heuristic (78-95): list/tuple/set/frozenset/dict → `len()`, None → 0, else → 1
- build unsigned dict, `signature = _hmac_hex(hmac_key, canonical_json(unsigned))` (170-181)
- assemble receipt, `store.append(receipt)` (183-196), emit `tex.receipts.issued` (198-205).

`_canonicalize_output` (`runtime.py:219-246`) coerces arbitrary Python into the JCS subset: pass-throughs, tuple/set→list, tz-aware datetime→ISO (rejects naive), dict recursion, **`repr()` fallback for anything else** (line 246) — explicitly a TODO(p1) papered-over case (235-235).

**3. `ReceiptVerifier` (`runtime.py:249-448`).**
`verify_claim()` (273-378) returns `(is_grounded, issues)`:
- UNGROUNDED → immediately `(False, ("ungrounded claim",))` (323-332)
- resolve every claimed id: miss → "fabricated receipt id" (341), HMAC fail → "hmac mismatch" (344) (`_signature_ok`, 380-388, constant-time `hmac.compare_digest`)
- per-source structural checks (349-360): PRATYAKSHA needs ≥1 id, ANUMANA/SHABDA need ≥1 resolved, ABHAVA needs ≥1 resolved with `result_count == 0`
- count-misstatement check for PRATYAKSHA/ANUMANA only (`_count_misstatement`, 390-425): extracts integer literals via regex `\b(\d{1,12})\b` (line 62), flags only when **every** extracted integer is unaccounted for (conservative, avoids years/ids false positives)
- emit `tex.receipts.verified` or `tex.receipts.hallucination_detected` (427-448).

`_signature_ok` returns `False` for any receipt whose `hmac_key_id != self._key_id` (382-386) — single-key verifier; multi-key dispatch is a TODO(p1).

**4. Store (`store.py:35-90`).** `InMemoryReceiptStore` is an append-only `dict[str, ToolExecutionReceipt]` under an `RLock`. `append` raises `ValueError` on duplicate id (58-65). `list_for_session` returns receipts sorted by `started_at` (72-85).

---

## Public API

### `tex.events` (`__init__.py:80-94`)
- `Event`, `genesis_ledger_hash` (eager)
- `EventLedger` (Protocol), `InMemoryLedger`, `CryptoProvenance` (lazy via PEP 562)
- Exceptions: `LedgerAppendError`, `ChainLinkError`, `MissingUpstreamError`, `PayloadHashMismatchError`, `RecordHashMismatchError`, `SequenceGapError`, `SignatureVerificationError`
- **Heavily-used internal submodules** imported directly by other units (bypassing `__init__` to dodge cycles): `tex.events._canonical` (canonical_json/sha256_hex/canonical_sha256) and `tex.events._ecdsa_provider` (`default_signature_provider`, `EcdsaP256Provider`, `signature_algorithm_for`).

### `tex.receipts` (`__init__.py:48-55`)
- `EpistemicSource`, `ToolExecutionReceipt`, `ReceiptIssuer`, `ReceiptVerifier`, `InMemoryReceiptStore`, `ReceiptStore`

---

## Wiring

### Wiring In — Events (LIVE)

**Live call path from the app:**
```
tex.main.build_runtime (main.py:926-959)
  ├─ default_signature_provider()                          [main.py:926]
  ├─ provider.generate_keypair("tex-ecosystem-engine")     [main.py:927-929]
  ├─ InMemoryLedger(verifying_public_key=..., signing_provider=...)   [main.py:932-935]
  ├─ CryptoProvenance(signing_key=..., signing_provider=...)          [main.py:936-939]
  ├─ OntologyValidator(event_lookup=_ecosystem_ledger)     [main.py:940-944]  (ledger doubles as EventLookup)
  └─ EcosystemEngine(events=_ecosystem_ledger, provenance=_ecosystem_provenance, ...) [main.py:946-959]
        └─ EcosystemBridge(engine=ecosystem_engine)         [main.py:960]
              └─ EvaluateActionCommand(ecosystem_bridge=ecosystem_bridge) [main.py:962-982]
```
`EvaluateActionCommand` is reachable from multiple API routes — e.g. `api/guardrail.py:825`, `api/guardrail_streaming.py:179/325/415`, `api/mcp_server.py:255`, all via `_get_evaluate_action_command(request)` reading `request.app.state.evaluate_action_command` (`api/guardrail.py:872-882`). On the PERMIT path the engine calls `self._events.append_proposed(proposed, provenance=self._provenance, event_id=...)` (`ecosystem/engine.py:1157-1161`), which exercises `CryptoProvenance.attach` + `InMemoryLedger.append`.

**Gating flag:** the ecosystem pass is **guarded by `TEX_ECOSYSTEM`** (env). The bridge always exists, but the engine short-circuits when `TEX_ECOSYSTEM != "1"` (`commands/evaluate_action.py:919-922`; `ecosystem/bridge.py:170` docstring). So the *ledger-append* portion of the events path runs LIVE only when `TEX_ECOSYSTEM=1`. The events **submodules** (`_canonical`, `_ecdsa_provider`) are LIVE unconditionally — pulled by c2pa, graph, provenance (`provenance/bundle.py:65`, `provenance/ledger.py:31`, `provenance/delegation.py:40`), voice (`voice/attestation.py:53`), interchange (`interchange/gix_merge.py:58`), and pqcrypto (`pqcrypto/evidence_chain_signer.py:67`, `pqcrypto/evidence_quorum.py:51`, `pqcrypto/algorithm_agility.py:215`).

**`wired_status` (events): LIVE** (the package, its canonical helpers, and the ECDSA provider are unconditionally on live paths; the full ledger-append flow is flag-gated by `TEX_ECOSYSTEM`).

### Wiring In — Receipts (NOT LIVE)

Grep across `src/tex` for `ReceiptIssuer | ReceiptVerifier | InMemoryReceiptStore | ToolExecutionReceipt | from tex.receipts import`:
- The **only** non-self importer is `tex/_pending/pitch/insurer_export.py:95` (`from tex.receipts.receipt import ToolExecutionReceipt`), and `_pending` is an ORPHAN subsystem (spine pass: `_pending=ORPHAN`).
- `ReceiptIssuer`/`ReceiptVerifier`/`InMemoryReceiptStore` are **never instantiated** outside the package itself or tests.
- Test-only callers: `tests/frontier/test_receipts.py`, `tests/frontier/test_scaffolding_imports.py`.
- **No `tex.main`, no `tex.api`, no command constructs receipts.** There is no `app.state` wiring, no route.

**`wired_status` (receipts): DEMO_TEST_ONLY.** (Spine called it INDIRECT — the only import edge is from `_pending` (orphan) and from tests; no live runtime path exists. The code is real and passes, but nothing in the running app uses it.)

### The events↔receipts seam (NOT connected)

`Event.tool_receipt_id` (`event.py:59`) and `CryptoProvenance.attach(..., tool_receipt_id=...)` (`crypto_provenance.py:88`) and `InMemoryLedger.append_proposed(..., tool_receipt_id=...)` (`ledger.py:166`) exist to bind a ledger event to a tool receipt. **But the live engine call `append_proposed(proposed, provenance=..., event_id=proposed_event_id)` (`engine.py:1157-1161`) passes no `tool_receipt_id`**, so it defaults to `None`. Grep confirms `tool_receipt_id` is never assigned from a real `receipt.receipt_id` anywhere. The two units are independent at runtime.

### Wiring Out

**Events depends on:**
- `tex.observability.telemetry.emit_event` (`ledger.py:48`, `crypto_provenance.py:47`) — LIVE telemetry.
- `tex.pqcrypto.algorithm_agility` (`SignatureProvider`, `SignatureKeyPair`, `SignatureAlgorithm`, `get_signature_provider`) — `ledger.py:49`, `crypto_provenance.py:48`, `_ecdsa_provider.py:33`.
- `tex.ecosystem.proposed_event.ProposedEvent` (`crypto_provenance.py:40`; `TYPE_CHECKING` in `ledger.py:62`).
- External: `cryptography` (SECP256R1, SHA256, PEM/PKCS8 serialization — `_ecdsa_provider.py:29-31`), `pydantic` (`event.py:25`), stdlib `hashlib`/`json`/`base64`/`hmac`.

**Receipts depends on:**
- `tex.events._canonical` (`canonical_json`, `canonical_sha256`) — `runtime.py:52` (cross-unit reuse of the events JCS helper).
- `tex.observability.telemetry.emit_event` (`runtime.py:53`).
- External: stdlib `hmac`, `hashlib.sha256`, `secrets`, `re`, `pydantic`, `threading.RLock`.

---

## Implementation Reality

**REAL (verified live):**
- **ECDSA-P256 signing/verification is genuine.** `EcdsaP256Provider` uses `cryptography` SECP256R1 + SHA-256 + DER (`_ecdsa_provider.py:40-83`). Smoke test (`PYTHONPATH=src`): `default_signature_provider()` → `EcdsaP256Provider`; sign produced a **72-byte DER signature**; verify of the correct message → `True`, tampered → `False`. Not a stub.
- **Hash chain + canonicalization are real.** `InMemoryLedger.append` enforces all six invariants with real SHA-256 re-derivation (`ledger.py:295-308`); `verify_chain` re-walks the slice (`ledger.py:216-291`).
- **HMAC receipts are real.** Smoke test issued a receipt (`rcpt-` + 32 hex), HMAC-SHA-256 over canonical JSON; verifier returned `(True, ())` for a valid pratyaksha claim, `(False, ('fabricated receipt id: ...',))` for a bad id, and `(False, ('count misstatement: claim mentions [99] ...',))` for a count lie. All three NabaOS detection types work as coded.

**STUBS / honest non-implementations:**
- `ml_dsa_not_yet_wired()` (`_ecdsa_provider.py:135-148`) — raises `NotImplementedError` by design ("Thread 4"). It is **not called by anything** (grep: only definition + docstring mention). Honest dead-end, not a silent fallback.
- The ML-DSA story in docstrings (`crypto_provenance.py:22-27`, `event.py:56`) is **aspirational**: the default and only shipped events path is ECDSA-P256. `pq_signature_algorithm` defaults to `"ecdsa-p256"` (`event.py:58`). The `pq_` prefix on field names is misleading — there is no post-quantum signing on the events ledger today.

**DEAD / vestigial logic:**
- `default_signature_provider()` (`_ecdsa_provider.py:109-132`) claims to fall back to the local `EcdsaP256Provider` *if* `get_signature_provider(ECDSA_P256)` raises `NotImplementedError`. But `tex.pqcrypto.algorithm_agility.get_signature_provider` **returns `EcdsaP256Provider()` for ECDSA_P256** (`algorithm_agility.py:215-218`) and does **not** raise. So the `try` always succeeds and the `except NotImplementedError` branch (lines 131-132) is **effectively unreachable**. Both paths yield the same provider class, so behavior is correct — but the documented fallback is dead and the docstring (`_ecdsa_provider.py:113-117` "if that raises NotImplementedError (the current scaffolding behavior)") is stale.

**Float gap (real limitation):** `canonical_json` rejects floats (`_canonical.py:71-75`); RFC 8785 I-JSON number serialization is a tracked `TODO(P1)` (`_canonical.py:18`). Any event/receipt payload containing a float will raise `TypeError` at hashing time.

**Other TODOs (not blocking, but open):** `_canonicalize_output` `repr()` fallback (`runtime.py:235`), single-key verifier (`runtime.py:385`), locale-aware number extraction (`runtime.py:61`), URL-refetch protocol + "six hallucination types" verification (`runtime.py:305-312`, `runtime.py:405`).

---

## Technology / SOTA

- **ECDSA over NIST P-256 (SECP256R1) + SHA-256, DER signatures, PKCS8/PEM keys** — FIPS 186-5 (`_ecdsa_provider.py:14`), via `cryptography`.
- **RFC 8785 JSON Canonicalization Scheme (subset)** for deterministic hashing (`_canonical.py:1-19`). Mirrors `tex.evidence.chain._stable_json`.
- **Tamper-evident hash chain** — each record links `previous_ledger_hash → prior record_hash`; signature is over `record_hash` (not payload), so identity/lineage fields are all bound. Cited inspiration: arxiv 2512.18561 "AAF" (`__init__.py:17`, `ledger.py:13-18`) — *(claim, unverified; the citation is a design reference, the chain is independently real)*.
- **HMAC-SHA-256 tool receipts** with constant-time compare (`runtime.py:388`) — the integrity argument is that the LLM never holds the key, so it cannot forge a receipt id.
- **Nyaya Shastra pramana taxonomy** (PRATYAKSHA/ANUMANA/SHABDA/ABHAVA/UNGROUNDED) mapped to verification rules (`epistemic_source.py`, `runtime.py:349-360`). Cited: arxiv 2603.10060 "Tool Receipts, Not Zero-Knowledge Proofs" (`receipts/__init__.py:20`) — detection-rate numbers (94.2%/87.6%/91.3%, `__init__.py:28-29`) are **paper claims, unverified in this repo**.
- **Design patterns:** structural typing (`Protocol` + `runtime_checkable` for `EventLedger`/`ReceiptStore`), dependency injection of the signature/HMAC provider (algorithm agility), PEP 562 lazy module attributes to break import cycles (`events/__init__.py:65-73`), frozen pydantic value objects.

---

## Persistence

**Both units are in-memory only in the shipped paths.**
- `InMemoryLedger` holds `list[Event]` + `dict[str, Event]` (`ledger.py:100-101`). No durable backend exists in scope. The `__init__.py` docstring's "P0 production deployment box" / quorum-shard talk (`ledger.py:16-22`) is *(claim, unverified)* — quorum is deferred to `_pending.events.quorum_shard` (`ledger.py:22`), which is orphaned.
- `InMemoryReceiptStore` holds `dict[str, ToolExecutionReceipt]` under `RLock` (`store.py:44-45`). The `store.py` docstring says "Use Postgres in production, SQLite in dev" (`store.py:4`) — **no such backend exists** in scope; only the in-memory implementation is present. *(claim, unverified.)*
- Append-only invariants are enforced in-process: ledger by `SequenceGapError`/`ChainLinkError` (`ledger.py:121-138`); receipt store by duplicate-id `ValueError` (`store.py:58-65`).
- Durability is at-best transitive: the LIVE ledger instance in `build_runtime` (`main.py:932`) lives only for the process lifetime. (The *durable* ledgers in `tex.main` — `PostgresActionLedger`, `SealedFactLedger` — are different subsystems, not `tex.events`.)

---

## Notable Findings

1. **Receipts is real but orphaned at runtime.** Fully-implemented, test-passing NabaOS receipt subsystem with **zero LIVE wiring**. Its only non-test importer is in `_pending/` (orphan). Classify **DEMO_TEST_ONLY**, not LIVE. (Spine said INDIRECT; the only edges are orphan + tests.)

2. **The events↔receipts link is unconnected.** `tool_receipt_id` plumbing exists end-to-end in the events unit, but the live engine never passes a real receipt id (`engine.py:1157-1161`), and nothing constructs a receipt to link. The "events ledger tags an HMAC tool receipt" story (`events/__init__.py:13`) is **not realized in LIVE code**.

3. **`pq_*` field names overstate cryptographic posture.** `pq_signature_b64`, `pq_signing_key_id`, `pq_signature_algorithm` (`event.py:56-58`) imply post-quantum signing. The shipped algorithm is classical **ECDSA-P256**; ML-DSA is an explicit `NotImplementedError` stub (`_ecdsa_provider.py:135-148`). Not a security hole, but a naming/claim mismatch an auditor would flag.

4. **Dead fallback branch.** `default_signature_provider()`'s `except NotImplementedError` (`_ecdsa_provider.py:131-132`) is unreachable because `get_signature_provider(ECDSA_P256)` returns a provider, never raises (`algorithm_agility.py:215-218`). The accompanying docstring ("the current scaffolding behavior") is stale.

5. **`verify_chain` with no key is fail-closed.** Unlike `append` (which soft-skips signature checks when no provider is configured, `ledger.py:311-324`), `verify_chain` forces verification and **raises** if no key/provider is wired (`ledger.py:318-323`, `force=True` at 274). Good security default, but means a ledger built without a verifying key cannot be chain-verified at all.

6. **Float-blind canonicalization is a latent foot-gun.** `_canonical.py` rejects floats (`:71-75`). Since `canonical_json` is reused across c2pa, graph, pqcrypto, compliance, institutional, and receipts, any of those passing a float payload will raise `TypeError`. Tracked as TODO(P1) but unfixed.

7. **Detection-rate claims are paper numbers, not measured here.** The 94.2%/87.6%/91.3% figures (`receipts/__init__.py:28-29`) and AAF storage figures (`ledger.py:16-18`) come from cited arxiv papers; nothing in this repo measures them. Label any external repetition as *(claim, unverified)*.

8. **Strong import-cycle hygiene.** Both `__init__` files and `ledger.py`/`engine.py` use `TYPE_CHECKING` + PEP 562 lazy exports + inline imports specifically to keep the offline ECDSA verify path free of the heavy ecosystem/telemetry chain (`events/__init__.py:47-73`, `ledger.py:31-62`). This is genuine engineering, not cargo-culting — and it is why so many external units import `tex.events._canonical`/`_ecdsa_provider` submodules directly instead of the package root.
