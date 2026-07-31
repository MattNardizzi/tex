# Subsystem Dossier: `_pending` (parked / staging modules)

**Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/_pending/`
**Branch:** `feat/proof-carrying-gate`
**Classification:** **ORPHAN** — no module outside `_pending/` imports anything in it.
**Verify imports with:** `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src python ...`

---

## Overview

`_pending` is Tex's **staging / parking lot**. The directory holds code that exists on disk but is deliberately *not wired into the running app*. The underscore prefix is the contract signal: "intentionally not wired yet" (`src/tex/_pending/__init__.py:12`). The package marker confirms it is not a real architectural layer: `__layer__ = None`, `__layer_kind__ = 'pending'` (`src/tex/_pending/__init__.py:27-28`).

The 34 files split sharply into **two populations**:

1. **Hollow stubs** (interop, compliance, events, graph subtrees) — small files whose public functions/classes are `raise NotImplementedError(...)` or `pass`-only. These are scaffolding placeholders for future integration work (A2A, Okta, Ping, Microsoft, NIST, NAIC, JanusGraph, Postgres KG, quorum sharding).

2. **A fully-real-but-orphaned product surface** (`pitch/` + `api/pitch_routes.py`) — ~2,300 lines of working code that imports *live* Tex subsystems (`tex.api.auth`, `tex.pqcrypto`, `tex.c2pa`, `tex.observability`, `tex.receipts`, `tex.domain`, `tex.events`), builds dossiers, signs evidence packets with real post-quantum/classical crypto, and round-trips through an independent verifier. It runs end-to-end today (verified below) — it is simply never mounted into `tex.main`.

**The single most important finding:** nothing in the live application imports `_pending`. The pitch HTTP router (`build_pitch_router`) has **zero callers** and is **not** in the `app.include_router(...)` block in `tex.main` (`src/tex/main.py:1441-1529`). A test (`tests/frontier/test_scaffolding_imports.py`) actively *enforces* that the active `tex.pitch.*` / `tex.api.pitch_routes` names MUST FAIL to import — the parking is intentional and guarded, not an accident.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `_pending/__init__.py` | 28 | Parking-convention doc; `__layer__=None`, `__layer_kind__='pending'`. |
| `_pending/api/__init__.py` | 3 | Docstring-only marker for parked API routes. |
| `_pending/api/pitch_routes.py` | 676 | **REAL.** FastAPI router (`build_pitch_router`) with 3 export endpoints; signing-key resolution, artifact collection from `app.state`. Never mounted. |
| `_pending/compliance/__init__.py` | 5 | Marker. |
| `_pending/compliance/naic/__init__.py` | 3 | Marker. |
| `_pending/compliance/naic/cyber_rider.py` | 15 | **STUB.** `emit_cyber_rider_packet()` → `NotImplementedError`. |
| `_pending/compliance/naic/model_bulletin.py` | 12 | **STUB.** `emit_naic_bulletin_evidence()` → `NotImplementedError`. |
| `_pending/compliance/nist/__init__.py` | 3 | Marker. |
| `_pending/compliance/nist/agent_standards.py` | 12 | **STUB.** `emit_agent_standards_evidence()` → `NotImplementedError`. |
| `_pending/compliance/nist/ai_rmf.py` | 12 | **STUB.** `emit_ai_rmf_evidence()` → `NotImplementedError`. |
| `_pending/events/__init__.py` | 5 | Marker. |
| `_pending/events/quorum_shard.py` | 16 | **STUB.** `QuorumShardReplicator` class, body `pass`. |
| `_pending/graph/__init__.py` | 5 | Marker. |
| `_pending/graph/janusgraph_backend.py` | 14 | **STUB.** `JanusGraphTemporalKG` class, body `pass`. |
| `_pending/graph/postgres_backend.py` | 25 | **STUB.** `PostgresTemporalKG.__init__` stores DSN; no methods implemented. |
| `_pending/interop/__init__.py` | 23 | Doc of interop targets; `__all__ = []`. |
| `_pending/interop/a2a/__init__.py` | 23 | Re-exports `SignedAgentCard`, `verify_agent_card`, `A2aBusListener`. |
| `_pending/interop/a2a/bus_listener.py` | 21 | **STUB.** `A2aBusListener.on_message()` → `NotImplementedError`. |
| `_pending/interop/a2a/signed_agent_card.py` | 39 | **MIXED.** `SignedAgentCard` dataclass (real shape); `verify_agent_card()` → `NotImplementedError`. |
| `_pending/interop/microsoft/__init__.py` | 12 | Marker; `__all__ = []`. |
| `_pending/interop/microsoft/policy_bundle_exporter.py` | 13 | **STUB.** `export_policies_to_msagt()` → `NotImplementedError`. |
| `_pending/interop/nist/__init__.py` | 13 | Marker; `__all__ = []`. |
| `_pending/interop/nist/self_assessment.py` | 13 | **STUB.** `emit_self_assessment()` → `NotImplementedError`. |
| `_pending/interop/okta/__init__.py` | 11 | Marker; `__all__ = []`. |
| `_pending/interop/okta/agent_identity_sync.py` | 14 | **STUB.** `sync_agents_from_okta()` → `NotImplementedError`. |
| `_pending/interop/ping/__init__.py` | 11 | Marker; `__all__ = []`. |
| `_pending/interop/ping/verdict_publisher.py` | 13 | **STUB.** `publish_verdict_to_ping()` → `NotImplementedError`. |
| `_pending/pitch/__init__.py` | 95 | **REAL.** Aggregates and re-exports the pitch public API (18 symbols). Wrongly self-labels `__layer__=5 'evidence'`. |
| `_pending/pitch/_compliance_corpus.py` | 218 | **REAL.** Frozen pydantic data tables: FTC enforcement actions, regulatory anchors, MCP CVEs, BlueRock figures. No I/O. |
| `_pending/pitch/_intel.py` | 141 | **REAL (heuristic).** SHA-256-seeded deterministic "OSINT" estimators (vendor, volume, MCP footprint). No network. |
| `_pending/pitch/ciso.py` | 196 | **REAL.** `build_mcp_risk_dossier()`, `McpRiskDossier`, sub-linear SSRF risk score. |
| `_pending/pitch/insurer_export.py` | 344 | **REAL.** `build_insurer_evidence_packet()` — JCS-canonical manifest, SHA-256 digests, algorithm-agile signature. |
| `_pending/pitch/verifier.py` | 257 | **REAL.** `verify_insurer_evidence_packet()` — independent re-derivation + signature verify + tamper detection. |
| `_pending/pitch/vp_marketing.py` | 199 | **REAL.** `build_brand_safety_dossier()`, `BrandSafetyDossier`, exposure summary builder. |

Totals: 34 `.py` files. ~13 stub/marker files with `NotImplementedError`/`pass`; the `pitch/` + `api/pitch_routes.py` cluster (~2,126 lines) is real working logic.

---

## Internal Architecture

There are two independent internal graphs. The stub subtrees have no data flow worth diagramming (each public symbol immediately raises). The pitch cluster has a real dataflow.

### Pitch dataflow (the only substantive internal architecture)

**Data source — `_compliance_corpus.py`:** A frozen, side-effect-free data table. Three pydantic models with `ConfigDict(frozen=True, extra="forbid")`: `EnforcementAction` (`:31`), `RegulatoryAnchor` (`:42`), `McpCveExposure` (`:53`, CVE-id regex-validated `:58`). Module-level constants carry the actual corpus: `FTC_OPERATION_AI_COMPLY` (5 dockets, `:66`), `FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD = 24_000_000` (`:116`), `MARKETING_REGULATORY_ANCHORS` (4 statutes, `:120`), `MCP_CVE_EXPOSURE` (4 CVEs, `:166`), `BLUEROCK_FLEET_SAMPLE_SIZE = 7_000` / `BLUEROCK_SSRF_VULNERABLE_FRACTION = 0.367` (`:204-205`).

**Intelligence helpers — `_intel.py`:** Deterministic, domain-seeded heuristics, explicitly *not* live OSINT (docstring `:6-25`). `_seed_int(domain, label)` derives an int from `sha256("{label}::{normalized_domain}")` (`:66-69`). On that seed: `derive_company_name` (`:72`), `estimate_ai_sdr_vendor` (returns `None` for ~10% via `seed % 10 == 0`, `:82-94`), `estimate_outbound_volume_per_month` (5k–250k bucketized, `:97-108`), `detect_mcp_runtime_footprint` (1–5 entries, re-mixed cursor to avoid dup picks, `:111-133`). NOTE the normalization at `_intel.py:63` uses `.lstrip("https://")` — `str.lstrip` strips *characters*, not a prefix, so this is a latent bug (it would mangle any domain starting with chars in `"htps:/"`). Harmless for typical bare domains; flagged below.

**VP Marketing builder — `vp_marketing.py`:** `build_brand_safety_dossier(company_domain)` (`:131`) calls the three `_intel` estimators, assembles a headline via `_summarize_exposure` (`:93`), and packs everything into the frozen `BrandSafetyDossier` dataclass (`:55`) along with the full enforcement corpus and `_TEX_BRAND_SAFETY_CAPABILITIES` marketing strings (`:41`). Emits `pitch.dossier.built` telemetry (`:185`).

**CISO builder — `ciso.py`:** `build_mcp_risk_dossier(company_domain)` (`:128`) calls `_intel.detect_mcp_runtime_footprint`, computes `_ssrf_risk_score` (`:94`) — a sub-linear accumulation `score = 1 - (1 - base) * (0.5 ** n_vuln)` anchored on the 0.367 BlueRock baseline so it never exceeds 1.0 — and packs `McpRiskDossier` (`:54`) with the 4 canonical CVEs and `_TEX_RUNTIME_CAPABILITIES` (`:38`). Emits `pitch.dossier.built` (`:183`).

**Insurer packet builder — `insurer_export.py`:** The cryptographic core.
- `build_insurer_evidence_packet(tenant_id, period_start, period_end, *, evidence_records, c2pa_manifests, receipts, signing_key)` (`:201`).
- **Fails closed:** if any of the four keyword artifacts is `None` it raises `TypeError` rather than producing an empty unsigned shell (`:247-259`) — a deliberate anti-footgun: the 3-positional scaffold signature is preserved but cannot yield a verifiable packet.
- Each artifact group is canonicalized to deterministic bytes via `model_dump(mode="json")` → `canonical_json` (JCS / RFC 8785) (`_serialize_evidence_chain :111`, `_serialize_c2pa_manifests :123`, `_serialize_receipts :129`).
- SHA-256 digests of each artifact (`:270-272`); manifest is built signing **digests, not raw bytes** (`_build_manifest :135`, rationale `:55-59`: bounded manifest size + constant-time tamper check).
- Signs via algorithm-agile dispatcher `get_signature_provider(signing_key.algorithm).sign(...)` (`:282-284`).
- Output: frozen `InsurerEvidencePacket` dataclass (`:159`) carrying `artifacts: dict[str,bytes]`, `artifact_digests`, `manifest_signature_b64`, `signing_public_key`, `layout_version="1"` (`:99`).
- `_rebuild_manifest_for_verification(packet)` (`:315`) is exported so the verifier re-derives the manifest *identically and independently*.

**Independent verifier — `verifier.py`:** `verify_insurer_evidence_packet(packet, *, expected_public_key=None)` (`:84`). Six non-short-circuiting checks accumulating issues: (1) algorithm in `_ACCEPTED_VERIFICATION_ALGORITHMS` (`:72`, note: deliberately a *narrower* set than the builder accepts — composite schemes excluded); (2) re-hash each artifact vs embedded digest (`:138`); (3) orphan-digest check (`:161`); (4) optional pinned-public-key equality for offline KMS pinning (`:174`); (5) base64 signature decode (`:187`); (6) `provider.verify(rebuilt_manifest, signature, public_key)` (`:203-232`), failing closed on any exception. Returns `PacketVerificationResult` with full `issues` tuple. Emits `pitch.evidence_packet.verified` (`:241`).

**HTTP surface — `api/pitch_routes.py`:** `build_pitch_router()` (`:487`) returns an `APIRouter(prefix="/v1/exports")` with router-level `Depends(authenticate_request)` (`:502`) and three routes, each gated by `RequireScope("evidence:export")` (`:143`, `:523`/`:556`/`:605`):
- `POST /v1/exports/vp-marketing` (`:507`) → `build_brand_safety_dossier`.
- `POST /v1/exports/ciso` (`:542`) → `build_mcp_risk_dossier`.
- `POST /v1/exports/insurer` (`:575`) → adds pre-handler `RequireTenantMatch.from_body("tenant_id")` (`:484`, `:600`) for OWASP BOLA defence, plus belt-and-suspenders `enforce_tenant_match` inside the handler (`:611`). Collects artifacts from `app.state.{evidence_exporter, manifest_mirror, tool_receipt_store}` — all of which gracefully return empty tuples when unwired (`:378-476`) — then signs via `_get_or_create_signing_key`.
- Signing-key resolution: `_resolve_signing_algorithm()` reads `TEX_PITCH_SIGNING_ALGORITHM` (default `ML_DSA_65`, `:144`/`:178`); `_get_or_create_signing_key` lazily generates and caches on `app.state.pitch_signing_key` under a `threading.Lock` (`:209-259`), with a real PQ→ED25519 fallback (logged via telemetry, never silent) if liboqs is absent (`:238-251`).

---

## Public API

### Pitch (`tex._pending.pitch.__all__`, `__init__.py:71-95` — 18 symbols)
- Builders: `build_brand_safety_dossier`, `build_mcp_risk_dossier`, `build_insurer_evidence_packet`, `verify_insurer_evidence_packet`.
- Result/DTO types: `BrandSafetyDossier`, `McpRiskDossier`, `InsurerEvidencePacket`, `PacketVerificationIssue`, `PacketVerificationResult`.
- Corpus types + constants: `EnforcementAction`, `RegulatoryAnchor`, `McpCveExposure`, `FTC_OPERATION_AI_COMPLY`, `MARKETING_REGULATORY_ANCHORS`, `MCP_CVE_EXPOSURE`, `BLUEROCK_SSRF_VULNERABLE_FRACTION`, `BLUEROCK_FLEET_SAMPLE_SIZE`, `FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD`.

### API (`api/pitch_routes.py:676`)
- `build_pitch_router()` → `APIRouter`.

### Interop / stubs (would-be API if implemented)
- `interop.a2a`: `SignedAgentCard`, `verify_agent_card` (raises), `A2aBusListener` (raises).
- `interop.okta.sync_agents_from_okta`, `interop.ping.publish_verdict_to_ping`, `interop.microsoft.export_policies_to_msagt`, `interop.nist.emit_self_assessment` — all raise `NotImplementedError`.
- `compliance.naic.{cyber_rider,model_bulletin}`, `compliance.nist.{ai_rmf,agent_standards}` — all raise.
- `events.quorum_shard.QuorumShardReplicator`, `graph.{janusgraph_backend.JanusGraphTemporalKG, postgres_backend.PostgresTemporalKG}` — empty classes.

**Crucially: none of these public symbols is imported by any non-`_pending` module** (see Wiring).

---

## Wiring

### Wiring In — NONE (orphan, code-verified)
`grep -rn "tex\._pending|from tex\.pitch|build_pitch_router|pitch_routes" src/tex` (excluding `_pending/` itself) returns **only false positives**:
- `src/tex/contracts/runtime_enforcement.py:643,651,700,705` — `self._soft_pending` (an unrelated dict attribute).
- `src/tex/stores/*_postgres.py` — local `still_pending` variables.
- `src/tex/provenance/feed.py:214,324` — `self._pending` dict.
- `src/tex/events/ledger.py:20` — a docstring comment: `Quorum replication is P2 — see ``_pending.events.quorum_shard``` (a reference, not an import).

`build_pitch_router` / `pitch_router` / `pitch_routes` have **zero call-sites** anywhere in `src/tex`.

### Live call path — NONE
`tex.main` registers routers in one block (`src/tex/main.py:1441-1529`). The list (`build_api_router`, `build_incident_router`, `build_agent_router`, `build_voice_router`, `c2pa_router`, `zkprov_router`, …) does **not** include the pitch router. `grep -n "pitch|exports" src/tex/main.py` returns nothing. `grep -rn "v1/exports|exports/insurer|exports/ciso|exports/vp-marketing" src/tex` (excluding the route file) returns nothing. **There is no path from `tex.main:create_app`/`build_runtime` or any `api/` route to this unit.**

### Wiring In — tests only
`tests/frontier/test_scaffolding_imports.py` is the **sole** consumer. It does *not* exercise functionality — it enforces the parking contract: each module must import under `tex._pending.<name>` AND the active `tex.<name>` import MUST raise (`test_pending_module_in_pending_namespace`, `:175-197`; the active↔pending name map at `:134-163`). So even the test treats `_pending` as parked, not live. (Note: the spine pass labelled `_pending=ORPHAN`; this is consistent — "DEMO_TEST_ONLY" would overstate it, since the test asserts non-importability under the live namespace, not behavior.)

### Wiring Out — what the *pitch* cluster depends on (live subsystems, verified to exist)
Even though orphaned, the pitch code imports real, live Tex modules (all confirmed present on disk):
- `tex.api.auth` → `RequireScope`, `RequireTenantMatch`, `TexPrincipal`, `authenticate_request`, `enforce_tenant_match` (`pitch_routes.py:116-122`).
- `tex.observability.telemetry.emit_event` (all pitch builders + routes).
- `tex.pqcrypto.algorithm_agility` → `SignatureAlgorithm`, `SignatureKeyPair`, `get_signature_provider` (`insurer_export.py:90-94`, `verifier.py:41-44`, `pitch_routes.py:132-136`).
- `tex.c2pa.manifest.C2paManifest` (`insurer_export.py:86`).
- `tex.domain.evidence.EvidenceRecord` (`insurer_export.py:87`).
- `tex.events._canonical.canonical_json` (JCS) (`insurer_export.py:88`).
- `tex.receipts.receipt.ToolExecutionReceipt` (`insurer_export.py:95`).

External libs: `fastapi`, `pydantic` (`pitch_routes.py:113-114`, `_compliance_corpus.py:28`), stdlib `hashlib`/`base64`/`json`/`threading`/`os`/`dataclasses`. The stub subtrees import nothing beyond stdlib `dataclasses`/`hashlib`.

**Confirmation it would work if wired:** running under `PYTHONPATH=.../src`, `import tex._pending.api.pitch_routes` succeeds, `build_pitch_router` is callable, and `build_brand_safety_dossier`/`build_mcp_risk_dossier` produce populated dossiers. The insurer packet **round-trips through the verifier** (`is_valid=True, 0 issues`) and a tampered signature is correctly rejected (`is_valid=False, SIGNATURE_INVALID`). This is real, exercised crypto — not a hollow stub.

---

## Implementation Reality

| Component | Reality | Evidence |
|-----------|---------|----------|
| `pitch/_compliance_corpus.py` | **REAL** frozen data table. | Validated pydantic models, no I/O (`:21` "no side effects and no I/O"). |
| `pitch/_intel.py` | **REAL but heuristic** — deterministic SHA-256-seeded fakes, *explicitly not live OSINT* (`:6-25`). Honest about it. Contains a latent `.lstrip("https://")` prefix-stripping bug (`:63`). |
| `pitch/vp_marketing.py`, `ciso.py` | **REAL** assembly logic over the corpus + heuristics. Marketing capability strings are static (`vp_marketing.py:41`, `ciso.py:38`). |
| `pitch/insurer_export.py` | **REAL crypto.** JCS canonicalization, SHA-256 digest binding, algorithm-agile signature. Fails closed on missing artifacts (`:247`). P1/P2 extensions (ZKPROV, TEE, VET) are documented-as-future TODOs (`:232-239`) — *absent*, not stubbed. |
| `pitch/verifier.py` | **REAL.** Independent re-derivation, 6-step fail-closed verification, exercised round-trip + tamper test pass. |
| `api/pitch_routes.py` | **REAL** FastAPI surface with genuine auth/BOLA gating + real PQ→ED25519 fallback (`:238-251`, logged not silent). The artifact collectors are *graceful-empty by design* (`app.state` getters return `tuple()` when unwired, `:378-476`) — a deliberate "empty signed packet = no AI activity" posture, not a stub. |
| `interop/a2a/signed_agent_card.py` | **MIXED.** `SignedAgentCard` is a real dataclass; `verify_agent_card` is a stub → `NotImplementedError("A2A signed agent card verification")` (`:39`). |
| `interop/{a2a/bus_listener, okta, ping, microsoft, nist}/*` | **HOLLOW STUBS.** Every public function body is `raise NotImplementedError(...)`. E.g. `bus_listener.py:21`, `agent_identity_sync.py:14`, `verdict_publisher.py:13`, `policy_bundle_exporter.py:13`, `self_assessment.py:13`. |
| `compliance/{naic,nist}/*` | **HOLLOW STUBS.** 4 functions, all `raise NotImplementedError(...)` (`cyber_rider.py:15`, `model_bulletin.py:12`, `ai_rmf.py:12`, `agent_standards.py:12`). |
| `events/quorum_shard.py` | **HOLLOW STUB.** `QuorumShardReplicator` body is `pass` (`:16`). |
| `graph/janusgraph_backend.py` | **HOLLOW STUB.** `JanusGraphTemporalKG` body `pass` (`:14`). |
| `graph/postgres_backend.py` | **HOLLOW STUB.** `PostgresTemporalKG.__init__` stores DSN; no methods (`:25`). |

No crypto/zk/tee primitives are *implemented inside* `_pending` — the pitch code *consumes* the live `tex.pqcrypto` algorithm-agile providers (real ML-DSA-with-graceful-fallback per the spine pass). So the only real cryptographic behavior in scope is correct *use* of those live providers plus SHA-256/JCS/base64 plumbing.

---

## Technology / SOTA

- **Algorithm-agile post-quantum signatures** via `tex.pqcrypto` — default `ML-DSA-65` (NIST FIPS 204 Level 3); accepted set includes ML-DSA-44/65/87, hybrid `ML-DSA+Ed25519`, composite `ML-DSA-65+Ed25519` / `ML-DSA-87+ECDSA-P384`, plus classical Ed25519/ECDSA-P256 (`pitch_routes.py:151-160`). Real PQ→ED25519 dev fallback when liboqs absent (`:238-251`).
- **JSON Canonicalization Scheme (RFC 8785)** for deterministic manifest bytes via `tex.events._canonical.canonical_json` (`insurer_export.py:120,156`).
- **Digest-over-bytes signing pattern** — sign SHA-256 digests, not raw artifacts, for bounded manifest size + constant-time tamper detection (`insurer_export.py:55-59`).
- **Verifier-narrower-than-signer** acceptance set — verifier deliberately refuses composite schemes the builder allows, failing closed on unknown algorithms (`verifier.py:69-81`).
- **OWASP API #1 BOLA defence** — pre-handler `RequireTenantMatch.from_body` + in-handler `enforce_tenant_match` belt-and-suspenders (`pitch_routes.py:484,600,611`).
- **Deterministic domain-seeded heuristics** (SHA-256 PRNG over normalized domain) for reproducible demo dossiers (`_intel.py:66-69`).
- **Frozen dataclasses / frozen pydantic models** throughout (immutable DTOs).
- Referenced-but-unbuilt SOTA (TODOs only): NabaOS HMAC receipts (arxiv 2603.10060), ZKPROV (arxiv 2506.20915), VET Agent Identity Documents (arxiv 2512.15892), AAF quorum sharding (arxiv 2512.18561), A2A v1.2 signed Agent Cards, Microsoft Agent Governance Toolkit, C2PA 2.4.

---

## Persistence

**Entirely in-memory / stateless within scope.**
- The pitch builders are pure functions over a frozen corpus — no DB, no disk.
- The insurer packet exists only as a returned dataclass; durability is the caller's concern.
- The HTTP router caches a lazily-generated signing key on `app.state.pitch_signing_key` for the process lifetime (`pitch_routes.py:223,253`) — process-local, not durable; production is expected to pre-populate it from KMS/HSM (`:215-216`).
- Artifact collection *reads* from external stores (`app.state.evidence_exporter`, `manifest_mirror`, `tool_receipt_store`) when present (`:396,428,457`) — but those stores live in live subsystems, not here, and are unwired in this orphaned path.
- `graph/postgres_backend.py` and `graph/janusgraph_backend.py` *describe* durable KG backends (Postgres+pgvector schema sketch at `postgres_backend.py:7-19`) but implement nothing.

---

## Notable Findings

1. **The pitch cluster is a fully-working, production-grade product surface that is completely unmounted.** `build_pitch_router` has zero callers and is absent from `tex.main`'s router block (`src/tex/main.py:1441-1529`). ~2,100 lines of real auth-gated, crypto-signed export code (three buyer-facing endpoints) that the running app never exposes. This is the headline surprise: not dead *stub* code, but dead *real* code.

2. **Self-mislabeled architectural layer.** `pitch/__init__.py:41-42` declares `__layer__ = 5; __layer_kind__ = 'evidence'` and the docstring calls it "Layer 5 (Evidence)". The parent `_pending/__init__.py:27-28` correctly declares `__layer__ = None; __layer_kind__ = 'pending'`. A symbol claiming to be live Evidence-layer code while parked in `_pending` is a contradiction — the layer marker is stale from before the code was parked.

3. **Docstrings reference the *active* import path that intentionally does not exist.** `pitch/__init__.py:40`, `insurer_export.py:18`, and `pitch_routes.py:96-99` all say `tex.pitch.*` / `tex.pitch.verifier`. The real path is `tex._pending.pitch.*`; the active `tex.pitch` name is *guaranteed to fail* by `test_scaffolding_imports.py:159-163`. (claim vs reality, verified.)

4. **`_intel.py:63` latent bug:** `domain.strip().lower().lstrip("https://").lstrip("http://")`. `str.lstrip(chars)` strips any leading characters in the set `"htps:/"`, not the literal prefix — so e.g. a domain like `tportal.com` would lose its leading `t`. Harmless for the normal bare-domain inputs the heuristic is seeded on, and only affects deterministic fakes, but it's a real correctness defect.

5. **`build_insurer_evidence_packet` fails closed, which contradicts the route's "empty packet is fine" narrative — but the route handles it.** The builder raises `TypeError` if artifacts are `None` (`insurer_export.py:247-259`), yet the route always passes *empty tuples* (not `None`) when stores are unwired (`pitch_routes.py:613-633`), so the "verifiable empty packet" path works. The two pieces are consistent only because the route never passes `None`; a direct caller passing `None` gets a `TypeError`. Worth noting as a sharp edge.

6. **Honest scaffolding.** Unlike some audited Tex subsystems, the stubs here do not overstate: every unimplemented function loudly raises `NotImplementedError` with a descriptive message, and `_intel.py` explicitly documents its estimators as deterministic fakes, not live OSINT (`:6-25`). The `_pending` convention is self-documenting and test-enforced. No leetspeak-bypass / `rm -rf`-permit / inert-governance class of overstatement appears in this unit.

7. **The numbers cited in the corpus are claims sourced to repo `.md` files** (`FRONTIER_COMPLIANCE.md`, `FRONTIER_KNOWN_BYPASSES.md`) — e.g. `$24M` FTC judgments, `36.7%` BlueRock SSRF, four named CVEs. These are hard-coded constants (`_compliance_corpus.py:116,205,168-198`); their *external accuracy* is unverifiable from code (claim, unverified). The code faithfully carries whatever the table says.

8. **Restoration is well-defined.** `_pending/__init__.py:14-17` and `test_scaffolding_imports.py:183-188` document the exact restore procedure (move dir back under `src/tex/`, add tests, wire the call site, update the "Current contents" doc). For the pitch cluster specifically, "wiring" means a single `app.include_router(build_pitch_router())` in `tex.main` plus populating the three `app.state` stores.
