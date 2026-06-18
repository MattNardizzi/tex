# Discovery / conduit (connect-your-directory) — Subsystem Dossier

**Unit:** `discovery`
**Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/discovery/` (53 `.py` files, ~9,853 lines)
**Branch:** `feat/proof-carrying-gate`
**Layer:** Layer 1 / Discovery (`__layer__ = 1`, `__layer_kind__ = 'discovery'` — `discovery/__init__.py:30-31`)
**Wired status:** **LIVE** (verified call paths from `tex.main.build_runtime` and three API routers; cited below).

All file:line references are under `/Users/matthewnardizzi/dev/tex/src/tex/discovery/` unless an absolute path is given. Every claim here was read in code; docstring/`.md` claims that were *not* code-confirmed are explicitly labelled "(claim, unverified)".

---

## Overview

The discovery layer answers "what AI agents exist in this org that nobody told Tex about?" It is a **connector → reconciliation engine → registry/ledger → drift/alert/presence → conduit-seal** pipeline. Two structurally distinct halves coexist:

1. **The classic connector library** (`connectors/`, `service.py`, `reconciliation.py`, `scheduler.py`, `presence.py`, `dormancy.py`, `alerts.py`, `ocsf.py`, `ignition.py`, `demo_seed.py`). A `DiscoveryService` runs every wired `DiscoveryConnector`, each emitting `CandidateAgent` records; a pure `ReconciliationEngine` decides REGISTER / UPDATE / QUARANTINE / HOLD / NO-OP per candidate; the service mutates the agent registry and appends a discovery-ledger entry. A daemon-thread `BackgroundScanScheduler` re-scans on an interval and diffs runs to emit drift events.

2. **tex-conduit** (`conduit/`) — the "Connect your directory" capability. One read-only IdP admin grant, and a single shared `ProviderConsentGraphConnector` (parameterized by a declarative `ProviderProfile` per IdP: Entra/Okta/Google/Ping) walks the directory, builds a consent **graph**, computes each agent's transitive **blast radius**, and emits the same `CandidateAgent` shape. Conduit additionally seals the *grant itself* (`GRANT_SEALED`) and the *exact inventory at time T* (`INVENTORY_SNAPSHOT_SEALED`) as offline-verifiable receipts on its own append-only Merkle/Ed25519/RFC-3161 chain (`conduit/seal.py`).

The differentiator vs. dashboard products (the docstrings name Zenity/Noma — `reconciliation.py:5-6`, claim, unverified) is that discovery output is a **registry action**, not a report, and (in conduit) a **tamper-evident, externally-anchored receipt**.

---

## File Inventory

| File | LOC | Role |
|------|-----|------|
| `__init__.py` | 53 | Package: re-exports `DiscoveryService`, `ReconciliationEngine`, `ReconciliationIndex`, thresholds; layer markers. |
| `service.py` | 721 | `DiscoveryService` orchestrator + `ReconciliationIndex` + `DiscoveryScanResult` + `ScanInProgress`. Runs connectors, applies decisions, locks/idempotency, registry-state hash, optional provenance birth + held-hold surfacing. |
| `reconciliation.py` | 394 | Pure `ReconciliationEngine`, `ReconciliationDecision`, drift scoring, surface-from-hints, thresholds. |
| `scheduler.py` | 657 | `BackgroundScanScheduler` daemon: interval re-scan, run-vs-run drift diff, presence machine, dormancy sweep, snapshot capture, metrics. |
| `presence.py` | 439 | `PresenceTracker` soft-disappearance state machine (PRESENT→MISSING_ONCE→TWICE→CONFIRMED), Postgres-durable. |
| `dormancy.py` | 262 | `DormancyController` — sleep-provably-safe / hold-uncertain / flag-day-90-deletion sweep; wake/revoke human acts. |
| `alerts.py` | 371 | `AlertEngine` + `AlertRule` + Log/Webhook/Slack sinks; threshold rules over drift events. |
| `reconciliation.py` | (above) | — |
| `consent_graph.py` | 168 | Pure `ConsentGraph` + `ConsentEdge`; blast-radius transitive closure; Entra HIGH/CRITICAL scope stems. |
| `graph_transport.py` | 168 | `GraphTransport` Protocol; `LiveGraphTransport` (MS Graph, httpx), `FixtureGraphTransport`, `GraphCredentials`. |
| `ocsf.py` | 153 | `OcsfEvent` + `cloudtrail_to_ocsf` + `normalize` — vendor-neutral audit normalization. |
| `ignition.py` | 84 | `IgnitionRegistry` per-tenant "said hello once" flag; `humanize_count` number-to-words. |
| `demo_seed.py` | 109 | `entra_pages` + `cloudtrail_records` fixtures (33 Entra + 8 audit = 41 agents) for first-run demo. |
| **`connectors/`** | | |
| `connectors/__init__.py` | 41 | Re-exports 13 connector classes + base protocol/errors. |
| `connectors/base.py` | 152 | `DiscoveryConnector` Protocol, `ConnectorContext`, `BaseConnector` (cap/filter), `ConnectorError`/`Timeout`. |
| `connectors/openai_assistants.py` | 155 | `OpenAIConnector` — mock OpenAI Assistants. |
| `connectors/openai_live.py` | 290 | `OpenAIAssistantsLiveConnector` — live OpenAI `/v1/assistants` over urllib. |
| `connectors/slack.py` | 220 | `SlackConnector` — mock Slack bots/scopes. |
| `connectors/slack_live.py` | 368 | `SlackLiveConnector` — live Slack `users.list` + `admin.apps.approved.list`. |
| `connectors/microsoft_graph.py` | 200 | `MicrosoftGraphConnector` — mock Copilot Studio / Graph OAuth apps. |
| `connectors/aws_bedrock.py` | 157 | `AwsBedrockConnector` — mock Bedrock agents. |
| `connectors/github.py` | 214 | `GitHubConnector` — mock Copilot seats + GitHub App installs. |
| `connectors/salesforce.py` | 162 | `SalesforceConnector` — mock Agentforce/Einstein bots. |
| `connectors/mcp_server.py` | 184 | `MCPServerConnector` — mock MCP server client inventory. |
| `connectors/cloud_audit.py` | 235 | `CloudAuditConnector` — mock CloudTrail AgentCore audit folding. |
| `connectors/cloud_audit_ocsf.py` | 121 | `OcsfAuditConnector` — live-capable OCSF/CloudTrail audit-plane connector. |
| `connectors/kernel_ebpf.py` | 204 | `KernelEbpfConnector` — mock Tetragon eBPF process-exec discovery. |
| `connectors/network_egress.py` | 194 | `NetworkEgressConnector` — mock DNS/TLS-SNI/JA4 egress discovery. |
| `connectors/entra_consent_graph.py` | 57 | `EntraConsentGraphConnector` — thin binding of shared engine to `ENTRA_PROFILE`. |
| **`conduit/`** | | |
| `conduit/__init__.py` | 27 | Package docstring (no exports). |
| `conduit/connector.py` | 289 | `ProviderConsentGraphConnector` + `ProviderProfile` + `GrantCollection` — the one shared IdP walker. |
| `conduit/seal.py` | 537 | `ConduitProvenanceChain`, `ConduitReceipt`, `seal_grant`, drift detect, `InventorySnapshotSealer`, `DriftGuardedConnector`, `StandingWatch`. |
| `conduit/grant.py` | 138 | `DirectoryGrant` (frozen, secret-free, degraded/missing-scope computation), `canonical_scopes`. |
| `conduit/broker.py` | 162 | `ConnectBroker` four-state machine REQUESTED→CONSENTED→PROBED→SEALED; `Connection`, `ConnectState`. |
| `conduit/evidence_fold.py` | 164 | `EvidenceFold` — guarded additive card enrichment (Ed25519 JCS verify; never resolves identity, never raises trust). |
| `conduit/tiers.py` | 191 | `ProvenanceTierConfig` — opt-in ML-DSA / witness-cosign / OpenTimestamps tiers over the always-on floor. |
| `conduit/shadow.py` | 247 | `ShadowCorrelator` — cross-plane (audit↔control-plane) correlation; SHADOW vs CORRELATED. |
| `conduit/live_connector.py` | 53 | `ConduitConnectionsConnector` — tenant-aware connector borrowing a sealed connection's transport. |
| `conduit/risk_dictionary.py` | 132 | Per-provider CRITICAL scope sets + HIGH-risk stems (Okta/Google/GCP/Ping). |
| `conduit/providers/base.py` | 131 | `ConnectStrategy` Protocol, `ConsentChallenge/Step/Callback`, `BaseConnectStrategy`, `make_connection_id`. |
| `conduit/providers/entra.py` | 56 | `EntraConnectStrategy` — one-click admin consent; `ENTRA_READ_SCOPES`. |
| `conduit/providers/okta.py` | 86 | `OktaConnectStrategy` — multi-step service-app + per-scope checklist. |
| `conduit/providers/google.py` | 98 | `GoogleWorkspaceConnectStrategy` + `GcpIamConnectStrategy` — two grants. |
| `conduit/providers/ping.py` | 55 | `PingConnectStrategy` — per-deployment service account. |
| `conduit/providers/__init__.py` | 3 | Docstring only. |
| `conduit/profiles/entra_profile.py` | 167 | `ENTRA_PROFILE` + Entra predicates/edge mappers (reference profile). |
| `conduit/profiles/okta_profile.py` | 128 | `OKTA_PROFILE` + Okta agent predicate/edge mapper. |
| `conduit/profiles/google_profile.py` | 159 | `GCP_IAM_PROFILE` + `GOOGLE_WORKSPACE_PROFILE` (inline-edge profiles). |
| `conduit/profiles/ping_profile.py` | 84 | `PING_PROFILE` (inline-edge profile). |
| `conduit/profiles/__init__.py` | 3 | Docstring only. |
| `conduit/transport/google_transport.py` | 103 | `GoogleWorkspaceTransport` + `GoogleIamAssetTransport` (pageToken). |
| `conduit/transport/okta_transport.py` | 236 | `OktaTransport` + `build_client_assertion_jwt` (private-key JWT, Link-header paging). |
| `conduit/transport/ping_transport.py` | 68 | `PingTransport` (HAL `_links.next` paging). |
| `conduit/transport/__init__.py` | 3 | Docstring only. |

---

## Internal Architecture

### Domain contract (external, but central to this unit)
Every connector emits `tex.domain.discovery.CandidateAgent`; decisions key off `candidate.reconciliation_key` (constructed in domain as `f"{source}:{tenant_id}:{external_id.casefold()}"` — confirmed structurally by `service.py:149` `_key_from_metadata`). Capability hints are `DiscoveredCapabilityHints`; risk is `DiscoveryRiskBand` (LOW/MEDIUM/HIGH/CRITICAL). The 16 `DiscoverySource` members (verified at runtime): `microsoft_graph, okta, google_workspace, gcp_iam, ping, salesforce, aws_bedrock, github, openai, slack, mcp_server, langsmith, generic, cloud_audit, network_egress, kernel_ebpf`.

### 1. Connector framework (`connectors/base.py`)
- `DiscoveryConnector` — `@runtime_checkable` Protocol: `source`, `name`, `scan(context) -> Iterable[CandidateAgent]` (`base.py:88-112`).
- `BaseConnector` (ABC) — `scan` enforces `max_candidates` cap, tenant-id gate (`candidate.tenant_id != context.tenant_id.casefold()` skips), and `name_filter` contains-match; subclasses implement `_run_scan` (`base.py:115-147`).
- `ConnectorError`/`ConnectorTimeout` — typed so the service records structured scan errors instead of crashing (`base.py:54-66`).

### 2. Reconciliation engine (`reconciliation.py`) — pure, stores-free
- Thresholds: `AUTO_REGISTER_THRESHOLD = 0.80` (`:66`), `QUARANTINE_DRIFT_THRESHOLD = 0.60` (`:71`).
- `ReconciliationEngine.decide(candidate, existing)` (`:113-144`) is a total function with mutually-exclusive branches:
  - **No existing** → `_handle_new` (`:148`): below threshold → `NO_OP_BELOW_THRESHOLD`; `surface_unbounded` → `HELD_AMBIGUOUS` (operator must bless); else build a new `AgentIdentity` with `lifecycle_status=PENDING`, trust tier from risk band, metadata stamping `discovery_source`/`discovery_external_id`/`discovery_risk_band` (`:200-204`) — this metadata is what `ReconciliationIndex._bootstrap_from_registry` later reads.
  - **Existing REVOKED** → `SKIPPED_REVOKED` (revoke stays terminal — `:130-142`).
  - **Existing known** → `_handle_known` (`:224`): `_capability_drift` score; 0.0 → `NO_OP_KNOWN_UNCHANGED`; `>= 0.60` → `QUARANTINED_FOR_DRIFT`; else `UPDATED_DRIFT` (widen surface).
- `_capability_drift` (`:302-356`): only **widening** is penalized (new entries in proposed not in existing), per-dimension signal `min(1.0, len(new)/4.0)` averaged across 6 dimensions (action_types, channels, recipient_domains, tools, mcp_servers, data_scopes). Narrowing is not drift (`:312-316` docstring + code).
- Output is a `ReconciliationDecision` (outcome + optional `new_agent`/`update_capability_surface_for`/`new_capability_surface`/`quarantine_agent_id`); the engine never touches a store.

### 3. DiscoveryService (`service.py`) — the orchestrator
- `ReconciliationIndex` (`:73-130`): bidirectional `reconciliation_key ↔ agent_id` map, RLock-guarded, rebuilt from registry on construction so operator-registered agents carrying discovery metadata are recognized.
- `scan(...)` (`:278-469`): captures `ledger_seq_start`; iterates connectors; per-candidate `_handle_candidate`; per-connector `ConnectorError`/`Exception` caught and appended to `errors` (one broken platform never halts the run — `:366-377`); records per-connector health; heartbeats the scan-run; builds `DiscoveryScanRun` summary; computes `registry_state_hash`; closes the durable run row.
- **Idempotency + per-tenant lock** (`:316-333`): when a `ScanRunStore` is wired, `acquire(...)` returns either a new run or replays a completed one (`_replay_completed_run`, `:538-590`); `ScanLockHeld` → `ScanInProgress` (→ HTTP 409). When no store is wired, behavior is the legacy synchronous path (docstring "V15", `:306-307`).
- `_handle_candidate` (`:594-630`): registry mutation happens **before** the ledger append (so any ledger entry corresponds to an already-applied registry change — `:599-601`). On REGISTER with a wired `provenance_engine`, `_seal_discovery_birth` anchors a behavioural birth (`:669-689`, best-effort, never breaks the scan). On a held decision with a wired `held_sink` + `surface_holds=True`, `_maybe_surface_hold` routes a `HeldDecision` to the voice queue, deduped per reconciliation key (`:632-667`).
- `_apply` (`:691-721`): save new agent + index link; or `model_copy` capability-surface update; or `set_lifecycle(..., QUARANTINED)`; NO-OP/SKIPPED/HELD apply nothing.
- `_compute_registry_state_hash` (`:508-536`): SHA-256 over a sorted compact projection (`agent_id, revision, tenant_id, lifecycle_status, trust_tier`) — lets snapshots prove they captured the exact registry state.

### 4. Scheduler (`scheduler.py`) — standing watch
- One daemon thread (`_run_loop`, `:245-261`): runs once on start, then sleeps in 1-second slices for responsive `stop()`. Opt-in via `TEX_DISCOVERY_SCAN_INTERVAL_SECONDS`; tenants from `TEX_DISCOVERY_SCAN_TENANTS`; min interval 30s (`:66`), default 3600s. `enroll_tenant` adds a tenant under lock at runtime (`:166-182`).
- `_run_one_cycle` (`:263-385`): per tenant, `service.scan(trigger="scheduled", surface_holds=True)`; `_emit_drift_events`; optional `snapshot_capture_callable`; metrics. Catches `ScanInProgress` (lock conflict counter) and generic failures. **Once per cycle** runs the dormancy sweep (`:363-371`).
- `_emit_drift_events` (`:389-542`): diffs this run's `_entry_digest` against `_last_seen_by_tenant[tenant]`. NEW_AGENT for first-seen keys; AGENT_CHANGED via `_digests_equivalent`/`_changes_between` (severity WARN if `capability_widened`); AGENT_DISAPPEARED for vanished keys — but **soft** when a `PresenceTracker` is wired (only the transition into `CONFIRMED_DISAPPEARED` emits). `RECOVERED`/`REAPPEARED`/`SILENT_MISS` counted from the presence machine.
- `_notify` dispatches each drift event to the `AlertEngine`.

### 5. Presence (`presence.py`) — soft-disappearance
`PresenceTracker` runs a per-`(tenant, reconciliation_key)` machine PRESENT→MISSING_ONCE→MISSING_TWICE→CONFIRMED_DISAPPEARED (default threshold 3, `:59`). `observe_seen`/`observe_missing` return `(record, TransitionEvent)`. State persists to Postgres (`tex_presence_states`, schema at `:81-99`) when `DATABASE_URL` is set; otherwise in-memory with a warning (`:181-186`). Schema-bootstrap failure falls back to in-memory (`:192-198`).

### 6. Dormancy (`dormancy.py`) — governance not notification
`DormancyController.sweep()` (`:136-197`): for each ACTIVE agent idle past threshold (default 30 days, `:53`), if `_is_load_bearing` is true or unknown (conservative: unknown → load-bearing, `:124-133`) it appends a `dormancy_abstain` `HeldDecision`; otherwise `_sleep` sets lifecycle SLEEPING and `provenance_engine.seal_sleep(...)`. Already-sleeping agents only get `_check_day90`: past the 90-day reversible window (`:57`), appends a `dormancy_permanent_deletion` held decision — it **never deletes itself** (`:30-32`, `:214-240`). `wake`/`revoke` are the sealed human acts.

### 7. Alerts (`alerts.py`) — detection only
`AlertEngine.from_environment()` (`:271-288`) builds Log (always-on) + Webhook (`TEX_ALERT_WEBHOOK_URL`) + Slack (`TEX_ALERT_SLACK_WEBHOOK_URL`) sinks; `TEX_ALERTS_DISABLED` kills it. `default_rules()` (`:182-236`): `ungoverned_high_risk_appeared` (CRITICAL), `agent_disappeared` (WARN), `capability_surface_widened` (WARN). Sinks fire on a daemon worker thread so a slow webhook never blocks the scheduler (`:342-357`). Explicitly **detection, not response** (`:21-26`).

### 8. Conduit shared walker (`conduit/connector.py`)
`ProviderConsentGraphConnector` (`:140-289`) is the single IdP enumerator. `_build_graph` (`:173-204`): for each principal row from `transport.get_paginated(profile.principal_collection)`, register it (`is_agent` from profile predicate), then for each `GrantCollection` format `path_template` with the principal id and map grant rows to `ConsentEdge`s; profiles with `inline_edges` (Google/Ping) yield edges straight off the principal row. `_candidate_from_principal` (`:207-276`): `graph.blast_radius(id)`, then risk band from the **profile's own** `critical_scopes` (exact membership) and `high_risk_stems` (substring), overwriting the three blast-evidence fields so the sealed evidence reflects this provider's dictionary, not Entra's (`:249-252`). `sweep_delta` (`:279-289`) advances a persisted `delta_link` for the standing watch.

`ProviderProfile` (`:88-137`) is a frozen dataclass of everything that differs per IdP: source, principal collection, grant collections + mappers, agent predicate, critical/high sets, field extractors, optional `inline_edges`. `GrantCollection` (`:72-85`) pairs a path template with a `ConsentEdgeMapper`.

### 9. Consent graph (`consent_graph.py`) — pure, deterministic
`ConsentGraph` of `ConsentEdge(client_id, resource_id, resource_name, scopes, tenant_wide)`. `reachable_resources` (`:109-127`) is a cycle-guarded DFS transitive closure (a resource that is itself an agent extends the path). `blast_radius` (`:138-161`) returns direct resource names, reachable count, scope set, high-risk scopes (substring stems), critical scopes (exact membership against `CRITICAL_SCOPE_STEMS`), `tenant_wide_grant`, and `surface_unbounded = bool(critical) or (tenant_wide and bool(high))`. `agents()` returns principals flagged `is_agent`.

### 10. Conduit seal engine (`conduit/seal.py`) — the headline differentiator
- `ConduitProvenanceChain` (`:225-289`): append-only list of leaf hashes, sealed by a gix `CheckpointPublisher` (C2SP tlog-checkpoint + Ed25519 signed-note). **Separate from the governance decision ledger by construction** (`:13-23`) so the L3 count-conservation counters never see conduit events (the `VERDICT_TRANSCRIPT` discipline).
- `ConduitReceipt` (Pydantic, `:119-221`): self-contained, offline-verifiable. `.verify(...)` (`:149-221`) recomputes the leaf hash, checks Merkle inclusion (`verify_inclusion`), parses + verifies the Ed25519 signed-note against a pinned-or-embedded key (`Ed25519NoteVerifier`), and verifies the RFC-3161 anchor against a pinned TSA cert (`verify_anchor_receipt`). Any malformation is fail-closed (`:185`, `:194`).
- `seal_grant` (`:327-334`) → `GRANT_SEALED`. `InventorySnapshotSealer.seal` (`:475-483`) → `INVENTORY_SNAPSHOT_SEALED`: a Merkle root over the **sorted** set of per-agent `candidate_digest`s (order-independent, `:428-433`), with **batched** external anchoring (`anchor_every`, `:478`). `DriftGuardedConnector` (`:370-409`) refuses to scan when live scopes diverge from the sealed grant — seals `CONNECTION_DRIFT` and raises `ConnectionDriftError` (fail-closed on stale consent). `StandingWatch` (`:496-537`) bridges `sweep_delta()` to a re-sealed snapshot.
- `make_rfc3161_anchor` (`:293-319`) builds an `AnchorFn` over an injected `Poster` — no network import in this module.

### 11. Broker (`conduit/broker.py`) — four-state machine
`ConnectBroker.request → consent → probe → seal` (`:112-162`). `request` calls `strategy.begin_consent`; `consent` calls `strategy.finalize_consent` → `DirectoryGrant`; `probe` calls `strategy.build_transport` (or records scope baseline if no transport factory — `:144-148`); `seal` calls `seal_grant` and stores the receipt. `sealed_connection_for(tenant)` (`:92-101`) returns the latest SEALED connection — this is what the discovery layer borrows. The broker **never holds long-lived secrets** (only `connection_id` + `credential_ref`, `:5-8`).

### 12. Grant / strategies / profiles / transports
- `DirectoryGrant` (`grant.py:43-138`): frozen Pydantic, `extra="forbid"`, tenant normalized, scopes canonicalized (strip/casefold/dedupe/sort), `granted_at` must be tz-aware, `credential_ref` rejects whitespace ("not a secret blob", `:92-100`). `degraded`/`missing_scopes` computed from requested−granted (`:109-115`). `canonical_payload` is the deterministic hashed leaf.
- `ConnectStrategy` Protocol + `BaseConnectStrategy` (`providers/base.py:73-120`): `build_transport` raises `NotImplementedError` if no `transport_factory` is wired (`:115-119`) — this is an interface guard, not a stub.
- Per-provider strategies declare honest consent steps: Entra is genuinely `one_click=True` (`entra.py:43-55`); Okta is 3 steps, one `needs_super_admin` + `optional` (`okta.py:53-85`); Google is two separate grants/receipts (`google.py`); Ping is per-deployment (`ping.py`).
- `ENTRA_PROFILE` reproduces the legacy hand-written connector byte-for-byte (claim that the `FixtureGraphTransport` tests pass unchanged, `entra_profile.py:11-14` — unverified here, but the code path is a clean refactor: `entra_is_agent` is "the legacy predicate, verbatim" with the `TEX_DISCOVERY_HOME_TENANT_ONLY` gate keyed off intrinsic `appOwnerOrganizationId`, `:73-95`).
- Transports all implement the `GraphTransport` Protocol and lazily import `httpx`: `LiveGraphTransport` (MS Graph, client-credentials, `@odata.nextLink`, 429/Retry-After backoff, delta links — `graph_transport.py:64-145`); `OktaTransport` (`build_client_assertion_jwt` RS256 private-key JWT via `cryptography`, Link-header paging — `okta_transport.py`); Google pageToken transports; Ping HAL-cursor transport.

---

## Public API (symbols other code imports)

From `tex.discovery` (`__init__.py:45-53`): `DiscoveryService`, `DiscoveryScanResult`, `ReconciliationEngine`, `ReconciliationDecision`, `ReconciliationIndex`, `AUTO_REGISTER_THRESHOLD`, `QUARANTINE_DRIFT_THRESHOLD`.

Other live import surfaces (confirmed by grep across `src/tex`):
- `tex.discovery.service` → `DiscoveryService`, `ScanInProgress` (used by `api/discovery_routes.py:47`, `main.py:65`).
- `tex.discovery.scheduler` → `BackgroundScanScheduler` (`main.py:716`).
- `tex.discovery.dormancy.DormancyController`, `tex.discovery.ignition.IgnitionRegistry`, `humanize_count` (`main.py:63-64`, `api/discovery_surface_routes.py:42`).
- `tex.discovery.connectors` → all 13 classes (`main.py:49-61`).
- `tex.discovery.conduit.broker.ConnectBroker`, `conduit.providers.entra.{EntraConnectStrategy, ENTRA_READ_SCOPES}`, `conduit.seal.ConduitProvenanceChain`, `conduit.live_connector.ConduitConnectionsConnector`, `conduit.profiles.entra_profile.ENTRA_PROFILE` (`main.py:1469-1471,1616-1617`; `api/conduit_routes.py:41-42`).
- `tex.discovery.graph_transport.{GraphCredentials, LiveGraphTransport, FixtureGraphTransport}` (`main.py`, `sim/connectors.py`).
- `tex.sim.connectors` imports `EntraConsentGraphConnector`, `OcsfAuditConnector`, `MCPServerConnector`, `FixtureGraphTransport` (`sim/connectors.py:45-48`).

---

## Wiring

### Wiring In — LIVE call paths

**Path A — synchronous scan API.** `main.create_app` includes `build_discovery_router()` (`main.py:1445`, prefix `/v1/discovery`). `api/discovery_routes.py:593` reads `app.state.discovery_service`; the scan handler calls `service.scan(...)` (`discovery_routes.py:334`). `app.state.discovery_service` is set from `runtime.discovery_service` (`main.py:1609`), which `build_runtime` constructs at `main.py:746-754` with `connectors=_build_discovery_connectors()`. **→ LIVE.**

**Path B — background scheduler.** `build_runtime` constructs `BackgroundScanScheduler(service=discovery_service, ...)` at `main.py:808-820`. `create_app`'s `lifespan` → `_start_scheduler(rt)` → `scheduler.start()` (`main.py:1360-1370, 1379`). A demo tenant is enrolled at boot (`main.py:826-830`). **→ LIVE** (the daemon only loops if it has tenants or a dormancy controller; it always has the dormancy controller, so the dormancy sweep runs even with zero scan tenants — `scheduler.py:147-152`).

**Path C — ignition surface.** `build_discovery_surface_router()` included at `main.py:1461` (prefix `/v1/surface/discovery`). `ignite` reads `app.state.ignition_registry` (set at `main.py:1728`) and calls `service.scan(trigger="ignition")` (`discovery_surface_routes.py:185-187`), then `ignition.fire(tenant)`. **→ LIVE.**

**Path D — conduit connect.** `build_conduit_router()` included at `main.py:1500` (prefix `/v1/surface/conduit`). `app.state.conduit_broker = ConnectBroker(strategies=[EntraConnectStrategy(...)], chain=ConduitProvenanceChain(...))` (`main.py:1496-1499`). The route handlers drive `broker.request` (`conduit_routes.py:141`), `broker.consent`/`probe`/`seal` (`:222-224`). **→ LIVE.**

**Path E — conduit→discovery bridge.** `ConduitConnectionsConnector(lookup=_conduit_lookup, profiles={MICROSOFT_GRAPH: ENTRA_PROFILE})` is registered onto the live `DiscoveryService` at `main.py:1632-1637`; `_conduit_lookup` lazily reads `app.state.conduit_broker.sealed_connection_for(tenant_id)`. So a scan for a *connected* tenant maps its real Entra estate via the sealed connection's live transport; inert for unconnected tenants (`live_connector.py:46-49`). **→ LIVE (INDIRECT until a tenant actually seals an Entra connection).**

### Connectors actually instantiated (`_build_discovery_connectors`, `main.py:1859-2013`)
Always: `MicrosoftGraphConnector`, `SalesforceConnector`, `AwsBedrockConnector`, `GitHubConnector`, `MCPServerConnector` (`:1899-1905`), plus `EntraConsentGraphConnector` (live transport if `TEX_DISCOVERY_ENTRA_*` set, else `FixtureGraphTransport(entra_pages())` demo seed — `:1912-1949`), `OcsfAuditConnector` (demo `cloudtrail_records()` or empty — `:1955-1968`), `OpenAIConnector`/`OpenAIAssistantsLiveConnector` (`:1970-1990`), `SlackConnector`/`SlackLiveConnector` (`:1992-2011`). `TEX_SANDBOX=1` swaps in `tex.sim.connectors.build_sandbox_connectors()` (`:1881-1883`).

**Imported but never instantiated in the runtime:** `CloudAuditConnector` (the non-OCSF mock), `KernelEbpfConnector`, `NetworkEgressConnector` (imported at `main.py:51,53,56`; no `(...)` call site found in `main.py`). These three connectors are present, fully implemented, and reachable via the package, but **no live scan emits their candidates** — they are demo/test/aspirational planes only.

### Wiring Out — dependencies
- **Internal tex subsystems:** `tex.domain.discovery` (CandidateAgent, sources, ledger entry, actions), `tex.domain.agent` (AgentIdentity, lifecycle, CapabilitySurface, environment), `tex.domain.signal_trust.tier_for_source` (admissibility tier 2=control-plane … 5=kernel), `tex.stores.{agent_registry, discovery_ledger, connector_health, scan_runs, drift_events}`, `tex.observability.discovery_metrics`, `tex.provenance.{engine, feed (HeldDecision/Sink), models}` (dormancy + birth-anchoring), `tex.interchange.{gix, external_anchor}` (conduit seal primitives).
- **External libraries:** `pydantic` (DirectoryGrant, ConduitReceipt), `psycopg` (presence durability), `cryptography` (`Ed25519PublicKey` in evidence_fold; RS256 private-key JWT in okta_transport; ML-DSA probe in tiers), `httpx` (live transports, lazy-imported), `urllib` (live OpenAI/Slack connectors + alert webhook/Slack sinks), stdlib `hashlib`/`json`/`threading`/`base64`.

---

## Implementation Reality

**REAL (substantive logic):**
- Reconciliation decision matrix and drift scoring — full branchy logic, no placeholders (`reconciliation.py`).
- DiscoveryService scan loop, idempotency/locking, registry-state hashing, replay (`service.py`).
- Scheduler drift diff, presence machine, dormancy sweep, metrics (`scheduler.py`).
- `PresenceTracker` Postgres write-through with real `INSERT … ON CONFLICT` upsert and bootstrap (`presence.py:397-423`).
- Consent graph transitive closure + blast radius (`consent_graph.py`).
- Conduit seal: real Merkle inclusion, real Ed25519 signed-note verification, real RFC-3161 anchor verification against a pinned TSA cert (`seal.py:149-221`) — composing the project's *verified* `interchange/gix.py` + `interchange/external_anchor.py` (and explicitly **not** the unverified `c2pa/timestamp.py`, `seal.py:6-9`). A `scripts/verify_conduit_receipt.py` exists (file present, 6055 bytes).
- `EvidenceFold` Ed25519 JCS-canonical verification via `cryptography` (`evidence_fold.py:111-118`); fail-closed (any verify failure → TAMPERED → risk-raising).
- Live transports: real OAuth client-credentials + pagination + 429 backoff (`graph_transport.py`, `okta_transport.py` incl. real RS256 JWT minting, `google_transport.py`, `ping_transport.py`).
- Live connectors: real HTTP enumeration over urllib (`openai_live.py`, `slack_live.py` with graceful admin-scope degradation).

**Mock-by-design (NOT stubs — they implement the full candidate-shaping logic against fixture records):** `microsoft_graph.py`, `salesforce.py`, `aws_bedrock.py`, `github.py`, `mcp_server.py`, `slack.py`, `openai_assistants.py`, `cloud_audit.py`, `kernel_ebpf.py`, `network_egress.py`. Each carries a docstring describing the real-API drop-in. These are the documented test/demo surface, not hollow.

**Interface guards (NotImplementedError that is correct, not a gap):**
- `BaseConnectStrategy.build_transport` raises `NotImplementedError` when no `transport_factory` is wired (`providers/base.py:115-119`) — and `broker.probe` *catches* it to degrade gracefully to consent-only (`broker.py:144-148`).
- `AlertSink.deliver` base raises `NotImplementedError` (`alerts.py:62`) — abstract method; concrete sinks override.

**Graceful-fallback crypto reality:**
- `tiers.ml_dsa_backend_available()` does a **real round-trip probe** (keygen+sign+verify ML-DSA-65 via `tex.pqcrypto.algorithm_agility`) and returns False on any failure (`tiers.py:84-95`). Default posture: ML-DSA "auto" — active iff a FIPS-204 backend is installed; **the floor (Ed25519 signed-note + RFC-3161 TSA) is always active with zero config** (`tiers.py:36-42`, `:113-168`).

**Honestly-flagged aspirational tiers (overstatement risk, but disclosed in code):**
- Witness cosigning is `available=False` this wave — `tiers.py:133-143` literally records "federated=False … The 'don't trust Tex' claim is go-to-market until then." OpenTimestamps off unless a calendar is configured. These are not active by default.

**Live-capable but unwired components (built, tested-elsewhere, no runtime call path):** `ShadowCorrelator`, `EvidenceFold`, `StandingWatch`, `DriftGuardedConnector`, `InventorySnapshotSealer`, `ProvenanceTierConfig`, and the Okta/Google/Ping `ConnectStrategy`+`Profile`+`Transport` triples. Grep across `src/tex` (excluding `/conduit/` and `/tests/`) found **zero** non-test instantiations of any of these. Only Entra is registered in the broker (`main.py:1497`) and only `ENTRA_PROFILE` is handed to the bridge (`main.py:1635`).

---

## Technology / SOTA

- **Consent-graph blast radius:** directory estate modeled as a graph; transitive closure of OAuth consent edges = an agent's reachable systems (`consent_graph.py`). "Defenders think in lists, attackers think in graphs" framing (`:2-4`).
- **Admissibility hierarchy of discovery planes** (verified tiers via `tier_for_source`): control-plane/IdP graph = 2, AUDIT_LOG (CloudTrail/OCSF) = 4, KERNEL_EBPF = 5. The OCSF audit connector folds many events per resource-ARN; the eBPF connector keys on a measured-code hash (Tetragon shape); the network-egress connector keys on TLS-SNI + JA3/JA4 client fingerprints (survives IP/cert rotation).
- **OCSF normalization** (`ocsf.py`): one schema for CloudTrail/Azure/Security-Lake; `cloudtrail_to_ocsf` adapter; content-free (actor/op/resource/time only).
- **Tamper-evident transparency log:** C2SP tlog-checkpoint + Ed25519 signed-note + Merkle inclusion (RFC 9162 empty-tree root constant, `seal.py:44`) + RFC-3161 CMS-verified external anchor; per-agent leaves sorted for order-independent inventory roots.
- **OAuth 2.1 private-key JWT** client assertion (RS256 over JCS-ish header/claims, `okta_transport.py:33-77`) — no PyJWT dependency.
- **FIPS-204 ML-DSA** optional seal tier; **CNSA 2.0** compliance language; mapped to NIST SP 800-53 AU-9/AU-10 and EU AI Act Arts. 10/12/15 (`tiers.py`).
- **Soft-disappearance state machine** to suppress false-positive disappearance alerts from transient API flakiness (`presence.py`).
- **JCS (RFC 8785-style) canonical JSON** for deterministic leaf hashing (`seal.py:85-92`, `evidence_fold.py:50-51`).

---

## Persistence

- **In-memory by default:** agent registry, discovery ledger, scan-run store, connector-health store, drift-event store (all `tex.stores.*` defaults), `ReconciliationIndex`, `IgnitionRegistry` (intentionally per-process, `ignition.py:16-18`), the conduit `ConduitProvenanceChain` leaf list (`seal.py:236`), broker connections (`broker.py:77`).
- **Durable when `DATABASE_URL` is set:** `PresenceTracker` → Postgres `tex_presence_states` with write-through upsert + restart bootstrap (`presence.py`). Other V15/V16 stores (drift/scan-runs/snapshots) advertise durability via `is_durable` and back to Postgres when configured (wired in `main.py`).
- **Externally anchored:** conduit receipts carry an RFC-3161 TSA token (when an `AnchorFn` is injected), making the inventory continuity un-backfillable without the TSA's cooperation. The chain itself is in-memory in the default runtime, so durability of conduit history depends on a deployment persisting receipts/leaves (no Postgres-backed conduit chain found in scope).

---

## Notable Findings

1. **The conduit "drift-guard / standing-watch / inventory-seal" trio is built but not wired into a scan path.** `DriftGuardedConnector`, `StandingWatch`, and `InventorySnapshotSealer` (`seal.py`) have zero runtime instantiations. The broker seals `GRANT_SEALED` on connect (live), but `INVENTORY_SNAPSHOT_SEALED` — billed as half the headline differentiator (`conduit/__init__.py:9-19`) — is never sealed by the running app. Inventory snapshot sealing is **code-complete but dormant in the wired runtime** (the discovery-surface ignition path seals via a different mechanism; see `discovery_surface_routes.py` references at `main.py:1731`, "ignition seals the inventory").

2. **Only Entra is live among the four IdPs.** Okta/Google/Ping have complete `ConnectStrategy` + `ProviderProfile` + `Transport` implementations and a curated critical-scope dictionary, but the broker registers only `EntraConnectStrategy` (`main.py:1497`) and the bridge only maps `MICROSOFT_GRAPH → ENTRA_PROFILE` (`main.py:1635`). The "cross-IdP neutrality" is real in the *engine* (one shared `ProviderConsentGraphConnector` + per-profile dictionaries) but not exercised end-to-end in the runtime. Cross-IdP support is **shipped as latent capability, not active surface.**

3. **Three discovery planes are imported but never instantiated:** `CloudAuditConnector` (non-OCSF mock), `KernelEbpfConnector`, `NetworkEgressConnector`. The eBPF and network-egress planes — described in docstrings as the top of the admissibility hierarchy and the "headless agent nothing else lists" — are **mock-only and not in any live scan**. (The OCSF audit plane *is* live via `OcsfAuditConnector`.)

4. **`ShadowCorrelator` and `EvidenceFold` are unwired.** `shadow.py` correctly notes reconciliation does NOT cross-correlate audit↔control-plane keys "for free" (`shadow.py:6-11`) — but the explicit pass that would bridge them is never called by the runtime. Same for the A2A/MCP card `EvidenceFold`.

5. **Self-aware honesty in `tiers.py` is a positive contradiction-of-overstatement.** The witness-cosign "you don't have to trust Tex" claim is flagged in code as go-to-market, not active (`tiers.py:136-143`). This is the opposite of an overstatement — it is a built-in disclaimer. Worth preserving.

6. **ML-DSA probe is genuine, not cosmetic.** `ml_dsa_backend_available()` actually keygens/signs/verifies (`tiers.py:84-95`); but note conduit checkpoint notes stay Ed25519 even when ML-DSA is available — only the evidence-chain seals use ML-DSA (`tiers.py:124-130`). So "PQ-sealed conduit receipts" would be an overstatement: the conduit signed-note is Ed25519; an ML-DSA-44 signed-note type is reserved as a future drop-in (`tiers.py:127-129`).

7. **Demo seed is on by default** (`TEX_DISCOVERY_DEMO_SEED=1`, `main.py:1892`): 33 fixture Entra agents + 8 fixture CloudTrail shadow agents = 41, deliberately sized to land "forty-one agents running" (`demo_seed.py:30-31, 22`). A production deploy that must never surface fixture agents has to set `TEX_DISCOVERY_DEMO_SEED=0`. The scheduler also enrolls a `demo` tenant at boot by default (`main.py:826-830`), so the standing watch runs against fixtures out of the box — operationally relevant.

8. **`_build_discovery_connectors` lists the mock and live connector pairs and prefers live when env credentials are present**, falling back to the mock on construction failure (`main.py:1922-1949, 1972-2011`) — a robust degrade pattern, accurately described by its docstring.

9. **Reconciliation drift only flags widening, never narrowing** (`reconciliation.py:312-316`). Intentional (compromise/misconfig signal is permission *gain*), but worth noting: an agent silently *losing* all its scopes produces NO drift event and is treated as `NO_OP_KNOWN_UNCHANGED` if nothing widened — disappearance is the only signal for "agent went dark," and that is soft-gated by the presence machine.

10. **Documentation cross-check:** the `__init__.py` docstring lists the SaaS connectors (OpenAI/Slack/Bedrock/GitHub/Graph/Salesforce/MCP) but predates the conduit IdP-root and the audit/eBPF/egress planes — it under-describes the current surface rather than over-claiming. The conduit module docstrings accurately describe the seal architecture as verified in code.
