# Trace: discovery-conduit-e2e

**Claim under test:** The conduit/discovery layer can connect a real directory and
populate the entity/agent stores that feed decisions.

**Verdict: CONFIRMED** (with one honest scope bound: of the four IdP connect
strategies implemented, only **Entra** is wired into the live broker — Okta /
Google / Ping are real code but unreachable from the running app).

Branch: `feat/proof-carrying-gate`. All paths absolute under
`/Users/matthewnardizzi/dev/tex`. Verified by reading code + a runtime smoke test,
not docstrings.

---

## The call path (every hop cited)

### A. Connect a directory (the front door → sealed grant + live transport)

1. **Router wired into the app.**
   `src/tex/main.py:1473-1508` — `build_conduit_router()` is imported and
   `app.include_router(build_conduit_router())` (`:1508`). The broker is attached
   at `app.state.conduit_broker = ConnectBroker(strategies=[EntraConnectStrategy(...)], chain=_conduit_chain)`
   (`:1501-1504`). Only the Entra strategy is registered.

2. **`POST /v1/surface/conduit/connect/entra/start`** — `src/tex/api/conduit_routes.py:128-164`.
   Calls `broker.request(DiscoverySource.MICROSOFT_GRAPH, tenant_id, nonce=...)`
   (`:141-143`) and returns the Microsoft admin-consent URL (`_admin_consent_url`,
   `:77-83`). If `TEX_CONDUIT_ENTRA_CLIENT_ID` is unset it returns
   `configured: false` and the honest step list — graceful degrade, not a crash.

3. **Broker state machine** — `src/tex/discovery/conduit/broker.py`.
   `REQUESTED -> CONSENTED -> PROBED -> SEALED`:
   - `request()` `:112-125` → `EntraConnectStrategy.begin_consent` (`providers/entra.py:37-56`).
   - `consent()` `:128-134` → `BaseConnectStrategy.finalize_consent` builds a frozen
     `DirectoryGrant` (`providers/base.py:99-112`).
   - `probe()` `:137-153` → `strategy.build_transport(grant)` →
     `BaseConnectStrategy.build_transport` (`providers/base.py:114-120`), which calls the
     injected `transport_factory`. In main that factory is `_entra_transport_factory`
     (`main.py:1481-1496`) returning a **real** `LiveGraphTransport(GraphCredentials(...))`.
     If no factory/creds, `NotImplementedError` is caught and the probe records the
     scope baseline with `transport=None` (consent-only, reachability unverified) —
     graceful, not a stub.
   - `seal()` `:156-162` → `seal_grant(chain, grant)` puts `GRANT_SEALED` on the conduit
     provenance chain and flips state to `SEALED`.

4. **`GET /v1/surface/conduit/connect/entra/callback`** — `conduit_routes.py:166-238`.
   Fail-closed on denied/errored consent (`:190-196`) and on tenant swap
   (`:200-210`). On success it runs `broker.consent → broker.probe → broker.seal`
   (`:222-224`) and returns `{"connected": true, "sealed": true, "next": {"ignite_tenant": <tenant>}}`.
   The callback itself does **not** scan; it hands the tenant to ignition.

### B. The bridge: sealed connection → discovery connector

5. **Tenant-aware connector registered on the live `DiscoveryService`** —
   `src/tex/main.py:1616-1644`. After publish, a `ConduitConnectionsConnector` is
   `runtime.discovery_service.register_connector(...)`'d with a lazy `_conduit_lookup`
   (`:1625-1635`) that reads `app.state.conduit_broker` at scan time and calls
   `broker.sealed_connection_for(tenant_id)` (`:1632`) → returns
   `(conn.transport, conn.provider)`. Inert (`(None, None)`) for any tenant that
   never sealed a connection.

6. **`ConduitConnectionsConnector._run_scan`** — `src/tex/discovery/conduit/live_connector.py:46-53`.
   Looks up the sealed transport; if present, delegates to
   `ProviderConsentGraphConnector(transport=transport, profile=ENTRA_PROFILE).scan(context)`.
   For an un-connected tenant it returns immediately → completely inert (no demo
   disturbance). `broker.sealed_connection_for` is at `broker.py:92-101`.

### C. Scan → entity/agent extraction

7. **`ProviderConsentGraphConnector`** — `src/tex/discovery/conduit/connector.py:140-289`.
   - `_build_graph` (`:173-204`) walks `profile.principal_collection`
     (`servicePrincipals`) via `transport.get_paginated`, and for each principal walks
     `grant_collections` (`oauth2PermissionGrants`, `appRoleAssignments`), mapping each
     grant row to a `ConsentEdge`.
   - `_run_scan` (`:164-170`) emits one `CandidateAgent` per agent-bearing principal.
   - `_candidate_from_principal` (`:207-276`) computes blast radius, risk band
     (CRITICAL/HIGH/MEDIUM/LOW), capability hints, and sealed evidence — substantive
     logic, not a placeholder.
   - `ENTRA_PROFILE` — `src/tex/discovery/conduit/profiles/entra_profile.py:138-167`:
     real `is_agent` predicate (`entra_is_agent` `:73-95`), delegated/app-role edge
     mappers (`:98-124`), Entra critical/high-risk scope sets.

8. **Transport is a real Graph reader** — `src/tex/discovery/graph_transport.py:64-145`.
   `LiveGraphTransport`: real OAuth2 client-credentials token fetch (`_bearer` `:78-98`,
   `httpx.post` to `/oauth2/v2.0/token`), real `@odata.nextLink` pagination
   (`get_paginated` `:121-129`), real `429`/`Retry-After` backoff (`_get` `:100-118`),
   real delta links (`get_delta` `:131-145`). `FixtureGraphTransport` (`:148-168`) is the
   test seam only.

### D. Discovery ledger + entity store + decision context

9. **`DiscoveryService.scan`** — `src/tex/discovery/service.py:278-469`.
   For each connector candidate: `_handle_candidate` (`:594-630`) →
   `ReconciliationEngine.decide` (`:608`) → `_apply` (`:691-721`).
   - `_apply` writes the new agent into the registry: `self._registry.save(decision.new_agent)`
     (`:695`) and links the reconciliation index (`:696-699`).
   - Every outcome is appended to the discovery ledger: `self._ledger.append(...)` (`:627-630`).
   - On REGISTER it best-effort seals a behavioural birth into the provenance engine
     (`_seal_discovery_birth` `:669-689`).

10. **Reconciliation is real promotion logic** — `src/tex/discovery/reconciliation.py:113-222`.
    `_handle_new` (`:148-222`) builds a genuine `AgentIdentity` (`:187-205`,
    lifecycle `PENDING`, capability surface from hints, discovery metadata) and returns
    `ReconciliationAction.REGISTERED`. Held branches: below-threshold → `NO_OP_BELOW_THRESHOLD`
    (`:149-162`); unbounded surface → `HELD_AMBIGUOUS` (`:164-177`). No stub / NotImplementedError.

11. **Shared registry == the decision context.** The same `agent_registry` object
    (created once at `main.py:574`/`:579`) is passed to:
    - `DiscoveryService(registry=agent_registry, ...)` (`main.py:752`),
    - `EvaluateActionCommand(agent_registry=agent_registry, ...)` (`main.py:967-974`),
    - `StandingGovernance(agent_registry=runtime.agent_registry, ...)` (`main.py:1744-1749`).
    `EvaluateActionCommand` reads it during adjudication: `existing = registry.get(resolved_agent_id)`
    (`src/tex/commands/evaluate_action.py:399`), pulling the discovered agent's capability
    surface into the decision. So a discovered agent is governed the instant it acts.

### E. The trigger that closes the loop

12. **`POST /v1/surface/discovery/ignite`** — `src/tex/api/discovery_surface_routes.py:140-224`.
    Calls `service.scan(tenant_id=tenant, trigger="ignition", surface_holds=is_real_tenant)`
    (`:185-189`), which runs the registered `ConduitConnectionsConnector` against the
    connected tenant. Also enrolls the standing watch (`:197-202`) and switches on the
    live PDP (`governance.activate(tenant)` `:208-213`). The spoken count is read from the
    same shared registry via `_estate_count` (`:85-90`). The conduit callback's
    `next.ignite_tenant` is exactly this route's input.
    Audit-grade twin: `POST /v1/discovery/scan` (`src/tex/api/discovery_routes.py:302-368`)
    also calls `service.scan(...)` (`:334`).

---

## Runtime proof (smoke test)

A fixture Entra estate (one Application SP + one delegated `Mail.Read User.Read`
grant) was pushed through `ConduitConnectionsConnector → DiscoveryService → registry`
with `PYTHONPATH=src`:

```
candidates_seen: 1
registry size after connected scan: 1
  AGENT: Billing Agent | lifecycle: PENDING | source: microsoft_graph
inert tenant candidates_seen: 0 | registry size: 0
```

A connected tenant populates the registry with a real `AgentIdentity`; an
un-connected tenant is inert. The path is live and behaves as wired.

---

## Which connectors are REAL (enumerated)

### Conduit connect strategies (the "connect a directory" front door)
| Provider | Strategy class | Profile | Transport | Wired in live broker? |
|---|---|---|---|---|
| **Entra / Microsoft Graph** | `EntraConnectStrategy` (`providers/entra.py:29`) | `ENTRA_PROFILE` (real) | `LiveGraphTransport` (real OAuth2+paging+429, `graph_transport.py:64`) | **YES** (`main.py:1502`) — true one-click admin consent |
| Okta | `OktaConnectStrategy` (`providers/okta.py:39`) | `okta_profile.py` (real, 128 LOC) | `OktaTransport` (real httpx, private-key-JWT, `okta_transport.py:80`) | **NO** — implemented, never registered |
| Google Workspace / GCP IAM | `GoogleWorkspaceConnectStrategy` / `GcpIamConnectStrategy` (`providers/google.py:40,71`) | `google_profile.py` (real, 159 LOC) | `GoogleWorkspaceTransport`/`GoogleIamAssetTransport` (real httpx, `google_transport.py:88,97`) | **NO** — implemented, never registered |
| Ping | `PingConnectStrategy` (`providers/ping.py:28`) | `ping_profile.py` (real, 84 LOC) | `PingTransport` (real httpx, `ping_transport.py:16`) | **NO** — implemented, never registered |

Reaching a non-Entra provider via `broker.request(...)` raises
`ConnectBrokerError("no connect strategy registered for <provider>")`
(`broker.py:80-84`). Grep confirms Okta/Google/Ping strategies are referenced
**only** inside `providers/` (definitions) — never wired into `main.py` or any
route. They are real, tested code on a shelf, not in the live path.

### Standalone discovery connectors (`_build_discovery_connectors`, `main.py:1864-2018`)
LIVE when env creds present, else fixture/mock (mocks default to `records=[]` → emit
nothing on a clean boot):
- **`EntraConsentGraphConnector`** — REAL. `LiveGraphTransport` when
  `TEX_DISCOVERY_ENTRA_*` set (`:1927-1948`), else `FixtureGraphTransport(entra_pages())`
  demo seed. Same `ProviderConsentGraphConnector` engine as the conduit path.
- **`OcsfAuditConnector`** — REAL feed consumer (`cloud_audit_ocsf.py`); demo seed by
  default, deployment-supplied OCSF reader otherwise (`:1956-1973`).
- **`OpenAIAssistantsLiveConnector`** — REAL HTTP (`openai_live.py`, `urllib` to
  `api.openai.com/v1`, `:135-145`) when `TEX_DISCOVERY_OPENAI_API_KEY` set; else
  `OpenAIConnector` mock (`:1976-1995`).
- **`SlackLiveConnector`** — REAL HTTP (`slack_live.py`, `urllib` to `slack.com/api`,
  `:216-221`, composes `users.list`/`bots.info`/`apps.list`) when `TEX_DISCOVERY_SLACK_TOKEN`
  set; else `SlackConnector` mock (`:1998-2016`).
- **Mocks (fixture-fed, `records=[]` default → inert):** `MicrosoftGraphConnector`,
  `SalesforceConnector`, `AwsBedrockConnector`, `GitHubConnector`, `MCPServerConnector`
  (`:1904-1910`). Real translation logic, no live API. Other connector files present but
  not in the default list: `aws_bedrock`, `network_egress`, `kernel_ebpf`,
  `entra_consent_graph` (used), `cloud_audit`, `microsoft_graph` (used as mock).

---

## Gaps / honest bounds

- **Only Entra is reachable as a connect strategy.** Okta/Google/Ping connect
  strategies, profiles, and transports are fully implemented and HTTP-real but are
  **not registered in the live broker** (`main.py:1502` lists only
  `EntraConnectStrategy`). The README/marketing "one button, four providers" is a
  *(claim, unverified for non-Entra in the live app)* — the code exists, the wire does not.
- **Live Entra still needs deployment config.** `_entra_transport_factory` requires
  `TEX_CONDUIT_ENTRA_CLIENT_ID` + `TEX_CONDUIT_ENTRA_CLIENT_SECRET`
  (`main.py:1482-1487`); without them `/start` returns `configured: false` and probe
  records `transport=None` (consent-only). The chain to a *real* tenant is correct but
  dormant until the multi-tenant Entra app is registered + secrets set. This is config,
  not a code gap.
- **Broker connection state is in-process.** `ConnectBroker._connections` is a dict
  (`broker.py:77`); a multi-worker deployment loses start→callback continuity. Noted in
  the route docstring; not a blocker for single-worker / test-client.
- The conduit connector registration is wrapped in `try/except ... pass`
  (`main.py:1620-1644`) — additive-by-design (never blocks boot), but a silent failure
  there would drop the conduit discovery path without surfacing. Low risk; flagged.

**Net:** The end-to-end path — connect (Entra one-click admin consent) → seal grant +
build live Graph transport → ignite → tenant-aware connector borrows the sealed
transport → `ProviderConsentGraphConnector` extracts agents → reconciliation promotes →
shared agent registry → consumed by `EvaluateActionCommand`/`StandingGovernance` at
decision time — is real, wired, and runtime-verified for **Microsoft Entra**. CONFIRMED.
