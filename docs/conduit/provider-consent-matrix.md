# Provider consent matrix

The honest, per-provider breakdown of what "Connect your directory" actually
asks for. The button is **one entry point, not one click** — this table is why.

| Provider | `DiscoverySource` | Consent shape | Read scopes requested | Agents discovered | Standing watch (delta) |
|---|---|---|---|---|---|
| **Microsoft Entra** | `microsoft_graph` | **One click** — multi-tenant admin consent | `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `AuditLog.Read.All` | service principals / app registrations / managed identities (+ Agent ID tags) | `servicePrincipals/delta` |
| **Okta** | `okta` | **Multi-step** — service app + private-key JWT + per-scope checklist | `okta.apps.read`, `okta.clients.read`, `okta.appGrants.read`¹, `okta.oauthIntegrations.read`, `okta.serviceAccounts.read`, `okta.apiTokens.read`, `okta.logs.read` | OAuth clients / service apps (`client_credentials`) | System Log (`logs`) |
| **Google Workspace** | `google_workspace` | **Grant 1 of 2** — domain-wide delegation | `admin.directory.user.readonly`, `admin.directory.domain.readonly`, `admin.reports.audit.readonly` | DWD OAuth clients | Reports token-audit |
| **GCP IAM** | `gcp_iam` | **Grant 2 of 2** — org viewer (separate receipt) | `roles/cloudasset.viewer`, `roles/iam.securityReviewer` | service accounts + IAM bindings (Cloud Asset Inventory) | asset feed |
| **Ping** | `ping` | **Per-deployment** service account (pluggable `base_url`) | `p1:read:application`, `p1:read:user`, `p1:read:role` | OAuth clients (`client_credentials`) | client management |

¹ `okta.appGrants.read` typically needs **Super Admin**. If withheld, the census
runs apps+clients only and the grant is **sealed as partial** (`degraded=true`),
never silently dropped.

## Risk banding is provider-specific by necessity

`blast_radius()` is one shared engine. The risk **dictionary** is not portable:

- **HIGH-risk stems are portable** (substring match): `readwrite`, `fullcontrol`,
  `manage`, `write`, `send`, `delete`, `impersonation`, `accessAsUser`. A few
  providers add stems (GCP: `owner`/`editor`/`admin`/`actAs`/`tokenCreator`;
  Ping: `create`/`update`).
- **CRITICAL scopes are literal and per-provider** (exact membership) — they
  confer org-wide control of identity itself, so blast radius = the whole org:

| Provider | Example critical scopes |
|---|---|
| Entra | `directory.readwrite.all`, `application.readwrite.all`, `roleManagement.readwrite.directory` |
| Okta | `okta.users.manage`, `okta.apps.manage`, `okta.roles.manage`, `okta.clients.manage` |
| GCP IAM | `roles/owner`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin` |
| Workspace | `admin.directory.user`, `admin.directory.rolemanagement`, `cloud-platform` |
| Ping | `p1:create:user`, `p1:update:user`, `p1:update:role`, `admin` |

The neutrality proof (tested): an over-privileged **Okta** client
(`okta.users.manage`) lands in the **same CRITICAL band** as an over-privileged
**Entra** app (`Directory.ReadWrite.All`) — same engine, different dictionary.

This dictionary is a **maintained, standing asset** (`risk_dictionary.py`).
Provider scope vocabularies drift; keeping it current is an ongoing obligation,
not a one-time seed.
