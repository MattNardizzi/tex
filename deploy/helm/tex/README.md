# Tex Helm chart

One install brings up the whole governance stack and makes the PEP enroll
workloads automatically — the ambient way.

```bash
# Prereq for the webhook serving cert:
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set crds.enabled=true

# Install Tex (PDP + operator + webhook; kernel floor optional):
helm install tex ./deploy/helm/tex -n tex-system --create-namespace

# Turn governance ON for a namespace — that's the only per-tenant action:
kubectl label namespace my-agents tex.systems/govern=enabled
# optional explicit tenant (else the namespace name is the tenant):
kubectl label namespace my-agents tex.systems/tenant=acme
```

From that point, **every new pod** in `my-agents` is governed automatically —
the mutating webhook injects the PEP at creation, no per-pod YAML, no restart.
A pod can opt out with `tex.systems/govern-exclude=true`.

## Two enrollment modes

- **Sidecar injection** (`sidecarInjection.enabled=true`, default): portable,
  no node privileges. The webhook injects the proxy + an egress-redirect init
  container into governed-namespace pods.
- **Kernel floor** (`kernelFloor.enabled=true`): sidecarless. One eBPF
  DaemonSet per node governs every workload incl. brand-new ones, with no
  injection. Requires privileged nodes. Both read the same enrollment scope.

## What gets installed

PDP `Deployment`+`Service` (Tex) · operator `Deployment`+`Service` (enrollment
controller + webhook) · `MutatingWebhookConfiguration` scoped to governed
namespaces · RBAC (watch namespaces/pods) · cert-manager `Issuer`+`Certificate`
for the webhook · optional kernel-floor `DaemonSet` · optional API-key `Secret`.

## The 24/7 watch

Set `pdp.scanIntervalSeconds` (default 3600) so the standing watch keeps
sealing newly discovered agents. Until an agent is sealed it is governed by
default (fail-closed: unknown = forbid).

## Durability (read before raising `pdp.replicas`)

`pdp.replicas` is **1 on purpose**, and this is the honest current limit, not an
oversight. Two facts make a second PDP replica unsafe today:

1. **The evidence record is a hash-chained JSONL file.** `EvidenceRecorder`
   continues the chain from the file's last record on boot
   (`src/tex/evidence/recorder.py:_load_last_record_hash`). Two pods writing two
   files produce two divergent chains that can never be reconciled into one
   append-only log.
2. **Caches, the discovery scheduler, and `/metrics` counters are
   process-local.** A second pod runs a second scheduler (double scans/alerts)
   and serves a different counter view per scrape.

What this chart gives you for a **durable single-process pilot**:

- `pdp.databaseUrl` → `DATABASE_URL`: all durable *shared* state (decisions,
  policies, the evidence **mirror**, agent registry, discovery ledger, drift,
  scans) writes through to Postgres synchronously and is bootstrapped on boot.
  **Leave it empty and the PDP runs pure in-memory — a restart erases state.**
- `pdp.persistence` → a ReadWriteOnce PVC mounted at `/app/var/tex` so the
  canonical hash-chain JSONL (`var/tex/evidence`) **and** the evidence-seal
  signing key (`var/tex/keys`, regenerated if lost) survive pod restarts. RWO is
  why a single writer is enforced; `strategy: Recreate` avoids two pods racing
  the volume on redeploy (the trade-off is a brief restart gap).
- `pdp.appEnv` → **`TEX_APP_ENV`** (the var the app actually reads; the previous
  chart set `TEX_ENV`, which nothing reads, so it silently ran `development`:
  fail-closed guards off and auth open). A production-like value turns on the
  fail-closed startup guards and therefore *requires* `pdp.evidenceSummarySecret`
  (HMAC signing key, ≥32B) and `pdp.apiKeys` (`TEX_API_KEYS`, else every
  authenticated route returns 401). Set both, or the pod will refuse to boot /
  fail closed.
- `/metrics` is scraped via pod annotations (`pdp.metrics`).

```bash
helm install tex ./deploy/helm/tex -n tex-system --create-namespace \
  --set pdp.databaseUrl='postgres://tex:***@pg:5432/tex' \
  --set pdp.evidenceSummarySecret="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  --set pdp.apiKeys='key_abc:tenant_acme:decision:write+evidence:read'
```

**Multi-replica (HA) is deferred, not pretended.** It requires a single-writer
evidence service (one process owns chain append; replicas call it) or a
DB-backed append-only chain with a Postgres advisory-lock / `FOR UPDATE`
chain-head — plus leader election for the scheduler. That work edits the
evidence/provenance core (`src/tex/evidence`, `src/tex/provenance`), which the
**truth** track owns, so it is out of scope for this chart. See
`deploy/DURABILITY.md`.
