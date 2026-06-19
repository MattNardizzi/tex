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

## Born-in-a-box admission (the deny half)

Enrollment makes compliant pods governed. **Admission makes the box
mandatory** — it *refuses* a governed-namespace pod that cannot be brought into
the box. This is what flips Tex from "enroll compliant pods" to "**non-compliant
agents cannot run.**"

A governed-namespace pod is **denied** (unless it carries
`tex.systems/govern-exclude`) when it:

- declares no approved sandbox `runtimeClassName` (gVisor / Kata / Confidential
  Containers — see `admission.approvedRuntimeClasses`);
- is missing the `tex.systems/injected=true` annotation (the injector runs
  *before* validation, so its absence means the PEP was **not** injected —
  fail closed); or
- requests a host-namespace escape (`hostNetwork` / `hostPID` / `hostIPC`) or a
  `privileged` / `allowPrivilegeEscalation` container.

Two enforcement points, same rule (kept 1:1 in lock-step):

- **`ValidatingAdmissionPolicy` (CEL, default ON).** Runs **inside** the API
  server (`failurePolicy: Fail`), so — unlike a webhook — it has no pod that can
  be "down". Requires Kubernetes ≥ 1.30. It only acts on
  `tex.systems/govern=enabled` namespaces, so a fresh install changes nothing
  until you opt a namespace in. **After you label a namespace, its pods must
  declare an approved sandbox `runtimeClassName`** or they will be refused.
- **Validating webhook (`/validate`, default OFF).** The operator-code twin
  (`admission.webhook.enabled=true`), for future deny logic the CEL policy can't
  express (e.g. signature lookups). `failurePolicy: Fail` ⇒ if the operator is
  down, governed pods do not admit.

### Signed-image gating (cosign, default OFF)

`imagePolicy.enabled=true` admits a governed pod only if its images carry a
cosign signature from your Tex-trusted identity (`imagePolicy.engine`:
`kyverno` ⇒ a `ClusterPolicy verifyImages`, or `sigstore` ⇒ a
`ClusterImagePolicy`). It is **off by default** because, with no trusted
identity set, it would (correctly) deny every image; the chart fails the render
if you enable it without `imagePolicy.publicKey` **or**
`imagePolicy.keyless.{issuer,subject}`.

> **Honesty.** This is a **new** integration with the sigstore admission stack.
> Tex's existing `src/tex/c2pa/cosign_verifier.py` verifies cosign signatures
> over **C2PA evidence assertions**, *not* OCI image signatures — it does **not**
> do image gating. Signing proves **provenance**, never **behavior**: a signed
> image can still be a malicious agent. Necessary, not sufficient.

### Prove it locally on a real kind cluster

The repo ships a self-contained harness that brings up a local
[kind](https://kind.sigs.k8s.io) cluster with the gVisor (`runsc`) sandbox
runtime baked into the node and installs this chart with the full admission
stack on (injector + VAP + validating webhook + the `gvisor` RuntimeClass):

```bash
make kind-up     # build the gVisor node image, create the cluster, install
                 # cert-manager + Tex (admission on), seed a governed namespace
make kind-test   # the live assertion (below); make kind-down to tear it all down
```

`make kind-test` then, against the **real kube-apiserver**:

1. applies a **non-compliant** pod (no sandbox `runtimeClassName`, not injected)
   and asserts the apiserver **denies** it — e.g. the actual message returned is

   > `ValidatingAdmissionPolicy 'tex-born-in-a-box' ... denied request: Tex
   > admission denied: pod must declare an approved sandbox runtimeClassName
   > (gVisor/Kata/Confidential Containers) to be admitted into the box`;
2. applies a **compliant** pod and asserts it is **admitted because the injector
   ran** (`tex.systems/injected=true` and the `tex-proxy` sidecar are present on
   the persisted pod — not hand-written); and
3. runs a pod under `runtimeClassName: gvisor` and asserts it is **really
   sandboxed** (`/proc/version` reports `gvisor`, containerd handler `runsc`).

Two harness-only notes the scripts make explicit: the operator image must carry
the `kubernetes` client for the namespace watch (`operator.installKubernetesClient`
self-bootstraps it without an image rebuild), and the injected egress-redirect
init uses `iptables -m owner`, which gVisor's userspace netstack does not
implement — so under gVisor the redirect must run via the eBPF node floor, not
the in-pod init. Admission (deny/admit) is unaffected; only the in-pod redirect
path is gVisor-incompatible.

### The honest boundary (necessary, not sufficient)

Admission only sees what flows through the kube-apiserver. **Static pods**
(kubelet reads from disk), **direct CRI/containerd**, or a **compromised
kubelet** bypass admission entirely. The **eBPF node floor**
(`kernelFloor.enabled=true`, below) redirects their egress *regardless of how
the workload was placed*, so bypass traffic still hits the PEP — run it
alongside admission for defense-in-depth. The **genuine** root — DICE/TPM
measured boot + SPIRE/Keylime node attestation + Confidential Containers — is
**research / RUNTIME-DEPENDENT** (Tex's attestation is verifier-only today). The
first slice closes the common doors and redirects bypass traffic; a node-level
adversary is closed only by the not-yet-running node-root.

## Two enrollment modes

- **Sidecar injection** (`sidecarInjection.enabled=true`, default): portable,
  no node privileges. The webhook injects the proxy + an egress-redirect init
  container into governed-namespace pods.
- **Kernel floor** (`kernelFloor.enabled=true`): sidecarless. One eBPF
  DaemonSet per node governs every workload incl. brand-new ones, with no
  injection. Requires privileged nodes. Both read the same enrollment scope.

## What gets installed

PDP `Deployment`+`Service` (Tex) · operator `Deployment`+`Service` (enrollment
controller + webhook) · `MutatingWebhookConfiguration` (inject) scoped to
governed namespaces · `ValidatingAdmissionPolicy`+`Binding` (the deny half,
default on) · optional `ValidatingWebhookConfiguration` (deny via `/validate`) ·
optional cosign image policy (`ClusterPolicy`/`ClusterImagePolicy`) · RBAC (watch
namespaces/pods) · cert-manager `Issuer`+`Certificate` for the webhook ·
optional kernel-floor `DaemonSet` (also the apiserver-bypass floor) · optional
API-key `Secret`.

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
