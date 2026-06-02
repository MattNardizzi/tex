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
