"""
tex.operator — auto-deploy and auto-enroll for the PEP, the ambient way.

The PDP decides; the PEP enforces. This package removes the last manual step:
making the PEP cover workloads automatically. Following the ambient/ztunnel
model, governance is turned on per namespace with a single label —

    tex.systems/govern=enabled

— and from then on every workload in that namespace is governed with no
per-pod action, no sidecar to hand-write, no restart of existing patterns.

Three parts:

  * EnrollmentScope  — the live source of truth for what is governed
    (which namespaces, mapped to which tenant). Maintained by the controller,
    read by the webhook and published to the node agents.

  * EnrollmentController — watches namespaces and reconciles the scope from
    the label. Framework-agnostic core (testable without a cluster) + a thin
    Kubernetes watch driver.

  * SidecarInjector (webhook) — a MutatingAdmissionWebhook that injects the
    Tex enforcement proxy into every new pod in an enrolled namespace, at
    creation time, by the API server. This is the per-pod auto-enrollment that
    needs no node privileges; the eBPF node DaemonSet (pep/kernel) is the
    sidecarless alternative and reads the same scope.

The one-time, declarative install (operator + DaemonSet + webhook + RBAC) is
the Helm chart under deploy/helm/tex. After that: label a namespace, and
enrollment is automatic for every node, pod, and new cluster.
"""

GOVERN_LABEL = "tex.systems/govern"
GOVERN_ENABLED = "enabled"
TENANT_LABEL = "tex.systems/tenant"
# Pods/namespaces carrying this opt OUT even inside an enrolled namespace.
EXCLUDE_LABEL = "tex.systems/govern-exclude"

__all__ = [
    "GOVERN_LABEL",
    "GOVERN_ENABLED",
    "TENANT_LABEL",
    "EXCLUDE_LABEL",
]
