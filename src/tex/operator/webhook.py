"""
SidecarInjector — the MutatingAdmissionWebhook that auto-enrolls every new pod.

When a pod is created in a governed namespace (``tex.systems/govern=enabled``),
the API server calls this webhook before the pod is persisted. The webhook
returns a JSONPatch that injects:

  * an init container that redirects the pod's egress to the local proxy
    (iptables, istio-init style), so traffic is transparently intercepted; and
  * the Tex enforcement proxy sidecar, configured with this pod's identity
    (from the downward API) so every request it sees is attributed to the
    right sealed agent and tenant.

No per-pod YAML, no developer action, no restart of the deployment pattern —
label the namespace and new pods are governed from birth. Pods carrying
``tex.systems/govern-exclude`` opt out.

The patch builder is a pure function (testable without a cluster). The
``build_webhook_app`` wrapper handles AdmissionReview parse/encode.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from tex.operator import EXCLUDE_LABEL
from tex.operator.scope import EnrollmentScope

__all__ = [
    "InjectorConfig",
    "should_inject",
    "should_validate",
    "admission_violations",
    "injection_patch",
    "build_admission_response",
    "build_webhook_app",
]

INJECTED_ANNOTATION = "tex.systems/injected"
PROXY_CONTAINER_NAME = "tex-proxy"
INIT_CONTAINER_NAME = "tex-init"

# Pod-spec fields that escape the pod's namespace sandbox; any one set => deny.
HOST_NAMESPACE_FIELDS = ("hostNetwork", "hostPID", "hostIPC")
_CONTAINER_LISTS = ("initContainers", "containers", "ephemeralContainers")
_TRUTHY = ("true", "1", "yes")


@dataclass(frozen=True, slots=True)
class InjectorConfig:
    proxy_image: str = "ghcr.io/vortexblack/tex:latest"
    init_image: str = "ghcr.io/vortexblack/tex-init:latest"
    proxy_port: int = 8088
    pdp_base: str = "http://tex.tex-system.svc.cluster.local:8080"
    pdp_secret_name: str = "tex-pep-secret"
    environment: str = "production"
    # Sandbox runtimes a governed pod may declare to be admitted "into the box".
    # These are the cluster's RuntimeClass handles (operator-configurable). The
    # ValidatingAdmissionPolicy in deploy/helm/tex carries the SAME set so the
    # in-apiserver CEL floor and this webhook agree byte-for-byte. gVisor (runsc)
    # / Kata / Confidential Containers are the production sandbox classes; the
    # *strength* of the isolation is RUNTIME-DEPENDENT on which one runs.
    approved_runtime_classes: tuple[str, ...] = (
        "gvisor",
        "kata",
        "kata-qemu",
        "kata-clh",
        "kata-fc",
        "kata-cc",
    )


def _truthy(value: Any) -> bool:
    """Admission JSON gives real booleans; tolerate string forms defensively."""
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in _TRUTHY


def _opted_out(pod_metadata: dict[str, Any]) -> bool:
    """True if the pod carries the opt-out label in any truthy form."""
    labels = (pod_metadata or {}).get("labels") or {}
    return str(labels.get(EXCLUDE_LABEL, "")).strip().casefold() in _TRUTHY


def should_inject(namespace_governed: bool, pod_metadata: dict[str, Any]) -> bool:
    """Inject iff the namespace is governed, the pod hasn't opted out, and it
    isn't already injected."""
    if not namespace_governed:
        return False
    if _opted_out(pod_metadata):
        return False
    annotations = (pod_metadata or {}).get("annotations") or {}
    if str(annotations.get(INJECTED_ANNOTATION, "")).strip().casefold() == "true":
        return False
    return True


def should_validate(namespace_governed: bool, pod_metadata: dict[str, Any]) -> bool:
    """Validate (and possibly DENY) iff the namespace is governed and the pod
    hasn't opted out. Unlike injection this does NOT skip already-injected pods —
    carrying the injected annotation is exactly what validation requires."""
    return bool(namespace_governed) and not _opted_out(pod_metadata)


def admission_violations(pod: dict[str, Any], cfg: InjectorConfig) -> list[str]:
    """Reasons an in-scope pod cannot be brought into the box. Empty == admit.

    Pure (no I/O) and a 1:1 mirror of the CEL ValidatingAdmissionPolicy shipped
    in deploy/helm/tex, so the in-apiserver floor and this webhook never
    disagree. This runs AFTER the mutating injector in the admission chain, so a
    compliant pod already carries ``INJECTED_ANNOTATION``; its absence means the
    injector did not run (down or bypassed) — which is exactly when we must fail
    closed and deny.
    """
    spec = pod.get("spec", {}) or {}
    meta = pod.get("metadata", {}) or {}
    annotations = meta.get("annotations") or {}
    reasons: list[str] = []

    # 1. an approved sandbox runtimeClassName — the "box" itself.
    rc = str(spec.get("runtimeClassName") or "").strip()
    approved = cfg.approved_runtime_classes
    if rc not in approved:
        seen = repr(rc) if rc else "none"
        reasons.append(
            f"runtimeClassName {seen} is not an approved sandbox; set one of "
            f"{list(approved)} (gVisor/Kata/Confidential Containers)"
        )

    # 2. the injected annotation — proves the Tex PEP injector actually ran.
    if str(annotations.get(INJECTED_ANNOTATION, "")).strip().casefold() != "true":
        reasons.append(
            f"missing {INJECTED_ANNOTATION}=true: the Tex PEP was not injected "
            "(injector down or bypassed) — failing closed"
        )

    # 3. host-namespace escapes break the sandbox before it starts.
    for field in HOST_NAMESPACE_FIELDS:
        if _truthy(spec.get(field)):
            reasons.append(f"spec.{field}=true escapes the pod sandbox")

    # 4. privileged / privilege-escalation in ANY container (incl. injected).
    for kind in _CONTAINER_LISTS:
        for c in spec.get(kind) or []:
            if not isinstance(c, dict):
                continue
            sc = c.get("securityContext") or {}
            name = c.get("name", "?")
            if _truthy(sc.get("privileged")):
                reasons.append(f"container {name!r} requests privileged=true")
            if _truthy(sc.get("allowPrivilegeEscalation")):
                reasons.append(
                    f"container {name!r} requests allowPrivilegeEscalation=true"
                )
    return reasons


def _already_has_proxy(pod_spec: dict[str, Any]) -> bool:
    for c in pod_spec.get("containers", []) or []:
        if isinstance(c, dict) and c.get("name") == PROXY_CONTAINER_NAME:
            return True
    return False


def _proxy_container(tenant: str, cfg: InjectorConfig) -> dict[str, Any]:
    return {
        "name": PROXY_CONTAINER_NAME,
        "image": cfg.proxy_image,
        "command": ["python", "-m", "tex.pep"],
        "env": [
            {"name": "TEX_PDP_MODE", "value": "http"},
            {"name": "TEX_PDP_BASE", "value": cfg.pdp_base},
            {"name": "TEX_PEP_ENV", "value": cfg.environment},
            {"name": "TEX_PEP_PORT", "value": str(cfg.proxy_port)},
            {"name": "TEX_PEP_TENANT", "value": tenant},
            # Identity from the downward API: this pod IS the agent.
            {
                "name": "TEX_AGENT",
                "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
            },
            {
                "name": "TEX_PDP_API_KEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": cfg.pdp_secret_name,
                        "key": "apiKey",
                        "optional": True,
                    }
                },
            },
        ],
        "ports": [{"containerPort": cfg.proxy_port, "name": "tex-proxy"}],
    }


def _init_container(cfg: InjectorConfig) -> dict[str, Any]:
    # Redirect the pod's outbound TCP to the local proxy, except traffic to the
    # proxy itself and to the PDP. istio-init style; needs NET_ADMIN.
    return {
        "name": INIT_CONTAINER_NAME,
        "image": cfg.init_image,
        "securityContext": {"capabilities": {"add": ["NET_ADMIN", "NET_RAW"]}},
        "command": ["/bin/sh", "-c"],
        "args": [
            "iptables -t nat -N TEX_OUT 2>/dev/null || true; "
            "iptables -t nat -A TEX_OUT -d 127.0.0.1/32 -j RETURN; "
            f"iptables -t nat -A TEX_OUT -p tcp -j REDIRECT --to-ports {cfg.proxy_port}; "
            "iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner $(id -u tex 2>/dev/null || echo 1337) -j TEX_OUT"
        ],
    }


def injection_patch(pod: dict[str, Any], tenant: str, cfg: InjectorConfig) -> list[dict[str, Any]]:
    """Build the JSONPatch that injects init + sidecar + the done annotation."""
    spec = pod.get("spec", {}) or {}
    meta = pod.get("metadata", {}) or {}
    ops: list[dict[str, Any]] = []

    # init container (create the array if absent)
    init = _init_container(cfg)
    if spec.get("initContainers"):
        ops.append({"op": "add", "path": "/spec/initContainers/-", "value": init})
    else:
        ops.append({"op": "add", "path": "/spec/initContainers", "value": [init]})

    # sidecar
    ops.append(
        {"op": "add", "path": "/spec/containers/-", "value": _proxy_container(tenant, cfg)}
    )

    # idempotency annotation (create the map if absent)
    if meta.get("annotations"):
        ops.append(
            {
                "op": "add",
                "path": f"/metadata/annotations/{_escape(INJECTED_ANNOTATION)}",
                "value": "true",
            }
        )
    else:
        ops.append(
            {"op": "add", "path": "/metadata/annotations", "value": {INJECTED_ANNOTATION: "true"}}
        )
    return ops


def _review_response(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


def build_admission_response(
    review: dict[str, Any],
    scope: EnrollmentScope,
    cfg: InjectorConfig,
    *,
    mode: str = "mutate",
) -> dict[str, Any]:
    """Given an AdmissionReview request dict, return the AdmissionReview response.

    ``mode="mutate"`` (default) is the existing injector: always ``allowed:
    True``, patched with the PEP sidecar + egress redirect when the pod is in
    scope. ``mode="validate"`` is the deny twin: ``allowed: False`` with a
    ``status.message`` when an in-scope pod cannot be brought into the box (no
    approved sandbox runtimeClass, not injected, or a host escape). Pods out of
    scope (ungoverned namespace or opted out) are allowed — this policy is silent
    on them.
    """
    if mode not in ("mutate", "validate"):
        raise ValueError(f"unknown admission mode {mode!r}")

    req = review.get("request", {}) or {}
    uid = req.get("uid", "")
    namespace = req.get("namespace", "") or ""
    pod = req.get("object", {}) or {}
    pod_meta = pod.get("metadata", {}) or {}
    governed = scope.is_governed(namespace)

    if mode == "validate":
        if not should_validate(governed, pod_meta):
            return _review_response({"uid": uid, "allowed": True})
        reasons = admission_violations(pod, cfg)
        if not reasons:
            return _review_response({"uid": uid, "allowed": True})
        return _review_response(
            {
                "uid": uid,
                "allowed": False,
                "status": {
                    "code": 403,
                    "message": "Tex admission denied (born-in-a-box): "
                    + "; ".join(reasons),
                },
            }
        )

    # mode == "mutate" — unchanged inject-only behavior.
    response: dict[str, Any] = {"uid": uid, "allowed": True}
    if should_inject(governed, pod_meta) and not _already_has_proxy(
        pod.get("spec", {}) or {}
    ):
        tenant = scope.tenant_for(namespace) or namespace
        patch = injection_patch(pod, tenant, cfg)
        encoded = base64.b64encode(json.dumps(patch).encode("utf-8")).decode("ascii")
        response["patchType"] = "JSONPatch"
        response["patch"] = encoded
    return _review_response(response)


def _escape(key: str) -> str:
    # JSONPatch path escaping (RFC 6901): ~ -> ~0, / -> ~1.
    return key.replace("~", "~0").replace("/", "~1")


def build_webhook_app(scope: EnrollmentScope, cfg: InjectorConfig | None = None):
    """Starlette app exposing POST /mutate, POST /validate and GET /healthz."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route

    config = cfg or InjectorConfig()

    async def mutate(request: Request) -> JSONResponse:
        try:
            review = await request.json()
        except Exception:  # noqa: BLE001
            # The mutating webhook is failurePolicy: Ignore — a bad body must
            # never block pod creation; just inject nothing.
            return JSONResponse(_review_response({"uid": "", "allowed": True}))
        return JSONResponse(build_admission_response(review, scope, config))

    async def validate(request: Request) -> JSONResponse:
        try:
            review = await request.json()
        except Exception:  # noqa: BLE001
            # The validating webhook is failurePolicy: Fail — an unparseable
            # body must DENY (fail closed), not slip through.
            return JSONResponse(
                _review_response(
                    {
                        "uid": "",
                        "allowed": False,
                        "status": {
                            "code": 400,
                            "message": "Tex admission: unparseable AdmissionReview",
                        },
                    }
                )
            )
        return JSONResponse(
            build_admission_response(review, scope, config, mode="validate")
        )

    async def healthz(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return Starlette(
        routes=[
            Route("/mutate", mutate, methods=["POST"]),
            Route("/validate", validate, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ]
    )
