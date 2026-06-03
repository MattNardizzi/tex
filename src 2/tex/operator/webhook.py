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
    "injection_patch",
    "build_admission_response",
    "build_webhook_app",
]

INJECTED_ANNOTATION = "tex.systems/injected"
PROXY_CONTAINER_NAME = "tex-proxy"
INIT_CONTAINER_NAME = "tex-init"


@dataclass(frozen=True, slots=True)
class InjectorConfig:
    proxy_image: str = "ghcr.io/vortexblack/tex:latest"
    init_image: str = "ghcr.io/vortexblack/tex-init:latest"
    proxy_port: int = 8088
    pdp_base: str = "http://tex.tex-system.svc.cluster.local:8080"
    pdp_secret_name: str = "tex-pep-secret"
    environment: str = "production"


def should_inject(namespace_governed: bool, pod_metadata: dict[str, Any]) -> bool:
    """Inject iff the namespace is governed, the pod hasn't opted out, and it
    isn't already injected."""
    if not namespace_governed:
        return False
    md = pod_metadata or {}
    labels = md.get("labels") or {}
    if str(labels.get(EXCLUDE_LABEL, "")).strip().casefold() in ("true", "1", "yes"):
        return False
    annotations = md.get("annotations") or {}
    if str(annotations.get(INJECTED_ANNOTATION, "")).strip().casefold() == "true":
        return False
    return True


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


def build_admission_response(
    review: dict[str, Any], scope: EnrollmentScope, cfg: InjectorConfig
) -> dict[str, Any]:
    """Given an AdmissionReview request dict, return the AdmissionReview
    response dict (always allowed; patched when injection applies)."""
    req = review.get("request", {}) or {}
    uid = req.get("uid", "")
    namespace = req.get("namespace", "") or ""
    pod = req.get("object", {}) or {}
    pod_meta = pod.get("metadata", {}) or {}

    response: dict[str, Any] = {"uid": uid, "allowed": True}

    governed = scope.is_governed(namespace)
    if (
        should_inject(governed, pod_meta)
        and not _already_has_proxy(pod.get("spec", {}) or {})
    ):
        tenant = scope.tenant_for(namespace) or namespace
        patch = injection_patch(pod, tenant, cfg)
        encoded = base64.b64encode(json.dumps(patch).encode("utf-8")).decode("ascii")
        response["patchType"] = "JSONPatch"
        response["patch"] = encoded

    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


def _escape(key: str) -> str:
    # JSONPatch path escaping (RFC 6901): ~ -> ~0, / -> ~1.
    return key.replace("~", "~0").replace("/", "~1")


def build_webhook_app(scope: EnrollmentScope, cfg: InjectorConfig | None = None):
    """Starlette app exposing POST /mutate and GET /healthz."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route

    config = cfg or InjectorConfig()

    async def mutate(request: Request) -> JSONResponse:
        try:
            review = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(
                {
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {"uid": "", "allowed": True},
                }
            )
        return JSONResponse(build_admission_response(review, scope, config))

    async def healthz(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return Starlette(
        routes=[
            Route("/mutate", mutate, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ]
    )
