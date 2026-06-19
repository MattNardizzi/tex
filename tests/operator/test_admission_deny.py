"""
Born-in-a-box admission: the DENY half of the operator webhook.

These tests pin the validating mode added to ``build_admission_response`` — the
twin of the existing injector that *refuses* an in-scope pod which cannot be
brought into the box (no approved sandbox runtimeClass, no injected annotation,
or a host escape). They run against fake ``AdmissionReview`` payloads; the full
in-apiserver behavior needs a cluster.

The load-bearing properties under test:
  * out-of-scope / opted-out pods are NEVER denied (the policy is silent on them);
  * an in-scope non-compliant pod is denied with allowed=False + a status message;
  * the mutating path is byte-for-byte unchanged (no regression);
  * Tex's OWN injected pod (init container with NET_ADMIN/NET_RAW caps + the
    injected annotation + an approved runtimeClass) is ADMITTED — the deny logic
    must not shoot down the very pod the injector produced;
  * fail-closed: a missing injected annotation (injector down) => deny.
"""

from __future__ import annotations

import base64
import json

import pytest

from tex.operator import EXCLUDE_LABEL, GOVERN_LABEL
from tex.operator.scope import EnrollmentScope
from tex.operator.webhook import (
    INJECTED_ANNOTATION,
    InjectorConfig,
    admission_violations,
    build_admission_response,
    should_validate,
)

CFG = InjectorConfig()
GOVERNED_NS = "agents"


def _scope() -> EnrollmentScope:
    s = EnrollmentScope()
    s.set_namespace(GOVERNED_NS, {GOVERN_LABEL: "enabled"})
    return s


def _review(pod: dict, namespace: str = GOVERNED_NS, uid: str = "u1") -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {"uid": uid, "namespace": namespace, "object": pod},
    }


def _pod(
    *,
    runtime_class: str | None = "gvisor",
    injected: bool = True,
    labels: dict | None = None,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    containers: list | None = None,
    init_containers: list | None = None,
) -> dict:
    meta: dict = {"name": "agent-0"}
    if labels:
        meta["labels"] = labels
    if injected:
        meta["annotations"] = {INJECTED_ANNOTATION: "true"}
    spec: dict = {"containers": containers or [{"name": "app", "image": "x"}]}
    if runtime_class is not None:
        spec["runtimeClassName"] = runtime_class
    if host_network:
        spec["hostNetwork"] = True
    if host_pid:
        spec["hostPID"] = True
    if host_ipc:
        spec["hostIPC"] = True
    if init_containers is not None:
        spec["initContainers"] = init_containers
    return {"metadata": meta, "spec": spec}


def _validate(pod: dict, namespace: str = GOVERNED_NS) -> dict:
    return build_admission_response(_review(pod, namespace), _scope(), CFG, mode="validate")


def _resp(review_response: dict) -> dict:
    return review_response["response"]


# ── scope: who the deny policy is silent on ──────────────────────────────────


def test_ungoverned_namespace_is_never_denied():
    # A blatantly non-compliant pod in an ungoverned namespace is still allowed.
    bad = _pod(runtime_class=None, injected=False, host_network=True)
    out = _resp(_validate(bad, namespace="default"))
    assert out["allowed"] is True
    assert "status" not in out


@pytest.mark.parametrize("form", ["true", "True", "YES", "1"])
def test_opted_out_pod_is_never_denied(form):
    # Case-insensitive opt-out (casefold). The VAP must match this via
    # lowerAscii(); a cased value like "True" must opt out in BOTH or the
    # webhook and the in-apiserver policy diverge.
    bad = _pod(runtime_class=None, injected=False, labels={EXCLUDE_LABEL: form})
    out = _resp(_validate(bad))
    assert out["allowed"] is True


@pytest.mark.parametrize("form", ["true", "1", "yes", "TRUE", "Yes"])
def test_opt_out_truthy_forms(form):
    assert should_validate(True, {"labels": {EXCLUDE_LABEL: form}}) is False


# ── the admit case ───────────────────────────────────────────────────────────


def test_compliant_pod_is_admitted():
    out = _resp(_validate(_pod()))
    assert out["allowed"] is True
    assert "status" not in out
    assert out["uid"] == "u1"


@pytest.mark.parametrize("rc", ["gvisor", "kata", "kata-qemu", "kata-clh", "kata-fc", "kata-cc"])
def test_every_approved_runtime_class_admits(rc):
    assert admission_violations(_pod(runtime_class=rc), CFG) == []


# ── the deny cases (one property each) ────────────────────────────────────────


def test_missing_runtime_class_denies():
    out = _resp(_validate(_pod(runtime_class=None)))
    assert out["allowed"] is False
    assert out["status"]["code"] == 403
    assert "runtimeClassName" in out["status"]["message"]


def test_unapproved_runtime_class_denies():
    out = _resp(_validate(_pod(runtime_class="runc")))
    assert out["allowed"] is False
    assert "runc" in out["status"]["message"]


def test_missing_injected_annotation_denies_fail_closed():
    # The injector being down (no annotation) must DENY, not slip through.
    out = _resp(_validate(_pod(injected=False)))
    assert out["allowed"] is False
    assert INJECTED_ANNOTATION in out["status"]["message"]


@pytest.mark.parametrize("field", ["host_network", "host_pid", "host_ipc"])
def test_host_namespace_escape_denies(field):
    out = _resp(_validate(_pod(**{field: True})))
    assert out["allowed"] is False
    assert "escapes the pod sandbox" in out["status"]["message"]


def test_privileged_container_denies():
    pod = _pod(containers=[{"name": "app", "securityContext": {"privileged": True}}])
    out = _resp(_validate(pod))
    assert out["allowed"] is False
    assert "privileged=true" in out["status"]["message"]


def test_allow_privilege_escalation_denies():
    pod = _pod(
        containers=[{"name": "app", "securityContext": {"allowPrivilegeEscalation": True}}]
    )
    out = _resp(_validate(pod))
    assert out["allowed"] is False
    assert "allowPrivilegeEscalation=true" in out["status"]["message"]


def test_privileged_init_container_denies():
    pod = _pod(init_containers=[{"name": "evil-init", "securityContext": {"privileged": True}}])
    out = _resp(_validate(pod))
    assert out["allowed"] is False
    assert "evil-init" in out["status"]["message"]


def test_multiple_violations_are_all_reported():
    bad = _pod(runtime_class=None, injected=False, host_network=True)
    reasons = admission_violations(bad, CFG)
    assert len(reasons) == 3  # runtimeClass + annotation + hostNetwork
    msg = _resp(_validate(bad))["status"]["message"]
    for r in reasons:
        assert r in msg


# ── the critical trap: do NOT deny Tex's OWN injected pod ─────────────────────


def test_injected_pod_with_net_admin_caps_is_admitted():
    """The injector adds an init container that requests NET_ADMIN/NET_RAW to set
    up the iptables egress redirect. The deny logic checks privileged /
    allowPrivilegeEscalation / host escapes — NOT capability adds — so Tex's own
    post-injection pod must pass validation. Regression guard against the obvious
    over-broad escape check that would brick injection."""
    injected_init = {
        "name": "tex-init",
        "image": "ghcr.io/vortexblack/tex-init:latest",
        "securityContext": {"capabilities": {"add": ["NET_ADMIN", "NET_RAW"]}},
    }
    proxy = {"name": "tex-proxy", "image": "ghcr.io/vortexblack/tex:latest"}
    pod = _pod(
        runtime_class="gvisor",
        injected=True,
        containers=[{"name": "app", "image": "x"}, proxy],
        init_containers=[injected_init],
    )
    assert admission_violations(pod, CFG) == []
    assert _resp(_validate(pod))["allowed"] is True


# ── the mutating path is unchanged (no regression) ───────────────────────────


def test_mutate_mode_still_injects_and_allows():
    # A bare compliant-namespace pod (uninjected) in mutate mode → allowed +
    # JSONPatch, exactly as before the deny-half existed.
    pod = {"metadata": {"name": "agent-0"}, "spec": {"containers": [{"name": "app"}]}}
    out = _resp(build_admission_response(_review(pod), _scope(), CFG))
    assert out["allowed"] is True
    assert out["patchType"] == "JSONPatch"
    patch = json.loads(base64.b64decode(out["patch"]))
    # init + sidecar + annotation ops present
    paths = [op["path"] for op in patch]
    assert "/spec/containers/-" in paths


def test_mutate_mode_default_is_mutate():
    pod = {"metadata": {"name": "a"}, "spec": {"containers": [{"name": "c"}]}}
    default = build_admission_response(_review(pod), _scope(), CFG)
    explicit = build_admission_response(_review(pod), _scope(), CFG, mode="mutate")
    assert default == explicit


def test_unknown_mode_raises():
    pod = {"metadata": {"name": "a"}, "spec": {"containers": []}}
    with pytest.raises(ValueError):
        build_admission_response(_review(pod), _scope(), CFG, mode="audit")


# ── string-boolean robustness (real admission JSON is bool; be defensive) ─────


def test_string_true_host_network_denies():
    pod = _pod()
    pod["spec"]["hostNetwork"] = "true"
    assert any("hostNetwork" in r for r in admission_violations(pod, CFG))


def test_false_escapes_do_not_deny():
    pod = _pod(host_network=False, host_pid=False)
    pod["spec"]["hostNetwork"] = False
    pod["spec"]["hostPID"] = False
    assert admission_violations(pod, CFG) == []


# ── the wired Starlette app: /validate route end-to-end ──────────────────────


def _client():
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient

    from tex.operator.webhook import build_webhook_app

    return TestClient(build_webhook_app(_scope(), CFG))


def test_app_validate_denies_noncompliant():
    client = _client()
    r = client.post("/validate", json=_review(_pod(runtime_class=None)))
    assert r.status_code == 200
    body = r.json()["response"]
    assert body["allowed"] is False


def test_app_validate_admits_compliant():
    client = _client()
    r = client.post("/validate", json=_review(_pod()))
    assert r.json()["response"]["allowed"] is True


def test_app_validate_unparseable_body_fails_closed():
    client = _client()
    r = client.post("/validate", content=b"not json")
    assert r.status_code == 200
    assert r.json()["response"]["allowed"] is False


def test_app_mutate_still_allows_compliant_namespace():
    client = _client()
    pod = {"metadata": {"name": "a"}, "spec": {"containers": [{"name": "c"}]}}
    r = client.post("/mutate", json=_review(pod))
    assert r.json()["response"]["allowed"] is True


def test_app_healthz():
    client = _client()
    assert _client_ok(client)


def _client_ok(client) -> bool:
    r = client.get("/healthz")
    return r.status_code == 200 and r.text == "ok"
