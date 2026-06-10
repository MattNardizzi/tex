"""
Durable-track guards + metrics units.

Two jobs:

1. **Single-writer regression guards.** Tex's authoritative evidence record is a
   per-process, file-backed hash chain (evidence/recorder.py:78). Running more
   than one writer forks the chain. These tests fail if a well-meaning edit
   silently reintroduces a second writer (replicas>1, workers>1, a multi-instance
   Render web service) or drops the persistence that keeps the chain alive across
   restarts. See deploy/DURABILITY.md.

2. **Metrics export units.** Prove the top-level /metrics surface renders and the
   observation middleware counts, without standing up the full runtime.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.observability.metrics import (
    PROMETHEUS_CONTENT_TYPE,
    HttpMetrics,
    install_metrics,
    render_metrics,
)

ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────── single-writer guards ───────────────────────────


def _values() -> dict:
    return yaml.safe_load((ROOT / "deploy/helm/tex/values.yaml").read_text())


def test_helm_replicas_is_one() -> None:
    assert _values()["pdp"]["replicas"] == 1, (
        "pdp.replicas must stay 1: the evidence hash-chain is a single-writer "
        "file (deploy/DURABILITY.md). Raising it forks the chain."
    )


def test_dockerfile_single_worker() -> None:
    df = (ROOT / "Dockerfile").read_text()
    assert "--workers 1" in df, "the web image must run a single uvicorn worker"


def test_render_web_is_single_instance() -> None:
    spec = yaml.safe_load((ROOT / "render.yaml").read_text())
    web = next(s for s in spec["services"] if s.get("name") == "tex-web")
    assert web["numInstances"] == 1
    # The disk pins a single instance AND must cover both evidence/ and keys/.
    assert web["disk"]["mountPath"] == "/app/var/tex"


def test_helm_pdp_has_recreate_pvc_and_parent_mount() -> None:
    txt = (ROOT / "deploy/helm/tex/templates/pdp.yaml").read_text()
    assert "Recreate" in txt, "RWO evidence volume needs strategy: Recreate"
    assert "PersistentVolumeClaim" in txt and "ReadWriteOnce" in txt
    assert _values()["pdp"]["persistence"]["mountPath"] == "/app/var/tex", (
        "mount the parent var/tex so the chain AND the seal key both persist"
    )


def test_helm_sets_app_env_not_the_noop_tex_env() -> None:
    # The app reads TEX_APP_ENV (config.py); the old chart declared TEX_ENV,
    # which nothing reads, so it silently ran development mode.
    txt = (ROOT / "deploy/helm/tex/templates/pdp.yaml").read_text()
    assert re.search(r"name:\s*TEX_APP_ENV\b", txt), "must declare TEX_APP_ENV"
    assert not re.search(r"name:\s*TEX_ENV\b", txt), (
        "TEX_ENV is a no-op the app never reads; do not declare it as an env var"
    )


# ─────────────────────────────── metrics units ──────────────────────────────


def test_http_metrics_observe_counts_by_method_and_status_class() -> None:
    m = HttpMetrics()
    m.observe(method="get", status=200, duration_s=0.01)
    m.observe(method="GET", status=404, duration_s=0.02)
    m.observe(method="POST", status=503, duration_s=0.05)
    snap = m.snapshot()
    assert snap["requests"][("GET", "2xx")] == 1
    assert snap["requests"][("GET", "4xx")] == 1
    assert snap["requests"][("POST", "5xx")] == 1
    assert snap["duration_sum"]["GET"] == pytest.approx(0.03)


def test_render_metrics_against_minimal_app() -> None:
    app = FastAPI(version="9.9.9")
    m = HttpMetrics()
    m.observe(method="POST", status=500, duration_s=0.1)
    text = render_metrics(app, m)
    assert 'tex_build_info{version="9.9.9"} 1' in text
    assert 'tex_http_requests_total{method="POST",status="5xx"} 1' in text
    # durability gauges always present (0 when DATABASE_URL unset)
    assert "tex_database_configured" in text


def test_metrics_endpoint_is_served_with_prometheus_content_type() -> None:
    app = FastAPI(version="1.2.3")
    install_metrics(app)
    client = TestClient(app)
    client.get("/metrics")  # generate one observed request
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == PROMETHEUS_CONTENT_TYPE
    assert "tex_build_info" in resp.text
    assert "tex_http_requests_total" in resp.text


def test_metrics_middleware_does_not_mutate_response_headers() -> None:
    # The observation middleware must be invisible to clients (no added headers),
    # which is why it is safe to attach unconditionally.
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "1"}

    install_metrics(app)
    resp = TestClient(app).get("/ping")
    assert resp.status_code == 200
    assert "x-request-id" not in resp.headers  # we do NOT inject one


def test_otlp_export_is_noop_when_endpoint_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    app = FastAPI()
    http = install_metrics(app)  # must not raise, must not start an exporter
    assert http is app.state.http_metrics
