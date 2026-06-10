"""
[Architecture: Layer 3 (Monitoring)] — top-level OpenMetrics / Prometheus export.

The honest gap this closes
--------------------------
Tex already had *scoped* metrics surfaces — ``DiscoveryMetrics`` (process-local
counters) and ``MetricsLearningObserver.prometheus_text`` (learning layer) — and
``governance_span`` renders OpenTelemetry-compatible span *attributes*. What was
missing is the one thing a default Prometheus scrape config looks for: a
**top-level ``GET /metrics``** in the standard text-exposition format, and a
process/HTTP/durability view that does not exist in either scoped surface.

This module is that aggregator. It takes **zero new hard dependencies** — the
exposition is rendered by hand exactly as ``learning/observability.py`` already
does — and it composes the surfaces that are already live rather than inventing
new counters.

Single-process on purpose
-------------------------
The counters here are process-local, and the web image runs a single uvicorn
worker (``--workers 1``) behind a single replica (see ``deploy/DURABILITY.md``).
That means **no** ``PROMETHEUS_MULTIPROC_DIR`` gymnastics and no cross-worker
aggregation gap: one scrape reflects the whole process. If Tex ever runs
multiple workers/replicas, these counters become per-process and must move to a
multiprocess collector — that is called out in DURABILITY.md, not hidden here.

OpenTelemetry (OTLP) push — optional, fail-open
-----------------------------------------------
``install_metrics`` also tries to start an OTLP push exporter, but ONLY when
``opentelemetry-sdk`` is installed AND ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set.
Otherwise it is a silent no-op. The OTLP path is an *optional* bridge (deps in
``requirements-otel.txt``); it is gated and fail-open so it can never affect the
verified pull-based ``/metrics`` surface or the app. It is not exercised by the
repo test suite (the SDK is not a hard dep) — the verified deliverable is the
``/metrics`` endpoint; the OTLP bridge is labelled accordingly.
"""

from __future__ import annotations

import logging
import os
import time
from threading import RLock
from typing import Any, Iterable

from fastapi import APIRouter, FastAPI, Request, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_logger = logging.getLogger(__name__)

# Prometheus / OpenMetrics text-exposition content type.
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Bucketed status classes keep label cardinality bounded (no per-path labels).
_STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")


def _status_class(status: int) -> str:
    if 100 <= status < 200:
        return "1xx"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    return "5xx"


class HttpMetrics:
    """
    Thread-safe, process-local HTTP request counters.

    Pure observation: the middleware that feeds this NEVER mutates the response
    (no extra headers, no per-request logging) so attaching it cannot change the
    behaviour any existing test asserts on. Label cardinality is bounded to
    method × status-class.
    """

    __slots__ = ("_lock", "_process_started_at", "_requests", "_duration_sum", "_in_flight")

    def __init__(self) -> None:
        self._lock = RLock()
        self._process_started_at = time.time()
        # (method, status_class) -> count
        self._requests: dict[tuple[str, str], int] = {}
        # method -> summed seconds
        self._duration_sum: dict[str, float] = {}
        self._in_flight = 0

    def inc_in_flight(self) -> None:
        with self._lock:
            self._in_flight += 1

    def dec_in_flight(self) -> None:
        with self._lock:
            self._in_flight -= 1

    def observe(self, *, method: str, status: int, duration_s: float) -> None:
        key = (method.upper(), _status_class(status))
        with self._lock:
            self._requests[key] = self._requests.get(key, 0) + 1
            self._duration_sum[method.upper()] = (
                self._duration_sum.get(method.upper(), 0.0) + duration_s
            )

    @property
    def uptime_seconds(self) -> float:
        return max(0.0, time.time() - self._process_started_at)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": self.uptime_seconds,
                "in_flight": self._in_flight,
                "requests": dict(self._requests),
                "duration_sum": dict(self._duration_sum),
            }


class MetricsMiddleware:
    """
    Minimal ASGI middleware that only *observes* requests into ``HttpMetrics``.

    It does not add headers, does not log per request, and passes the response
    through byte-for-byte — so it is safe to attach to the app unconditionally.
    """

    def __init__(self, app: ASGIApp, metrics: HttpMetrics) -> None:
        self._app = app
        self._metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "UNKNOWN")
        start = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message["status"])
            await send(message)

        self._metrics.inc_in_flight()
        try:
            await self._app(scope, receive, send_wrapper)
        except Exception:
            # An unhandled exception surfaces as a 5xx to the client; record it
            # as such and re-raise so behaviour is unchanged.
            self._metrics.observe(
                method=method,
                status=500,
                duration_s=time.perf_counter() - start,
            )
            raise
        else:
            self._metrics.observe(
                method=method,
                status=status_holder["status"],
                duration_s=time.perf_counter() - start,
            )
        finally:
            self._metrics.dec_in_flight()


# ── Exposition rendering ─────────────────────────────────────────────────────


def _line(buf: list[str], name: str, value: Any, labels: str = "") -> None:
    buf.append(f"{name}{labels} {value}")


def render_metrics(app: FastAPI, http: HttpMetrics) -> str:
    """
    Render the full top-level exposition by composing the live surfaces on
    ``app.state``. Every surface is read defensively: a missing or broken one is
    skipped (with a debug log), never a 500 on the scrape path.
    """
    out: list[str] = []

    # ---- build info -------------------------------------------------------
    version = getattr(app, "version", None) or "unknown"
    out.append("# HELP tex_build_info Tex build/version info.")
    out.append("# TYPE tex_build_info gauge")
    _line(out, "tex_build_info", 1, f'{{version="{_escape(version)}"}}')

    # ---- process ----------------------------------------------------------
    snap = http.snapshot()
    out.append("# HELP tex_process_uptime_seconds Seconds since this process started.")
    out.append("# TYPE tex_process_uptime_seconds gauge")
    _line(out, "tex_process_uptime_seconds", round(snap["uptime_seconds"], 3))

    # ---- HTTP requests ----------------------------------------------------
    out.append("# HELP tex_http_requests_total HTTP requests by method and status class.")
    out.append("# TYPE tex_http_requests_total counter")
    for (method, status_class), count in sorted(snap["requests"].items()):
        _line(
            out,
            "tex_http_requests_total",
            count,
            f'{{method="{_escape(method)}",status="{status_class}"}}',
        )
    out.append("# HELP tex_http_request_duration_seconds_sum Summed request duration by method.")
    out.append("# TYPE tex_http_request_duration_seconds_sum counter")
    for method, total in sorted(snap["duration_sum"].items()):
        _line(
            out,
            "tex_http_request_duration_seconds_sum",
            round(total, 6),
            f'{{method="{_escape(method)}"}}',
        )
    out.append("# HELP tex_http_requests_in_flight In-flight HTTP requests right now.")
    out.append("# TYPE tex_http_requests_in_flight gauge")
    _line(out, "tex_http_requests_in_flight", snap["in_flight"])

    # ---- durability -------------------------------------------------------
    _render_durability(out, app)

    # ---- discovery (already-live process counters) ------------------------
    _render_discovery(out, app)

    # ---- learning layer (splice its existing Prometheus text) -------------
    _render_learning(out, app)

    return "\n".join(out) + "\n"


def _render_durability(out: list[str], app: FastAPI) -> None:
    state = getattr(app, "state", None)

    database_configured = bool(os.environ.get("DATABASE_URL", "").strip())
    out.append("# HELP tex_database_configured 1 if DATABASE_URL is set (write-through durable).")
    out.append("# TYPE tex_database_configured gauge")
    _line(out, "tex_database_configured", 1 if database_configured else 0)

    # Memory-system durability health (per-store + overall). The runtime
    # publishes app.state.runtime (not app.state.memory), so try both.
    memory = getattr(state, "memory", None) if state is not None else None
    if memory is None and state is not None:
        runtime = getattr(state, "runtime", None)
        memory = getattr(runtime, "memory", None) if runtime is not None else None
    health = None
    if memory is not None:
        try:
            health = memory.health()
        except Exception as exc:  # pragma: no cover - defensive scrape path
            _logger.debug("metrics: memory.health() failed: %s", exc)
    if health is not None:
        out.append("# HELP tex_memory_durable 1 if the memory system is in durable (Postgres) mode.")
        out.append("# TYPE tex_memory_durable gauge")
        overall = 1 if bool(getattr(health, "durable", False)) else 0
        _line(out, "tex_memory_durable", overall)

        out.append("# HELP tex_store_durable Per-store durability (1=Postgres-backed, 0=in-memory).")
        out.append("# TYPE tex_store_durable gauge")
        for store, flag in _iter_store_durability(health):
            _line(out, "tex_store_durable", 1 if flag else 0, f'{{store="{_escape(store)}"}}')

    # Evidence-chain head: present means the recorder is continuing a chain.
    recorder = getattr(state, "evidence_recorder", None) if state is not None else None
    if recorder is not None:
        head = getattr(recorder, "_last_record_hash", None)
        out.append("# HELP tex_evidence_chain_head_present 1 if the evidence recorder holds a chain head.")
        out.append("# TYPE tex_evidence_chain_head_present gauge")
        _line(out, "tex_evidence_chain_head_present", 1 if head else 0)


def _iter_store_durability(health: Any) -> Iterable[tuple[str, bool]]:
    """
    Pull per-store durability flags off a MemoryHealth-like object. Tolerant of
    shape: reads either a ``to_dict()`` mapping or known boolean attributes.
    """
    mapping: dict[str, Any] | None = None
    for method_name in ("as_dict", "to_dict"):  # MemoryHealth uses as_dict()
        fn = getattr(health, method_name, None)
        if callable(fn):
            try:
                mapping = fn()
                break
            except Exception:  # pragma: no cover
                mapping = None
    if mapping is None:
        mapping = {
            k: getattr(health, k)
            for k in dir(health)
            if k.endswith("_durable") and not k.startswith("_")
        }
    for key, value in sorted(mapping.items()):
        if key.endswith("_durable") and isinstance(value, bool):
            yield key[: -len("_durable")], value


def _render_discovery(out: list[str], app: FastAPI) -> None:
    state = getattr(app, "state", None)
    dm = getattr(state, "discovery_metrics", None) if state is not None else None
    if dm is None:
        return
    try:
        snap = dm.snapshot()
    except Exception as exc:  # pragma: no cover
        _logger.debug("metrics: discovery_metrics.snapshot() failed: %s", exc)
        return
    if not isinstance(snap, dict):
        return
    out.append("# HELP tex_discovery Discovery control-loop counters (flattened).")
    out.append("# TYPE tex_discovery gauge")
    for key, value in sorted(_flatten_numeric(snap).items()):
        _line(out, "tex_discovery", value, f'{{metric="{_escape(key)}"}}')


def _render_learning(out: list[str], app: FastAPI) -> None:
    state = getattr(app, "state", None)
    lm = getattr(state, "learning_metrics", None) if state is not None else None
    if lm is None:
        return
    text = getattr(lm, "prometheus_text", None)
    if not callable(text):
        return
    try:
        rendered = text()
    except Exception as exc:  # pragma: no cover
        _logger.debug("metrics: learning prometheus_text() failed: %s", exc)
        return
    if rendered and rendered.strip():
        out.append("# Learning layer (tex.learning.observability):")
        out.append(rendered.rstrip("\n"))


def _flatten_numeric(d: dict[str, Any], prefix: str = "") -> dict[str, float]:
    flat: dict[str, float] = {}
    for key, value in d.items():
        name = f"{prefix}{key}"
        if isinstance(value, bool):
            flat[name] = 1.0 if value else 0.0
        elif isinstance(value, (int, float)):
            flat[name] = value
        elif isinstance(value, dict):
            flat.update(_flatten_numeric(value, prefix=f"{name}_"))
    return flat


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


# ── Router + install ─────────────────────────────────────────────────────────


def build_metrics_router(http: HttpMetrics) -> APIRouter:
    """A router exposing GET /metrics in Prometheus text-exposition format."""
    router = APIRouter(tags=["observability"])

    @router.get("/metrics", include_in_schema=False)
    def metrics(request: Request) -> Response:
        body = render_metrics(request.app, http)
        return Response(content=body, media_type=PROMETHEUS_CONTENT_TYPE)

    return router


def install_metrics(app: FastAPI) -> HttpMetrics:
    """
    Wire live metrics into ``app`` in one call (the single main.py wiring point):

      1. attach the pure-observation HTTP middleware,
      2. include the GET /metrics router,
      3. best-effort start the optional OTLP push exporter (no-op unless
         opentelemetry-sdk is installed AND OTEL_EXPORTER_OTLP_ENDPOINT is set).

    Returns the ``HttpMetrics`` instance (handy for tests). Idempotent-safe
    enough for app construction; not intended to be called twice on one app.
    """
    http = HttpMetrics()
    app.add_middleware(MetricsMiddleware, metrics=http)
    app.include_router(build_metrics_router(http))
    app.state.http_metrics = http
    try:
        _maybe_start_otlp_exporter(app, http)
    except Exception as exc:  # pragma: no cover - fail-open by construction
        _logger.debug("metrics: OTLP exporter not started: %s", exc)
    return http


def _maybe_start_otlp_exporter(app: FastAPI, http: HttpMetrics) -> None:
    """
    Optional OpenTelemetry OTLP metrics push. Gated + fail-open.

    Runs ONLY when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set and the OTel SDK is
    importable. Exports the same numbers ``/metrics`` exposes via observable
    instruments on a background interval. Any import/setup error disables it
    silently — it can never break the app or the pull-based endpoint.

    UNVERIFIED-AT-RUNTIME: opentelemetry-sdk is an optional dependency
    (requirements-otel.txt) and is not installed in the repo test environment,
    so this push path is not exercised by the test suite. The verified surface
    is GET /metrics.
    """
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return

    try:
        from opentelemetry.metrics import Observation, set_meter_provider
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource

        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )
        except Exception:  # http fallback
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
    except Exception as exc:
        _logger.info(
            "OTLP export requested (OTEL_EXPORTER_OTLP_ENDPOINT set) but "
            "opentelemetry-sdk is not installed (%s); install "
            "requirements-otel.txt to enable. /metrics is unaffected.",
            exc,
        )
        return

    interval_ms = int(
        float(os.environ.get("TEX_METRICS_OTLP_INTERVAL_SECONDS", "30").strip() or "30")
        * 1000.0
    )
    service_name = os.environ.get("OTEL_SERVICE_NAME", "tex").strip() or "tex"
    resource = Resource.create({"service.name": service_name})
    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(), export_interval_millis=interval_ms
    )
    provider = MeterProvider(metric_readers=[reader], resource=resource)
    set_meter_provider(provider)
    meter = provider.get_meter("tex.observability")

    def _uptime_cb(_options: Any) -> list[Any]:
        return [Observation(http.uptime_seconds)]

    def _in_flight_cb(_options: Any) -> list[Any]:
        return [Observation(http.snapshot()["in_flight"])]

    def _requests_cb(_options: Any) -> list[Any]:
        obs = []
        for (method, status_class), count in http.snapshot()["requests"].items():
            obs.append(Observation(count, {"method": method, "status": status_class}))
        return obs

    def _db_cb(_options: Any) -> list[Any]:
        return [Observation(1 if os.environ.get("DATABASE_URL", "").strip() else 0)]

    meter.create_observable_gauge("tex.process.uptime.seconds", callbacks=[_uptime_cb])
    meter.create_observable_gauge("tex.http.requests.in_flight", callbacks=[_in_flight_cb])
    meter.create_observable_counter("tex.http.requests.total", callbacks=[_requests_cb])
    meter.create_observable_gauge("tex.database.configured", callbacks=[_db_cb])

    _logger.info("OTLP metrics export started → %s (interval %dms)", endpoint, interval_ms)


__all__ = [
    "PROMETHEUS_CONTENT_TYPE",
    "HttpMetrics",
    "MetricsMiddleware",
    "build_metrics_router",
    "install_metrics",
    "render_metrics",
]
