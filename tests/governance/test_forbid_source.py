"""
Tests for the forbid-set source and the wired /v1/govern/forbid-set route.

The route is the contract the Go kernel loader (pep/kernel/agent/main.go,
fetchForbidSet) depends on:

    { "forbid": [ { "ip": "1.2.3.4", "port": 443 }, ... ] }

These tests prove:
  * a populated, correctly-shaped response from a sample source,
  * IPv4-only emission (the loader is IPv4-only) with host resolution,
  * a safe EMPTY set when no source is configured (fail-closed; never
    fail-open-to-allow),
  * per-tenant scoping, dedup, and fail-closed handling of bad/unresolvable
    entries.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.governance.forbid_source import (
    ForbidEntry,
    ForbidSource,
    resolve_forbid_source,
)


# --------------------------------------------------------------------------
# A deterministic resolver so tests never touch the network. It mimics
# socket.getaddrinfo's mixed-family output (v4 + v6 strings).
# --------------------------------------------------------------------------

_DNS: dict[str, list[str]] = {
    "evil.example.com": ["203.0.113.7", "203.0.113.8", "2001:db8::dead"],
    "exfil.test": ["198.51.100.42"],
    "v6only.test": ["2001:db8::beef"],  # no A record -> contributes nothing
}


def _fake_resolver(host: str) -> list[str]:
    if host in _DNS:
        return list(_DNS[host])
    raise OSError(f"unresolvable: {host}")


# --------------------------------------------------------------------------
# ForbidSource unit behavior
# --------------------------------------------------------------------------


def test_resolves_host_to_ipv4_only_and_shapes_entries() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    src.add("evil.example.com", 443)

    entries = src.for_tenant("acme")

    # The v6 address from DNS is dropped (loader is IPv4-only); both A records
    # are emitted at the configured port, in the contract's exact shape.
    assert entries == [
        {"ip": "203.0.113.7", "port": 443},
        {"ip": "203.0.113.8", "port": 443},
    ]
    for e in entries:
        assert set(e.keys()) == {"ip", "port"}
        assert isinstance(e["ip"], str) and isinstance(e["port"], int)


def test_ip_literal_passes_through_without_resolution() -> None:
    # A literal IPv4 must not hit the resolver at all.
    def _boom(host: str) -> list[str]:  # pragma: no cover - must not be called
        raise AssertionError("resolver called for an IP literal")

    src = ForbidSource(resolver=_boom)
    src.add("1.2.3.4", 8080)
    assert src.for_tenant("acme") == [{"ip": "1.2.3.4", "port": 8080}]


def test_ipv6_literal_is_dropped_loader_is_ipv4_only() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    src.add("2001:db8::1", 443)
    src.add("v6only.test", 443)  # resolves only to v6
    assert src.for_tenant("acme") == []


def test_unresolvable_host_is_failclosed_dropped_not_allowed() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    src.add("does-not-resolve.invalid", 443)
    src.add("exfil.test", 25)
    # The unresolvable host contributes nothing (decided at the proxy); the
    # resolvable one is still emitted. A drop is never a permit.
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 25}]


def test_invalid_port_is_rejected() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    assert src.add("1.2.3.4", 0) is False
    assert src.add("1.2.3.4", 70000) is False
    assert src.add("1.2.3.4", -1) is False
    assert len(src) == 0
    assert src.for_tenant("acme") == []


def test_dedup_by_ip_and_port() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    src.add("exfil.test", 443)
    src.add("198.51.100.42", 443)  # same (ip, port) by a different name
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 443}]


def test_tenant_scoping() -> None:
    src = ForbidSource(
        entries=[
            ForbidEntry(host="exfil.test", port=443, tenant="acme"),
            ForbidEntry(host="evil.example.com", port=443, tenant=None),  # all
        ],
        resolver=_fake_resolver,
    )
    acme = src.for_tenant("acme")
    globex = src.for_tenant("globex")

    # acme sees its own entry + the global one; globex sees only the global.
    assert {"ip": "198.51.100.42", "port": 443} in acme
    assert {"ip": "203.0.113.7", "port": 443} in acme
    assert {"ip": "198.51.100.42", "port": 443} not in globex
    assert {"ip": "203.0.113.7", "port": 443} in globex


def test_empty_source_yields_empty_set() -> None:
    assert ForbidSource(resolver=_fake_resolver).for_tenant("acme") == []


def test_add_host_expands_default_https_port() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    assert src.add_host("exfil.test") == 1
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 443}]


# --------------------------------------------------------------------------
# from_env / resolve_forbid_source
# --------------------------------------------------------------------------


def test_from_env_parses_host_port_tokens() -> None:
    env = {"TEX_FORBID_SET": "evil.example.com:443, exfil.test:25  1.2.3.4:8080"}
    src = ForbidSource.from_env(env, resolver=_fake_resolver)
    entries = src.for_tenant("acme")
    assert {"ip": "1.2.3.4", "port": 8080} in entries
    assert {"ip": "198.51.100.42", "port": 25} in entries
    assert {"ip": "203.0.113.7", "port": 443} in entries


def test_from_env_unset_is_empty() -> None:
    assert ForbidSource.from_env({}, resolver=_fake_resolver).for_tenant("x") == []
    assert (
        ForbidSource.from_env({"TEX_FORBID_SET": "   "}, resolver=_fake_resolver)
        .for_tenant("x")
        == []
    )


def test_from_env_skips_malformed_tokens_failclosed() -> None:
    env = {"TEX_FORBID_SET": "1.2.3.4:99999 :443 garbage:: exfil.test:443"}
    src = ForbidSource.from_env(env, resolver=_fake_resolver)
    # Only the one well-formed, resolvable token survives.
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 443}]


def test_resolve_forbid_source_rejects_wrong_type_failclosed() -> None:
    class _State:
        forbid_source = "not a ForbidSource"

    assert resolve_forbid_source(_State()) is None


def test_resolve_forbid_source_builds_from_env_when_absent(monkeypatch) -> None:
    monkeypatch.delenv("TEX_FORBID_SET", raising=False)

    class _State:
        pass

    state = _State()
    src = resolve_forbid_source(state)
    assert isinstance(src, ForbidSource)
    # Cached back onto state.
    assert state.forbid_source is src
    assert src.for_tenant("acme") == []


# --------------------------------------------------------------------------
# The wired route — the loader's contract
# --------------------------------------------------------------------------


def _client(forbid_source: object | None) -> TestClient:
    """Build a minimal app with the standing router, a stub governance (the
    route requires one attached), and a fixed authenticated principal."""
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    app.state.standing_governance = object()  # non-None precondition
    app.state.forbid_source = forbid_source
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:read"}),
    )
    return TestClient(app)


def test_route_returns_populated_correctly_shaped_set() -> None:
    src = ForbidSource(resolver=_fake_resolver)
    src.add("evil.example.com", 443, tenant="acme")
    src.add("exfil.test", 25)  # all tenants

    resp = _client(src).get("/v1/govern/forbid-set")
    assert resp.status_code == 200
    body = resp.json()

    assert set(body.keys()) == {"forbid", "count"}
    assert body["count"] == len(body["forbid"]) == 3
    for e in body["forbid"]:
        assert set(e.keys()) == {"ip", "port"}
        assert isinstance(e["ip"], str) and isinstance(e["port"], int)
    assert {"ip": "198.51.100.42", "port": 25} in body["forbid"]
    assert {"ip": "203.0.113.7", "port": 443} in body["forbid"]


def test_route_safe_empty_when_no_source_configured(monkeypatch) -> None:
    # Nothing attached and TEX_FORBID_SET unset -> the route resolves to a
    # freshly built, empty source: the safe default. Never fail-open.
    monkeypatch.delenv("TEX_FORBID_SET", raising=False)
    resp = _client(None).get("/v1/govern/forbid-set")
    assert resp.status_code == 200
    assert resp.json() == {"forbid": [], "count": 0}


def test_route_503_when_governance_not_attached() -> None:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    app.state.forbid_source = ForbidSource(resolver=_fake_resolver)
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test", tenant="acme", scopes=frozenset({"decision:read"})
    )
    # standing_governance intentionally not set -> the route's precondition 503s.
    resp = TestClient(app, raise_server_exceptions=False).get("/v1/govern/forbid-set")
    assert resp.status_code == 503
