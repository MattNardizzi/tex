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

    assert set(body.keys()) == {"forbid", "count", "epoch"}
    assert body["count"] == len(body["forbid"]) == 3
    # epoch is a monotonic version stamp (bumped on every add); two adds above.
    assert isinstance(body["epoch"], int) and body["epoch"] >= 2
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
    assert resp.json() == {"forbid": [], "count": 0, "epoch": 0}


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


# --------------------------------------------------------------------------
# Upgraded store: TTL, dedup/refresh, revoke-wins, bounded LRU, epoch.
# A controllable clock so TTL tests never sleep.
# --------------------------------------------------------------------------


class _Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_ttl_entry_self_prunes_after_expiry() -> None:
    clk = _Clock(1000.0)
    src = ForbidSource(resolver=_fake_resolver, clock=clk, default_ttl_seconds=100.0)
    src.add("exfil.test", 25)  # finite TTL by default
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 25}]
    clk.t = 1000.0 + 101  # past the TTL
    assert src.for_tenant("acme") == []  # self-pruned, never a permit
    assert len(src) == 0


def test_permanent_env_seed_entry_never_expires() -> None:
    clk = _Clock(1000.0)
    src = ForbidSource(resolver=_fake_resolver, clock=clk, default_ttl_seconds=10.0)
    src.add("exfil.test", 25, ttl_seconds=None)  # permanent (env-seed semantics)
    clk.t = 10**9  # far future
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 25}]


def test_readd_refreshes_ttl_and_does_not_duplicate() -> None:
    clk = _Clock(1000.0)
    src = ForbidSource(resolver=_fake_resolver, clock=clk, default_ttl_seconds=100.0)
    src.add("exfil.test", 25)
    clk.t = 1090.0  # 90s in, would expire at 1100
    src.add("exfil.test", 25)  # refresh -> new expiry 1190
    assert len(src) == 1  # refreshed, not duplicated
    clk.t = 1150.0  # past the OLD expiry, before the new one
    assert src.for_tenant("acme") == [{"ip": "198.51.100.42", "port": 25}]


def test_revoke_removes_and_absence_never_does() -> None:
    src = ForbidSource(resolver=_fake_resolver, default_ttl_seconds=None)
    src.add("exfil.test", 25)
    src.add("evil.example.com", 443, tenant="acme")
    assert len(src) == 2
    # revoke-wins: an explicit revoke removes; nothing else does.
    assert src.revoke("exfil.test") == 1
    assert src.for_tenant("acme") == [
        {"ip": "203.0.113.7", "port": 443},
        {"ip": "203.0.113.8", "port": 443},
    ]
    # revoking an absent host is a no-op, never an error.
    assert src.revoke("not-there.test") == 0


def test_revoke_is_tenant_and_port_scoped() -> None:
    src = ForbidSource(resolver=_fake_resolver, default_ttl_seconds=None)
    src.add("exfil.test", 25, tenant="acme")
    src.add("exfil.test", 25, tenant="other")
    # Narrow the revoke to one tenant: the other survives.
    assert src.revoke("exfil.test", tenant="acme") == 1
    assert src.for_tenant("acme") == []
    assert src.for_tenant("other") == [{"ip": "198.51.100.42", "port": 25}]


def test_epoch_is_monotonic_across_mutations() -> None:
    src = ForbidSource(resolver=_fake_resolver, default_ttl_seconds=None)
    e0 = src.epoch
    src.add("exfil.test", 25)
    e1 = src.epoch
    src.revoke("exfil.test")
    e2 = src.epoch
    assert e0 < e1 < e2


def test_bounded_lru_evicts_oldest_ttl_entries_never_permanent() -> None:
    clk = _Clock(1000.0)
    src = ForbidSource(
        resolver=_fake_resolver, clock=clk, default_ttl_seconds=10_000.0, max_entries=2
    )
    src.add("1.1.1.1", 443, ttl_seconds=None)  # permanent seed
    clk.t += 1
    src.add("2.2.2.2", 443)  # ttl'd, oldest auto entry
    clk.t += 1
    src.add("3.3.3.3", 443)  # ttl'd -> pushes over cap (2): evict 2.2.2.2
    ips = {e["ip"] for e in src.for_tenant("acme")}
    assert "1.1.1.1" in ips  # permanent never evicted
    assert "3.3.3.3" in ips  # newest kept
    assert "2.2.2.2" not in ips  # oldest TTL'd evicted


# --------------------------------------------------------------------------
# The network-destination predicate: only egress-shaped FORBIDs feed the set.
# --------------------------------------------------------------------------


def test_predicate_admits_http_actions_rejects_non_network() -> None:
    from tex.governance.forbid_source import network_destination_for_forbid as nd

    assert nd("http_get", "evil.example.com") == "evil.example.com"
    assert nd("http_post", "https://evil.example.com/path") == "evil.example.com"
    assert nd("http_connect", "evil.example.com:8443") == "evil.example.com"
    # Non-network actions can never pollute the destination hot set.
    assert nd("wire_transfer", "acct-99887766") is None
    assert nd("send_email", "ceo@corp.test") is None
    # Opaque/undecodable egress labels are excluded (they are ABSTAIN, not FORBID).
    assert nd("https_opaque", "evil.example.com") is None
    assert nd("http_opaque_body", "evil.example.com") is None
    # Empty / missing recipient or action -> nothing.
    assert nd("http_get", None) is None
    assert nd("", "evil.example.com") is None


def test_feed_from_decision_warms_per_tenant_ttl() -> None:
    src = ForbidSource(resolver=_fake_resolver, default_ttl_seconds=100.0)
    added = src.feed_from_decision(
        action_type="http_get",
        recipient="evil.example.com",
        tenant="acme",
        decision_id="dec-1",
    )
    assert added == 1
    # Scoped to the deciding tenant: present for acme, absent for another tenant.
    assert src.for_tenant("acme") == [
        {"ip": "203.0.113.7", "port": 443},
        {"ip": "203.0.113.8", "port": 443},
    ]
    assert src.for_tenant("other") == []
    # A non-network FORBID feeds nothing.
    assert (
        src.feed_from_decision(action_type="wire_transfer", recipient="acct-1") == 0
    )


# --------------------------------------------------------------------------
# Decision-side wiring: StandingGovernance feeds a destination-attributable
# FORBID, and ONLY that — agent-scoped denials and PERMITs never feed.
# --------------------------------------------------------------------------


def _gov(forbid_sink):
    from tex.governance.standing import StandingGovernance

    # agent_registry is unused on the path we exercise (_maybe_feed_forbid_set),
    # so a bare object suffices.
    return StandingGovernance(agent_registry=object(), forbid_sink=forbid_sink)


def _outcome(scope, *, verdict=None):
    from tex.domain.verdict import Verdict
    from tex.governance.standing import DecisionOutcome

    return DecisionOutcome(
        verdict=verdict or Verdict.FORBID,
        released=False,
        reason="test",
        tier="deep",
        forbid_scope=scope,
    )


def test_decision_feed_fires_for_destination_scoped_forbid() -> None:
    calls: list[dict] = []
    gov = _gov(lambda **kw: calls.append(kw))
    for scope in ("surface", "deep"):
        calls.clear()
        gov._maybe_feed_forbid_set(
            _outcome(scope),
            action_type="http_get",
            recipient="evil.example.com",
            tenant="acme",
        )
        assert len(calls) == 1, scope
        assert calls[0]["recipient"] == "evil.example.com"
        assert calls[0]["tenant"] == "acme"


def test_decision_feed_skips_agent_scoped_and_error_forbids() -> None:
    calls: list[dict] = []
    gov = _gov(lambda **kw: calls.append(kw))
    for scope in ("identity", "lifecycle", "deep_error", "floor", None):
        gov._maybe_feed_forbid_set(
            _outcome(scope),
            action_type="http_get",
            recipient="evil.example.com",
            tenant="acme",
        )
    assert calls == []  # agent-scoped / fail-closed denials never feed the set


def test_decision_feed_skips_permit_and_missing_sink() -> None:
    from tex.domain.verdict import Verdict

    calls: list[dict] = []
    gov = _gov(lambda **kw: calls.append(kw))
    # A PERMIT (even with a recipient) never feeds.
    gov._maybe_feed_forbid_set(
        _outcome("deep", verdict=Verdict.PERMIT),
        action_type="http_get",
        recipient="evil.example.com",
        tenant="acme",
    )
    assert calls == []
    # No sink wired -> no-op, no crash.
    _gov(None)._maybe_feed_forbid_set(
        _outcome("deep"),
        action_type="http_get",
        recipient="evil.example.com",
        tenant="acme",
    )


def test_decision_feed_end_to_end_into_real_source() -> None:
    # Wire a real ForbidSource as the sink: a destination-attributable FORBID
    # makes the hot set serve that destination — closing the live gap.
    src = ForbidSource(resolver=_fake_resolver, default_ttl_seconds=100.0)
    gov = _gov(src.feed_from_decision)
    gov._maybe_feed_forbid_set(
        _outcome("deep"),
        action_type="http_post",
        recipient="evil.example.com",
        tenant="acme",
    )
    assert src.for_tenant("acme") == [
        {"ip": "203.0.113.7", "port": 443},
        {"ip": "203.0.113.8", "port": 443},
    ]


def test_sink_failure_never_breaks_the_ruling() -> None:
    def _boom(**kw):
        raise RuntimeError("sink exploded")

    gov = _gov(_boom)
    # Must not raise: feeding is best-effort and isolated from the decision.
    gov._maybe_feed_forbid_set(
        _outcome("deep"),
        action_type="http_get",
        recipient="evil.example.com",
        tenant="acme",
    )


def test_public_decide_routes_through_feed_and_skips_identity_scoped() -> None:
    # End-to-end through the REAL public decide(): an unknown agent yields an
    # identity-scoped FORBID, which is agent-scoped, so the live feed must NOT
    # warm the kernel hot set with that destination — proving both that decide()
    # is on the feed path and that the scope gate holds end-to-end.
    from tex.domain.verdict import Verdict

    calls: list[dict] = []
    gov = _gov(lambda **kw: calls.append(kw))
    outcome = gov.decide(
        tenant="acme",
        action_type="http_get",
        content="GET https://evil.example.com/",
        recipient="evil.example.com",
        agent_external_id="ghost-agent",  # not in the (empty) registry
    )
    assert outcome.verdict is Verdict.FORBID
    assert outcome.forbid_scope == "identity"
    assert calls == []  # agent-scoped denial does not feed the destination set
