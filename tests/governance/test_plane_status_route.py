"""Tests for the wired GET /v1/govern/agents/plane route — the per-agent
enforcement-plane badge derived from LIVE, OBSERVED signals.

THE HONESTY CONTRACT under test (constitution C1):

  * Default-OFF behind ``TEX_PLANE_STATUS`` (inert 503 when unset) — and the
    flag-off short-circuit fires BEFORE governance/registry is ever touched.
  * EMPTY registry => EVERY governed agent reads ``DECIDE-ONLY`` with
    ``last_handshake_ts=null``. The flag only exposes the endpoint; it never
    upgrades a plane.
  * A recorded, FRESH credential handshake => that agent reads
    ``CREDENTIAL-ENFORCED``; others stay DECIDE-ONLY.
  * A recorded, FRESH in-path poll for the tenant => every governed agent reads
    ``IN-PATH-BLOCKING``.
  * STALENESS DEGRADES: any signal past its TTL is treated as absent and the
    plane drops back to DECIDE-ONLY.
  * RENDER-LIKE (flag ON, empty stores, no poll producer): no agent ever reads
    IN-PATH-BLOCKING or CREDENTIAL-ENFORCED.
  * BROKER AVAILABILITY IS NOT A SIGNAL: a broker / TEX_GOVERN_MINT configured on
    app.state with no recorded handshake still yields DECIDE-ONLY.

Mirrors test_govern_mint_route.py: a bare FastAPI app mounting
``build_governance_standing_router()`` with a FAKE governance whose
``_list_tenant_agents`` returns agent records for tenant ``acme``, plus a real
``PlaneSignalRegistry`` we can feed to assert the REAL derivation (never
hardcoded outputs).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.governance.plane_signals import (
    PLANE_CREDENTIAL_ENFORCED,
    PLANE_DECIDE_ONLY,
    PLANE_IN_PATH_BLOCKING,
    PlaneSignalRegistry,
)


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


@dataclass
class _FakeAgent:
    agent_id: UUID
    name: str
    tenant_id: str
    lifecycle_status: str = "active"
    external_agent_id: str | None = None


class _FakeGovernance:
    """Minimal stand-in for StandingGovernance exposing exactly the accessors
    the plane route uses: ``_list_tenant_agents``, ``_is_governable``,
    ``_agent_uuid``. Records whether the agent list was ever iterated so the
    flag-off short-circuit can be proven inert."""

    def __init__(self, agents: list[_FakeAgent]) -> None:
        self._agents = agents
        self.listed = False

    def _list_tenant_agents(self, tenant: str) -> list[_FakeAgent]:
        self.listed = True
        return [a for a in self._agents if a.tenant_id.casefold() == tenant.casefold()]

    @staticmethod
    def _is_governable(agent: _FakeAgent) -> bool:
        return str(agent.lifecycle_status).upper() not in {"DORMANT", "RETIRED", "DECOMMISSIONED"}

    @staticmethod
    def _agent_uuid(agent: _FakeAgent) -> UUID | None:
        return agent.agent_id


def _client(
    gov: object | None,
    registry: PlaneSignalRegistry | None = None,
    *,
    extra_state: dict | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    if gov is not None:
        app.state.standing_governance = gov
    if registry is not None:
        app.state.plane_signal_registry = registry
    for k, v in (extra_state or {}).items():
        setattr(app.state, k, v)
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:read"}),
    )
    return TestClient(app)


def _two_agents() -> list[_FakeAgent]:
    return [
        _FakeAgent(agent_id=uuid4(), name="atlas", tenant_id="acme"),
        _FakeAgent(agent_id=uuid4(), name="orion", tenant_id="acme"),
    ]


def _planes_by_id(payload: dict) -> dict[str, dict]:
    return {a["agent_id"]: a for a in payload["agents"]}


# --------------------------------------------------------------------------- #
# 1. FLAG-OFF => 503, and governance/registry never touched                   #
# --------------------------------------------------------------------------- #


def test_default_off_inert(monkeypatch) -> None:
    monkeypatch.delenv("TEX_PLANE_STATUS", raising=False)
    gov = _FakeGovernance(_two_agents())
    resp = _client(gov).get("/v1/govern/agents/plane")
    assert resp.status_code == 503
    # Inertness proof: the flag-off short-circuit fires BEFORE any iteration.
    assert gov.listed is False


# --------------------------------------------------------------------------- #
# 2. FLAG-ON + EMPTY registry => every governed agent DECIDE-ONLY             #
# --------------------------------------------------------------------------- #


def test_flag_on_empty_all_decide_only(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    resp = _client(_FakeGovernance(agents), PlaneSignalRegistry()).get(
        "/v1/govern/agents/plane"
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["count"] == 2
    for a in payload["agents"]:
        assert a["plane"] == PLANE_DECIDE_ONLY
        assert a["last_handshake_ts"] is None
        # No agent is ever optimistically upgraded with an empty registry.
        assert a["plane"] != PLANE_CREDENTIAL_ENFORCED
        assert a["plane"] != PLANE_IN_PATH_BLOCKING


def test_flag_on_no_registry_attached_still_decide_only(monkeypatch) -> None:
    # No registry on app.state => route builds a fresh EMPTY one => all floor.
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    resp = _client(_FakeGovernance(_two_agents())).get("/v1/govern/agents/plane")
    assert resp.status_code == 200, resp.text
    assert all(a["plane"] == PLANE_DECIDE_ONLY for a in resp.json()["agents"])


# --------------------------------------------------------------------------- #
# 3. FED credential handshake => that agent CREDENTIAL-ENFORCED               #
# --------------------------------------------------------------------------- #


def test_fed_credential_signal_upgrades_one_agent(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    target = agents[0]
    reg = PlaneSignalRegistry(clock=lambda: 1000.0)
    # An OBSERVED downstream handshake for the target agent, recorded just now.
    reg.record_handshake(str(target.agent_id), "acme", "payroll.example", ts=995.0)

    resp = _client(_FakeGovernance(agents), reg).get("/v1/govern/agents/plane")
    assert resp.status_code == 200, resp.text
    by_id = _planes_by_id(resp.json())
    assert by_id[str(target.agent_id)]["plane"] == PLANE_CREDENTIAL_ENFORCED
    assert by_id[str(target.agent_id)]["last_handshake_ts"] == 995.0
    # The other agent has no signal => stays at the floor.
    other = str(agents[1].agent_id)
    assert by_id[other]["plane"] == PLANE_DECIDE_ONLY
    assert by_id[other]["last_handshake_ts"] is None


# --------------------------------------------------------------------------- #
# 4. EXPIRED credential handshake => DEGRADES back to DECIDE-ONLY             #
# --------------------------------------------------------------------------- #


def test_expired_credential_signal_degrades(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    target = agents[0]
    # cred_ttl_s=120; record a handshake well outside the window.
    reg = PlaneSignalRegistry(cred_ttl_s=120.0, clock=lambda: 1000.0)
    reg.record_handshake(str(target.agent_id), "acme", "payroll.example", ts=1000.0 - 130.0)

    resp = _client(_FakeGovernance(agents), reg).get("/v1/govern/agents/plane")
    by_id = _planes_by_id(resp.json())
    # Stale => treated as absent => floor, and the ts field is null again.
    assert by_id[str(target.agent_id)]["plane"] == PLANE_DECIDE_ONLY
    assert by_id[str(target.agent_id)]["last_handshake_ts"] is None


# --------------------------------------------------------------------------- #
# 5. FED in-path poll => every governed agent IN-PATH-BLOCKING; expiry drops  #
# --------------------------------------------------------------------------- #


def test_fed_in_path_poll_upgrades_whole_tenant(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    reg = PlaneSignalRegistry(poll_ttl_s=90.0, clock=lambda: 2000.0)
    # A live loader heartbeat for the tenant — applies to every governed agent.
    reg.record_poll("acme", "loader-1", ts=1990.0)

    resp = _client(_FakeGovernance(agents), reg).get("/v1/govern/agents/plane")
    assert resp.status_code == 200, resp.text
    for a in resp.json()["agents"]:
        assert a["plane"] == PLANE_IN_PATH_BLOCKING
        # IN-PATH is tenant-scoped, not a per-agent handshake => ts stays null.
        assert a["last_handshake_ts"] is None


def test_expired_in_path_poll_degrades_all(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    reg = PlaneSignalRegistry(poll_ttl_s=90.0, clock=lambda: 2000.0)
    reg.record_poll("acme", "loader-1", ts=2000.0 - 100.0)  # outside the window

    resp = _client(_FakeGovernance(agents), reg).get("/v1/govern/agents/plane")
    for a in resp.json()["agents"]:
        assert a["plane"] == PLANE_DECIDE_ONLY


def test_in_path_dominates_credential(monkeypatch) -> None:
    # When both fresh signals exist, the stronger plane (IN-PATH) wins, but the
    # per-agent handshake ts is still reported (the DoD field).
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    target = agents[0]
    reg = PlaneSignalRegistry(clock=lambda: 3000.0)
    reg.record_handshake(str(target.agent_id), "acme", "payroll.example", ts=2990.0)
    reg.record_poll("acme", "loader-1", ts=2990.0)

    resp = _client(_FakeGovernance(agents), reg).get("/v1/govern/agents/plane")
    by_id = _planes_by_id(resp.json())
    assert by_id[str(target.agent_id)]["plane"] == PLANE_IN_PATH_BLOCKING
    assert by_id[str(target.agent_id)]["last_handshake_ts"] == 2990.0


# --------------------------------------------------------------------------- #
# 6. RENDER-LIKE: flag ON, no poll producer ever => never IN-PATH/CREDENTIAL  #
# --------------------------------------------------------------------------- #


def test_render_like_never_in_path(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    # Render reality: the endpoint is exposed, but no loader polls and no
    # verifier reports back. An empty registry, nothing fed.
    agents = _two_agents()
    resp = _client(_FakeGovernance(agents), PlaneSignalRegistry()).get(
        "/v1/govern/agents/plane"
    )
    planes = {a["plane"] for a in resp.json()["agents"]}
    assert PLANE_IN_PATH_BLOCKING not in planes
    assert PLANE_CREDENTIAL_ENFORCED not in planes
    assert planes == {PLANE_DECIDE_ONLY}


# --------------------------------------------------------------------------- #
# 7. Governance unwired => 503                                                 #
# --------------------------------------------------------------------------- #


def test_governance_unwired_503(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    resp = _client(None).get("/v1/govern/agents/plane")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# 8. Broker availability is NOT a signal                                       #
# --------------------------------------------------------------------------- #


def test_broker_availability_is_not_a_signal(monkeypatch) -> None:
    # Configure mint capability + a broker object on app.state, but record NO
    # handshake. Availability must never upgrade a plane.
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    agents = _two_agents()
    resp = _client(
        _FakeGovernance(agents),
        PlaneSignalRegistry(),
        extra_state={"credential_broker": object()},
    ).get("/v1/govern/agents/plane")
    assert resp.status_code == 200, resp.text
    for a in resp.json()["agents"]:
        assert a["plane"] == PLANE_DECIDE_ONLY
        assert a["last_handshake_ts"] is None


# --------------------------------------------------------------------------- #
# 9. Non-governable agents are excluded                                        #
# --------------------------------------------------------------------------- #


def test_non_governable_agents_excluded(monkeypatch) -> None:
    monkeypatch.setenv("TEX_PLANE_STATUS", "1")
    agents = _two_agents()
    agents.append(
        _FakeAgent(agent_id=uuid4(), name="ghost", tenant_id="acme", lifecycle_status="DORMANT")
    )
    resp = _client(_FakeGovernance(agents), PlaneSignalRegistry()).get(
        "/v1/govern/agents/plane"
    )
    payload = resp.json()
    # The dormant agent is observed-but-not-governed => not in the badge list.
    assert payload["count"] == 2
    names = {a["agent_id"] for a in payload["agents"]}
    assert str(agents[2].agent_id) not in names
