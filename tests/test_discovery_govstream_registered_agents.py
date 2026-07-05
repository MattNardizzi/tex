"""
Regression — the govstream plane must NOT double-count registered agents.

The reproduced bug (2026-07-05): 20 agents registered via ``POST /v1/agents``
(tenant ``tex-enterprise``, names like ``PayrollPilot``), fleet calling
``/v1/govern/decide`` with ``agent_external_id=<name>``; firing ignite with
``TEX_SIEVE_P11_OTEL`` ran the governance-stream plane, whose candidates carry
``external_id="sieve-<name>"``. That key (``generic:<tenant>:sieve-<name>``)
never matched the registered agent, so ``adapter.project`` minted a SECOND row
per agent — estate 20 → 40, and the spoken line said "You have forty agents
running" for a 20-agent fleet.

The fix: on an index miss, ``project`` binds the entity to an already-
registered agent by ``external_agent_id`` OR ``name`` within the tenant — the
same binding ``StandingGovernance._resolve_agent`` applies to every
``decide()`` call — and links the sieve key to that agent instead of minting.

The capability mandate (never removed): an agent that binds to NOTHING — a
genuinely unknown/shadow agent — must STILL land as a new governable row.
Both directions are pinned here.

Events are fed exactly the way the live gate feeds them: the same row shape
``governance_standing_routes.decide`` passes to ``record_decision``, drained
by the sensor's ``live_decisions`` ring-buffer source inside ``run_planes``.
"""

from __future__ import annotations

import pytest

# Importing the adapter binds the SieveEntity output-boundary methods used by
# ``run_planes``' ADAPT stage, so it must be importable for the projection path.
from tex.discovery.engine import adapter
from tex.discovery.engine.models import SieveEntity
from tex.discovery.engine.pipeline import run_planes
from tex.discovery.engine.sensors.governance_stream import (
    _LIVE_DECISIONS,
    record_decision,
)
from tex.discovery.service import ReconciliationIndex
from tex.domain.agent import AgentIdentity
from tex.domain.discovery import ReconciliationAction
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

_P11_FLAG = "TEX_SIEVE_P11_OTEL"
_TENANT = "tex-enterprise"

# The enterprise fleet's registered names (the repro used 20; 3 pins the math).
_FLEET = ("PayrollPilot", "InvoiceSentry", "LedgerScribe")


@pytest.fixture(autouse=True)
def _clean_decision_buffer():
    """The gate's ring buffer is module-global; isolate it per test."""
    _LIVE_DECISIONS.clear()
    yield
    _LIVE_DECISIONS.clear()


def _registered_fleet(names=_FLEET, tenant: str = _TENANT) -> InMemoryAgentRegistry:
    """A registry seeded the way ``POST /v1/agents`` seeds it — plain
    registered identities with NO discovery provenance metadata (that absence
    is exactly what made the reconciliation index blind to them)."""
    registry = InMemoryAgentRegistry()
    for name in names:
        registry.save(AgentIdentity(name=name, owner="ops@tex", tenant_id=tenant))
    return registry


def _decide_event(name: str, tenant: str = _TENANT) -> dict[str, object]:
    """The exact row shape the live ``/v1/govern/decide`` route records."""
    return {
        "agent_external_id": name,
        "agent_id": None,
        "tool_name": "payment",
        "verdict": "PERMIT",
        "tenant": tenant,
    }


def _ignite(registry, ledger, tenant: str = _TENANT):
    """Run the plane exactly as ignite does: P11 flag on, live ring-buffer
    source, tenant threaded so discovered agents land in the same estate."""
    return run_planes(
        env={_P11_FLAG: "1"},
        registry=registry,
        ledger=ledger,
        tenant_id=tenant,
    )


# ---------------------------------------------------------------------------
# The regression: registered agents observed by govstream stay N, not 2N.
# ---------------------------------------------------------------------------


def test_registered_fleet_observed_by_govstream_keeps_estate_at_n() -> None:
    registry = _registered_fleet()
    ledger = InMemoryDiscoveryLedger()
    registered_ids = {a.agent_id for a in registry.list_all()}

    for name in _FLEET:
        record_decision(_decide_event(name))

    result = _ignite(registry, ledger)

    # Every observed agent projected... to the EXISTING rows. The estate count
    # the spoken line reads is len(registry): it must stay N, never 2N.
    assert result.projected == len(_FLEET)
    assert len(registry.list_all()) == len(_FLEET)
    assert {a.agent_id for a in registry.list_all()} == registered_ids

    # The ledger tells the bind story: every row is a KNOWN no-op resolving to
    # the registered agent — nothing minted, and the finding names the bind.
    entries = ledger.list_all()
    assert len(entries) == len(_FLEET)
    for entry in entries:
        assert entry.outcome.action is ReconciliationAction.NO_OP_KNOWN_UNCHANGED
        assert entry.outcome.resulting_agent_id in registered_ids
        assert any("bound_to_registered_agent" in f for f in entry.outcome.findings)


def test_second_ignite_run_is_stable_at_n() -> None:
    """Re-igniting (a fresh index each run, like the live route) must not
    drift the estate — the bind re-fires on the miss and re-links."""
    registry = _registered_fleet()
    ledger = InMemoryDiscoveryLedger()

    for name in _FLEET:
        record_decision(_decide_event(name))
    _ignite(registry, ledger)
    _ignite(registry, ledger)

    assert len(registry.list_all()) == len(_FLEET)


def test_case_drifted_observation_still_binds() -> None:
    """The reconciliation key casefolds, so a case-drifted observed id must
    bind to the registered agent rather than re-mint."""
    registry = _registered_fleet(names=("PayrollPilot",))
    ledger = InMemoryDiscoveryLedger()

    record_decision(_decide_event("payrollpilot"))
    _ignite(registry, ledger)

    assert len(registry.list_all()) == 1


# ---------------------------------------------------------------------------
# The capability mandate: shadow discovery is NOT removed by the bind.
# ---------------------------------------------------------------------------


def test_unknown_shadow_agent_still_lands_as_a_new_row() -> None:
    registry = _registered_fleet()
    ledger = InMemoryDiscoveryLedger()

    record_decision(_decide_event("ShadowScraper"))

    result = _ignite(registry, ledger)

    assert result.projected == 1
    agents = registry.list_all()
    assert len(agents) == len(_FLEET) + 1
    minted = [a for a in agents if a.name not in _FLEET]
    assert len(minted) == 1
    assert minted[0].metadata.get("discovery_external_id") == "sieve-ShadowScraper"

    entry = ledger.latest()
    assert entry is not None
    assert entry.outcome.action is ReconciliationAction.REGISTERED


def test_mixed_fleet_and_shadow_counts_exactly_n_plus_one() -> None:
    registry = _registered_fleet()
    ledger = InMemoryDiscoveryLedger()

    for name in (*_FLEET, "ShadowScraper"):
        record_decision(_decide_event(name))

    _ignite(registry, ledger)

    # 3 bound + 1 minted — the repro's 20→40 becomes N→N (+ the true unknown).
    assert len(registry.list_all()) == len(_FLEET) + 1


def test_bind_never_crosses_tenants() -> None:
    """An agent registered under ANOTHER tenant is not this estate's agent:
    the observation must mint under the ignite tenant, not leak a bind."""
    registry = _registered_fleet(names=("PayrollPilot",), tenant="other-tenant")
    ledger = InMemoryDiscoveryLedger()

    record_decision(_decide_event("PayrollPilot"))
    _ignite(registry, ledger, tenant=_TENANT)

    agents = registry.list_all()
    assert len(agents) == 2
    minted = [a for a in agents if a.tenant_id == _TENANT]
    assert len(minted) == 1
    assert minted[0].metadata.get("discovery_external_id") == "sieve-PayrollPilot"


# ---------------------------------------------------------------------------
# Boundary-level unit: the bind seam itself, without the sensor in the loop.
# ---------------------------------------------------------------------------


def test_project_binds_entity_to_registered_agent_directly() -> None:
    registry = _registered_fleet(names=("PayrollPilot",))
    ledger = InMemoryDiscoveryLedger()
    index = ReconciliationIndex(registry=registry)
    registered = registry.list_all()[0]

    entity = SieveEntity(
        merge_axis="PayrollPilot", label="PayrollPilot", fusion_confidence=0.9
    )
    adapter.project(entity, registry, ledger, index, tenant=_TENANT)

    assert len(registry.list_all()) == 1
    # The sieve key is now linked to the registered agent, so the NEXT scan is
    # an index hit (the bind pays its registry scan exactly once).
    key = adapter.reconciliation_key(entity, _TENANT)
    assert index.get_agent_id(key) == registered.agent_id


def test_prior_index_link_wins_over_the_bind() -> None:
    """An entity already linked (e.g. a previously minted sieve row) keeps its
    link — the bind only fires on a genuine miss, so existing linkage and
    presence keys never churn."""
    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    index = ReconciliationIndex(registry=registry)

    entity = SieveEntity(
        merge_axis="PayrollPilot", label="PayrollPilot", fusion_confidence=0.9
    )
    # First projection mints (nothing registered yet) and links the key.
    adapter.project(entity, registry, ledger, index, tenant=_TENANT)
    minted_id = index.get_agent_id(adapter.reconciliation_key(entity, _TENANT))
    assert minted_id is not None

    # A registered agent with the same name arrives LATER; the existing link
    # still wins for this key — no re-targeting, no second mint.
    registry.save(AgentIdentity(name="PayrollPilot", owner="ops@tex", tenant_id=_TENANT))
    adapter.project(entity, registry, ledger, index, tenant=_TENANT)

    assert index.get_agent_id(adapter.reconciliation_key(entity, _TENANT)) == minted_id
    assert len(registry.list_all()) == 2  # the mint + the manual registration
