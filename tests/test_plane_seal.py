"""
E1 — PLANE-sealing seam tests.

Proves the producer that turns the LIVE PlaneSignalRegistry into a SEALED,
offline-verifiable plane snapshot the voice can answer from:

  * ``seal_plane(None, ...)`` is a zero-cost no-op (the prod-INERT default), and
  * ``build_plane_fact`` is pure and produces a canonical ``SealedFact(PLANE)``
    whose claim carries both timestamps and the honesty phrasing, and
  * the sealed plane EQUALS the observed ``registry.derive(...)`` signal byte-for-
    byte (DECIDE-ONLY by default; CREDENTIAL-ENFORCED only on a recorded handshake),
    never an upgraded guess, and
  * a PLANE fact appended with the plain ``append`` stays OUT of the per-identity
    ``verify_no_gaps`` sequence (a missing snapshot is NOT a bypass) and does not
    break ``verify_chain``.
"""

from __future__ import annotations

import time

from tex.governance.plane_signals import (
    PLANE_CREDENTIAL_ENFORCED,
    PLANE_DECIDE_ONLY,
    PlaneSignalRegistry,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.provenance.plane_seal import (
    build_plane_fact,
    seal_plane,
    snapshot_planes,
)


# ─────────────────────────── tiny fakes for the producer ───────────────────────
class _FakeAgent:
    def __init__(self, *, agent_id=None, name=None, external_agent_id=None,
                 tenant_id="acme", lifecycle_status="ACTIVE"):
        self.agent_id = agent_id
        self.name = name
        self.external_agent_id = external_agent_id
        self.tenant_id = tenant_id
        self.lifecycle_status = lifecycle_status


class _FakeGov:
    """The minimal surface ``snapshot_planes`` calls — the same accessors the
    /v1/govern/agents/plane endpoint uses."""

    def __init__(self, agents):
        self._agents = agents

    def _list_tenant_agents(self, tenant):
        return [a for a in self._agents
                if (a.tenant_id or "").strip().casefold() == tenant]

    @staticmethod
    def _is_governable(agent):
        return str(getattr(agent, "lifecycle_status", "") or "").upper() != "RETIRED"

    @staticmethod
    def _agent_uuid(agent):
        return None  # external agents (named by string), like the voice case


# ─────────────────────────────── no-op / default-OFF ───────────────────────────
def test_seal_plane_is_noop_when_ledger_none():
    # The prod-INERT path: no ledger → no fact, no cost, no raise.
    assert seal_plane(None, "AtlasPay", PLANE_DECIDE_ONLY,
                      tenant="acme", last_handshake_ts=None) is None


def test_snapshot_planes_is_noop_when_ledger_none():
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()
    assert snapshot_planes(None, gov, reg, tenant="acme") == 0


# ─────────────────────────────── build_plane_fact (pure) ───────────────────────
def test_build_plane_fact_is_canonical():
    fact = build_plane_fact(
        "AtlasPay", PLANE_DECIDE_ONLY,
        tenant="acme", last_handshake_ts=None, captured_at=123.5,
        agent_name="AtlasPay",
    )
    assert fact.kind is SealedFactKind.PLANE
    assert fact.subject_id == "AtlasPay"
    assert set(fact.detail) == {
        "agent_id", "agent_name", "plane", "last_handshake_ts", "tenant", "captured_at",
    }
    assert fact.detail["plane"] == PLANE_DECIDE_ONLY
    assert fact.detail["captured_at"] == 123.5
    # Freshness-checkable + honesty disclaimers carried IN the sealed claim.
    assert "captured_at=123.5" in fact.claim
    assert "last_handshake_ts=None" in fact.claim
    assert "NOT asserted from capability" in fact.claim
    assert "possession != authorization" in fact.claim


# ─────────────── sealed plane EQUALS the observed derive() signal ───────────────
def test_sealed_plane_equals_observed_signal_floor():
    # Empty registry → derive() returns the DECIDE-ONLY floor; we seal EXACTLY that.
    reg = PlaneSignalRegistry()
    observed = reg.derive("AtlasPay", "acme")
    assert observed.plane == PLANE_DECIDE_ONLY
    fact = build_plane_fact(
        observed.agent_id, observed.plane,
        tenant="acme", last_handshake_ts=observed.last_handshake_ts, captured_at=1.0,
    )
    assert fact.detail["plane"] == observed.plane == PLANE_DECIDE_ONLY
    assert fact.detail["last_handshake_ts"] is None


def test_sealed_plane_equals_observed_signal_credential_enforced():
    # A recorded handshake upgrades derive() → CREDENTIAL-ENFORCED; the seal mirrors it.
    reg = PlaneSignalRegistry()
    now = time.time()
    reg.record_handshake("AtlasPay", "acme", "ledgerd", ts=now)
    observed = reg.derive("AtlasPay", "acme")
    assert observed.plane == PLANE_CREDENTIAL_ENFORCED
    fact = build_plane_fact(
        observed.agent_id, observed.plane,
        tenant="acme", last_handshake_ts=observed.last_handshake_ts, captured_at=now,
    )
    assert fact.detail["plane"] == PLANE_CREDENTIAL_ENFORCED
    assert fact.detail["last_handshake_ts"] == observed.last_handshake_ts == now


# ─────────────── PLANE facts are invisible to verify_no_gaps ────────────────────
def test_plane_fact_excluded_from_no_gaps_and_chain_intact():
    ledger = SealedFactLedger()
    rec = seal_plane(ledger, "AtlasPay", PLANE_DECIDE_ONLY,
                     tenant="acme", last_handshake_ts=None, captured_at=1.0)
    assert rec is not None
    assert rec.fact.kind is SealedFactKind.PLANE
    # Plain append → no identity sequence → invisible to the negative-space check.
    gaps = ledger.verify_no_gaps()
    assert gaps["sequenced_records"] == 0
    assert gaps["complete"] is True
    # The hash chain is still intact after appending a PLANE fact.
    assert ledger.verify_chain()["intact"] is True
    # And it is retrievable by kind for the voice answer path.
    assert len(ledger.list_by_kind(SealedFactKind.PLANE)) == 1


# ─────────────────────────── the producer's one tick ───────────────────────────
def test_snapshot_planes_seals_one_decide_only_fact_per_governed_agent():
    ledger = SealedFactLedger()
    gov = _FakeGov([
        _FakeAgent(name="AtlasPay"),
        _FakeAgent(external_agent_id="LedgerBot"),
        _FakeAgent(name="Retired", lifecycle_status="RETIRED"),  # not governable
        _FakeAgent(name="OtherTenant", tenant_id="zzz"),         # wrong tenant
    ])
    reg = PlaneSignalRegistry()  # empty → every agent DECIDE-ONLY (the honest floor)
    n = snapshot_planes(ledger, gov, reg, tenant="acme", captured_at=5.0)
    assert n == 2  # AtlasPay + LedgerBot only
    facts = ledger.list_by_kind(SealedFactKind.PLANE)
    planes = {f.fact.subject_id: f.fact.detail["plane"] for f in facts}
    assert planes == {"AtlasPay": PLANE_DECIDE_ONLY, "LedgerBot": PLANE_DECIDE_ONLY}
    # The honest default: nothing upgraded, every snapshot is the floor.
    assert all(f.fact.detail["last_handshake_ts"] is None for f in facts)
