"""
E1+ — continuous SEAL-ON-CHANGE PLANE snapshotting on the standing watch.

E1 sealed plane facts ONCE at boot, so an agent discovered AFTER boot (everything
/ignite finds, plus POST /v1/agents) never got a sealed PLANE fact and the voice
could only ever ABSTAIN about it. E1+ wires the snapshotter to run CONTINUOUSLY on
the standing-watch cycle, with seal-on-change semantics so the ledger stays
BOUNDED.

The INVARIANT proven here:

  * a newly-governed agent gets a sealed PLANE fact on a cycle;
  * a SECOND cycle with NO change seals NOTHING (bounded — the ledger does not
    grow per-tick in steady state);
  * a CHANGED derived plane seals a new fact;
  * the default boot (no flags) seals nothing and starts NO plane-seal callable;
  * the voice (E1) then answers about a discovered agent from the FRESH fact.
"""

from __future__ import annotations

import os
import time
import types

from tex.domain.verdict import Verdict
from tex.governance.plane_signals import (
    PLANE_CREDENTIAL_ENFORCED,
    PLANE_DECIDE_ONLY,
    PlaneSignalRegistry,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.provenance.plane_seal import snapshot_planes_on_change
from tex.voice import answer_forms, voice_ask


# ─────────────────────────── tiny fakes (mirror test_plane_seal) ────────────────
class _FakeAgent:
    def __init__(self, *, name=None, external_agent_id=None,
                 tenant_id="acme", lifecycle_status="ACTIVE"):
        self.agent_id = None
        self.name = name
        self.external_agent_id = external_agent_id
        self.tenant_id = tenant_id
        self.lifecycle_status = lifecycle_status


class _FakeGov:
    """The minimal surface the producer calls — same accessors the
    /v1/govern/agents/plane endpoint uses. Mutable so a test can add an agent
    AFTER the first cycle (an agent discovered post-boot)."""

    def __init__(self, agents):
        self._agents = list(agents)

    def add(self, agent):
        self._agents.append(agent)

    def _list_tenant_agents(self, tenant):
        return [a for a in self._agents
                if (a.tenant_id or "").strip().casefold() == tenant]

    @staticmethod
    def _is_governable(agent):
        return str(getattr(agent, "lifecycle_status", "") or "").upper() != "RETIRED"

    @staticmethod
    def _agent_uuid(agent):
        return None  # external agents named by string, like the voice case


def _planes(ledger):
    return [
        (f.fact.subject_id, f.fact.detail["plane"])
        for f in ledger.list_by_kind(SealedFactKind.PLANE)
    ]


# ─────────────── 1. newly-governed agent sealed once; no-change cycle = bounded ──
def test_new_agent_sealed_once_then_no_change_seals_nothing():
    ledger = SealedFactLedger()
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()  # empty → DECIDE-ONLY floor

    # Cycle 1: the new agent gets exactly one sealed PLANE fact.
    n1 = snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=1.0)
    assert n1 == 1
    assert _planes(ledger) == [("AtlasPay", PLANE_DECIDE_ONLY)]

    # Cycle 2: NOTHING changed → seals NOTHING. The ledger does not grow per-tick.
    n2 = snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=2.0)
    assert n2 == 0
    assert len(ledger.list_by_kind(SealedFactKind.PLANE)) == 1  # still one

    # Cycle 3 (still steady state): still bounded.
    n3 = snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=3.0)
    assert n3 == 0
    assert len(ledger.list_by_kind(SealedFactKind.PLANE)) == 1


def test_agent_discovered_after_first_cycle_is_sealed_on_the_next_cycle():
    # An agent that only appears AFTER the first cycle (the E1 gap: post-boot
    # discovery) gets a sealed PLANE fact on the cycle that first sees it — and
    # the already-sealed agent is NOT re-sealed.
    ledger = SealedFactLedger()
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()

    assert snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=1.0) == 1

    gov.add(_FakeAgent(external_agent_id="LedgerBot"))  # discovered post-boot
    n = snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=2.0)
    assert n == 1  # ONLY the new one — AtlasPay unchanged, not re-sealed
    assert dict(_planes(ledger)) == {
        "AtlasPay": PLANE_DECIDE_ONLY,
        "LedgerBot": PLANE_DECIDE_ONLY,
    }


# ─────────────────────────── 2. a changed plane seals a new fact ────────────────
def test_changed_plane_seals_a_new_fact():
    ledger = SealedFactLedger()
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()

    assert snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=1.0) == 1
    assert dict(_planes(ledger))["AtlasPay"] == PLANE_DECIDE_ONLY

    # A real upgrade: record a fresh handshake so derive() now returns
    # CREDENTIAL-ENFORCED (default ts=now so it is inside the freshness window).
    reg.record_handshake("AtlasPay", "acme", "ledgerd")
    assert reg.derive("AtlasPay", "acme").plane == PLANE_CREDENTIAL_ENFORCED

    n = snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=20.0)
    assert n == 1  # the transition seals a fresh fact
    facts = ledger.list_by_kind(SealedFactKind.PLANE)
    assert len(facts) == 2  # old DECIDE-ONLY + new CREDENTIAL-ENFORCED
    # The freshest (max captured_at) is the upgrade — what the voice will answer.
    freshest = max(facts, key=lambda f: f.fact.detail["captured_at"])
    assert freshest.fact.detail["plane"] == PLANE_CREDENTIAL_ENFORCED

    # And the next steady-state cycle (no further change) seals nothing again.
    assert snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=30.0) == 0
    assert len(ledger.list_by_kind(SealedFactKind.PLANE)) == 2


def test_noop_when_ledger_none():
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    assert snapshot_planes_on_change(None, gov, PlaneSignalRegistry(), tenant="acme") == 0


# ─────────────── 3. the standing-watch cycle invokes the seal-on-change leg ──────
class _FakeSummary:
    run_id = None
    duration_seconds = 0.0
    candidates_seen = 0
    registered_count = 0
    updated_drift_count = 0
    quarantined_count = 0
    held_count = 0
    errors: tuple = ()


class _FakeRun:
    summary = _FakeSummary()
    scan_run_id = None
    ledger_seq_start = None
    ledger_seq_end = None
    registry_state_hash = None
    entries: tuple = ()


class _FakeService:
    def scan(self, **_kwargs):
        return _FakeRun()


def test_standing_cycle_invokes_plane_seal_on_change():
    from tex.discovery.scheduler import BackgroundScanScheduler

    ledger = SealedFactLedger()
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()

    def _seal_for_tenant(*, tenant_id: str) -> int:
        return snapshot_planes_on_change(ledger, gov, reg, tenant=tenant_id)

    sched = BackgroundScanScheduler(
        service=_FakeService(),
        drift_store=None,           # _emit_drift_events returns early
        tenants=["acme"],
    )
    sched.attach_plane_seal(_seal_for_tenant)

    # One synchronous cycle (no thread) → the new agent is sealed once.
    sched.trigger_now()
    assert dict(_planes(ledger)) == {"AtlasPay": PLANE_DECIDE_ONLY}

    # A second cycle with no change seals nothing — bounded on the standing watch.
    sched.trigger_now()
    assert len(ledger.list_by_kind(SealedFactKind.PLANE)) == 1

    # A post-boot agent appears → the next cycle seals exactly it.
    gov.add(_FakeAgent(external_agent_id="LedgerBot"))
    sched.trigger_now()
    assert dict(_planes(ledger)) == {
        "AtlasPay": PLANE_DECIDE_ONLY,
        "LedgerBot": PLANE_DECIDE_ONLY,
    }


def test_scheduler_without_plane_seal_callable_is_unchanged():
    # Default: no attach_plane_seal → the callable is None → the cycle seals
    # nothing and behaves byte-for-byte as before E1+.
    from tex.discovery.scheduler import BackgroundScanScheduler

    sched = BackgroundScanScheduler(
        service=_FakeService(), drift_store=None, tenants=["acme"],
    )
    assert sched._plane_seal_callable is None  # noqa: SLF001 — invariant under test
    out = sched.trigger_now()
    assert out["tenants"][0]["tenant_id"] == "acme"


# ─────────────── 4. default boot (no flags) seals nothing + starts no leg ────────
def test_default_boot_seals_nothing_and_attaches_no_plane_seal(monkeypatch):
    # No TEX_SEAL_DECISIONS, no TEX_SEAL_PLANE → decision_ledger is None, the
    # scheduler gets NO plane-seal callable, and nothing is sealed.
    for var in (
        "TEX_SEAL_DECISIONS", "TEX_SEAL_PLANE",
        "TEX_DISCOVERY_SCAN_INTERVAL_SECONDS", "TEX_DISCOVERY_SCAN_TENANTS",
        "TEX_SIEVE_ENABLED",
    ):
        monkeypatch.delenv(var, raising=False)

    from tex.main import create_app

    app = create_app()
    state = app.state
    assert getattr(state, "decision_ledger", None) is None  # nothing to seal into
    sched = getattr(state, "scan_scheduler", None)
    if sched is not None:
        # The standing watch exists, but NO plane-seal leg is attached at default.
        assert sched._plane_seal_callable is None  # noqa: SLF001
        assert not sched.is_running  # building the app starts no thread


# ─────────────── 5. the voice answers about a discovered agent from the fact ─────
def test_voice_answers_from_the_freshly_sealed_fact():
    # End-to-end E1+→E1: an agent discovered after boot is sealed by the
    # continuous producer; the E1 voice then answers about it from that SEALED
    # fact (never reading the live registry).
    ledger = SealedFactLedger()
    gov = _FakeGov([_FakeAgent(name="AtlasPay")])
    reg = PlaneSignalRegistry()

    snapshot_planes_on_change(ledger, gov, reg, tenant="acme", captured_at=7.0)

    request = types.SimpleNamespace(
        app=types.SimpleNamespace(
            state=types.SimpleNamespace(decision_store=None, decision_ledger=ledger),
        )
    )
    out = voice_ask.answer_question(
        request, transcript="is AtlasPay credential-enforced or decide-only", tenant=None,
    )
    assert out.verdict is Verdict.PERMIT
    assert "DECIDE-ONLY" in out.answer
    assert out.answer != answer_forms.ABSTAIN_NO_PLANE
    assert "observed as of 7.0" in out.answer
