"""
D5 — REAL chain-break timestamps.

The system-state chain block exposes booleans for chain integrity
(``discovery_chain_intact`` / ``snapshot_chain_intact``). The UI's
"Tex is down" / faltering surface needs a real break TIMESTAMP it can
stand behind, not a generic timestamp-less doom line.

These tests pin the honest contract:

- ``snapshot_broke_at`` is the real ``captured_at`` of the offending
  snapshot when the snapshot chain is broken, and ``None`` when intact.
- ``discovery_broke_at`` is the real ``appended_at`` of the offending
  ledger entry when the discovery chain is broken, and ``None`` when
  intact.
- the new DTO fields are additive / backward-compatible with the
  always-on chain booleans (default ``None``, ``extra="forbid"`` still
  holds, the prior fields are unchanged).
- NO ``datetime.now()`` fabrication: the surfaced time is the recorded
  write-time of a REAL record, never a synthesized "now".
"""

from __future__ import annotations

from datetime import UTC, datetime

from tex.api.system_state_routes import SystemChainDTO, _chain_block
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryFindingKind,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger
from tex.stores.governance_snapshots import GovernanceSnapshotStore


# --------------------------------------------------------------------------
# fixtures (mirror the existing store tests)
# --------------------------------------------------------------------------


def _governance_payload(*, governed: int = 6) -> dict:
    return {
        "counts": {
            "total_agents": 10,
            "governed": governed,
            "ungoverned": 3,
            "partial": 1,
            "unknown": 0,
            "high_risk_total": 4,
            "high_risk_ungoverned": 1,
            "governed_with_forbids": 2,
        },
        "agents": [
            {
                "agent_id": "11111111-1111-1111-1111-111111111111",
                "name": "ungoverned-1",
                "discovery_source": "openai",
                "external_id": "asst_abc",
                "risk_band": "HIGH",
                "tenant_id": "default",
                "governance_state": "UNGOVERNED",
            },
        ],
        "coverage_root_sha256": "abc123",
        "signature_hmac_sha256": "sig123",
    }


def _candidate(name: str = "bot", external_id: str = "ext-1") -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.MICROSOFT_GRAPH,
        tenant_id="acme",
        external_id=external_id,
        name=name,
        confidence=0.9,
        risk_band=DiscoveryRiskBand.LOW,
    )


def _outcome(candidate: CandidateAgent) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=candidate.reconciliation_key,
        finding_kind=DiscoveryFindingKind.NEW_AGENT,
        action=ReconciliationAction.REGISTERED,
        confidence=candidate.confidence,
        resulting_agent_id=None,
        findings=("auto-promoted",),
    )


class _FakeState:
    def __init__(self, *, discovery_ledger=None, governance_snapshot_store=None):
        self.discovery_ledger = discovery_ledger
        self.governance_snapshot_store = governance_snapshot_store


class _FakeApp:
    def __init__(self, state: _FakeState):
        self.state = state


class _FakeRequest:
    def __init__(self, app: _FakeApp):
        self.app = app


def _request(**kw) -> _FakeRequest:
    return _FakeRequest(_FakeApp(_FakeState(**kw)))


# --------------------------------------------------------------------------
# snapshot store: find break captured_at
# --------------------------------------------------------------------------


class TestSnapshotBrokeAt:
    def test_intact_snapshot_chain_has_no_broke_at(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        store.capture(governance_payload=_governance_payload(governed=7))

        out = _chain_block(_request(governance_snapshot_store=store))
        assert out.snapshot_chain_intact is True
        assert out.snapshot_broke_at is None

    def test_broken_snapshot_surfaces_real_captured_at(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        store.capture(governance_payload=_governance_payload(governed=7))
        store.capture(governance_payload=_governance_payload(governed=8))

        # Tamper the middle record (index 1 oldest->newest) without
        # recomputing its hash — exactly what verify_chain detects.
        records_in_order = list(store._cache.values())
        middle = records_in_order[1]
        middle["governed"] = 9999

        # The real captured_at of the offending record, taken straight
        # from the chain order verify_chain uses (list_recent reversed).
        chain = list(reversed(store.list_recent(limit=200)))
        expected = str(chain[1]["captured_at"])

        out = _chain_block(_request(governance_snapshot_store=store))
        assert out.snapshot_chain_intact is False
        assert out.snapshot_broke_at == expected
        # Real, never fabricated: it parses as a timezone-aware time and
        # is the offending snapshot's recorded capture moment.
        parsed = datetime.fromisoformat(out.snapshot_broke_at)
        assert parsed.tzinfo is not None
        assert str(parsed) == str(datetime.fromisoformat(expected))

    def test_broke_at_is_not_now(self, monkeypatch):
        # Prove the surfaced time is the RECORD's time, not now(). We
        # freeze a known captured_at on the offending record and assert
        # the DTO echoes it verbatim, so a now()-fabrication would fail.
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        store.capture(governance_payload=_governance_payload(governed=7))

        records_in_order = list(store._cache.values())
        frozen = "2020-01-02T03:04:05+00:00"
        records_in_order[1]["captured_at"] = frozen
        records_in_order[1]["governed"] = 9999  # break the chain

        out = _chain_block(_request(governance_snapshot_store=store))
        assert out.snapshot_chain_intact is False
        assert out.snapshot_broke_at == frozen


# --------------------------------------------------------------------------
# discovery ledger: find_break appended_at
# --------------------------------------------------------------------------


class TestDiscoveryBrokeAt:
    def test_find_break_returns_none_when_intact(self):
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        ledger.append(candidate=cand, outcome=_outcome(cand))
        assert ledger.verify_chain() is True
        assert ledger.find_break() is None

    def test_find_break_returns_offending_entry(self):
        ledger = InMemoryDiscoveryLedger()
        c0 = _candidate(external_id="a")
        c1 = _candidate(external_id="b")
        ledger.append(candidate=c0, outcome=_outcome(c0))
        e1 = ledger.append(candidate=c1, outcome=_outcome(c1))

        # Forge the second entry's payload without recomputing its hash.
        forged_cand = _candidate(name="forged", external_id="hijack")
        forged = ledger._entries[1].model_copy(update={"candidate": forged_cand})
        ledger._entries[1] = forged

        broken = ledger.find_break()
        assert broken is not None
        assert broken.sequence == 1
        # appended_at is preserved by model_copy → it is the REAL write
        # time of the offending record, not a fresh now().
        assert broken.appended_at == e1.appended_at

    def test_intact_discovery_chain_has_no_broke_at(self):
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        ledger.append(candidate=cand, outcome=_outcome(cand))

        out = _chain_block(_request(discovery_ledger=ledger))
        assert out.discovery_chain_intact is True
        assert out.discovery_broke_at is None

    def test_broken_discovery_surfaces_real_appended_at(self):
        ledger = InMemoryDiscoveryLedger()
        c0 = _candidate(external_id="a")
        c1 = _candidate(external_id="b")
        ledger.append(candidate=c0, outcome=_outcome(c0))
        e1 = ledger.append(candidate=c1, outcome=_outcome(c1))

        forged_cand = _candidate(name="forged", external_id="hijack")
        forged = ledger._entries[1].model_copy(update={"candidate": forged_cand})
        ledger._entries[1] = forged

        out = _chain_block(_request(discovery_ledger=ledger))
        assert out.discovery_chain_intact is False
        assert out.discovery_broke_at == e1.appended_at.isoformat()
        # Real, never now(): equals the offending record's appended_at.
        assert datetime.fromisoformat(out.discovery_broke_at).tzinfo is not None


# --------------------------------------------------------------------------
# DTO: additive / backward-compatible
# --------------------------------------------------------------------------


class TestChainDTOAdditive:
    def test_new_fields_default_to_none(self):
        dto = SystemChainDTO()
        assert dto.snapshot_broke_at is None
        assert dto.discovery_broke_at is None
        # prior always-on booleans unchanged
        assert dto.discovery_chain_intact is True
        assert dto.snapshot_chain_intact is True

    def test_empty_state_is_intact_with_null_broke_at(self):
        # No stores wired → DTO defaults stand; the faltering surface
        # must NOT fire (intact True, broke_at None). This is the
        # backward-compatible / safe-default contract.
        out = _chain_block(_request())
        assert out.discovery_chain_intact is True
        assert out.snapshot_chain_intact is True
        assert out.snapshot_broke_at is None
        assert out.discovery_broke_at is None

    def test_extra_fields_still_forbidden(self):
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SystemChainDTO(not_a_real_field=1)
