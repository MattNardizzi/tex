"""
V15 tests: PostgresDiscoveryLedger fallback mode + chain integrity.
"""

from __future__ import annotations

from uuid import uuid4

from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryFindingKind,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)
from tex.stores.discovery_ledger_postgres import PostgresDiscoveryLedger


def _make_candidate(*, name: str = "alpha", external_id: str = "ext-1") -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.OPENAI,
        external_id=external_id,
        tenant_id="default",
        name=name,
        owner_hint="founder@example.com",
        risk_band=DiscoveryRiskBand.MEDIUM,
        confidence=0.9,
        capability_hints=DiscoveredCapabilityHints(
            inferred_tools=("send_email",),
            inferred_data_scopes=("crm.contacts.read",),
        ),
    )


def _make_outcome(*, recon_key: str, candidate_id, action: ReconciliationAction = ReconciliationAction.REGISTERED) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        candidate_id=candidate_id,
        reconciliation_key=recon_key,
        finding_kind=DiscoveryFindingKind.NEW_AGENT,
        action=action,
        confidence=0.9,
        resulting_agent_id=uuid4() if action is ReconciliationAction.REGISTERED else None,
    )


class TestLedgerFallback:
    def test_falls_back_when_no_dsn(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        l = PostgresDiscoveryLedger()
        assert l.is_durable is False
        assert len(l) == 0

    def test_append_records_an_entry(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        l = PostgresDiscoveryLedger()
        c = _make_candidate()
        entry = l.append(
            candidate=c,
            outcome=_make_outcome(recon_key="openai_assistants:ext-1", candidate_id=c.candidate_id),
        )
        assert entry.sequence == 0
        assert len(l) == 1
        assert l.latest() is not None

    def test_chain_intact_for_single_entry(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        l = PostgresDiscoveryLedger()
        c = _make_candidate()
        l.append(
            candidate=c,
            outcome=_make_outcome(recon_key="openai_assistants:ext-1", candidate_id=c.candidate_id),
        )
        assert l.verify_chain() is True

    def test_chain_intact_across_many_entries(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        l = PostgresDiscoveryLedger()
        for i in range(5):
            c = _make_candidate(name=f"agent-{i}", external_id=f"ext-{i}")
            l.append(
                candidate=c,
                outcome=_make_outcome(
                    recon_key=f"openai_assistants:ext-{i}",
                    candidate_id=c.candidate_id,
                ),
            )
        assert l.verify_chain() is True
        assert len(l) == 5

    def test_list_for_key_filters(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        l = PostgresDiscoveryLedger()
        ca = _make_candidate(name="a", external_id="ext-a")
        cb = _make_candidate(name="b", external_id="ext-b")
        l.append(candidate=ca, outcome=_make_outcome(recon_key="key-a", candidate_id=ca.candidate_id))
        l.append(candidate=cb, outcome=_make_outcome(recon_key="key-b", candidate_id=cb.candidate_id))
        assert len(l.list_for_key("key-a")) == 1
        assert len(l.list_for_key("key-b")) == 1
        assert len(l.list_for_key("missing")) == 0
