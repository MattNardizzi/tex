"""
Tests for the discovery ledger.

The ledger is the audit substrate for discovery. Tests verify:

- entries land in append order with correct sequence numbers
- the chain hash links every record to its predecessor
- mutating any field breaks chain verification
- the by-key and by-agent_id indexes are correct
- thread safety (light cover; the lock is RLock so this is mostly
  a correctness statement)
"""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Thread
from uuid import uuid4

from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryFindingKind,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger


def _candidate(name: str = "bot", external_id: str = "ext-1") -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.MICROSOFT_GRAPH,
        tenant_id="acme",
        external_id=external_id,
        name=name,
        confidence=0.9,
        risk_band=DiscoveryRiskBand.LOW,
    )


def _outcome(
    candidate: CandidateAgent,
    *,
    action: ReconciliationAction = ReconciliationAction.REGISTERED,
    resulting_agent_id=None,
) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=candidate.reconciliation_key,
        finding_kind=DiscoveryFindingKind.NEW_AGENT,
        action=action,
        confidence=candidate.confidence,
        resulting_agent_id=resulting_agent_id,
        findings=("auto-promoted",),
    )


class TestAppendAndOrder:
    def test_first_entry_has_no_previous_hash(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        entry = ledger.append(candidate=cand, outcome=_outcome(cand))
        assert entry.sequence == 0
        assert entry.previous_hash is None

    def test_sequence_increments(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        for i in range(5):
            cand = _candidate(external_id=f"ext-{i}")
            ledger.append(candidate=cand, outcome=_outcome(cand))
        assert [e.sequence for e in ledger.list_all()] == [0, 1, 2, 3, 4]

    def test_previous_hash_links_entries(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand1 = _candidate(external_id="a")
        cand2 = _candidate(external_id="b")
        e1 = ledger.append(candidate=cand1, outcome=_outcome(cand1))
        e2 = ledger.append(candidate=cand2, outcome=_outcome(cand2))
        assert e2.previous_hash == e1.record_hash


class TestChainVerification:
    def test_clean_chain_verifies(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        for i in range(10):
            cand = _candidate(external_id=f"ext-{i}")
            ledger.append(candidate=cand, outcome=_outcome(cand))
        assert ledger.verify_chain() is True

    def test_empty_chain_is_valid(self) -> None:
        assert InMemoryDiscoveryLedger().verify_chain() is True

    def test_tampered_payload_breaks_chain(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        ledger.append(candidate=cand, outcome=_outcome(cand))

        # Splice a forged entry directly into the internal list. We
        # bypass the public API to simulate a malicious operator who
        # somehow obtained write access to the storage layer; this is
        # exactly the case the chain is supposed to detect.
        forged_cand = _candidate(name="forged", external_id="hijack")
        forged = ledger._entries[0].model_copy(update={"candidate": forged_cand})
        ledger._entries[0] = forged
        assert ledger.verify_chain() is False


class TestIndexes:
    def test_list_for_key_returns_only_matching_entries(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand_a = _candidate(external_id="a")
        cand_b = _candidate(external_id="b")
        ledger.append(candidate=cand_a, outcome=_outcome(cand_a))
        ledger.append(candidate=cand_b, outcome=_outcome(cand_b))
        ledger.append(candidate=cand_a, outcome=_outcome(cand_a))

        for_a = ledger.list_for_key(cand_a.reconciliation_key)
        for_b = ledger.list_for_key(cand_b.reconciliation_key)

        assert len(for_a) == 2
        assert len(for_b) == 1

    def test_list_for_agent_id_returns_only_matching_entries(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        agent_id = uuid4()
        cand_a = _candidate(external_id="a")
        cand_b = _candidate(external_id="b")
        ledger.append(
            candidate=cand_a,
            outcome=_outcome(cand_a, resulting_agent_id=agent_id),
        )
        ledger.append(candidate=cand_b, outcome=_outcome(cand_b))

        for_agent = ledger.list_for_agent_id(str(agent_id))
        assert len(for_agent) == 1
        assert for_agent[0].candidate.external_id == "a"

    def test_no_op_outcomes_with_no_resulting_agent_dont_index(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        ledger.append(
            candidate=cand,
            outcome=_outcome(
                cand, action=ReconciliationAction.NO_OP_BELOW_THRESHOLD
            ),
        )
        assert ledger.list_for_agent_id(str(uuid4())) == ()


class TestThreadSafety:
    def test_concurrent_appends_preserve_ordering(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        threads = []
        for i in range(20):
            cand = _candidate(external_id=f"ext-{i}")
            t = Thread(
                target=ledger.append,
                kwargs={"candidate": cand, "outcome": _outcome(cand)},
            )
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ledger) == 20
        assert ledger.verify_chain() is True
        sequences = [e.sequence for e in ledger.list_all()]
        assert sequences == list(range(20))


class TestLatestAndLen:
    def test_latest_returns_last_entry(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        assert ledger.latest() is None
        cand = _candidate()
        e = ledger.append(candidate=cand, outcome=_outcome(cand))
        assert ledger.latest() is e

    def test_len_tracks_entries(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        assert len(ledger) == 0
        for i in range(3):
            cand = _candidate(external_id=f"ext-{i}")
            ledger.append(candidate=cand, outcome=_outcome(cand))
        assert len(ledger) == 3


class TestAppendedAtTimezone:
    def test_appended_at_is_utc(self) -> None:
        ledger = InMemoryDiscoveryLedger()
        cand = _candidate()
        entry = ledger.append(candidate=cand, outcome=_outcome(cand))
        assert entry.appended_at.tzinfo == UTC
        assert entry.appended_at <= datetime.now(UTC)
