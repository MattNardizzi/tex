"""Shared fixtures: a populated app.state over REAL in-memory stores.

Tests exercise the presence read-tools against the same store classes the live
runtime wires onto ``app.state`` — not mocks — so a passing test reflects real
read behaviour.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from tex.domain.agent import ActionLedgerEntry, AgentIdentity, AgentLifecycleStatus
from tex.domain.decision import Decision
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryFindingKind,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)
from tex.domain.verdict import Verdict
from tex.evidence.recorder import EvidenceRecorder
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger
from tex.stores.drift_events import DriftEventKind, DriftEventStore
from tex.stores.scan_runs import ScanRunStore

KNOWN_AGENT_TENANT = "acme"


def _hex(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _decision(verdict: Verdict) -> Decision:
    kwargs = dict(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.1 if verdict is Verdict.PERMIT else 0.8,
        action_type="send_email",
        channel="email",
        environment="prod",
        content_excerpt="hello",
        content_sha256=_hex(f"content-{uuid4()}"),
        policy_version="v1",
    )
    if verdict is Verdict.ABSTAIN:
        kwargs["uncertainty_flags"] = ["needs_human"]
    return Decision(**kwargs)


def _action(agent_id: UUID, verdict: str) -> ActionLedgerEntry:
    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        action_type="send_email",
        channel="email",
        environment="prod",
        final_score=0.2,
        confidence=0.9,
        content_sha256=_hex(f"action-{uuid4()}"),
    )


def _candidate(tenant: str, ext: str) -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.OKTA,
        tenant_id=tenant,
        external_id=ext,
        name="discovered-bot",
        confidence=0.9,
    )


def _outcome(candidate: CandidateAgent) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=f"{candidate.source}:{candidate.tenant_id}:{candidate.external_id}",
        finding_kind=DiscoveryFindingKind.NEW_AGENT,
        action=ReconciliationAction.REGISTERED,
        confidence=0.9,
    )


@pytest.fixture
def known_agent_id(populated_state) -> UUID:
    return populated_state._known_agent_id


@pytest.fixture
def populated_state(tmp_path) -> SimpleNamespace:
    registry = InMemoryAgentRegistry()
    active = registry.save(AgentIdentity(name="active-bot", owner="ops", tenant_id=KNOWN_AGENT_TENANT))
    registry.save(AgentIdentity(name="other-bot", owner="ops", tenant_id="other"))
    revoked = registry.save(AgentIdentity(name="revoked-bot", owner="ops", tenant_id=KNOWN_AGENT_TENANT))
    registry.set_lifecycle(revoked.agent_id, AgentLifecycleStatus.REVOKED)

    decisions = InMemoryDecisionStore()
    forbid = _decision(Verdict.FORBID)
    decisions.save(forbid)
    decisions.save(_decision(Verdict.PERMIT))
    decisions.save(_decision(Verdict.PERMIT))

    ledger = InMemoryActionLedger()
    ledger.append(_action(active.agent_id, "PERMIT"))
    ledger.append(_action(active.agent_id, "FORBID"))

    discovery = InMemoryDiscoveryLedger()
    for ext in ("ext-acme-1", "ext-acme-2"):
        cand = _candidate(KNOWN_AGENT_TENANT, ext)
        discovery.append(candidate=cand, outcome=_outcome(cand))
    other = _candidate("other", "ext-other-1")
    discovery.append(candidate=other, outcome=_outcome(other))

    recorder = EvidenceRecorder(path=str(tmp_path / "evidence.jsonl"))
    recorder.record_decision(forbid)

    drift = DriftEventStore()
    drift.emit(
        tenant_id=KNOWN_AGENT_TENANT,
        kind=DriftEventKind.NEW_AGENT,
        reconciliation_key="okta:acme:ext-acme-1",
        severity="WARN",
        summary="new agent discovered",
    )
    drift.emit(
        tenant_id="other",
        kind=DriftEventKind.AGENT_CHANGED,
        reconciliation_key="okta:other:ext-other-1",
        severity="INFO",
        summary="agent changed",
    )

    scans = ScanRunStore()
    scans.acquire(tenant_id=KNOWN_AGENT_TENANT, trigger="manual")

    state = SimpleNamespace(
        agent_registry=registry,
        decision_store=decisions,
        action_ledger=ledger,
        discovery_ledger=discovery,
        evidence_recorder=recorder,
        drift_event_store=drift,
        scan_run_store=scans,
        governance_snapshot_store=None,  # optional V15 store — exercises degrade path
    )
    state._known_agent_id = active.agent_id
    state._forbid_decision_id = forbid.decision_id
    return state


@pytest.fixture
def empty_state() -> SimpleNamespace:
    """app.state with no stores attached — every tool must degrade, not crash."""
    return SimpleNamespace()
