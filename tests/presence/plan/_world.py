"""A realistic Tex 'world' for exercising the ask-anything engine end to end.

Built from the REAL in-memory stores + domain models, with varied owners, statuses,
trust tiers, providers, and TIMESTAMPS (registered today / days ago / weeks ago;
forbids/permits at various times; backdated evidence) so the full battery of questions
has real answers — counts, ownership, durations, time-windows ('added today', 'two
weeks ago'), forbids today, etc. Shared by the operator tests and the live battery.

The numbers are pinned in WORLD_FACTS so a test (or the independent verifier) can assert
the engine's answer against the ground truth.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from tex.domain.agent import (
    ActionLedgerEntry,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
)
from tex.domain.decision import Decision
from tex.domain.evidence import EvidenceRecord
from tex.domain.verdict import Verdict
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

TENANT = "acme"


def _ago(**kw) -> datetime:
    return datetime.now(UTC) - timedelta(**kw)


def _hex() -> str:
    return hashlib.sha256(str(uuid4()).encode()).hexdigest()


def _agent(name, owner, *, status=AgentLifecycleStatus.ACTIVE,
           trust=AgentTrustTier.STANDARD, provider=None, registered) -> AgentIdentity:
    return AgentIdentity(
        name=name, owner=owner, tenant_id=TENANT, lifecycle_status=status,
        trust_tier=trust, model_provider=provider,
        registered_at=registered, updated_at=registered,
    )


def _decision(verdict: Verdict, decided: datetime) -> Decision:
    flags = ["needs_human"] if verdict is Verdict.ABSTAIN else []
    return Decision(
        request_id=uuid4(), verdict=verdict, confidence=0.9, final_score=0.5,
        action_type="send_email", channel="email", environment="prod",
        content_excerpt="x", content_sha256=_hex(), policy_version="v1",
        uncertainty_flags=flags, decided_at=decided,
    )


def _action(agent_id, recorded: datetime) -> ActionLedgerEntry:
    return ActionLedgerEntry(
        agent_id=agent_id, decision_id=uuid4(), request_id=uuid4(), verdict="PERMIT",
        action_type="send_email", channel="email", environment="prod",
        final_score=0.2, confidence=0.9, content_sha256=_hex(), recorded_at=recorded,
    )


class _FakeRecorder:
    """Minimal evidence recorder exposing read_all()/last_record() over a hand-chained
    list with real (backdated) recorded_at — so evidence time-window questions have real
    answers (the real EvidenceRecorder timestamps at write-time and can't be backdated)."""

    def __init__(self, records):
        self._records = tuple(records)

    def read_all(self):
        return self._records

    def last_record(self):
        return self._records[-1] if self._records else None


def _evidence(n: int, *, recorded: datetime, prev: str | None) -> EvidenceRecord:
    payload = json.dumps({"i": n}, separators=(",", ":"))
    psha = hashlib.sha256(payload.encode()).hexdigest()
    rhash = hashlib.sha256((psha + (prev or "")).encode()).hexdigest()
    return EvidenceRecord(
        decision_id=uuid4(), request_id=uuid4(), record_type="decision",
        payload_json=payload, payload_sha256=psha, previous_hash=prev,
        record_hash=rhash, policy_version="v1", recorded_at=recorded,
    )


# Ground truth the engine's answers can be checked against.
WORLD_FACTS = {
    "agents_total": 6,
    "agents_by_owner": {"alice": 3, "bob": 2, "carol": 1},
    "agents_active": 4,                 # billing-bot, okta-sync, crm-writer (default ACTIVE), nightly-report
    "agents_revoked": 1,                # data-export
    "agents_quarantined": 1,            # slack-router
    "agents_registered_today": 2,       # billing-bot (3h), nightly-report (5h)
    "has_okta_agent": True,             # okta-sync
    "forbid_total": 3,
    "permit_total": 2,
    "abstain_total": 1,
    "forbid_today": 2,                  # 2h, 4h ago (the 15-day one is old)
    "evidence_total": 3,
    "evidence_today": 1,                # 2h ago (1 day + 14 day are older)
    "tenant": TENANT,
}


def build_world() -> SimpleNamespace:
    """A populated app.state-like object over the real stores. tenant = 'acme'."""
    registry = InMemoryAgentRegistry()
    agents = [
        _agent("billing-bot", "alice", registered=_ago(hours=3)),                       # today, ACTIVE
        _agent("okta-sync", "alice", provider="anthropic", registered=_ago(days=2)),    # ACTIVE
        _agent("slack-router", "alice", status=AgentLifecycleStatus.QUARANTINED, registered=_ago(days=14)),
        _agent("crm-writer", "bob", trust=AgentTrustTier.TRUSTED, registered=_ago(days=14)),
        _agent("data-export", "bob", status=AgentLifecycleStatus.REVOKED, registered=_ago(days=40)),
        _agent("nightly-report", "carol", registered=_ago(hours=5)),                    # today, ACTIVE
    ]
    for a in agents:
        registry.save(a)
    billing = agents[0]

    decisions = InMemoryDecisionStore()
    for verdict, decided in [
        (Verdict.FORBID, _ago(hours=2)), (Verdict.FORBID, _ago(hours=4)), (Verdict.FORBID, _ago(days=15)),
        (Verdict.PERMIT, _ago(hours=1)), (Verdict.PERMIT, _ago(days=3)),
        (Verdict.ABSTAIN, _ago(hours=6)),
    ]:
        decisions.save(_decision(verdict, decided))

    ledger = InMemoryActionLedger()
    for when in (_ago(hours=2), _ago(hours=3), _ago(days=5)):
        ledger.append(_action(billing.agent_id, when))

    recs, prev = [], None
    for i, when in enumerate((_ago(days=14), _ago(days=1), _ago(hours=2))):
        r = _evidence(i, recorded=when, prev=prev)
        recs.append(r)
        prev = r.record_hash
    recorder = _FakeRecorder(recs)

    return SimpleNamespace(
        agent_registry=registry,
        decision_store=decisions,
        action_ledger=ledger,
        evidence_recorder=recorder,
        discovery_ledger=InMemoryDiscoveryLedger(),
        scan_run_store=None,
        drift_event_store=None,
        connector_health_store=None,
        governance_snapshot_store=None,
        _billing_agent_id=billing.agent_id,
    )
