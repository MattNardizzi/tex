"""Phase 3 — the un-bypassable network PEP seals the SAME proof-carrying receipt
as the in-process gate. Exercises the REAL StandingGovernance PDP through the
PEP's decision-client layer (no HTTP needed): an unknown agent is FORBIDden by
the floor; a sealed running agent is PERMITted by the deep tier. Both seal an
offline-verifiable SealedFact(ENFORCEMENT) tagged source="network_pep".
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tex.domain.evaluation import EvaluationResponse
from tex.domain.verdict import Verdict
from tex.governance.standing import StandingGovernance
from tex.pep.decision_client import Decision, InProcessDecisionClient
from tex.pep.sealing import SealingDecisionClient
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind


class _EmptyRegistry:
    def get(self, _uid):
        return None

    def list_all(self):
        return []


class _Agent:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = "ACTIVE"
        self.capability_surface = None
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


class _PermitEvaluate:
    def execute(self, _request):
        return EvaluationResponse(
            decision_id=uuid4(),
            verdict=Verdict.PERMIT,
            confidence=0.9,
            final_score=0.05,
            reasons=["clean"],
            policy_version="test",
            evaluated_at=datetime.now(UTC),
        )


def test_pep_forbid_seals_blocked_receipt():
    ledger = SealedFactLedger()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())  # unknown agent -> floor FORBID
    client = SealingDecisionClient(InProcessDecisionClient(gov), ledger)

    result = client.decide(
        Decision(
            tenant="acme",
            action_type="rm_rf",
            content="rm -rf / --no-preserve-root",
            channel="api",
            environment="production",
        )
    )
    assert result.released is False
    assert len(client.records) == 1
    fact = client.records[0].fact
    assert fact.kind is SealedFactKind.ENFORCEMENT
    assert fact.detail["allowed"] is False
    assert fact.detail["outcome"] == "blocked"
    assert fact.detail["source"] == "network_pep"
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_pep_permit_seals_executed_receipt():
    ledger = SealedFactLedger()
    agent_id = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(agent_id)),
        evaluate_command=_PermitEvaluate(),
    )
    client = SealingDecisionClient(InProcessDecisionClient(gov), ledger)

    result = client.decide(
        Decision(
            tenant="acme",
            action_type="wire_transfer",
            content="pay vendor 100",
            channel="api",
            environment="production",
            agent_id=agent_id,
        )
    )
    assert result.released is True
    fact = client.records[0].fact
    assert fact.detail["allowed"] is True
    assert fact.detail["outcome"] == "executed"
    assert fact.detail["source"] == "network_pep"
    assert ledger.verify_chain()["intact"] is True
