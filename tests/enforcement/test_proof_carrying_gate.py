"""Phase 0 — the brain↔body join proves itself.

Every gate allow/deny is sealed as a SealedFact(ENFORCEMENT) into the real
SealedFactLedger and is offline-verifiable. These exercise the REAL
StandingGovernance PDP (not a stub): an unknown agent is FORBIDden by the
structural floor; a sealed, running, in-surface agent is PERMITted by the deep
tier. The only doubles are the agent registry and the deep evaluator — the
decision *flow* (resolve → governable → surface → adjudicate → release → gate
blocks/runs → seal → verify) is all real.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationResponse
from tex.domain.verdict import Verdict
from tex.enforcement.errors import TexAbstainError, TexForbiddenError
from tex.enforcement.seal import build_proof_carrying_gate
from tex.governance.standing import StandingGovernance
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind


# --------------------------------------------------------------------------- doubles
class _EmptyRegistry:
    """No agents — every lookup misses, so the floor forbids on 'unknown agent'."""

    def get(self, _uid):
        return None

    def list_all(self):
        return []


class _Agent:
    """A minimal sealed, running, no-capability-surface agent."""

    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = "ACTIVE"
        self.capability_surface = None  # None -> floor surface check is skipped
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


def _response(verdict: Verdict) -> EvaluationResponse:
    return EvaluationResponse(
        decision_id=uuid4(),
        verdict=verdict,
        confidence=0.9 if verdict is Verdict.PERMIT else 0.4,
        final_score=0.05 if verdict is Verdict.PERMIT else 0.6,
        reasons=["clean"] if verdict is Verdict.PERMIT else ["uncertain"],
        uncertainty_flags=[] if verdict is not Verdict.ABSTAIN else ["needs_review"],
        policy_version="test",
        evaluated_at=datetime.now(UTC),
    )


class _Evaluate:
    """A deep-evaluator double that returns a fixed verdict."""

    def __init__(self, verdict: Verdict):
        self._verdict = verdict

    def execute(self, _request):
        return _response(self._verdict)


# --------------------------------------------------------------------------- tests
def test_forbid_blocks_callable_and_seals_verifiable_fact():
    ledger = SealedFactLedger()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())  # unknown agent -> floor FORBID
    gate, observer = build_proof_carrying_gate(gov, ledger=ledger, tenant="acme")

    ran = {"v": False}

    def danger(*, content):
        ran["v"] = True
        return "ran"

    guarded = gate.wrap(danger, content_arg="content", action_type="rm_rf")

    with pytest.raises(TexForbiddenError):
        guarded(content="rm -rf / --no-preserve-root")

    assert ran["v"] is False  # the callable provably did NOT run
    assert len(observer.records) == 1
    fact = observer.records[0].fact
    assert fact.kind is SealedFactKind.ENFORCEMENT
    assert fact.detail["allowed"] is False
    assert fact.detail["outcome"] == "blocked"
    assert fact.detail["verdict"] == "FORBID"
    # The sealed proof verifies offline against the ledger's own crypto.
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_permit_runs_and_seals_verifiable_fact():
    ledger = SealedFactLedger()
    agent_id = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(agent_id)),
        evaluate_command=_Evaluate(Verdict.PERMIT),
    )
    gate, observer = build_proof_carrying_gate(gov, ledger=ledger, tenant="acme")

    ran = {"v": False}

    def act(*, content):
        ran["v"] = True
        return "done"

    guarded = gate.wrap(act, content_arg="content", agent_id=agent_id, action_type="wire_transfer")

    assert guarded(content="pay vendor 100") == "done"
    assert ran["v"] is True
    assert len(observer.records) == 1
    fact = observer.records[0].fact
    assert fact.kind is SealedFactKind.ENFORCEMENT
    assert fact.detail["allowed"] is True
    assert fact.detail["outcome"] == "executed"
    assert fact.detail["verdict"] == "PERMIT"
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_abstain_blocks_and_seals():
    ledger = SealedFactLedger()
    agent_id = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(agent_id)),
        evaluate_command=_Evaluate(Verdict.ABSTAIN),
    )
    gate, observer = build_proof_carrying_gate(gov, ledger=ledger, tenant="acme")

    ran = {"v": False}

    def act(*, content):
        ran["v"] = True
        return "done"

    guarded = gate.wrap(act, content_arg="content", agent_id=agent_id, action_type="email")

    with pytest.raises(TexAbstainError):
        guarded(content="send the email")

    assert ran["v"] is False  # ABSTAIN is fail-closed: the action did not run
    fact = observer.records[0].fact
    assert fact.detail["outcome"] == "blocked"
    assert fact.detail["verdict"] == "ABSTAIN"


def test_tamper_breaks_the_chain():
    ledger = SealedFactLedger()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())
    gate, _observer = build_proof_carrying_gate(gov, ledger=ledger, tenant="acme")

    guarded = gate.wrap(lambda *, content: "ran", content_arg="content", action_type="x")
    with pytest.raises(TexForbiddenError):
        guarded(content="do the thing")

    assert ledger.verify_chain()["intact"] is True

    # Tamper: flip 'allowed' inside a sealed fact while keeping the old hashes.
    rec = ledger._entries[0]
    bad_fact = rec.fact.model_copy(update={"detail": {**rec.fact.detail, "allowed": True}})
    ledger._entries[0] = rec.model_copy(update={"fact": bad_fact})

    broken = ledger.verify_chain()
    assert broken["intact"] is False
    assert broken["break_at"] == 0


def test_attested_identity_is_sealed_into_the_fact():
    from tex.identity.agent_credential import AttestedIdentity

    ledger = SealedFactLedger()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())  # floor FORBID
    attested = AttestedIdentity(
        verified=True, status="verified", issuer="issuer-1", claimed_agent_id="agent-007"
    )
    gate, observer = build_proof_carrying_gate(
        gov, ledger=ledger, tenant="acme", attested_identity=attested
    )
    guarded = gate.wrap(lambda *, content: "ran", content_arg="content", action_type="x")
    with pytest.raises(TexForbiddenError):
        guarded(content="do the thing")

    fact = observer.records[0].fact
    att = fact.detail["identity_attestation"]
    assert att["verified"] is True
    assert att["issuer"] == "issuer-1"
    assert att["method"] == "ed25519_agent_card"
    assert "ATTESTED" in fact.claim
    assert ledger.verify_chain()["intact"] is True
