"""C2 acceptance — EVERY decide() outcome carries a sealed evidence record.

Until now only verdicts that reached the DEEP six-layer PDP carried a
decision_id + evidence_hash and sealed a fact; the DETERMINISTIC FLOOR outcomes
(``_forbid_floor`` / ``_abstain_uninspectable``) sealed nothing and returned
``decision_id=None`` / ``evidence_hash=None`` — a large share of real traffic
(unknown / unsealed / out-of-surface / no-deep-PDP / deep-raised). This pins the
seam that closes that gap:

  * FLAG-ON: every floor FORBID and floor ABSTAIN seals one offline-verifiable
    ``SealedFact(ENFORCEMENT)`` onto the SAME ledger the deep path uses, and the
    returned outcome carries a minted decision_id + the record's hash;
  * the deep seal path is UNCHANGED (deep verdicts still carry the engine's
    decision_id, not a floor-minted one);
  * FLAG-OFF (no ledger): the floor seals nothing and returns None/None —
    byte-for-byte identical to today;
  * the floor record is HONEST — kind is ENFORCEMENT (not DECISION), it carries
    NO fabricated deep-evidence fields, and its claim says so in words;
  * sealing is fail-soft: it never suppresses the hold and never breaks the ruling.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tex.domain.agent import CapabilitySurface
from tex.domain.evaluation import EvaluationResponse
from tex.domain.verdict import Verdict
from tex.governance.standing import StandingGovernance
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind


# --------------------------------------------------------------------------- #
# Fakes (same idiom as tests/governance/test_opaque_abstain.py)               #
# --------------------------------------------------------------------------- #


class _Agent:
    def __init__(self, agent_id, *, surface=None, status="ACTIVE"):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = status
        self.capability_surface = surface
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


class _EmptyRegistry:
    def get(self, _uid):
        return None

    def list_all(self):
        return []


class _ListSink:
    def __init__(self):
        self.items: list = []

    def append(self, item):
        self.items.append(item)


def _evaluate(verdict):
    class _Eval:
        def execute(self, _request):
            return EvaluationResponse(
                decision_id=uuid4(),
                verdict=verdict,
                confidence=0.99,
                final_score=0.01,
                reasons=["deep"],
                policy_version="test",
                evaluated_at=datetime.now(UTC),
            )

    return _Eval()


# --------------------------------------------------------------------------- #
# 1. FLAG-ON floor FORBID seals a retrievable record                          #
# --------------------------------------------------------------------------- #


def test_flagon_floor_forbid_unknown_agent_seals():
    ledger = SealedFactLedger()
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=ledger,
    )
    out = gov.decide(
        tenant="acme",
        action_type="wire_transfer",
        content="send $48k",
        channel="api",
        environment="production",
        recipient="bank",
        agent_id=uuid4(),
    )
    assert out.verdict is Verdict.FORBID
    assert out.tier == "floor"
    assert out.forbid_scope == "identity"
    # The floor now carries a retrievable evidence record.
    assert out.decision_id is not None
    assert out.evidence_hash is not None
    assert len(ledger) == 1
    rec = ledger._entries[-1]
    assert rec.fact.kind is SealedFactKind.ENFORCEMENT
    assert rec.fact.detail["tier"] == "floor"
    assert rec.fact.detail["verdict"] == "FORBID"
    assert rec.fact.detail["forbid_scope"] == "identity"
    assert rec.fact.detail["decision_id"] == str(out.decision_id)
    assert rec.fact.detail["action_type"] == "wire_transfer"
    assert rec.fact.detail["tenant"] == "acme"
    # evidence_hash IS the real record hash-chain hash.
    assert out.evidence_hash == rec.record_hash
    # Offline-verifiable.
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_flagon_floor_forbid_all_scopes_seal():
    # surface (out-of-surface), lifecycle (revoked), deep_error (no deep PDP).
    cases = []

    # out-of-surface
    aid = uuid4()
    ledger = SealedFactLedger()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(
            _Agent(aid, surface=CapabilitySurface(allowed_action_types=("send_email",)))
        ),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=ledger,
    )
    out = gov.decide(
        tenant="acme",
        action_type="wire_transfer",
        content="x",
        agent_id=aid,
    )
    cases.append((out, ledger, "surface"))

    # lifecycle (revoked)
    aid = uuid4()
    ledger = SealedFactLedger()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid, status="REVOKED")),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=ledger,
    )
    out = gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=aid)
    cases.append((out, ledger, "lifecycle"))

    # deep_error (no deep PDP wired)
    aid = uuid4()
    ledger = SealedFactLedger()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid)),
        evaluate_command=None,
        decision_ledger=ledger,
    )
    out = gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=aid)
    cases.append((out, ledger, "deep_error"))

    for out, ledger, scope in cases:
        assert out.verdict is Verdict.FORBID, scope
        assert out.tier == "floor", scope
        assert out.forbid_scope == scope, scope
        assert out.decision_id is not None, scope
        assert out.evidence_hash is not None, scope
        assert len(ledger) == 1, scope
        rec = ledger._entries[-1]
        assert rec.fact.kind is SealedFactKind.ENFORCEMENT, scope
        assert rec.fact.detail["forbid_scope"] == scope, scope
        assert out.evidence_hash == rec.record_hash, scope


# --------------------------------------------------------------------------- #
# 2. FLAG-ON floor ABSTAIN seals                                              #
# --------------------------------------------------------------------------- #


def test_flagon_floor_abstain_seals_and_still_holds():
    ledger = SealedFactLedger()
    sink = _ListSink()
    aid = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid)),
        evaluate_command=_evaluate(Verdict.PERMIT),
        held_sink=sink,
        decision_ledger=ledger,
    )
    out = gov.decide(
        tenant="acme",
        action_type="http_opaque_body",
        content="opaque body",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=aid,
    )
    assert out.verdict is Verdict.ABSTAIN
    assert out.held is True
    assert out.released is False
    assert out.tier == "floor"
    # Sealed with a retrievable id + hash.
    assert out.decision_id is not None
    assert out.evidence_hash is not None
    assert len(ledger) == 1
    rec = ledger._entries[-1]
    assert rec.fact.kind is SealedFactKind.ENFORCEMENT
    assert rec.fact.detail["verdict"] == "ABSTAIN"
    assert rec.fact.detail["tier"] == "floor"
    assert rec.fact.detail["reason_code"] == "uninspectable_request_body"
    assert out.evidence_hash == rec.record_hash
    # Sealing did NOT suppress the hold.
    assert len(sink.items) == 1
    assert sink.items[0].kind == "http_opaque_body"


# --------------------------------------------------------------------------- #
# 3. Deep path STILL seals unchanged (engine's id, not a floor-minted one)    #
# --------------------------------------------------------------------------- #


def test_deep_permit_carries_engine_id_not_floor():
    ledger = SealedFactLedger()
    aid = uuid4()
    ev = _evaluate(Verdict.PERMIT)
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid)),
        evaluate_command=ev,
        decision_ledger=ledger,
    )
    out = gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=aid)
    assert out.verdict is Verdict.PERMIT
    assert out.tier == "deep"
    assert out.decision_id is not None
    # The floor seal helper did NOT run for a deep verdict, so no ENFORCEMENT
    # floor fact was appended by StandingGovernance for this ruling.
    assert len(ledger) == 0


def test_deep_forbid_does_not_floor_seal():
    ledger = SealedFactLedger()
    aid = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid)),
        evaluate_command=_evaluate(Verdict.FORBID),
        decision_ledger=ledger,
    )
    out = gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=aid)
    assert out.verdict is Verdict.FORBID
    assert out.tier == "deep"  # deep FORBID, not a floor block
    assert len(ledger) == 0  # the deep path seals via the PDP, not via _seal_floor


# --------------------------------------------------------------------------- #
# 4. FLAG-OFF seals nothing / inert (byte-for-byte today)                     #
# --------------------------------------------------------------------------- #


def test_flagoff_floor_forbid_is_inert():
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=None,
    )
    out = gov.decide(
        tenant="acme",
        action_type="wire_transfer",
        content="x",
        agent_id=uuid4(),
    )
    assert out.verdict is Verdict.FORBID
    assert out.tier == "floor"
    # Byte-for-byte today: no id, no hash.
    assert out.decision_id is None
    assert out.evidence_hash is None


def test_flagoff_floor_abstain_is_inert():
    sink = _ListSink()
    aid = uuid4()
    gov = StandingGovernance(
        agent_registry=_OneAgentRegistry(_Agent(aid)),
        evaluate_command=_evaluate(Verdict.PERMIT),
        held_sink=sink,
        decision_ledger=None,
    )
    out = gov.decide(
        tenant="acme",
        action_type="http_opaque_body",
        content="x",
        recipient="api.openai.com",
        agent_id=aid,
    )
    assert out.verdict is Verdict.ABSTAIN
    assert out.held is True
    assert out.decision_id is None
    assert out.evidence_hash is None
    # The hold still fires with the ledger off — unchanged behaviour.
    assert len(sink.items) == 1


def test_flagoff_jsonable_snapshot_unchanged():
    # The serialized outcome a default boot returns must be identical to today.
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        evaluate_command=_evaluate(Verdict.PERMIT),
    )  # decision_ledger defaults to None
    out = gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=uuid4())
    j = out.to_jsonable()
    assert j["verdict"] == str(Verdict.FORBID)
    assert j["tier"] == "floor"
    assert j["decision_id"] is None
    assert j["evidence_hash"] is None


# --------------------------------------------------------------------------- #
# 5. The floor record is HONEST (no fabricated deep chain)                     #
# --------------------------------------------------------------------------- #


def test_floor_record_is_honest_no_deep_fields():
    ledger = SealedFactLedger()
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=ledger,
    )
    gov.decide(tenant="acme", action_type="http_post", content="x", agent_id=uuid4())
    rec = ledger._entries[-1]
    fact = rec.fact
    # Correct kind — NOT a DECISION (which would corrupt L1/L3 invariants).
    assert fact.kind is SealedFactKind.ENFORCEMENT
    # No fabricated six-layer / deep adjudication fields.
    deep_only = {
        "final_score",
        "policy_id",
        "policy_version",
        "determinism_fingerprint",
        "content_sha256",
        "confidence",
    }
    assert deep_only.isdisjoint(fact.detail.keys())
    # The claim states it is deterministic and NOT a deep adjudication.
    assert "DETERMINISTIC" in fact.claim
    assert "NOT a six-layer" in fact.claim
    # No proof-carrying e-value is attached (the floor proves authorship+integrity only).
    assert fact.evidence is None


# --------------------------------------------------------------------------- #
# 6. Fail-soft: a ledger append failure never breaks the ruling               #
# --------------------------------------------------------------------------- #


def test_seal_failure_does_not_break_ruling(monkeypatch):
    ledger = SealedFactLedger()

    def _boom(_fact):
        raise RuntimeError("ledger down")

    monkeypatch.setattr(ledger, "append", _boom)
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        evaluate_command=_evaluate(Verdict.PERMIT),
        decision_ledger=ledger,
    )
    out = gov.decide(
        tenant="acme",
        action_type="wire_transfer",
        content="x",
        agent_id=uuid4(),
    )
    # The ruling is unaffected; the evidence_hash falls back to None.
    assert out.verdict is Verdict.FORBID
    assert out.released is False
    assert out.tier == "floor"
    assert out.evidence_hash is None
