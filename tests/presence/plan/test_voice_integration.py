"""End-to-end through voice_ask.answer_question with the planner flag on (stubbed).

Proves the live /v1/ask path: with a plan compiler configured on app.state, the
question is compiled → executed → sealed as a presence answer; with no compiler (or
an ungrounded plan) the deterministic pipeline runs UNCHANGED — the plan path only
ever adds coverage."""

from __future__ import annotations

import types

from tex.domain.agent import AgentIdentity
from tex.domain.verdict import Verdict
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.decision_store import InMemoryDecisionStore
from tex.voice import answer_forms, voice_ask


class _StubCompiler:
    def __init__(self, plan: Plan | None) -> None:
        self._plan = plan

    def compile(self, *, question, tenant, tool_catalog, ops=None, reference_now=None):
        return self._plan


def _req(**state_kw):
    state = types.SimpleNamespace(decision_store=InMemoryDecisionStore(), **state_kw)
    return types.SimpleNamespace(app=types.SimpleNamespace(state=state))


def _count_agents_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")


def test_planner_answers_a_non_canned_question_end_to_end():
    reg = InMemoryAgentRegistry()
    reg.save(AgentIdentity(name="alpha", owner="acme", tenant_id="acme"))
    reg.save(AgentIdentity(name="beta", owner="acme", tenant_id="acme"))
    req = _req(agent_registry=reg, presence_plan_compiler=_StubCompiler(_count_agents_plan()))

    out = voice_ask.answer_question(req, transcript="how many agents do I have", tenant="acme")

    assert out.verdict is Verdict.PERMIT
    assert out.answer == "There are 2 agents."
    assert out.routed_dimension == "presence"
    assert out.presence is not None and out.presence.verdicts
    assert out.presence.verdicts[0].tier.value == "sealed"
    assert out.attestation_anchor and len(out.attestation_anchor) == 64


def test_ungrounded_plan_falls_through_to_legacy_unchanged():
    # Compiler yields no plan → the plan path abstains → the deterministic pipeline
    # runs unchanged and produces the legacy fixed-decline for an unroutable question.
    req = _req(presence_plan_compiler=_StubCompiler(None))
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE


def test_no_compiler_is_byte_identical_to_legacy():
    req = _req()  # no presence_plan_compiler attached
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE
