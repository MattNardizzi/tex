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


def test_ungrounded_plan_gives_honest_abstain_not_legacy_canned():
    # When the planner is engaged but can't ground, it returns an HONEST decline — it must
    # NOT fall through to a legacy canned dimension answer (the confidently-wrong demo
    # behaviour). This is the fix for the live-run finding ('0 of 0 high-risk agents...').
    req = _req(presence_plan_compiler=_StubCompiler(None))
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert "don't have" in out.answer.lower()
    assert out.answer != answer_forms.ABSTAIN_NO_ROUTE  # not the legacy canned path


def test_no_compiler_is_byte_identical_to_legacy():
    req = _req()  # no presence_plan_compiler attached
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE


def _latest_action_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="execution.recent_actions"),
        Op(node_id="l", kind=OpKind.LATEST, inputs=("a",), args={"ordering_field": "recorded_at"}),
        Op(node_id="g", kind=OpKind.GET, inputs=("l",), args={"field": "action_type"}),
    ), output="g")


def test_grounded_single_record_plan_object_is_a_value_kind_handle():
    # A single sealed-record answer (LATEST→GET) yields the {value, kind} handle the
    # /v1/ask `object` field promises — read off the bound sealed evidence — NOT the rich
    # {"claims": ...} surface_object (which would 500 ObjectDTO at the route). This pins the
    # source-side fix; the HTTP serialization is pinned in tests/voice/test_voice_routes_http.
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4
    import hashlib

    from tex.domain.agent import ActionLedgerEntry
    from tex.stores.action_ledger import InMemoryActionLedger

    led = InMemoryActionLedger()
    for h in (1, 2):
        led.append(ActionLedgerEntry(
            agent_id=uuid4(), decision_id=uuid4(), request_id=uuid4(), verdict="PERMIT",
            action_type="send_email", channel="email", environment="prod",
            final_score=0.2, confidence=0.9,
            content_sha256=hashlib.sha256(uuid4().hex.encode()).hexdigest(),
            recorded_at=datetime.now(UTC) - timedelta(hours=h),
        ))
    req = _req(action_ledger=led, presence_plan_compiler=_StubCompiler(_latest_action_plan()))

    out = voice_ask.answer_question(req, transcript="what was the last action sealed", tenant="acme")

    assert out.verdict is Verdict.PERMIT
    assert out.object is not None
    assert set(out.object) == {"value", "kind"}  # exactly the ObjectDTO shape — never {"claims": ...}
    assert out.object["kind"] == "hash"
    assert len(out.object["value"]) == 64
    # The bound sealed evidence is the source of the handle (honest, not fabricated).
    assert out.object["value"] == out.presence.verdicts[0].evidence[0].record_hash


def test_grounded_aggregate_plan_has_no_handle():
    # A COUNT (or any multi-row aggregate) has no single thing to grab → object is None,
    # mirroring answer_forms ("a count is meaning, not a handle"). Never a surface_object.
    reg = InMemoryAgentRegistry()
    reg.save(AgentIdentity(name="alpha", owner="acme", tenant_id="acme"))
    reg.save(AgentIdentity(name="beta", owner="acme", tenant_id="acme"))
    req = _req(agent_registry=reg, presence_plan_compiler=_StubCompiler(_count_agents_plan()))

    out = voice_ask.answer_question(req, transcript="how many agents do I have", tenant="acme")

    assert out.verdict is Verdict.PERMIT
    assert out.answer == "There are 2 agents."
    assert out.object is None  # the count's many witness refs are not a single graspable handle


def _duration_action_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="execution.recent_actions"),
        Op(node_id="l", kind=OpKind.LATEST, inputs=("a",), args={"ordering_field": "recorded_at"}),
        Op(node_id="d", kind=OpKind.DURATION, inputs=("l",), args={"field": "recorded_at"}),
    ), output="d")


def _list_agents_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="ls", kind=OpKind.LIST, inputs=("a",), args={"field": "name", "limit": 3}),
    ), output="ls")


def _exists_agents_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="e", kind=OpKind.EXISTS, inputs=("a",), args={}),
    ), output="e")


def test_plan_object_is_never_a_bad_shape_across_op_types():
    # THE SHAPE INVARIANT (the real contract): for EVERY grounded plan, AskOutcome.object is
    # either None or exactly {value:<64-hex sha256>, kind:"hash"} — NEVER the {"claims": ...}
    # surface_object or any other shape that would 500 ObjectDTO. Exercised over a populated
    # world across the distinct evidence-cardinality + value-type cases the single helper
    # predicate (exactly-one-ref + is_sha256_hex) must handle. Fills the per-op coverage gap.
    from types import SimpleNamespace

    from ._world import build_world

    def _run(plan, transcript):
        world = build_world()
        world.presence_plan_compiler = _StubCompiler(plan)
        req = SimpleNamespace(app=SimpleNamespace(state=world))
        return voice_ask.answer_question(req, transcript=transcript, tenant="acme")

    cases = {
        "duration": _run(_duration_action_plan(), "how long ago was the last action"),  # 1 ref → hash
        "list": _run(_list_agents_plan(), "list three agents"),                          # many refs → None
        "exists": _run(_exists_agents_plan(), "do I have any agents"),                    # bool, 1 witness ref
        "count": _run(_count_agents_plan(), "how many agents"),                           # many refs → None
        "latest_get": _run(_latest_action_plan(), "what was the last action"),            # 1 ref → hash
    }

    for name, out in cases.items():
        assert out.verdict is Verdict.PERMIT, f"{name} should ground over the populated world"
        obj = out.object
        # The invariant that makes the 500 structurally impossible: None, or exactly the
        # ObjectDTO shape with a provably-real SHA-256 value.
        assert obj is None or (set(obj) == {"value", "kind"} and obj["kind"] == "hash"
                               and len(obj["value"]) == 64), f"{name} produced a bad object: {obj!r}"

    # The doctrine, pinned per op: a single-record answer surfaces its sealed record's hash...
    assert cases["duration"].object is not None and cases["duration"].object["kind"] == "hash"
    assert cases["latest_get"].object is not None
    # ...a multi-row aggregate has no single thing to grab → None ("a count is meaning").
    assert cases["list"].object is None
    assert cases["count"].object is None
    # ...and a boolean EXISTS surfaces its sole sealed WITNESS (decision A: honest witness, not
    # a claim of "the only" record — the full evidence set still rides the presence envelope).
    ex = cases["exists"].object
    assert ex is not None and ex["value"] == cases["exists"].presence.verdicts[0].evidence[0].record_hash


class _RaisingCompiler:
    def compile(self, *, question, tenant, tool_catalog, ops=None, reference_now=None):
        raise RuntimeError("model unavailable (e.g. no credits)")


def test_model_unavailable_falls_through_to_legacy():
    # Planner engaged but the model is unreachable → degrade to the legacy deterministic path,
    # NOT a presence abstain. A model outage must never take /v1/ask down or make it go dark.
    req = _req(presence_plan_compiler=_RaisingCompiler())
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE  # legacy path, not "I don't have..."
