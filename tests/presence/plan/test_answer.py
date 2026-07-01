"""answer_with_plan: compile → execute → spoken envelope, reusing build_envelope.

Proves the plan path produces a real AnswerEnvelope whose spoken text is the gate-
authored phrasing, prosody is bound to the verdict tier, and an ungrounded plan
abstains to the templated answer — without ever speaking the model's words."""

from __future__ import annotations

from tex.presence.contract import PresenceTier
from tex.presence.plan.answer import answer_with_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan

_ABSTAIN = "I can't answer that from the records."


class _StubCompiler:
    """A compiler that returns a fixed plan (or None) — stands in for the LLM."""

    def __init__(self, plan: Plan | None) -> None:
        self._plan = plan

    def compile(self, *, question, tenant, tool_catalog, ops=None, reference_now=None):
        return self._plan


def _count_agents_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")


def _count_revoked_plan() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="f", kind=OpKind.FILTER, inputs=("a",),
           args={"field": "lifecycle_status", "op": "eq", "value": "REVOKED"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("f",)),
    ), output="n")


def test_grounded_plan_yields_sealed_envelope(populated_state):
    env = answer_with_plan(
        populated_state, transcript="how many agents do I have",
        tenant="acme", compiler=_StubCompiler(_count_agents_plan()),
        templated_abstain=_ABSTAIN,
    )
    assert "2" in env.spoken_text and "agents" in env.spoken_text
    assert env.verdicts and env.verdicts[0].tier is PresenceTier.SEALED
    assert env.prosody_plan.tier is PresenceTier.SEALED          # prosody bound to verdict
    assert env.verdicts[0].evidence                               # bound to real rows


def test_spoken_text_is_gate_authored_not_model_text(populated_state):
    """The compiler 'wanted' a plan; the spoken words come from the operator's
    canonical phrasing, never from the model. (Sanity: it reads like Tex, with the
    real recomputed number.)"""
    env = answer_with_plan(
        populated_state, transcript="count agents", tenant="acme",
        compiler=_StubCompiler(_count_agents_plan()), templated_abstain=_ABSTAIN,
    )
    assert env.spoken_text == "There are 2 agents."


def test_no_plan_abstains_to_templated(populated_state):
    env = answer_with_plan(
        populated_state, transcript="what's the weather", tenant="acme",
        compiler=_StubCompiler(None), templated_abstain=_ABSTAIN,
    )
    assert env.spoken_text == _ABSTAIN
    assert not env.verdicts
    assert env.prosody_plan.tier is PresenceTier.ABSTAIN


class _RaisingCompiler:
    """Stands in for the model being UNAVAILABLE (no credits / outage) — compile raises."""

    def compile(self, *, question, tenant, tool_catalog, ops=None, reference_now=None):
        raise RuntimeError("model unavailable")


def test_model_unavailable_returns_none_for_legacy_fallback(populated_state):
    # When the MODEL can't be reached, answer_with_plan returns None so the caller degrades
    # to the legacy path — it does NOT abstain (a model outage must not take the voice down).
    env = answer_with_plan(
        populated_state, transcript="how many agents do I have", tenant="acme",
        compiler=_RaisingCompiler(), templated_abstain=_ABSTAIN,
    )
    assert env is None


def test_zero_count_plan_speaks_a_sealed_none(populated_state):
    env = answer_with_plan(
        populated_state, transcript="how many revoked agents", tenant="acme",
        compiler=_StubCompiler(_count_revoked_plan()), templated_abstain=_ABSTAIN,
    )
    assert env.spoken_text.startswith("None")   # a sealed honest zero, not an abstain
    assert env.verdicts                          # grounded, witnessed by the full scan


def test_surface_object_carries_the_evidence(populated_state):
    env = answer_with_plan(
        populated_state, transcript="how many agents", tenant="acme",
        compiler=_StubCompiler(_count_agents_plan()), templated_abstain=_ABSTAIN,
    )
    assert env.surface_object and env.surface_object.get("claims")
    row = env.surface_object["claims"][0]
    assert row["tier"] == "sealed" and row["evidence"]
