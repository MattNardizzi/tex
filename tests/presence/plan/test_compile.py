"""The PlanCompiler: provider payload → validated Plan, or None → abstain.

Driven by a STUB provider (the StructuredSemanticProvider protocol is just
``analyze(*, system_prompt, user_prompt) -> Mapping``), so the full compile path is
verified deterministically without a live model call."""

from __future__ import annotations

from typing import Any

from tex.presence.plan.compile import (
    PROPOSE_PLAN_TOOL_NAME,
    PlanCompiler,
    build_plan_system_prompt,
    plan_tool_schema,
)
from tex.presence.plan.executor import IMPLEMENTED_OPS, execute_plan
from tex.presence.plan.ir import OpKind

_CATALOG = {"identity.list_agents": "List agents (params: status, include_revoked, limit)."}


class _Stub:
    """A provider that returns a fixed payload (or raises)."""

    def __init__(self, payload: Any = None, *, raises: bool = False) -> None:
        self._payload = payload
        self._raises = raises

    def analyze(self, *, system_prompt: str, user_prompt: str) -> Any:
        if self._raises:
            raise RuntimeError("provider boom")
        return self._payload


_VALID_PLAN = {
    "nodes": [
        {"node_type": "leaf", "node_id": "a", "tool": "identity.list_agents", "params": {}},
        {"node_type": "op", "node_id": "n", "kind": "count", "inputs": ["a"], "args": {}},
    ],
    "output": "n",
}


def _compile(payload, *, raises=False):
    c = PlanCompiler(provider=_Stub(payload, raises=raises))
    return c.compile(question="how many agents", tenant="acme", tool_catalog=_CATALOG)


def test_valid_payload_compiles_to_plan():
    plan = _compile(_VALID_PLAN)
    assert plan is not None and plan.output == "n" and len(plan.nodes) == 2


def test_no_provider_returns_none():
    assert PlanCompiler(provider=None).compile(
        question="x", tenant="acme", tool_catalog=_CATALOG) is None


def test_provider_exception_propagates_for_legacy_fallback():
    # A model/transport error PROPAGATES out of compile() so the caller can degrade to the
    # legacy path; it is NOT swallowed to None (which would conflate 'model down' with 'no
    # answer' and make a model outage abstain on everything).
    import pytest

    with pytest.raises(RuntimeError):
        _compile(None, raises=True)


def test_non_mapping_payload_returns_none():
    assert _compile("not a plan") is None
    assert _compile(None) is None


def test_unknown_tool_fails_closed_validation():
    bad = {
        "nodes": [
            {"node_type": "leaf", "node_id": "a", "tool": "evil.tool", "params": {}},
            {"node_type": "op", "node_id": "n", "kind": "count", "inputs": ["a"], "args": {}},
        ],
        "output": "n",
    }
    assert _compile(bad) is None


def test_operator_outside_the_offered_set_fails_closed():
    # Every OpKind now has an implementation, so closed-world is enforced by the OFFERED
    # set: an op not in the ops handed to compile is rejected (drops to abstain).
    bad = {
        "nodes": [
            {"node_type": "leaf", "node_id": "a", "tool": "identity.list_agents", "params": {}},
            {"node_type": "op", "node_id": "g", "kind": "group_by", "inputs": ["a"], "args": {"field": "owner"}},
        ],
        "output": "g",
    }
    c = PlanCompiler(provider=_Stub(bad))
    assert c.compile(question="x", tenant="acme", tool_catalog=_CATALOG,
                     ops=frozenset({OpKind.COUNT})) is None


def test_compiled_plan_executes_end_to_end(populated_state):
    """The whole pipeline: stub 'model' compiles a plan → executor recomputes it →
    grounded answer from the real rows."""
    plan = _compile(_VALID_PLAN)
    rc = execute_plan(plan, request=populated_state, tenant="acme")
    assert rc.grounded and rc.value == 2  # populated_state has 2 acme agents


def test_system_prompt_lists_only_the_offered_ops():
    prompt = build_plan_system_prompt(_CATALOG, frozenset({OpKind.COUNT, OpKind.FILTER}))
    assert "identity.list_agents" in prompt
    # check the op-CATALOG lines ("  - <op>: ...") so incidental mentions don't match
    assert "- count:" in prompt and "- filter:" in prompt
    assert "- group_by:" not in prompt and "- latest:" not in prompt  # not offered → not catalogued


def test_plan_tool_schema_is_a_usable_object_schema():
    schema = plan_tool_schema()
    assert isinstance(schema, dict)
    assert "properties" in schema and "nodes" in schema["properties"]
    assert "output" in schema["properties"]
    assert PROPOSE_PLAN_TOOL_NAME  # name constant present for strict tool-use wiring
