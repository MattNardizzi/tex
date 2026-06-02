"""
Tests for tex.causal.chief — HierarchicalCausalGraph.

Covers
------
* OTAR parsing for Tex-native, Who&When, and marker-delimited traces
* HCG construction over a 50-step seeded-fault trace with explicit
  subtask annotations
* Three-tier backtracking (subtask → agent → step) per CHIEF §4.2.2
* Counterfactual root-cause attribution: chooses the *earliest* decisive
  error step per Eq. (1) of the paper, not the symptom
* Edge taxonomy: E_sub, E_agt, E_step are all materialised
* Resolves observed_failure by event_id, by (step_id, agent_id), and by
  bare step_id; raises on ambiguity / missing
"""

from __future__ import annotations

import pytest

from tex.causal._hcg import (
    AgentNode,
    EdgeKind,
    NodeKind,
    SubtaskNode,
    agent_node_id,
    subtask_node_id,
)
from tex.causal._otar import OTARTuple, parse_otar
from tex.causal.chief import HCGResult, HierarchicalCausalGraph


# ---------- OTAR parsing ----------------------------------------------


def test_otar_native_keys() -> None:
    step = {
        "observation": "user query",
        "thought": "decompose",
        "action": "delegate",
        "result": "ok",
    }
    otar = parse_otar(step)
    assert otar.observation == "user query"
    assert otar.thought == "decompose"
    assert otar.action == "delegate"
    assert otar.result == "ok"


def test_otar_who_and_when_assistant() -> None:
    """Who&When-style assistant turn maps to thought + action."""
    step = {
        "role": "assistant",
        "name": "Excel_Expert",
        "content": "Let me analyze the spreadsheet.",
    }
    otar = parse_otar(step)
    assert otar.thought == "Let me analyze the spreadsheet."
    assert otar.action == "Let me analyze the spreadsheet."
    assert otar.observation == ""


def test_otar_who_and_when_user() -> None:
    """Who&When user/tool turn maps to observation + result."""
    step = {
        "role": "user",
        "name": "Computer_terminal",
        "content": "exitcode: 0\nstdout: 42",
    }
    otar = parse_otar(step)
    assert otar.observation.startswith("exitcode: 0")
    assert otar.result.startswith("exitcode: 0")


def test_otar_marker_delimited() -> None:
    content = (
        "Observation: file=foo.txt\n"
        "Thought: I should read it\n"
        "Action: read_file(foo.txt)\n"
        "Result: file contents loaded"
    )
    otar = parse_otar({"content": content})
    assert otar.observation == "file=foo.txt"
    assert otar.thought == "I should read it"
    assert otar.action == "read_file(foo.txt)"
    assert otar.result == "file contents loaded"


def test_otar_marker_overrides_role() -> None:
    """Markers in content trump the assistant/user heuristic."""
    step = {
        "role": "assistant",
        "content": "Action: tool_x()\nResult: 200 OK",
    }
    otar = parse_otar(step)
    assert otar.action == "tool_x()"
    assert otar.result == "200 OK"


def test_otar_falls_back_to_action() -> None:
    """Plain free text with no markers becomes action."""
    otar = parse_otar({"content": "just some prose"})
    assert otar.action == "just some prose"
    assert otar.observation == ""


def test_otar_empty_step() -> None:
    otar = parse_otar({})
    assert otar == OTARTuple()


# ---------- HCG construction ------------------------------------------


def _make_50_step_trace() -> tuple[dict, ...]:
    """
    50-step trace across 5 subtasks and 3 agents.

    Layout:
      subtask=plan       (steps 0..4,  agent=planner)
      subtask=fetch      (steps 5..14, agents=planner, fetcher)
      subtask=transform  (steps 15..29, agents=fetcher, transformer)  ← seeded fault at step 22
      subtask=chart      (steps 30..44, agents=transformer, charter) ← propagated symptoms
      subtask=summary    (steps 45..49, agent=summary_writer)        ← final failure at step 49

    Steps 22..29 produce results containing 'error' or 'invalid' tokens —
    propagating downstream from the seeded fault.
    """
    trace: list[dict] = []

    def add(step_id: str, agent: str, subtask: str, t: int, otar: dict, upstream: tuple[str, ...] = ()) -> None:
        trace.append({
            "step_id": step_id,
            "agent_id": agent,
            "subtask_id": subtask,
            "timestep": t,
            **otar,
            "upstream_step_ids": upstream,
        })

    # plan (0..4)
    for i in range(5):
        add(
            f"s{i:02d}", "planner", "plan", i,
            {
                "observation": "user request",
                "thought": "decompose",
                "action": "emit plan",
                "result": "ok",
            },
            upstream=(f"s{i-1:02d}",) if i > 0 else (),
        )

    # fetch (5..14)
    for i in range(5, 15):
        add(
            f"s{i:02d}",
            "fetcher" if i % 2 else "planner",
            "fetch", i,
            {
                "observation": "fetch task",
                "thought": "query db",
                "action": f"sql_select(t{i})",
                "result": "rows ready",
            },
            upstream=(f"s{i-1:02d}",),
        )

    # transform (15..29) — seed fault at step 22
    for i in range(15, 30):
        if i == 22:
            otar = {
                "observation": "rows received",
                "thought": "apply transform",
                "action": "wrong_aggregation()",
                "result": "ERROR: invalid aggregation, schema mismatch",
            }
        elif 22 < i:
            # propagated taint
            otar = {
                "observation": "bad rows from upstream",
                "thought": "continue transform",
                "action": "next_op()",
                "result": "error: cannot recover from upstream invalid input",
            }
        else:
            otar = {
                "observation": "rows received",
                "thought": "apply transform",
                "action": "transform_op()",
                "result": "transformed ok",
            }
        add(
            f"s{i:02d}",
            "transformer" if i >= 18 else "fetcher",
            "transform", i, otar,
            upstream=(f"s{i-1:02d}",),
        )

    # chart (30..44) — propagated symptoms continue
    for i in range(30, 45):
        otar = {
            "observation": "bad data",
            "thought": "render chart anyway",
            "action": "chart()",
            "result": "error: cannot render with invalid data",
        }
        add(
            f"s{i:02d}",
            "charter" if i >= 35 else "transformer",
            "chart", i, otar,
            upstream=(f"s{i-1:02d}",),
        )

    # summary (45..49) — final failure node
    for i in range(45, 50):
        if i == 49:
            otar = {
                "observation": "everything is broken",
                "thought": "report failure",
                "action": "emit_summary()",
                "result": "FAILED: pipeline did not complete",
            }
        else:
            otar = {
                "observation": "failures upstream",
                "thought": "compose summary",
                "action": "summarise()",
                "result": "error: missing chart",
            }
        add(
            f"s{i:02d}", "summary_writer", "summary", i, otar,
            upstream=(f"s{i-1:02d}",),
        )

    assert len(trace) == 50
    return tuple(trace)


@pytest.fixture
def trace_50() -> tuple[dict, ...]:
    return _make_50_step_trace()


def test_build_from_trace_produces_correct_node_count(trace_50: tuple[dict, ...]) -> None:
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    assert isinstance(result, HCGResult)
    # 50 agent nodes + 5 subtask nodes
    assert result.graph.number_of_nodes() == 55
    assert result.subtask_ids == ("plan", "fetch", "transform", "chart", "summary")


def test_build_from_trace_two_tier_node_taxonomy(trace_50: tuple[dict, ...]) -> None:
    """Verify V = V_sub ∪ V_agt per §4.1.1."""
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    subtask_count = 0
    agent_count = 0
    for node_id, attrs in result.graph.nodes(data=True):
        kind = attrs["kind"]
        payload = attrs["data"]
        if kind == NodeKind.SUBTASK.value:
            assert isinstance(payload, SubtaskNode)
            subtask_count += 1
        elif kind == NodeKind.AGENT.value:
            assert isinstance(payload, AgentNode)
            agent_count += 1
        else:
            pytest.fail(f"unknown node kind: {kind}")
    assert subtask_count == 5
    assert agent_count == 50


def test_build_from_trace_three_edge_kinds(trace_50: tuple[dict, ...]) -> None:
    """Verify E = E_sub ∪ E_agt ∪ E_step per §4.1.2."""
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    edge_kinds: set[EdgeKind] = set()
    for _, _, data in result.graph.edges(data=True):
        edge_kinds.add(data["edge"].kind)

    # All three edge tiers should be represented in a 50-step multi-agent trace.
    assert EdgeKind.SUB in edge_kinds
    assert EdgeKind.AGT in edge_kinds
    assert EdgeKind.STEP in edge_kinds


def test_e_step_edges_carry_explicit_data_refs(trace_50: tuple[dict, ...]) -> None:
    """§4.1.2: step edges record exact upstream output / downstream input refs."""
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    step_edges = [
        (u, v, data["edge"])
        for u, v, data in result.graph.edges(data=True)
        if data["edge"].kind is EdgeKind.STEP
    ]
    assert step_edges, "expected at least one E_step edge"
    for _, _, edge in step_edges:
        assert edge.upstream_output_ref is not None
        assert edge.downstream_input_ref is not None


def test_subtask_node_membership(trace_50: tuple[dict, ...]) -> None:
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    # transform subtask should hold steps s15..s29 = 15 members
    transform_node = result.graph.nodes[subtask_node_id("transform")]
    payload = transform_node["data"]
    assert isinstance(payload, SubtaskNode)
    assert len(payload.member_step_ids) == 15
    assert "s22" in payload.member_step_ids


# ---------- Root-cause attribution ------------------------------------


def test_attribute_root_cause_finds_seeded_fault(trace_50: tuple[dict, ...]) -> None:
    """
    Per CHIEF Eq. (1): root cause = arg min_t over decisive errors.

    Seeded fault at step s22 should be returned, not any of the
    propagated symptoms at s23..s49.
    """
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    root_id, confidence = hcg.attribute_root_cause(
        causal_graph=result,
        observed_failure={"step_id": "s49", "agent_id": "summary_writer"},
    )
    assert root_id == agent_node_id(step_id="s22", agent_id="transformer")
    assert 0.5 <= confidence <= 1.0


def test_attribute_root_cause_with_event_id(trace_50: tuple[dict, ...]) -> None:
    """observed_failure may use the graph node id directly as 'event_id'."""
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    failure_node = agent_node_id(step_id="s49", agent_id="summary_writer")
    root_id, _ = hcg.attribute_root_cause(
        causal_graph=result,
        observed_failure={"event_id": failure_node},
    )
    assert root_id == agent_node_id(step_id="s22", agent_id="transformer")


def test_attribute_root_cause_unknown_failure_raises(trace_50: tuple[dict, ...]) -> None:
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(trace_50)

    with pytest.raises(KeyError):
        hcg.attribute_root_cause(
            causal_graph=result,
            observed_failure={"step_id": "does_not_exist"},
        )


def test_attribute_root_cause_with_raw_digraph() -> None:
    """attribute_root_cause must accept a raw nx.DiGraph too."""
    hcg = HierarchicalCausalGraph()
    trace = (
        {"step_id": "a", "agent_id": "p", "timestep": 0,
         "observation": "x", "thought": "t", "action": "do",
         "result": "ok"},
        {"step_id": "b", "agent_id": "p", "timestep": 1,
         "observation": "x", "thought": "t", "action": "do",
         "result": "error: failed", "upstream_step_ids": ("a",)},
    )
    result = hcg.build_from_trace(trace)
    root_id, _ = hcg.attribute_root_cause(
        causal_graph=result.graph,  # raw DiGraph
        observed_failure={"step_id": "b"},
    )
    assert root_id == agent_node_id(step_id="b", agent_id="p")


# ---------- Edge cases -------------------------------------------------


def test_empty_trace_yields_empty_graph() -> None:
    hcg = HierarchicalCausalGraph()
    result = hcg.build_from_trace(())
    assert result.graph.number_of_nodes() == 0
    assert result.subtask_ids == ()


def test_trace_without_explicit_subtasks_uses_heuristic() -> None:
    """When subtask_id is missing, consecutive same-agent steps share a subtask."""
    hcg = HierarchicalCausalGraph()
    trace = (
        {"step_id": "1", "agent_id": "a", "timestep": 0,
         "action": "x", "result": "ok"},
        {"step_id": "2", "agent_id": "a", "timestep": 1,
         "action": "y", "result": "ok"},
        {"step_id": "3", "agent_id": "b", "timestep": 2,
         "action": "z", "result": "ok"},
    )
    result = hcg.build_from_trace(trace)
    # Two heuristic subtasks: agent 'a' (steps 1,2) and agent 'b' (step 3)
    assert len(result.subtask_ids) == 2


def test_trace_events_must_be_tuple() -> None:
    hcg = HierarchicalCausalGraph()
    with pytest.raises(TypeError):
        hcg.build_from_trace([{"step_id": "x"}])  # type: ignore[arg-type]
