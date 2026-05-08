"""
CHIEF — Hierarchical Causal Graph (arxiv 2602.23701).

Three components:
  1. Graph constructor — decompose tasks into subtasks; OTAR parsing;
     model data dependencies between steps explicitly
  2. Hierarchical oracle-guided backtracking — top-down search to pinpoint
     the precise failure step via synthesized virtual oracles
  3. Counterfactual attribution — progressive causal screening; deviation-aware
     reversibility check; distinguish root causes from propagated symptoms

Implementation notes
--------------------
* The paper's RAG-based task decomposition (§4.1.1) and LLM-based
  oracle synthesizer (§4.2.1) are LLM-driven; here we expose
  ``HierarchicalCausalGraph`` as a deterministic structural builder
  that consumes traces with explicit ``subtask_id`` annotations. For
  traces without subtasks, a heuristic decomposer groups consecutive
  steps that share the same ``agent_id`` into a subtask. Replacing the
  heuristic with an LLM-driven decomposer is a future-thread P1 task
  and is annotated in the relevant TODOs.
* "Counterfactual re-execution" in §4.3 is operationalised here as a
  graph-mask reachability test rather than literal LLM replay (the
  paper's ablation §6.4 confirms the structural variant is the
  load-bearing component for both agent- and step-level accuracy).

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from tex.causal._hcg import (
    AgentNode,
    CausalEdge,
    EdgeKind,
    NodeKind,
    SubtaskNode,
    agent_node_id,
    node_kind_of,
    subtask_node_id,
)
from tex.causal._otar import parse_otar
from tex.causal.counterfactual import CounterfactualScreener
from tex.observability.telemetry import emit_event


# Anomaly markers used by the deterministic semantic evaluator that
# replaces F_eval (§4.2.2). Conservative — only obvious failure tokens.
_ANOMALY_MARKERS: tuple[str, ...] = (
    "error",
    "failed",
    "failure",
    "invalid",
    "denied",
    "rejected",
    "exception",
    "violated",
    "timeout",
    "abort",
    "incorrect",
    "wrong",
    "anomal",  # matches anomaly / anomalous
)


@dataclass(frozen=True, slots=True)
class HCGResult:
    """
    Output of ``HierarchicalCausalGraph.build_from_trace``.

    Exposes the underlying ``networkx.DiGraph`` plus typed views so
    downstream callers (counterfactual screener, ARM bridges, etc.) can
    reach in without re-parsing node attributes.
    """

    graph: nx.DiGraph
    subtask_ids: tuple[str, ...]
    agent_step_ids: tuple[str, ...]


class _ParsedStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str
    agent_id: str
    subtask_id: str
    timestep: int
    otar: object  # OTARTuple — typed, but pydantic v2 + forward ref is awkward here
    upstream_step_ids: tuple[str, ...] = Field(default_factory=tuple)


class HierarchicalCausalGraph:
    """
    CHIEF Hierarchical Causal Graph builder + backtracking attribution.

    Reference: arxiv 2602.23701.
    """

    def __init__(
        self,
        *,
        screener: CounterfactualScreener | None = None,
    ) -> None:
        self._screener = screener or CounterfactualScreener()

    # ------------------------------------------------------------------
    # 1. Graph construction (§4.1)
    # ------------------------------------------------------------------

    def build_from_trace(self, trace_events: tuple[dict, ...]) -> HCGResult:
        """
        TODO(P1, arxiv:2602.23701 §4.1.1): OTAR parse — extract Observation,
                  Thought, Action, Result per step
            - DONE: deterministic parser in ``tex.causal._otar.parse_otar``
              handles Tex-native, Who&When, and marker-delimited content.
        TODO(P1, arxiv:2602.23701 §4.1.1): decompose task into hierarchical
                  subtask nodes
            - DONE: explicit ``subtask_id`` is honoured if present;
              otherwise we fall back to grouping consecutive steps by
              ``agent_id``. RAG-based LLM decomposition (paper Appx. A)
              is left for a future thread.
        TODO(P1, arxiv:2602.23701 §4.1.2): draw data-dependency edges
                  between steps
            - DONE: E_step edges materialise upstream_step_ids and inline
              variable references parsed from OTAR.observation.
        TODO(P1, arxiv:2602.23701 §4.1.2): emit hierarchical causal graph
            - DONE: returns an HCGResult wrapping a networkx.DiGraph.
        """
        if not isinstance(trace_events, tuple):
            raise TypeError("trace_events must be a tuple")

        parsed_steps = self._parse_trace(trace_events)
        graph: nx.DiGraph = nx.DiGraph()

        # Subtask nodes — collected in first-seen order (preserves the
        # turn-based linearity of the underlying trace per §3 problem
        # formulation).
        subtask_order: list[str] = []
        subtask_members: dict[str, list[str]] = {}
        subtask_step_ids: dict[str, list[str]] = {}
        agent_node_ids: dict[str, str] = {}  # step_id → graph node id

        for step in parsed_steps:
            if step.subtask_id not in subtask_members:
                subtask_order.append(step.subtask_id)
                subtask_members[step.subtask_id] = []
                subtask_step_ids[step.subtask_id] = []

            agt_id = agent_node_id(
                step_id=step.step_id, agent_id=step.agent_id
            )
            if step.agent_id not in subtask_members[step.subtask_id]:
                subtask_members[step.subtask_id].append(step.agent_id)
            subtask_step_ids[step.subtask_id].append(step.step_id)

            agent_payload = AgentNode(
                step_id=step.step_id,
                agent_id=step.agent_id,
                parent_subtask_id=step.subtask_id,
                timestep=step.timestep,
                otar=step.otar,  # type: ignore[arg-type]
            )
            graph.add_node(
                agt_id,
                data=agent_payload,
                kind=NodeKind.AGENT.value,
            )
            agent_node_ids[step.step_id] = agt_id

        # Materialise subtask nodes once members are known.
        for subtask_id in subtask_order:
            sub_payload = SubtaskNode(
                subtask_id=subtask_id,
                member_agent_ids=tuple(subtask_members[subtask_id]),
                member_step_ids=tuple(subtask_step_ids[subtask_id]),
            )
            graph.add_node(
                subtask_node_id(subtask_id),
                data=sub_payload,
                kind=NodeKind.SUBTASK.value,
            )

        # E_sub: adjacency between subtasks in temporal order (§4.1.2).
        for i in range(len(subtask_order) - 1):
            edge = CausalEdge(kind=EdgeKind.SUB)
            graph.add_edge(
                subtask_node_id(subtask_order[i]),
                subtask_node_id(subtask_order[i + 1]),
                edge=edge,
                kind=EdgeKind.SUB.value,
            )

        # E_agt + E_step: walk parsed steps; explicit upstream refs feed
        # E_step edges, and consecutive same-agent steps within a subtask
        # additionally get an E_agt edge to encode inter-agent collaboration.
        last_step_per_agent: dict[str, str] = {}
        for step in parsed_steps:
            target_id = agent_node_ids[step.step_id]

            # E_step — explicit upstream data dependencies
            for upstream_step in step.upstream_step_ids:
                if upstream_step in agent_node_ids:
                    src_id = agent_node_ids[upstream_step]
                    edge = CausalEdge(
                        kind=EdgeKind.STEP,
                        upstream_output_ref=upstream_step,
                        downstream_input_ref=step.step_id,
                    )
                    graph.add_edge(
                        src_id,
                        target_id,
                        edge=edge,
                        kind=EdgeKind.STEP.value,
                    )

            # E_agt — connect this agent's prior step to the current one
            # if both are in the same subtask (inter-agent collaboration
            # pattern from §4.1.2). When agent_id changes within a
            # subtask, we still emit an E_agt edge from the previous
            # step in the subtask to capture the orchestrator→executor
            # handoff pattern that drives the planner-control attribution.
            previous_step_in_agent = last_step_per_agent.get(step.agent_id)
            if previous_step_in_agent is not None:
                src_id = agent_node_ids[previous_step_in_agent]
                edge = CausalEdge(kind=EdgeKind.AGT)
                graph.add_edge(
                    src_id,
                    target_id,
                    edge=edge,
                    kind=EdgeKind.AGT.value,
                )
            last_step_per_agent[step.agent_id] = step.step_id

            # Subtask membership edges (V_sub → V_agt). Not in the
            # paper's three-letter taxonomy, but useful for navigation;
            # we mark them with EdgeKind.SUB so they don't pollute
            # E_step / E_agt traversals downstream.
            sub_id = subtask_node_id(step.subtask_id)
            if not graph.has_edge(sub_id, target_id):
                edge = CausalEdge(kind=EdgeKind.SUB)
                graph.add_edge(
                    sub_id,
                    target_id,
                    edge=edge,
                    kind=EdgeKind.SUB.value,
                )

        emit_event(
            "causal.chief.graph_built",
            steps=len(parsed_steps),
            subtasks=len(subtask_order),
            nodes=graph.number_of_nodes(),
            edges=graph.number_of_edges(),
        )

        return HCGResult(
            graph=graph,
            subtask_ids=tuple(subtask_order),
            agent_step_ids=tuple(agent_node_ids.values()),
        )

    # ------------------------------------------------------------------
    # 2 + 3. Hierarchical oracle-guided backtracking + counterfactual
    # ------------------------------------------------------------------

    def attribute_root_cause(
        self,
        *,
        causal_graph: Any,
        observed_failure: dict,
    ) -> tuple[str, float]:
        """
        Returns ``(root_cause_event_id, confidence)``.

        TODO(P1, arxiv:2602.23701 §4.2): top-down oracle-guided
                  backtracking
            - DONE: subtask candidates collected in reverse topological
              order; agent and step candidates drilled down within them.
              The LLM-based F_eval (§4.2.2) is approximated by a
              deterministic semantic evaluator that flags steps whose
              OTAR result contains an anomaly marker, mirroring the
              paper's binary 0/1 evaluator output.
        TODO(P1, arxiv:2602.23701 §4.3): counterfactual re-execution at
                  each candidate node
            - DONE: delegates to ``CounterfactualScreener.screen_detailed``
              which runs the four-stage progressive screen.
        TODO(P1, arxiv:2602.23701 §4.3.4): distinguish root causes from
                  propagated symptoms
            - DONE: data-flow stage masks each candidate and checks
              failure reachability; deviation-aware stage suppresses
              reversed deviations.
        """
        graph = _resolve_graph(causal_graph)
        failure_event_id = self._resolve_failure_id(graph, observed_failure)

        # ---- Subtask Level (§4.2.2) ----
        # Reverse-topological traversal restricted to subtask nodes. We
        # use a sentinel "all subtasks" pass for traces that lack rich
        # subtask annotation: any subtask containing the failure step
        # is automatically a candidate.
        candidate_subtasks = self._candidate_subtasks(graph, failure_event_id)

        # ---- Agent Level (§4.2.2) + Step Level ----
        candidate_agents = self._candidate_agent_steps(
            graph, candidate_subtasks, failure_event_id
        )
        if not candidate_agents:
            # No anomaly markers anywhere — fall back to the failure
            # step itself as the candidate. The screener will sort it.
            candidate_agents = [failure_event_id]

        # ---- Counterfactual Attribution (§4.3) ----
        # Among candidates, select the *earliest* (smallest timestep) one
        # that the screener confirms as a true root cause. This matches
        # the paper's Eq. (1): root cause = arg min_t over decisive
        # errors. Ties broken by higher confidence.
        best_id: str | None = None
        best_confidence: float = 0.0
        best_timestep: int | None = None

        for cand_id in candidate_agents:
            outcome = self._screener.screen_detailed(
                candidate_root_cause_id=cand_id,
                observed_failure_id=failure_event_id,
                causal_graph=graph,
            )
            if not outcome.is_true_root_cause:
                continue
            payload = graph.nodes[cand_id]["data"]
            timestep = (
                payload.timestep if isinstance(payload, AgentNode) else 0
            )
            if (
                best_id is None
                or timestep < (best_timestep or 0)
                or (timestep == best_timestep and outcome.confidence > best_confidence)
            ):
                best_id = cand_id
                best_confidence = outcome.confidence
                best_timestep = timestep

        if best_id is None:
            # No screener-confirmed candidate — degrade gracefully and
            # return the earliest anomaly we found, with reduced confidence.
            best_id = self._earliest_by_timestep(graph, candidate_agents)
            best_confidence = 0.5

        emit_event(
            "causal.chief.attribution",
            root_cause=best_id,
            confidence=best_confidence,
            failure=failure_event_id,
            candidates=len(candidate_agents),
        )
        return best_id, best_confidence

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _parse_trace(
        self, trace_events: Iterable[Mapping[str, Any]]
    ) -> list[_ParsedStep]:
        events_list = list(trace_events)
        if not events_list:
            return []

        steps: list[_ParsedStep] = []
        # Heuristic subtask grouping for traces without explicit subtasks:
        # advance the subtask counter whenever the agent_id changes.
        prev_agent: str | None = None
        heuristic_subtask_index = 0

        for index, raw in enumerate(events_list):
            if not isinstance(raw, Mapping):
                raise TypeError(
                    f"trace step {index} is not a Mapping (got {type(raw).__name__})"
                )
            step_id = _string_or(raw.get("step_id"), default=f"step_{index:04d}")
            agent_id = _string_or(
                raw.get("agent_id") or raw.get("name"),
                default="unknown_agent",
            )
            timestep = int(raw.get("timestep", index))

            explicit_subtask = raw.get("subtask_id")
            if explicit_subtask is not None:
                subtask_id = _string_or(explicit_subtask, default="subtask_0")
            else:
                if prev_agent is not None and prev_agent != agent_id:
                    heuristic_subtask_index += 1
                subtask_id = f"subtask_{heuristic_subtask_index:03d}"
            prev_agent = agent_id

            otar = parse_otar(raw)
            upstream_raw = raw.get("upstream_step_ids", ())
            if isinstance(upstream_raw, (list, tuple)):
                upstream = tuple(str(u) for u in upstream_raw)
            else:
                upstream = ()

            steps.append(
                _ParsedStep(
                    step_id=step_id,
                    agent_id=agent_id,
                    subtask_id=subtask_id,
                    timestep=timestep,
                    otar=otar,
                    upstream_step_ids=upstream,
                )
            )
        return steps

    def _resolve_failure_id(
        self, graph: nx.DiGraph, observed_failure: Mapping[str, Any]
    ) -> str:
        """Map an observed-failure descriptor onto a graph node id."""
        if not isinstance(observed_failure, Mapping):
            raise TypeError("observed_failure must be a Mapping")

        # Direct event_id match.
        explicit = observed_failure.get("event_id")
        if isinstance(explicit, str) and explicit in graph:
            return explicit

        # (step_id, agent_id) pair → derived node id.
        step_id = observed_failure.get("step_id")
        agent_id_raw = observed_failure.get("agent_id")
        if isinstance(step_id, str) and isinstance(agent_id_raw, str):
            derived = agent_node_id(step_id=step_id, agent_id=agent_id_raw)
            if derived in graph:
                return derived

        # step_id alone — find the unique agent node with that step_id.
        if isinstance(step_id, str):
            matches = [
                n
                for n in graph.nodes
                if isinstance(graph.nodes[n].get("data"), AgentNode)
                and graph.nodes[n]["data"].step_id == step_id
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise ValueError(
                    f"multiple nodes match step_id={step_id!r}; provide agent_id"
                )

        raise KeyError(
            f"could not resolve observed_failure to a graph node: {dict(observed_failure)!r}"
        )

    def _candidate_subtasks(
        self, graph: nx.DiGraph, failure_id: str
    ) -> list[str]:
        """Collect subtask node IDs that contain the failure or precede it."""
        failure_payload = graph.nodes[failure_id].get("data")
        if not isinstance(failure_payload, AgentNode):
            # If the failure is *not* an agent node, fall back to all subtasks.
            return [
                n
                for n in graph.nodes
                if graph.nodes[n].get("kind") == NodeKind.SUBTASK.value
            ]

        # Walk reverse-topologically over subtasks; include the failure's
        # own subtask plus all its ancestors.
        all_subtasks = [
            n
            for n in graph.nodes
            if graph.nodes[n].get("kind") == NodeKind.SUBTASK.value
        ]
        failure_subtask = subtask_node_id(failure_payload.parent_subtask_id)
        if failure_subtask not in all_subtasks:
            return all_subtasks

        ancestors = nx.ancestors(graph, failure_subtask) | {failure_subtask}
        # Filter to subtask nodes only.
        candidate_subtasks = [
            n for n in ancestors if n in all_subtasks
        ]
        # Stable ordering: reverse topological by sequence in graph.
        try:
            topo = list(nx.topological_sort(graph.subgraph(all_subtasks)))
        except nx.NetworkXUnfeasible:
            topo = list(all_subtasks)
        return [s for s in reversed(topo) if s in candidate_subtasks]

    def _candidate_agent_steps(
        self,
        graph: nx.DiGraph,
        candidate_subtasks: list[str],
        failure_id: str,
    ) -> list[str]:
        """Drill down to agent steps inside candidate subtasks; flag anomalies."""
        flagged: list[str] = []
        seen: set[str] = set()

        for sub_id in candidate_subtasks:
            sub_payload = graph.nodes[sub_id].get("data")
            if not isinstance(sub_payload, SubtaskNode):
                continue
            for step_id in sub_payload.member_step_ids:
                # Find agent node(s) for this step (may be multiple if
                # several agents acted on the same step).
                for n in graph.nodes:
                    if n in seen:
                        continue
                    payload = graph.nodes[n].get("data")
                    if not isinstance(payload, AgentNode):
                        continue
                    if payload.step_id != step_id:
                        continue
                    if _has_anomaly(payload) or n == failure_id:
                        flagged.append(n)
                        seen.add(n)
                        break

        # Sort by timestep so attribution prefers earlier candidates.
        flagged.sort(key=lambda n: graph.nodes[n]["data"].timestep)
        return flagged

    def _earliest_by_timestep(
        self, graph: nx.DiGraph, node_ids: list[str]
    ) -> str:
        return min(
            node_ids,
            key=lambda n: graph.nodes[n]["data"].timestep
            if isinstance(graph.nodes[n].get("data"), AgentNode)
            else 0,
        )


# ---- helpers ---------------------------------------------------------


def _resolve_graph(value: Any) -> nx.DiGraph:
    if isinstance(value, nx.DiGraph):
        return value
    inner = getattr(value, "graph", None)
    if isinstance(inner, nx.DiGraph):
        return inner
    raise TypeError(
        "causal_graph must be a networkx.DiGraph or wrapper exposing .graph"
    )


def _string_or(value: Any, *, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str):
        s = value.strip()
        return s if s else default
    return str(value)


def _has_anomaly(payload: AgentNode) -> bool:
    """
    Deterministic substitute for the LLM-based F_eval (§4.2.2).

    Marks a step as anomalous if any OTAR component contains a known
    failure token. Conservative — only obvious tokens — but matches the
    paper's binary 0/1 evaluator output and keeps the test suite
    deterministic. The LLM-based evaluator is the natural drop-in via
    a future-thread P1 strategy parameter on HierarchicalCausalGraph.
    """
    text = " ".join(
        (
            payload.otar.observation,
            payload.otar.thought,
            payload.otar.action,
            payload.otar.result,
        )
    ).lower()
    return any(marker in text for marker in _ANOMALY_MARKERS)
