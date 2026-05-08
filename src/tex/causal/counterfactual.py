"""
Counterfactual screener — CHIEF §4.3 progressive causal screening.

Reference: arxiv 2602.23701 §4.3 (Counterfactual Attribution),
                          §4.3.1 Local Attribution,
                          §4.3.2 Planning-Control Attribution,
                          §4.3.3 Data-Flow Attribution,
                          §4.3.4 Deviation-Aware Attribution.

The screener disentangles error-propagation paths and decides whether a
candidate failure step is the *true root cause* or a *propagated
symptom*. Stages run in a strict order:

  1. Local Attribution
       If the candidate has no upstream causal trigger, the error
       originated at the candidate → root cause is local.
  2. Planning-Control Attribution
       For loop groups (cycles in agent edges), distinguish planner
       responsibility (orchestrator emits identical thoughts under
       repeated errors) from executor responsibility.
  3. Data-Flow Attribution
       Reconstruct the error-propagation path along ``E_step`` edges,
       walk backwards along ``upstream_output_ref`` snapshots, and pin
       the *first* step that corrupted valid upstream input.
  4. Deviation-Aware Attribution (reversibility)
       If a later step re-satisfies the oracle criteria after the
       suspect step, the deviation is reversible and the candidate is
       NOT a root cause (paper §4.3.4 — "we prioritize the attribution
       to irreversible errors").

Priority: P1.
"""

from __future__ import annotations

from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict

from tex.causal._hcg import (
    AgentNode,
    EdgeKind,
    NodeKind,
    coerce_node_payload,
)
from tex.observability.telemetry import emit_event


class ScreeningOutcome(BaseModel):
    """
    Detailed result of one screening pass. Returned alongside the legacy
    ``(bool, float)`` API so downstream consumers can branch on stage
    without reparsing the rationale string.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_true_root_cause: bool
    confidence: float
    stage: str  # "local" | "planning_control" | "data_flow" | "deviation_aware"
    rationale: str


class CounterfactualScreener:
    """Progressive causal screener per CHIEF §4.3."""

    def screen(
        self,
        *,
        candidate_root_cause_id: str,
        observed_failure_id: str,
        causal_graph: dict,
    ) -> tuple[bool, float]:
        """
        Returns ``(is_true_root_cause, confidence)``.

        TODO(P1, arxiv:2602.23701 §4.3): re-execute the trace with the
                  candidate node masked
            - DONE: implemented as graph-mask reachability (we do not
              re-run the LLM; the paper's counterfactual is operationalised
              as a structural ablation per §4.3.1).
        TODO(P1, arxiv:2602.23701 §4.3): compare resulting outcome to
                  observed failure
            - DONE: a candidate is a true root cause iff the failure
              becomes unreachable from any source node when the
              candidate is removed (Local + Data-Flow stages).
        TODO(P1, arxiv:2602.23701 §4.3.4): apply deviation-aware
                  reversibility check
            - DONE: if a later AGENT node on a path from candidate to
              failure has ``otar.result`` indicating recovery, the
              deviation is deemed reversible.
        """
        outcome = self.screen_detailed(
            candidate_root_cause_id=candidate_root_cause_id,
            observed_failure_id=observed_failure_id,
            causal_graph=causal_graph,
        )
        return outcome.is_true_root_cause, outcome.confidence

    def screen_detailed(
        self,
        *,
        candidate_root_cause_id: str,
        observed_failure_id: str,
        causal_graph: Any,
    ) -> ScreeningOutcome:
        """
        Full 4-stage progressive screen (see module docstring).

        Accepts either a raw ``networkx.DiGraph`` or a wrapper whose
        ``.graph`` attribute holds the underlying nx graph (matching the
        return shape of ``HierarchicalCausalGraph.build_from_trace``).
        """
        graph = _resolve_graph(causal_graph)

        if candidate_root_cause_id not in graph:
            raise KeyError(
                f"candidate node {candidate_root_cause_id!r} not in graph"
            )
        if observed_failure_id not in graph:
            raise KeyError(
                f"observed failure node {observed_failure_id!r} not in graph"
            )

        # --- Stage 1: Local Attribution (§4.3.1) --------------------
        # S_cause = {x' ∈ Pre(x) | Bias(x') →Φ Anomaly(x)}.
        # Pragmatic structural proxy: if the candidate has no incoming
        # causal edges of any kind from another agent step, the error
        # is local — there were no upstream triggers to propagate from.
        upstream = list(graph.predecessors(candidate_root_cause_id))
        upstream_agents = [
            uid
            for uid in upstream
            if _is_agent_node(graph, uid)
        ]

        if not upstream_agents:
            # Local — but we still need the deviation-aware reversibility
            # check (§4.3.4) before declaring the candidate a root cause.
            if _is_reversible(
                graph,
                suspect_id=candidate_root_cause_id,
                failure_id=observed_failure_id,
            ):
                emit_event(
                    "causal.screen.reversible",
                    candidate=candidate_root_cause_id,
                    stage="local",
                )
                return ScreeningOutcome(
                    is_true_root_cause=False,
                    confidence=0.4,
                    stage="deviation_aware",
                    rationale="local error self-corrected downstream",
                )
            return ScreeningOutcome(
                is_true_root_cause=True,
                confidence=0.95,
                stage="local",
                rationale="no upstream causal trigger; error originates at candidate",
            )

        # --- Stage 2: Planning-Control Attribution (§4.3.2) ---------
        # Detect loop groups via simple cycles on the agent-edge subgraph;
        # if the candidate participates in a cycle, attribute to planner
        # vs executor by inspecting OTAR thoughts/actions.
        loop_attribution = _planning_control_attribution(
            graph, candidate_root_cause_id
        )
        if loop_attribution is not None:
            stage_label, rationale, confidence = loop_attribution
            reversible = _is_reversible(
                graph,
                suspect_id=candidate_root_cause_id,
                failure_id=observed_failure_id,
            )
            if reversible:
                return ScreeningOutcome(
                    is_true_root_cause=False,
                    confidence=0.4,
                    stage="deviation_aware",
                    rationale="loop deviation self-corrected downstream",
                )
            return ScreeningOutcome(
                is_true_root_cause=True,
                confidence=confidence,
                stage=stage_label,
                rationale=rationale,
            )

        # --- Stage 3: Data-Flow Attribution (§4.3.3) ----------------
        # Walk E_step edges in reverse from the candidate to find the
        # earliest step whose result was the first divergence. The
        # paper's structural test: if removing the candidate disconnects
        # the failure node from its source, the candidate caused the
        # failure; otherwise the candidate is a downstream propagator.
        masked = graph.copy()
        masked.remove_node(candidate_root_cause_id)
        still_reachable = (
            observed_failure_id in masked
            and any(
                nx.has_path(masked, src, observed_failure_id)
                for src in _trace_sources(masked)
            )
        )
        if still_reachable:
            emit_event(
                "causal.screen.propagator",
                candidate=candidate_root_cause_id,
                failure=observed_failure_id,
            )
            return ScreeningOutcome(
                is_true_root_cause=False,
                confidence=0.7,
                stage="data_flow",
                rationale="failure remains reachable when candidate masked; downstream propagator",
            )

        # --- Stage 4: Deviation-Aware reversibility (§4.3.4) --------
        if _is_reversible(
            graph,
            suspect_id=candidate_root_cause_id,
            failure_id=observed_failure_id,
        ):
            return ScreeningOutcome(
                is_true_root_cause=False,
                confidence=0.5,
                stage="deviation_aware",
                rationale="deviation reversed by downstream recovery step",
            )

        return ScreeningOutcome(
            is_true_root_cause=True,
            confidence=0.85,
            stage="data_flow",
            rationale="failure unreachable when candidate masked; irreversible",
        )


# ---- helpers ---------------------------------------------------------


def _resolve_graph(value: Any) -> nx.DiGraph:
    """Accept either a raw nx.DiGraph or an HCG wrapper with ``.graph``."""
    if isinstance(value, nx.DiGraph):
        return value
    inner = getattr(value, "graph", None)
    if isinstance(inner, nx.DiGraph):
        return inner
    raise TypeError(
        "causal_graph must be a networkx.DiGraph or wrapper exposing .graph"
    )


def _is_agent_node(graph: nx.DiGraph, node_id: str) -> bool:
    kind = graph.nodes[node_id].get("kind")
    return kind == NodeKind.AGENT.value


def _trace_sources(graph: nx.DiGraph) -> list[str]:
    """Return all in-degree-zero AGENT nodes (entry points to the trace)."""
    return [
        n
        for n in graph.nodes
        if graph.in_degree(n) == 0 and _is_agent_node(graph, n)
    ]


# Heuristic markers indicating a step recovered the system into a valid
# state. Conservative — we only treat unambiguous tokens as recovery.
_RECOVERY_MARKERS: tuple[str, ...] = (
    "recovered",
    "succeeded",
    "success",
    "ok",
    "passed",
    "resolved",
    "verified",
)


def _is_reversible(
    graph: nx.DiGraph,
    *,
    suspect_id: str,
    failure_id: str,
) -> bool:
    """
    §4.3.4 reversibility check.

    Walks descendants of the suspect that are temporally between suspect
    and failure (by ``timestep`` on the AgentNode payload) and returns
    True if any such intermediate step's OTAR result contains a recovery
    marker. The check is intentionally conservative: only AGENT nodes
    are inspected, and the marker set is small.
    """
    suspect_payload = graph.nodes.get(suspect_id, {}).get("data")
    failure_payload = graph.nodes.get(failure_id, {}).get("data")
    if not isinstance(suspect_payload, AgentNode):
        return False
    if not isinstance(failure_payload, AgentNode):
        return False

    suspect_t = suspect_payload.timestep
    failure_t = failure_payload.timestep
    if failure_t <= suspect_t:
        return False

    # Successors of suspect — bounded walk.
    descendants = nx.descendants(graph, suspect_id)
    for desc_id in descendants:
        if desc_id == failure_id:
            continue
        payload = graph.nodes[desc_id].get("data")
        if not isinstance(payload, AgentNode):
            continue
        if not (suspect_t < payload.timestep < failure_t):
            continue
        result_text = payload.otar.result.lower()
        if any(marker in result_text for marker in _RECOVERY_MARKERS):
            return True
    return False


def _planning_control_attribution(
    graph: nx.DiGraph,
    candidate_id: str,
) -> tuple[str, str, float] | None:
    """
    §4.3.2 — distinguish planner vs executor on loop groups.

    Returns ``(stage_label, rationale, confidence)`` if the candidate
    participates in an agent-edge cycle, else ``None``. Loop detection
    is restricted to cycles among agent nodes connected by ``EdgeKind.AGT``
    edges — that is the paper's "loop group" notion.
    """
    candidate_payload = coerce_node_payload(graph.nodes[candidate_id]["data"])
    if not isinstance(candidate_payload, AgentNode):
        return None

    # Build the agent-edge-only subgraph.
    agt_edges = [
        (u, v)
        for u, v, data in graph.edges(data=True)
        if data.get("edge") is not None
        and data["edge"].kind is EdgeKind.AGT
    ]
    if not agt_edges:
        return None
    agt_subgraph = graph.edge_subgraph(agt_edges).copy()

    # Find a cycle containing the candidate, if any.
    try:
        cycles = list(nx.simple_cycles(agt_subgraph))
    except nx.NetworkXNoCycle:
        return None
    candidate_cycles = [c for c in cycles if candidate_id in c]
    if not candidate_cycles:
        return None

    cycle = candidate_cycles[0]

    # Inspect OTAR thoughts of agents in the cycle: if multiple
    # iterations share identical thoughts/actions despite errors, it's
    # planner failure (orchestrator stuck); if thoughts vary while
    # results stay anomalous, it's executor failure.
    thoughts: list[str] = []
    actions: list[str] = []
    for node_id in cycle:
        payload = graph.nodes[node_id].get("data")
        if isinstance(payload, AgentNode):
            thoughts.append(payload.otar.thought.strip())
            actions.append(payload.otar.action.strip())

    distinct_thoughts = len({t for t in thoughts if t})
    distinct_actions = len({a for a in actions if a})

    if distinct_thoughts <= 1 and len(thoughts) >= 2:
        return (
            "planning_control",
            "loop with identical planner thoughts under repeated errors → planner fault",
            0.8,
        )
    if distinct_actions <= 1 and len(actions) >= 2:
        return (
            "planning_control",
            "loop with identical executor actions under repeated errors → executor fault",
            0.8,
        )
    # Plan changes but loop persists → executor cannot break out.
    return (
        "planning_control",
        "loop persists despite planner re-strategy → executor fault",
        0.7,
    )
