"""
AgentArmor Graph Constructor.

Reference: arxiv 2508.01249 (Wang et al., ByteDance), §III-A.

Converts agent runtime traces into program-dependence graph IR. Each event
in the trace is decomposed into typed nodes per the paper's node taxonomy:

    - SystemMessage (system prompt)
    - UserMessage (user instruction)
    - ModelMessage (LLM thought / reasoning step)
    - ToolName (which tool is being called)
    - ToolParam (parameters bound to that call)
    - Tool (the tool execution itself)
    - Observation (tool return value)

CFG (Control Flow Graph): temporal/logical sequence of agent steps. Default
    edges follow temporal order. Each Action node is decomposed into
    ToolName + ToolParam children of the preceding Thought (ModelMessage).

DFG (Data Flow Graph): built on CFG by EXCLUDING LLM and Thought nodes (they
    are not data-bearing). Connects ToolName + ToolParam -> Tool nodes (data
    flowing INTO the tool), and Tool -> Observation -> next ToolParam (data
    flowing out and into subsequent calls).

PDG (Program Dependence Graph): union of CFG control edges and DFG data
    edges, annotated by edge type. This is what the type system operates on.

Priority: P1.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event, get_logger

_logger = get_logger("tex.runtime.agentarmor.graph")


class NodeKind(str, Enum):
    """Typed node taxonomy per AgentArmor §III-A."""

    SYSTEM = "system"
    USER = "user"
    MODEL = "model"  # LLM thought / reasoning
    TOOL_NAME = "tool_name"
    TOOL_PARAM = "tool_param"
    TOOL = "tool"
    OBSERVATION = "observation"


class EdgeKind(str, Enum):
    """Edge taxonomy: control vs. data dependencies."""

    CONTROL = "control"  # temporal / logical successor
    DATA = "data"  # value flows from src to dst
    DECOMPOSE = "decompose"  # parent -> typed child (Thought -> ToolName)


class TraceEvent(BaseModel):
    """One event in an agent runtime trace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int = Field(ge=0)
    kind: str  # "system" | "user" | "model" | "action" | "observation"
    content: str = ""
    tool_name: str | None = None
    tool_params: dict[str, Any] | None = None
    observation: str | None = None
    source: str = "agent"  # "agent" | "external" | "user" — used for taint root


class GraphIR(BaseModel):
    """Container for the constructed graphs.

    Holds three networkx DiGraphs sharing the same node ids. Pydantic is
    only used here for the declarative typed shape; the graphs themselves
    are mutated in place during construction.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    cfg: nx.DiGraph
    dfg: nx.DiGraph
    pdg: nx.DiGraph
    node_attrs: dict[str, dict[str, Any]]


class GraphConstructor:
    """Builds CFG, DFG, and PDG from a runtime trace.

    Implementation faithfully follows AgentArmor §III-A.2 node decomposition:
    the Action event (a tool call) is decomposed into a ToolName child and
    one ToolParam child per parameter, all hung under the immediately
    preceding ModelMessage (Thought) node. The Tool node is the actual call;
    Observation is its return value.
    """

    def build_pdg(self, trace_events: tuple[dict, ...] | tuple[TraceEvent, ...]) -> GraphIR:
        """Build CFG, DFG, and PDG over a runtime trace.

        Accepts either dict events (legacy) or TraceEvent (preferred).
        """
        events: list[TraceEvent] = []
        for e in trace_events:
            if isinstance(e, TraceEvent):
                events.append(e)
            else:
                events.append(TraceEvent.model_validate(e))

        cfg = nx.DiGraph()
        dfg = nx.DiGraph()
        node_attrs: dict[str, dict[str, Any]] = {}

        prev_cfg_node: str | None = None
        last_thought: str | None = None
        last_tool_node: str | None = None
        # Track ALL prior observations so any later tool_param can be
        # data-flow-linked to any earlier observation whose content it
        # references. This is essential for AgentArmor's taint propagation
        # across the full trajectory: observations from an external source
        # may be used many turns later by the agent.
        prior_observations: list[str] = []

        for ev in events:
            step = ev.step

            if ev.kind == "system":
                nid = self._add_node(cfg, dfg, node_attrs, step, NodeKind.SYSTEM, ev,
                                     content=ev.content)
                self._link_control(cfg, prev_cfg_node, nid)
                prev_cfg_node = nid

            elif ev.kind == "user":
                nid = self._add_node(cfg, dfg, node_attrs, step, NodeKind.USER, ev,
                                     content=ev.content)
                self._link_control(cfg, prev_cfg_node, nid)
                prev_cfg_node = nid

            elif ev.kind == "model":
                nid = self._add_node(cfg, dfg, node_attrs, step, NodeKind.MODEL, ev,
                                     content=ev.content)
                self._link_control(cfg, prev_cfg_node, nid)
                prev_cfg_node = nid
                last_thought = nid

            elif ev.kind == "action":
                if not ev.tool_name:
                    raise ValueError(f"action event at step {step} missing tool_name")

                tname_id = self._add_node(
                    cfg, dfg, node_attrs, step, NodeKind.TOOL_NAME, ev,
                    tool_name=ev.tool_name,
                )
                if last_thought is not None:
                    cfg.add_edge(last_thought, tname_id, kind=EdgeKind.DECOMPOSE.value)

                param_ids: list[str] = []
                for p_name, p_val in (ev.tool_params or {}).items():
                    pid = self._add_node(
                        cfg, dfg, node_attrs, step, NodeKind.TOOL_PARAM, ev,
                        param_name=p_name, param_value=p_val,
                        tool_name=ev.tool_name,
                    )
                    if last_thought is not None:
                        cfg.add_edge(last_thought, pid, kind=EdgeKind.DECOMPOSE.value)
                    param_ids.append(pid)

                tool_id = self._add_node(
                    cfg, dfg, node_attrs, step, NodeKind.TOOL, ev,
                    tool_name=ev.tool_name,
                )
                self._link_control(cfg, prev_cfg_node, tool_id)

                # DFG: tool_name + each tool_param → tool (data flow into tool).
                dfg.add_node(tname_id, **node_attrs[tname_id])
                dfg.add_node(tool_id, **node_attrs[tool_id])
                dfg.add_edge(tname_id, tool_id, kind=EdgeKind.DATA.value)
                for pid in param_ids:
                    dfg.add_node(pid, **node_attrs[pid])
                    dfg.add_edge(pid, tool_id, kind=EdgeKind.DATA.value)

                # If any prior Observation's content appears in any
                # tool_param value, link it as a data source. This catches
                # IPI patterns where the agent re-uses tainted observation
                # content many turns after first reading it.
                for obs_id in prior_observations:
                    obs_text = node_attrs[obs_id].get("content", "") or ""
                    if not obs_text:
                        continue
                    for pid in param_ids:
                        pv = node_attrs[pid].get("param_value")
                        if pv is not None and self._references(pv, obs_text):
                            dfg.add_node(obs_id, **node_attrs[obs_id])
                            dfg.add_edge(obs_id, pid,
                                         kind=EdgeKind.DATA.value)

                prev_cfg_node = tool_id
                last_tool_node = tool_id

            elif ev.kind == "observation":
                obs_id = self._add_node(
                    cfg, dfg, node_attrs, step, NodeKind.OBSERVATION, ev,
                    content=ev.observation or ev.content,
                )
                self._link_control(cfg, prev_cfg_node, obs_id)
                if last_tool_node is not None:
                    dfg.add_node(last_tool_node, **node_attrs[last_tool_node])
                    dfg.add_node(obs_id, **node_attrs[obs_id])
                    dfg.add_edge(last_tool_node, obs_id, kind=EdgeKind.DATA.value)
                prev_cfg_node = obs_id
                prior_observations.append(obs_id)

            else:
                raise ValueError(f"unknown event kind: {ev.kind}")

        pdg = nx.DiGraph()
        for n, attrs in node_attrs.items():
            pdg.add_node(n, **attrs)
        for u, v, edata in cfg.edges(data=True):
            pdg.add_edge(u, v, **edata)
        for u, v, edata in dfg.edges(data=True):
            if pdg.has_edge(u, v):
                existing = pdg[u][v].get("kind")
                pdg[u][v]["kind"] = (
                    f"{existing}+{edata.get('kind')}" if existing else edata.get("kind")
                )
            else:
                pdg.add_edge(u, v, **edata)

        emit_event(
            "agentarmor.graph.built",
            logger=_logger,
            cfg_nodes=cfg.number_of_nodes(),
            cfg_edges=cfg.number_of_edges(),
            dfg_edges=dfg.number_of_edges(),
            pdg_edges=pdg.number_of_edges(),
        )

        return GraphIR(cfg=cfg, dfg=dfg, pdg=pdg, node_attrs=node_attrs)

    @staticmethod
    def _add_node(
        cfg: nx.DiGraph,
        dfg: nx.DiGraph,
        node_attrs: dict[str, dict[str, Any]],
        step: int,
        kind: NodeKind,
        ev: TraceEvent,
        **extra: Any,
    ) -> str:
        disc = extra.get("param_name") or extra.get("tool_name") or ""
        nid = f"n{step:03d}_{kind.value}" + (f"_{disc}" if disc else "")
        i = 0
        base = nid
        while nid in node_attrs:
            i += 1
            nid = f"{base}_{i}"

        attrs: dict[str, Any] = {
            "step": step,
            "kind": kind.value,
            "source": ev.source,
        }
        attrs.update(extra)
        node_attrs[nid] = attrs
        cfg.add_node(nid, **attrs)
        return nid

    @staticmethod
    def _link_control(cfg: nx.DiGraph, prev: str | None, curr: str) -> None:
        if prev is not None:
            cfg.add_edge(prev, curr, kind=EdgeKind.CONTROL.value)

    @staticmethod
    def _references(param_value: Any, obs_text: str) -> bool:
        """Heuristic data-flow detection between an observation and a later
        tool parameter. Conservative: returns True if a non-trivial substring
        of the observation appears in the param value (or vice versa).
        """
        if not isinstance(param_value, str) or len(obs_text) < 4:
            return False
        sample = obs_text.strip()
        if len(sample) >= 16:
            sample = sample[:64]
        return sample in param_value or param_value in obs_text
