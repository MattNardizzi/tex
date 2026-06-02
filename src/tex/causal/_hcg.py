"""
Hierarchical Causal Graph node + edge types.

Per arxiv 2602.23701 §4.1.1 — §4.1.2:

  V = V_sub ∪ V_agt
    V_sub  — Subtask Node (high-level logical phase)
    V_agt  — Agent Node (atomic execution unit, OTAR-attributed)

  E = E_sub ∪ E_agt ∪ E_step
    E_sub  — links adjacent subtasks (high-level logical progression)
    E_agt  — connects agent nodes (inter-agent collaboration)
    E_step — explicit data-flow at step granularity, recording exact
             upstream outputs and downstream inputs (variable references
             in OTAR tuples — paper §4.1.2)

Edge construction follows the paper's pattern: subtask and agent edges
carry counterfactual patterns ``Φ`` linking ``Bias(u)`` to
``Anomaly(v)``; step edges serve as data snapshots.

Implementation
--------------
The graph itself is a ``networkx.DiGraph`` keyed by ``str`` node IDs.
Per-node payloads (subtask metadata, OTAR tuple, step references) live
in the node's ``data`` attribute as one of the frozen pydantic models
below.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.causal._otar import OTARTuple


class NodeKind(str, Enum):
    """Node tier per CHIEF §4.1.1."""

    SUBTASK = "subtask"
    AGENT = "agent"


class EdgeKind(str, Enum):
    """Edge tier per CHIEF §4.1.2."""

    SUB = "subtask"  # E_sub
    AGT = "agent"    # E_agt
    STEP = "step"    # E_step


class SubtaskNode(BaseModel):
    """
    A high-level logical phase. Per Fig. 5(a) of the CHIEF paper.

    ``goal`` corresponds to ``G_sub`` in the virtual oracle tuple
    ``O_k = ⟨G_sub, P_pre, E_key, C_acc⟩`` (§4.2.1). The remaining
    oracle fields are populated by ``OracleSynthesizer`` if/when wired
    (P1 work — see ``HierarchicalCausalGraph``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subtask_id: str = Field(min_length=1, max_length=256)
    goal: str = Field(default="", max_length=4_000)
    member_agent_ids: tuple[str, ...] = Field(default_factory=tuple)
    member_step_ids: tuple[str, ...] = Field(default_factory=tuple)


class AgentNode(BaseModel):
    """
    An atomic agent execution unit, OTAR-attributed.

    ``otar`` is the ⟨Observation, Thought, Action, Result⟩ tuple per
    §4.1.1 / Fig. 5(b). ``step_id`` and ``agent_id`` together uniquely
    identify the node within the trace; the graph node ID itself is
    derived deterministically from them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    parent_subtask_id: str = Field(min_length=1, max_length=256)
    timestep: int = Field(ge=0)
    otar: OTARTuple


class CausalEdge(BaseModel):
    """
    A causal edge with type-specific attributes.

    For ``EdgeKind.STEP`` edges, ``upstream_output_ref`` and
    ``downstream_input_ref`` capture the exact variable / OTAR-result
    references that constitute the data-flow snapshot (§4.1.2).
    For ``EdgeKind.SUB`` and ``EdgeKind.AGT`` edges, ``pattern`` carries
    the counterfactual pattern ``Φ`` (Bias → Anomaly).

    All fields are optional; only ``kind`` is required.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: EdgeKind
    upstream_output_ref: str | None = None
    downstream_input_ref: str | None = None
    pattern: str | None = None


# Deterministic graph-node ID format: ``{kind}:{stable_id}``. The
# ``stable_id`` is the subtask_id for V_sub nodes and ``{step_id}@{agent_id}``
# for V_agt nodes — chosen so that two agent nodes with the same step
# but different agents (e.g. orchestrator vs executor at the same turn)
# remain distinguishable.

def subtask_node_id(subtask_id: str) -> str:
    return f"subtask:{subtask_id}"


def agent_node_id(*, step_id: str, agent_id: str) -> str:
    return f"agent:{step_id}@{agent_id}"


# Convenience: a typed payload for ``networkx`` node ``data`` attribute.
NodePayload = SubtaskNode | AgentNode


def node_kind_of(payload: NodePayload) -> NodeKind:
    if isinstance(payload, SubtaskNode):
        return NodeKind.SUBTASK
    if isinstance(payload, AgentNode):
        return NodeKind.AGENT
    raise TypeError(f"unknown node payload type: {type(payload).__name__}")


def coerce_node_payload(value: Any) -> NodePayload:
    """
    Defensive helper for callers reading ``G.nodes[n]['data']`` —
    networkx will return whatever was stored, so we runtime-check the
    type before consumers reach into it.
    """
    if isinstance(value, (SubtaskNode, AgentNode)):
        return value
    raise TypeError(
        f"expected SubtaskNode or AgentNode, got {type(value).__name__}"
    )
